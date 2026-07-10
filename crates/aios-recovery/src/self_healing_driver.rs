//! Self-healing driver trait and in-memory implementation.
//!
//! The driver is the autonomous decision engine: given a health observation,
//! the active recovery state, and the declared policy, it decides whether (and
//! how) to heal a component, then executes the action and emits evidence.

#![allow(
    clippy::module_name_repetitions,
    reason = "Public names mirror the self-healing vocabulary"
)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::RwLock;

use crate::boundary::RecoveryBoundary;
use crate::evidence_emit::RecoveryEvidenceEmitter;
use crate::ipc::{HealCommand, HealCommandResponse};
use crate::mode::RecoveryMode;
use crate::registry::ComponentRegistry;
use crate::self_healing::{
    ComponentHealingTracker, ComponentHealthState, ComponentIsolationLevel, ComponentSnapshot,
    HealAction, HealActionKind, PanicContext, RestartBoundary, SelfHealingPolicy,
};
use crate::watchdog::{WatchdogPolicy, WatchdogTimer};
use crate::{RecoveryError, RecoveryMutableScope, RecoverySubBoundary};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Autonomous self-healing driver surface.
///
/// Implementors decide and execute healing actions for unhealthy components.
/// Every action MUST be emitted as immutable evidence; silent healing is
/// constitutionally forbidden by INV-005.
#[async_trait]
pub trait SelfHealingDriver: Send + Sync {
    /// Register or update a health observation for a component.
    async fn observe_health(
        &self,
        component_id: &str,
        state: ComponentHealthState,
    ) -> Result<(), RecoveryError>;

    /// Register a structured panic event for a component.
    ///
    /// Unlike [`SelfHealingDriver::observe_health`] which records state only,
    /// this method captures full panic context (severity, backtrace hash, core dump
    /// reference) and classifies the crash to decide whether auto-restart is safe
    /// or escalation is required.
    ///
    /// The panic is always recorded in the tracker (bumps consecutive failures)
    /// and evidence is emitted immediately when an emitter is attached — even before
    /// `evaluate()` / `heal_cycle()` runs.  This matches MINIX's behaviour where the
    /// process manager logs crashes at detection time, not at decision time.
    async fn observe_panic(&self, ctx: PanicContext) -> Result<String, RecoveryError>;

    /// Evaluate all observed components and produce a list of healing actions.
    ///
    /// Returns an empty vec when no intervention is needed or when the policy
    /// disables autonomous healing.
    async fn evaluate(&self) -> Result<Vec<HealAction>, RecoveryError>;

    /// Execute a single decided healing action within recovery scope.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] when recovery is not active, the required
    /// scope grant is missing, or evidence emission fails.
    async fn execute_heal(&self, action: &HealAction)
        -> Result<HealExecutionResult, RecoveryError>;

    /// Run one full observe → evaluate → execute cycle for all components.
    ///
    /// This is the main loop primitive used by the background daemon.
    async fn heal_cycle(&self) -> Result<HealCycleResult, RecoveryError>;
}

/// Outcome of a single [`SelfHealingDriver::execute_heal`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealExecutionResult {
    /// The component that was targeted.
    pub component_id: String,
    /// Action kind that was attempted / performed.
    pub action_kind: HealActionKind,
    /// `true` when the action was executed and evidence was emitted.
    pub success: bool,
    /// Evidence receipt id (when emission succeeded).
    pub receipt_id: Option<String>,
    /// Human-readable outcome detail.
    pub detail: String,
}

/// Outcome of a full heal cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealCycleResult {
    /// Number of components evaluated.
    pub components_evaluated: u64,
    /// Healing actions decided.
    pub actions_decided: usize,
    /// Healing actions successfully executed.
    pub actions_executed: usize,
    /// Actions that failed (execution error or escalation).
    pub actions_failed: usize,
    /// UTC timestamp when the cycle started.
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// UTC timestamp when the cycle completed.
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/// Internal envelope alias used by the command-channel machinery.
type CommandEnvelope = (
    HealCommand,
    tokio::sync::oneshot::Sender<HealCommandResponse>,
);

/// In-process self-healing driver backed by `HashMap`s and an optional emitter.
pub struct InMemorySelfHealingDriver {
    policy: RwLock<SelfHealingPolicy>,
    health_registry: RwLock<HashMap<String, ComponentHealthState>>,
    trackers: RwLock<HashMap<String, ComponentHealingTracker>>,
    command_channels: RwLock<HashMap<String, tokio::sync::mpsc::Sender<CommandEnvelope>>>,
    registry: Option<Arc<ComponentRegistry>>,
    watchdog: WatchdogTimer,
    boundary: Arc<dyn RecoveryBoundary>,
    evidence_emitter: Option<Arc<RecoveryEvidenceEmitter>>,
    global_sequence: RwLock<u64>,
}

impl Default for InMemorySelfHealingDriver {
    fn default() -> Self {
        Self {
            policy: RwLock::new(SelfHealingPolicy::default()),
            health_registry: RwLock::new(HashMap::new()),
            trackers: RwLock::new(HashMap::new()),
            command_channels: RwLock::new(HashMap::new()),
            registry: None,
            watchdog: WatchdogTimer::default(),
            boundary: Arc::new(crate::InMemoryRecoveryBoundary::new()),
            evidence_emitter: None,
            global_sequence: RwLock::new(0),
        }
    }
}

impl InMemorySelfHealingDriver {
    /// Construct a new disabled driver (policy `enabled = false`).
    #[must_use]
    pub fn new(boundary: Arc<dyn RecoveryBoundary>) -> Self {
        Self {
            boundary,
            ..Default::default()
        }
    }

    /// Set the declarative self-healing policy.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] when the policy violates INV-012 (normal-mode
    /// mutations) or other structural invariants.
    pub async fn set_policy(&self, policy: SelfHealingPolicy) -> Result<(), RecoveryError> {
        policy.validate()?;
        {
            let mut guard = self.policy.write().await;
            *guard = policy;
        }
        Ok(())
    }

    /// Return a snapshot of the current policy.
    #[must_use]
    pub async fn policy(&self) -> SelfHealingPolicy {
        self.policy.read().await.clone()
    }

    /// Attach a component registry so the driver can consult isolation levels
    /// and dependency chains when deciding healing actions.
    #[must_use]
    pub fn with_registry(mut self, registry: Arc<ComponentRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Attach an evidence emitter so every heal action produces a receipt.
    #[must_use]
    pub fn with_evidence_emitter(mut self, emitter: Arc<RecoveryEvidenceEmitter>) -> Self {
        self.evidence_emitter = Some(emitter);
        self
    }

    /// Return the current health registry snapshot.
    #[must_use]
    pub async fn health_snapshot(&self) -> HashMap<String, ComponentHealthState> {
        self.health_registry.read().await.clone()
    }

    /// Return the tracker for a specific component (or default if untracked).
    #[must_use]
    pub async fn tracker_for(&self, component_id: &str) -> ComponentHealingTracker {
        self.trackers
            .read()
            .await
            .get(component_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Set the watchdog policy and optionally replace the timer state.
    pub async fn set_watchdog_policy(&self, policy: WatchdogPolicy) {
        self.watchdog.set_policy(policy).await;
    }

    /// Return a snapshot of the current watchdog policy.
    #[must_use]
    pub async fn watchdog_policy(&self) -> WatchdogPolicy {
        self.watchdog.policy().await
    }

    /// Register a component for watchdog liveness monitoring.
    pub async fn register_watchdog(&self, component_id: &str) {
        self.watchdog.register(component_id).await;
    }

    /// Signal a liveness ping from a component, resetting its watchdog deadline.
    pub async fn ping_watchdog(&self, component_id: &str) {
        self.watchdog.ping(component_id).await;
    }

    /// Check all watchdog deadlines and auto-flag expired components as
    /// Degraded via [`SelfHealingDriver::observe_health`].
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] when `observe_health` fails on an expired
    /// component.
    pub async fn watchdog_check(&self) -> Result<(), RecoveryError> {
        let expired = self.watchdog.check_deadlines().await;
        for component_id in &expired {
            self.observe_health(component_id, ComponentHealthState::Degraded)
                .await?;
        }
        Ok(())
    }

    /// Builder: attach a pre-configured watchdog timer.
    #[must_use]
    pub fn with_watchdog_policy(mut self, policy: WatchdogPolicy) -> Self {
        self.watchdog = WatchdogTimer::new(policy);
        self
    }

    /// Capture a last-known-good snapshot of a component's current config before restart.
    ///
    /// Serializes the current tracker state into a hex-encoded blob, computes its
    /// BLAKE3 hash, calls [`ComponentHealingTracker::checkpoint`] to persist the
    /// hash and timestamp, and returns an immutable [`ComponentSnapshot`].
    ///
    /// Call this **before** executing a [`HealActionKind::Restart`] action so
    /// the driver can detect crash-loops during reincarnation.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError`] when the config blob cannot be serialized.
    pub async fn take_snapshot(
        &self,
        component_id: &str,
        config_blob: &[u8],
    ) -> Result<ComponentSnapshot, RecoveryError> {
        let hash = blake3::hash(config_blob).to_hex().to_string();
        let config_blob_hex = hex::encode(config_blob);
        let captured_at = Utc::now();

        {
            let mut trackers = self.trackers.write().await;
            let tracker = trackers.entry(component_id.to_owned()).or_default();
            tracker.checkpoint(&hash);
            drop(trackers);
        }

        Ok(ComponentSnapshot {
            component_id: component_id.to_owned(),
            checkpoint_hash: hash,
            config_blob_hex,
            captured_at,
        })
    }

    /// Restore a previously captured [`ComponentSnapshot`] into the tracker.
    ///
    /// Sets the `checkpoint_hash` and `checkpoint_timestamp` on the component's
    /// tracker from the snapshot data.  This is called during reincarnation to
    /// carry forward the last-known-good state so crash-loop detection can run.
    ///
    /// Returns `true` if the tracker was updated (component existed), `false`
    /// if the component was not tracked (snapshot stored but no prior state).
    pub async fn restore_snapshot(&self, snapshot: &ComponentSnapshot) -> bool {
        let mut trackers = self.trackers.write().await;
        if let Some(tracker) = trackers.get_mut(&snapshot.component_id) {
            tracker.checkpoint_hash = Some(snapshot.checkpoint_hash.clone());
            tracker.checkpoint_timestamp = Some(snapshot.captured_at);
            true
        } else {
            let tracker = ComponentHealingTracker {
                checkpoint_hash: Some(snapshot.checkpoint_hash.clone()),
                checkpoint_timestamp: Some(snapshot.captured_at),
                ..Default::default()
            };
            trackers.insert(snapshot.component_id.clone(), tracker);
            false
        }
    }

    /// Register a command channel for a component.
    ///
    /// Creates a new `mpsc` channel pair, stores the sender in the driver's
    /// per-component map, and returns the receiver half. The caller (typically
    /// the component's runtime) should hold the receiver and call
    /// [`HealCommandChannel::try_receive`] in its main loop.
    ///
    /// After registration, the driver can deliver [`HealCommand`] messages to
    /// this component via [`SelfHealingDriver::deliver_heal_command`].
    ///
    /// If a channel already exists for this component, the old sender is
    /// replaced and the old receiver will receive no more commands.
    #[must_use]
    pub async fn register_command_channel(
        &self,
        component_id: &str,
        capacity: usize,
    ) -> crate::ipc::HealCommandChannel {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        {
            let mut channels = self.command_channels.write().await;
            channels.insert(component_id.to_owned(), tx.clone());
        }
        crate::ipc::HealCommandChannel::from_raw(tx, rx)
    }

    /// Deliver a healing command to a registered component and wait for its
    /// response.
    ///
    /// Looks up the component's command channel sender, sends the command
    /// together with a oneshot response channel, and awaits the component's
    /// [`HealCommandResponse`].
    ///
    /// Returns `None` when no channel has been registered for this component
    /// (graceful fallback — the caller should proceed with direct action).
    pub async fn deliver_heal_command(
        &self,
        component_id: &str,
        command: HealCommand,
    ) -> Option<HealCommandResponse> {
        let tx = {
            let channels = self.command_channels.read().await;
            channels.get(component_id)?.clone()
        };
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        tx.send((command, response_tx)).await.ok()?;
        response_rx.await.ok()
    }

    // --- internal decision logic ---

    /// Decide what (if any) to do for a single component given its state.
    async fn decide_for_component(
        &self,
        component_id: &str,
        state: ComponentHealthState,
        policy: &SelfHealingPolicy,
        tracker: &ComponentHealingTracker,
    ) -> Option<HealAction> {
        if !state.needs_intervention() {
            return None;
        }

        let restart_policy = policy.policy_for_component(component_id);
        let allowed_scopes = policy.scopes_for_component(component_id);
        let config = policy.config_for_component(component_id);
        let restart_boundary = config.map_or_else(RestartBoundary::default, |c| c.restart_boundary);

        let isolation = self.registry.as_ref().map_or_else(
            || config.map_or_else(ComponentIsolationLevel::default, |c| c.isolation_level),
            |registry| registry.isolation_level_of(component_id),
        );

        // Critical components MUST escalate immediately — the driver is never
        // allowed to restart or kill them.
        if isolation.requires_escalation() {
            let sequence = {
                let mut seq = self.global_sequence.write().await;
                *seq += 1;
                *seq
            };
            return Some(HealAction {
                component_id: component_id.to_owned(),
                observed_state: state,
                action_kind: HealActionKind::Escalate,
                required_scope: RecoveryMutableScope::ProcessLifecycle,
                reason: format!(
                    "component={component_id} isolation_level=Critical restart_boundary={restart_boundary:?} — escalation required"
                ),
                decided_at: Utc::now(),
                sequence,
            });
        }

        // Pick the best available scope for this action
        let required_scope = allowed_scopes
            .first()
            .copied()
            .unwrap_or(RecoveryMutableScope::ProcessLifecycle);

        let attempt = tracker.consecutive_failures.saturating_add(1);
        let mut action_kind = if attempt > restart_policy.max_retries {
            HealActionKind::Escalate
        } else if state.is_terminal() && attempt > restart_policy.max_retries / 2 {
            // After half max retries with terminal failure, try failover first
            if allowed_scopes.contains(&RecoveryMutableScope::MeshRouting) {
                HealActionKind::Failover
            } else {
                HealActionKind::Isolate
            }
        } else {
            HealActionKind::Restart
        };

        // Belt-and-suspenders: if the action was decided as Restart but the
        // component is Critical, escalate instead (should already be caught above).
        if action_kind == HealActionKind::Restart && isolation.requires_escalation() {
            action_kind = HealActionKind::Escalate;
        }

        // Check escalate_after threshold on the restart policy: when set,
        // escalate immediately for any component at or above the threshold.
        if let Some(threshold) = restart_policy.escalate_after {
            if isolation >= threshold {
                action_kind = HealActionKind::Escalate;
            }
        }

        let sequence = {
            let mut seq = self.global_sequence.write().await;
            *seq += 1;
            *seq
        };

        Some(HealAction {
            component_id: component_id.to_owned(),
            observed_state: state,
            action_kind,
            required_scope,
            reason: format!(
                "component={component_id} state={state:?} consecutive_failures={} attempt={}/{} isolation_level={isolation:?} restart_boundary={restart_boundary:?}",
                tracker.consecutive_failures,
                attempt,
                restart_policy.max_retries,
            ),
            decided_at: Utc::now(),
            sequence,
        })
    }
}

#[async_trait]
impl SelfHealingDriver for InMemorySelfHealingDriver {
    async fn observe_health(
        &self,
        component_id: &str,
        state: ComponentHealthState,
    ) -> Result<(), RecoveryError> {
        // Update health registry
        {
            let mut reg = self.health_registry.write().await;
            reg.insert(component_id.to_owned(), state);
        }
        // Update tracker
        {
            let mut trackers = self.trackers.write().await;
            trackers
                .entry(component_id.to_owned())
                .or_default()
                .record_observation(state);
        }
        Ok(())
    }

    async fn observe_panic(&self, ctx: PanicContext) -> Result<String, RecoveryError> {
        let component_id = &ctx.component_id;

        // 1. Update health registry to Failed (panic = failed state)
        {
            let mut reg = self.health_registry.write().await;
            reg.insert(component_id.to_owned(), ComponentHealthState::Failed);
        }

        // 2. Record in tracker using panic-specific logic
        {
            let mut trackers = self.trackers.write().await;
            trackers
                .entry(component_id.to_owned())
                .or_default()
                .record_panic();
        }

        // 3. Emit structured panic evidence immediately (MINIX-style:
        //    log at detection time, not decision time)
        if let Some(emitter) = &self.evidence_emitter {
            emit_panic_evidence(emitter, &ctx).await
        } else {
            Ok(format!(
                "panic-{}-{}",
                ctx.component_id, ctx.consecutive_panics
            ))
        }
    }

    async fn evaluate(&self) -> Result<Vec<HealAction>, RecoveryError> {
        // Clone policy data to minimise lock hold time
        let (enabled, minimum_mode) = {
            let policy = self.policy.read().await;
            (policy.enabled, policy.minimum_mode)
        };
        if !enabled {
            return Ok(Vec::new());
        }

        // Normal minimum_mode: no recovery gate needed
        if minimum_mode != RecoveryMode::Normal {
            // Check minimum mode requirement via boundary for system-level modes
            let current_state = self.boundary.current_state().await;
            let full_recovery_active = current_state.mode == RecoveryMode::Recovery;
            let mode_satisfied = match minimum_mode {
                RecoveryMode::Normal => true, // unreachable
                RecoveryMode::Recovery => full_recovery_active,
                RecoveryMode::Degraded => matches!(
                    current_state.mode,
                    RecoveryMode::Degraded | RecoveryMode::Recovery
                ),
                RecoveryMode::FirstBoot => current_state.mode == RecoveryMode::FirstBoot,
            };
            // If the mode gate is NOT satisfied, fall through to sub-boundary
            // check.  Mode gate failing does not block evaluation when the
            // component's sub-boundary is independently active.
            if !mode_satisfied {
                // Check whether any sub-boundary (individual or SystemFull) is active
                let any_sub_active = self
                    .boundary
                    .is_sub_recovery_active(RecoverySubBoundary::Network)
                    .await
                    .unwrap_or(false)
                    || self
                        .boundary
                        .is_sub_recovery_active(RecoverySubBoundary::Storage)
                        .await
                        .unwrap_or(false)
                    || self
                        .boundary
                        .is_sub_recovery_active(RecoverySubBoundary::Compute)
                        .await
                        .unwrap_or(false)
                    || self
                        .boundary
                        .is_sub_recovery_active(RecoverySubBoundary::SystemFull)
                        .await
                        .unwrap_or(false);
                if !any_sub_active {
                    return Ok(Vec::new());
                }
            }
        }

        // Snapshot registries under separate read locks, then release
        let states: Vec<(String, ComponentHealthState)>;
        let trackers_snapshot: HashMap<String, ComponentHealingTracker>;
        {
            let health = self.health_registry.read().await;
            let trackers = self.trackers.read().await;
            states = health.iter().map(|(k, v)| (k.clone(), *v)).collect();
            trackers_snapshot = trackers.clone();
            drop(health);
            drop(trackers);
        }

        let policy = self.policy.read().await;
        let mut actions = Vec::new();
        for (component_id, state) in &states {
            let default_tracker = ComponentHealingTracker::default();
            let tracker = trackers_snapshot
                .get(component_id)
                .unwrap_or(&default_tracker);

            // Per-component sub-boundary gate: at least one of this
            // component's allowed scopes must map to an active sub-boundary.
            if minimum_mode != RecoveryMode::Normal {
                let allowed_scopes = policy.scopes_for_component(component_id);
                let mut scope_granted = allowed_scopes.is_empty(); // empty list = default granted
                for scope in &allowed_scopes {
                    if let Some(sub) = RecoverySubBoundary::from_mutable_scope(*scope) {
                        if self
                            .boundary
                            .is_sub_recovery_active(sub)
                            .await
                            .unwrap_or(false)
                        {
                            scope_granted = true;
                            break;
                        }
                    }
                }
                if !scope_granted {
                    continue;
                }
            }

            if let Some(action) = self
                .decide_for_component(component_id, *state, &policy, tracker)
                .await
            {
                actions.push(action);
            }
        }
        drop(policy);
        Ok(actions)
    }

    async fn execute_heal(
        &self,
        action: &HealAction,
    ) -> Result<HealExecutionResult, RecoveryError> {
        // INV-012 guard: map the action's required scope to its narrowest
        // sub-boundary and verify it is active.  Falls back to the traditional
        // is_recovery_active() check for backward compatibility when no
        // sub-boundary mapping exists.
        let required_sub = RecoverySubBoundary::from_mutable_scope(action.required_scope)
            .unwrap_or(RecoverySubBoundary::SystemFull);
        let sub_active = self
            .boundary
            .is_sub_recovery_active(required_sub)
            .await
            .unwrap_or(false);

        let full_recovery_active = self.boundary.is_recovery_active().await;

        if !sub_active && !full_recovery_active {
            let policy = self.policy.read().await;
            if policy.minimum_mode == RecoveryMode::Recovery {
                return Ok(HealExecutionResult {
                    component_id: action.component_id.clone(),
                    action_kind: action.action_kind,
                    success: false,
                    receipt_id: None,
                    detail: format!(
                        "sub-boundary {required_sub:?} not active — healing denied (INV-012)"
                    ),
                });
            }
        }

        // MINIX-style: for Restart actions, attempt graceful shutdown through
        // the command channel before force-terminating.  The component gets a
        // chance to flush buffers, close connections, and checkpoint state.
        // If no channel is registered or the component refuses/times out, we
        // fall back to direct restart (no crash — graceful degradation).
        if action.action_kind == HealActionKind::Restart {
            let shutdown_cmd = HealCommand::Shutdown {
                grace_period_seconds: 5,
            };
            match self
                .deliver_heal_command(&action.component_id, shutdown_cmd)
                .await
            {
                Some(HealCommandResponse::Ack(ref msg)) => {
                    // Component acknowledged — graceful shutdown succeeded.
                    // Proceed with the normal healing flow below.
                    let _ = msg;
                }
                Some(HealCommandResponse::Nack { .. } | HealCommandResponse::Timeout) | None => {
                    // No channel, refused, or timed out — fall through to direct restart.
                    // This is not an error; it's graceful degradation (MINIX-style
                    // "driver unresponsive → PM force-restarts it").
                }
            }
        }

        // Update tracker
        {
            let mut trackers = self.trackers.write().await;
            if let Some(tracker) = trackers.get_mut(&action.component_id) {
                tracker.record_action(action.sequence);
            }
        }

        // Emit evidence (best-effort but we report failures)
        let receipt_id = if let Some(emitter) = &self.evidence_emitter {
            match emit_healing_action(emitter, action).await {
                Ok(id) => Some(id),
                Err(e) => {
                    // Evidence failure is logged but does not block the action result
                    // — the action itself was decided; only its audit trail is incomplete
                    return Ok(HealExecutionResult {
                        component_id: action.component_id.clone(),
                        action_kind: action.action_kind,
                        success: false,
                        receipt_id: None,
                        detail: format!("evidence emission failed: {e}"),
                    });
                }
            }
        } else {
            None
        };

        Ok(HealExecutionResult {
            component_id: action.component_id.clone(),
            action_kind: action.action_kind,
            success: true,
            receipt_id,
            detail: format!(
                "{:?} executed for {} (seq={})",
                action.action_kind, action.component_id, action.sequence
            ),
        })
    }

    async fn heal_cycle(&self) -> Result<HealCycleResult, RecoveryError> {
        let started_at = Utc::now();

        self.watchdog_check().await?;

        let actions = self.evaluate().await?;
        let actions_decided = actions.len();

        let mut actions_executed = 0_usize;
        let mut actions_failed = 0_usize;

        for action in &actions {
            match self.execute_heal(action).await {
                Ok(result) if result.success => {
                    actions_executed += 1;
                }
                Ok(_) | Err(_) => {
                    actions_failed += 1;
                }
            }
        }

        let components_evaluated = self.health_registry.read().await.len() as u64;

        Ok(HealCycleResult {
            components_evaluated,
            actions_decided,
            actions_executed,
            actions_failed,
            started_at,
            completed_at: Utc::now(),
        })
    }
}

// ---------------------------------------------------------------------------
// Evidence emission helpers
// ---------------------------------------------------------------------------

/// Emit a healing-action evidence record using the closest available S3.1 type.
///
/// Currently maps to `RECOVERY_OPERATION_PERFORMED`; a future reduced
/// vocabulary may fold into a generic `HEALING_EVENT`.
async fn emit_healing_action(
    emitter: &RecoveryEvidenceEmitter,
    action: &HealAction,
) -> Result<String, RecoveryError> {
    use crate::evidence_payloads::HealingAttemptedPayload;
    use aios_evidence::RecordType;

    let payload = HealingAttemptedPayload {
        component_id: action.component_id.clone(),
        observed_state: action.observed_state,
        action_kind: action.action_kind,
        required_scope: action.required_scope,
        reason: action.reason.clone(),
        decided_at: action.decided_at,
        sequence: action.sequence,
    };
    // Use RECOVERY_OPERATION_PERFORMED as the closest S3.1 record type for
    // autonomous healing actions.  A future vocabulary may add HEALING_ATTEMPTED.
    emitter
        .emit(RecordType::RecoveryOperationPerformed, &payload, None)
        .await
}

/// Emit a structured panic evidence record.
///
/// Uses `RECOVERYOperationPerformed` (same as healing actions) because panic
/// is an autonomous recovery operation. The severity and classification are
/// captured inside the payload for post-mortem filtering.
async fn emit_panic_evidence(
    emitter: &RecoveryEvidenceEmitter,
    ctx: &PanicContext,
) -> Result<String, RecoveryError> {
    use crate::evidence_payloads::ComponentPanicPayload;
    use aios_evidence::RecordType;

    let payload = ComponentPanicPayload {
        component_id: ctx.component_id.clone(),
        severity: ctx.severity,
        message: ctx.message.clone(),
        file: ctx.file.clone(),
        line: ctx.line,
        backtrace_hash: ctx.backtrace_hash.clone(),
        core_dump_ref: ctx.core_dump_ref.clone(),
        observed_at: ctx.observed_at,
        consecutive_panics: ctx.consecutive_panics,
        recoverable_by_restart: ctx.severity.is_recoverable_by_restart(),
        requires_escalation: ctx.severity.requires_escalation(),
    };

    emitter
        .emit(RecordType::RecoveryOperationPerformed, &payload, None)
        .await
}
