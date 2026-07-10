//! Autonomous self-healing module inspired by MINIX process manager / reincarnation server.
//!
//! Unlike operator-driven recovery, the self-healing daemon runs autonomously:
//! it monitors component health, decides restart/isolate/failover actions,
//! executes them within recovery-mode scope, and emits immutable evidence for
//! every action taken.
//!
//! ## Architecture
//!
//! ```text
//! SelfHealingDriver trait          ← abstract driver surface
//!   └── InMemorySelfHealingDriver   ← in-process impl with health registry
//!
//! SelfHealingPolicy                ← declarative policy: which components, limits, scopes
//! RestartPolicy                    ← per-component: immediate/backoff/max-retries
//! ComponentHealthState             ← observed state: Healthy/Degraded/Failed/Unknown
//! HealAction                       ← decided autonomous action + required scope grant
//! ```
//!
//! ## Constitutional guarantees
//!
//! - INV-001 (no L5 in recovery): self-healing only mutates L1–L4 infrastructure.
//! - INV-012 (recovery required): every mutation happens inside an active recovery session.
//! - INV-005 (evidence append-only): each heal action produces a FOREVER receipt.
//! - The subject `_system:service:self-healing` holds pre-authorized scoped grants; no
//!   operator approval is needed at decision time (grants were pre-approved during boot).

#![allow(
    clippy::module_name_repetitions,
    reason = "Public names mirror the self-healing vocabulary"
)]

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::mode::{HealingCapability, RecoveryMode};
use crate::{RecoveryError, RecoveryMutableScope};

// ---------------------------------------------------------------------------
// Isolation level (MINIX-inspired driver server model)
// ---------------------------------------------------------------------------

/// How isolated a component is from the rest of the system.
///
/// Determines what the self-healing driver is allowed to do when the component
/// becomes unhealthy:
///
/// * [`ComponentIsolationLevel::Critical`] — **never stop or restart**; the
///   driver MUST escalate immediately.
/// * [`ComponentIsolationLevel::Important`] — **can restart** but not kill
///   permanently; the driver may attempt a bounded number of restarts.
/// * [`ComponentIsolationLevel::Replaceable`] — **can kill and replace**;
///   the driver may restart aggressively, including hot-swap to a standby.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentIsolationLevel {
    /// Cannot stop, cannot restart — escalation is the only option.
    Critical,
    /// May restart within policy limits, but must not be killed permanently.
    Important,
    /// May be killed and replaced (hot-swap to standby instance).
    #[default]
    Replaceable,
}

impl ComponentIsolationLevel {
    /// Numeric rank for ordering — higher = more restrictive.
    ///
    /// `Replaceable` (0) < `Important` (1) < `Critical` (2).
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Replaceable => 0,
            Self::Important => 1,
            Self::Critical => 2,
        }
    }

    /// Returns `true` when the driver may attempt a restart for this level.
    #[must_use]
    pub const fn may_restart(self) -> bool {
        !matches!(self, Self::Critical)
    }

    /// Returns `true` when the driver may kill and replace this component.
    #[must_use]
    pub const fn may_kill_and_replace(self) -> bool {
        matches!(self, Self::Replaceable)
    }

    /// Returns `true` when escalation is **mandatory** (Critical = never touch).
    #[must_use]
    pub const fn requires_escalation(self) -> bool {
        matches!(self, Self::Critical)
    }
}

impl PartialOrd for ComponentIsolationLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ComponentIsolationLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

// ---------------------------------------------------------------------------
// Restart boundary — how far a restart action propagates
// ---------------------------------------------------------------------------

/// Declares the propagation scope of a component restart.
///
/// Inspired by the MINIX driver-server model where some servers can restart
/// locally while others require a full system reincarnation cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestartBoundary {
    /// Restart only the component process; no wider effect.
    #[default]
    ProcessLocal,
    /// Restart and notify mesh peers so they can refresh routing / connections.
    MeshLocal,
    /// Requires a full recovery-mode cycle — affects the whole system.
    SystemWide,
}

/// Canonical pre-authorised subject id for self-healing evidence emissions.
///
/// This subject is granted scoped [`RecoveryMutableScope`] authorisations at
/// boot time via the constitutional bootstrap path.  No per-action operator
/// sign-off is required — the grant was already approved when the system was
/// provisioned.
pub const SELF_HEALING_SUBJECT: &str = "_system:service:self-healing";

// ---------------------------------------------------------------------------
// Health states
// ---------------------------------------------------------------------------

/// Observed health of a single AIOS component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentHealthState {
    /// Component responding within SLA bounds.
    Healthy,
    /// Component alive but degraded (slow, partial errors, elevated latency).
    Degraded,
    /// Component unresponsive or returning hard errors.
    Failed,
    /// Health probe has not yet completed or component is unknown to the registry.
    #[default]
    Unknown,
}

impl ComponentHealthState {
    /// Returns `true` if the component requires a healing intervention.
    #[must_use]
    pub const fn needs_intervention(self) -> bool {
        matches!(self, Self::Degraded | Self::Failed)
    }

    /// Returns `true` if the component is completely non-functional.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed)
    }
}

// ---------------------------------------------------------------------------
// Heal actions (decisions)
// ---------------------------------------------------------------------------

/// An autonomous healing decision produced by the self-healing driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HealAction {
    /// Target component this action addresses.
    pub component_id: String,
    /// Observed health that triggered the action.
    pub observed_state: ComponentHealthState,
    /// Kind of healing operation to perform.
    pub action_kind: HealActionKind,
    /// Required recovery-mutable scope grant for this operation.
    ///
    /// The self-healing subject must hold a pre-authorised grant covering this
    /// scope; otherwise the action MUST be rejected by the runtime adapter.
    pub required_scope: RecoveryMutableScope,
    /// Human-readable rationale for audit trails.
    pub reason: String,
    /// UTC timestamp when this decision was made.
    pub decided_at: DateTime<Utc>,
    /// Sequence number for ordering within a healing cycle.
    pub sequence: u64,
}

/// Kinds of autonomous healing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealActionKind {
    /// Graceful stop followed by start of the component process.
    Restart,
    /// Stop component and route traffic to a cold/warm standby instance.
    Failover,
    /// Isolate component from the service mesh but do not restart (e.g. crash-looping).
    Isolate,
    /// No action possible — escalation required.
    Escalate,
}

// ---------------------------------------------------------------------------
// Restart policy (per-component)
// ---------------------------------------------------------------------------

/// Per-component restart strategy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RestartPolicy {
    /// Maximum number of automatic restarts before escalating.
    ///
    /// After this threshold the driver emits `HealActionKind::Escalate`.
    pub max_retries: u32,
    /// Backoff multiplier in seconds after each failed restart attempt (geometric).
    ///
    /// A value of `0.0` means *immediate* retry (MINIX-style hot restart).
    pub backoff_seconds_base: f64,
    /// Upper bound on backoff delay in seconds.
    pub backoff_cap_seconds: f64,
    /// Whether to reset the retry counter after `Healthy` observation.
    pub reset_on_healthy: bool,
    /// Escalation threshold by isolation level.
    ///
    /// When set, any component at this isolation level or higher is escalated
    /// immediately instead of following the normal restart / failover flow.
    #[serde(default)]
    pub escalate_after: Option<ComponentIsolationLevel>,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_seconds_base: 1.0,
            backoff_cap_seconds: 60.0,
            reset_on_healthy: true,
            escalate_after: None,
        }
    }
}

impl RestartPolicy {
    /// MINIX-inspired zero-backoff policy: restart immediately, up to N attempts.
    #[must_use]
    pub const fn minix_style(max_retries: u32) -> Self {
        Self {
            max_retries,
            backoff_seconds_base: 0.0,
            backoff_cap_seconds: 0.0,
            reset_on_healthy: true,
            escalate_after: None,
        }
    }

    /// Conservative backoff policy with exponential delay.
    #[must_use]
    pub const fn conservative(max_retries: u32) -> Self {
        Self {
            max_retries,
            backoff_seconds_base: 2.0,
            backoff_cap_seconds: 300.0,
            reset_on_healthy: true,
            escalate_after: None,
        }
    }

    /// Compute the backoff delay in seconds for the given attempt count (1-based).
    ///
    /// Returns `None` when `attempt > max_retries` (should escalate).
    #[must_use]
    pub fn backoff_for_attempt(&self, attempt: u32) -> Option<f64> {
        if attempt > self.max_retries {
            return None;
        }
        if self.backoff_seconds_base <= 0.0 || self.backoff_cap_seconds <= 0.0 {
            return Some(0.0);
        }
        let raw = self.backoff_seconds_base * f64::from(2_u32.saturating_sub(attempt));
        Some(raw.min(self.backoff_cap_seconds))
    }
}

// ---------------------------------------------------------------------------
// Top-level policy
// ---------------------------------------------------------------------------

/// Declarative self-healing configuration loaded at boot time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SelfHealingPolicy {
    /// Global toggle — when `false`, the driver refuses all healing requests.
    pub enabled: bool,
    /// Minimum mode required for any healing action.
    ///
    /// Typically `RecoveryMode::Degraded` or `RecoveryMode::Recovery`; setting this
    /// to `RecoveryMode::Normal` would allow healing without entering recovery first
    /// (NOT recommended — breaks INV-012).
    pub minimum_mode: RecoveryMode,
    /// Per-component restart policies.
    pub component_policies: HashMap<String, ComponentHealingConfig>,
    /// Default policy applied to components not listed in `component_policies`.
    pub default_policy: RestartPolicy,
}

/// Healing config for a single component inside [`SelfHealingPolicy`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ComponentHealingConfig {
    /// Human-readable display name for evidence payloads.
    pub display_name: String,
    /// Restart / failover strategy for this component.
    pub restart_policy: RestartPolicy,
    /// Scopes the self-healing subject may use when acting on this component.
    ///
    /// Must be a subset of the subject's pre-authorised grant set; the runtime
    /// adapter will reject out-of-scope actions.
    pub allowed_scopes: Vec<RecoveryMutableScope>,
    /// Fine-grained capability grants for this component.
    ///
    /// Each entry is a specific healing capability (e.g. [`HealingCapability::CanRestartProcess`])
    /// that the self-healing subject is authorized to perform on this component.
    /// Unlike [`RecoveryMutableScope`], capabilities grant exactly what each action
    /// needs — nothing more.  When empty, the runtime falls back to
    /// [`Self::allowed_scopes`] for backward compatibility.
    #[serde(default)]
    pub allowed_capabilities: Vec<HealingCapability>,
    /// Isolation level for this component (Critical / Important / Replaceable).
    ///
    /// When the driver decides an action for this component, the isolation
    /// level gates what the driver is allowed to do: Critical components are
    /// immediately escalated, Important may restart but cannot be killed, and
    /// Replaceable may be hot-swapped without ceremony.
    #[serde(default)]
    pub isolation_level: ComponentIsolationLevel,
    /// Declared restart propagation boundary for this component.
    ///
    /// [`RestartBoundary::ProcessLocal`] restarts only the component process;
    /// [`RestartBoundary::MeshLocal`] also notifies mesh peers to refresh;
    /// [`RestartBoundary::SystemWide`] requires a full recovery cycle.
    #[serde(default)]
    pub restart_boundary: RestartBoundary,
    /// Optional component type tag used for grouping and routing.
    #[serde(default)]
    pub component_type: Option<String>,
}

impl ComponentHealingConfig {
    /// Returns the required [`HealingCapability`] set for each [`HealActionKind`].
    ///
    /// This provides a static, action-to-capability mapping that the self-healing
    /// driver uses to verify the subject holds the necessary grant before execution.
    #[must_use]
    pub fn capabilities_for_action(action_kind: HealActionKind) -> Vec<HealingCapability> {
        match action_kind {
            HealActionKind::Restart | HealActionKind::Failover => {
                vec![HealingCapability::CanRestartProcess]
            }
            HealActionKind::Isolate => vec![HealingCapability::CanIsolateMeshNode],
            HealActionKind::Escalate => vec![HealingCapability::CanEscalateToOperator],
        }
    }
}

impl Default for SelfHealingPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            minimum_mode: RecoveryMode::Recovery,
            component_policies: HashMap::new(),
            default_policy: RestartPolicy::default(),
        }
    }
}

impl SelfHealingPolicy {
    /// Return the effective [`RestartPolicy`] for the given component id.
    #[must_use]
    pub fn policy_for_component(&self, component_id: &str) -> &RestartPolicy {
        self.component_policies
            .get(component_id)
            .map_or(&self.default_policy, |c| &c.restart_policy)
    }

    /// Return the allowed scopes for the given component, or empty if unknown.
    #[must_use]
    pub fn scopes_for_component(&self, component_id: &str) -> Vec<RecoveryMutableScope> {
        self.component_policies
            .get(component_id)
            .map(|c| c.allowed_scopes.clone())
            .unwrap_or_default()
    }

    /// Return the full [`ComponentHealingConfig`] for the given component, if registered.
    #[must_use]
    pub fn config_for_component(&self, component_id: &str) -> Option<&ComponentHealingConfig> {
        self.component_policies.get(component_id)
    }

    /// Validate that the policy does not permit normal-mode healing (INV-012 guard).
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Internal`] when `minimum_mode` is set to `Normal`
    /// because that would allow recovery-only mutations outside of recovery mode.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.minimum_mode == RecoveryMode::Normal && !self.component_policies.is_empty() {
            return Err(RecoveryError::Internal(
                "self-healing policy must not permit Normal-mode mutations (INV-012)".to_owned(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal counters (tracked per component by the driver)
// ---------------------------------------------------------------------------

/// Runtime tracking data for a single component's healing history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentHealingTracker {
    /// Current consecutive failure count since last healthy observation.
    pub consecutive_failures: u32,
    /// Total healing actions performed on this component since boot (or reset).
    pub total_actions: u64,
    /// UTC timestamp of the most recent healing action (if any).
    pub last_action_at: Option<DateTime<Utc>>,
    /// Most recent health observation.
    pub last_observed_state: ComponentHealthState,
    /// BLAKE3 hash of the last known good configuration state.
    ///
    /// Set by [`ComponentHealingTracker::checkpoint`] before a restart action
    /// is attempted.  Used during reincarnation to detect and avoid crash-loops
    /// with corrupted state — if the restored config hash matches a previously
    /// crash-looped hash, the driver escalates instead of restarting again.
    pub checkpoint_hash: Option<String>,
    /// UTC timestamp when the last known good config was captured.
    pub checkpoint_timestamp: Option<DateTime<Utc>>,
}

impl Default for ComponentHealingTracker {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            total_actions: 0,
            last_action_at: None,
            last_observed_state: ComponentHealthState::Unknown,
            checkpoint_hash: None,
            checkpoint_timestamp: None,
        }
    }
}

impl ComponentHealingTracker {
    /// Record a new observation and update internal state.
    pub fn record_observation(&mut self, state: ComponentHealthState) {
        if state.needs_intervention() {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        } else if state == ComponentHealthState::Healthy {
            // Reset on healthy if policy says so
            self.consecutive_failures = 0;
        }
        self.last_observed_state = state;
    }

    /// Record that an action was taken.
    pub fn record_action(&mut self, _sequence: u64) {
        self.total_actions = self.total_actions.saturating_add(1);
        self.last_action_at = Some(Utc::now());
        // Note: we don't reset consecutive_failures here — only healthy obs resets them
    }

    /// Record that a panic was observed for this component.
    ///
    /// Unlike normal failure observation, a panic always bumps the consecutive count
    /// regardless of current state — panics are treated as more severe signals.
    pub fn record_panic(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_observed_state = ComponentHealthState::Failed;
        self.total_actions = self.total_actions.saturating_add(1);
        self.last_action_at = Some(Utc::now());
    }

    /// Capture a last-known-good checkpoint before a restart is attempted.
    ///
    /// Stores the config hash (BLAKE3) and the current UTC timestamp so
    /// the driver can detect crash-loops on reincarnation: if a restored
    /// snapshot carries the same hash as a previous crash, the driver
    /// escalates instead of resetting into the same failure.
    pub fn checkpoint(&mut self, state_hash: &str) {
        self.checkpoint_hash = Some(state_hash.to_owned());
        self.checkpoint_timestamp = Some(Utc::now());
    }
}

// ---------------------------------------------------------------------------
// Component snapshot (MINIX-inspired state preservation)
// ---------------------------------------------------------------------------

/// Immutable snapshot of a component's last-known-good configuration state.
///
/// Captured by the self-healing driver before a restart action is executed.
/// During reincarnation the driver compares the restored snapshot against the
/// crash-loop history; if the same hash appears repeatedly, the driver
/// escalates instead of blindly restarting into the same failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ComponentSnapshot {
    /// Component this snapshot belongs to.
    pub component_id: String,
    /// BLAKE3 hash of the serialized config blob at checkpoint time.
    pub checkpoint_hash: String,
    /// Hex-encoded serialized configuration blob that was hashed.
    ///
    /// The caller decides what constitutes "config" for a given component
    /// type; this field stores the opaque blob that was fed into BLAKE3.
    pub config_blob_hex: String,
    /// UTC timestamp when this snapshot was captured.
    pub captured_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Panic handler pattern (MINIX-inspired structured crash reporting)
// ---------------------------------------------------------------------------

/// Severity classification for a component panic event.
///
/// Mirrors MINIX's distinction between signal-based termination causes:
/// some are recoverable (SIGSEGV handler → restart), others indicate corruption
/// (SIGABRT from assertion → escalate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PanicSeverity {
    /// Graceful unwind / caught panic (Rust `panic = "unwind"`).
    ///
    /// Component caught an unrecoverable error but unwound cleanly.
    /// Recovery strategy: restart with state preservation if possible.
    Unwind,

    /// Process abort (SIGABRT / assertion failure / intentional terminate).
    ///
    /// Indicates a logic invariant violation inside the component.
    /// Recovery strategy: restart BUT flag for post-mortem analysis.
    Abort,

    /// Out-of-memory kill (OOM killer).
    ///
    /// System-level resource exhaustion; restarting immediately may loop.
    /// Recovery strategy: isolate + escalate before attempting restart.
    Oom,

    /// Segfault / bus error / illegal instruction (hardware-level fault).
    ///
    /// Indicates memory corruption or binary incompatibility.
    /// Recovery strategy: isolate + do NOT restart automatically (escalate).
    SigFault,

    /// Unknown or unclassified panic cause.
    ///
    /// Fallback when no structured information is available.
    #[default]
    Unknown,
}

impl PanicSeverity {
    /// Returns `true` if this panic is safe to auto-restart through.
    ///
    /// `Unwind` and `Abort` are considered recoverable; `Oom` and `SigFault`
    /// require escalation because immediate restart would likely re-panic.
    #[must_use]
    pub const fn is_recoverable_by_restart(self) -> bool {
        matches!(self, Self::Unwind | Self::Abort)
    }

    /// Returns `true` if this panic requires escalation without restart attempt.
    #[must_use]
    pub const fn requires_escalation(self) -> bool {
        matches!(self, Self::Oom | Self::SigFault)
    }
}

/// Structured context for a component panic event.
///
/// Captures everything needed for a MINIX-style post-mortem analysis:
/// what happened, where, how severe, and where to find the artefacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PanicContext {
    /// Component id that panicked.
    pub component_id: String,
    /// Classified severity of the panic.
    pub severity: PanicSeverity,
    /// Human-readable panic message or assertion string.
    pub message: String,
    /// Source file where the panic originated (if available).
    pub file: Option<String>,
    /// Line number inside the source file.
    pub line: Option<u32>,
    /// Backtrace hash (BLAKE3 of the symbolised backtrace, not raw addresses).
    ///
    /// Used to deduplicate identical crashes and link to persisted backtrace
    /// storage without embedding megabytes of frame data in evidence JSON.
    pub backtrace_hash: Option<String>,
    /// Reference path to a core dump file (if one was captured).
    ///
    /// Format is intentionally opaque: the runtime adapter decides where dumps
    /// live and how they're named.
    pub core_dump_ref: Option<String>,
    /// UTC timestamp when the panic was observed by the healing driver.
    pub observed_at: DateTime<Utc>,
    /// Number of times this component has panicked consecutively (including this one).
    pub consecutive_panics: u32,
}
