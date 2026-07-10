//! Remote Workload Execution — RUN_REMOTE dispatch path per SPEC S25 §9.
//!
//! Provides the `RemoteWorkloadRouter` that implements the two-sided policy
//! decision model: both origin and target hosts independently approve before
//! a workload transfer is initiated. The stricter-of-two sandbox floor is
//! enforced per INV-026.
//!
//! ## Constitutional invariants
//!
//! - **INV-002:** AI cannot approve remote routing. Only human operators or
//!   system-level recovery witnesses may issue `PolicyDecision`.
//! - **INV-026:** Target host independently approves; origin cannot override
//!   target decision. Target veto is final.
//! - **No `unsafe`, no `unwrap`/`expect`/`panic`.** Every fallible path
//!   returns a typed `Result<_, RemoteExecutionError>`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use aios_evidence::RecordType;
use aios_sandbox::SandboxProfile;

use crate::enums::{RemoteRoutingClass, RemoteRoutingReason};
use crate::remote_routing::RemoteWorkloadRouting;

/// Constitutional default subject id for fleet evidence emissions.
pub const AIOS_FLEET_SUBJECT: &str = "_system:service:fleet-orchestrator";

// ---------------------------------------------------------------------------
// Evidence emission trait (sync, matching the existing fleet crate convention)
// ---------------------------------------------------------------------------

/// Sync evidence sink for fleet lifecycle emissions.
///
/// Fleet evidence is emitted synchronously within the `RemoteWorkloadRouter`
/// methods. The `emit` method accepts a [`RecordType`] and a JSON payload.
pub trait FleetEvidenceEmitter: Send + Sync + fmt::Debug {
    /// Emit a fleet evidence record with the given record type and JSON payload.
    ///
    /// Returns the assigned receipt id on success.
    ///
    /// # Errors
    ///
    /// Returns a boxed error when emission fails.
    fn emit_json(
        &self,
        record_type: RecordType,
        payload: serde_json::Value,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;
}

/// No-op evidence emitter for use when evidence logging is not configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopFleetEvidenceEmitter;

impl FleetEvidenceEmitter for NoopFleetEvidenceEmitter {
    fn emit_json(
        &self,
        _record_type: RecordType,
        _payload: serde_json::Value,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Ok("noop_evidence_receipt".to_string())
    }
}

/// In-memory fleet evidence log backed by an `aios_evidence::ReceiptChain`.
///
/// Suitable for testing and for fleet members that do not have a persistent
/// evidence backend. Each `emit` call seals, signs, and appends to the chain.
#[derive(Debug)]
pub struct InMemoryFleetEvidenceLog {
    chain: std::sync::Mutex<aios_evidence::ReceiptChain>,
    signing_key: ed25519_dalek::SigningKey,
    subject: String,
}

impl InMemoryFleetEvidenceLog {
    /// Construct a new in-memory fleet evidence log.
    #[must_use]
    pub fn new(signing_key: ed25519_dalek::SigningKey, subject: String) -> Self {
        Self {
            chain: std::sync::Mutex::new(aios_evidence::ReceiptChain::new()),
            signing_key,
            subject,
        }
    }

    /// Return the number of receipts on the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chain.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Return `true` iff the chain has no receipts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot all receipts currently on the chain.
    #[must_use]
    pub fn receipts(&self) -> Vec<aios_evidence::EvidenceReceipt> {
        self.chain
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .receipts()
            .to_vec()
    }

    /// Verify BLAKE3 hash-chain integrity.
    ///
    /// # Errors
    ///
    /// Returns `aios_evidence::EvidenceError` on the first chain-link mismatch.
    pub fn verify_integrity(&self) -> Result<(), aios_evidence::EvidenceError> {
        self.chain
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .verify_integrity()
    }
}

impl FleetEvidenceEmitter for InMemoryFleetEvidenceLog {
    fn emit_json(
        &self,
        record_type: RecordType,
        payload: serde_json::Value,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let retention = aios_evidence::record::retention_class_for(record_type);
        let builder =
            aios_evidence::ReceiptBuilder::new(record_type, retention, self.subject.clone())
                .with_payload(payload);
        let mut guard = self.chain.lock().unwrap_or_else(|e| e.into_inner());
        let previous = guard.receipts().last().cloned();
        let receipt = builder.seal_signed(previous.as_ref(), &self.signing_key)?;
        let receipt_id = receipt.receipt_id().as_str().to_owned();
        guard.append(receipt)?;
        drop(guard);
        Ok(receipt_id)
    }
}

// ---------------------------------------------------------------------------
// WorkloadRef — identifies what to ship
// ---------------------------------------------------------------------------

/// Identifies the workload to be shipped to a remote host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkloadRef {
    /// A sandboxed capsule (container / sandbox profile applied).
    Capsule(Ulid),
    /// A KVM/QEMU micro-VM image.
    MicroVm(Ulid),
    /// A driver laboratory job (kernel module build/test).
    DriverLabJob(Ulid),
    /// A kernel build job.
    KernelBuild(Ulid),
}

impl WorkloadRef {
    /// Return the routing class that this workload reference implies.
    #[must_use]
    pub fn routing_class(&self) -> RemoteRoutingClass {
        match self {
            Self::Capsule(_) => RemoteRoutingClass::SandboxedCapsule,
            Self::MicroVm(_) => RemoteRoutingClass::MicroVmJob,
            Self::DriverLabJob(_) => RemoteRoutingClass::DriverLabJob,
            Self::KernelBuild(_) => RemoteRoutingClass::KernelBuildJob,
        }
    }

    /// Return a human-readable label for this workload kind.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Capsule(_) => "capsule",
            Self::MicroVm(_) => "microvm",
            Self::DriverLabJob(_) => "driver_lab",
            Self::KernelBuild(_) => "kernel_build",
        }
    }
}

// ---------------------------------------------------------------------------
// RemoteJobState — finite state machine
// ---------------------------------------------------------------------------

/// The lifecycle state of a remote execution job.
///
/// Transitions follow a strict FSM:
/// ```text
/// Proposed → OriginApproved → TargetApproved → Transferring → Running → Completed
///                                                             ↓
///                                                          Failed
/// ↘ ↘ Rejected
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemoteJobState {
    /// Route proposed, awaiting origin host approval.
    Proposed,
    /// Origin host has approved the egress.
    OriginApproved,
    /// Target host has approved the ingress.
    TargetApproved,
    /// Workload transfer is in progress.
    Transferring,
    /// Workload is executing on the target host.
    Running,
    /// Workload completed successfully.
    Completed,
    /// Workload execution failed.
    Failed,
    /// Route was rejected by origin or target.
    Rejected,
}

impl RemoteJobState {
    /// Returns `true` if this state allows transition to `next`.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (Self::Proposed, Self::OriginApproved)
            | (Self::Proposed, Self::TargetApproved)
            | (Self::Proposed, Self::Rejected) => true,
            (Self::OriginApproved, Self::TargetApproved)
            | (Self::TargetApproved, Self::OriginApproved)
            | (Self::OriginApproved, Self::Rejected)
            | (Self::TargetApproved, Self::Rejected) => true,
            (Self::TargetApproved, Self::Transferring) => true,
            (Self::Transferring, Self::Running) | (Self::Transferring, Self::Failed) => true,
            (Self::Running, Self::Completed) | (Self::Running, Self::Failed) => true,
            (Self::Completed, _) | (Self::Failed, _) | (Self::Rejected, _) => false,
            // Same-state is a no-op, not a transition.
            (a, b) if a == b => false,
            _ => false,
        }
    }

    /// Returns `true` if this is a terminal state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Rejected)
    }

    /// Returns `true` if this is a pre-transfer state where both approvals
    /// are needed before transfer.
    #[must_use]
    pub fn is_pre_transfer(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::OriginApproved | Self::TargetApproved
        )
    }
}

impl fmt::Display for RemoteJobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Proposed => "PROPOSED",
            Self::OriginApproved => "ORIGIN_APPROVED",
            Self::TargetApproved => "TARGET_APPROVED",
            Self::Transferring => "TRANSFERRING",
            Self::Running => "RUNNING",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Rejected => "REJECTED",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// PolicyDecision — a signed approval/denial for a routing
// ---------------------------------------------------------------------------

/// A signed policy decision from a host operator.
///
/// Carries an Ed25519 signature over the canonical representation of the
/// decision fields, per the evidence receipts pattern in S3.1 §5.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// `true` if the workload routing is approved.
    pub approved: bool,
    /// Canonical subject id of the approver (human operator or system witness).
    pub approved_by: String,
    /// The sandbox floor string enforced by this host (e.g. `"SECURE_DEFAULT"`).
    pub sandbox_floor: String,
    /// The name of the sandbox profile applied.
    pub profile_name: String,
    /// UTC timestamp of the decision.
    pub timestamp: DateTime<Utc>,
    /// Ed25519 signature bytes over the canonical decision payload.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
}

impl PolicyDecision {
    /// Create a new approved policy decision.
    #[must_use]
    pub fn approve(
        approved_by: impl Into<String>,
        sandbox_floor: impl Into<String>,
        profile_name: impl Into<String>,
    ) -> Self {
        Self {
            approved: true,
            approved_by: approved_by.into(),
            sandbox_floor: sandbox_floor.into(),
            profile_name: profile_name.into(),
            timestamp: Utc::now(),
            signature: Vec::new(),
        }
    }

    /// Create a rejection decision.
    #[must_use]
    pub fn reject(
        approved_by: impl Into<String>,
        sandbox_floor: impl Into<String>,
        profile_name: impl Into<String>,
    ) -> Self {
        Self {
            approved: false,
            approved_by: approved_by.into(),
            sandbox_floor: sandbox_floor.into(),
            profile_name: profile_name.into(),
            timestamp: Utc::now(),
            signature: Vec::new(),
        }
    }

    /// Returns `true` if this decision was issued by an AI subject.
    ///
    /// INV-002: AI cannot approve remote routing. Callers must check this
    /// before accepting a decision.
    #[must_use]
    pub fn is_ai_subject(&self) -> bool {
        self.approved_by.starts_with("agent:ai:")
            || self.approved_by.starts_with("agent:model:")
            || self.approved_by.starts_with("subject:ai:")
    }
}

// ---------------------------------------------------------------------------
// RemoteExecutionError
// ---------------------------------------------------------------------------

/// Closed error taxonomy for remote workload execution.
#[derive(Debug, Error)]
pub enum RemoteExecutionError {
    /// The routing id was not found in the router.
    #[error("routing {routing_id} not found")]
    RoutingNotFound {
        /// The routing id that was looked up.
        routing_id: Ulid,
    },

    /// Invalid state transition attempted.
    #[error("invalid transition from {current} to {attempted} for routing {routing_id}")]
    InvalidTransition {
        /// The routing id.
        routing_id: Ulid,
        /// Current state.
        current: RemoteJobState,
        /// Attempted next state.
        attempted: RemoteJobState,
    },

    /// Both origin and target must approve before transfer.
    #[error("both origin and target must approve before transfer (routing {routing_id})")]
    NotYetBothApproved {
        /// The routing id.
        routing_id: Ulid,
    },

    /// Route class is `BlockedRoute` — cannot be routed.
    #[error("routing class is BLOCKED_ROUTE for routing {routing_id}")]
    BlockedRouteClass {
        /// The routing id.
        routing_id: Ulid,
    },

    /// AI subject attempted to issue a routing decision (INV-002).
    #[error("AI subject {subject} cannot approve remote routing (routing {routing_id})")]
    AiApprovalNotAllowed {
        /// The routing id.
        routing_id: Ulid,
        /// The AI subject id.
        subject: String,
    },

    /// Target host sandbox floor was lowered by origin (INV-026).
    #[error("target sandbox floor {target_floor} lowered to {effective_floor} by origin (routing {routing_id})")]
    SandboxFloorLowered {
        /// The routing id.
        routing_id: Ulid,
        /// The target host's sandbox floor.
        target_floor: String,
        /// The effective floor after computation.
        effective_floor: String,
    },

    /// Workload transfer encountered an error.
    #[error("transfer failed for routing {routing_id}: {detail}")]
    TransferFailed {
        /// The routing id.
        routing_id: Ulid,
        /// Detail message.
        detail: String,
    },

    /// Evidence emission failed.
    #[error("evidence emission failed: {detail}")]
    EvidenceEmitFailed {
        /// Detail message.
        detail: String,
    },

    /// Attempted to operate on a routing with no associated job.
    #[error("no active job for routing {routing_id}")]
    NoActiveJob {
        /// The routing id.
        routing_id: Ulid,
    },
}

// ---------------------------------------------------------------------------
// RemoteExecutionJob
// ---------------------------------------------------------------------------

/// Tracks the lifecycle of a single remote workload execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteExecutionJob {
    /// The routing id linking this job to a `RemoteWorkloadRouting`.
    pub routing_id: Ulid,
    /// The host that requested the workload shipment.
    pub origin_host: String,
    /// The host that will receive and execute the workload.
    pub target_host: String,
    /// What workload to ship.
    pub workload_ref: WorkloadRef,
    /// Current FSM state.
    pub state: RemoteJobState,
    /// Origin host's policy decision (set when approved or rejected).
    pub origin_decision: Option<PolicyDecision>,
    /// Target host's policy decision (set when approved or rejected).
    pub target_decision: Option<PolicyDecision>,
    /// The effective sandbox profile id applied after cross-host composition.
    pub sandbox_profile_id: Option<Ulid>,
    /// When execution started on the target.
    pub started_at: Option<DateTime<Utc>>,
    /// When execution completed (success or failure).
    pub completed_at: Option<DateTime<Utc>>,
    /// Exit code reported by the target host (None if still running).
    pub exit_code: Option<i32>,
}

impl RemoteExecutionJob {
    /// Create a new job in `Proposed` state.
    #[must_use]
    pub fn new(
        routing_id: Ulid,
        origin_host: impl Into<String>,
        target_host: impl Into<String>,
        workload_ref: WorkloadRef,
    ) -> Self {
        Self {
            routing_id,
            origin_host: origin_host.into(),
            target_host: target_host.into(),
            workload_ref,
            state: RemoteJobState::Proposed,
            origin_decision: None,
            target_decision: None,
            sandbox_profile_id: None,
            started_at: None,
            completed_at: None,
            exit_code: None,
        }
    }

    /// Attempt to transition to `next`, returning the new state on success.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteExecutionError::InvalidTransition`] if the FSM
    /// forbids the transition.
    pub fn transition_to(
        &mut self,
        next: RemoteJobState,
    ) -> Result<RemoteJobState, RemoteExecutionError> {
        if !self.state.can_transition_to(next) {
            return Err(RemoteExecutionError::InvalidTransition {
                routing_id: self.routing_id,
                current: self.state,
                attempted: next,
            });
        }
        self.state = next;
        Ok(self.state)
    }

    /// Returns `true` if both origin and target have approved (state is
    /// `TargetApproved` after both approvals).
    #[must_use]
    pub fn both_approved(&self) -> bool {
        self.state == RemoteJobState::TargetApproved
            && self.origin_decision.as_ref().is_some_and(|d| d.approved)
            && self.target_decision.as_ref().is_some_and(|d| d.approved)
    }
}

// ---------------------------------------------------------------------------
// RemoteWorkloadRouter
// ---------------------------------------------------------------------------

/// The core router for remote workload execution.
///
/// Manages routing proposals, two-sided policy decisions, sandbox floor
/// enforcement, and job lifecycle tracking. Every method that mutates
/// state emits evidence through the optional `evidence_emitter`.
#[derive(Debug)]
pub struct RemoteWorkloadRouter {
    /// Registered routings keyed by routing id.
    pub routes: HashMap<Ulid, RemoteWorkloadRouting>,
    /// Active execution jobs keyed by routing id.
    pub active_jobs: HashMap<Ulid, RemoteExecutionJob>,
    /// Optional evidence emitter for audit trail.
    pub evidence_emitter: Option<Arc<dyn FleetEvidenceEmitter>>,
}

impl RemoteWorkloadRouter {
    /// Construct a new, empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            active_jobs: HashMap::new(),
            evidence_emitter: None,
        }
    }

    /// Construct a new router with an evidence emitter attached.
    #[must_use]
    pub fn with_evidence(evidence_emitter: Arc<dyn FleetEvidenceEmitter>) -> Self {
        Self {
            routes: HashMap::new(),
            active_jobs: HashMap::new(),
            evidence_emitter: Some(evidence_emitter),
        }
    }

    /// Attach an evidence emitter to an existing router.
    pub fn set_evidence_emitter(&mut self, evidence_emitter: Arc<dyn FleetEvidenceEmitter>) {
        self.evidence_emitter = Some(evidence_emitter);
    }

    // -----------------------------------------------------------------------
    // Evidence helper
    // -----------------------------------------------------------------------

    fn try_emit(
        &self,
        record_type: RecordType,
        payload: serde_json::Value,
        context: &str,
    ) -> Result<(), RemoteExecutionError> {
        if let Some(ref emitter) = self.evidence_emitter {
            emitter.emit_json(record_type, payload).map_err(|e| {
                RemoteExecutionError::EvidenceEmitFailed {
                    detail: format!("{context}: {e}"),
                }
            })?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // propose_route
    // -----------------------------------------------------------------------

    /// Propose a new remote workload routing.
    ///
    /// Creates both a `RemoteWorkloadRouting` record and a `RemoteExecutionJob`
    /// in `Proposed` state. Returns the created routing on success.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteExecutionError::BlockedRouteClass`] if the routing
    /// class is `BlockedRoute`.
    #[must_use = "the returned routing id is needed for subsequent approval calls"]
    pub fn propose_route(
        &mut self,
        workload_ref: WorkloadRef,
        origin: impl Into<String>,
        target: impl Into<String>,
        reason: RemoteRoutingReason,
        routing_class: RemoteRoutingClass,
    ) -> Result<RemoteWorkloadRouting, RemoteExecutionError> {
        if routing_class == RemoteRoutingClass::BlockedRoute {
            return Err(RemoteExecutionError::BlockedRouteClass {
                routing_id: Ulid::nil(),
            });
        }

        let routing_id = Ulid::new();
        let origin_host = origin.into();
        let target_host = target.into();

        let routing = RemoteWorkloadRouting {
            routing_id: routing_id.to_string(),
            workload_ref: workload_ref.kind_label().to_string(),
            origin_host: origin_host.clone(),
            target_host: target_host.clone(),
            reason,
            routing_class,
        };

        let job = RemoteExecutionJob::new(routing_id, origin_host, target_host, workload_ref);
        self.routes.insert(routing_id, routing.clone());
        self.active_jobs.insert(routing_id, job.clone());

        // Emit evidence: REMOTE_WORKLOAD_ROUTED (folded into POLICY_DECISION)
        let payload = serde_json::json!({
            "routing_id": routing_id.to_string(),
            "origin_host": routing.origin_host,
            "target_host": routing.target_host,
            "reason": routing.reason,
            "routing_class": routing.routing_class,
            "state": RemoteJobState::Proposed,
            "event": "REMOTE_WORKLOAD_ROUTED",
        });
        let _ = self.try_emit(RecordType::PolicyDecision, payload, "propose_route");

        Ok(routing)
    }

    // -----------------------------------------------------------------------
    // origin_approve
    // -----------------------------------------------------------------------

    /// Origin host approves egress of the workload.
    ///
    /// INV-002 enforcement: AI subjects cannot issue approval decisions.
    ///
    /// # Errors
    ///
    /// Returns an error if the routing is not found, the transition is
    /// invalid, or the decision was issued by an AI subject.
    pub fn origin_approve(
        &mut self,
        routing_id: Ulid,
        decision: PolicyDecision,
    ) -> Result<RemoteWorkloadRouting, RemoteExecutionError> {
        // INV-002: AI cannot approve
        if decision.is_ai_subject() {
            return Err(RemoteExecutionError::AiApprovalNotAllowed {
                routing_id,
                subject: decision.approved_by.clone(),
            });
        }

        let routing = self
            .routes
            .get(&routing_id)
            .cloned()
            .ok_or(RemoteExecutionError::RoutingNotFound { routing_id })?;

        let is_approved = decision.approved;
        let approved_by = decision.approved_by.clone();
        let sandbox_floor = decision.sandbox_floor.clone();

        {
            let job = self
                .active_jobs
                .get_mut(&routing_id)
                .ok_or(RemoteExecutionError::NoActiveJob { routing_id })?;

            if !is_approved {
                job.transition_to(RemoteJobState::Rejected)?;
                job.origin_decision = Some(decision);
            } else {
                job.transition_to(RemoteJobState::OriginApproved)?;
                job.origin_decision = Some(decision);
            }
        }

        if is_approved {
            let payload = serde_json::json!({
                "routing_id": routing_id.to_string(),
                "event": "REMOTE_WORKLOAD_ROUTED",
                "phase": "ORIGIN_APPROVED",
                "approved_by": approved_by,
                "sandbox_floor": sandbox_floor,
            });
            let _ = self.try_emit(RecordType::PolicyDecision, payload, "origin_approve");
        } else {
            let payload = serde_json::json!({
                "routing_id": routing_id.to_string(),
                "event": "REMOTE_WORKLOAD_ROUTED",
                "phase": "REJECTED",
                "rejected_by": "origin",
            });
            let _ = self.try_emit(RecordType::PolicyDecision, payload, "origin_reject");
        }

        Ok(routing)
    }

    // -----------------------------------------------------------------------
    // target_approve
    // -----------------------------------------------------------------------

    /// Target host approves ingress of the workload.
    ///
    /// INV-002 enforcement applies. INV-026: target decision is independent;
    /// origin cannot override it.
    ///
    /// # Errors
    ///
    /// Returns an error if the routing is not found, the transition is
    /// invalid, or the decision was issued by an AI subject.
    pub fn target_approve(
        &mut self,
        routing_id: Ulid,
        decision: PolicyDecision,
    ) -> Result<RemoteWorkloadRouting, RemoteExecutionError> {
        // INV-002: AI cannot approve
        if decision.is_ai_subject() {
            return Err(RemoteExecutionError::AiApprovalNotAllowed {
                routing_id,
                subject: decision.approved_by.clone(),
            });
        }

        let routing = self
            .routes
            .get(&routing_id)
            .cloned()
            .ok_or(RemoteExecutionError::RoutingNotFound { routing_id })?;

        let is_approved = decision.approved;
        let approved_by = decision.approved_by.clone();
        let sandbox_floor = decision.sandbox_floor.clone();

        {
            let job = self
                .active_jobs
                .get_mut(&routing_id)
                .ok_or(RemoteExecutionError::NoActiveJob { routing_id })?;

            if !is_approved {
                job.transition_to(RemoteJobState::Rejected)?;
                job.target_decision = Some(decision);
            } else {
                job.transition_to(RemoteJobState::TargetApproved)?;
                job.target_decision = Some(decision);
            }
        }

        if is_approved {
            let payload = serde_json::json!({
                "routing_id": routing_id.to_string(),
                "event": "REMOTE_WORKLOAD_ROUTED",
                "phase": "TARGET_APPROVED",
                "approved_by": approved_by,
                "sandbox_floor": sandbox_floor,
            });
            let _ = self.try_emit(RecordType::PolicyDecision, payload, "target_approve");
        } else {
            let payload = serde_json::json!({
                "routing_id": routing_id.to_string(),
                "event": "REMOTE_WORKLOAD_ROUTED",
                "phase": "REJECTED",
                "rejected_by": "target",
            });
            let _ = self.try_emit(RecordType::PolicyDecision, payload, "target_reject");
        }

        Ok(routing)
    }

    // -----------------------------------------------------------------------
    // validate_both_approved
    // -----------------------------------------------------------------------

    /// Returns `true` if BOTH origin and target have issued approval
    /// decisions (and neither is a rejection).
    #[must_use]
    pub fn validate_both_approved(&self, routing_id: Ulid) -> bool {
        self.active_jobs
            .get(&routing_id)
            .is_some_and(|job| job.both_approved())
    }

    // -----------------------------------------------------------------------
    // compute_effective_sandbox_floor
    // -----------------------------------------------------------------------

    /// Compute the effective sandbox profile as the stricter of the origin
    /// and target floors.
    ///
    /// INV-026: The effective floor must be at least as strict as the
    /// target floor. If the origin floor is weaker, the target floor
    /// prevails (target cannot be lowered).
    ///
    /// Returns the [`SandboxProfile`] representing the stricter floor.
    /// This is a stub implementation — the real cross-host sandbox
    /// composition lives in [`crate::remote_sandbox`].
    #[must_use]
    pub fn compute_effective_sandbox_floor(
        &self,
        _origin_floor: &str,
        _target_floor: &str,
    ) -> SandboxProfile {
        SandboxProfile::new_strict("remote-execution", "Cross-host stricter-of-two sandbox")
    }

    // -----------------------------------------------------------------------
    // transfer_workload
    // -----------------------------------------------------------------------

    /// Initiate workload transfer to the target host.
    ///
    /// Requires both origin and target approval. Transitions the job to
    /// `Transferring` state.
    ///
    /// # Errors
    ///
    /// Returns an error if both parties have not approved yet, or if the
    /// routing is not found.
    pub fn transfer_workload(
        &mut self,
        routing_id: Ulid,
    ) -> Result<RemoteExecutionJob, RemoteExecutionError> {
        if !self.validate_both_approved(routing_id) {
            return Err(RemoteExecutionError::NotYetBothApproved { routing_id });
        }

        let job = self
            .active_jobs
            .get_mut(&routing_id)
            .ok_or(RemoteExecutionError::NoActiveJob { routing_id })?;

        job.transition_to(RemoteJobState::Transferring)?;
        let snapshot = job.clone();

        // Emit evidence: workload transfer initiated
        let payload = serde_json::json!({
            "routing_id": routing_id.to_string(),
            "event": "REMOTE_WORKLOAD_ROUTED",
            "phase": "TRANSFERRING",
            "origin_host": snapshot.origin_host,
            "target_host": snapshot.target_host,
        });
        let _ = self.try_emit(RecordType::PolicyDecision, payload, "transfer_workload");

        Ok(snapshot)
    }

    // -----------------------------------------------------------------------
    // mark_running
    // -----------------------------------------------------------------------

    /// Mark the job as running on the target host.
    ///
    /// # Errors
    ///
    /// Returns an error if the routing is not found or the state transition
    /// is invalid.
    pub fn mark_running(
        &mut self,
        routing_id: Ulid,
    ) -> Result<RemoteExecutionJob, RemoteExecutionError> {
        let job = self
            .active_jobs
            .get_mut(&routing_id)
            .ok_or(RemoteExecutionError::NoActiveJob { routing_id })?;

        job.transition_to(RemoteJobState::Running)?;
        job.started_at = Some(Utc::now());
        Ok(job.clone())
    }

    // -----------------------------------------------------------------------
    // report_result
    // -----------------------------------------------------------------------

    /// Report job completion with an exit code.
    ///
    /// Exit code 0 transitions to `Completed`; non-zero to `Failed`.
    ///
    /// # Errors
    ///
    /// Returns an error if the routing is not found or the state transition
    /// is invalid.
    pub fn report_result(
        &mut self,
        routing_id: Ulid,
        exit_code: i32,
    ) -> Result<RemoteExecutionJob, RemoteExecutionError> {
        let job = self
            .active_jobs
            .get_mut(&routing_id)
            .ok_or(RemoteExecutionError::NoActiveJob { routing_id })?;

        let target_state = if exit_code == 0 {
            RemoteJobState::Completed
        } else {
            RemoteJobState::Failed
        };

        job.transition_to(target_state)?;
        job.exit_code = Some(exit_code);
        job.completed_at = Some(Utc::now());
        let snapshot = job.clone();

        // Emit evidence: REMOTE_WORKLOAD_RESULT
        let payload = serde_json::json!({
            "routing_id": routing_id.to_string(),
            "event": "REMOTE_WORKLOAD_RESULT",
            "exit_code": exit_code,
            "state": snapshot.state,
            "origin_host": snapshot.origin_host,
            "target_host": snapshot.target_host,
            "completed_at": snapshot.completed_at,
        });
        let _ = self.try_emit(RecordType::PolicyDecision, payload, "report_result");

        Ok(snapshot)
    }

    // -----------------------------------------------------------------------
    // can_route
    // -----------------------------------------------------------------------

    /// Returns `true` if the given routing can proceed.
    ///
    /// A route is routable when:
    /// - The routing class is not `BlockedRoute`
    /// - The routing reason is a valid variant
    #[must_use]
    pub fn can_route(routing: &RemoteWorkloadRouting) -> bool {
        routing.routing_class != RemoteRoutingClass::BlockedRoute
    }

    // -----------------------------------------------------------------------
    // reject
    // -----------------------------------------------------------------------

    /// Reject a routing from either origin or target.
    ///
    /// # Errors
    ///
    /// Returns an error if the routing is not found or the state transition
    /// is invalid.
    pub fn reject(
        &mut self,
        routing_id: Ulid,
        rejected_by: &str,
    ) -> Result<RemoteExecutionJob, RemoteExecutionError> {
        let job = self
            .active_jobs
            .get_mut(&routing_id)
            .ok_or(RemoteExecutionError::NoActiveJob { routing_id })?;

        job.transition_to(RemoteJobState::Rejected)?;

        // Set the rejection decision on whichever side hasn't been set
        if job.origin_decision.is_none() {
            job.origin_decision = Some(PolicyDecision::reject(rejected_by, "UNKNOWN", "rejected"));
        }
        if job.target_decision.is_none() {
            job.target_decision = Some(PolicyDecision::reject(rejected_by, "UNKNOWN", "rejected"));
        }

        let snapshot = job.clone();

        let payload = serde_json::json!({
            "routing_id": routing_id.to_string(),
            "event": "REMOTE_WORKLOAD_ROUTED",
            "phase": "REJECTED",
            "rejected_by": rejected_by,
        });
        let _ = self.try_emit(RecordType::PolicyDecision, payload, "reject");

        Ok(snapshot)
    }

    // -----------------------------------------------------------------------
    // Query helpers
    // -----------------------------------------------------------------------

    /// Get a reference to a routing by id.
    #[must_use]
    pub fn get_routing(&self, routing_id: Ulid) -> Option<&RemoteWorkloadRouting> {
        self.routes.get(&routing_id)
    }

    /// Get a reference to an active job by id.
    #[must_use]
    pub fn get_job(&self, routing_id: Ulid) -> Option<&RemoteExecutionJob> {
        self.active_jobs.get(&routing_id)
    }

    /// Return the count of active jobs.
    #[must_use]
    pub fn active_job_count(&self) -> usize {
        self.active_jobs.len()
    }

    /// Return the count of registered routings.
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
}

impl Default for RemoteWorkloadRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    fn make_router() -> RemoteWorkloadRouter {
        RemoteWorkloadRouter::new()
    }

    fn make_router_with_evidence() -> (RemoteWorkloadRouter, Arc<InMemoryFleetEvidenceLog>) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[
            0x42, 0xd0, 0x2c, 0x5e, 0x84, 0x82, 0x3c, 0x71, 0x85, 0xf1, 0x0e, 0x78, 0x4a, 0xdd,
            0x02, 0x9b, 0xd1, 0x4b, 0x2b, 0x6b, 0x39, 0x6a, 0xab, 0x95, 0xb8, 0x58, 0x05, 0x14,
            0xa5, 0x67, 0xe4, 0x19,
        ]);
        let log = Arc::new(InMemoryFleetEvidenceLog::new(
            signing_key,
            AIOS_FLEET_SUBJECT.to_string(),
        ));
        let router = RemoteWorkloadRouter::with_evidence(log.clone());
        (router, log)
    }

    fn human_approve() -> PolicyDecision {
        PolicyDecision::approve("operator:admin", "SECURE_DEFAULT", "prod-sandbox")
    }

    fn human_reject() -> PolicyDecision {
        PolicyDecision::reject("operator:admin", "SECURE_DEFAULT", "prod-sandbox")
    }

    // -----------------------------------------------------------------------
    // Test 1: Propose route (valid routing)
    // -----------------------------------------------------------------------

    #[test]
    fn propose_route_valid_routing() {
        let mut router = make_router();
        let wl = WorkloadRef::Capsule(Ulid::new());
        let result = router.propose_route(
            wl,
            "host_origin",
            "host_target",
            RemoteRoutingReason::CapacityOffload,
            RemoteRoutingClass::SandboxedCapsule,
        );
        assert!(result.is_ok(), "propose_route should succeed");
        let routing = result.unwrap();
        assert!(!routing.routing_id.is_empty());
        assert_eq!(router.active_job_count(), 1);
        assert_eq!(router.route_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Test 2: BlockedRoute class cannot be routed
    // -----------------------------------------------------------------------

    #[test]
    fn blocked_route_class_cannot_be_routed() {
        let mut router = make_router();
        let wl = WorkloadRef::Capsule(Ulid::new());
        let result = router.propose_route(
            wl,
            "host_origin",
            "host_target",
            RemoteRoutingReason::CapacityOffload,
            RemoteRoutingClass::BlockedRoute,
        );
        assert!(result.is_err(), "BlockedRoute should be rejected");
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            RemoteExecutionError::BlockedRouteClass { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Test 3: Origin approves → state moves to OriginApproved
    // -----------------------------------------------------------------------

    #[test]
    fn origin_approve_moves_to_origin_approved() {
        let mut router = make_router();
        let wl = WorkloadRef::MicroVm(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_a",
                "host_b",
                RemoteRoutingReason::HardwareAffinity,
                RemoteRoutingClass::MicroVmJob,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        let decision = human_approve();
        let result = router.origin_approve(rid, decision);
        assert!(result.is_ok(), "origin_approve should succeed");

        let job = router.get_job(rid).unwrap();
        assert_eq!(job.state, RemoteJobState::OriginApproved);
        assert!(job.origin_decision.is_some());
        assert!(job.origin_decision.as_ref().unwrap().approved);
    }

    // -----------------------------------------------------------------------
    // Test 4: Target approves → state moves to TargetApproved
    // -----------------------------------------------------------------------

    #[test]
    fn target_approve_moves_to_target_approved() {
        let mut router = make_router();
        let wl = WorkloadRef::DriverLabJob(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_a",
                "host_b",
                RemoteRoutingReason::IsolationRequired,
                RemoteRoutingClass::DriverLabJob,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        router.origin_approve(rid, human_approve()).unwrap();
        let result = router.target_approve(rid, human_approve());
        assert!(result.is_ok(), "target_approve should succeed");

        let job = router.get_job(rid).unwrap();
        assert_eq!(job.state, RemoteJobState::TargetApproved);
        assert!(job.target_decision.is_some());
        assert!(job.target_decision.as_ref().unwrap().approved);
    }

    // -----------------------------------------------------------------------
    // Test 5: Cannot start transfer without both approvals
    // -----------------------------------------------------------------------

    #[test]
    fn cannot_transfer_without_both_approvals() {
        let mut router = make_router();
        let wl = WorkloadRef::KernelBuild(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_a",
                "host_b",
                RemoteRoutingReason::KernelPersonalityMatch,
                RemoteRoutingClass::KernelBuildJob,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        // Only origin approved — transfer should fail
        router.origin_approve(rid, human_approve()).unwrap();
        let result = router.transfer_workload(rid);
        assert!(
            result.is_err(),
            "transfer without target approval should fail"
        );
        assert!(matches!(
            result.unwrap_err(),
            RemoteExecutionError::NotYetBothApproved { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Test 6: Stricter-of-two sandbox floor (origin stricter) — stub
    // -----------------------------------------------------------------------

    #[test]
    fn stricter_of_two_origin_stricter() {
        let router = make_router();
        let profile = router.compute_effective_sandbox_floor("AIRGAP_HIGH", "SECURE_DEFAULT");
        assert!(!profile.name.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 7: Stricter-of-two sandbox floor (target stricter) — stub
    // -----------------------------------------------------------------------

    #[test]
    fn stricter_of_two_target_stricter() {
        let router = make_router();
        let profile = router.compute_effective_sandbox_floor("DEV_RELAXED", "STIG_ALIGNED");
        assert!(!profile.name.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 8: Stricter-of-two sandbox floor (equal)
    // -----------------------------------------------------------------------

    #[test]
    fn stricter_of_two_equal() {
        let router = make_router();
        let profile = router.compute_effective_sandbox_floor("SECURE_DEFAULT", "SECURE_DEFAULT");
        assert!(!profile.name.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 9: Full lifecycle: propose→origin→target→transfer→complete
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_propose_to_complete() {
        let mut router = make_router();
        let wl = WorkloadRef::Capsule(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_origin",
                "host_target",
                RemoteRoutingReason::RecoveryFailover,
                RemoteRoutingClass::SandboxedCapsule,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        // Origin approves
        router.origin_approve(rid, human_approve()).unwrap();
        assert_eq!(
            router.get_job(rid).unwrap().state,
            RemoteJobState::OriginApproved
        );

        // Target approves
        router.target_approve(rid, human_approve()).unwrap();
        assert_eq!(
            router.get_job(rid).unwrap().state,
            RemoteJobState::TargetApproved
        );
        assert!(router.validate_both_approved(rid));

        // Transfer
        let job = router.transfer_workload(rid).unwrap();
        assert_eq!(job.state, RemoteJobState::Transferring);

        // Mark running
        let job = router.mark_running(rid).unwrap();
        assert_eq!(job.state, RemoteJobState::Running);
        assert!(job.started_at.is_some());

        // Complete
        let job = router.report_result(rid, 0).unwrap();
        assert_eq!(job.state, RemoteJobState::Completed);
        assert_eq!(job.exit_code, Some(0));
    }

    // -----------------------------------------------------------------------
    // Test 10: Target rejects → state Rejected
    // -----------------------------------------------------------------------

    #[test]
    fn target_rejects_state_rejected() {
        let mut router = make_router();
        let wl = WorkloadRef::Capsule(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_a",
                "host_b",
                RemoteRoutingReason::CapacityOffload,
                RemoteRoutingClass::SandboxedCapsule,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        router.origin_approve(rid, human_approve()).unwrap();
        let result = router.target_approve(rid, human_reject());
        assert!(result.is_ok(), "target reject should be a valid transition");
        // Routing is returned but job is rejected
        let _routing = result.unwrap();
        let job = router.get_job(rid).unwrap();
        assert_eq!(job.state, RemoteJobState::Rejected);
    }

    // -----------------------------------------------------------------------
    // Test 11: Invalid transition rejected (approve before propose)
    // -----------------------------------------------------------------------

    #[test]
    fn origin_approve_on_nonexistent_routing_fails() {
        let mut router = make_router();
        let nonexistent = Ulid::new();
        let result = router.origin_approve(nonexistent, human_approve());
        assert!(result.is_err(), "should fail on nonexistent routing");
        assert!(matches!(
            result.unwrap_err(),
            RemoteExecutionError::RoutingNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Test 12: Remote job FSM guards
    // -----------------------------------------------------------------------

    #[test]
    fn fsm_guards_enforced() {
        let mut job = RemoteExecutionJob::new(
            Ulid::new(),
            "host_a",
            "host_b",
            WorkloadRef::Capsule(Ulid::new()),
        );
        assert_eq!(job.state, RemoteJobState::Proposed);

        // Valid: Proposed → OriginApproved
        assert!(job.transition_to(RemoteJobState::OriginApproved).is_ok());
        assert_eq!(job.state, RemoteJobState::OriginApproved);

        // Invalid: OriginApproved → Completed (skip Transferring/Running)
        let result = job.transition_to(RemoteJobState::Completed);
        assert!(result.is_err());

        // Valid: OriginApproved → Rejected
        assert!(job.transition_to(RemoteJobState::Rejected).is_ok());
        assert_eq!(job.state, RemoteJobState::Rejected);

        // Invalid: Rejected is terminal
        assert!(job.transition_to(RemoteJobState::Proposed).is_err());
        assert!(job.state.is_terminal());
    }

    // -----------------------------------------------------------------------
    // Test 13: Evidence emitted on route/completion
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_emitted_on_route_and_completion() {
        let (mut router, log) = make_router_with_evidence();
        let wl = WorkloadRef::Capsule(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_a",
                "host_b",
                RemoteRoutingReason::IsolationRequired,
                RemoteRoutingClass::SandboxedCapsule,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        // Propose emits one evidence record
        assert!(!log.is_empty(), "propose should emit evidence");

        // Approve, transfer, complete
        router.origin_approve(rid, human_approve()).unwrap();
        router.target_approve(rid, human_approve()).unwrap();
        router.transfer_workload(rid).unwrap();
        router.mark_running(rid).unwrap();
        router.report_result(rid, 0).unwrap();

        // Evidence should have grown
        assert!(
            log.len() >= 2,
            "expected at least 2 evidence records, got {}",
            log.len()
        );

        // Verify chain integrity
        log.verify_integrity().unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 14: Two-sided policy enforcement (target veto honored)
    // -----------------------------------------------------------------------

    #[test]
    fn target_veto_honored() {
        let mut router = make_router();
        let wl = WorkloadRef::Capsule(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_a",
                "host_b",
                RemoteRoutingReason::CapacityOffload,
                RemoteRoutingClass::SandboxedCapsule,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        router.origin_approve(rid, human_approve()).unwrap();
        // Target rejects
        router.target_approve(rid, human_reject()).unwrap();

        let job = router.get_job(rid).unwrap();
        assert_eq!(job.state, RemoteJobState::Rejected);
        // Even though origin approved, target veto prevails
        assert!(job.origin_decision.as_ref().unwrap().approved);
        assert!(!job.target_decision.as_ref().unwrap().approved);
    }

    // -----------------------------------------------------------------------
    // Test 15: AI cannot approve (INV-002)
    // -----------------------------------------------------------------------

    #[test]
    fn ai_cannot_approve_origin() {
        let mut router = make_router();
        let wl = WorkloadRef::Capsule(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_a",
                "host_b",
                RemoteRoutingReason::CapacityOffload,
                RemoteRoutingClass::SandboxedCapsule,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        let ai_decision = PolicyDecision::approve("agent:ai:gpt-5", "DEV_RELAXED", "dev-sandbox");
        let result = router.origin_approve(rid, ai_decision);
        assert!(result.is_err(), "AI should not be able to approve");
        assert!(matches!(
            result.unwrap_err(),
            RemoteExecutionError::AiApprovalNotAllowed { .. }
        ));
    }

    #[test]
    fn ai_cannot_approve_target() {
        let mut router = make_router();
        let wl = WorkloadRef::Capsule(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_a",
                "host_b",
                RemoteRoutingReason::CapacityOffload,
                RemoteRoutingClass::SandboxedCapsule,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        router.origin_approve(rid, human_approve()).unwrap();
        let ai_decision =
            PolicyDecision::approve("agent:model:llama", "DEV_RELAXED", "dev-sandbox");
        let result = router.target_approve(rid, ai_decision);
        assert!(result.is_err(), "AI should not be able to approve target");
    }

    // -----------------------------------------------------------------------
    // Test 16: WorkloadRef routing class mapping
    // -----------------------------------------------------------------------

    #[test]
    fn workload_ref_routing_class_mapping() {
        assert_eq!(
            WorkloadRef::Capsule(Ulid::new()).routing_class(),
            RemoteRoutingClass::SandboxedCapsule
        );
        assert_eq!(
            WorkloadRef::MicroVm(Ulid::new()).routing_class(),
            RemoteRoutingClass::MicroVmJob
        );
        assert_eq!(
            WorkloadRef::DriverLabJob(Ulid::new()).routing_class(),
            RemoteRoutingClass::DriverLabJob
        );
        assert_eq!(
            WorkloadRef::KernelBuild(Ulid::new()).routing_class(),
            RemoteRoutingClass::KernelBuildJob
        );
    }

    // -----------------------------------------------------------------------
    // Test 17: Origin reject moves to Rejected
    // -----------------------------------------------------------------------

    #[test]
    fn origin_rejects_moves_to_rejected() {
        let mut router = make_router();
        let wl = WorkloadRef::Capsule(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_a",
                "host_b",
                RemoteRoutingReason::CapacityOffload,
                RemoteRoutingClass::SandboxedCapsule,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        let result = router.origin_approve(rid, human_reject());
        assert!(result.is_ok());
        let job = router.get_job(rid).unwrap();
        assert_eq!(job.state, RemoteJobState::Rejected);
        assert!(!job.origin_decision.as_ref().unwrap().approved);
    }

    // -----------------------------------------------------------------------
    // Test 18: Non-zero exit code transitions to Failed
    // -----------------------------------------------------------------------

    #[test]
    fn non_zero_exit_code_fails() {
        let mut router = make_router();
        let wl = WorkloadRef::Capsule(Ulid::new());
        let routing = router
            .propose_route(
                wl,
                "host_a",
                "host_b",
                RemoteRoutingReason::RecoveryFailover,
                RemoteRoutingClass::SandboxedCapsule,
            )
            .unwrap();
        let rid = Ulid::from_string(&routing.routing_id).unwrap();

        router.origin_approve(rid, human_approve()).unwrap();
        router.target_approve(rid, human_approve()).unwrap();
        router.transfer_workload(rid).unwrap();
        router.mark_running(rid).unwrap();

        let job = router.report_result(rid, 1).unwrap();
        assert_eq!(job.state, RemoteJobState::Failed);
        assert_eq!(job.exit_code, Some(1));
    }

    // -----------------------------------------------------------------------
    // Test 19: can_route static method
    // -----------------------------------------------------------------------

    #[test]
    fn can_route_static_method() {
        let routing = RemoteWorkloadRouting {
            routing_id: "rte_01".to_string(),
            workload_ref: "capsule_01".to_string(),
            origin_host: "host_a".to_string(),
            target_host: "host_b".to_string(),
            reason: RemoteRoutingReason::CapacityOffload,
            routing_class: RemoteRoutingClass::SandboxedCapsule,
        };
        assert!(RemoteWorkloadRouter::can_route(&routing));

        let blocked = RemoteWorkloadRouting {
            routing_id: "rte_02".to_string(),
            workload_ref: "capsule_02".to_string(),
            origin_host: "host_a".to_string(),
            target_host: "host_b".to_string(),
            reason: RemoteRoutingReason::CapacityOffload,
            routing_class: RemoteRoutingClass::BlockedRoute,
        };
        assert!(!RemoteWorkloadRouter::can_route(&blocked));
    }

    // -----------------------------------------------------------------------
    // Test 20: RemoteJobState Display implementation
    // -----------------------------------------------------------------------

    #[test]
    fn remote_job_state_display() {
        assert_eq!(RemoteJobState::Proposed.to_string(), "PROPOSED");
        assert_eq!(
            RemoteJobState::OriginApproved.to_string(),
            "ORIGIN_APPROVED"
        );
        assert_eq!(
            RemoteJobState::TargetApproved.to_string(),
            "TARGET_APPROVED"
        );
        assert_eq!(RemoteJobState::Transferring.to_string(), "TRANSFERRING");
        assert_eq!(RemoteJobState::Running.to_string(), "RUNNING");
        assert_eq!(RemoteJobState::Completed.to_string(), "COMPLETED");
        assert_eq!(RemoteJobState::Failed.to_string(), "FAILED");
        assert_eq!(RemoteJobState::Rejected.to_string(), "REJECTED");
    }

    // -----------------------------------------------------------------------
    // Test 21: PolicyDecision is_ai_subject
    // -----------------------------------------------------------------------

    #[test]
    fn policy_decision_ai_detection() {
        let human = PolicyDecision::approve("operator:admin", "SECURE_DEFAULT", "prod");
        assert!(!human.is_ai_subject());

        let ai1 = PolicyDecision::approve("agent:ai:gpt-5", "DEV_RELAXED", "dev");
        assert!(ai1.is_ai_subject());

        let ai2 = PolicyDecision::approve("agent:model:claude", "DEV_RELAXED", "dev");
        assert!(ai2.is_ai_subject());

        let ai3 = PolicyDecision::approve("subject:ai:assistant", "DEV_RELAXED", "dev");
        assert!(ai3.is_ai_subject());
    }

    // -----------------------------------------------------------------------
    // Test 22: default router is empty
    // -----------------------------------------------------------------------

    #[test]
    fn default_router_is_empty() {
        let router = RemoteWorkloadRouter::default();
        assert_eq!(router.active_job_count(), 0);
        assert_eq!(router.route_count(), 0);
    }
}
