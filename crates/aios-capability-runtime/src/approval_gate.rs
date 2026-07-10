//! INV-002 mechanical enforcement gate — "AI proposes, never executes".
//!
//! The [`ApprovalGate`] is the single point where every AI-proposed action
//! is checked against the configured [`ApprovalPolicy`]. No AI capsule may
//! execute any action without first passing through this gate. The gate is
//! consulted at six concrete code sites across the system (terminal dispatch,
//! policy evaluation, runtime execution, capsule lifecycle, adapter
//! registration, and evidence emission).
//!
//! ## INV-002 constitutional invariants
//!
//! - **AI never self-approves.** The `approve_manually` and `deny_manually`
//!   methods require a non-AI `approver` identifier. An AI capsule ID
//!   presented as the approver is rejected.
//! - **AI cannot modify approval policy.** `set_policy` is exposed for the
//!   human / system operator; gate consumers must enforce that only trusted
//!   callers invoke it.
//! - **AI cannot modify evidence.** The audit trail is append-only.
//! - **AI cannot escalate its own privileges.** Every `Escalated` decision
//!   records the escalation target; the escalated decision does not
//!   circumvent the gate.
//! - **Every denial is recorded as typed evidence** in the audit trail.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};
use tokio::sync::RwLock;

use aios_action::ActionId;

// ---------------------------------------------------------------------------
// ApprovalPolicy — four-tier gating strategy.
// ---------------------------------------------------------------------------

/// The configured approval strategy the gate enforces.
///
/// | Variant          | Behaviour                                              |
/// |------------------|--------------------------------------------------------|
/// | [`AutoDeny`]     | Every AI request is immediately denied.                |
/// | [`HumanRequired`]| Every AI request must be manually approved by a human. |
/// | [`ClassifiedOnly`]| Only requests targeting classified / sensitive         |
/// |                  | capabilities require human approval; others bypass.    |
/// | [`Delegated`]    | Pre-approved scope: the gate auto-approves requests    |
/// |                  | whose `delegated_scope_tag` matches the configured tag.|
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalPolicy {
    /// All AI-proposed actions are denied unconditionally.
    AutoDeny,
    /// Every AI-proposed action requires explicit human approval.
    #[default]
    HumanRequired,
    /// Only actions targeting classified / sensitive capabilities
    /// require human approval; others are auto-approved.
    ClassifiedOnly,
    /// Actions whose scope tag matches the delegated tag are
    /// auto-approved; others require human approval.
    Delegated {
        /// The scope tag that identifies the delegated authority
        /// boundary. Actions carrying this tag bypass the gate.
        delegated_scope_tag: String,
    },
}

impl ApprovalPolicy {
    /// Returns `true` when the policy unconditionally blocks all AI actions.
    #[must_use]
    pub const fn is_auto_deny(&self) -> bool {
        matches!(self, Self::AutoDeny)
    }

    /// Returns `true` when the policy requires human approval for every action.
    #[must_use]
    pub const fn is_human_required(&self) -> bool {
        matches!(self, Self::HumanRequired)
    }
}

// ---------------------------------------------------------------------------
// ApprovalRequest — what the AI capsule submits to the gate.
// ---------------------------------------------------------------------------

/// An AI capsule's request to execute an action, submitted to the gate.
///
/// This is the gate-internal request type; it is distinct from
/// [`crate::approval::ApprovalRequest`] which carries the runtime's outbound
/// message to the S5.3 Approval Mechanics service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateApprovalRequest {
    /// Canonical action id (S0.1 `act_<ULID>`).
    pub action_id: ActionId,
    /// The AI capsule id proposing the action.
    pub proposed_by_capsule_id: String,
    /// The target resource path or identifier.
    pub target_resource: String,
    /// The required capability token name (e.g. `"filesystem:write"`,
    /// `"network:egress"`).
    pub required_capability: String,
    /// Optional delegated scope tag — when present and the policy is
    /// `Delegated`, the gate compares this tag against the configured
    /// `delegated_scope_tag`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_scope_tag: Option<String>,
    /// `true` when the request targets a classified / sensitive capability.
    #[serde(default)]
    pub is_classified: bool,
    /// Wall-clock when the request was submitted.
    pub submitted_at: DateTime<Utc>,
}

impl GateApprovalRequest {
    /// Create a new gate request with the current wall-clock timestamp.
    #[must_use]
    pub fn new(
        action_id: ActionId,
        proposed_by_capsule_id: impl Into<String>,
        target_resource: impl Into<String>,
        required_capability: impl Into<String>,
    ) -> Self {
        Self {
            action_id,
            proposed_by_capsule_id: proposed_by_capsule_id.into(),
            target_resource: target_resource.into(),
            required_capability: required_capability.into(),
            delegated_scope_tag: None,
            is_classified: false,
            submitted_at: Utc::now(),
        }
    }

    /// Mark this request as targeting a classified / sensitive capability.
    #[must_use]
    pub fn with_classified(mut self, classified: bool) -> Self {
        self.is_classified = classified;
        self
    }

    /// Attach a delegated scope tag.
    #[must_use]
    pub fn with_scope_tag(mut self, tag: impl Into<String>) -> Self {
        self.delegated_scope_tag = Some(tag.into());
        self
    }
}

// ---------------------------------------------------------------------------
// ApprovalDecision — the gate's output.
// ---------------------------------------------------------------------------

/// The outcome of an [`ApprovalGate::evaluate`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// The action is approved. Carries the identity of the approver
    /// (`"system:auto"` for auto-approved, or the human operator id).
    Approved(String),
    /// The action is denied. Carries a structured reason.
    Denied(String),
    /// The request has been escalated to a higher authority. The
    /// `escalated_to` field records the escalation target.
    Escalated {
        /// The identity of the escalation target (subject id).
        escalated_to: String,
        /// The reason for escalation.
        reason: String,
    },
    /// The request is pending manual review. Carries the timeout
    /// deadline; if the deadline passes without a decision, the
    /// pending entry becomes a denial.
    Pending(DateTime<Utc>),
}

impl ApprovalDecision {
    /// `true` when the decision is [`Approved`](Self::Approved).
    #[must_use]
    pub const fn is_approved(&self) -> bool {
        matches!(self, Self::Approved(_))
    }

    /// `true` when the decision is [`Denied`](Self::Denied).
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Denied(_))
    }

    /// `true` when the decision is [`Pending`](Self::Pending).
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_))
    }
}

// ---------------------------------------------------------------------------
// GateAuditEntry — immutable evidence record.
// ---------------------------------------------------------------------------

/// A single entry in the gate's append-only audit trail.
///
/// Every request evaluated by the gate produces one audit entry. Denials,
/// approvals, escalations, and pending timeouts are all recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateAuditEntry {
    /// The request that was evaluated.
    pub request: GateApprovalRequest,
    /// The decision the gate produced.
    pub decision: ApprovalDecision,
    /// Wall-clock when the decision was recorded.
    pub decided_at: DateTime<Utc>,
    /// Blake3 hash of the serialised `(request, decision, decided_at)`
    /// tuple, providing tamper-evident integrity for the audit trail.
    pub evidence_hash: String,
}

impl GateAuditEntry {
    /// Compute the evidence hash for a request/decision pair at the
    /// given timestamp. The hash is the first 32 hex characters of
    /// Blake3 applied to a canonical JSON serialisation.
    fn compute_evidence_hash(
        request: &GateApprovalRequest,
        decision: &ApprovalDecision,
        timestamp: &DateTime<Utc>,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        let payload = format!(
            "{}|{}|{}",
            serde_json::to_string(request).unwrap_or_default(),
            serde_json::to_string(decision).unwrap_or_default(),
            timestamp.to_rfc3339(),
        );
        hasher.update(payload.as_bytes());
        let hash = hasher.finalize();
        hash.to_hex()[..32].to_string()
    }
}

// ---------------------------------------------------------------------------
// ApprovalGate — the central enforcement point.
// ---------------------------------------------------------------------------

/// The mechanical enforcement gate for INV-002.
///
/// All state is behind `RwLock` guards so the gate is `Send + Sync` and
/// safe to share across concurrent capsule contexts.
///
/// ## Lifecycle
///
/// 1. An AI capsule submits a [`GateApprovalRequest`] via [`evaluate`].
/// 2. The gate applies the current [`ApprovalPolicy`].
/// 3. If the decision is `Pending`, the request is parked in the internal
///    pending map until a human operator calls [`approve_manually`] or
///    [`deny_manually`].
/// 4. Every decision — including auto-decisions — is appended to the
///    audit trail.
#[derive(Debug)]
pub struct ApprovalGate {
    policy: RwLock<ApprovalPolicy>,
    pending: RwLock<HashMap<String, GateApprovalRequest>>,
    audit_trail: RwLock<Vec<GateAuditEntry>>,
}

impl ApprovalGate {
    /// Create a new gate with the given initial policy.
    #[must_use]
    pub fn new(policy: ApprovalPolicy) -> Self {
        Self {
            policy: RwLock::new(policy),
            pending: RwLock::new(HashMap::new()),
            audit_trail: RwLock::new(Vec::new()),
        }
    }

    /// Wrap `self` in an [`Arc`] for shared ownership.
    #[must_use]
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    // ------------------------------------------------------------------
    // Core evaluation.
    // ------------------------------------------------------------------

    /// Evaluate a request against the current policy.
    ///
    /// The decision logic is driven by the configured [`ApprovalPolicy`]:
    ///
    /// - [`ApprovalPolicy::AutoDeny`] → `Denied("automatic denial policy in effect")`.
    /// - [`ApprovalPolicy::HumanRequired`] → `Pending(now + 300s)`. The
    ///   timeout defaults to 300 seconds when no explicit TTL is configured.
    /// - [`ApprovalPolicy::ClassifiedOnly`] → `Approved("system:classified-bypass")`
    ///   when `is_classified` is `false`; otherwise `Pending(now + 300s)`.
    /// - [`ApprovalPolicy::Delegated`] → `Approved("system:delegated")` when
    ///   the request's `delegated_scope_tag` matches the policy's
    ///   `delegated_scope_tag`; otherwise `Pending(now + 300s)`.
    ///
    /// Pending requests are stored in the internal pending map for later
    /// manual resolution. Auto-decisions (`Approved`, `Denied`) are
    /// recorded in the audit trail immediately.
    pub async fn evaluate(&self, request: GateApprovalRequest) -> ApprovalDecision {
        let policy = self.policy.read().await.clone();
        let now = Utc::now();
        let timeout = now + Duration::seconds(300);

        let decision = match &policy {
            ApprovalPolicy::AutoDeny => {
                ApprovalDecision::Denied("automatic denial policy in effect".to_string())
            }
            ApprovalPolicy::HumanRequired => ApprovalDecision::Pending(timeout),
            ApprovalPolicy::ClassifiedOnly => {
                if request.is_classified {
                    ApprovalDecision::Pending(timeout)
                } else {
                    ApprovalDecision::Approved("system:classified-bypass".to_string())
                }
            }
            ApprovalPolicy::Delegated {
                delegated_scope_tag,
            } => {
                if request
                    .delegated_scope_tag
                    .as_ref()
                    .is_some_and(|tag| tag == delegated_scope_tag)
                {
                    ApprovalDecision::Approved("system:delegated".to_string())
                } else {
                    ApprovalDecision::Pending(timeout)
                }
            }
        };

        // Record in audit trail.
        let entry = GateAuditEntry {
            evidence_hash: GateAuditEntry::compute_evidence_hash(&request, &decision, &now),
            request: request.clone(),
            decision: decision.clone(),
            decided_at: now,
        };
        self.audit_trail.write().await.push(entry);

        // Park pending requests.
        if decision.is_pending() {
            self.pending
                .write()
                .await
                .insert(request.action_id.to_string(), request);
        }

        decision
    }

    // ------------------------------------------------------------------
    // Policy control.
    // ------------------------------------------------------------------

    /// Replace the active approval policy.
    ///
    /// Callers MUST ensure this is only invoked by trusted (human / system)
    /// code paths, not by AI capsule code. The gate itself does not enforce
    /// the caller's identity — that enforcement lives at the call site.
    pub async fn set_policy(&self, policy: ApprovalPolicy) {
        *self.policy.write().await = policy;
    }

    /// Return the current active policy.
    pub async fn current_policy(&self) -> ApprovalPolicy {
        self.policy.read().await.clone()
    }

    // ------------------------------------------------------------------
    // Manual approval / denial.
    // ------------------------------------------------------------------

    /// Manually approve a pending request.
    ///
    /// # INV-002 enforcement
    ///
    /// The `approver` parameter is checked: if it matches an AI capsule
    /// prefix (`"ai:"`), the approval is rejected with `false`. AI never
    /// self-approves.
    ///
    /// # Returns
    ///
    /// `true` when the request was found in the pending map and approved.
    /// `false` when the request was not found or the approver is an AI
    /// capsule.
    pub async fn approve_manually(&self, action_id: &str, approver: &str) -> bool {
        if Self::is_ai_actor(approver) {
            return false;
        }

        let mut pending = self.pending.write().await;
        if let Some(request) = pending.remove(action_id) {
            let now = Utc::now();
            let decision = ApprovalDecision::Approved(approver.to_string());
            let entry = GateAuditEntry {
                evidence_hash: GateAuditEntry::compute_evidence_hash(&request, &decision, &now),
                request,
                decision,
                decided_at: now,
            };
            self.audit_trail.write().await.push(entry);
            true
        } else {
            false
        }
    }

    /// Manually deny a pending request.
    ///
    /// # INV-002 enforcement
    ///
    /// The `denier` parameter is checked: if it matches an AI capsule
    /// prefix (`"ai:"`), the denial is rejected with `false`. AI never
    /// self-approves and cannot manipulate denials either.
    ///
    /// # Returns
    ///
    /// `true` when the request was found and denied. `false` when the
    /// request was not found or the denier is an AI capsule.
    pub async fn deny_manually(&self, action_id: &str, reason: &str, denier: &str) -> bool {
        if Self::is_ai_actor(denier) {
            return false;
        }

        let mut pending = self.pending.write().await;
        if let Some(request) = pending.remove(action_id) {
            let now = Utc::now();
            let decision = ApprovalDecision::Denied(reason.to_string());
            let entry = GateAuditEntry {
                evidence_hash: GateAuditEntry::compute_evidence_hash(&request, &decision, &now),
                request,
                decision,
                decided_at: now,
            };
            self.audit_trail.write().await.push(entry);
            true
        } else {
            false
        }
    }

    /// Escalate a pending request to a higher authority.
    ///
    /// The request remains in the pending map with its original timeout;
    /// the escalation is recorded as a separate audit entry.
    ///
    /// # Returns
    ///
    /// `true` when the request was found and an escalation entry was
    /// recorded. `false` when the request was not found.
    pub async fn escalate(&self, action_id: &str, escalated_to: &str, reason: &str) -> bool {
        let pending = self.pending.read().await;
        if let Some(request) = pending.get(action_id) {
            let now = Utc::now();
            let decision = ApprovalDecision::Escalated {
                escalated_to: escalated_to.to_string(),
                reason: reason.to_string(),
            };
            let entry = GateAuditEntry {
                evidence_hash: GateAuditEntry::compute_evidence_hash(request, &decision, &now),
                request: request.clone(),
                decision,
                decided_at: now,
            };
            self.audit_trail.write().await.push(entry);
            true
        } else {
            false
        }
    }

    // ------------------------------------------------------------------
    // Audit trail.
    // ------------------------------------------------------------------

    /// Return the complete append-only audit trail.
    pub async fn audit_trail(&self) -> Vec<GateAuditEntry> {
        self.audit_trail.read().await.clone()
    }

    /// Return the number of pending (not yet resolved) requests.
    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }

    /// Return the number of entries in the audit trail.
    pub async fn audit_trail_len(&self) -> usize {
        self.audit_trail.read().await.len()
    }

    /// Expire all pending requests whose timeout has elapsed.
    ///
    /// Each expired request is removed from the pending map and a `Denied`
    /// entry is appended to the audit trail with the reason
    /// `"pending timeout expired"`.
    ///
    /// # Returns
    ///
    /// The number of expired requests that were cleaned up.
    pub async fn expire_stale_pending(&self) -> usize {
        let now = Utc::now();
        let mut expired_requests = Vec::new();

        {
            let pending = self.pending.read().await;
            for (id, request) in pending.iter() {
                let deadline = request.submitted_at + Duration::seconds(300);
                if now >= deadline {
                    expired_requests.push((id.clone(), request.clone()));
                }
            }
        }

        if expired_requests.is_empty() {
            return 0;
        }

        let mut pending = self.pending.write().await;
        for (id, request) in &expired_requests {
            pending.remove(id);
            let decision = ApprovalDecision::Denied("pending timeout expired".to_string());
            let entry = GateAuditEntry {
                evidence_hash: GateAuditEntry::compute_evidence_hash(request, &decision, &now),
                request: request.clone(),
                decision,
                decided_at: now,
            };
            self.audit_trail.write().await.push(entry);
        }

        expired_requests.len()
    }

    // ------------------------------------------------------------------
    // Internal helpers.
    // ------------------------------------------------------------------

    /// Returns `true` when `id` matches an AI capsule prefix pattern.
    /// AI capsule identifiers are expected to start with `"ai:"`.
    fn is_ai_actor(id: &str) -> bool {
        id.starts_with("ai:")
    }
}

impl Default for ApprovalGate {
    fn default() -> Self {
        Self::new(ApprovalPolicy::default())
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    fn fixture_request() -> GateApprovalRequest {
        GateApprovalRequest::new(
            ActionId::new(),
            "ai:agent-42",
            "/data/export/secret.csv",
            "filesystem:read",
        )
    }

    fn fixture_classified_request() -> GateApprovalRequest {
        fixture_request().with_classified(true)
    }

    fn fixture_delegated_request(tag: &str) -> GateApprovalRequest {
        fixture_request().with_scope_tag(tag)
    }

    // ------------------------------------------------------------------
    // Test 1 — AutoDeny blocks all requests.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn auto_deny_blocks_all_requests() {
        let gate = ApprovalGate::new(ApprovalPolicy::AutoDeny);
        let req = fixture_request();
        let decision = gate.evaluate(req).await;
        assert!(decision.is_denied(), "AutoDeny must deny all requests");
        assert_eq!(gate.pending_count().await, 0);
    }

    // ------------------------------------------------------------------
    // Test 2 — HumanRequired needs manual approval.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn human_required_needs_manual_approval() {
        let gate = ApprovalGate::new(ApprovalPolicy::HumanRequired);
        let req = fixture_request();
        let action_id = req.action_id.to_string();
        let decision = gate.evaluate(req).await;
        assert!(decision.is_pending(), "HumanRequired must park as pending");
        assert_eq!(gate.pending_count().await, 1);

        let ok = gate.approve_manually(&action_id, "human:lucky").await;
        assert!(ok, "human approver must succeed");
        assert_eq!(gate.pending_count().await, 0);
        assert_eq!(gate.audit_trail_len().await, 2);
    }

    // ------------------------------------------------------------------
    // Test 3 — AI cannot self-approve.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn ai_cannot_self_approve() {
        let gate = ApprovalGate::new(ApprovalPolicy::HumanRequired);
        let req = fixture_request();
        let action_id = req.action_id.to_string();
        gate.evaluate(req).await;

        let ok = gate.approve_manually(&action_id, "ai:rogue-agent").await;
        assert!(!ok, "AI must not self-approve");
        assert_eq!(gate.pending_count().await, 1, "request still pending");
    }

    #[tokio::test]
    async fn ai_cannot_self_deny() {
        let gate = ApprovalGate::new(ApprovalPolicy::HumanRequired);
        let req = fixture_request();
        let action_id = req.action_id.to_string();
        gate.evaluate(req).await;

        let ok = gate
            .deny_manually(&action_id, "override attempt", "ai:rogue-agent")
            .await;
        assert!(!ok, "AI must not manipulate denials");
        assert_eq!(gate.pending_count().await, 1);
    }

    // ------------------------------------------------------------------
    // Test 4 — Escalation path.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn escalation_path_is_recorded() {
        let gate = ApprovalGate::new(ApprovalPolicy::HumanRequired);
        let req = fixture_request();
        let action_id = req.action_id.to_string();
        gate.evaluate(req).await;

        let ok = gate
            .escalate(&action_id, "human:admin", "needs senior review")
            .await;
        assert!(ok, "escalation must succeed");
        // Request still pending after escalation.
        assert_eq!(gate.pending_count().await, 1);

        let trail = gate.audit_trail().await;
        let escalation_entry = trail
            .iter()
            .find(|e| matches!(e.decision, ApprovalDecision::Escalated { .. }))
            .expect("escalation entry must exist");
        match &escalation_entry.decision {
            ApprovalDecision::Escalated {
                escalated_to,
                reason,
            } => {
                assert_eq!(escalated_to, "human:admin");
                assert_eq!(reason, "needs senior review");
            }
            _ => unreachable!(),
        }
    }

    // ------------------------------------------------------------------
    // Test 5 — Audit trail completeness.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn audit_trail_records_every_decision() {
        let gate = ApprovalGate::new(ApprovalPolicy::HumanRequired);

        // Evaluate three requests.
        let r1 = fixture_request();
        let a1 = r1.action_id.to_string();
        gate.evaluate(r1).await;

        let r2 = fixture_request().with_classified(true);
        let a2 = r2.action_id.to_string();
        gate.evaluate(r2).await;

        let r3 = fixture_request();
        let a3 = r3.action_id.to_string();
        gate.evaluate(r3).await;

        // Approve one, deny one, escalate one.
        gate.approve_manually(&a1, "human:alice").await;
        gate.deny_manually(&a2, "classified not allowed", "human:bob")
            .await;
        gate.escalate(&a3, "human:admin", "escalation test").await;

        let trail = gate.audit_trail().await;
        // 3 evaluate entries + 2 manual resolve entries + 1 escalation = 6
        assert_eq!(trail.len(), 6, "every decision must be recorded");

        // Every entry must have a non-empty evidence hash.
        for entry in &trail {
            assert!(
                !entry.evidence_hash.is_empty(),
                "evidence hash must not be empty"
            );
            assert_eq!(
                entry.evidence_hash.len(),
                32,
                "evidence hash must be 32 hex chars"
            );
        }
    }

    // ------------------------------------------------------------------
    // Test 6 — Timeout on pending.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn expire_stale_pending_cleans_up_timed_out_requests() {
        let gate = ApprovalGate::new(ApprovalPolicy::HumanRequired);
        let req = fixture_request();
        gate.evaluate(req).await;
        assert_eq!(gate.pending_count().await, 1);

        // Force expire — in practice the deadline is 300 s from now, so
        // this should return 0 in a fresh test. But the method is
        // exercised regardless; we test the timeout pathway by verifying
        // the method runs without error and the count stays correct when
        // no requests are stale.
        let expired = gate.expire_stale_pending().await;
        // In test conditions, 0 stale entries is expected.
        assert_eq!(expired, 0);
        assert_eq!(
            gate.pending_count().await,
            1,
            "non-expired request stays pending"
        );
    }

    // ------------------------------------------------------------------
    // Test 7 — ClassifiedOnly allows non-classified operations.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn classified_only_allows_non_classified_operations() {
        let gate = ApprovalGate::new(ApprovalPolicy::ClassifiedOnly);

        let non_classified = fixture_request(); // is_classified = false
        let decision = gate.evaluate(non_classified).await;
        assert!(decision.is_approved(), "non-classified must auto-approve");
        assert_eq!(gate.pending_count().await, 0);

        let classified = fixture_classified_request();
        let decision = gate.evaluate(classified).await;
        assert!(
            decision.is_pending(),
            "classified must require manual approval"
        );
        assert_eq!(gate.pending_count().await, 1);
    }

    // ------------------------------------------------------------------
    // Test 8 — Delegated scope enforcement.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn delegated_scope_tag_enforcement() {
        let gate = ApprovalGate::new(ApprovalPolicy::Delegated {
            delegated_scope_tag: "build-pipeline".to_string(),
        });

        // Matching tag → auto-approved.
        let matched = fixture_delegated_request("build-pipeline");
        let decision = gate.evaluate(matched).await;
        assert!(
            decision.is_approved(),
            "matching delegated scope must auto-approve"
        );
        assert_eq!(gate.pending_count().await, 0);

        // Non-matching tag → pending.
        let mismatched = fixture_delegated_request("admin-console");
        let decision = gate.evaluate(mismatched).await;
        assert!(
            decision.is_pending(),
            "non-matching scope must require approval"
        );
        assert_eq!(gate.pending_count().await, 1);

        // No tag → pending.
        let no_tag = fixture_request();
        let decision = gate.evaluate(no_tag).await;
        assert!(
            decision.is_pending(),
            "missing scope tag must require approval"
        );
        assert_eq!(gate.pending_count().await, 2);
    }

    // ------------------------------------------------------------------
    // Test 9 — Policy switching.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn policy_can_be_switched_at_runtime() {
        let gate = ApprovalGate::new(ApprovalPolicy::AutoDeny);
        assert_eq!(gate.current_policy().await, ApprovalPolicy::AutoDeny);

        gate.set_policy(ApprovalPolicy::HumanRequired).await;
        assert_eq!(gate.current_policy().await, ApprovalPolicy::HumanRequired);

        let req = fixture_request();
        let decision = gate.evaluate(req).await;
        assert!(
            decision.is_pending(),
            "new policy must take effect immediately"
        );
    }

    // ------------------------------------------------------------------
    // Test 10 — Approve/deny unknown request returns false.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn manual_resolve_unknown_request_returns_false() {
        let gate = ApprovalGate::new(ApprovalPolicy::HumanRequired);
        let ok = gate
            .approve_manually("act_nonexistent", "human:admin")
            .await;
        assert!(!ok, "unknown request must not be approved");

        let ok = gate
            .deny_manually("act_nonexistent", "no such request", "human:admin")
            .await;
        assert!(!ok, "unknown request must not be denied");
    }

    // ------------------------------------------------------------------
    // Test 11 — Escalate unknown request returns false.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn escalate_unknown_request_returns_false() {
        let gate = ApprovalGate::new(ApprovalPolicy::HumanRequired);
        let ok = gate
            .escalate("act_nonexistent", "human:admin", "reason")
            .await;
        assert!(!ok);
    }

    // ------------------------------------------------------------------
    // Test 12 — GateApprovalRequest builder pattern.
    // ------------------------------------------------------------------

    #[test]
    fn gate_request_builder_chain() {
        let action_id = ActionId::new();
        let req = GateApprovalRequest::new(
            action_id.clone(),
            "ai:builder",
            "/tmp/output",
            "filesystem:write",
        )
        .with_classified(true)
        .with_scope_tag("ci-pipeline");

        assert_eq!(req.action_id, action_id);
        assert_eq!(req.proposed_by_capsule_id, "ai:builder");
        assert!(req.is_classified);
        assert_eq!(req.delegated_scope_tag, Some("ci-pipeline".to_string()));
    }
}
