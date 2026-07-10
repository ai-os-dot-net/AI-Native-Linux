//! AI action proposal lifecycle — the core typed-action proposal type and its
//! state machine.
//!
//! S20 §8: AIOS native AI acts through typed actions, not arbitrary shell
//! scripts. Every proposal carries a risk class, confidence floor, approval
//! strength, and evidence receipt so that the Policy Kernel, human operator,
//! and audit log can independently verify what was proposed and why.
//!
//! ## INV-002 enforcement
//!
//! AI proposes, never executes. A proposal must be approved by a human operator
//! before the capability runtime dispatches it. The [`validate`] method
//! enforces this mechanically: `EXACT_ACTION` scope only, confidence above
//! threshold, model provenance captured, no AI self-approval.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::enums::ProposalState;

/// Minimum confidence an AI-generated proposal must carry to be considered
/// for policy preflight. Proposals below this threshold are rejected before
/// they reach the Policy Kernel.
pub const MIN_PROPOSAL_CONFIDENCE: f64 = 0.50;

/// Minimum confidence an AI-generated proposal must carry for non-LOW risk
/// actions. Proposals in [`High`](crate::enums::ProposalRiskClass::High) or
/// [`Critical`](crate::enums::ProposalRiskClass::Critical) bands must
/// satisfy this stricter floor.
pub const MIN_HIGH_RISK_CONFIDENCE: f64 = 0.75;

/// Risk classification for a single AI action proposal.
///
/// S20 §8.1: every typed action must carry a `risk_class`. An action missing
/// `risk_class` is invalid and cannot reach policy preflight — the compiler
/// fails closed. This is a separate axis from the context-level risk
/// classification (§11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProposalRiskClass {
    /// Read-only or trivially reversible; no security/profile/boot/identity
    /// effect.
    Low,
    /// Reversible host/state mutation with a defined rollback plan.
    Medium,
    /// Security-, kernel-, driver-, firmware-, or network-exposure-affecting.
    High,
    /// Profile transition, boot-integrity-adjacent, or fleet-wide effect.
    Critical,
}

impl ProposalRiskClass {
    /// Returns the minimum confidence floor for this risk class.
    /// Proposals must have `confidence >= floor` to pass validation.
    #[must_use]
    pub fn confidence_floor(self) -> f64 {
        match self {
            Self::Low | Self::Medium => MIN_PROPOSAL_CONFIDENCE,
            Self::High | Self::Critical => MIN_HIGH_RISK_CONFIDENCE,
        }
    }

    /// Returns `true` if this risk class requires mandatory human approval
    /// (i.e., cannot be auto-granted).
    #[must_use]
    pub fn requires_mandatory_approval(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

/// Approval scope for a proposal — determines what the approval covers.
///
/// Per S20 §8 / INV-002: `ExactAction` is the only scope allowed for AI
/// proposals. Broader scopes (e.g., `Session`, `Role`) would grant the AI
/// execution authority beyond a single action and are blocked by the
/// proposal validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalScope {
    /// Approval covers exactly one typed action — required for AI proposals.
    ExactAction,
    /// Approval covers a session (blocked for AI proposals).
    Session,
    /// Approval covers a role (blocked for AI proposals).
    Role,
}

/// Validation outcome for a proposal check.
#[derive(Debug, Clone, PartialEq)]
pub enum ProposalValidation {
    /// Proposal passed all validations.
    Valid,
    /// Proposal failed one or more validations.
    Invalid(ProposalValidationError),
}

/// Concrete validation failure reason.
#[derive(Debug, Clone, PartialEq)]
pub enum ProposalValidationError {
    /// AI subject attempted self-approval (INV-002).
    AiSelfApprovalForbidden,
    /// Proposal scope is not `ExactAction`.
    InvalidScope,
    /// Confidence is below the minimum floor for this risk class.
    /// Confidence is below the minimum floor for this risk class.
    ConfidenceBelowFloor {
        /// The actual confidence value.
        actual: f64,
        /// The required minimum confidence.
        required: f64,
    },
    /// Model provenance not set — model_id is required.
    MissingModelId,
    /// Action name is empty.
    MissingActionName,
    /// Evidence receipt is missing.
    MissingEvidenceReceipt,
}

/// Proposal lifecycle transition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalTransitionError {
    /// Current state that rejected the transition.
    pub from: ProposalState,
    /// Requested target state.
    pub to: ProposalState,
}

/// An AI-generated action proposal — the core typed object that flows through
/// the terminal pipeline (submit → classify → compile → preflight → approve
/// → execute → verify → evidence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIActionProposal {
    /// Unique proposal identifier (Ulid).
    pub proposal_id: Ulid,
    /// Subject that originated the intent (actor canonical id).
    pub subject_id: String,
    /// Model that produced this proposal.
    pub model_id: String,
    /// Typed action name (e.g., `app.install`, `network.open_port`).
    pub action_name: String,
    /// Action parameters as a JSON object.
    pub parameters: serde_json::Value,
    /// AI confidence score [0.0, 1.0].
    pub confidence: f64,
    /// Human-readable rationale for the proposal.
    pub rationale: String,
    /// Risk classification of this single action.
    pub risk_class: ProposalRiskClass,
    /// FSM state of the proposal.
    pub state: ProposalState,
    /// Approval scope — must be `ExactAction` for AI proposals.
    pub approval_scope: ApprovalScope,
    /// Ed25519 signature chain (hex-encoded signatures).
    pub signature_chain: Vec<String>,
    /// Evidence receipt linking this proposal to the evidence log.
    pub evidence_receipt: Option<String>,
    /// When the proposal was created.
    pub created_at: DateTime<Utc>,
}

impl AIActionProposal {
    /// Create a new proposal in `Draft` state.
    #[must_use]
    pub fn new(
        subject_id: impl Into<String>,
        model_id: impl Into<String>,
        action_name: impl Into<String>,
        parameters: serde_json::Value,
        confidence: f64,
        rationale: impl Into<String>,
        risk_class: ProposalRiskClass,
    ) -> Self {
        Self {
            proposal_id: Ulid::new(),
            subject_id: subject_id.into(),
            model_id: model_id.into(),
            action_name: action_name.into(),
            parameters,
            confidence,
            rationale: rationale.into(),
            risk_class,
            state: ProposalState::Draft,
            approval_scope: ApprovalScope::ExactAction,
            signature_chain: Vec::new(),
            evidence_receipt: None,
            created_at: Utc::now(),
        }
    }

    /// Validate the proposal against INV-002 and S20 constraints.
    ///
    /// Checks:
    /// - Action name is non-empty.
    /// - Model ID is set (provenance must be captured).
    /// - Scope is `ExactAction` (AI may never hold broader approval).
    /// - Confidence meets the risk-class floor.
    /// - Evidence receipt is present.
    ///
    /// AI self-approval is always rejected — a proposal in `Approved` state
    /// with an AI-actor subject is invalid.
    #[must_use]
    pub fn validate(&self, actor_kind: Option<&str>) -> ProposalValidation {
        if self.action_name.is_empty() {
            return ProposalValidation::Invalid(ProposalValidationError::MissingActionName);
        }
        if self.model_id.is_empty() {
            return ProposalValidation::Invalid(ProposalValidationError::MissingModelId);
        }
        if self.approval_scope != ApprovalScope::ExactAction {
            return ProposalValidation::Invalid(ProposalValidationError::InvalidScope);
        }
        let floor = self.risk_class.confidence_floor();
        if self.confidence < floor {
            return ProposalValidation::Invalid(ProposalValidationError::ConfidenceBelowFloor {
                actual: self.confidence,
                required: floor,
            });
        }
        if self.evidence_receipt.is_none() {
            return ProposalValidation::Invalid(ProposalValidationError::MissingEvidenceReceipt);
        }
        if let Some("AI_NATIVE_SUBJECT" | "AI_AGENT_CAPSULE") = actor_kind {
            if self.state == ProposalState::Approved || self.state == ProposalState::Executed {
                return ProposalValidation::Invalid(
                    ProposalValidationError::AiSelfApprovalForbidden,
                );
            }
        }
        ProposalValidation::Valid
    }

    /// Transition the proposal to `Approved` state.
    ///
    /// This must only be called after a human operator explicitly approves.
    /// Returns `Ok(())` on success or a typed transition error if the current
    /// state does not allow this transition.
    pub fn approve(&mut self) -> Result<(), ProposalTransitionError> {
        self.transition_to(ProposalState::Approved)
    }

    /// Transition the proposal to `Rejected` state.
    ///
    /// This can be called from `UnderReview` or via operator rejection.
    pub fn reject(&mut self) -> Result<(), ProposalTransitionError> {
        self.transition_to(ProposalState::Rejected)
    }

    /// Transition the proposal to `Revoked` state.
    ///
    /// Only valid from `Approved` — corresponds to an emergency stop or
    /// operator revocation before execution.
    pub fn revoke(&mut self) -> Result<(), ProposalTransitionError> {
        self.transition_to(ProposalState::Revoked)
    }

    /// Transition the proposal to `Proposed` state (from `Draft`).
    pub fn submit(&mut self) -> Result<(), ProposalTransitionError> {
        self.transition_to(ProposalState::Proposed)
    }

    /// Transition the proposal to `UnderReview` state (from `Proposed`).
    pub fn move_to_review(&mut self) -> Result<(), ProposalTransitionError> {
        self.transition_to(ProposalState::UnderReview)
    }

    /// Transition the proposal to `Executed` state (from `Approved`).
    pub fn mark_executed(&mut self) -> Result<(), ProposalTransitionError> {
        self.transition_to(ProposalState::Executed)
    }

    fn transition_to(&mut self, target: ProposalState) -> Result<(), ProposalTransitionError> {
        if self.state.can_transition_to(target) {
            self.state = target;
            Ok(())
        } else {
            Err(ProposalTransitionError {
                from: self.state,
                to: target,
            })
        }
    }

    /// Attach an evidence receipt to this proposal.
    pub fn set_evidence_receipt(&mut self, receipt: impl Into<String>) {
        self.evidence_receipt = Some(receipt.into());
    }

    /// Attach a signature to the chain.
    pub fn add_signature(&mut self, sig: impl Into<String>) {
        self.signature_chain.push(sig.into());
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    fn make_proposal(confidence: f64, risk_class: ProposalRiskClass) -> AIActionProposal {
        let mut p = AIActionProposal::new(
            "subj_test",
            "model_gpt",
            "app.install",
            serde_json::json!({"pkg": "blender"}),
            confidence,
            "Install blender for 3d work",
            risk_class,
        );
        p.set_evidence_receipt("evr_test_001");
        p
    }

    fn make_proposal_with_state(
        confidence: f64,
        risk_class: ProposalRiskClass,
        state: ProposalState,
    ) -> AIActionProposal {
        let mut p = make_proposal(confidence, risk_class);
        match state {
            ProposalState::Draft => {} // already Draft
            ProposalState::Proposed => {
                p.submit().unwrap();
            }
            ProposalState::UnderReview => {
                p.submit().unwrap();
                p.move_to_review().unwrap();
            }
            ProposalState::Approved => {
                p.submit().unwrap();
                p.move_to_review().unwrap();
                p.approve().unwrap();
            }
            ProposalState::Executed => {
                p.submit().unwrap();
                p.move_to_review().unwrap();
                p.approve().unwrap();
                p.mark_executed().unwrap();
            }
            _ => {}
        }
        p
    }

    // ── FSM happy path ──

    #[test]
    fn fsm_draft_to_proposed() {
        let mut p = make_proposal(0.9, ProposalRiskClass::Low);
        p.submit().unwrap();
        assert_eq!(p.state, ProposalState::Proposed);
    }

    #[test]
    fn fsm_proposed_to_under_review() {
        let mut p = make_proposal(0.9, ProposalRiskClass::Low);
        p.submit().unwrap();
        p.move_to_review().unwrap();
        assert_eq!(p.state, ProposalState::UnderReview);
    }

    #[test]
    fn fsm_under_review_to_approved() {
        let mut p =
            make_proposal_with_state(0.9, ProposalRiskClass::Low, ProposalState::UnderReview);
        p.approve().unwrap();
        assert_eq!(p.state, ProposalState::Approved);
    }

    #[test]
    fn fsm_approved_to_executed() {
        let mut p = make_proposal_with_state(0.9, ProposalRiskClass::Low, ProposalState::Approved);
        p.mark_executed().unwrap();
        assert_eq!(p.state, ProposalState::Executed);
    }

    #[test]
    fn fsm_full_happy_path() {
        let mut p = make_proposal(0.85, ProposalRiskClass::Medium);
        assert_eq!(p.state, ProposalState::Draft);
        p.submit().unwrap();
        assert_eq!(p.state, ProposalState::Proposed);
        p.move_to_review().unwrap();
        assert_eq!(p.state, ProposalState::UnderReview);
        p.approve().unwrap();
        assert_eq!(p.state, ProposalState::Approved);
        p.mark_executed().unwrap();
        assert_eq!(p.state, ProposalState::Executed);
    }

    // ── Rejection / revocation ──

    #[test]
    fn fsm_under_review_reject() {
        let mut p =
            make_proposal_with_state(0.9, ProposalRiskClass::Low, ProposalState::UnderReview);
        p.reject().unwrap();
        assert_eq!(p.state, ProposalState::Rejected);
    }

    #[test]
    fn fsm_approved_revoke() {
        let mut p = make_proposal_with_state(0.9, ProposalRiskClass::Low, ProposalState::Approved);
        p.revoke().unwrap();
        assert_eq!(p.state, ProposalState::Revoked);
    }

    #[test]
    fn fsm_rejected_back_to_draft() {
        let mut p = make_proposal(0.9, ProposalRiskClass::Low);
        p.submit().unwrap();
        p.move_to_review().unwrap();
        p.reject().unwrap();
        assert_eq!(p.state, ProposalState::Rejected);
        // from Rejected we can return to Draft
        assert!(p.state.can_transition_to(ProposalState::Draft));
    }

    #[test]
    fn fsm_revoke_from_non_approved_fails() {
        let mut p = make_proposal(0.9, ProposalRiskClass::Low);
        assert!(p.revoke().is_err());
    }

    #[test]
    fn fsm_execute_from_non_approved_fails() {
        let mut p = make_proposal(0.9, ProposalRiskClass::Low);
        assert!(p.mark_executed().is_err());
    }

    #[test]
    fn fsm_double_submit_fails() {
        let mut p = make_proposal(0.9, ProposalRiskClass::Low);
        p.submit().unwrap();
        assert!(p.submit().is_err());
    }

    // ── Validation ──

    #[test]
    fn validate_good_proposal_passes() {
        let p = make_proposal(0.85, ProposalRiskClass::Medium);
        let result = p.validate(Some("HUMAN_OPERATOR"));
        assert_eq!(result, ProposalValidation::Valid);
    }

    #[test]
    fn validate_missing_model_id_fails() {
        let mut p = make_proposal(0.85, ProposalRiskClass::Medium);
        p.model_id = String::new();
        let result = p.validate(Some("HUMAN_OPERATOR"));
        assert_eq!(
            result,
            ProposalValidation::Invalid(ProposalValidationError::MissingModelId)
        );
    }

    #[test]
    fn validate_missing_action_name_fails() {
        let mut p = make_proposal(0.85, ProposalRiskClass::Medium);
        p.action_name = String::new();
        let result = p.validate(Some("HUMAN_OPERATOR"));
        assert_eq!(
            result,
            ProposalValidation::Invalid(ProposalValidationError::MissingActionName)
        );
    }

    #[test]
    fn validate_ai_self_approval_blocked() {
        let p = make_proposal_with_state(0.85, ProposalRiskClass::Medium, ProposalState::Approved);
        let result = p.validate(Some("AI_NATIVE_SUBJECT"));
        assert_eq!(
            result,
            ProposalValidation::Invalid(ProposalValidationError::AiSelfApprovalForbidden)
        );
    }

    #[test]
    fn validate_ai_agent_capsule_self_approval_blocked() {
        let p = make_proposal_with_state(0.85, ProposalRiskClass::Medium, ProposalState::Executed);
        let result = p.validate(Some("AI_AGENT_CAPSULE"));
        assert_eq!(
            result,
            ProposalValidation::Invalid(ProposalValidationError::AiSelfApprovalForbidden)
        );
    }

    #[test]
    fn validate_confidence_below_low_floor_fails() {
        let p = make_proposal(0.30, ProposalRiskClass::Low);
        let result = p.validate(Some("HUMAN_OPERATOR"));
        assert!(matches!(
            result,
            ProposalValidation::Invalid(ProposalValidationError::ConfidenceBelowFloor { .. })
        ));
    }

    #[test]
    fn validate_confidence_below_high_floor_fails() {
        let p = make_proposal(0.50, ProposalRiskClass::High);
        let result = p.validate(Some("HUMAN_OPERATOR"));
        assert!(matches!(
            result,
            ProposalValidation::Invalid(ProposalValidationError::ConfidenceBelowFloor { .. })
        ));
    }

    #[test]
    fn validate_confidence_meets_high_floor_passes() {
        let p = make_proposal(0.80, ProposalRiskClass::High);
        let result = p.validate(Some("HUMAN_OPERATOR"));
        assert_eq!(result, ProposalValidation::Valid);
    }

    #[test]
    fn validate_non_exact_action_scope_blocked() {
        let mut p = make_proposal(0.85, ProposalRiskClass::Low);
        p.approval_scope = ApprovalScope::Session;
        let result = p.validate(Some("HUMAN_OPERATOR"));
        assert_eq!(
            result,
            ProposalValidation::Invalid(ProposalValidationError::InvalidScope)
        );
    }

    #[test]
    fn validate_missing_evidence_receipt_fails() {
        let mut p = make_proposal(0.85, ProposalRiskClass::Low);
        p.evidence_receipt = None;
        let result = p.validate(Some("HUMAN_OPERATOR"));
        assert_eq!(
            result,
            ProposalValidation::Invalid(ProposalValidationError::MissingEvidenceReceipt)
        );
    }

    #[test]
    fn risk_class_confidence_floor_low() {
        assert!(
            (ProposalRiskClass::Low.confidence_floor() - MIN_PROPOSAL_CONFIDENCE).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn risk_class_confidence_floor_high() {
        assert!(
            (ProposalRiskClass::High.confidence_floor() - MIN_HIGH_RISK_CONFIDENCE).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn risk_class_mandatory_approval() {
        assert!(!ProposalRiskClass::Low.requires_mandatory_approval());
        assert!(!ProposalRiskClass::Medium.requires_mandatory_approval());
        assert!(ProposalRiskClass::High.requires_mandatory_approval());
        assert!(ProposalRiskClass::Critical.requires_mandatory_approval());
    }

    #[test]
    fn signature_chain_append() {
        let mut p = make_proposal(0.85, ProposalRiskClass::Low);
        assert!(p.signature_chain.is_empty());
        p.add_signature("abcd1234");
        assert_eq!(p.signature_chain.len(), 1);
        p.add_signature("efgh5678");
        assert_eq!(p.signature_chain.len(), 2);
    }

    #[test]
    fn proposal_id_is_unique() {
        let p1 = make_proposal(0.9, ProposalRiskClass::Low);
        let p2 = make_proposal(0.9, ProposalRiskClass::Low);
        assert_ne!(p1.proposal_id, p2.proposal_id);
    }

    #[test]
    fn proposal_serde_round_trip() {
        let p = make_proposal(0.85, ProposalRiskClass::Medium);
        let json = serde_json::to_string(&p).unwrap();
        let back: AIActionProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(p.proposal_id, back.proposal_id);
        assert_eq!(p.action_name, back.action_name);
        assert_eq!(p.state, back.state);
        assert_eq!(p.risk_class, back.risk_class);
    }
}
