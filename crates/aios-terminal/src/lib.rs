//! `aios-terminal` — S20 Native AI Control Plane Terminal.
//!
//! Provides:
//!
//! - **Enums** — closed vocabulary types: [`TerminalMode`] (Lx/Mix/Ai),
//!   [`ProposalState`] (7-state FSM), [`AiMarker`] (transparency markers),
//!   [`UserIntentClass`] (intent classification), [`ActionOutcome`]
//!   (execution outcomes).
//! - **Proposal** — [`AIActionProposal`] typed-action lifecycle with FSM
//!   transitions, validation against INV-002 (no AI self-approval), and
//!   confidence/scope enforcement.
//! - **Fabric** — [`TerminalFabric`] orchestrates the full pipeline:
//!   submit → safety classify → intent classify → compile → validate →
//!   approve → execute, with evidence emission at each step.
//! - **Safety** — [`PromptSafetyClassifier`] detects prompt-injection,
//!   prohibited patterns (shell bypass, env-spray, exfiltration, AI
//!   self-approval), and classifies user input per S20 §12/§14.
//! - **Mode Switch** — [`TerminalModeSwitch`] manages LX ↔ MIX ↔ AI
//!   transitions with security profile gating (AIRGAP_HIGH = LX only,
//!   HIGH_RISK_READY = no AI mode).
//!
//! ## Constitutional invariants
//!
//! - `#![forbid(unsafe_code)]` — no unsafe anywhere.
//! - No `unwrap()`, no `expect()`, no `panic!()`, no `todo!()`,
//!   no `unimplemented!()` outside test blocks.
//! - `#[must_use]` on pure functions.
//! - INV-002 enforced mechanically: AI proposes, never executes — proposals
//!   must be approved by a human operator before the capability runtime
//!   dispatches them.

#![forbid(unsafe_code)]

pub mod enums;
pub mod mode_switch;
pub mod proposal;
pub mod safety;
pub mod terminal_fabric;

pub use enums::{ActionOutcome, AiMarker, ProposalState, TerminalMode, UserIntentClass};
pub use mode_switch::{
    available_modes_for_profile, ModeSwitchError, ModeSwitchEvidence, SecurityProfileLevel,
    TerminalModeSwitch,
};
pub use proposal::{
    AIActionProposal, ApprovalScope, ProposalRiskClass, ProposalValidation,
    ProposalValidationError, MIN_HIGH_RISK_CONFIDENCE, MIN_PROPOSAL_CONFIDENCE,
};
pub use safety::{ProhibitedPattern, PromptSafetyClassifier, SafetyResult, SafetyVerdict};
pub use terminal_fabric::{
    ExecutionResult, FabricContext, FabricEvent, FabricEventRecord, SubmissionResult,
    TerminalFabric,
};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn re_export_terminal_mode() {
        let mode = TerminalMode::Ai;
        assert_eq!(mode, TerminalMode::Ai);
    }

    #[test]
    fn re_export_proposal_state() {
        let state = ProposalState::Draft;
        assert_eq!(state, ProposalState::Draft);
    }

    #[test]
    fn re_export_ai_marker() {
        let marker = AiMarker::HumanWritten;
        assert_eq!(marker, AiMarker::HumanWritten);
    }

    #[test]
    fn re_export_user_intent_class() {
        let intent = UserIntentClass::AiAssistRequest;
        assert_eq!(intent, UserIntentClass::AiAssistRequest);
    }

    #[test]
    fn re_export_action_outcome() {
        let outcome = ActionOutcome::Success;
        assert_eq!(outcome, ActionOutcome::Success);
    }

    #[test]
    fn re_export_safety_verdict() {
        let v = SafetyVerdict::Clean;
        assert_eq!(v, SafetyVerdict::Clean);
    }

    #[test]
    fn re_export_fabric_event() {
        let ev = FabricEvent::ProposalSubmitted;
        assert_eq!(ev, FabricEvent::ProposalSubmitted);
    }

    #[test]
    fn ai_action_proposal_constructable() {
        let mut p = AIActionProposal::new(
            "subj",
            "model",
            "app.test",
            serde_json::json!({}),
            0.85,
            "test",
            ProposalRiskClass::Low,
        );
        p.set_evidence_receipt("evr_001");
        let result = p.validate(Some("HUMAN_OPERATOR"));
        assert_eq!(result, ProposalValidation::Valid);
    }
}
