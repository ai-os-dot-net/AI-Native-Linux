//! [`VoiceApprovalSession`] — voice approval FSM.
//!
//! Implements the 7-state voice approval lifecycle:
//! `Listening → Transcribing → Validating → Confirming → Confirmed / Rejected / TimedOut`.
//!
//! ## Risk-based gating
//!
//! - CRITICAL risk actions cannot be approved by voice alone (require visual
//!   co-approval).
//! - HIGH risk actions require confidence >= 0.80.
//! - CRITICAL risk actions require confidence >= 0.95.
//!
//! ## Evidence chain
//!
//! Every state transition emits evidence via [`VoiceEvidenceEmitter`].
//! The full chain is: `VoiceApprovalStarted → VoiceApprovalTranscribed →
//! VoiceApprovalConfirmed / VoiceApprovalRejected`.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
// serde used only for evidence payload construction
use ulid::Ulid;

use crate::enums::{VoiceApprovalState, VoiceRiskClass};
use crate::error::VoiceRendererError;
use crate::evidence::{VoiceEvidence, VoiceEvidenceEmitter, VoiceRecordType};

/// A voice approval session — binds a transcript to an action request and
/// guides the user through the approval FSM.
#[derive(Debug, Clone)]
pub struct VoiceApprovalSession {
    /// Unique session identifier (`vas_<ULID>`).
    pub session_id: String,
    /// The voice surface this session belongs to.
    pub surface_id: String,
    /// The action request being approved.
    pub bound_action_request_id: String,
    /// BLAKE3 canonical hash of the action.
    pub bound_action_canonical_hash: String,
    /// Current state in the approval FSM.
    pub state: VoiceApprovalState,
    /// The transcribed approval utterance, if available.
    pub transcript: Option<String>,
    /// Confidence score of the STT transcript.
    pub confidence: f64,
    /// Risk class of the action being approved.
    pub risk_class: VoiceRiskClass,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// When the session expires (TTL).
    pub expires_at: DateTime<Utc>,
}

impl VoiceApprovalSession {
    /// Create a new voice approval session.
    ///
    /// The session starts in [`VoiceApprovalState::Listening`] and expires
    /// after `ttl_seconds`.
    #[must_use]
    pub fn new(
        surface_id: String,
        bound_action_request_id: String,
        bound_action_canonical_hash: String,
        risk_class: VoiceRiskClass,
        ttl_seconds: u32,
    ) -> Self {
        let now = Utc::now();
        Self {
            session_id: format!("vas_{}", Ulid::new()),
            surface_id,
            bound_action_request_id,
            bound_action_canonical_hash,
            state: VoiceApprovalState::Listening,
            transcript: None,
            confidence: 0.0,
            risk_class,
            created_at: now,
            expires_at: now + Duration::seconds(i64::from(ttl_seconds)),
        }
    }

    /// Check whether the session has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Attempt to transition to a new state.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceRendererError::ApprovalTimeout`] if the session has
    /// expired, or an error string if the transition is invalid.
    pub async fn transition(
        &mut self,
        target: VoiceApprovalState,
        evidence_emitter: &Arc<dyn VoiceEvidenceEmitter>,
    ) -> Result<(), VoiceRendererError> {
        if self.state.is_terminal() {
            return Err(VoiceRendererError::IoError(format!(
                "session {} is already terminal ({:?})",
                self.session_id, self.state
            )));
        }

        if !self.state.can_transition_to(target) {
            return Err(VoiceRendererError::IoError(format!(
                "invalid transition from {:?} to {:?}",
                self.state, target
            )));
        }

        self.state = target;
        self.emit_evidence(evidence_emitter).await?;
        Ok(())
    }

    /// Record a transcript and transition from Listening to Transcribing.
    ///
    /// # Errors
    ///
    /// Returns an error if the transition is invalid or evidence emission fails.
    pub async fn set_transcript(
        &mut self,
        transcript: String,
        confidence: f64,
        evidence_emitter: &Arc<dyn VoiceEvidenceEmitter>,
    ) -> Result<(), VoiceRendererError> {
        self.transcript = Some(transcript);
        self.confidence = confidence;
        self.transition(VoiceApprovalState::Transcribing, evidence_emitter)
            .await?;
        self.transition(VoiceApprovalState::Validating, evidence_emitter)
            .await
    }

    /// Validate the approval against risk-based confidence thresholds.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceRendererError::ApprovalHighRiskRejected`] for CRITICAL
    /// risk without visual co-approval, or
    /// [`VoiceRendererError::SttConfidenceTooLow`] if confidence is below
    /// the risk-class floor.
    pub fn validate(&self) -> Result<(), VoiceRendererError> {
        let floor = self.risk_class.confidence_floor();
        if self.confidence < floor {
            return Err(VoiceRendererError::SttConfidenceTooLow {
                confidence: self.confidence,
                threshold: floor,
            });
        }
        Ok(())
    }

    /// Approve the action — validate risk and confidence, then transition
    /// through Confirming to Confirmed.
    ///
    /// # Errors
    ///
    /// Returns an error if risk/confidence checks fail, session is expired,
    /// or evidence emission fails.
    pub async fn approve(
        &mut self,
        evidence_emitter: &Arc<dyn VoiceEvidenceEmitter>,
    ) -> Result<(), VoiceRendererError> {
        // INV-031 + constitutional: CRITICAL risk cannot be approved by voice alone
        if self.risk_class.requires_visual_confirm() {
            return Err(VoiceRendererError::ApprovalHighRiskRejected);
        }

        self.validate()?;

        if self.is_expired() {
            self.state = VoiceApprovalState::TimedOut;
            self.emit_evidence(evidence_emitter).await?;
            return Err(VoiceRendererError::ApprovalTimeout {
                session_id: self.session_id.clone(),
                ttl_ms: (self.expires_at - self.created_at).num_milliseconds() as u64,
            });
        }

        self.transition(VoiceApprovalState::Confirming, evidence_emitter)
            .await?;
        self.transition(VoiceApprovalState::Confirmed, evidence_emitter)
            .await
    }

    /// Reject the approval.
    ///
    /// # Errors
    ///
    /// Returns an error if the transition or evidence emission fails.
    pub async fn reject(
        &mut self,
        evidence_emitter: &Arc<dyn VoiceEvidenceEmitter>,
    ) -> Result<(), VoiceRendererError> {
        self.transition(VoiceApprovalState::Rejected, evidence_emitter)
            .await
    }

    /// Emit an evidence record for the current state.
    async fn emit_evidence(
        &self,
        evidence_emitter: &Arc<dyn VoiceEvidenceEmitter>,
    ) -> Result<(), VoiceRendererError> {
        let record_type = match self.state {
            VoiceApprovalState::Listening => VoiceRecordType::VoiceApprovalStarted,
            VoiceApprovalState::Confirmed => VoiceRecordType::VoiceApprovalConfirmed,
            VoiceApprovalState::Rejected | VoiceApprovalState::TimedOut => {
                VoiceRecordType::VoiceApprovalRejected
            }
            _ => VoiceRecordType::VoiceApprovalStarted,
        };

        let mut evidence = VoiceEvidence::new(
            record_type,
            self.surface_id.clone(),
            String::new(),
        );
        evidence.session_id = Some(self.session_id.clone());
        evidence.bound_action_id = Some(self.bound_action_request_id.clone());
        evidence.transcript = self.transcript.clone();
        evidence.payload = serde_json::json!({
            "confidence": self.confidence,
            "risk_class": self.risk_class,
            "created_at": self.created_at.to_rfc3339(),
            "expires_at": self.expires_at.to_rfc3339(),
        });

        evidence_emitter
            .emit(evidence)
            .await
            .map_err(VoiceRendererError::IoError)?;

        Ok(())
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
    use crate::evidence::InMemoryVoiceEvidenceEmitter;

    fn make_emitter() -> Arc<dyn VoiceEvidenceEmitter> {
        Arc::new(InMemoryVoiceEvidenceEmitter::new())
    }

    #[tokio::test]
    async fn approval_fsm_listening_to_confirmed() {
        let emitter = make_emitter();
        let mut session = VoiceApprovalSession::new(
            "vsrf_01HX".to_string(),
            "act_01HY".to_string(),
            blake3::hash(b"test-action").to_hex().to_string(),
            VoiceRiskClass::Low,
            300,
        );
        assert_eq!(session.state, VoiceApprovalState::Listening);

        session
            .set_transcript("approve".to_string(), 0.92, &emitter)
            .await
            .expect("set transcript");

        session.approve(&emitter).await.expect("approve");
        assert_eq!(session.state, VoiceApprovalState::Confirmed);
    }

    #[tokio::test]
    async fn approval_fsm_rejected_on_low_confidence() {
        let emitter = make_emitter();
        let mut session = VoiceApprovalSession::new(
            "vsrf_01HX".to_string(),
            "act_01HY".to_string(),
            blake3::hash(b"test-action").to_hex().to_string(),
            VoiceRiskClass::High,
            300,
        );
        session
            .set_transcript("approve".to_string(), 0.35, &emitter)
            .await
            .expect("set transcript");

        let result = session.approve(&emitter).await;
        assert!(result.is_err());
        match result {
            Err(VoiceRendererError::SttConfidenceTooLow { .. }) => {}
            other => panic!("expected SttConfidenceTooLow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn approval_reject_critical_risk_without_visual() {
        let emitter = make_emitter();
        let mut session = VoiceApprovalSession::new(
            "vsrf_01HX".to_string(),
            "act_01HY".to_string(),
            blake3::hash(b"critical-action").to_hex().to_string(),
            VoiceRiskClass::Critical,
            300,
        );
        session
            .set_transcript("approve".to_string(), 0.99, &emitter)
            .await
            .expect("set transcript");

        let result = session.approve(&emitter).await;
        assert!(result.is_err());
        match result {
            Err(VoiceRendererError::ApprovalHighRiskRejected) => {}
            other => panic!("expected ApprovalHighRiskRejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn approval_timed_out_after_ttl() {
        let emitter = make_emitter();
        let mut session = VoiceApprovalSession::new(
            "vsrf_01HX".to_string(),
            "act_01HY".to_string(),
            blake3::hash(b"test-action").to_hex().to_string(),
            VoiceRiskClass::Low,
            0, // zero TTL — expires immediately
        );
        session
            .set_transcript("approve".to_string(), 0.92, &emitter)
            .await
            .expect("set transcript");

        let result = session.approve(&emitter).await;
        assert!(result.is_err());
        match result {
            Err(VoiceRendererError::ApprovalTimeout { .. }) => {}
            other => panic!("expected ApprovalTimeout, got {other:?}"),
        }
        assert_eq!(session.state, VoiceApprovalState::TimedOut);
    }

    #[tokio::test]
    async fn approval_explicit_reject() {
        let emitter = make_emitter();
        let mut session = VoiceApprovalSession::new(
            "vsrf_01HX".to_string(),
            "act_01HY".to_string(),
            blake3::hash(b"test-action").to_hex().to_string(),
            VoiceRiskClass::Low,
            300,
        );
        session
            .set_transcript("no thanks".to_string(), 0.92, &emitter)
            .await
            .expect("set transcript");

        session.reject(&emitter).await.expect("reject");
        assert_eq!(session.state, VoiceApprovalState::Rejected);
    }

    #[test]
    fn session_id_has_correct_prefix() {
        let session = VoiceApprovalSession::new(
            "vsrf_01HX".to_string(),
            "act_01HY".to_string(),
            "abc123".to_string(),
            VoiceRiskClass::Low,
            300,
        );
        assert!(session.session_id.starts_with("vas_"));
    }

    #[test]
    fn session_not_expired_initially() {
        let session = VoiceApprovalSession::new(
            "vsrf_01HX".to_string(),
            "act_01HY".to_string(),
            "abc123".to_string(),
            VoiceRiskClass::Low,
            300,
        );
        assert!(!session.is_expired());
    }

    #[tokio::test]
    async fn cannot_transition_from_terminal() {
        let emitter = make_emitter();
        let mut session = VoiceApprovalSession::new(
            "vsrf_01HX".to_string(),
            "act_01HY".to_string(),
            blake3::hash(b"test-action").to_hex().to_string(),
            VoiceRiskClass::Low,
            300,
        );
        session
            .set_transcript("approve".to_string(), 0.92, &emitter)
            .await
            .expect("set transcript");
        session.approve(&emitter).await.expect("approve");
        assert!(session.state.is_terminal());

        let result = session
            .transition(VoiceApprovalState::Listening, &emitter)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn risk_class_high_satisfies_threshold() {
        let session = VoiceApprovalSession::new(
            "vsrf_01HX".to_string(),
            "act_01HY".to_string(),
            "abc123".to_string(),
            VoiceRiskClass::High,
            300,
        );
        // 0.85 >= 0.80 — should pass
        let mut s = session;
        s.confidence = 0.85;
        assert!(s.validate().is_ok());

        // 0.75 < 0.80 — should fail
        s.confidence = 0.75;
        assert!(s.validate().is_err());
    }

    #[test]
    fn risk_class_critical_satisfies_threshold() {
        let mut session = VoiceApprovalSession::new(
            "vsrf_01HX".to_string(),
            "act_01HY".to_string(),
            "abc123".to_string(),
            VoiceRiskClass::Critical,
            300,
        );
        session.confidence = 0.96;
        // confidence passes but risk class still blocks approval
        assert!(session.validate().is_ok());

        session.confidence = 0.90;
        assert!(session.validate().is_err());
    }
}
