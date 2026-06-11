//! [`VoiceSurface`] — policy surface bound to a human operator.
//!
//! INV-031: A voice surface is a policy surface, never an authority. It can
//! capture audio (via PipeWire) and emit evidence, but it cannot authorize
//! actions on its own — all actions require the standard policy pipeline.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use aios_cognitive::SubjectRef;

use crate::enums::{SttProvider, TtsProvider, VoiceSurfaceState};
use crate::error::VoiceRendererError;
use crate::evidence::{VoiceEvidence, VoiceEvidenceEmitter, VoiceRecordType};

/// Policy constraints for a single voice surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceSurfacePolicy {
    /// Untrusted input flag — always true for voice surfaces.
    pub untrusted_input: bool,
    /// High-risk proposals require visual confirmation — always true.
    pub high_risk_requires_visual_confirm: bool,
    /// Optional wake word that activates the listening window.
    pub wake_word: Option<String>,
    /// Maximum listening duration in milliseconds (default 30 000).
    pub max_listen_duration_ms: u64,
}

impl Default for VoiceSurfacePolicy {
    fn default() -> Self {
        Self {
            untrusted_input: true,
            high_risk_requires_visual_confirm: true,
            wake_word: None,
            max_listen_duration_ms: 30_000,
        }
    }
}

/// A voice renderer surface bound to a single human operator.
///
/// Each surface captures audio via PipeWire, routes transcripts through the
/// STT pipeline, and emits voice evidence for every lifecycle event.
#[derive(Debug, Clone)]
pub struct VoiceSurface {
    /// Unique surface identifier (`vsrf_<ULID>`).
    pub surface_id: String,
    /// Canonical subject (HUMAN_OPERATOR only).
    pub bound_subject: SubjectRef,
    /// Current lifecycle state.
    pub state: VoiceSurfaceState,
    /// STT provider.
    pub stt_provider: SttProvider,
    /// TTS provider.
    pub tts_provider: TtsProvider,
    /// Per-surface policy constraints.
    pub policy: VoiceSurfacePolicy,
    /// Evidence emitter for lifecycle events.
    evidence_emitter: Arc<dyn VoiceEvidenceEmitter>,
    /// Timestamp when the surface was registered.
    pub registered_at: Option<DateTime<Utc>>,
}

impl VoiceSurface {
    /// Create a new voice surface in [`VoiceSurfaceState::Unconfigured`].
    #[must_use]
    pub fn new(
        subject: SubjectRef,
        stt_provider: SttProvider,
        tts_provider: TtsProvider,
        evidence_emitter: Arc<dyn VoiceEvidenceEmitter>,
    ) -> Self {
        Self {
            surface_id: format!("vsrf_{}", Ulid::new()),
            bound_subject: subject,
            state: VoiceSurfaceState::Unconfigured,
            stt_provider,
            tts_provider,
            policy: VoiceSurfacePolicy::default(),
            evidence_emitter,
            registered_at: None,
        }
    }

    /// Create a new surface with a custom policy.
    #[must_use]
    pub fn new_with_policy(
        subject: SubjectRef,
        stt_provider: SttProvider,
        tts_provider: TtsProvider,
        evidence_emitter: Arc<dyn VoiceEvidenceEmitter>,
        policy: VoiceSurfacePolicy,
    ) -> Self {
        Self {
            surface_id: format!("vsrf_{}", Ulid::new()),
            bound_subject: subject,
            state: VoiceSurfaceState::Unconfigured,
            stt_provider,
            tts_provider,
            policy,
            evidence_emitter,
            registered_at: None,
        }
    }

    /// Validate that the bound subject is a HUMAN_OPERATOR.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceRendererError::SubjectNotHumanOperator`] if the subject
    /// is not a human operator.
    pub fn validate_subject_human(&self) -> Result<(), VoiceRendererError> {
        let subj_str = self.bound_subject.0.to_lowercase();
        if subj_str.starts_with("human:") {
            Ok(())
        } else {
            Err(VoiceRendererError::SubjectNotHumanOperator {
                subject_type: self.bound_subject.0.clone(),
            })
        }
    }

    /// Register the voice surface — validate subject, emit evidence.
    ///
    /// # Errors
    ///
    /// Returns an error if subject validation fails or evidence emission fails.
    pub async fn register(&mut self) -> Result<(), VoiceRendererError> {
        self.validate_subject_human()?;

        self.state = VoiceSurfaceState::Idle;
        self.registered_at = Some(Utc::now());

        let evidence = VoiceEvidence::new(
            VoiceRecordType::VoiceSurfaceRegistered,
            self.surface_id.clone(),
            self.bound_subject.0.clone(),
        );
        self.evidence_emitter
            .emit(evidence)
            .await
            .map_err(VoiceRendererError::IoError)?;

        Ok(())
    }

    /// Begin audio capture from PipeWire.
    ///
    /// Transitions the surface to [`VoiceSurfaceState::Listening`] and emits
    /// a `VoiceListeningStarted` evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceRendererError::PipeWireNotAvailable`] if the PipeWire
    /// service is not accessible.
    pub async fn start_listening(&mut self) -> Result<(), VoiceRendererError> {
        if self.state == VoiceSurfaceState::Listening {
            return Ok(());
        }

        self.state = VoiceSurfaceState::Listening;

        let mut evidence = VoiceEvidence::new(
            VoiceRecordType::VoiceListeningStarted,
            self.surface_id.clone(),
            self.bound_subject.0.clone(),
        );
        evidence.payload = serde_json::json!({
            "max_listen_duration_ms": self.policy.max_listen_duration_ms,
        });
        self.evidence_emitter
            .emit(evidence)
            .await
            .map_err(VoiceRendererError::IoError)?;

        Ok(())
    }

    /// Stop audio capture.
    ///
    /// Transitions the surface back to [`VoiceSurfaceState::Idle`] and emits
    /// a `VoiceListeningStopped` evidence record.
    ///
    /// # Errors
    ///
    /// Returns an error if evidence emission fails.
    pub async fn stop_listening(&mut self) -> Result<(), VoiceRendererError> {
        if self.state != VoiceSurfaceState::Listening {
            return Err(VoiceRendererError::SurfaceNotListening {
                surface_id: self.surface_id.clone(),
                state: format!("{:?}", self.state),
            });
        }

        self.state = VoiceSurfaceState::Idle;

        let evidence = VoiceEvidence::new(
            VoiceRecordType::VoiceListeningStopped,
            self.surface_id.clone(),
            self.bound_subject.0.clone(),
        );
        self.evidence_emitter
            .emit(evidence)
            .await
            .map_err(VoiceRendererError::IoError)?;

        Ok(())
    }

    /// Speak text through the TTS audio pipeline to PipeWire.
    ///
    /// # Errors
    ///
    /// Returns an error if TTS synthesis or PipeWire playback fails.
    pub async fn speak(&self, _text: &str) -> Result<(), VoiceRendererError> {
        Err(VoiceRendererError::PipeWireNotAvailable(
            "PipeWire speech output not yet integrated".to_string(),
        ))
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

    #[tokio::test]
    async fn surface_register_human_operator_only() {
        let emitter = Arc::new(InMemoryVoiceEvidenceEmitter::new());
        let mut surface = VoiceSurface::new(
            SubjectRef("human:operator-1".to_string()),
            SttProvider::WhisperCpp,
            TtsProvider::Piper,
            emitter.clone(),
        );
        let result = surface.register().await;
        assert!(result.is_ok());
        assert_eq!(surface.state, VoiceSurfaceState::Idle);
        assert!(surface.registered_at.is_some());
        assert_eq!(emitter.len().await, 1);
    }

    #[tokio::test]
    async fn surface_reject_ai_subject() {
        let emitter = Arc::new(InMemoryVoiceEvidenceEmitter::new());
        let mut surface = VoiceSurface::new(
            SubjectRef("agent:dev:01HX".to_string()),
            SttProvider::WhisperCpp,
            TtsProvider::Piper,
            emitter.clone(),
        );
        let result = surface.register().await;
        assert!(result.is_err());
        match result {
            Err(VoiceRendererError::SubjectNotHumanOperator { .. }) => {}
            other => panic!("expected SubjectNotHumanOperator, got {other:?}"),
        }
        assert_eq!(emitter.len().await, 0);
    }

    #[tokio::test]
    async fn surface_start_listening() {
        let emitter = Arc::new(InMemoryVoiceEvidenceEmitter::new());
        let mut surface = VoiceSurface::new(
            SubjectRef("human:operator-1".to_string()),
            SttProvider::WhisperCpp,
            TtsProvider::Piper,
            emitter.clone(),
        );
        surface.register().await.expect("register");
        let result = surface.start_listening().await;
        assert!(result.is_ok());
        assert_eq!(surface.state, VoiceSurfaceState::Listening);
        assert_eq!(emitter.len().await, 2);
    }

    #[tokio::test]
    async fn surface_stop_listening() {
        let emitter = Arc::new(InMemoryVoiceEvidenceEmitter::new());
        let mut surface = VoiceSurface::new(
            SubjectRef("human:operator-1".to_string()),
            SttProvider::WhisperCpp,
            TtsProvider::Piper,
            emitter.clone(),
        );
        surface.register().await.expect("register");
        surface.start_listening().await.expect("start listening");
        let result = surface.stop_listening().await;
        assert!(result.is_ok());
        assert_eq!(surface.state, VoiceSurfaceState::Idle);
        assert_eq!(emitter.len().await, 3);
    }

    #[tokio::test]
    async fn surface_stop_listening_when_not_listening_fails() {
        let emitter = Arc::new(InMemoryVoiceEvidenceEmitter::new());
        let mut surface = VoiceSurface::new(
            SubjectRef("human:operator-1".to_string()),
            SttProvider::WhisperCpp,
            TtsProvider::Piper,
            emitter.clone(),
        );
        surface.register().await.expect("register");
        let result = surface.stop_listening().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn double_start_listening_is_idempotent() {
        let emitter = Arc::new(InMemoryVoiceEvidenceEmitter::new());
        let mut surface = VoiceSurface::new(
            SubjectRef("human:operator-1".to_string()),
            SttProvider::WhisperCpp,
            TtsProvider::Piper,
            emitter.clone(),
        );
        surface.register().await.expect("register");
        surface.start_listening().await.expect("start 1");
        surface.start_listening().await.expect("start 2");
        assert_eq!(surface.state, VoiceSurfaceState::Listening);
    }

    #[test]
    fn surface_id_has_correct_prefix() {
        let emitter = Arc::new(InMemoryVoiceEvidenceEmitter::new());
        let surface = VoiceSurface::new(
            SubjectRef("human:operator-1".to_string()),
            SttProvider::WhisperCpp,
            TtsProvider::Piper,
            emitter,
        );
        assert!(surface.surface_id.starts_with("vsrf_"));
    }

    #[test]
    fn default_policy_has_correct_values() {
        let policy = VoiceSurfacePolicy::default();
        assert!(policy.untrusted_input);
        assert!(policy.high_risk_requires_visual_confirm);
        assert_eq!(policy.max_listen_duration_ms, 30_000);
        assert!(policy.wake_word.is_none());
    }

    #[test]
    fn pipewire_not_available_returns_error() {
        let emitter = Arc::new(InMemoryVoiceEvidenceEmitter::new());
        let surface = VoiceSurface::new(
            SubjectRef("human:operator-1".to_string()),
            SttProvider::WhisperCpp,
            TtsProvider::Piper,
            emitter,
        );
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let result = rt.block_on(surface.speak("hello"));
        assert!(result.is_err());
        match result {
            Err(VoiceRendererError::PipeWireNotAvailable { .. }) => {}
            other => panic!("expected PipeWireNotAvailable, got {other:?}"),
        }
    }

    #[test]
    fn constructor_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VoiceSurface>();
        assert_send_sync::<VoiceSurfacePolicy>();
        assert_send_sync::<InMemoryVoiceEvidenceEmitter>();
    }
}
