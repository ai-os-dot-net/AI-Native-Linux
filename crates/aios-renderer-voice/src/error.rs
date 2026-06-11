//! [`VoiceRendererError`] — closed failure taxonomy for the Voice Renderer.

use thiserror::Error;

/// Failure modes for voice surface, STT, TTS, and approval operations.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum VoiceRendererError {
    /// STT model path has not been configured.
    #[error("STT model not configured — call configure_model before transcribing")]
    SttModelNotConfigured,

    /// STT transcription pipeline failed.
    #[error("STT transcription failed: {0}")]
    SttTranscriptionFailed(String),

    /// STT confidence fell below the required threshold.
    #[error("STT confidence too low: {confidence:.2} < {threshold:.2}")]
    SttConfidenceTooLow {
        /// Actual confidence from STT engine.
        confidence: f64,
        /// Required confidence threshold.
        threshold: f64,
    },

    /// TTS synthesis pipeline failed.
    #[error("TTS synthesis failed: {0}")]
    TtsSynthesisFailed(String),

    /// TTS provider is not supported or not configured.
    #[error("TTS provider unsupported: {0}")]
    TtsUnsupportedProvider(String),

    /// Voice surface has not been registered.
    #[error("voice surface `{surface_id}` is not registered")]
    SurfaceNotRegistered {
        /// The surface id that was looked up.
        surface_id: String,
    },

    /// Voice surface is not in the Listening state.
    #[error("voice surface `{surface_id}` is not listening (current state: {state:?})")]
    SurfaceNotListening {
        /// The surface id.
        surface_id: String,
        /// Current state of the surface.
        state: String,
    },

    /// Voice approval session timed out before confirmation.
    #[error("voice approval session `{session_id}` timed out after {ttl_ms}ms")]
    ApprovalTimeout {
        /// The session id.
        session_id: String,
        /// Time-to-live in milliseconds.
        ttl_ms: u64,
    },

    /// Voice approval was rejected due to high risk without visual co-approval.
    #[error("voice approval rejected: CRITICAL risk requires visual co-approval")]
    ApprovalHighRiskRejected,

    /// PipeWire service is not available on this host.
    #[error("PipeWire not available: {0}")]
    PipeWireNotAvailable(String),

    /// Subject validation failed — only HUMAN_OPERATOR subjects are allowed.
    #[error(
        "voice surfaces are restricted to HUMAN_OPERATOR subjects, got subject_type `{subject_type}`"
    )]
    SubjectNotHumanOperator {
        /// The subject type that was rejected.
        subject_type: String,
    },

    /// General I/O failure.
    #[error("voice renderer I/O error: {0}")]
    IoError(String),
}
