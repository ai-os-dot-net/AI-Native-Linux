//! [`SttAdapter`] — speech-to-text routing adapter.
//!
//! Routes transcription requests to WhisperCpp, Vosk, or OnDevice providers
//! and runs the 4-state voice intent pipeline:
//! `Received → Classified → MappedToTypedAction → RejectedAsUnsafe`.

use serde::{Deserialize, Serialize};

use crate::enums::{SttProvider, VoiceIntent, VoiceRiskClass};
use crate::error::VoiceRendererError;

/// Result of a speech-to-text transcription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SttResult {
    /// The transcribed text.
    pub transcript: String,
    /// Confidence score (0.0 .. 1.0).
    pub confidence: f64,
    /// Detected language (ISO 639-1), if available.
    pub language: Option<String>,
    /// Duration of the audio input in milliseconds.
    pub audio_duration_ms: u64,
}

impl SttResult {
    /// Create a new STT result.
    #[must_use]
    pub fn new(transcript: String, confidence: f64, audio_duration_ms: u64) -> Self {
        Self {
            transcript,
            confidence,
            language: None,
            audio_duration_ms,
        }
    }

    /// Check if confidence meets or exceeds the given threshold.
    #[must_use]
    pub fn meets_confidence(&self, threshold: f64) -> bool {
        self.confidence >= threshold
    }
}

/// Speech-to-text adapter — routes to concrete STT providers.
///
/// Current providers are stub/mock only; real PipeWire audio capture and
/// model invocation land in a follow-up task.
#[derive(Debug, Clone)]
pub enum SttAdapter {
    /// Whisper.cpp provider.
    WhisperCpp {
        /// Path to the Whisper model file.
        model_path: Option<String>,
    },
    /// Vosk provider.
    Vosk {
        /// Path to the Vosk model directory.
        model_path: Option<String>,
    },
    /// On-device policy-approved provider.
    OnDevice {
        /// Path to the on-device model.
        model_path: Option<String>,
    },
}

impl SttAdapter {
    /// Create a new adapter for the given provider.
    #[must_use]
    pub fn new(provider: SttProvider) -> Self {
        match provider {
            SttProvider::WhisperCpp => Self::WhisperCpp { model_path: None },
            SttProvider::Vosk => Self::Vosk { model_path: None },
            SttProvider::OnDevicePolicyApproved => Self::OnDevice { model_path: None },
        }
    }

    /// Configure the model path for this adapter.
    pub fn configure_model(&mut self, path: &str) {
        match self {
            Self::WhisperCpp { model_path } | Self::Vosk { model_path } | Self::OnDevice { model_path } => {
                *model_path = Some(path.to_string());
            }
        }
    }

    /// Check whether a model has been configured.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        match self {
            Self::WhisperCpp { model_path } | Self::Vosk { model_path } | Self::OnDevice { model_path } => {
                model_path.is_some()
            }
        }
    }

    /// Transcribe raw audio data to text.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceRendererError::SttModelNotConfigured`] if no model path
    /// has been set, or [`VoiceRendererError::SttTranscriptionFailed`] if the
    /// mock/stub transcription cannot proceed.
    pub async fn transcribe(&self, _audio_data: &[u8]) -> Result<SttResult, VoiceRendererError> {
        if !self.is_configured() {
            return Err(VoiceRendererError::SttModelNotConfigured);
        }

        Err(VoiceRendererError::SttTranscriptionFailed(
            "STT engine not integrated (stub)".to_string(),
        ))
    }

    /// Transcribe and validate confidence against a threshold.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceRendererError::SttConfidenceTooLow`] if the result
    /// confidence is below the threshold.
    pub async fn transcribe_with_confidence(
        &self,
        audio_data: &[u8],
        threshold: f64,
    ) -> Result<SttResult, VoiceRendererError> {
        let result = self.transcribe(audio_data).await?;
        if !result.meets_confidence(threshold) {
            return Err(VoiceRendererError::SttConfidenceTooLow {
                confidence: result.confidence,
                threshold,
            });
        }
        Ok(result)
    }
}

/// Voice intent classifier — classifies a transcript through the 4-state
/// voice intent pipeline.
#[derive(Debug, Clone)]
pub struct VoiceIntentClassifier;

impl VoiceIntentClassifier {
    /// Create a new classifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Classify a transcript into a voice intent.
    ///
    /// For a real implementation this would integrate with
    /// `PromptBoundaryClassifier` from `aios-terminal`. The stub always
    /// returns `MappedToTypedAction` for non-empty transcripts.
    #[must_use]
    pub fn classify(&self, _transcript: &str) -> VoiceIntent {
        VoiceIntent::MappedToTypedAction
    }

    /// Classify and assess risk.
    ///
    /// Returns the classified intent and an associated risk class.
    #[must_use]
    pub fn classify_with_risk(&self, transcript: &str) -> (VoiceIntent, VoiceRiskClass) {
        let intent = self.classify(transcript);
        let risk = if transcript.contains("sudo")
            || transcript.contains("rm -rf")
            || transcript.contains("format")
        {
            VoiceRiskClass::Critical
        } else if transcript.contains("systemctl")
            || transcript.contains("modprobe")
            || transcript.contains("iptables")
        {
            VoiceRiskClass::High
        } else if transcript.contains("apt") || transcript.contains("pip") || transcript.contains("curl")
        {
            VoiceRiskClass::Medium
        } else {
            VoiceRiskClass::Low
        };
        (intent, risk)
    }
}

impl Default for VoiceIntentClassifier {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn stt_result_new_has_correct_fields() {
        let result = SttResult::new("hello".to_string(), 0.95, 3000);
        assert_eq!(result.transcript, "hello");
        assert!((result.confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(result.audio_duration_ms, 3000);
        assert!(result.language.is_none());
    }

    #[test]
    fn stt_result_meets_confidence() {
        let result = SttResult::new("hello".to_string(), 0.85, 1000);
        assert!(result.meets_confidence(0.80));
        assert!(!result.meets_confidence(0.90));
    }

    #[tokio::test]
    async fn stt_transcribe_fails_when_not_configured() {
        let adapter = SttAdapter::new(SttProvider::WhisperCpp);
        let result = adapter.transcribe(&[0u8; 16000]).await;
        assert!(result.is_err());
        match result {
            Err(VoiceRendererError::SttModelNotConfigured) => {}
            other => panic!("expected SttModelNotConfigured, got {other:?}"),
        }
    }

    #[test]
    fn stt_configure_model_sets_path() {
        let mut adapter = SttAdapter::new(SttProvider::WhisperCpp);
        adapter.configure_model("/models/whisper.bin");
        assert!(adapter.is_configured());
    }

    #[tokio::test]
    async fn stt_transcribe_routes_to_correct_provider() {
        let mut adapter = SttAdapter::new(SttProvider::Vosk);
        adapter.configure_model("/models/vosk");
        // Vosk is configured but not integrated — should get transcription failed,
        // NOT model not configured
        let result = adapter.transcribe(&[0u8; 16000]).await;
        assert!(result.is_err());
        match result {
            Err(VoiceRendererError::SttTranscriptionFailed(_)) => {}
            other => panic!("expected SttTranscriptionFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stt_low_confidence_rejected() {
        // For this test, we validate the confidence-checking logic directly
        // since the stub doesn't return real results
        let result = SttResult::new("hello".to_string(), 0.45, 1000);
        assert!(!result.meets_confidence(0.80));
        let err = VoiceRendererError::SttConfidenceTooLow {
            confidence: 0.45,
            threshold: 0.80,
        };
        assert!(err.to_string().contains("0.45"));
        assert!(err.to_string().contains("0.80"));
    }

    #[test]
    fn voice_intent_classified_maps_to_action() {
        let classifier = VoiceIntentClassifier::new();
        let intent = classifier.classify("show me the logs");
        assert_eq!(intent, VoiceIntent::MappedToTypedAction);
    }

    #[test]
    fn voice_intent_classified_with_risk_low() {
        let classifier = VoiceIntentClassifier::new();
        let (_intent, risk) = classifier.classify_with_risk("show me the logs");
        assert_eq!(risk, VoiceRiskClass::Low);
    }

    #[test]
    fn voice_intent_classified_with_risk_medium() {
        let classifier = VoiceIntentClassifier::new();
        let (_intent, risk) = classifier.classify_with_risk("apt install curl");
        assert_eq!(risk, VoiceRiskClass::Medium);
    }

    #[test]
    fn voice_intent_classified_with_risk_high() {
        let classifier = VoiceIntentClassifier::new();
        let (_intent, risk) = classifier.classify_with_risk("systemctl restart nginx");
        assert_eq!(risk, VoiceRiskClass::High);
    }

    #[test]
    fn voice_intent_classified_with_risk_critical() {
        let classifier = VoiceIntentClassifier::new();
        let (_intent, risk) = classifier.classify_with_risk("sudo rm -rf /");
        assert_eq!(risk, VoiceRiskClass::Critical);
    }
}
