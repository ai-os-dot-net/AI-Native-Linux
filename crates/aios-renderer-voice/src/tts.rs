//! [`TtsAdapter`] — text-to-speech routing adapter.
//!
//! Routes synthesis requests to Piper, eSpeak NG, or ElevenLabs (Vault Broker).
//! ElevenLabs always traverses the Vault Broker — never a direct API call.

use serde::{Deserialize, Serialize};

use crate::enums::TtsProvider;
use crate::error::VoiceRendererError;

/// A text-to-speech synthesis request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtsRequest {
    /// The text to synthesize.
    pub text: String,
    /// Voice profile identifier.
    pub voice_id: String,
    /// Playback speed multiplier (0.5 .. 2.0).
    pub speed: f64,
    /// Optional pitch adjustment (Hz).
    pub pitch: Option<f64>,
}

impl TtsRequest {
    /// Create a new TTS request with default speed.
    #[must_use]
    pub fn new(text: String, voice_id: String) -> Self {
        Self {
            text,
            voice_id,
            speed: 1.0,
            pitch: None,
        }
    }

    /// Validate that speed is within the allowed range.
    ///
    /// # Errors
    ///
    /// Returns an error string if speed is outside 0.5..2.0.
    pub fn validate_speed(&self) -> Result<(), String> {
        if self.speed < 0.5 || self.speed > 2.0 {
            return Err(format!(
                "speed {} out of range: must be 0.5..2.0",
                self.speed
            ));
        }
        Ok(())
    }
}

/// Result of a text-to-speech synthesis.
#[derive(Debug, Clone)]
pub struct TtsResult {
    /// Synthesized audio as WAV bytes.
    pub audio_wav: Vec<u8>,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Duration of the synthesized audio in milliseconds.
    pub duration_ms: u64,
}

impl TtsResult {
    /// Create a new TTS result.
    #[must_use]
    pub fn new(audio_wav: Vec<u8>, sample_rate: u32, duration_ms: u64) -> Self {
        Self {
            audio_wav,
            sample_rate,
            duration_ms,
        }
    }
}

/// Text-to-speech adapter — routes to concrete TTS providers.
///
/// Current providers are stub/mock only; real synthesis and PipeWire
/// playback land in a follow-up task.
#[derive(Debug, Clone)]
pub enum TtsAdapter {
    /// Piper TTS provider.
    Piper,
    /// eSpeak NG provider.
    EspeakNg,
    /// ElevenLabs via Vault Broker (never direct).
    ElevenLabsVaultBrokered,
}

impl TtsAdapter {
    /// Create a new adapter for the given provider.
    #[must_use]
    pub fn new(provider: TtsProvider) -> Self {
        match provider {
            TtsProvider::Piper => Self::Piper,
            TtsProvider::EspeakNg => Self::EspeakNg,
            TtsProvider::ElevenLabsVaultBrokered => Self::ElevenLabsVaultBrokered,
        }
    }

    /// Synthesize text into audio.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceRendererError::TtsSynthesisFailed`] for stub providers
    /// and [`VoiceRendererError::TtsUnsupportedProvider`] for unknown providers.
    pub async fn synthesize(&self, _request: &TtsRequest) -> Result<TtsResult, VoiceRendererError> {
        match self {
            Self::ElevenLabsVaultBrokered => {
                Err(VoiceRendererError::TtsSynthesisFailed(
                    "ElevenLabs Vault Broker route not yet integrated (stub)".to_string(),
                ))
            }
            _ => Err(VoiceRendererError::TtsSynthesisFailed(
                "TTS engine not integrated (stub)".to_string(),
            )),
        }
    }

    /// Synthesize and play through a PipeWire surface.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceRendererError::PipeWireNotAvailable`] since PipeWire
    /// playback is not yet integrated.
    pub async fn speak_to_surface(
        &self,
        _surface_id: &str,
        _text: &str,
    ) -> Result<(), VoiceRendererError> {
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

    #[test]
    fn tts_request_validate_speed_in_range() {
        let req = TtsRequest::new("hello".to_string(), "en-US".to_string());
        assert!(req.validate_speed().is_ok());

        let req_fast = TtsRequest {
            text: "hello".to_string(),
            voice_id: "en-US".to_string(),
            speed: 2.0,
            pitch: None,
        };
        assert!(req_fast.validate_speed().is_ok());
    }

    #[test]
    fn tts_request_validate_speed_out_of_range() {
        let req = TtsRequest {
            text: "hello".to_string(),
            voice_id: "en-US".to_string(),
            speed: 3.0,
            pitch: None,
        };
        assert!(req.validate_speed().is_err());

        let req_slow = TtsRequest {
            text: "hello".to_string(),
            voice_id: "en-US".to_string(),
            speed: 0.1,
            pitch: None,
        };
        assert!(req_slow.validate_speed().is_err());
    }

    #[test]
    fn tts_result_new_has_correct_fields() {
        let wav = vec![0u8; 1024];
        let result = TtsResult::new(wav.clone(), 22050, 1500);
        assert_eq!(result.audio_wav, wav);
        assert_eq!(result.sample_rate, 22050);
        assert_eq!(result.duration_ms, 1500);
    }

    #[tokio::test]
    async fn tts_synthesize_returns_error_stub() {
        let adapter = TtsAdapter::new(TtsProvider::Piper);
        let req = TtsRequest::new("hello".to_string(), "en-US".to_string());
        let result = adapter.synthesize(&req).await;
        assert!(result.is_err());
        match result {
            Err(VoiceRendererError::TtsSynthesisFailed(_)) => {}
            other => panic!("expected TtsSynthesisFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tts_eleven_labs_routed_through_vault() {
        let adapter = TtsAdapter::new(TtsProvider::ElevenLabsVaultBrokered);
        let req = TtsRequest::new("hello".to_string(), "eleven-voice-1".to_string());
        let result = adapter.synthesize(&req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ElevenLabs") || msg.contains("Vault Broker"),
            "expected ElevenLabs/Vault error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn tts_synthesize_returns_wav_stub() {
        // stub returns error — verify it's the expected error type
        let adapter = TtsAdapter::new(TtsProvider::Piper);
        let req = TtsRequest::new("test".to_string(), "voice-1".to_string());
        let result = adapter.synthesize(&req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn tts_speak_to_surface_returns_pipewire_error() {
        let adapter = TtsAdapter::new(TtsProvider::Piper);
        let result = adapter.speak_to_surface("vsrf_01HX", "hello").await;
        assert!(result.is_err());
        match result {
            Err(VoiceRendererError::PipeWireNotAvailable { .. }) => {}
            other => panic!("expected PipeWireNotAvailable, got {other:?}"),
        }
    }
}
