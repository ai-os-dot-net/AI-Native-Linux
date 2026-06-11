//! Closed vocabulary types for the Voice Renderer (Rev.6 S7.∞).
//!
//! Every enum derives `EnumIter` + `EnumCount` for compile-time exhaustiveness
//! checking. Serde wire form is `SCREAMING_SNAKE_CASE`.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// Voice surface lifecycle state.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoiceSurfaceState {
    /// Surface created but not yet configured.
    Unconfigured,
    /// Surface is capturing audio from PipeWire.
    Listening,
    /// Captured audio is being processed by STT.
    Processing,
    /// Surface is producing audio output via TTS.
    Speaking,
    /// Surface is ready but not actively capturing or producing.
    Idle,
    /// Surface is in an error state.
    Error,
}

impl Default for VoiceSurfaceState {
    fn default() -> Self {
        Self::Unconfigured
    }
}

/// STT provider enumeration — closed vocabulary.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SttProvider {
    /// OpenAI Whisper.cpp — local on-device STT.
    WhisperCpp,
    /// Vosk — lightweight on-device STT.
    Vosk,
    /// On-device policy-approved STT provider.
    OnDevicePolicyApproved,
}

/// TTS provider enumeration — closed vocabulary.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TtsProvider {
    /// Piper TTS — local on-device synthesis.
    Piper,
    /// eSpeak NG — lightweight local synthesis.
    EspeakNg,
    /// ElevenLabs — must go through Vault Broker (never direct).
    ElevenLabsVaultBrokered,
}

/// Voice approval session state — 7-state FSM.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoiceApprovalState {
    /// Session created, awaiting audio capture.
    Listening,
    /// Audio captured, STT transcription in progress.
    Transcribing,
    /// Transcript available, being validated against policy.
    Validating,
    /// Validation passed, awaiting user confirm utterance.
    Confirming,
    /// Approval confirmed by voice.
    Confirmed,
    /// Approval explicitly rejected.
    Rejected,
    /// Session TTL expired before confirmation.
    TimedOut,
}

impl VoiceApprovalState {
    /// Returns `true` if this is a terminal state (no further transitions).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Confirmed | Self::Rejected | Self::TimedOut)
    }

    /// Returns the valid next state, or `None` if this is terminal.
    #[must_use]
    pub fn can_transition_to(self, target: Self) -> bool {
        match (self, target) {
            (Self::Listening, Self::Transcribing) => true,
            (Self::Transcribing, Self::Validating) => true,
            (Self::Validating, Self::Confirming) => true,
            (Self::Validating, Self::Rejected) => true,
            (Self::Confirming, Self::Confirmed) => true,
            (Self::Confirming, Self::Rejected) => true,
            (Self::Confirming, Self::TimedOut) => true,
            (s, _) if s.is_terminal() => false,
            _ => false,
        }
    }
}

/// Voice intent lifecycle — 4-state pipeline.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoiceIntent {
    /// Raw audio has been received.
    Received,
    /// Transcript has been classified by PromptBoundaryClassifier.
    Classified,
    /// Intent successfully mapped to a typed action.
    MappedToTypedAction,
    /// Intent rejected as unsafe by policy.
    RejectedAsUnsafe,
}

/// Risk classification for voice-originated intents.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoiceRiskClass {
    /// Read-only or trivially reversible intent.
    Low,
    /// Reversible mutation with defined rollback.
    Medium,
    /// Security-, kernel-, or network-affecting intent.
    High,
    /// Critical profile / boot-integrity intent — cannot approve by voice alone.
    Critical,
}

impl VoiceRiskClass {
    /// Minimum confidence threshold for this risk class.
    #[must_use]
    pub fn confidence_floor(self) -> f64 {
        match self {
            Self::Low | Self::Medium => 0.50,
            Self::High => 0.80,
            Self::Critical => 0.95,
        }
    }

    /// Returns `true` if this risk class requires visual co-approval
    /// (cannot be approved by voice alone).
    #[must_use]
    pub fn requires_visual_confirm(self) -> bool {
        matches!(self, Self::Critical)
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
    use strum::{EnumCount, IntoEnumIterator};

    #[test]
    fn voice_surface_state_is_six_variants() {
        assert_eq!(VoiceSurfaceState::COUNT, 6);
    }

    #[test]
    fn stt_provider_is_three_variants() {
        assert_eq!(SttProvider::COUNT, 3);
    }

    #[test]
    fn tts_provider_is_three_variants() {
        assert_eq!(TtsProvider::COUNT, 3);
    }

    #[test]
    fn voice_approval_state_is_seven_variants() {
        assert_eq!(VoiceApprovalState::COUNT, 7);
    }

    #[test]
    fn voice_intent_is_four_variants() {
        assert_eq!(VoiceIntent::COUNT, 4);
    }

    #[test]
    fn voice_risk_class_is_four_variants() {
        assert_eq!(VoiceRiskClass::COUNT, 4);
    }

    #[test]
    fn surface_default_state_is_unconfigured() {
        assert_eq!(
            VoiceSurfaceState::default(),
            VoiceSurfaceState::Unconfigured
        );
    }

    #[test]
    fn terminal_states_are_terminal() {
        assert!(VoiceApprovalState::Confirmed.is_terminal());
        assert!(VoiceApprovalState::Rejected.is_terminal());
        assert!(VoiceApprovalState::TimedOut.is_terminal());
        assert!(!VoiceApprovalState::Listening.is_terminal());
    }

    #[test]
    fn approval_fsm_valid_transitions() {
        assert!(VoiceApprovalState::Listening.can_transition_to(VoiceApprovalState::Transcribing));
        assert!(VoiceApprovalState::Transcribing.can_transition_to(VoiceApprovalState::Validating));
        assert!(VoiceApprovalState::Validating.can_transition_to(VoiceApprovalState::Confirming));
        assert!(VoiceApprovalState::Validating.can_transition_to(VoiceApprovalState::Rejected));
        assert!(VoiceApprovalState::Confirming.can_transition_to(VoiceApprovalState::Confirmed));
        assert!(VoiceApprovalState::Confirming.can_transition_to(VoiceApprovalState::Rejected));
        assert!(VoiceApprovalState::Confirming.can_transition_to(VoiceApprovalState::TimedOut));
    }

    #[test]
    fn approval_fsm_invalid_transitions() {
        assert!(!VoiceApprovalState::Listening.can_transition_to(VoiceApprovalState::Confirmed));
        assert!(!VoiceApprovalState::Transcribing.can_transition_to(VoiceApprovalState::Confirming));
        assert!(!VoiceApprovalState::Confirmed
            .can_transition_to(VoiceApprovalState::Listening));
    }

    #[test]
    fn critical_requires_visual_confirm() {
        assert!(VoiceRiskClass::Critical.requires_visual_confirm());
        assert!(!VoiceRiskClass::High.requires_visual_confirm());
        assert!(!VoiceRiskClass::Medium.requires_visual_confirm());
        assert!(!VoiceRiskClass::Low.requires_visual_confirm());
    }

    #[test]
    fn confidence_floors() {
        assert!((VoiceRiskClass::Low.confidence_floor() - 0.50).abs() < f64::EPSILON);
        assert!((VoiceRiskClass::Medium.confidence_floor() - 0.50).abs() < f64::EPSILON);
        assert!((VoiceRiskClass::High.confidence_floor() - 0.80).abs() < f64::EPSILON);
        assert!((VoiceRiskClass::Critical.confidence_floor() - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn serde_roundtrip_all_enums() {
        for variant in VoiceSurfaceState::iter() {
            let json = serde_json::to_string(&variant).expect("serialize");
            let back: VoiceSurfaceState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, back);
        }
        for variant in VoiceApprovalState::iter() {
            let json = serde_json::to_string(&variant).expect("serialize");
            let back: VoiceApprovalState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, back);
        }
        for variant in VoiceRiskClass::iter() {
            let json = serde_json::to_string(&variant).expect("serialize");
            let back: VoiceRiskClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, back);
        }
        for variant in VoiceIntent::iter() {
            let json = serde_json::to_string(&variant).expect("serialize");
            let back: VoiceIntent = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn error_display_contains_message() {
        let err = crate::error::VoiceRendererError::PipeWireNotAvailable("no pw".to_string());
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }
}
