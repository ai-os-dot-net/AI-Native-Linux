//! `aios-renderer-voice` — Rev.6 Voice Renderer (S7.∞).
//!
//! Provides speech-to-text (STT), text-to-speech (TTS), and voice approval
//! channels under the same policy/evidence discipline as other renderers.
//!
//! ## Surface model
//!
//! - [`VoiceSurface`] — a policy surface bound to a single human operator.
//!   Registers with PipeWire, captures audio, and emits evidence.
//! - [`VoiceSurfacePolicy`] — per-surface constraints (wake word, max listen
//!   duration, untrusted-input flag).
//!
//! ## STT pipeline
//!
//! - [`SttAdapter`] routes to WhisperCpp / Vosk / OnDevice providers.
//! - Voice intents flow through a 4-state pipeline:
//!   `Received → Classified → MappedToTypedAction → RejectedAsUnsafe`.
//!
//! ## TTS pipeline
//!
//! - [`TtsAdapter`] routes to Piper / EspeakNg / ElevenLabsVaultBrokered.
//! - ElevenLabs always traverses the Vault Broker (never direct).
//!
//! ## Voice approval FSM
//!
//! - 7-state lifecycle: `Listening → Transcribing → Validating → Confirming →
//!   Confirmed / Rejected / TimedOut`.
//! - CRITICAL risk actions cannot be approved by voice alone (require visual
//!   co-approval).
//!
//! ## Constitutional invariants
//!
//! - INV-031: Voice surface is a policy surface, never an authority.
//! - #![forbid(unsafe_code)] — no unsafe anywhere.
//! - No unwrap / expect / panic outside test blocks.

#![forbid(unsafe_code)]

pub mod approval;
pub mod component_render;
pub mod enums;
pub mod error;
pub mod evidence;
pub mod stt;
pub mod surface;
pub mod tts;

pub use approval::VoiceApprovalSession;
pub use enums::{
    SttProvider, TtsProvider, VoiceApprovalState, VoiceIntent, VoiceRiskClass, VoiceSurfaceState,
};
pub use error::VoiceRendererError;
pub use evidence::{InMemoryVoiceEvidenceEmitter, VoiceEvidenceEmitter, VoiceRecordType};
pub use stt::{SttAdapter, SttResult};
pub use surface::{VoiceSurface, VoiceSurfacePolicy};
pub use tts::{TtsAdapter, TtsRequest, TtsResult};
