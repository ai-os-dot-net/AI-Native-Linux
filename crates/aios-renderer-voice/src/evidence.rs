//! Voice evidence emission — record types and emitter trait.
//!
//! Defines a closed [`VoiceRecordType`] vocabulary for voice-renderer events
//! and the [`VoiceEvidenceEmitter`] trait that mirrors the cognitive / SGR
//! evidence emission discipline.

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Closed record-type taxonomy for voice renderer evidence events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoiceRecordType {
    /// A new voice surface was registered.
    VoiceSurfaceRegistered,
    /// Voice surface started capturing audio.
    VoiceListeningStarted,
    /// Voice surface stopped capturing audio.
    VoiceListeningStopped,
    /// STT produced a transcript.
    VoiceTranscriptReceived,
    /// Transcript was classified (intent pipeline step 2).
    VoiceTranscriptClassified,
    /// Transcript was rejected as unsafe (intent pipeline step 4).
    VoiceTranscriptRejectedAsUnsafe,
    /// TTS synthesis completed.
    TtsSynthesized,
    /// Voice approval session started.
    VoiceApprovalStarted,
    /// Voice approval was confirmed.
    VoiceApprovalConfirmed,
    /// Voice approval was rejected.
    VoiceApprovalRejected,
}

/// A sealed voice evidence record — emitted for every voice-surface event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceEvidence {
    /// Type of event being recorded.
    pub record_type: VoiceRecordType,
    /// The surface id that emitted this event.
    pub surface_id: String,
    /// Wall-clock timestamp at emission time.
    pub timestamp: DateTime<Utc>,
    /// Subject canonical id (the human operator bound to the surface).
    pub subject: String,
    /// Optional bound action request id.
    pub bound_action_id: Option<String>,
    /// Optional session id (for approval events).
    pub session_id: Option<String>,
    /// Optional transcript text.
    pub transcript: Option<String>,
    /// Additional context payload as JSON.
    pub payload: serde_json::Value,
}

impl VoiceEvidence {
    /// Create a new evidence record with the minimum required fields.
    #[must_use]
    pub fn new(record_type: VoiceRecordType, surface_id: String, subject: String) -> Self {
        Self {
            record_type,
            surface_id,
            timestamp: Utc::now(),
            subject,
            bound_action_id: None,
            session_id: None,
            transcript: None,
            payload: serde_json::Value::Null,
        }
    }
}

/// Async trait for voice evidence emission.
///
/// Every voice-surface event (registration, listening start/stop, transcript,
/// TTS, approval) must record an evidence event through this trait.
#[async_trait]
pub trait VoiceEvidenceEmitter: Send + Sync + Debug {
    /// Emit a voice evidence record.
    ///
    /// # Errors
    ///
    /// Returns an error string if the emission failed.
    async fn emit(&self, evidence: VoiceEvidence) -> Result<(), String>;
}

/// In-memory voice evidence emitter for test and prototype use.
#[derive(Debug, Default)]
pub struct InMemoryVoiceEvidenceEmitter {
    records: Mutex<Vec<VoiceEvidence>>,
}

impl InMemoryVoiceEvidenceEmitter {
    /// Create a new empty in-memory evidence store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
        }
    }

    /// Snapshot all records currently stored.
    pub async fn records(&self) -> Vec<VoiceEvidence> {
        self.records.lock().await.clone()
    }

    /// Count of records currently stored.
    pub async fn len(&self) -> usize {
        self.records.lock().await.len()
    }

    /// `true` iff no records have been emitted.
    pub async fn is_empty(&self) -> bool {
        self.records.lock().await.is_empty()
    }
}

#[async_trait]
impl VoiceEvidenceEmitter for InMemoryVoiceEvidenceEmitter {
    async fn emit(&self, evidence: VoiceEvidence) -> Result<(), String> {
        self.records.lock().await.push(evidence);
        Ok(())
    }
}

#[async_trait]
impl VoiceEvidenceEmitter for Arc<InMemoryVoiceEvidenceEmitter> {
    async fn emit(&self, evidence: VoiceEvidence) -> Result<(), String> {
        self.records.lock().await.push(evidence);
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

    #[tokio::test]
    async fn evidence_emitted_on_surface_registered() {
        let emitter = InMemoryVoiceEvidenceEmitter::new();
        let evidence = VoiceEvidence::new(
            VoiceRecordType::VoiceSurfaceRegistered,
            "vsrf_01HX".to_string(),
            "human:op-1".to_string(),
        );
        emitter.emit(evidence).await.expect("emit succeed");
        assert_eq!(emitter.len().await, 1);
        let records = emitter.records().await;
        assert_eq!(
            records[0].record_type,
            VoiceRecordType::VoiceSurfaceRegistered
        );
    }

    #[tokio::test]
    async fn evidence_emitted_on_transcript() {
        let emitter = InMemoryVoiceEvidenceEmitter::new();
        let mut evidence = VoiceEvidence::new(
            VoiceRecordType::VoiceTranscriptReceived,
            "vsrf_01HX".to_string(),
            "human:op-1".to_string(),
        );
        evidence.transcript = Some("hello world".to_string());
        emitter.emit(evidence).await.expect("emit succeed");
        assert_eq!(emitter.len().await, 1);
    }

    #[tokio::test]
    async fn evidence_emitted_on_approval() {
        let emitter = InMemoryVoiceEvidenceEmitter::new();
        let mut evidence = VoiceEvidence::new(
            VoiceRecordType::VoiceApprovalConfirmed,
            "vsrf_01HX".to_string(),
            "human:op-1".to_string(),
        );
        evidence.session_id = Some("vas_01HY".to_string());
        evidence.bound_action_id = Some("act_01HZ".to_string());
        emitter.emit(evidence).await.expect("emit succeed");
        assert_eq!(emitter.len().await, 1);
        let records = emitter.records().await;
        assert_eq!(
            records[0].record_type,
            VoiceRecordType::VoiceApprovalConfirmed
        );
        assert_eq!(records[0].session_id, Some("vas_01HY".to_string()));
    }

    #[tokio::test]
    async fn evidence_emitted_on_tts() {
        let emitter = InMemoryVoiceEvidenceEmitter::new();
        let evidence = VoiceEvidence::new(
            VoiceRecordType::TtsSynthesized,
            "vsrf_01HX".to_string(),
            "human:op-1".to_string(),
        );
        emitter.emit(evidence).await.expect("emit succeed");
        assert_eq!(emitter.len().await, 1);
        let records = emitter.records().await;
        assert_eq!(records[0].record_type, VoiceRecordType::TtsSynthesized);
    }

    #[tokio::test]
    async fn arc_emitter_works() {
        let emitter = Arc::new(InMemoryVoiceEvidenceEmitter::new());
        let evidence = VoiceEvidence::new(
            VoiceRecordType::VoiceSurfaceRegistered,
            "vsrf_01HX".to_string(),
            "human:op-1".to_string(),
        );
        emitter.emit(evidence).await.expect("emit succeed");
        assert_eq!(emitter.len().await, 1);
    }

    #[tokio::test]
    async fn is_empty_after_creation() {
        let emitter = InMemoryVoiceEvidenceEmitter::new();
        assert!(emitter.is_empty().await);
    }
}
