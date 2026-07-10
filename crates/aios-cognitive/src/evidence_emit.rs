//! Cognitive evidence emission policy (S13.x -> S3.1).
//!
//! Mirrors the SGR evidence pattern (T-090) with expected-previous-receipt
//! validation, Ed25519 signing, and BLAKE3 ReceiptChain linkage.

#![allow(
    clippy::module_name_repetitions,
    reason = "Public names mirror the cognitive evidence vocabulary"
)]

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use aios_evidence::{EvidenceError, EvidenceReceipt, ReceiptBuilder, ReceiptChain, RecordType};

use crate::circuit::CircuitState;
use crate::evidence_payloads::{
    AiDirectInternetDeniedPayload, BackendHealthChangedPayload, CircuitBreakerTrippedPayload,
    ModelCallPayload, RoutingDecisionPayload,
};
use crate::routing::{AICrossOriginPosture, BackendHealthState, ModelBackendKind, ProviderClass};
use crate::CognitiveError;

/// Constitutional default subject id for cognitive evidence emissions.
pub const AIOS_COGNITIVE_SUBJECT: &str = "_system:service:cognitive-core";

/// Canonical subject reference for cognitive evidence emission.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CognitiveSubjectRef(
    /// Canonical S5.1 subject id.
    pub String,
);

/// Async append-only sink for sealed, signed cognitive evidence receipts.
#[async_trait]
pub trait CognitiveEvidenceLog: Send + Sync + Debug {
    /// Seal, sign, and append a receipt builder.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] when sealing, signing, chain validation, or
    /// backend storage fails.
    async fn append_signed(
        &self,
        builder: ReceiptBuilder,
        signing_key: &SigningKey,
        expected_previous_receipt_id: Option<&str>,
    ) -> Result<EvidenceReceipt, EvidenceError>;
}

/// In-process evidence sink backed by a single `ReceiptChain`.
#[derive(Debug)]
pub struct InMemoryCognitiveEvidenceLog {
    chain: Mutex<ReceiptChain>,
}

impl Default for InMemoryCognitiveEvidenceLog {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCognitiveEvidenceLog {
    /// Construct an empty in-memory evidence log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            chain: Mutex::new(ReceiptChain::new()),
        }
    }

    /// Snapshot every receipt currently on the chain.
    pub async fn receipts(&self) -> Vec<EvidenceReceipt> {
        self.chain.lock().await.receipts().to_vec()
    }

    /// Count of receipts currently on the chain.
    pub async fn len(&self) -> usize {
        self.chain.lock().await.len()
    }

    /// `true` iff the chain has no receipts yet.
    pub async fn is_empty(&self) -> bool {
        self.chain.lock().await.is_empty()
    }

    /// Verify BLAKE3 hash-chain integrity.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] on the first chain-link mismatch.
    pub async fn verify_integrity(&self) -> Result<(), EvidenceError> {
        self.chain.lock().await.verify_integrity()
    }

    /// Verify BLAKE3 hash-chain integrity and each receipt signature.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] on the first chain or signature failure.
    pub async fn verify_integrity_signed(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<(), EvidenceError> {
        self.chain
            .lock()
            .await
            .verify_integrity_signed(verifying_key)
    }
}

#[async_trait]
impl CognitiveEvidenceLog for InMemoryCognitiveEvidenceLog {
    async fn append_signed(
        &self,
        builder: ReceiptBuilder,
        signing_key: &SigningKey,
        expected_previous_receipt_id: Option<&str>,
    ) -> Result<EvidenceReceipt, EvidenceError> {
        let mut guard = self.chain.lock().await;
        let previous = guard.receipts().last().cloned();
        validate_expected_previous_receipt(previous.as_ref(), expected_previous_receipt_id)?;
        let receipt = builder.seal_signed(previous.as_ref(), signing_key)?;
        guard.append(receipt.clone())?;
        drop(guard);
        Ok(receipt)
    }
}

/// Cognitive evidence emitter with helpers for S13.x lifecycle points.
#[derive(Clone)]
pub struct CognitiveEvidenceEmitter {
    log: Arc<dyn CognitiveEvidenceLog>,
    signing_key: SigningKey,
    subject: CognitiveSubjectRef,
}

impl Debug for CognitiveEvidenceEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CognitiveEvidenceEmitter")
            .field("log", &"<dyn CognitiveEvidenceLog>")
            .field("signing_key", &"<redacted>")
            .field("subject", &self.subject)
            .finish()
    }
}

impl CognitiveEvidenceEmitter {
    /// Construct a new cognitive evidence emitter.
    #[must_use]
    pub fn new(
        log: Arc<dyn CognitiveEvidenceLog>,
        signing_key: SigningKey,
        subject: CognitiveSubjectRef,
    ) -> Self {
        Self {
            log,
            signing_key,
            subject,
        }
    }

    /// Borrow the underlying sink.
    #[must_use]
    pub fn log(&self) -> &Arc<dyn CognitiveEvidenceLog> {
        &self.log
    }

    /// Return the Ed25519 verifying key for receipts emitted by this emitter.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    async fn emit<P>(&self, record_type: RecordType, payload: &P) -> Result<String, CognitiveError>
    where
        P: Serialize + Sync,
    {
        let payload_value = serde_json::to_value(payload).map_err(|e| {
            CognitiveError::EvidenceEmitFailed(format!("payload serialization failed: {e}"))
        })?;
        let retention = aios_evidence::record::retention_class_for(record_type);
        let builder = ReceiptBuilder::new(record_type, retention, self.subject.0.clone())
            .with_payload(payload_value);
        let receipt = self
            .log
            .append_signed(builder, &self.signing_key, None)
            .await
            .map_err(|e| CognitiveError::EvidenceEmitFailed(e.to_string()))?;
        Ok(receipt.receipt_id().as_str().to_owned())
    }

    /// Emit `MODEL_CALL` after a successful model invocation.
    ///
    /// # Errors
    ///
    /// Returns [`CognitiveError::EvidenceEmitFailed`] when evidence append fails.
    pub async fn emit_model_call(
        &self,
        model_id: &str,
        routing_id: &str,
        tokens_in: u32,
        tokens_out: u32,
        cost_micros: u64,
        latency_ms: u64,
    ) -> Result<String, CognitiveError> {
        let payload = ModelCallPayload {
            model_id: model_id.to_owned(),
            routing_id: routing_id.to_owned(),
            tokens_in,
            tokens_out,
            cost_micros,
            latency_ms,
            occurred_at: Utc::now(),
        };
        self.emit(RecordType::ModelCall, &payload).await
    }

    /// Emit `ROUTING_DECISION` after the model router selects a backend.
    ///
    /// # Errors
    ///
    /// Returns [`CognitiveError::EvidenceEmitFailed`] when evidence append fails.
    pub async fn emit_routing_decision(
        &self,
        routing_id: &str,
        chosen_backend: ModelBackendKind,
        inputs_hash: &str,
        code_version: &str,
    ) -> Result<String, CognitiveError> {
        let payload = RoutingDecisionPayload {
            routing_id: routing_id.to_owned(),
            chosen_backend,
            inputs_hash: inputs_hash.to_owned(),
            decided_at: Utc::now(),
            code_version: code_version.to_owned(),
        };
        self.emit(RecordType::RoutingDecision, &payload).await
    }

    /// Emit `CIRCUIT_BREAKER_OPENED` or `CIRCUIT_BREAKER_CLOSED` on state transition.
    ///
    /// # Errors
    ///
    /// Returns [`CognitiveError::EvidenceEmitFailed`] when evidence append fails.
    pub async fn emit_circuit_breaker_tripped(
        &self,
        backend: ModelBackendKind,
        from_state: CircuitState,
        to_state: CircuitState,
        error_rate: f64,
    ) -> Result<String, CognitiveError> {
        let record_type = match to_state {
            CircuitState::Open => RecordType::CircuitBreakerOpened,
            CircuitState::Closed | CircuitState::HalfOpen => RecordType::CircuitBreakerClosed,
        };
        let payload = CircuitBreakerTrippedPayload {
            backend,
            from_state,
            to_state,
            error_rate,
            transitioned_at: Utc::now(),
        };
        self.emit(record_type, &payload).await
    }

    /// Emit `AI_DIRECT_INTERNET_DENIED` when external backend is blocked by posture.
    ///
    /// # Errors
    ///
    /// Returns [`CognitiveError::EvidenceEmitFailed`] when evidence append fails.
    pub async fn emit_ai_direct_internet_denied(
        &self,
        model_id: &str,
        posture: AICrossOriginPosture,
        attempt_summary: &str,
    ) -> Result<String, CognitiveError> {
        let payload = AiDirectInternetDeniedPayload {
            model_id: model_id.to_owned(),
            posture,
            attempt_summary: attempt_summary.to_owned(),
            denied_at: Utc::now(),
        };
        self.emit(RecordType::AiDirectInternetDenied, &payload)
            .await
    }

    /// Emit `STATUS_TRANSITION` when a backend health state changes.
    ///
    /// # Errors
    ///
    /// Returns [`CognitiveError::EvidenceEmitFailed`] when evidence append fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn emit_backend_health_changed(
        &self,
        backend_kind: ModelBackendKind,
        provider_class: ProviderClass,
        from_state: BackendHealthState,
        to_state: BackendHealthState,
        last_latency_ms: u64,
        consecutive_failures: u32,
        last_error: Option<&str>,
    ) -> Result<String, CognitiveError> {
        let payload = BackendHealthChangedPayload {
            backend_kind,
            provider_class,
            from_state,
            to_state,
            last_latency_ms,
            consecutive_failures,
            last_error: last_error.map(str::to_string),
            transitioned_at: Utc::now(),
        };
        self.emit(RecordType::StatusTransition, &payload).await
    }
}

/// Validate the chain tail receipt id matches the expected value.
fn validate_expected_previous_receipt(
    previous: Option<&EvidenceReceipt>,
    expected_previous_receipt_id: Option<&str>,
) -> Result<(), EvidenceError> {
    let Some(expected) = expected_previous_receipt_id else {
        return Ok(());
    };
    let Some(previous) = previous else {
        return Err(EvidenceError::EncodingFailed(format!(
            "expected previous receipt id {expected}, but chain is empty"
        )));
    };
    if previous.receipt_id().as_str() == expected {
        return Ok(());
    }
    Err(EvidenceError::EncodingFailed(format!(
        "expected previous receipt id {expected}, but chain tail is {}",
        previous.receipt_id().as_str()
    )))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        reason = "panic-on-failure is the idiomatic test signal"
    )]

    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn test_subject() -> CognitiveSubjectRef {
        CognitiveSubjectRef(AIOS_COGNITIVE_SUBJECT.to_string())
    }

    #[tokio::test]
    async fn emitter_constructs_and_returns_verifying_key() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let log: Arc<dyn CognitiveEvidenceLog> = Arc::new(InMemoryCognitiveEvidenceLog::new());
        let emitter = CognitiveEvidenceEmitter::new(log, sk, test_subject());
        assert_eq!(emitter.verifying_key(), vk);
    }

    #[tokio::test]
    async fn emit_model_call_produces_signed_receipt() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let log = Arc::new(InMemoryCognitiveEvidenceLog::new());
        let emitter = CognitiveEvidenceEmitter::new(log.clone(), sk, test_subject());

        let receipt_id = emitter
            .emit_model_call("mdl_01", "rtdg_01", 100, 50, 42, 200)
            .await
            .unwrap();
        assert!(!receipt_id.is_empty());
        assert_eq!(log.len().await, 1);
        log.verify_integrity().await.unwrap();
        log.verify_integrity_signed(&vk).await.unwrap();
    }

    #[tokio::test]
    async fn emit_routing_decision_produces_signed_receipt() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let log = Arc::new(InMemoryCognitiveEvidenceLog::new());
        let emitter = CognitiveEvidenceEmitter::new(log.clone(), sk, test_subject());

        emitter
            .emit_routing_decision("rtdg_01", ModelBackendKind::LocalGpu, "abc123", "0.1.0")
            .await
            .unwrap();
        assert_eq!(log.len().await, 1);
        log.verify_integrity_signed(&vk).await.unwrap();
    }

    #[tokio::test]
    async fn emit_circuit_breaker_tripped_opened() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let log = Arc::new(InMemoryCognitiveEvidenceLog::new());
        let emitter = CognitiveEvidenceEmitter::new(log.clone(), sk, test_subject());

        emitter
            .emit_circuit_breaker_tripped(
                ModelBackendKind::LocalGpu,
                CircuitState::Closed,
                CircuitState::Open,
                0.15,
            )
            .await
            .unwrap();
        assert_eq!(log.len().await, 1);
        log.verify_integrity_signed(&vk).await.unwrap();
    }

    #[tokio::test]
    async fn emit_circuit_breaker_tripped_closed() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let log = Arc::new(InMemoryCognitiveEvidenceLog::new());
        let emitter = CognitiveEvidenceEmitter::new(log.clone(), sk, test_subject());

        emitter
            .emit_circuit_breaker_tripped(
                ModelBackendKind::LocalGpu,
                CircuitState::HalfOpen,
                CircuitState::Closed,
                0.0,
            )
            .await
            .unwrap();
        assert_eq!(log.len().await, 1);
        log.verify_integrity_signed(&vk).await.unwrap();
    }

    #[tokio::test]
    async fn emit_ai_direct_internet_denied_produces_signed_receipt() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let log = Arc::new(InMemoryCognitiveEvidenceLog::new());
        let emitter = CognitiveEvidenceEmitter::new(log.clone(), sk, test_subject());

        emitter
            .emit_ai_direct_internet_denied(
                "mdl_ext",
                AICrossOriginPosture::AiNoExternal,
                "blocked external call",
            )
            .await
            .unwrap();
        assert_eq!(log.len().await, 1);
        log.verify_integrity_signed(&vk).await.unwrap();
    }

    #[tokio::test]
    async fn chain_integrity_across_multiple_emissions() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let log = Arc::new(InMemoryCognitiveEvidenceLog::new());
        let emitter = CognitiveEvidenceEmitter::new(log.clone(), sk, test_subject());

        emitter
            .emit_routing_decision("r1", ModelBackendKind::LocalGpu, "h1", "v1")
            .await
            .unwrap();
        emitter
            .emit_model_call("m1", "r1", 10, 5, 0, 100)
            .await
            .unwrap();
        emitter
            .emit_circuit_breaker_tripped(
                ModelBackendKind::LocalGpu,
                CircuitState::Closed,
                CircuitState::Open,
                0.2,
            )
            .await
            .unwrap();

        assert_eq!(log.len().await, 3);
        log.verify_integrity().await.unwrap();
        log.verify_integrity_signed(&vk).await.unwrap();
    }

    #[tokio::test]
    async fn empty_log_is_empty() {
        let log = InMemoryCognitiveEvidenceLog::new();
        assert!(log.is_empty().await);
        assert_eq!(log.len().await, 0);
        assert!(log.receipts().await.is_empty());
    }
}
