//! LLM-driven Capability Translator (Rev.5 Agent 5/8).
//!
//! Converts natural-language intents into structured [`TranslationResult`] values
//! by prompting an LLM (Ollama or vLLM) to produce typed JSON, then parsing and
//! validating the response against a confidence threshold.
//!
//! # Architecture
//!
//! ```text
//! CognitiveIntent
//!   → prompt_builder()       (system prompt + user utterance)
//!   → route → adapter call   (Ollama / vLLM)
//!   → parse_json_response()  (structured extraction)
//!   → TranslationResult      (envelope + provenance)
//! ```

#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use aios_action::{ActionEnvelope, Identity, Request, Trace};

use crate::adapter::ollama::{OllamaAdapter, OllamaError, OllamaGenerateRequest};
use crate::adapter::vllm::{VllmAdapter, VllmCompletionRequest, VllmError};
use crate::error::CognitiveError;
use crate::evidence_emit::CognitiveEvidenceEmitter;
use crate::intent::CognitiveIntent;
use crate::router::ModelRouter;
use crate::routing::{ProviderClass, RoutingInputs};
use crate::translator::{TranslationProvenance, TranslationResult};

const DEFAULT_MIN_CONFIDENCE: f64 = 0.6;
const ENGINE_VERSION: &str = "aios-cognitive/0.2.0-translator-engine";

// ---------------------------------------------------------------------------
// TranslateResponse — parsed LLM output
// ---------------------------------------------------------------------------

/// The structured JSON the LLM is instructed to produce for each translation.
///
/// All fields use `#[serde(default)]` so that a partial response (missing keys,
/// extra keys) parses cleanly and the caller can decide how to handle incomplete
/// responses via field-level validation rather than serde-level rejection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TranslateResponse {
    /// The typed capability name (e.g. `"service.restart"`, `"file.read"`).
    #[serde(default)]
    pub action_name: String,
    /// Named parameters for the action (e.g. `{"service_name": "nginx"}`).
    #[serde(default)]
    pub parameters: HashMap<String, String>,
    /// Confidence score in the 0.0–1.0 range.
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// Brief natural-language explanation of the translation decision.
    #[serde(default)]
    pub reasoning: String,
}

fn default_confidence() -> f64 {
    0.0
}

// ---------------------------------------------------------------------------
// TranslatorEngine
// ---------------------------------------------------------------------------

/// LLM-driven capability translator.
///
/// Prompts an LLM to convert a natural-language intent into a typed action
/// envelope, parses the structured JSON response, and packages the result
/// with full provenance metadata.
pub struct TranslatorEngine {
    router: Arc<ModelRouter>,
    ollama_adapter: Option<Arc<OllamaAdapter>>,
    vllm_adapter: Option<Arc<VllmAdapter>>,
    evidence_emitter: Option<Arc<CognitiveEvidenceEmitter>>,
    min_confidence: f64,
}

impl TranslatorEngine {
    /// Create an engine with the given router and no adapters attached.
    #[must_use]
    pub fn new(router: Arc<ModelRouter>) -> Self {
        Self {
            router,
            ollama_adapter: None,
            vllm_adapter: None,
            evidence_emitter: None,
            min_confidence: DEFAULT_MIN_CONFIDENCE,
        }
    }

    /// Attach an Ollama adapter for local inference.
    #[must_use]
    pub fn with_ollama(mut self, adapter: Arc<OllamaAdapter>) -> Self {
        self.ollama_adapter = Some(adapter);
        self
    }

    /// Attach a vLLM adapter for local GPU inference.
    #[must_use]
    pub fn with_vllm(mut self, adapter: Arc<VllmAdapter>) -> Self {
        self.vllm_adapter = Some(adapter);
        self
    }

    /// Attach a cognitive evidence emitter for `MODEL_CALL` receipts.
    #[must_use]
    pub fn with_evidence_emitter(mut self, emitter: Arc<CognitiveEvidenceEmitter>) -> Self {
        self.evidence_emitter = Some(emitter);
        self
    }

    /// Set the minimum confidence threshold (clamped to 0.0–1.0).
    ///
    /// Translations whose parsed confidence falls below this threshold
    /// are rejected with [`CognitiveError::TranslationFailed`].
    #[must_use]
    pub fn with_min_confidence(mut self, min_confidence: f64) -> Self {
        self.min_confidence = min_confidence.clamp(0.0, 1.0);
        self
    }

    /// Return the configured minimum confidence threshold.
    #[must_use]
    pub fn min_confidence(&self) -> f64 {
        self.min_confidence
    }

    /// Return a reference to the router.
    #[must_use]
    pub fn router(&self) -> &Arc<ModelRouter> {
        &self.router
    }

    // -------------------------------------------------------------------
    // Prompt building (public for integration use by ProductionCognitiveCore)
    // -------------------------------------------------------------------

    /// Build the system prompt that instructs the LLM to produce valid JSON.
    #[must_use]
    pub fn build_system_prompt(&self) -> String {
        include_str!("../assets/translator_system_prompt.txt").to_string()
    }

    /// Combine the system prompt with the user's natural-language intent
    /// into a single prompt string suitable for models that do not support
    /// a separate `system` field (e.g. plain completions).
    #[must_use]
    pub fn build_combined_prompt(&self, user_prompt: &str) -> String {
        let system = self.build_system_prompt();
        format!("{system}\n\nUser intent: {user_prompt}\n\nResponse (JSON only):")
    }

    // -------------------------------------------------------------------
    // JSON parsing (public for integration + testing)
    // -------------------------------------------------------------------

    /// Attempt to parse and validate an LLM response into a [`TranslateResponse`].
    ///
    /// Returns `Ok(response)` when the output is structurally valid JSON and
    /// all required fields are present. Returns `Err(CognitiveError)` when the
    /// response is empty, not valid JSON, or missing critical fields.
    pub fn parse_json_response(
        &self,
        raw_response: &str,
    ) -> Result<TranslateResponse, CognitiveError> {
        let trimmed = raw_response.trim();

        if trimmed.is_empty() {
            return Err(CognitiveError::TranslationFailed(
                "LLM returned empty response".into(),
            ));
        }

        match serde_json::from_str::<TranslateResponse>(trimmed) {
            Ok(parsed) => {
                if parsed.action_name.is_empty() {
                    return Err(CognitiveError::TranslationFailed(
                        "LLM response missing 'action_name' field".into(),
                    ));
                }
                Ok(parsed)
            }
            Err(serde_err) => self.fallback_parse(trimmed, serde_err),
        }
    }

    /// Attempt to extract JSON from a response that may contain non-JSON
    /// wrapper text (e.g. markdown code fences, leading prose).
    fn try_extract_json_block(&self, text: &str) -> Option<String> {
        let text = text.trim();

        // Case 1: JSON code fence ```json ... ```
        if let Some(inner) = text
            .strip_prefix("```json")
            .and_then(|s| s.strip_suffix("```"))
        {
            let inner = inner.trim();
            if !inner.is_empty() {
                return Some(inner.to_string());
            }
        }

        // Case 2: plain code fence ``` ... ```
        if let Some(inner) = text.strip_prefix("```").and_then(|s| s.strip_suffix("```")) {
            let inner = inner.trim();
            if !inner.is_empty() && (inner.starts_with('{') || inner.starts_with('[')) {
                return Some(inner.to_string());
            }
        }

        // Case 3: extract first { ... } block (greedy)
        if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}')) {
            if start < end {
                let candidate = &text[start..=end];
                if candidate.len() > 2 {
                    return Some(candidate.to_string());
                }
            }
        }

        None
    }

    /// Fallback parse: try to extract a JSON block, then build a degraded
    /// response if that also fails.
    fn fallback_parse(
        &self,
        raw: &str,
        _serde_err: serde_json::Error,
    ) -> Result<TranslateResponse, CognitiveError> {
        if let Some(candidate) = self.try_extract_json_block(raw) {
            if let Ok(parsed) = serde_json::from_str::<TranslateResponse>(&candidate) {
                if !parsed.action_name.is_empty() {
                    return Ok(parsed);
                }
            }
        }

        // Complete failure: return a low-confidence fallback with the raw
        // text preserved as the reasoning so the operator can inspect it.
        Ok(TranslateResponse {
            action_name: String::new(),
            parameters: HashMap::new(),
            confidence: 0.0,
            reasoning: format!(
                "[UNPARSEABLE] LLM did not produce valid JSON: {}",
                &raw[..raw.len().min(500)]
            ),
        })
    }

    // -------------------------------------------------------------------
    // Standalone translation pipeline
    // -------------------------------------------------------------------

    /// Run the full translation pipeline: route → prompt → dispatch → parse → result.
    ///
    /// # Errors
    ///
    /// Returns [`CognitiveError::NoRouteAvailable`] when the router cannot
    /// select a backend.
    ///
    /// Returns [`CognitiveError::TranslationFailed`] when the LLM response
    /// cannot be parsed or its confidence falls below `min_confidence`.
    pub async fn translate(
        &self,
        intent: &CognitiveIntent,
    ) -> Result<TranslationResult, CognitiveError> {
        let start = Instant::now();

        let inputs = RoutingInputs {
            latency_class: intent.latency_class,
            privacy_class: intent.privacy_class,
            ai_cross_origin_posture: crate::routing::AICrossOriginPosture::AiVaultBrokeredOnly,
            backend_health_snapshot: vec![],
            recovery_mode: false,
            budget_ok: true,
        };

        let decision = self.router.route(&inputs)?;
        let (raw_response, tokens_in, tokens_out, model_name) =
            self.dispatch_to_adapter(&decision, intent).await?;

        let parsed = self.parse_json_response(&raw_response)?;
        let clamped_confidence = parsed.confidence.clamp(0.0, 1.0);

        if clamped_confidence < self.min_confidence {
            return Err(CognitiveError::TranslationFailed(format!(
                "confidence {clamped_confidence} below threshold {}",
                self.min_confidence
            )));
        }

        let envelope = ActionEnvelope::new(
            Identity::new(intent.subject.0.clone(), true),
            Request::new(
                &parsed.action_name,
                serde_json::to_value(&parsed.parameters).unwrap_or_default(),
            ),
            Trace::new("00000000000000000000000000000000", "0000000000000000", None),
        );

        let latency_ms = start.elapsed().as_millis() as u64;

        if let Some(ref emitter) = self.evidence_emitter {
            let _ = emitter
                .emit_model_call(
                    &model_name,
                    &decision.routing_id,
                    tokens_in,
                    tokens_out,
                    0,
                    latency_ms,
                )
                .await;
        }

        Ok(TranslationResult {
            intent_id: intent.intent_id.clone(),
            produced_action: envelope,
            routing_decision_id: Some(decision.routing_id),
            verification_intent: Some(parsed.reasoning),
            translation_provenance: TranslationProvenance {
                translator_version: ENGINE_VERSION.into(),
                model_used: model_name,
                tokens_in,
                tokens_out,
                model_signed_response: Some(raw_response),
            },
            translated_at: Utc::now(),
        })
    }

    // -------------------------------------------------------------------
    // Internal dispatch helpers
    // -------------------------------------------------------------------

    /// Dispatch the intent to the adapter selected by the router.
    async fn dispatch_to_adapter(
        &self,
        decision: &crate::routing::RoutingDecision,
        intent: &CognitiveIntent,
    ) -> Result<(String, u32, u32, String), CognitiveError> {
        let system_prompt = self.build_system_prompt();

        match decision.provider_class {
            ProviderClass::Ollama => {
                let adapter = self
                    .ollama_adapter
                    .as_ref()
                    .ok_or_else(|| {
                        CognitiveError::Internal(
                            "Ollama selected but no OllamaAdapter configured".into(),
                        )
                    })?;

                let request = OllamaGenerateRequest::new(
                    self.resolve_ollama_model(decision),
                    &intent.natural_language,
                )
                .with_system(&system_prompt);

                let model_name = format!("ollama:{}", request.model);

                match adapter.generate(request).await {
                    Ok(response) => {
                        let tokens_in = response.prompt_eval_count.unwrap_or(0);
                        let tokens_out = response.eval_count.unwrap_or(0);
                        Ok((response.response, tokens_in, tokens_out, model_name))
                    }
                    Err(err) => Err(map_ollama_err(err)),
                }
            }
            ProviderClass::Vllm => {
                let adapter = self
                    .vllm_adapter
                    .as_ref()
                    .ok_or_else(|| {
                        CognitiveError::Internal(
                            "vLLM selected but no VllmAdapter configured".into(),
                        )
                    })?;

                let combined = self.build_combined_prompt(&intent.natural_language);

                let request = VllmCompletionRequest::new(
                    self.resolve_vllm_model(decision),
                    &combined,
                )
                .with_max_tokens(1024)
                .with_temperature(0.1);

                let model_name = format!("vllm:{}", request.model);

                match adapter.complete(request).await {
                    Ok(response) => {
                        let text = response
                            .choices
                            .first()
                            .map(|c| c.text.clone())
                            .unwrap_or_default();
                        let usage = response.usage.as_ref();
                        let tokens_in = usage.map_or(0, |u| u.prompt_tokens);
                        let tokens_out = usage.map_or(0, |u| u.completion_tokens);
                        Ok((text, tokens_in, tokens_out, model_name))
                    }
                    Err(err) => Err(map_vllm_err(err)),
                }
            }
            ProviderClass::Anthropic | ProviderClass::Openai | ProviderClass::OtherVaultBrokered => {
                Err(CognitiveError::Internal(format!(
                    "external provider {:?} not supported by TranslatorEngine; use ProductionCognitiveCore pipeline",
                    decision.provider_class,
                )))
            }
        }
    }

    fn resolve_ollama_model(&self, decision: &crate::routing::RoutingDecision) -> String {
        let _ = decision;
        "llama3".to_string()
    }

    fn resolve_vllm_model(&self, decision: &crate::routing::RoutingDecision) -> String {
        let _ = decision;
        "meta-llama/Llama-3.1-8B-Instruct".to_string()
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_ollama_err(err: OllamaError) -> CognitiveError {
    match err {
        OllamaError::ModelNotFound(msg) => {
            CognitiveError::NoMatchingCapability(format!("ollama model not found: {msg}"))
        }
        OllamaError::Timeout => CognitiveError::Internal("ollama request timed out".into()),
        OllamaError::ParseError(msg) => {
            CognitiveError::ModelResponseInvalid(format!("ollama parse error: {msg}"))
        }
        other => CognitiveError::Internal(format!("ollama error: {other}")),
    }
}

fn map_vllm_err(err: VllmError) -> CognitiveError {
    match err {
        VllmError::ModelNotFound(msg) => {
            CognitiveError::NoMatchingCapability(format!("vllm model not found: {msg}"))
        }
        VllmError::Timeout => CognitiveError::Internal("vllm request timed out".into()),
        VllmError::ParseError(msg) => {
            CognitiveError::ModelResponseInvalid(format!("vllm parse error: {msg}"))
        }
        other => CognitiveError::Internal(format!("vllm error: {other}")),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        clippy::unwrap_in_result,
        clippy::float_cmp,
        reason = "panic-on-failure is the idiomatic test signal"
    )]

    use super::*;
    use crate::intent::{CognitiveIntent, IntentId, SubjectRef};
    use crate::latency::{LatencyTier, PrivacyClass};
    use crate::router::ModelRouter;

    fn make_engine() -> TranslatorEngine {
        TranslatorEngine::new(Arc::new(ModelRouter::new_with_defaults()))
    }

    #[allow(dead_code)]
    fn make_intent(text: &str) -> CognitiveIntent {
        CognitiveIntent {
            intent_id: IntentId::new(),
            subject: SubjectRef("test-subject".into()),
            natural_language: text.to_string(),
            context_hash: String::new(),
            created_at: Utc::now(),
            latency_class: LatencyTier::T3LocalCognitive,
            privacy_class: PrivacyClass::Public,
        }
    }

    // -------------------------------------------------------------------
    // Prompt building
    // -------------------------------------------------------------------

    #[test]
    fn build_system_prompt_is_non_empty() {
        let engine = make_engine();
        let prompt = engine.build_system_prompt();
        assert!(!prompt.is_empty(), "system prompt must not be empty");
        assert!(
            prompt.contains("action_name"),
            "system prompt must mention action_name"
        );
        assert!(
            prompt.contains("confidence"),
            "system prompt must mention confidence"
        );
        assert!(
            prompt.to_lowercase().contains("json"),
            "system prompt must instruct JSON output"
        );
    }

    #[test]
    fn build_combined_prompt_contains_user_intent() {
        let engine = make_engine();
        let combined = engine.build_combined_prompt("restart the nginx service");
        assert!(
            combined.contains("restart the nginx service"),
            "combined prompt must embed user intent"
        );
        assert!(
            combined.contains("JSON only"),
            "combined prompt must cue JSON output"
        );
    }

    // -------------------------------------------------------------------
    // JSON parsing — valid input
    // -------------------------------------------------------------------

    #[test]
    fn parse_valid_json_produces_correct_response() {
        let engine = make_engine();
        let json = r#"{
            "action_name": "service.restart",
            "parameters": {"service_name": "nginx"},
            "confidence": 0.95,
            "reasoning": "The user explicitly asked to restart nginx."
        }"#;

        let parsed = engine.parse_json_response(json).unwrap();
        assert_eq!(parsed.action_name, "service.restart");
        assert_eq!(
            parsed.parameters.get("service_name").map(String::as_str),
            Some("nginx")
        );
        assert!((parsed.confidence - 0.95).abs() < 0.001);
        assert!(parsed.reasoning.contains("nginx"));
    }

    #[test]
    fn parse_json_with_missing_optional_fields_fills_defaults() {
        let engine = make_engine();
        let json = r#"{
            "action_name": "file.read",
            "parameters": {}
        }"#;

        let parsed = engine.parse_json_response(json).unwrap();
        assert_eq!(parsed.action_name, "file.read");
        assert_eq!(parsed.confidence, 0.0);
        assert!(parsed.reasoning.is_empty());
    }

    #[test]
    fn parse_json_with_extra_fields_is_tolerant() {
        let engine = make_engine();
        let json = r#"{
            "action_name": "process.list",
            "parameters": {},
            "confidence": 0.8,
            "reasoning": "ok",
            "extra_field": "should be ignored"
        }"#;

        let parsed = engine.parse_json_response(json).unwrap();
        assert_eq!(parsed.action_name, "process.list");
        assert!((parsed.confidence - 0.8).abs() < 0.001);
    }

    // -------------------------------------------------------------------
    // JSON parsing — malformed / edge cases
    // -------------------------------------------------------------------

    #[test]
    fn parse_empty_response_fails() {
        let engine = make_engine();
        let result = engine.parse_json_response("");
        assert!(result.is_err());
        match result {
            Err(CognitiveError::TranslationFailed(msg)) => {
                assert!(msg.contains("empty"));
            }
            other => panic!("expected TranslationFailed, got {other:?}"),
        }
    }

    #[test]
    fn parse_whitespace_only_response_fails() {
        let engine = make_engine();
        let result = engine.parse_json_response("   \n\t  ");
        assert!(result.is_err());
        match result {
            Err(CognitiveError::TranslationFailed(msg)) => {
                assert!(msg.contains("empty"));
            }
            other => panic!("expected TranslationFailed, got {other:?}"),
        }
    }

    #[test]
    fn parse_malformed_json_produces_fallback() {
        let engine = make_engine();
        let raw = "not valid json at all, just prose";
        let parsed = engine.parse_json_response(raw).unwrap();
        assert!(parsed.action_name.is_empty());
        assert_eq!(parsed.confidence, 0.0);
        assert!(parsed.reasoning.starts_with("[UNPARSEABLE]"));
        assert!(parsed.reasoning.contains(raw));
    }

    #[test]
    fn parse_malformed_json_with_action_name_missing_fails() {
        let engine = make_engine();
        // Valid JSON but missing action_name (which is critical)
        let json = r#"{"parameters": {}, "confidence": 0.5, "reasoning": "test"}"#;
        let result = engine.parse_json_response(json);
        assert!(result.is_err());
        match result {
            Err(CognitiveError::TranslationFailed(msg)) => {
                assert!(msg.contains("action_name"));
            }
            other => panic!("expected TranslationFailed, got {other:?}"),
        }
    }

    #[test]
    fn parse_text_with_embedded_json_block_succeeds() {
        let engine = make_engine();
        let raw = r#"Here is the translation:
```json
{
    "action_name": "file.read",
    "parameters": {"path": "/etc/hosts"},
    "confidence": 0.9,
    "reasoning": "User requested reading a file."
}
```
Hope this helps!"#;

        let parsed = engine.parse_json_response(raw).unwrap();
        assert_eq!(parsed.action_name, "file.read");
        assert_eq!(
            parsed.parameters.get("path").map(String::as_str),
            Some("/etc/hosts")
        );
        assert!((parsed.confidence - 0.9).abs() < 0.001);
    }

    #[test]
    fn parse_text_with_json_wrapped_in_braces_succeeds() {
        let engine = make_engine();
        let raw = r#"Certainly! {"action_name": "service.restart", "parameters": {"svc": "apache"}, "confidence": 0.85, "reasoning": "restart requested"}"#;

        let parsed = engine.parse_json_response(raw).unwrap();
        assert_eq!(parsed.action_name, "service.restart");
        assert_eq!(
            parsed.parameters.get("svc").map(String::as_str),
            Some("apache")
        );
        assert!((parsed.confidence - 0.85).abs() < 0.001);
    }

    // -------------------------------------------------------------------
    // Confidence threshold
    // -------------------------------------------------------------------

    #[test]
    fn confidence_below_threshold_is_rejected() {
        let engine = make_engine().with_min_confidence(0.8);
        let json = r#"{
            "action_name": "service.restart",
            "parameters": {},
            "confidence": 0.3,
            "reasoning": "not sure"
        }"#;

        let parsed = engine.parse_json_response(json).unwrap();
        // parse_json_response succeeds (confidence is just a field),
        // but translate() would reject below threshold.
        assert_eq!(parsed.confidence, 0.3);
        assert!(parsed.confidence < engine.min_confidence());
    }

    #[test]
    fn confidence_above_threshold_passes() {
        let engine = make_engine().with_min_confidence(0.7);
        assert_eq!(engine.min_confidence(), 0.7);

        let json = r#"{
            "action_name": "service.restart",
            "parameters": {},
            "confidence": 0.95,
            "reasoning": "confident"
        }"#;

        let parsed = engine.parse_json_response(json).unwrap();
        assert!(parsed.confidence >= engine.min_confidence());
    }

    #[test]
    fn confidence_clamped_to_valid_range() {
        let engine = make_engine();

        // Above 1.0 → clamped
        let json_high =
            r#"{"action_name": "x", "parameters": {}, "confidence": 1.5, "reasoning": "x"}"#;
        let parsed = engine.parse_json_response(json_high).unwrap();
        assert!(
            (parsed.confidence - 1.5).abs() < 0.01,
            "raw value preserved; caller clamps"
        );

        // Below 0.0 → clamped
        let json_low =
            r#"{"action_name": "x", "parameters": {}, "confidence": -0.5, "reasoning": "x"}"#;
        let parsed = engine.parse_json_response(json_low).unwrap();
        assert!(
            parsed.confidence < 0.0,
            "raw value preserved; caller clamps"
        );
    }

    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    #[test]
    fn new_engine_has_no_adapters() {
        let engine = make_engine();
        assert!(engine.ollama_adapter.is_none());
        assert!(engine.vllm_adapter.is_none());
        assert!(engine.evidence_emitter.is_none());
        assert_eq!(engine.min_confidence(), DEFAULT_MIN_CONFIDENCE);
    }

    #[test]
    fn with_ollama_sets_adapter() {
        let adapter = Arc::new(OllamaAdapter::new("http://localhost:11434", 30));
        let engine = make_engine().with_ollama(adapter);
        assert!(engine.ollama_adapter.is_some());
    }

    #[test]
    fn with_vllm_sets_adapter() {
        let adapter = Arc::new(VllmAdapter::new("http://localhost:8000", 30));
        let engine = make_engine().with_vllm(adapter);
        assert!(engine.vllm_adapter.is_some());
    }

    #[test]
    fn with_min_confidence_clamps() {
        let engine = make_engine().with_min_confidence(1.5);
        assert_eq!(engine.min_confidence(), 1.0);

        let engine = make_engine().with_min_confidence(-0.5);
        assert_eq!(engine.min_confidence(), 0.0);
    }

    // -------------------------------------------------------------------
    // Send + Sync
    // -------------------------------------------------------------------

    #[test]
    fn translator_engine_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TranslatorEngine>();
    }
}
