//! Production CognitiveCore — wires Ollama/vLLM adapters into the cognitive pipeline.
//!
//! Replaces the [`InMemoryCognitiveCore`] test stub with adapter-backed
//! model invocation, deterministic routing, circuit breaking, and evidence
//! emission per S13.2 §5, S13.2 §7, and S14.1 §6.

#![allow(
    clippy::module_name_repetitions,
    reason = "public struct name follows the cognitive vocabulary"
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::RwLock;

use aios_action::{ActionEnvelope, Identity, Request, Trace};

use crate::adapter::ollama::{OllamaAdapter, OllamaError, OllamaGenerateRequest};
use crate::adapter::vllm::{VllmAdapter, VllmCompletionRequest, VllmError};
use crate::breaker_registry::CircuitBreakerRegistry;
use crate::circuit::{CircuitBreakerConfig, CircuitBreakerStats, CircuitState};
use crate::core::{CognitiveCore, IntentCapability, TranslationContext};
use crate::error::CognitiveError;
use crate::evidence_emit::CognitiveEvidenceEmitter;
use crate::health_monitor::HealthMonitor;
use crate::intent::{CognitiveIntent, IntentId, SubjectRef};
use crate::latency::LatencyTier;
use crate::latency_classifier::LatencyClassifier;
use crate::model::{CognitiveModel, ModelId};
use crate::model_catalog::CognitiveModelCatalog;
use crate::provider_dispatch::{DispatchOutcome, ProviderDispatcher};
use crate::router::ModelRouter;
use crate::router_state::RouterState;
use crate::routing::{BackendHealthEntry, ProviderClass, RoutingDecision, RoutingInputs};
use crate::translator::{TranslationProvenance, TranslationResult};
use crate::translator_engine::TranslatorEngine;

const TRANSLATOR_VERSION: &str = "aios-cognitive/0.2.0-production-core";

// ---------------------------------------------------------------------------
// ProductionCognitiveCore
// ---------------------------------------------------------------------------

/// Production implementation of [`CognitiveCore`] that wires Ollama and vLLM
/// adapters into the full cognitive pipeline: classify → route → breaker →
/// dispatch → evidence → result.
pub struct ProductionCognitiveCore {
    /// Deterministic precedence-table model router (S13.2 §7).
    router: Arc<ModelRouter>,
    /// Provider dispatcher for vault-brokered external providers.
    dispatcher: Arc<ProviderDispatcher>,
    /// Model catalog — loaded via `bootstrap_models()`.
    catalog: Arc<CognitiveModelCatalog>,
    /// Optional Ollama adapter for local CPU/GPU inference.
    ollama_adapter: Option<Arc<OllamaAdapter>>,
    /// Optional vLLM adapter for local GPU inference.
    vllm_adapter: Option<Arc<VllmAdapter>>,
    /// Optional cognitive evidence emitter.
    evidence_emitter: Option<Arc<CognitiveEvidenceEmitter>>,
    /// Per-backend circuit breaker registry.
    breaker_registry: Arc<CircuitBreakerRegistry>,
    /// Router operational state for health tracking.
    router_state: Arc<RouterState>,
    /// Live backend health monitor (optional, started via `with_health_monitoring`).
    health_monitor: Option<HealthMonitor>,
    /// Translation cache keyed by intent id.
    translation_cache: RwLock<HashMap<IntentId, TranslationResult>>,
    /// LLM-driven capability translator for prompt building + JSON parsing.
    translator_engine: TranslatorEngine,
}

impl ProductionCognitiveCore {
    /// Create a core with default router, dispatcher, catalog, and no adapters.
    ///
    /// Call [`with_ollama`] / [`with_vllm`] to attach adapters, then
    /// [`bootstrap_models`] to discover and register models from the servers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            router: Arc::new(ModelRouter::new_with_defaults()),
            dispatcher: Arc::new(ProviderDispatcher::new()),
            catalog: Arc::new(CognitiveModelCatalog::new()),
            ollama_adapter: None,
            vllm_adapter: None,
            evidence_emitter: None,
            breaker_registry: Arc::new(CircuitBreakerRegistry::new_with_defaults()),
            router_state: Arc::new(RouterState::new()),
            health_monitor: None,
            translation_cache: RwLock::new(HashMap::new()),
            translator_engine: TranslatorEngine::new(Arc::new(ModelRouter::new_with_defaults())),
        }
    }

    /// Attach an Ollama adapter targeting `base_url`.
    ///
    /// Models are not registered until [`bootstrap_models`] is called.
    #[must_use]
    pub fn with_ollama(mut self, base_url: &str) -> Self {
        self.ollama_adapter = Some(Arc::new(OllamaAdapter::new(base_url, 30)));
        self
    }

    /// Attach a vLLM adapter targeting `base_url`.
    ///
    /// Models are not registered until [`bootstrap_models`] is called.
    #[must_use]
    pub fn with_vllm(mut self, base_url: &str) -> Self {
        self.vllm_adapter = Some(Arc::new(VllmAdapter::new(base_url, 30)));
        self
    }

    /// Attach a health monitor that will start on [`bootstrap_models`].
    ///
    /// The monitor pings configured adapters on a configurable interval, updates
    /// router state and circuit breaker registry, and emits evidence on state
    /// transitions.
    #[must_use]
    pub fn with_health_monitoring(mut self, monitor: HealthMonitor) -> Self {
        self.health_monitor = Some(monitor);
        self
    }

    /// Attach an evidence emitter for `ROUTING_DECISION` / `CIRCUIT_BREAKER_TRIPPED` evidence.
    #[must_use]
    pub fn with_evidence_emitter(mut self, emitter: Arc<CognitiveEvidenceEmitter>) -> Self {
        // Also wire the evidence emitter into the adapters for MODEL_CALL evidence.
        if let Some(ref oa) = self.ollama_adapter {
            let new_oa = (**oa).clone().with_evidence_emitter(Arc::clone(&emitter));
            self.ollama_adapter = Some(Arc::new(new_oa));
        }
        if let Some(ref va) = self.vllm_adapter {
            let new_va = (**va).clone().with_evidence_emitter(Arc::clone(&emitter));
            self.vllm_adapter = Some(Arc::new(new_va));
        }
        self.evidence_emitter = Some(emitter);
        self
    }

    /// Return a shared reference to the model catalog.
    #[must_use]
    pub fn catalog(&self) -> &Arc<CognitiveModelCatalog> {
        &self.catalog
    }

    /// Return a shared reference to the router.
    #[must_use]
    pub fn router(&self) -> &Arc<ModelRouter> {
        &self.router
    }

    // -----------------------------------------------------------------------
    // Bootstrap
    // -----------------------------------------------------------------------

    /// Discover models from attached Ollama and vLLM servers and register them
    /// into the catalog.
    ///
    /// Calls `list_models()` on each configured adapter. Models are registered
    /// with their server name as the `model_id` prefix. Does not fail if a
    /// server is unreachable — logs the error and continues.
    ///
    /// # Errors
    ///
    /// Returns `CognitiveError::NoMatchingCapability` only when *both* adapters
    /// fail to discover any models and the catalog is still empty.
    pub async fn bootstrap_models(&self) -> Result<(), CognitiveError> {
        let mut discovered = 0u32;

        if let Some(ref adapter) = self.ollama_adapter {
            match adapter.list_models().await {
                Ok(infos) => {
                    for info in infos {
                        let model = CognitiveModel {
                            model_id: ModelId(format!("mdl_ollama_{}", info.name)),
                            provider: ProviderClass::Ollama,
                            capabilities: vec!["text-generation".into()],
                            max_tokens: 4096,
                            input_cost_per_1k: 0,
                            output_cost_per_1k: 0,
                            vault_capability_id: None,
                            created_at: Utc::now(),
                        };
                        if self.catalog.register(model).await.is_ok() {
                            discovered += 1;
                        }
                    }
                }
                Err(err) => {
                    // Best-effort: server unreachable is not fatal.
                    tracing::warn!(
                        target: "aios_cognitive",
                        %err,
                        "ollama list_models failed — continuing without Ollama models"
                    );
                }
            }
        }

        if let Some(ref adapter) = self.vllm_adapter {
            match adapter.list_models().await {
                Ok(infos) => {
                    for info in infos {
                        let model = CognitiveModel {
                            model_id: ModelId(format!("mdl_vllm_{}", info.id)),
                            provider: ProviderClass::Vllm,
                            capabilities: vec!["text-generation".into()],
                            max_tokens: 32768,
                            input_cost_per_1k: 0,
                            output_cost_per_1k: 0,
                            vault_capability_id: None,
                            created_at: Utc::now(),
                        };
                        if self.catalog.register(model).await.is_ok() {
                            discovered += 1;
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        target: "aios_cognitive",
                        %err,
                        "vllm list_models failed — continuing without vLLM models"
                    );
                }
            }
        }

        if discovered == 0 {
            // Seed a fixture so the catalog is never empty (graceful degradation).
            let fixture = CognitiveModel {
                model_id: ModelId("mdl_fallback_null".into()),
                provider: ProviderClass::Ollama,
                capabilities: vec!["text-generation".into()],
                max_tokens: 4096,
                input_cost_per_1k: 0,
                output_cost_per_1k: 0,
                vault_capability_id: None,
                created_at: Utc::now(),
            };
            let _ = self.catalog.register(fixture).await;
        }

        // Start the health monitor if configured.
        if let Some(ref monitor) = self.health_monitor {
            monitor.start_monitoring().await;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Pipeline
    // -----------------------------------------------------------------------

    /// Run the full cognitive pipeline on an intent:
    ///
    /// 1. Classify latency tier
    /// 2. Route to model (deterministic precedence table)
    /// 3. Check circuit breaker
    /// 4. Dispatch to provider adapter (Ollama / vLLM / vault) with
    ///    translation system prompt
    /// 5. Parse the LLM JSON response into a typed action envelope
    /// 6. Collect token counts and timing
    /// 7. Emit evidence
    /// 8. Return [`TranslationResult`] with AI-generated provenance
    ///
    /// # Errors
    ///
    /// - [`CognitiveError::NoRouteAvailable`] — router cannot select a backend.
    /// - [`CognitiveError::CircuitBreakerOpen`] — breaker prevents dispatch.
    /// - [`CognitiveError::Internal`] — no adapter configured for the routed provider.
    /// - [`CognitiveError::ModelResponseInvalid`] — adapter returned an error.
    /// - [`CognitiveError::TranslationFailed`] — LLM response could not be
    ///   parsed into a structured action envelope.
    pub async fn process_intent(
        &self,
        intent: &CognitiveIntent,
    ) -> Result<TranslationResult, CognitiveError> {
        let start = Instant::now();

        // ── Step 1: Classify latency tier ──
        let classifier = LatencyClassifier::new_with_defaults();
        let latency_tier =
            classifier.classify(intent, &format!("{:?}", intent.privacy_class), false);

        // ── Step 2: Route ──
        let decision = self.route_intent(intent, latency_tier).await?;

        // ── Step 3: Check circuit breaker ──
        let _ticket = match self
            .breaker_registry
            .try_admit(decision.chosen_backend)
            .await
        {
            Ok(ticket) => ticket,
            Err(err) => {
                if let Some(ref emitter) = self.evidence_emitter {
                    if let Some(breaker) = self.breaker_registry.get(decision.chosen_backend).await
                    {
                        let stats = breaker.current_stats().await;
                        let _ = emitter
                            .emit_circuit_breaker_tripped(
                                decision.chosen_backend,
                                stats.state,
                                CircuitState::Open,
                                stats.error_rate,
                            )
                            .await;
                    }
                }
                return Err(err);
            }
        };

        // ── Step 4: Build translation prompt and dispatch to adapter ──
        let translation_prompt = self
            .translator_engine
            .build_combined_prompt(&intent.natural_language);
        let system_prompt = self.translator_engine.build_system_prompt();

        let (response_text, tokens_in, tokens_out, _adapter_latency_ms) = self
            .dispatch_translation(&decision, &translation_prompt, &system_prompt)
            .await?;

        // ── Step 5: Parse LLM JSON → structured action ──
        let parsed = self.translator_engine.parse_json_response(&response_text)?;

        let clamped_confidence = parsed.confidence.clamp(0.0, 1.0);
        if clamped_confidence < self.translator_engine.min_confidence() {
            return Err(CognitiveError::TranslationFailed(format!(
                "confidence {clamped_confidence} below threshold {}",
                self.translator_engine.min_confidence()
            )));
        }

        // ── Step 6: Build the typed ActionEnvelope from parsed output ──
        let model_used = self.resolve_model_name(&decision).await;
        let mut envelope = ActionEnvelope::new(
            Identity::new(intent.subject.0.clone(), true),
            Request::new(
                &parsed.action_name,
                serde_json::to_value(&parsed.parameters).unwrap_or_default(),
            ),
            Trace::new("00000000000000000000000000000000", "0000000000000000", None),
        );

        if let Some(target) = envelope.request.target.as_object_mut() {
            target.insert(
                "cognitive_provenance".to_string(),
                serde_json::Value::String(TRANSLATOR_VERSION.to_string()),
            );
            target.insert(
                "translation_confidence".to_string(),
                serde_json::Value::Number(
                    serde_json::Number::from_f64(clamped_confidence)
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                ),
            );
            target.insert(
                "translation_reasoning".to_string(),
                serde_json::Value::String(parsed.reasoning.clone()),
            );
        }

        let total_latency_ms = start.elapsed().as_millis() as u64;

        // ── Step 7: Emit MODEL_CALL evidence ──
        if let Some(ref emitter) = self.evidence_emitter {
            let _ = emitter
                .emit_model_call(
                    &model_used,
                    &decision.routing_id,
                    tokens_in,
                    tokens_out,
                    0,
                    total_latency_ms,
                )
                .await;
        }

        // ── Step 8: Return TranslationResult ──
        let result = TranslationResult {
            intent_id: intent.intent_id.clone(),
            produced_action: envelope,
            routing_decision_id: Some(decision.routing_id.clone()),
            verification_intent: Some(parsed.reasoning),
            translation_provenance: TranslationProvenance {
                translator_version: TRANSLATOR_VERSION.into(),
                model_used,
                tokens_in,
                tokens_out,
                model_signed_response: Some(response_text),
            },
            translated_at: Utc::now(),
        };

        self.router_state
            .observe_invocation(decision.chosen_backend, true)
            .await;

        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Internal pipeline helpers
    // -----------------------------------------------------------------------

    /// Build routing inputs, call the router, and emit `ROUTING_DECISION` evidence.
    async fn route_intent(
        &self,
        intent: &CognitiveIntent,
        latency_tier: LatencyTier,
    ) -> Result<RoutingDecision, CognitiveError> {
        let health_map = self.router_state.get_health().await;
        let health_snapshot: Vec<BackendHealthEntry> = health_map
            .iter()
            .map(|(kind, hstate)| BackendHealthEntry {
                backend_kind: *kind,
                provider_class: ProviderClass::Ollama,
                state: *hstate,
                config: CircuitBreakerConfig::default(),
                stats: CircuitBreakerStats {
                    state: CircuitState::Closed,
                    success_count: 0,
                    failure_count: 0,
                    error_rate: 0.0,
                    cooldown_seconds: 0,
                    last_state_change_at: Utc::now(),
                    next_probe_at: None,
                },
            })
            .collect();

        let inputs = RoutingInputs {
            latency_class: latency_tier,
            privacy_class: intent.privacy_class,
            ai_cross_origin_posture: crate::routing::AICrossOriginPosture::AiVaultBrokeredOnly,
            backend_health_snapshot: health_snapshot,
            recovery_mode: false,
            budget_ok: true,
        };

        let inputs_hash = {
            let json = serde_json::to_string(&inputs).unwrap_or_default();
            let hash = blake3::hash(json.as_bytes());
            hash.to_hex().to_string()
        };

        let decision = self.router.route(&inputs)?;

        // Emit ROUTING_DECISION evidence.
        if let Some(ref emitter) = self.evidence_emitter {
            let _ = emitter
                .emit_routing_decision(
                    &decision.routing_id,
                    decision.chosen_backend,
                    &inputs_hash,
                    self.router.code_version(),
                )
                .await;
        }

        Ok(decision)
    }

    /// Dispatch a translation-specific prompt (system + user) to the provider
    /// adapter selected by the router.
    ///
    /// Returns `(response_text, tokens_in, tokens_out, latency_ms)`.
    async fn dispatch_translation(
        &self,
        decision: &RoutingDecision,
        combined_prompt: &str,
        system_prompt: &str,
    ) -> Result<(String, u32, u32, u64), CognitiveError> {
        match decision.provider_class {
            ProviderClass::Ollama => {
                let adapter = self.ollama_adapter.as_ref().ok_or_else(|| {
                    CognitiveError::Internal(
                        "Ollama provider selected but no OllamaAdapter configured".into(),
                    )
                })?;

                let request = OllamaGenerateRequest::new(
                    self.ollama_model_name(decision).await,
                    combined_prompt,
                )
                .with_system(system_prompt);

                match adapter.generate(request).await {
                    Ok(response) => {
                        let tokens_in = response.prompt_eval_count.unwrap_or(0);
                        let tokens_out = response.eval_count.unwrap_or(0);
                        let latency_ns = response.total_duration.unwrap_or(0);
                        let latency_ms = latency_ns / 1_000_000;
                        Ok((response.response, tokens_in, tokens_out, latency_ms))
                    }
                    Err(err) => Err(map_ollama_error(err)),
                }
            }
            ProviderClass::Vllm => {
                let adapter = self.vllm_adapter.as_ref().ok_or_else(|| {
                    CognitiveError::Internal(
                        "vLLM provider selected but no VllmAdapter configured".into(),
                    )
                })?;

                let request = VllmCompletionRequest::new(
                    self.vllm_model_name(decision).await,
                    combined_prompt,
                )
                .with_max_tokens(1024)
                .with_temperature(0.1);

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
                        let latency_ms = 0;
                        Ok((text, tokens_in, tokens_out, latency_ms))
                    }
                    Err(err) => Err(map_vllm_error(err)),
                }
            }
            ProviderClass::Anthropic
            | ProviderClass::Openai
            | ProviderClass::OtherVaultBrokered => {
                self.dispatch_via_dispatcher(decision, combined_prompt)
                    .await
            }
        }
    }

    /// Dispatch the intent to the provider adapter selected by the router
    /// (legacy path kept for reference; prefer dispatch_translation).
    ///
    /// Returns `(response_text, tokens_in, tokens_out, latency_ms)`.
    #[allow(dead_code)]
    async fn dispatch_to_adapter(
        &self,
        decision: &RoutingDecision,
        intent: &CognitiveIntent,
    ) -> Result<(String, u32, u32, u64), CognitiveError> {
        let prompt = &intent.natural_language;

        match decision.provider_class {
            ProviderClass::Ollama => {
                let adapter = self.ollama_adapter.as_ref().ok_or_else(|| {
                    CognitiveError::Internal(
                        "Ollama provider selected but no OllamaAdapter configured".into(),
                    )
                })?;

                let request =
                    OllamaGenerateRequest::new(self.ollama_model_name(decision).await, prompt);

                match adapter.generate(request).await {
                    Ok(response) => {
                        let tokens_in = response.prompt_eval_count.unwrap_or(0);
                        let tokens_out = response.eval_count.unwrap_or(0);
                        let latency_ns = response.total_duration.unwrap_or(0);
                        let latency_ms = latency_ns / 1_000_000;
                        Ok((response.response, tokens_in, tokens_out, latency_ms))
                    }
                    Err(err) => Err(map_ollama_error(err)),
                }
            }
            ProviderClass::Vllm => {
                let adapter = self.vllm_adapter.as_ref().ok_or_else(|| {
                    CognitiveError::Internal(
                        "vLLM provider selected but no VllmAdapter configured".into(),
                    )
                })?;

                let request =
                    VllmCompletionRequest::new(self.vllm_model_name(decision).await, prompt);

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
                        let latency_ms = 0; // vLLM doesn't provide total_duration; timed externally
                        Ok((text, tokens_in, tokens_out, latency_ms))
                    }
                    Err(err) => Err(map_vllm_error(err)),
                }
            }
            ProviderClass::Anthropic
            | ProviderClass::Openai
            | ProviderClass::OtherVaultBrokered => {
                self.dispatch_via_dispatcher(decision, &intent.natural_language)
                    .await
            }
        }
    }

    /// Dispatch through [`ProviderDispatcher`] for vault-brokered providers.
    async fn dispatch_via_dispatcher(
        &self,
        decision: &RoutingDecision,
        prompt: &str,
    ) -> Result<(String, u32, u32, u64), CognitiveError> {
        let model = CognitiveModel {
            model_id: ModelId::new(),
            provider: decision.provider_class,
            capabilities: vec!["text-generation".into()],
            max_tokens: 200_000,
            input_cost_per_1k: 15_000,
            output_cost_per_1k: 75_000,
            vault_capability_id: Some(format!("vcap_{}", ulid::Ulid::new())),
            created_at: Utc::now(),
        };

        // Build a minimal intent for the dispatcher (unused beyond routing context).
        let dummy_intent = CognitiveIntent {
            intent_id: IntentId::new(),
            subject: SubjectRef("_system:translator".into()),
            natural_language: prompt.to_string(),
            context_hash: String::new(),
            created_at: Utc::now(),
            latency_class: LatencyTier::T3LocalCognitive,
            privacy_class: crate::latency::PrivacyClass::Public,
        };

        let outcome = self
            .dispatcher
            .dispatch_to_provider(
                &model,
                &dummy_intent,
                crate::routing::AICrossOriginPosture::AiVaultBrokeredOnly,
            )
            .await?;

        match outcome {
            DispatchOutcome::LocalInvocation {
                tokens_in,
                tokens_out,
                latency_ms,
                ..
            }
            | DispatchOutcome::VaultBrokeredInvocation {
                tokens_in,
                tokens_out,
                latency_ms,
                ..
            } => Ok((
                "[vault-brokered response]".into(),
                tokens_in,
                tokens_out,
                latency_ms,
            )),
            DispatchOutcome::Denied { reason, .. } => Err(CognitiveError::TranslationRefused(
                format!("dispatch denied: {reason}"),
            )),
        }
    }

    /// Resolve the model name to use in provenance from the catalog.
    async fn resolve_model_name(&self, decision: &RoutingDecision) -> String {
        self.catalog
            .list_by_provider(decision.provider_class)
            .await
            .first()
            .map(|m| m.model_id.0.clone())
            .unwrap_or_else(|| format!("{:?}", decision.chosen_backend).to_lowercase())
    }

    /// Resolve the Ollama model name from the catalog for the given decision.
    async fn ollama_model_name(&self, decision: &RoutingDecision) -> String {
        let _ = decision; // keep signature consistent
        self.catalog
            .list_by_provider(ProviderClass::Ollama)
            .await
            .first()
            .map(|m| {
                m.model_id
                    .0
                    .strip_prefix("mdl_ollama_")
                    .unwrap_or(&m.model_id.0)
                    .to_string()
            })
            .unwrap_or_else(|| "llama3".into())
    }

    /// Resolve the vLLM model name from the catalog for the given decision.
    async fn vllm_model_name(&self, decision: &RoutingDecision) -> String {
        let _ = decision; // keep signature consistent
        self.catalog
            .list_by_provider(ProviderClass::Vllm)
            .await
            .first()
            .map(|m| {
                m.model_id
                    .0
                    .strip_prefix("mdl_vllm_")
                    .unwrap_or(&m.model_id.0)
                    .to_string()
            })
            .unwrap_or_else(|| "meta-llama/Llama-3.1-8B-Instruct".into())
    }

    /// Build a typed `ActionEnvelope` for the given intent (INV-002).
    #[allow(dead_code)]
    fn build_action_envelope(&self, intent: &CognitiveIntent) -> ActionEnvelope {
        let mut envelope = ActionEnvelope::new(
            Identity::new(intent.subject.0.clone(), true),
            Request::new(
                "cognitive.translate",
                serde_json::json!({
                    "intent_id": intent.intent_id.0,
                    "natural_language": intent.natural_language,
                }),
            ),
            Trace::new("00000000000000000000000000000000", "0000000000000000", None),
        );

        if let Some(target) = envelope.request.target.as_object_mut() {
            target.insert(
                "cognitive_provenance".to_string(),
                serde_json::Value::String(TRANSLATOR_VERSION.to_string()),
            );
        }

        envelope
    }
}

impl Default for ProductionCognitiveCore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CognitiveCore trait impl
// ---------------------------------------------------------------------------

#[async_trait]
impl CognitiveCore for ProductionCognitiveCore {
    async fn translate_intent(
        &self,
        intent: &CognitiveIntent,
        _context: &TranslationContext,
    ) -> Result<TranslationResult, CognitiveError> {
        let result = self.process_intent(intent).await?;

        self.translation_cache
            .write()
            .await
            .insert(intent.intent_id.clone(), result.clone());

        Ok(result)
    }

    fn list_supported_intents(&self) -> Vec<IntentCapability> {
        vec![
            IntentCapability {
                intent_kind: "service.restart".into(),
                description: "Restart a system service".into(),
                requires_latency_tier: LatencyTier::T1Deterministic,
                produces_action_type: "service.restart".into(),
                max_tokens_estimate: 512,
            },
            IntentCapability {
                intent_kind: "cognitive.translate".into(),
                description: "Translate a natural-language intent into a typed action".into(),
                requires_latency_tier: LatencyTier::T3LocalCognitive,
                produces_action_type: "cognitive.translate".into(),
                max_tokens_estimate: 2048,
            },
            IntentCapability {
                intent_kind: "model.invoke".into(),
                description: "Direct model invocation through the cognitive pipeline".into(),
                requires_latency_tier: LatencyTier::T3LocalCognitive,
                produces_action_type: "model.invoke".into(),
                max_tokens_estimate: 4096,
            },
        ]
    }

    async fn get_translation(
        &self,
        intent_id: &IntentId,
    ) -> Result<TranslationResult, CognitiveError> {
        self.translation_cache
            .read()
            .await
            .get(intent_id)
            .cloned()
            .ok_or_else(|| {
                CognitiveError::NoMatchingCapability(format!("intent not found: {}", intent_id.0))
            })
    }
}

// ---------------------------------------------------------------------------
// Error mapping helpers
// ---------------------------------------------------------------------------

fn map_ollama_error(err: OllamaError) -> CognitiveError {
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

fn map_vllm_error(err: VllmError) -> CognitiveError {
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
        reason = "panic-on-failure is the idiomatic test signal"
    )]

    use super::*;
    use crate::intent::{CognitiveIntent, IntentId, SubjectRef};
    use crate::latency::PrivacyClass;
    use crate::routing::ModelBackendKind;

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

    fn make_core() -> ProductionCognitiveCore {
        ProductionCognitiveCore::new()
    }

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    #[test]
    fn new_creates_core_with_defaults() {
        let core = make_core();
        assert!(core.ollama_adapter.is_none());
        assert!(core.vllm_adapter.is_none());
        assert!(core.evidence_emitter.is_none());
        // Catalog is empty on construction.
    }

    #[test]
    fn with_ollama_sets_adapter() {
        let core = ProductionCognitiveCore::new().with_ollama("http://localhost:11434");
        assert!(core.ollama_adapter.is_some());
        assert_eq!(
            core.ollama_adapter.as_ref().unwrap().base_url(),
            "http://localhost:11434"
        );
    }

    #[test]
    fn with_vllm_sets_adapter() {
        let core = ProductionCognitiveCore::new().with_vllm("http://localhost:8000");
        assert!(core.vllm_adapter.is_some());
        assert_eq!(
            core.vllm_adapter.as_ref().unwrap().base_url(),
            "http://localhost:8000"
        );
    }

    #[test]
    fn with_evidence_emitter_stores_emitter() {
        use crate::evidence_emit::{CognitiveEvidenceEmitter, InMemoryCognitiveEvidenceLog};
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let log: Arc<dyn crate::evidence_emit::CognitiveEvidenceLog> =
            Arc::new(InMemoryCognitiveEvidenceLog::new());
        let emitter = Arc::new(CognitiveEvidenceEmitter::new(
            log,
            sk,
            crate::evidence_emit::CognitiveSubjectRef("test".into()),
        ));

        let core = make_core().with_evidence_emitter(emitter);
        assert!(core.evidence_emitter.is_some());
    }

    // -----------------------------------------------------------------------
    // bootstrap_models
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn bootstrap_models_no_adapters_returns_ok() {
        let core = make_core();
        let result = core.bootstrap_models().await;
        // With no adapters, no models are discovered — a fallback fixture is seeded.
        assert!(result.is_ok());
        let models = core.catalog.list().await;
        assert!(!models.is_empty(), "fallback fixture should be registered");
    }

    #[tokio::test]
    async fn bootstrap_models_seeds_fallback_when_no_adapters() {
        let core = make_core();
        core.bootstrap_models().await.unwrap();
        let models = core.catalog.list().await;
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].model_id.0, "mdl_fallback_null");
        assert_eq!(models[0].provider, ProviderClass::Ollama);
    }

    // -----------------------------------------------------------------------
    // Pipeline: routing
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn process_intent_routes_t3_to_local_gpu() {
        let core = make_core();
        // Set LocalGpu as healthy.
        core.router_state
            .set_health(
                ModelBackendKind::LocalGpu,
                crate::routing::BackendHealthState::Healthy,
            )
            .await;

        // Use a T3-worthy intent.
        let words: Vec<String> = (0..80).map(|i| format!("word{i}")).collect();
        let intent = make_intent(&words.join(" "));

        // Without adapters configured, dispatch will fail — but routing should succeed.
        let result = core.process_intent(&intent).await;
        // Expect adapter-not-configured error for Ollama (default for LocalGpu).
        assert!(result.is_err(), "should fail on no adapter configured");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("OllamaAdapter"),
            "expected adapter-not-configured error, got: {err}"
        );
    }

    #[tokio::test]
    async fn process_intent_routes_t1_to_local_cpu_fallback() {
        let core = make_core();
        // No backends explicitly healthy.
        // T1 intent.
        let intent = make_intent("restart nginx");
        let result = core.process_intent(&intent).await;
        // T1 produces DegradedNull (rule 3) → ProviderClass::Anthropic → vault client not configured.
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("vault"),
            "expected vault-related error, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Circuit breaker
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn circuit_breaker_blocks_when_open() {
        let core = make_core();
        // Force the LocalGpu breaker open.
        for _ in 0..10 {
            core.breaker_registry
                .observe_and_update(ModelBackendKind::LocalGpu, false, 500)
                .await;
        }

        let breaker = core
            .breaker_registry
            .get(ModelBackendKind::LocalGpu)
            .await
            .unwrap();
        assert_eq!(breaker.current_state().await, CircuitState::Open);

        let result = core
            .breaker_registry
            .try_admit(ModelBackendKind::LocalGpu)
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CognitiveError::CircuitBreakerOpen(_)
        ));
    }

    #[tokio::test]
    async fn process_intent_fails_when_breaker_open_for_routed_backend() {
        let core = make_core();
        // Set LocalGpu healthy for routing, but open the breaker.
        core.router_state
            .set_health(
                ModelBackendKind::LocalGpu,
                crate::routing::BackendHealthState::Healthy,
            )
            .await;

        for _ in 0..10 {
            core.breaker_registry
                .observe_and_update(ModelBackendKind::LocalGpu, false, 500)
                .await;
        }

        let words: Vec<String> = (0..80).map(|i| format!("word{i}")).collect();
        let intent = make_intent(&words.join(" "));

        let result = core.process_intent(&intent).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CognitiveError::CircuitBreakerOpen(_)
        ));
    }

    // -----------------------------------------------------------------------
    // list_supported_intents
    // -----------------------------------------------------------------------

    #[test]
    fn list_supported_intents_returns_three_capabilities() {
        let core = make_core();
        let intents = core.list_supported_intents();
        assert_eq!(intents.len(), 3);
        assert!(intents.iter().any(|c| c.intent_kind == "service.restart"));
        assert!(intents
            .iter()
            .any(|c| c.intent_kind == "cognitive.translate"));
        assert!(intents.iter().any(|c| c.intent_kind == "model.invoke"));
    }

    // -----------------------------------------------------------------------
    // translate_intent (trait method)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn translate_intent_caches_result() {
        let core = make_core();
        let intent = make_intent("restart nginx");

        let ctx = TranslationContext {
            subject: intent.subject.clone(),
            available_models: vec![],
            latency_class: intent.latency_class,
            privacy_class: intent.privacy_class,
            ai_cross_origin_posture: crate::routing::AICrossOriginPosture::AiVaultBrokeredOnly,
            recovery_mode: false,
            budget_ok: true,
        };

        // translate_intent on a core without adapters — will fail on adapter not configured.
        let result = core.translate_intent(&intent, &ctx).await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Error mapping
    // -----------------------------------------------------------------------

    #[test]
    fn ollama_model_not_found_maps_to_no_matching_capability() {
        let err = map_ollama_error(OllamaError::ModelNotFound("unknown".into()));
        assert!(matches!(err, CognitiveError::NoMatchingCapability(_)));
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn ollama_timeout_maps_to_internal() {
        let err = map_ollama_error(OllamaError::Timeout);
        assert!(matches!(err, CognitiveError::Internal(_)));
        assert!(err.to_string().contains("timed out"));
    }

    #[test]
    fn ollama_parse_error_maps_to_model_response_invalid() {
        let err = map_ollama_error(OllamaError::ParseError("bad json".into()));
        assert!(matches!(err, CognitiveError::ModelResponseInvalid(_)));
    }

    #[test]
    fn vllm_model_not_found_maps_to_no_matching_capability() {
        let err = map_vllm_error(VllmError::ModelNotFound("missing".into()));
        assert!(matches!(err, CognitiveError::NoMatchingCapability(_)));
    }

    #[test]
    fn vllm_timeout_maps_to_internal() {
        let err = map_vllm_error(VllmError::Timeout);
        assert!(matches!(err, CognitiveError::Internal(_)));
    }

    #[test]
    fn vllm_parse_error_maps_to_model_response_invalid() {
        let err = map_vllm_error(VllmError::ParseError("bad sse".into()));
        assert!(matches!(err, CognitiveError::ModelResponseInvalid(_)));
    }

    // -----------------------------------------------------------------------
    // Send + Sync
    // -----------------------------------------------------------------------

    #[test]
    fn production_cognitive_core_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProductionCognitiveCore>();
    }
}
