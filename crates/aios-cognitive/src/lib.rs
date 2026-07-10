//! `aios-cognitive` — L5 Cognitive Core typed skeleton (S1.1, S1.2, S13.1, S13.2, S14.1).
//!
//! Types-only crate; no implementation logic, no gRPC, no evidence emission.

#![forbid(unsafe_code)]

/// Provider adapters — Ollama HTTP client, vLLM, etc.
pub mod adapter;
/// S14.1 circuit breaker driver.
pub mod breaker;
/// S14.1 circuit breaker registry.
pub mod breaker_registry;
/// S14.1 circuit breaker types.
pub mod circuit;
/// `CognitiveCore` async trait + `TranslationContext` + `IntentCapability` (S1.1).
pub mod core;
/// `CognitiveError` taxonomy.
pub mod error;
/// S13.x evidence emission policy (S13.x ↔ S3.1).
pub mod evidence_emit;
/// Typed cognitive evidence payloads.
pub mod evidence_payloads;
/// Live backend health monitoring loop.
pub mod health_monitor;
/// `InMemoryCognitiveCore` — test/prototype implementation of `CognitiveCore`.
pub mod in_memory_core;
/// `CognitiveIntent` + `IntentId` + `SubjectRef`.
pub mod intent;
/// `LatencyTier` + `PrivacyClass`.
pub mod latency;
/// Latency tiering classifier per S1.2 (stub heuristic; replaced M12+).
pub mod latency_classifier;
/// `CognitiveModel` + `ModelId`.
pub mod model;
/// `ModelBinding` + `ModelBindingRegistry` — runtime invocation tracking (S13.1).
pub mod model_binding;
/// `CognitiveModelCatalog` — model registration and lifecycle (S13.1).
pub mod model_catalog;
/// Production `CognitiveCore` — wires Ollama/vLLM adapters into the cognitive pipeline.
pub mod production_core;
/// INV-002 cross-crate provenance adapter — bridges `aios-cognitive` ↔ `aios-capability-runtime`.
pub mod provenance_adapter;
/// Provider dispatch — routes model invocations by ProviderClass (S13.2 §5).
pub mod provider_dispatch;
/// Model router precedence table (S13.2 §7).
pub mod router;
/// Router operational state — health tracking (S13.2 §9).
pub mod router_state;
/// Model router types (S13.2).
pub mod routing;
/// gRPC CognitiveCore service (T-101, S13.1 §19).
pub mod service;
/// `TranslationResult` + `TranslationProvenance`.
pub mod translator;
/// LLM-driven capability translator engine (Rev.5 Agent 5/8).
pub mod translator_engine;

// Re-exports — flattened public surface
pub use breaker::{AdmissionTicket, CallOutcome, CircuitBreaker};
pub use breaker_registry::CircuitBreakerRegistry;
pub use circuit::{CircuitBreakerConfig, CircuitBreakerStats, CircuitState};
pub use core::{CognitiveCore, IntentCapability, TranslationContext};
pub use error::CognitiveError;
pub use evidence_emit::{
    CognitiveEvidenceEmitter, CognitiveEvidenceLog, CognitiveSubjectRef,
    InMemoryCognitiveEvidenceLog, AIOS_COGNITIVE_SUBJECT,
};
pub use evidence_payloads::{
    AiDirectInternetDeniedPayload, BackendHealthChangedPayload, CircuitBreakerTrippedPayload,
    ModelCallPayload, RoutingDecisionPayload,
};
pub use health_monitor::{BackendHealthSnapshot, HealthMonitor, HealthMonitorConfig, HealthReport};
pub use in_memory_core::InMemoryCognitiveCore;
pub use intent::{CognitiveIntent, IntentId, SubjectRef};
pub use latency::{LatencyTier, PrivacyClass};
pub use latency_classifier::LatencyClassifier;
pub use model::{CognitiveModel, ModelId};
pub use model_binding::{ModelBinding, ModelBindingRegistry};
pub use model_catalog::CognitiveModelCatalog;
pub use production_core::ProductionCognitiveCore;
pub use provenance_adapter::{CognitiveProvenanceAdapter, PROVENANCE_MARKER_KEY};
pub use provider_dispatch::{
    DispatchOutcome, ProviderDispatcher, VaultClientAdapter, VaultRequest, VaultResponse,
};
pub use router::{ModelRouter, RoutingRule};
pub use router_state::RouterState;
pub use routing::{
    AICrossOriginPosture, BackendHealthEntry, BackendHealthState, ModelBackendKind, ProviderClass,
    RoutingDecision, RoutingInputs,
};
pub use translator::{TranslationProvenance, TranslationResult};
pub use translator_engine::{TranslateResponse, TranslatorEngine};

/// Crate version marker — bump on every semantic change.
pub const DEFAULT_CODE_VERSION: &str = "aios-cognitive/0.1.0-T105";
