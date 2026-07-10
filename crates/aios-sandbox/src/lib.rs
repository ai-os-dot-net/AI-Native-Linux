//! `aios-sandbox` — L6 Sandbox Composition typed core + composer (S3.2).
//!
//! Provides the 6-source profile merge algorithm per S3.2 §5.1 + §19.1.

#![forbid(unsafe_code)]

/// T-112 — `SandboxCognitiveHint` for cognitive↔sandbox profile suggestions.
pub mod cognitive_adapter;
/// `SandboxComposer` async trait + `ComposeRequest` / `ComposeResult` (S3.2 §19.1).
pub mod composer;
/// LSM confinement generator — produces AppArmor profiles and systemd units
/// from `SandboxProfile` structs (Rev.6).
pub mod confinement_generator;
/// `SandboxError` taxonomy.
pub mod error;
/// `SandboxEvidenceEmitter` + `SandboxEvidenceLog` trait + `InMemorySandboxEvidenceLog` (S3.2 ↔ S3.1).
pub mod evidence_emit;
/// Typed sandbox evidence payloads (S3.2 ↔ S3.1).
pub mod evidence_payloads;
/// `GpuPolicy` + `GpuCapabilityClass` (S3.2 + S8.2 type-level).
pub mod gpu;
/// `GpuPolicyEnforcer` — validates GPU policies, checks capability bounds,
/// and computes stub `GpuCapabilityBinding` per (group, subject) (S3.2 §`GpuPolicy` + S8.2).
pub mod gpu_enforcer;
/// `InMemorySandboxComposer` — in-memory profile catalog + 6-source merge.
pub mod in_memory_composer;
/// `IsolationKind` closed enum.
pub mod isolation;
/// `NetworkPosture` closed enum.
pub mod network;
/// `SandboxProfile` + `ProfileId`.
pub mod profile;
/// `ResourceLimitEnforcer` + `ResourceRequest` / `ResourceUsage` / `ResourceRemaining` (S3.2).
pub mod resource_enforcer;
/// `ResourceLimits` + default factories + validation.
pub mod resources;
/// T-112 — `SandboxRuntimeAdapter` bridging [`InMemorySandboxComposer`] to the
/// capability-runtime [`RuntimeSandboxComposer`] trait.
pub mod runtime_adapter;
/// gRPC `SandboxService` surface (T-110).
pub mod service;

// Re-exports — flattened public surface
pub use cognitive_adapter::SandboxCognitiveHint;
pub use composer::{ComposeRequest, ComposeResult, SandboxComposer, SubjectRef};
pub use error::SandboxError;
pub use evidence_emit::{
    InMemorySandboxEvidenceLog, SandboxEvidenceEmitter, SandboxEvidenceLog, SandboxSubjectRef,
    AIOS_SANDBOX_SUBJECT,
};
pub use evidence_payloads::{
    GpuCapabilityBoundPayload, ResourceLimitExceededPayload, SandboxComposedPayload,
    SandboxViolationDetectedPayload,
};
pub use gpu::{GpuCapabilityClass, GpuPolicy};
pub use gpu_enforcer::{GpuCapabilityBinding, GpuPolicyEnforcer, IommuStatus};
pub use in_memory_composer::InMemorySandboxComposer;
pub use isolation::IsolationKind;
pub use network::NetworkPosture;
pub use profile::{ProfileId, SandboxProfile};
pub use resource_enforcer::{
    ResourceLimitEnforcer, ResourceRemaining, ResourceRequest, ResourceUsage, SyscallEnforcement,
};
pub use resources::ResourceLimits;
pub use runtime_adapter::SandboxRuntimeAdapter;
pub use service::{
    SandboxServiceClient, SandboxServiceGrpc, SandboxServiceGrpcServer, SandboxServiceImpl,
    SCHEMA_VERSION,
};

/// Crate version marker — bump on every semantic change.
pub const DEFAULT_CODE_VERSION: &str = "aios-sandbox/0.1.0-T114";
