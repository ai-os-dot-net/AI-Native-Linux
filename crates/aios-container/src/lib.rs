//! `aios-container` — S24 Container and Kubernetes Native Plane.
//!
//! Provides the typed core skeleton for container admission, engine selection,
//! isolation mapping, workload import detection, and security profile gates.
//! Full gRPC surface, evidence emission, and runtime integration land in
//! later tasks.

#![forbid(unsafe_code)]

pub mod ecosystem_adapters;
pub mod engine_policy;
pub mod enums;
pub mod evidence;
pub mod helm_controller;
pub mod importer;
pub mod isolation;
pub mod k8s_operator;
pub mod manifest_validator;
pub mod passport;
pub mod profile_gates;

pub use ecosystem_adapters::{is_ai_allowed_runtime, map_runtime_to_isolation};
pub use engine_policy::ContainerEnginePolicy;
pub use enums::{
    ContainerAdmissionDecision, ContainerEngine, EcosystemRuntimeAdapter, ImageBuildEngine,
    IsolationLevel, K8sProfile, WorkloadImporter,
};
pub use evidence::{
    encode_admission_evidence, ContainerAdmittedPayload, ContainerBlockedPayload,
    ContainerQuarantinedPayload,
};
pub use helm_controller::{
    Ed25519Signature, HelmChartDescriptor, HelmController, HelmRelease, HelmReleaseState,
    HelmValues, ValueConstraint,
};
pub use importer::parse_workload;
pub use isolation::SecureRuntimeSelector;
pub use k8s_operator::{
    default_admission_rules, profile_to_security_label, rule_digest_pin_required,
    rule_egress_policy_default_deny, rule_gpu_isolation_required,
    rule_privileged_containers_blocked, rule_secrets_env_spray_blocked,
    rule_unsigned_images_warn_or_block, AdmissionDecision, AdmissionRule, K8sAdmissionController,
    K8sNamespace, K8sOperator, K8sResourceRequest, K8sWorkloadDescriptor, WorkloadHealth,
    WorkloadState,
};
pub use manifest_validator::{
    ContainerSpec, K8sManifestValidator, ManifestResource, PortSpec, ResourceSpec,
    ValidatedManifest, ValidationError, ValidationSeverity,
};
pub use passport::CloudNativePassport;
pub use profile_gates::{is_privileged_allowed, is_unsigned_allowed, requires_digest_pin};
