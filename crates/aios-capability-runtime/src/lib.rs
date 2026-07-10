//! `aios-capability-runtime` — core types for the AIOS Capability Runtime
//! (S10.1, schema `aios.runtime.v1alpha1`).
//!
//! This crate implements the **wire-format-agnostic core data model** for the
//! L3 Capability Runtime defined in
//! `002.AI-OS.NET--SPECREV.2/L3_AIOS_SGR_Service_Graph_Runtime/03_capability_runtime_grpc.md`.
//! It is the L3 sibling of `aios-policy` (L4) and consumes `aios-action` (S0.1).
//!
//! ## Scope of T-026 (M4 opener — types-only skeleton)
//!
//! - [`ActionLifecycleState`] — closed 14-state FSM per S10.1 §3.1.
//! - [`ActionDispatchKind`] — closed 4-variant dispatch enum per §3.2.
//! - [`AdapterIOMode`] — closed 2-variant adapter IO mode per §3.3.
//! - [`AdapterStability`] — closed 5-variant stability ladder per §3.4.
//! - [`QueueClass`] — closed 4-variant queue class per §3.5.
//! - [`ExecutionFailureReason`] — closed 12-variant execution failure enum per §3.6.
//! - [`RollbackOutcome`] — closed 4-variant rollback enum per §3.7.
//! - [`RuntimeErrorCode`] — closed 20-variant RPC error enum per §3.8.
//! - [`AdapterManifest`] — closed adapter manifest record per §10.1.
//! - [`ActionContext`] — internal per-action runtime context.
//! - [`RuntimeError`] — typed error taxonomy for the orchestration RPCs.
//!
//! Trait surface (`CapabilityRuntime`), adapter registry, dispatch queue,
//! policy / evidence integration, rollback FSM driver, approval orchestration,
//! and the gRPC service shell are **explicitly out of scope** for T-026 and
//! are queued for T-027..T-035.
//!
//! ## Constitutional invariants enforced here
//!
//! - **No `unsafe`, no `panic!`, no `unwrap`/`expect`, no `todo!`/`unimplemented!`** —
//!   workspace lints forbid them; every fallible path returns a typed `Result`.
//! - **`ActionLifecycleState::COUNT == 14`** — `EnumCount` provides the
//!   compile-time anchor; the round-trip tests assert the count.
//! - **Terminal states are terminal** — [`ActionLifecycleState::is_terminal`]
//!   returns `true` for the four spec-pinned strict terminals
//!   (`SUCCEEDED`, `ROLLED_BACK`, `ROLLBACK_FAILED`, `OVERRIDE_DENIED`) per
//!   the §4.2 forbidden-transition table.
//! - **Wire form is `SCREAMING_SNAKE_CASE`** for every closed enum, matching
//!   the proto IDL declared in §5.1 / §10.1.

#![forbid(unsafe_code)]

/// R3-W3 Step 3.2 — Typed-action fabric: intent → translate → typed action → dispatch.
pub mod action_fabric;
pub mod adapter_handle;
pub mod adapter_manifest;
pub mod adapter_registry;
/// T-034 — Approval orchestration types (S10.1 §6 ↔ S5.3).
pub mod approval;
/// R3-W3.3 — INV-002 mechanical enforcement gate ("AI proposes, never executes").
pub mod approval_gate;
/// T-034 — Approval binding sink (S10.1 ↔ S5.3 Approval Mechanics).
pub mod approval_sink;
/// S16.4 — Measured Boot Attestation Chain: TPM quote → measured boot log →
/// IMA appraisal → dm-verity root hash assembled into a single attestation report.
pub mod boot_attestation;
/// R3-W2: Capsule evidence trail for every lifecycle event.
pub mod capsule_evidence;
/// R3-W2: Capsule lifecycle manager integrating sandbox/isolation/namespace/snapshot.
pub mod capsule_lifecycle;
/// OS-RESEARCH: Plan 9/Inferno-inspired per-capsule namespace model.
pub mod capsule_namespace;
/// R3-W2: cgroups v2 resource quotas (CPU / memory / I/O) per capsule.
pub mod cgroups;
pub mod context;
pub mod dispatch;
pub mod dispatch_queue;
pub mod dispatcher;
/// R3-W4.1: Driver capsule template — signed, canary-booted, rollbackable driver sandbox.
pub mod driver_capsule;
pub mod error;
pub mod evidence_emit;
pub mod evidence_payloads;
pub mod failure;
/// R3-W1 Step 1.6: FIPS 140-3 crypto boundary — CMVP-validated provider routing
/// and compliance-sensitive operation validation (S16.5).
pub mod fips;
/// R3-W1: GDPR crypto-shred module for personal data classification and RTBF erasure (S16.9).
pub mod gdpr;
/// OS-RESEARCH: Linux IMA/EVM integrity measurement and appraisal (S16.4).
pub mod ima;
/// R3-W5.1: Kernel personality and portability — Linux gold path, capability matrix, canary boot.
pub mod kernel_personality;
/// OS-RESEARCH: Singularity/Midori-inspired managed-code isolation boundary.
pub mod managed_isolate;
/// R3-W6.1: Package Rosetta — universal intake across deb/rpm/flatpak/snap/appimage/nix/oci/source.
pub mod package_rosetta;
pub mod pipeline;
/// OS-RESEARCH: Genode/seL4-inspired recursive sandbox hierarchy.
pub mod recursive_sandbox;
pub mod rollback;
pub mod rollback_engine;
pub mod rollback_strategy;
pub mod runtime;
/// R3-W1: SBOM provenance and SLSA supply-chain evidence.
pub mod sbom;
/// OS-RESEARCH: BeOS/QNX-inspired adaptive partition scheduler.
pub mod scheduler;
/// Security Profile Matrix — Rev.3 S16.1 four-profile model with 14 dimensions.
pub mod security_profile;
/// OS-RESEARCH: seL4-inspired capability token model with formal invariants.
pub mod sel4_cap_model;
/// OS-RESEARCH: NSA SELinux/Flask-inspired mandatory access control policy plane (S16.2).
pub mod selinux;
/// T-033 — gRPC `CapabilityRuntime` service surface
/// (`aios.runtime.v1alpha1`, S10.1 §5).
pub mod service;
/// Service Hardening Score Gates — S16.7 measurable, scored, gated
/// hardening posture for AIOS systemd services.
pub mod service_hardening;
/// OS-RESEARCH: Plan 9 Fossil/Singularity-inspired capsule snapshot & restore.
pub mod snapshot;
/// R3-W2: Per-capsule filesystem isolation sandbox enforcing state-root boundaries.
pub mod state_sandbox;
pub mod status;
/// R3-W3 Step 3.1 — Terminal mode dispatcher (Lx / Mix / Ai).
pub mod terminal;
/// OS-RESEARCH: TCG TPM 2.0 dual-chain attestation root (S16.4).
pub mod tpm;
/// OS-RESEARCH: QNX/Plan 9-inspired transparent distributed IPC model.
pub mod transparent_ipc;
/// R3-W1: dm-verity / IPE immutable root filesystem integrity.
pub mod verity;

pub use adapter_handle::RealAdapterHandle;
pub use adapter_manifest::AdapterManifest;
pub use adapter_registry::{
    canonical_signed_manifest_bytes, encode_hex_signature, InMemoryAdapterRegistry,
    RegisteredAdapter,
};
pub use approval::{ApprovalBinding, ApprovalBindingState, ApprovalRequest};
pub use approval_sink::{ApprovalBindingSink, InMemoryApprovalSink};
pub use context::ActionContext;
pub use dispatch::{ActionDispatchKind, AdapterIOMode, AdapterStability, QueueClass};
pub use dispatch_queue::{
    DispatchQueue, TokenBucket, AGENT_PROPOSAL_CAP_DEN, AGENT_PROPOSAL_CAP_NUM,
    DEFAULT_BURST_CAPACITY, DEFAULT_REFILL_PER_SECOND, DEFAULT_TOTAL_CAPACITY,
};
pub use dispatcher::{ActionDispatcher, AI_INTERACTIVE_DOWNGRADE_MARKER};
pub use error::RuntimeError;
pub use evidence_emit::{
    EvidenceEmitter, EvidenceSink, InMemoryEvidenceSink, CAPABILITY_RUNTIME_SUBJECT,
};
pub use evidence_payloads::{
    ActionQueuedPayload, ActionReceivedPayload, AiInteractiveQueueDowngradePayload,
    ExecutionCompletedPayload, ExecutionStartedPayload, PolicyDecisionPayload,
    RollbackCompletedPayload, RoutingDecisionPayload, VerificationResultPayload,
};
pub use failure::{ExecutionFailureReason, RollbackOutcome, RuntimeErrorCode};
pub use pipeline::{
    apply_transition, compute_dispatch_kind, fresh_context, ActionLifecyclePipeline,
    DispatchKindInputs, PipelineState, TRANSITIONS,
};
pub use rollback::RollbackDriver;
pub use rollback_engine::{RollbackDecision, RollbackEngine, RollbackPolicy, RollbackResult};
pub use rollback_strategy::{RollbackFailureMode, RollbackStrategy};
pub use runtime::{
    AdapterHandle, AdapterRegistry, CapabilityRuntime, InMemoryCapabilityRuntime,
    NoOpAdapterHandle, NoOpAdapterRegistry, RuntimeCognitiveProvenance, RuntimeContext,
    RuntimeRecoveryHook, RuntimeSandboxComposer, SandboxProfileSummary,
};
pub use status::ActionLifecycleState;
// OS-RESEARCH re-exports
pub use capsule_namespace::{
    next_capsule_id, CapsuleId, CapsuleNamespace, MountFlag, NamespaceBinding, NamespacePath,
    NamespaceRegistry,
};
pub use managed_isolate::{IsolationMechanism, IsolationRegistry, ManagedIsolate};
pub use recursive_sandbox::{
    RecursiveSandbox, SandboxCapability, SandboxHierarchy, SandboxLevel, SandboxResource, MAX_DEPTH,
};
pub use scheduler::{
    AdaptivePartition, CapsulePriority, CapsuleSchedulingEntity, DecisionReason,
    PartitionScheduler, PriorityBand, SchedulingDecision,
};
pub use security_profile::{
    FipsOverlay, ProfileDimension, ProfileManifest, ProfileMatrix, ProfileRequirement,
    ProfileTransition, SecurityProfile,
};
pub use sel4_cap_model::{CapRight, CapRights, CapToken, CapTokenId, CapTokenTree};
pub use snapshot::{CapsuleSnapshot, SnapshotId, SnapshotPayload, SnapshotStore};
pub use tpm::{
    BootIntegrityVerifier, BootPosture, BootPostureReport, GoldenPcrValues, PcrBank, PcrRegister,
    PcrValue, PcrVerificationDetail, RootIntegrityEvidence, TpmAttestationKey, TpmQuote,
};
pub use transparent_ipc::{
    next_msg_id, CapsuleAddr, CapsuleMessage, MessageRouter, MsgId, MsgType, PendingRequest,
};
// S16.7 — Service hardening score gates re-exports
pub use service_hardening::{
    DirectiveResult, GateVerdict, HardeningBaseline, HardeningDirective, HardeningDirectiveValue,
    HardeningScore, HardeningScoreCalculator, ServiceClass, ServiceHardeningPolicy,
    ServiceHardeningScoredEvidence,
};
// IMA re-exports
pub use ima::{
    ImaAppraisalState, ImaMeasurement, ImaMeasurementList, ImaPolicy, ImaVerifier,
    IntegrityViolation,
};
// SELinux re-exports
pub use selinux::{
    AvcAuditEngine, AvcDecision, AvcDecisionKind, AvcDenial, MacPolicyCompiler, MacPolicyLifecycle,
    MacPolicyRequirement, McsLabel, MlsLabel, SeLinuxContext, SeLinuxDomain, SeLinuxPermission,
    SeLinuxRule, SePolicyBundle, SePolicyValidator, SelinuEvidenceEvent, SelinuxPolicyGate,
    ValidationError, AIOS_DATA_DOMAIN, AIOS_SYSTEM_DOMAIN,
};
// R3-W1: verity, SBOM, FIPS re-exports
pub use fips::{
    ComplianceOperation, CryptoProvider, FipsAlgorithm, FipsAlgorithmStatus, FipsBoundary,
    FipsBoundaryValidation, FipsCryptoEvidenceLog, FipsCryptoOperation, FipsCryptoOperationType,
    FipsEvidenceType, FipsMode, FipsOverlayState, FipsSelfTest, FipsSelfTestRunner,
    FipsSelfTestType, ParallelShaEvidence,
};
pub use sbom::{
    ReproStatus, ReproducibleBuildReceipt, SbomComponent, SbomDocument, SbomFormat, SbomGenerator,
    SbomRelationship, SbomRelationshipKind, SlcaProvenanceAttestation, SlcaProvenanceLevel,
    SlsaProvenance, SupplyChainEvidenceRecordType, VexJustification, VexStatement, VexStatus,
};
pub use verity::{IpePolicy, VerityHashTree, VerityImage, VerityResult, VerityVerifier};
// R3-W2: Lifecycle, rollback, state sandbox re-exports
pub use capsule_evidence::{CapsuleEvent, CapsuleEvidence, EvidenceChain};
pub use capsule_lifecycle::{CapsuleLifecycle, CapsuleLifecycleManager, CapsuleLifecycleState};
pub use driver_capsule::{
    CanaryBootResult, DriverCapsule, DriverClass, DriverRegistry, DriverSignature,
};
pub use state_sandbox::{
    AccessDecision, AccessMode, CapsuleStateRoot, FileAccessRule, FilePermission, SandboxViolation,
    StateSandbox,
};
// R3-W2: cgroups v2 resource quotas re-exports
pub use cgroups::{
    CgroupProfile, EnforcementAction, EnforcementMode, QuotaViolation, ResourceQuota, ResourceType,
    ResourceUsage,
};
// R3-W3 Step 3.1 — Terminal dispatcher re-exports
pub use terminal::{
    ActionProposal, ApprovalStatus, TerminalDispatcher, TerminalMode, TerminalSession,
};
// R3-W3.3 — Approval gate re-exports (INV-002)
pub use approval_gate::{
    ApprovalDecision, ApprovalGate, ApprovalPolicy, GateApprovalRequest, GateAuditEntry,
};
// R3-W3 Step 3.2 — Action fabric re-exports
pub use action_fabric::{ActionFabric, ActionIntent, CapabilityCatalog, FabricResult, TypedAction};
// R3-W1: GDPR crypto-shred re-exports
pub use gdpr::{
    AuditEntry, AuditExportFormat, AuditTrail, CryptoShredEvidence, CryptoShredKey,
    CryptoShredRequest, CryptoShredScope, DataCategory, DataClassification, DataGovernanceRegistry,
    DataResidencyConstraint, DataResidencyEnforcer, DataResidencyPolicy, DataSubject, ExportBundle,
    GdprAuditExport, GdprAuditExporter, ResidencyRegion, RetentionClass, RetentionPolicy,
    RightToBeForgottenPipeline, ShredEvidence, ShredRequest, ShredResult,
};
// R3-W6.1: Package Rosetta re-exports
pub use package_rosetta::{
    PackageFormat, PackagePassport, PackageRegistry, ShadowInstall, ShadowResult,
};
// S16.4 — Boot attestation re-exports
pub use boot_attestation::{
    attest_boot_chain, BootAttestationChain, BootAttestationError, BootAttestationReport,
    BootAttestedPayload, BootIntegrityState, MeasuredBootPolicy,
};
