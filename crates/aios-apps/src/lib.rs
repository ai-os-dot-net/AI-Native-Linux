#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::doc_markdown)]

//! AIOS L6 Apps, Packages, Compatibility — typed skeleton.
//!
//! This crate provides the closed-enum vocabularies and newtype identifiers
//! for the five L6 sub-specs:
//!
//! - **S12.1** App Runtime Model → [`ecosystem`]
//! - **S12.2** Package Object Model → [`package`]
//! - **S12.3** Compatibility Runtime → [`orchestration`]
//! - **S12.4** Compatibility Knowledge → [`app_profile`]
//! - **S6.5**  Session Container Model → [`session`]
//!
//! Every enum is closed; adding a variant is a versioned spec change.

pub mod app_profile;
pub mod compatibility_orchestrator;
pub mod compatibility_runtime;
pub mod ecosystem;
pub mod error;
pub mod evidence;
pub mod integration;
pub mod knowledge_db;
pub mod orchestration;
pub mod recipe_registry;
pub mod package;
pub mod package_store;
pub mod rosetta_solver;
pub mod runtime;
pub mod service;
pub mod session;
pub mod session_container_driver;
pub mod session_driver;
pub mod update_driver;
pub mod version_chain;

// Re-export all public types at crate root for convenience.
pub use app_profile::{
    AppProfile, CompatibilityRating, EvidenceLevel, KnownIssueClass, ProfileRetiredReason,
    ProfileVisibility, RatingDimension,
};
pub use compatibility_orchestrator::CompatibilityOrchestrator;
pub use compatibility_runtime::{
    AiosNativeRuntimeAdapter, AndroidRuntimeAdapter, CompatibilityRuntimeAdapter, LaunchContext,
    LinuxRuntimeAdapter, RuntimeCapability, SubjectRef, WebRuntimeAdapter, WindowsRuntimeAdapter,
};
pub use ecosystem::{
    EcosystemHonestyClass, EcosystemRuntime, ManifestDeltaOutcome, ManifestTranslationStrategy,
    RecipeTrustClass,
};
pub use error::AppsError;
pub use evidence::{
    AppsEvidenceEmitter, AppsEvidenceReceipt, AppsRecordType, InMemoryAppsEvidenceEmitter,
    SessionPhaseRecord, UpdatePhaseRecord,
};
pub use knowledge_db::{AppProfileMutation, CompatibilityKnowledgeDB};
pub use orchestration::{
    LaunchOutcome, OrchestrationKind, VMFallbackKind, WaydroidIsolationLevel, WinePrefixKind,
};
pub use recipe_registry::{
    Recipe, RecipeId, RecipeInstallResult, RecipeRegistry, RecipeReview, RecipeState,
    RecipeTrustBadge, RecipeVerificationStatus, ReviewId, ReviewVerdict, RECIPE_APPROVED,
    RECIPE_DEPRECATED, RECIPE_FLAGGED, RECIPE_INSTALLED, RECIPE_PUBLISHED, RECIPE_SUBMITTED,
};
pub use package::{
    PackageContentKind, PackageId, PackageObjectKind, PackageObjectState, PackageRecord,
    RollbackKind,
};
pub use package_store::{blake3_hex, AppPackage, InMemoryPackageStore, PackageStore};
pub use runtime::{
    AppManifestProposal, AppRuntime, InMemoryAppRuntime, ObservedBehavior, SyscallClass,
};
pub use session::{
    SessionContainerMode, SessionContainerRuntime, SessionContainerState, SessionFailureClass,
    SessionId, SessionRecord, StreamProtocol,
};
pub use session_container_driver::{SessionContainerConfig, SessionContainerDriver};
pub use session_driver::{
    CapabilityHandle, InMemorySessionDriver, OpenSessionRequest, Principal, SessionDescriptor,
    SessionDriver, SessionExitReason, SessionFilter, SessionMetrics, SessionState,
    SessionTerminationReceipt,
};
pub use update_driver::{
    FailureClass, InMemoryUpdateDriver, RollbackExitState, RollbackReason, RollbackReceipt,
    UpdateOutcome, UpdatePlan, UpdatePlanId, UpdatePlanRequest, UpdateRollbackDriver, UpdateState,
    UpdateVerification,
};
pub use rosetta_solver::{
    CompatibilityScore, ComplexityBand, ConversionStrategy, IsolationLevel, PackageFormat,
    PackagePassport, ProvenanceGrade, RosettaSolver, RosettaTranslation, ShadowInstall,
    ShadowInstallState,
};
pub use version_chain::{PackageState, VersionChain, VersionChainEntry};

/// M13 closure marker — canonical code version.
pub const DEFAULT_CODE_VERSION: &str = "aios-apps/0.1.0-T126";

// Integration bridge re-exports
pub use integration::{RuntimeBridge, SandboxBridge, SgrBridge};
