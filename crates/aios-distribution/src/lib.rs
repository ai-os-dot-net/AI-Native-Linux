//! `aios-distribution` — core types for the AIOS Distribution layer (S11.1, schema
//! `aios.distribution.v1alpha1`).
//!
//! This crate implements the **typed skeleton** for the Repository Model + Trust Roots
//! defined in `L10_Distribution_Ecosystem_Marketplace/01_repository_model.md`. It is
//! the contract surface that every later L10 sub-spec builds on.
//!
//! ## Scope of T-187 (M19 open)
//!
//! - [`PublisherTrustLevel`] closed enum — 5 tiers (S11.1 §3.1).
//! - [`RepositoryKind`] closed enum — 5 repository classes (S11.1 §3.2).
//! - [`UpdateChannel`] closed enum — 4 channels (S11.1 §3.3).
//! - [`PackageKind`] closed enum — 9 kinds (S11.1 §3.4).
//! - [`InstallScope`] closed enum — 4 scopes (S11.1 §3.5).
//! - [`PackageInstallState`] closed FSM — 10 states (S11.1 §3.7).
//! - [`PackageVerificationResult`] closed enum — 10 outcomes (S11.1 §3.8).
//! - [`MirrorSemantic`] closed enum — 3 semantics (S11.1 §3.9).
//! - [`TakedownReason`] closed enum — 7 reasons (S11.1 §3.10).
//! - 6 identifier newtypes ([`PackageId`], [`PublisherId`], [`PublisherRootId`],
//!   [`PackageSigningKeyId`], [`RepositoryId`], [`ManifestId`]).
//! - [`DistributionError`] + [`DistributionErrorCode`] — 18-code error taxonomy.
//! - Per-package monotonic downgrade protection ([`VersionMonotonicCounter`]) per
//!   S11.1 §15.2.
//! - [`UpdateChannel`] rollout discipline ([`auto_update_allowed`],
//!   [`stable_auto_update_permitted`], [`channel_widening_requires_approval`],
//!   [`requires_reissue_for_channel_change`], [`validate_channel_for_repo`],
//!   [`recovery_critical_requires_recovery`]) per S11.1 §3.3.
//! - Strict [`SemVer`] parser + precedence ordering (no external semver crate).
//!
//! ## Deferred to T-194+
//!
//! - Trust chain logic (T-188).
//! - Manifest verification (T-189).
//! - Install FSM (T-190).
//! - Mirror blacklisting (T-191).
//! - Deplatform discipline (T-192).
//! - Capability lie audit (T-194).
//! - gRPC surface (T-195).
//! - Evidence emission (T-196).
//! - Cross-crate wiring (T-197).
//!
//! ## Constitutional invariants enforced here
//!
//! - **No `unsafe`, no `panic!`, no `unwrap`/`expect`, no `todo!`/`unimplemented!`** — workspace
//!   lints forbid them; every fallible path returns a typed `Result`.

#![forbid(unsafe_code)]

pub mod airgap_store;
pub mod canonical;
pub mod catalog;
pub mod cve_binding;
pub mod deplatform;
pub mod downgrade;
pub mod error;
pub mod evidence;
pub mod ids;
pub mod install_fsm;
pub mod install_pipeline;
pub mod install_state;
pub mod lie_audit;
pub mod manifest;
pub mod manifest_pipeline;
pub mod mirror;
pub mod mirror_blacklist;
pub mod mirror_fetch;
pub mod mirror_policy;
pub mod package_kind;
pub mod repository;
pub mod rollout;
pub mod rotation;
pub mod service;
pub mod takedown;
pub mod publisher_trust;
pub mod trust;
pub mod trust_chain;
pub mod verifier;
pub mod version;

pub use airgap_store::{
    AirgapAuditEvent, AirgapAuditLog, AirgapAuditLogEntry, AirgapInstallSource, AirgapPackage,
    AirgapProfileGate, AirgapStoreBuilder, AirgapStoreManifest, AirgapStoreMedium,
    AirgapUpdateSet, blocks_live_registry, requires_airgap_only,
};
pub use canonical::{content_hash, manifest_canonical_hash, signing_payload};
pub use catalog::{PublisherCatalog, SigningKeyCatalog};
pub use cve_binding::{apply_cve_binding, CveAction, CveEnforcementLevel, PackageCveBinding};
pub use deplatform::{
    apply_deplatform, default_grace_end, extend_grace, grace_expired, health_check_quarantine,
    returning_publisher_default_trust, verify_deplatform_event, InstalledPackageRecord,
    PublisherDeplatformEvent,
};
pub use downgrade::VersionMonotonicCounter;
pub use error::{DistributionError, DistributionErrorCode};
pub use evidence::{
    extended_60m_variants, forever_variants, record_type_for_failure, standard_24m_variants,
    DistributionEvidenceEmitter, DistributionEvidenceReceipt, DistributionRecordType,
};
pub use ids::{
    ManifestId, PackageId, PackageSigningKeyId, PublisherId, PublisherRootId, RepositoryId,
};
pub use install_fsm::{apply as apply_install_state, can_transition};
pub use install_pipeline::{
    run_first_run_audit, run_install, ApprovalOutcome, FetchedBytesMeta, InMemoryPipelineDeps,
    InstallOutcome, InstallPipelineDeps, PipelineStep, PolicyOutcome, StepFailure,
};
pub use install_state::{PackageInstallState, PackageVerificationResult};
pub use lie_audit::{
    apply_audit_outcome, AuditOutcome, CapabilityObservation, FirstRunAudit, ObservationSource,
};
pub use manifest::{NetworkManifestRef, PackageManifest, SandboxProfileRef};
pub use manifest_pipeline::{is_eol, validate_fields, verify_manifest, ManifestField};
pub use mirror::MirrorSemantic;
pub use mirror_blacklist::MirrorBlacklist;
pub use mirror_fetch::{resolve_and_verify, MirrorByteSource, ResolvedBytes};
pub use mirror_policy::{detect_resign_attempt, fetch_order, verify_mirror_bytes, MirrorEndpoint};
pub use package_kind::{InstallScope, PackageKind};
pub use repository::{RepositoryKind, UpdateChannel};
pub use rollout::{
    auto_update_allowed, channel_widening_requires_approval, recovery_critical_requires_recovery,
    requires_reissue_for_channel_change, stable_auto_update_permitted, validate_channel_for_repo,
    UpdateWindow,
};
pub use rotation::{
    apply_publisher_rotation, verify_rotation_event, AiosRootRotationEvent, PublisherRotationEvent,
    RotationOutcome,
};
pub use takedown::TakedownReason;
pub use publisher_trust::{
    AuditEntry, PublisherAuditTrail, PublisherReputation, PublisherTrustPolicy, ReputationEngine,
    ReputationEvent, SigningKeyRotation, TrustTier,
};
pub use trust::PublisherTrustLevel;
pub use trust_chain::{
    canonical_depth, AiosRootKey, LinkSignature, PackageSigningKey, PublisherRoot, SignedPayload,
    MAX_CHAIN_DEPTH,
};
pub use verifier::TrustChainVerifier;
pub use version::{parse as parse_semver, SemVer};

/// Code version marker for T-198 closure invariants.
///
/// This constant anchors the crate's identity at compile time so that closure
/// tests (T-198) can verify the distribution layer shipped with the correct
/// typed contract before cross-crate wiring lands in T-197.
pub const DEFAULT_CODE_VERSION: &str = "aios-distribution/0.0.1-T196";
