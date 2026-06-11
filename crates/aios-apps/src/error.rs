//! AppsError — closed error taxonomy for the L6 apps/packages/compatibility layer.
//!
//! Every error variant maps to a closed reason code suitable for evidence
//! emission and operator-facing display. No free-form error strings.

use thiserror::Error;

/// Closed error taxonomy for L6 apps, packages, compatibility, and session
/// container operations. Each variant carries a structured discriminator
/// suitable for evidence record emission.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AppsError {
    /// Package object not found at the expected AIOS-FS path.
    #[error("package object not found: {0}")]
    PackageNotFound(String),

    /// Package object state transition rejected by the FSM.
    #[error("illegal state transition: {from} → {to}")]
    IllegalStateTransition {
        /// Current state.
        from: String,
        /// Requested target state.
        to: String,
    },

    /// Package object layout on disk does not match the closed file set.
    #[error("package object layout corruption: {0}")]
    PackageObjectLayoutCorruption(String),

    /// Manifest materialization drift — BLAKE3 of manifest.json ≠ meta.aios pointer.
    #[error("manifest materialization drift for {package_id}: expected {expected}, got {actual}")]
    ManifestMaterializationDrift {
        /// The package id.
        package_id: String,
        /// Expected hash from meta.aios pointer.
        expected: String,
        /// Computed hash of manifest.json on disk.
        actual: String,
    },

    /// Rollback blocked by publisher policy or blocklist.
    #[error("rollback forbidden: {0}")]
    RollbackForbidden(String),

    /// Rollback blocked because target version is blocklisted.
    #[error("rollback blocked: version {version} is on the blocklist: {reason}")]
    RollbackBlocklisted {
        /// The target version.
        version: String,
        /// Blocklist reason.
        reason: String,
    },

    /// Ecosystem runtime mismatch between manifest and adapter.
    #[error("ecosystem runtime mismatch: manifest declares {manifest_runtime}, adapter expects {adapter_runtime}")]
    EcosystemRuntimeMismatch {
        /// Runtime declared in the manifest.
        manifest_runtime: String,
        /// Runtime expected by the adapter.
        adapter_runtime: String,
    },

    /// EcosystemHonestyClass violated by observed runtime behaviour.
    #[error(
        "ecosystem honesty class violation: claimed {claimed}, observed behaviour contradicts"
    )]
    HonestyClassViolation {
        /// The claimed honesty class.
        claimed: String,
    },

    /// Compatibility profile not found for the given app and runtime.
    #[error("compatibility profile not found for {app_id} under {runtime}")]
    ProfileNotFound {
        /// App identifier.
        app_id: String,
        /// Ecosystem runtime.
        runtime: String,
    },

    /// Session container not found.
    #[error("session container not found: {0}")]
    SessionNotFound(String),

    /// Session container quota exceeded for the group.
    #[error("session quota exceeded for group {group_id}: {active} active, quota {quota}")]
    SessionQuotaExceeded {
        /// Group identifier.
        group_id: String,
        /// Currently active sessions.
        active: u32,
        /// Configured quota.
        quota: u32,
    },

    /// AI subject attempted to author a session container (INV-013 hard-deny).
    #[error("AI session container authorship blocked")]
    AiSessionAuthorshipBlocked,

    /// Streamed session surface attempted placement in CHROME zone (INV-023 hard-deny).
    #[error("streamed surface in chrome blocked")]
    StreamedSurfaceInChromeBlocked,

    /// Staged update already exists for this package; only one staged peer at a time.
    #[error("staged update already exists for {0}")]
    StagedUpdateAlreadyExists(String),

    /// Observation rejected because requested duration exceeds the hard cap
    /// per S12.1 §4.1.
    #[error("observation {observation_id} rejected: {reason}")]
    ObservationRejected {
        /// The observation identifier (may be empty if pre-observation rejection).
        observation_id: String,
        /// Reason for rejection.
        reason: String,
    },

    /// Update FSM invalid state transition.
    #[error("invalid state transition: {from} → {to}")]
    InvalidStateTransition {
        /// Current state.
        from: String,
        /// Requested target state.
        to: String,
    },

    /// Update plan not found for the given id.
    #[error("update plan not found: {0}")]
    UpdatePlanNotFound(String),

    /// Validation failed for an incoming manifest or contribution.
    #[error("validation failed: {0}")]
    ValidationFailed(String),

    /// Evidence emission failed — seal or chain append rejected.
    #[error("evidence emit failed: {0}")]
    EvidenceEmitFailed(String),

    /// Capability Runtime rejected the typed action for policy or
    /// adapter-level reasons.
    #[error("runtime rejected action: {0}")]
    RuntimeReject(String),

    /// The declared runtime class does not match the operation (e.g.
    /// non-service profile used with `register_service`).
    #[error("invalid runtime class: {0}")]
    InvalidRuntimeClass(String),

    /// A resource referenced by the bridge layer was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Session container runtime operation failed.
    #[error("session container error: {0}")]
    SessionContainerError(String),
}
