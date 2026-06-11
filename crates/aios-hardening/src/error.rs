use thiserror::Error;

/// Closed error taxonomy for the hardening audit scanner.
#[derive(Debug, Error)]
pub enum HardeningError {
    /// A probe failed to execute with an OS-level error.
    #[error("probe execution failed: {message}")]
    ProbeExecution {
        /// Human-readable error description.
        message: String,
    },

    /// A profile referenced a probe class that is not registered.
    #[error("unknown probe class: {class:?}")]
    UnknownProbeClass {
        /// The unrecognized probe class.
        class: String,
    },

    /// The scanner received an invalid profile identifier.
    #[error("invalid profile id: {profile_id}")]
    InvalidProfile {
        /// The invalid profile identifier.
        profile_id: String,
    },

    /// Evidence emission failed.
    #[error("evidence emission failed: {message}")]
    EvidenceEmission {
        /// Description of the emission failure.
        message: String,
    },

    /// A required system feature is unavailable (e.g. no TPM, no SELinux).
    #[error("system feature unavailable: {feature}")]
    FeatureUnavailable {
        /// The missing feature name.
        feature: String,
    },

    /// Internal scanner state corruption.
    #[error("internal error: {message}")]
    Internal {
        /// Human-readable internal error description.
        message: String,
    },
}
