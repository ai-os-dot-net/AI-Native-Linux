use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WineError {
    #[error("wine executable not found on system: {0}")]
    WineNotFound(String),

    #[error("prefix creation failed for capsule {capsule_id}: {detail}")]
    PrefixCreationFailed { capsule_id: String, detail: String },

    #[error("app installation failed in prefix {prefix_id}: {detail}")]
    InstallFailed { prefix_id: String, detail: String },

    #[error("app not found in prefix {prefix_id}: {name}")]
    AppNotFound { prefix_id: String, name: String },

    #[error("DXVK setup failed: {0}")]
    DxvkSetupFailed(String),

    #[error("proton version not found at expected path: {0}")]
    ProtonVersionNotFound(String),

    #[error("prefix {prefix_id} already has a running app")]
    AlreadyRunning { prefix_id: String },

    #[error("sandbox violation in prefix {prefix_id}: {detail}")]
    SandboxViolation { prefix_id: String, detail: String },

    #[error("invalid prefix state transition from {from:?} to {to:?} for prefix {prefix_id}")]
    InvalidStateTransition {
        prefix_id: String,
        from: crate::WinePrefixState,
        to: crate::WinePrefixState,
    },

    #[error("proton compatibility tool not found for app {app_id}")]
    ProtonCompatToolNotFound { app_id: String },
}

impl WineError {
    #[must_use]
    pub fn wine_not_found(detail: impl Into<String>) -> Self {
        Self::WineNotFound(detail.into())
    }

    #[must_use]
    pub fn prefix_creation_failed(capsule_id: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::PrefixCreationFailed {
            capsule_id: capsule_id.into(),
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn install_failed(prefix_id: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::InstallFailed {
            prefix_id: prefix_id.into(),
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn app_not_found(prefix_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::AppNotFound {
            prefix_id: prefix_id.into(),
            name: name.into(),
        }
    }

    #[must_use]
    pub fn dxvk_setup_failed(detail: impl Into<String>) -> Self {
        Self::DxvkSetupFailed(detail.into())
    }

    #[must_use]
    pub fn proton_version_not_found(detail: impl Into<String>) -> Self {
        Self::ProtonVersionNotFound(detail.into())
    }

    #[must_use]
    pub fn already_running(prefix_id: impl Into<String>) -> Self {
        Self::AlreadyRunning {
            prefix_id: prefix_id.into(),
        }
    }

    #[must_use]
    pub fn sandbox_violation(prefix_id: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::SandboxViolation {
            prefix_id: prefix_id.into(),
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn invalid_state_transition(
        prefix_id: impl Into<String>,
        from: crate::WinePrefixState,
        to: crate::WinePrefixState,
    ) -> Self {
        Self::InvalidStateTransition {
            prefix_id: prefix_id.into(),
            from,
            to,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let err = WineError::wine_not_found("no wine binary at /usr/bin/wine");
        let msg = err.to_string();
        assert!(msg.contains("wine executable not found"));
        assert!(msg.contains("no wine binary"));
    }

    #[test]
    fn prefix_creation_failed_carries_capsule_id() {
        let err = WineError::prefix_creation_failed("caps_01ABCDEF", "mkdir failed");
        let msg = err.to_string();
        assert!(msg.contains("caps_01ABCDEF"));
        assert!(msg.contains("mkdir failed"));
    }

    #[test]
    fn install_failed_carries_prefix_and_detail() {
        let err = WineError::install_failed("wpre_01ABCDEF", "msiexec exit code 1603");
        let msg = err.to_string();
        assert!(msg.contains("wpre_01ABCDEF"));
        assert!(msg.contains("msiexec exit code 1603"));
    }

    #[test]
    fn error_clone_and_eq() {
        let err1 = WineError::already_running("wpre_XYZ");
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }

    #[test]
    fn sandbox_violation_carries_prefix_and_detail() {
        let err = WineError::sandbox_violation("wpre_01ABCDEF", "network access denied");
        let msg = err.to_string();
        assert!(msg.contains("wpre_01ABCDEF"));
        assert!(msg.contains("network access denied"));
    }
}
