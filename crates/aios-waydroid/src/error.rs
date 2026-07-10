use thiserror::Error;

use crate::WaydroidContainerState;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WaydroidError {
    #[error("waydroid binary not found on system: {0}")]
    WaydroidNotFound(String),

    #[error("container init failed for capsule {capsule_id}: {detail}")]
    ContainerInitFailed { capsule_id: String, detail: String },

    #[error("container start failed for capsule {capsule_id}: {detail}")]
    ContainerStartFailed { capsule_id: String, detail: String },

    #[error("binder kernel module missing: {0}")]
    BinderModuleMissing(String),

    #[error("APK install failed for package {package_name}: {detail}")]
    ApkInstallFailed {
        package_name: String,
        detail: String,
    },

    #[error("app not found: {package_name}")]
    AppNotFound { package_name: String },

    #[error("GPU configuration failed: {0}")]
    GpuConfigFailed(String),

    #[error("container {capsule_id} is already in state {state:?}")]
    AlreadyRunning {
        capsule_id: String,
        state: WaydroidContainerState,
    },

    #[error("invalid container state transition from {from:?} to {to:?} for capsule {capsule_id}")]
    InvalidStateTransition {
        capsule_id: String,
        from: WaydroidContainerState,
        to: WaydroidContainerState,
    },

    #[error("command execution failed: {0}")]
    CommandFailed(String),
}

impl WaydroidError {
    #[must_use]
    pub fn waydroid_not_found(detail: impl Into<String>) -> Self {
        Self::WaydroidNotFound(detail.into())
    }

    #[must_use]
    pub fn container_init_failed(capsule_id: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::ContainerInitFailed {
            capsule_id: capsule_id.into(),
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn container_start_failed(
        capsule_id: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::ContainerStartFailed {
            capsule_id: capsule_id.into(),
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn binder_module_missing(detail: impl Into<String>) -> Self {
        Self::BinderModuleMissing(detail.into())
    }

    #[must_use]
    pub fn apk_install_failed(package_name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::ApkInstallFailed {
            package_name: package_name.into(),
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn app_not_found(package_name: impl Into<String>) -> Self {
        Self::AppNotFound {
            package_name: package_name.into(),
        }
    }

    #[must_use]
    pub fn gpu_config_failed(detail: impl Into<String>) -> Self {
        Self::GpuConfigFailed(detail.into())
    }

    #[must_use]
    pub fn already_running(capsule_id: impl Into<String>, state: WaydroidContainerState) -> Self {
        Self::AlreadyRunning {
            capsule_id: capsule_id.into(),
            state,
        }
    }

    #[must_use]
    pub fn invalid_state_transition(
        capsule_id: impl Into<String>,
        from: WaydroidContainerState,
        to: WaydroidContainerState,
    ) -> Self {
        Self::InvalidStateTransition {
            capsule_id: capsule_id.into(),
            from,
            to,
        }
    }

    #[must_use]
    pub fn command_failed(detail: impl Into<String>) -> Self {
        Self::CommandFailed(detail.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let err = WaydroidError::waydroid_not_found("no waydroid binary at /usr/bin/waydroid");
        let msg = err.to_string();
        assert!(msg.contains("waydroid binary not found"));
        assert!(msg.contains("no waydroid binary"));
    }

    #[test]
    fn container_init_failed_carries_capsule_id() {
        let err = WaydroidError::container_init_failed("wdrd_01ABCDEF", "mkdir failed");
        let msg = err.to_string();
        assert!(msg.contains("wdrd_01ABCDEF"));
        assert!(msg.contains("mkdir failed"));
    }

    #[test]
    fn apk_install_failed_carries_package_and_detail() {
        let err = WaydroidError::apk_install_failed("com.example.app", "exit code 1");
        let msg = err.to_string();
        assert!(msg.contains("com.example.app"));
        assert!(msg.contains("exit code 1"));
    }

    #[test]
    fn error_clone_and_eq() {
        let err1 = WaydroidError::already_running("wdrd_XYZ", WaydroidContainerState::Running);
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }

    #[test]
    fn binder_module_missing_carries_detail() {
        let err = WaydroidError::binder_module_missing("/dev/binder not found");
        let msg = err.to_string();
        assert!(msg.contains("binder kernel module missing"));
        assert!(msg.contains("/dev/binder not found"));
    }
}
