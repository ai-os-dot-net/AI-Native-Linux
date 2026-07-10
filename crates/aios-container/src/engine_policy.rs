use crate::enums::ContainerEngine;

/// Per-workload container engine selection policy.
///
/// Governs which container runtime engine is used, whether the Docker socket
/// is ever exposed, and whether rootful engines require human approval.
#[derive(Debug, Clone)]
pub struct ContainerEnginePolicy {
    pub default_engine: ContainerEngine,
    pub docker_socket_exposed: bool,
    pub rootful_requires_human_approval: bool,
    pub digest_pin_required: bool,
}

impl Default for ContainerEnginePolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerEnginePolicy {
    /// Create a new policy with safe production defaults.
    ///
    /// - Default engine: `PODMAN_ROOTLESS`
    /// - Docker socket: NEVER exposed
    /// - Rootful engines: ALWAYS require human approval
    pub fn new() -> Self {
        Self {
            default_engine: ContainerEngine::PodmanRootless,
            docker_socket_exposed: false,
            rootful_requires_human_approval: true,
            digest_pin_required: false,
        }
    }

    /// Whether the Docker socket is allowed in the current policy.
    /// Always returns `false` — socket exposure is forbidden by design.
    pub fn is_docker_socket_allowed(&self) -> bool {
        false
    }

    /// Select the appropriate container engine for a given workload type.
    pub fn select_engine(&self, workload_type: &str) -> ContainerEngine {
        match workload_type {
            "AI_INFERENCE" | "GPU_WORKLOAD" => ContainerEngine::Containerd,
            "SYSTEM_SERVICE" => ContainerEngine::PodmanRootful,
            _ => self.default_engine,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn new_defaults_are_safe() {
        let policy = ContainerEnginePolicy::new();
        assert_eq!(policy.default_engine, ContainerEngine::PodmanRootless);
        assert!(
            !policy.docker_socket_exposed,
            "docker socket must never be exposed by default"
        );
        assert!(
            policy.rootful_requires_human_approval,
            "rootful engines must require human approval by default"
        );
    }

    #[test]
    fn docker_socket_always_forbidden() {
        let policy = ContainerEnginePolicy::new();
        assert!(!policy.is_docker_socket_allowed());

        // Even if someone manually sets it, the method flat-out returns false
        let mut bypass = ContainerEnginePolicy::new();
        bypass.docker_socket_exposed = true;
        assert!(!bypass.is_docker_socket_allowed());
    }

    #[test]
    fn rootful_requires_human_approval_is_always_true_on_new() {
        let policy = ContainerEnginePolicy::new();
        assert!(policy.rootful_requires_human_approval);
    }

    #[test]
    fn select_engine_defaults_to_podman_rootless() {
        let policy = ContainerEnginePolicy::new();
        assert_eq!(
            policy.select_engine("web_server"),
            ContainerEngine::PodmanRootless
        );
    }

    #[test]
    fn select_engine_gpu_workload_uses_containerd() {
        let policy = ContainerEnginePolicy::new();
        assert_eq!(
            policy.select_engine("GPU_WORKLOAD"),
            ContainerEngine::Containerd
        );
    }

    #[test]
    fn select_engine_ai_inference_uses_containerd() {
        let policy = ContainerEnginePolicy::new();
        assert_eq!(
            policy.select_engine("AI_INFERENCE"),
            ContainerEngine::Containerd
        );
    }

    #[test]
    fn select_engine_system_service_uses_podman_rootful() {
        let policy = ContainerEnginePolicy::new();
        assert_eq!(
            policy.select_engine("SYSTEM_SERVICE"),
            ContainerEngine::PodmanRootful
        );
    }
}
