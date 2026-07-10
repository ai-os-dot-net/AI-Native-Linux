use std::path::PathBuf;

use aios_sandbox::{
    GpuPolicy, IsolationKind, NetworkPosture, ProfileId, ResourceLimits, SandboxProfile,
};

use crate::error::WaydroidError;

#[must_use]
pub fn generate_waydroid_sandbox_profile(
    capsule_id: impl Into<String>,
    _data_path: &PathBuf,
    network_allowed: bool,
) -> SandboxProfile {
    let capsule_id = capsule_id.into();

    let gpu_policy = GpuPolicy::default_deny_all();

    let network_posture = if network_allowed {
        NetworkPosture::Full
    } else {
        NetworkPosture::DenyAll
    };

    let syscall_allowlist = Some(vec![
        String::from("read"),
        String::from("write"),
        String::from("openat"),
        String::from("close"),
        String::from("fstat"),
        String::from("mmap"),
        String::from("mprotect"),
        String::from("munmap"),
        String::from("brk"),
        String::from("rt_sigaction"),
        String::from("rt_sigprocmask"),
        String::from("ioctl"),
        String::from("futex"),
        String::from("clone"),
        String::from("execve"),
        String::from("bind"),
        String::from("connect"),
        String::from("sendto"),
        String::from("recvfrom"),
        String::from("getpid"),
        String::from("gettid"),
        String::from("sched_yield"),
    ]);

    SandboxProfile {
        profile_id: ProfileId::new(),
        name: format!("waydroid-capsule-{capsule_id}"),
        description: format!("Waydroid Android capsule sandbox for {capsule_id}"),
        isolation_kind: IsolationKind::NamespaceLocal,
        resource_limits: ResourceLimits::default_strict(),
        gpu_policy,
        network_posture,
        syscall_allowlist,
        signing_authority: String::from("aios-waydroid"),
        signature_ed25519: Vec::new(),
    }
}

pub fn validate_data_path(data_path: &PathBuf) -> Result<(), WaydroidError> {
    let allowed_base = PathBuf::from("/var/lib/aios/waydroid/");
    if !data_path.starts_with(&allowed_base) {
        return Err(WaydroidError::container_init_failed(
            "unknown",
            format!("data path {data_path:?} is outside allowed waydroid root {allowed_base:?}"),
        ));
    }
    Ok(())
}

pub fn deny_proc_sys_access() -> Vec<String> {
    vec![
        String::from("/proc"),
        String::from("/sys"),
        String::from("/dev/mem"),
        String::from("/dev/kmem"),
        String::from("/dev/port"),
    ]
}

pub fn allow_waydroid_system_paths() -> Vec<String> {
    vec![
        String::from("/var/lib/waydroid/"),
        String::from("/usr/share/waydroid-extra/"),
        String::from("/dev/binder"),
        String::from("/dev/vndbinder"),
        String::from("/dev/hwbinder"),
    ]
}

pub fn allow_binder_socket(detail: impl Into<String>) -> Result<(), WaydroidError> {
    let binder_path = PathBuf::from("/dev/binder");
    if !binder_path.exists() {
        return Err(WaydroidError::binder_module_missing(detail.into()));
    }
    Ok(())
}

pub fn deny_waydroid_network() -> NetworkPosture {
    NetworkPosture::DenyAll
}

pub fn allow_waydroid_network() -> NetworkPosture {
    NetworkPosture::Full
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_profile_denies_network_by_default() {
        let data_path = PathBuf::from("/var/lib/aios/waydroid/caps_01ABCDEF/");
        let profile = generate_waydroid_sandbox_profile("caps_01ABCDEF", &data_path, false);
        assert_eq!(profile.network_posture, NetworkPosture::DenyAll);
    }

    #[test]
    fn sandbox_profile_allows_network_when_requested() {
        let data_path = PathBuf::from("/var/lib/aios/waydroid/caps_01ABCDEF/");
        let profile = generate_waydroid_sandbox_profile("caps_01ABCDEF", &data_path, true);
        assert_eq!(profile.network_posture, NetworkPosture::Full);
    }

    #[test]
    fn sandbox_profile_allows_binder_socket() {
        let binder_path = PathBuf::from("/dev/binder");
        if binder_path.exists() {
            let result = allow_binder_socket("/dev/binder exists");
            assert!(result.is_ok());
        } else {
            let result = allow_binder_socket("binder module not loaded");
            assert!(result.is_err());
        }
    }

    #[test]
    fn validate_data_path_allows_correct_path() {
        let path = PathBuf::from("/var/lib/aios/waydroid/caps_01ABCDEF/data");
        let result = validate_data_path(&path);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_data_path_rejects_outside_path() {
        let path = PathBuf::from("/tmp/waydroid/");
        let result = validate_data_path(&path);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_profile_name_includes_capsule_id() {
        let data_path = PathBuf::from("/var/lib/aios/waydroid/caps_XYZ/");
        let profile = generate_waydroid_sandbox_profile("caps_XYZ", &data_path, false);
        assert!(profile.name.contains("caps_XYZ"));
    }

    #[test]
    fn deny_proc_sys_access_returns_paths() {
        let denied = deny_proc_sys_access();
        assert!(denied.contains(&String::from("/proc")));
        assert!(denied.contains(&String::from("/sys")));
        assert!(denied.contains(&String::from("/dev/mem")));
    }

    #[test]
    fn allow_waydroid_system_paths_includes_binder() {
        let allowed = allow_waydroid_system_paths();
        assert!(allowed.contains(&String::from("/dev/binder")));
        assert!(allowed.contains(&String::from("/dev/vndbinder")));
    }

    #[test]
    fn deny_and_allow_network_postures_are_correct() {
        assert_eq!(deny_waydroid_network(), NetworkPosture::DenyAll);
        assert_eq!(allow_waydroid_network(), NetworkPosture::Full);
    }
}
