use std::path::PathBuf;

use aios_sandbox::{
    GpuPolicy, IsolationKind, NetworkPosture, ProfileId, ResourceLimits, SandboxProfile,
};

use crate::error::WineError;

#[must_use]
pub fn generate_wine_sandbox_profile(
    _prefix_path: &PathBuf,
    capsule_id: String,
    network_allowed: bool,
) -> SandboxProfile {
    let gpu_policy = if std::env::var("AIOS_WINE_GPU")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        GpuPolicy::default_permissive()
    } else {
        GpuPolicy::default_deny_all()
    };

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
    ]);

    let mut syscall_allowlist = syscall_allowlist;

    if network_allowed {
        if let Some(ref mut list) = syscall_allowlist {
            list.push(String::from("connect"));
            list.push(String::from("sendto"));
            list.push(String::from("recvfrom"));
            list.push(String::from("bind"));
        }
    }

    SandboxProfile {
        profile_id: ProfileId::new(),
        name: format!("wine-prefix-{capsule_id}"),
        description: format!("Wine capsule sandbox for prefix {capsule_id}"),
        isolation_kind: IsolationKind::NamespaceLocal,
        resource_limits: ResourceLimits::default_strict(),
        gpu_policy,
        network_posture,
        syscall_allowlist,
        signing_authority: String::from("aios-wine"),
        signature_ed25519: Vec::new(),
    }
}

pub fn validate_prefix_path(prefix_path: &PathBuf) -> Result<(), WineError> {
    let allowed_base = PathBuf::from("/var/lib/aios/capsules/");
    if !prefix_path.starts_with(&allowed_base) {
        return Err(WineError::sandbox_violation(
            "unknown",
            format!("prefix path {prefix_path:?} is outside allowed capsule root {allowed_base:?}"),
        ));
    }
    Ok(())
}

#[must_use]
pub fn deny_proc_sys() -> Vec<String> {
    vec![
        String::from("/proc/sys"),
        String::from("/sys/kernel"),
        String::from("/proc/kcore"),
    ]
}

#[must_use]
pub fn allow_wine_system_paths() -> Vec<String> {
    vec![
        String::from("/usr/lib/wine"),
        String::from("/usr/lib32/wine"),
        String::from("/usr/lib64/wine"),
        String::from("/opt/wine"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use aios_sandbox::GpuCapabilityClass;

    #[test]
    fn sandbox_profile_denies_network_by_default() {
        let prefix = PathBuf::from("/var/lib/aios/capsules/caps_01ABCDEF/wine");
        let profile = generate_wine_sandbox_profile(&prefix, String::from("caps_01ABCDEF"), false);
        assert_eq!(profile.network_posture, NetworkPosture::DenyAll);
    }

    #[test]
    fn sandbox_profile_allows_network_when_configured() {
        let prefix = PathBuf::from("/var/lib/aios/capsules/caps_01ABCDEF/wine");
        let profile = generate_wine_sandbox_profile(&prefix, String::from("caps_01ABCDEF"), true);
        assert_eq!(profile.network_posture, NetworkPosture::Full);
    }

    #[test]
    fn prefix_path_validation_rejects_paths_outside_capsule_root() {
        let bad_path = PathBuf::from("/tmp/some_prefix");
        let result = validate_prefix_path(&bad_path);
        assert!(result.is_err());
        assert!(result
            .expect_err("should fail")
            .to_string()
            .contains("outside allowed capsule root"));
    }

    #[test]
    fn prefix_path_validation_accepts_valid_paths() {
        let good_path = PathBuf::from("/var/lib/aios/capsules/caps_01ABCDEF/wine/drive_c");
        let result = validate_prefix_path(&good_path);
        assert!(result.is_ok());
    }

    #[test]
    fn deny_proc_sys_includes_proc_sys() {
        let deny_list = deny_proc_sys();
        assert!(deny_list.contains(&String::from("/proc/sys")));
        assert!(deny_list.contains(&String::from("/sys/kernel")));
    }

    #[test]
    fn allow_wine_system_paths_includes_usr_lib_wine() {
        let allow = allow_wine_system_paths();
        assert!(allow.contains(&String::from("/usr/lib/wine")));
    }

    #[test]
    fn sandbox_profile_has_wine_name_prefix() {
        let prefix = PathBuf::from("/var/lib/aios/capsules/caps_test/wine");
        let profile = generate_wine_sandbox_profile(&prefix, String::from("caps_test"), false);
        assert!(profile.name.starts_with("wine-prefix-"));
        assert!(profile.name.contains("caps_test"));
    }

    #[test]
    fn sandbox_profile_gpu_deny_by_default() {
        let prefix = PathBuf::from("/var/lib/aios/capsules/caps_test/wine");
        let profile = generate_wine_sandbox_profile(&prefix, String::from("caps_test"), false);
        assert_eq!(
            profile.gpu_policy.gpu_capability_class,
            GpuCapabilityClass::GpuPassiveDisplay
        );
    }
}
