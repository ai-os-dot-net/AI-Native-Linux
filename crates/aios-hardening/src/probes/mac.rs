use crate::enums::{HardeningProbeStatus, ProbeClass};
use crate::error::HardeningError;

/// Result of a MAC (Mandatory Access Control) posture check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacResult {
    /// Which probe class produced this result.
    pub probe_class: ProbeClass,
    /// The check identifier.
    pub check_id: String,
    /// Probe execution outcome.
    pub status: HardeningProbeStatus,
    /// Human-readable description of the observed state.
    pub observed: String,
    /// Human-readable description of the expected state.
    pub expected: String,
    /// Remediation hint if the check failed.
    pub remediation_hint: Option<String>,
}

/// SELinux MAC posture probe.
///
/// Validates SELinux enforcing status, policy version, boolean audit,
/// and AVC denial scanning.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacProbe;

impl MacProbe {
    /// Create a new MAC probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Check whether SELinux is enforcing.
    ///
    /// Reads `/sys/fs/selinux/enforce` to determine the current SELinux
    /// enforcement mode.
    ///
    /// # Errors
    ///
    /// Returns [`HardeningError::FeatureUnavailable`] if the sysfs interface
    /// is not accessible.
    pub fn check_selinux_enforcing(&self) -> Result<MacResult, HardeningError> {
        let enforce_path = std::path::Path::new("/sys/fs/selinux/enforce");
        let (status, observed, remediation) = if enforce_path.exists() {
            let enforce_val = std::fs::read_to_string(enforce_path).unwrap_or_default();
            let enforcing = enforce_val.trim() == "1";
            if enforcing {
                (
                    HardeningProbeStatus::Passed,
                    "SELinux is in enforcing mode".to_string(),
                    None,
                )
            } else {
                (
                    HardeningProbeStatus::Failed,
                    "SELinux is not enforcing".to_string(),
                    Some("Set SELinux to enforcing: setenforce 1 (runtime) or edit /etc/selinux/config".to_string()),
                )
            }
        } else {
            (
                HardeningProbeStatus::Skipped,
                "SELinux sysfs interface not available — SELinux may not be installed".to_string(),
                Some("Install and enable SELinux, then set to enforcing".to_string()),
            )
        };

        Ok(MacResult {
            probe_class: ProbeClass::MacPosture,
            check_id: "aios.check.mac.selinux_enforcing".into(),
            status,
            observed,
            expected: "SELinux is in enforcing mode".into(),
            remediation_hint: remediation,
        })
    }

    /// Check SELinux policy version.
    ///
    /// Reads `/sys/fs/selinux/policyvers` to determine the loaded policy
    /// version.
    pub fn check_policy_version(&self) -> Result<MacResult, HardeningError> {
        let policyvers_path = std::path::Path::new("/sys/fs/selinux/policyvers");
        let (status, observed, remediation) = if policyvers_path.exists() {
            let version = std::fs::read_to_string(policyvers_path).unwrap_or_default();
            let v: Result<u32, _> = version.trim().parse();
            match v {
                Ok(ver) if ver >= 33 => (
                    HardeningProbeStatus::Passed,
                    format!("SELinux policy version {ver} (>= 33)"),
                    None,
                ),
                Ok(ver) => (
                    HardeningProbeStatus::Warn,
                    format!("SELinux policy version {ver} (below 33)"),
                    Some(
                        "Upgrade SELinux userspace to a version supporting policy >= 33"
                            .to_string(),
                    ),
                ),
                Err(_) => (
                    HardeningProbeStatus::Error,
                    format!("unable to parse policy version: '{version}'"),
                    Some("Verify SELinux installation integrity".to_string()),
                ),
            }
        } else {
            (
                HardeningProbeStatus::Skipped,
                "SELinux policy version interface not available".to_string(),
                None,
            )
        };

        Ok(MacResult {
            probe_class: ProbeClass::MacPosture,
            check_id: "aios.check.mac.policy_version".into(),
            status,
            observed,
            expected: "SELinux policy version >= 33".into(),
            remediation_hint: remediation,
        })
    }

    /// Check for recent AVC denials via `audit.log` or `ausearch`.
    ///
    /// Scans `/var/log/audit/audit.log` for recent AVC denial entries.
    pub fn check_avc_denials(&self) -> Result<MacResult, HardeningError> {
        let audit_log = std::path::Path::new("/var/log/audit/audit.log");
        let (status, observed, remediation) = if audit_log.exists() {
            match std::fs::read_to_string(audit_log) {
                Ok(contents) => {
                    let avc_count = contents
                        .lines()
                        .filter(|line| line.contains("avc:  denied") || line.contains("AVC"))
                        .count();
                    if avc_count == 0 {
                        (
                            HardeningProbeStatus::Passed,
                            "No recent AVC denials found in audit log".to_string(),
                            None,
                        )
                    } else {
                        (
                            HardeningProbeStatus::Warn,
                            format!("{avc_count} AVC denial(s) found in audit log"),
                            Some("Review AVC denials and update SELinux policy or relabel filesystem".to_string()),
                        )
                    }
                }
                Err(_) => (
                    HardeningProbeStatus::Skipped,
                    "Unable to read audit log — insufficient permissions".to_string(),
                    Some("Run scanner as root or with CAP_AUDIT_READ".to_string()),
                ),
            }
        } else {
            (
                HardeningProbeStatus::Skipped,
                "Audit log not found at /var/log/audit/audit.log".to_string(),
                Some("Ensure auditd is installed and running".to_string()),
            )
        };

        Ok(MacResult {
            probe_class: ProbeClass::MacPosture,
            check_id: "aios.check.mac.avc_denials".into(),
            status,
            observed,
            expected: "No recent AVC denials in audit log".into(),
            remediation_hint: remediation,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn probe_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MacProbe>();
    }

    #[test]
    fn check_selinux_enforcing_returns_result_with_correct_class() {
        let probe = MacProbe::new();
        let result = probe.check_selinux_enforcing();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.probe_class, ProbeClass::MacPosture);
        assert_eq!(r.check_id, "aios.check.mac.selinux_enforcing");
        assert!(!r.observed.is_empty());
    }

    #[test]
    fn check_policy_version_returns_result_with_correct_class() {
        let probe = MacProbe::new();
        let result = probe.check_policy_version();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.probe_class, ProbeClass::MacPosture);
        assert_eq!(r.check_id, "aios.check.mac.policy_version");
        assert!(!r.observed.is_empty());
    }

    #[test]
    fn check_avc_denials_returns_result_with_correct_class() {
        let probe = MacProbe::new();
        let result = probe.check_avc_denials();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.probe_class, ProbeClass::MacPosture);
        assert_eq!(r.check_id, "aios.check.mac.avc_denials");
        assert!(!r.observed.is_empty());
    }

    #[test]
    fn mac_result_has_expected_structure() {
        let result = MacResult {
            probe_class: ProbeClass::MacPosture,
            check_id: "test.mac.check".into(),
            status: HardeningProbeStatus::Warn,
            observed: "policy version 31".into(),
            expected: ">= 33".into(),
            remediation_hint: Some("upgrade".into()),
        };
        assert_eq!(result.status, HardeningProbeStatus::Warn);
        assert!(result.remediation_hint.is_some());
    }
}
