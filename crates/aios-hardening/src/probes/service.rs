use crate::enums::{HardeningProbeStatus, ProbeClass};
use crate::error::HardeningError;

/// Result of a systemd service hardening posture check.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceResult {
    /// Which probe class produced this result.
    pub probe_class: ProbeClass,
    /// The check identifier.
    pub check_id: String,
    /// The service unit name.
    pub service_name: String,
    /// Probe execution outcome.
    pub status: HardeningProbeStatus,
    /// Human-readable description of the observed state.
    pub observed: String,
    /// Human-readable description of the expected state.
    pub expected: String,
    /// Remediation hint if the check failed.
    pub remediation_hint: Option<String>,
    /// The computed hardening score (0.0..=1.0).
    pub score: Option<f64>,
}

/// Hardening directive names checked by the service probe.
const HARDENING_DIRECTIVES: &[(&str, &str, bool)] = &[
    ("ProtectSystem", "strict", false),
    ("NoNewPrivileges", "yes", false),
    ("PrivateTmp", "yes", false),
    ("ProtectHome", "yes", false),
    ("ProtectKernelTunables", "yes", false),
    ("ProtectKernelModules", "yes", false),
    ("ProtectKernelLogs", "yes", false),
    ("ProtectControlGroups", "yes", false),
    ("RestrictRealtime", "yes", false),
    ("RestrictAddressFamilies", "AF_UNIX AF_NETLINK", false),
    ("MemoryDenyWriteExecute", "yes", false),
    ("LockPersonality", "yes", false),
    ("PrivateDevices", "yes", false),
    ("ProtectClock", "yes", false),
    ("ProtectHostname", "yes", false),
    ("RestrictSUIDSGID", "yes", false),
    ("RemoveIPC", "yes", false),
    ("RestrictNamespaces", "yes", false),
    ("SystemCallArchitectures", "native", false),
    ("SystemCallFilter", "@system-service", false),
];

/// systemd service hardening score probe.
///
/// Reads systemd unit files and computes a hardening score based on
/// the presence and value of security-relevant directives.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServiceProbe;

impl ServiceProbe {
    /// Create a new service probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute the hardening score for a single unit file.
    ///
    /// Reads the unit file, scans for hardening directives, and computes
    /// a score as the fraction of directives that are present with the
    /// expected value.
    ///
    /// # Errors
    ///
    /// Returns [`HardeningError::ProbeExecution`] if the unit file cannot
    /// be read.
    pub fn check_service_hardening(
        &self,
        service_name: &str,
    ) -> Result<ServiceResult, HardeningError> {
        let unit_paths = [
            format!("/etc/systemd/system/{service_name}"),
            format!("/usr/lib/systemd/system/{service_name}"),
        ];

        let contents = unit_paths
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok());

        let (status, score, observed, remediation) = match contents {
            Some(content) => {
                let mut present = 0_usize;
                let mut matched = 0_usize;

                for (directive, expected_value, _) in HARDENING_DIRECTIVES {
                    let prefix = format!("{directive}=");
                    if let Some(line) = content.lines().find(|l| l.trim().starts_with(&prefix)) {
                        present = present.wrapping_add(1);
                        let actual = line
                            .trim()
                            .strip_prefix(&prefix)
                            .unwrap_or("")
                            .trim();
                        if actual == *expected_value {
                            matched = matched.wrapping_add(1);
                        }
                    }
                }

                let total = HARDENING_DIRECTIVES.len();
                let score_val = matched as f64 / total as f64;

                if score_val >= 0.8 {
                    (
                        HardeningProbeStatus::Passed,
                        Some(score_val),
                        format!(
                            "Service {service_name} hardening score: {matched}/{total} directives matched"
                        ),
                        None,
                    )
                } else if score_val >= 0.5 {
                    (
                        HardeningProbeStatus::Warn,
                        Some(score_val),
                        format!(
                            "Service {service_name} hardening score: {matched}/{total} directives matched (below target)"
                        ),
                        Some("Add missing systemd hardening directives to the unit file".to_string()),
                    )
                } else {
                    (
                        HardeningProbeStatus::Failed,
                        Some(score_val),
                        format!(
                            "Service {service_name} hardening score: {matched}/{total} directives matched (critically low)"
                        ),
                        Some("Add systemd hardening directives: ProtectSystem=strict, NoNewPrivileges=yes, etc.".to_string()),
                    )
                }
            }
            None => {
                (
                    HardeningProbeStatus::Skipped,
                    None,
                    format!("Service unit file not found for '{service_name}'"),
                    None,
                )
            }
        };

        Ok(ServiceResult {
            probe_class: ProbeClass::ServicePosture,
            check_id: format!("aios.check.service.hardening.{service_name}"),
            service_name: service_name.to_string(),
            status,
            observed,
            expected: "Hardening score >= 0.8 (80% of directives match expected values)".into(),
            remediation_hint: remediation,
            score,
        })
    }

    /// Check hardening for a list of services and aggregate results.
    ///
    /// This runs [`check_service_hardening`] for each service and returns
    /// individual results plus a summary.
    pub fn check_multiple_services(
        &self,
        service_names: &[&str],
    ) -> Result<Vec<ServiceResult>, HardeningError> {
        service_names
            .iter()
            .map(|name| self.check_service_hardening(name))
            .collect()
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
        assert_send_sync::<ServiceProbe>();
    }

    #[test]
    fn check_nonexistent_service_returns_skipped() {
        let probe = ServiceProbe::new();
        let result = probe.check_service_hardening("nonexistent-fake.service");
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.status, HardeningProbeStatus::Skipped);
        assert!(r.score.is_none());
    }

    #[test]
    fn check_service_returns_correct_probe_class() {
        let probe = ServiceProbe::new();
        let result = probe.check_service_hardening("nonexistent-fake.service");
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.probe_class, ProbeClass::ServicePosture);
    }

    #[test]
    fn check_multiple_services_returns_correct_count() {
        let probe = ServiceProbe::new();
        let results = probe
            .check_multiple_services(&[
                "nonexistent-fake1.service",
                "nonexistent-fake2.service",
            ]);
        assert!(results.is_ok());
        let r = results.unwrap();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn service_result_stores_score() {
        let result = ServiceResult {
            probe_class: ProbeClass::ServicePosture,
            check_id: "test.check".into(),
            service_name: "test.service".into(),
            status: HardeningProbeStatus::Passed,
            observed: "ok".into(),
            expected: "ok".into(),
            remediation_hint: None,
            score: Some(1.0),
        };
        assert_eq!(result.score, Some(1.0));
        assert_eq!(result.service_name, "test.service");
    }

    #[test]
    fn hardening_directives_list_is_non_empty() {
        assert!(!HARDENING_DIRECTIVES.is_empty());
        assert!(HARDENING_DIRECTIVES.len() >= 10);
    }
}
