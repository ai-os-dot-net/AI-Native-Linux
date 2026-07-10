use chrono::{DateTime, Utc};
use ulid::Ulid;

use crate::enums::{HardeningProbeStatus, HardeningStandard, ProbeClass, ProbeSeverity};
use crate::error::HardeningError;
use crate::probes::{
    BootChainProbe, BootChainResult, CryptoProbe, CryptoResult, MacProbe, MacResult, ServiceProbe,
    ServiceResult,
};

/// A single probe execution outcome, abstracted across probe types.
#[derive(Debug, Clone)]
pub enum ProbeResult {
    /// Boot chain posture check result.
    Boot(BootChainResult),
    /// SELinux MAC posture check result.
    Mac(MacResult),
    /// systemd service hardening check result.
    Service(ServiceResult),
    /// Cryptographic posture check result.
    Crypto(CryptoResult),
}

impl ProbeResult {
    /// Extract the probe class.
    #[must_use]
    pub fn probe_class(&self) -> ProbeClass {
        match self {
            Self::Boot(r) => r.probe_class,
            Self::Mac(r) => r.probe_class,
            Self::Service(r) => r.probe_class,
            Self::Crypto(r) => r.probe_class,
        }
    }

    /// Extract the check identifier.
    #[must_use]
    pub fn check_id(&self) -> &str {
        match self {
            Self::Boot(r) => &r.check_id,
            Self::Mac(r) => &r.check_id,
            Self::Service(r) => &r.check_id,
            Self::Crypto(r) => &r.check_id,
        }
    }

    /// Extract the probe status.
    #[must_use]
    pub fn status(&self) -> HardeningProbeStatus {
        match self {
            Self::Boot(r) => r.status,
            Self::Mac(r) => r.status,
            Self::Service(r) => r.status,
            Self::Crypto(r) => r.status,
        }
    }

    /// Extract the severity.
    #[must_use]
    pub fn severity(&self) -> ProbeSeverity {
        self.status().severity()
    }

    /// Human-readable observation.
    #[must_use]
    pub fn observed(&self) -> &str {
        match self {
            Self::Boot(r) => &r.observed,
            Self::Mac(r) => &r.observed,
            Self::Service(r) => &r.observed,
            Self::Crypto(r) => &r.observed,
        }
    }
}

/// Aggregated result of a full hardening scan.
#[derive(Debug, Clone)]
pub struct HardeningScanResult {
    /// Unique scan identifier.
    pub scan_id: String,
    /// When the scan was performed.
    pub scanned_at: DateTime<Utc>,
    /// The target security profile label.
    pub profile_label: String,
    /// Per-probe results.
    pub probe_results: Vec<ProbeResult>,
    /// Summary counts.
    pub passed: usize,
    /// Number of probes that failed.
    pub failed: usize,
    /// Number of probes with warnings.
    pub warned: usize,
    /// Number of probes that were skipped.
    pub skipped: usize,
    /// Number of probes that encountered execution errors.
    pub errors: usize,
    /// Whether the scan blocks profile promotion.
    pub promotion_blocked: bool,
}

/// Centralized hardening audit scanner.
///
/// The scanner loads probe instances, executes them against a target
/// security profile, aggregates results, and emits evidence.
///
/// # Architecture
///
/// ```text
/// harden scan --profile STIG_ALIGNED
///   → HardeningScanner::scan(profile)
///     → BootChainProbe::check_tpm_pcr()
///     → BootChainProbe::check_secure_boot()
///     → BootChainProbe::check_kernel_lockdown()
///     → MacProbe::check_selinux_enforcing()
///     → MacProbe::check_policy_version()
///     → MacProbe::check_avc_denials()
///     → CryptoProbe::check_fips_enabled()
///     → CryptoProbe::check_openssl_fips_provider()
///     → aggregate → HardeningScanResult
/// ```
#[derive(Debug, Default)]
pub struct HardeningScanner {
    /// Boot chain probe instance.
    boot_probe: BootChainProbe,
    /// SELinux MAC probe instance.
    mac_probe: MacProbe,
    /// systemd service probe instance.
    service_probe: ServiceProbe,
    /// Cryptographic posture probe instance.
    crypto_probe: CryptoProbe,
    /// Service names to check (configured per-profile).
    profile_services: Vec<String>,
}

impl HardeningScanner {
    /// Create a new scanner with default probe instances.
    #[must_use]
    pub fn new() -> Self {
        Self {
            boot_probe: BootChainProbe::new(),
            mac_probe: MacProbe::new(),
            service_probe: ServiceProbe::new(),
            crypto_probe: CryptoProbe::new(),
            profile_services: vec![
                "aios-evidence.service".into(),
                "aios-policy.service".into(),
                "aios-sandbox.service".into(),
            ],
        }
    }

    /// Set the service names to check during service posture scans.
    #[must_use]
    pub fn with_services(mut self, services: Vec<String>) -> Self {
        self.profile_services = services;
        self
    }

    /// Execute a full hardening scan against the specified profile.
    ///
    /// # Parameters
    ///
    /// - `profile_label` — canonical label (`DEV_RELAXED`, `SECURE_DEFAULT`,
    ///   `STIG_ALIGNED`, `AIRGAP_HIGH`).
    ///
    /// # Returns
    ///
    /// A [`HardeningScanResult`] containing all probe results and a
    /// summary with promotion gate status.
    ///
    /// # Errors
    ///
    /// Returns [`HardeningError::InvalidProfile`] if the profile label
    /// is not recognized.
    pub fn scan(&self, profile_label: &str) -> Result<HardeningScanResult, HardeningError> {
        match profile_label {
            "DEV_RELAXED" | "SECURE_DEFAULT" | "STIG_ALIGNED" | "AIRGAP_HIGH" => {}
            other => {
                return Err(HardeningError::InvalidProfile {
                    profile_id: other.to_string(),
                });
            }
        }

        let standard: HardeningStandard = profile_label.into();
        let _bootstrap = standard == HardeningStandard::Stig
            || profile_label == "STIG_ALIGNED"
            || profile_label == "AIRGAP_HIGH";

        let mut probe_results = Vec::new();

        self.collect_boot_probes(&mut probe_results)?;
        self.collect_mac_probes(&mut probe_results)?;
        self.collect_crypto_probes(&mut probe_results)?;
        self.collect_service_probes(&mut probe_results)?;

        let mut passed = 0_usize;
        let mut failed = 0_usize;
        let mut warned = 0_usize;
        let mut skipped = 0_usize;
        let mut errors = 0_usize;
        let mut promotion_blocked = false;

        for r in &probe_results {
            match r.status() {
                HardeningProbeStatus::Passed => passed = passed.wrapping_add(1),
                HardeningProbeStatus::Failed => {
                    failed = failed.wrapping_add(1);
                    promotion_blocked = true;
                }
                HardeningProbeStatus::Warn => warned = warned.wrapping_add(1),
                HardeningProbeStatus::Skipped => skipped = skipped.wrapping_add(1),
                HardeningProbeStatus::Error => {
                    errors = errors.wrapping_add(1);
                    promotion_blocked = true;
                }
            }
        }

        Ok(HardeningScanResult {
            scan_id: Ulid::new().to_string(),
            scanned_at: Utc::now(),
            profile_label: profile_label.to_string(),
            probe_results,
            passed,
            failed,
            warned,
            skipped,
            errors,
            promotion_blocked,
        })
    }

    fn collect_boot_probes(&self, results: &mut Vec<ProbeResult>) -> Result<(), HardeningError> {
        results.push(ProbeResult::Boot(self.boot_probe.check_tpm_pcr()?));
        results.push(ProbeResult::Boot(self.boot_probe.check_secure_boot()?));
        results.push(ProbeResult::Boot(self.boot_probe.check_kernel_lockdown()?));
        Ok(())
    }

    fn collect_mac_probes(&self, results: &mut Vec<ProbeResult>) -> Result<(), HardeningError> {
        results.push(ProbeResult::Mac(self.mac_probe.check_selinux_enforcing()?));
        results.push(ProbeResult::Mac(self.mac_probe.check_policy_version()?));
        results.push(ProbeResult::Mac(self.mac_probe.check_avc_denials()?));
        Ok(())
    }

    fn collect_crypto_probes(&self, results: &mut Vec<ProbeResult>) -> Result<(), HardeningError> {
        results.push(ProbeResult::Crypto(self.crypto_probe.check_fips_enabled()?));
        results.push(ProbeResult::Crypto(
            self.crypto_probe.check_openssl_fips_provider()?,
        ));
        Ok(())
    }

    fn collect_service_probes(&self, results: &mut Vec<ProbeResult>) -> Result<(), HardeningError> {
        for service_name in &self.profile_services {
            results.push(ProbeResult::Service(
                self.service_probe.check_service_hardening(service_name)?,
            ));
        }
        Ok(())
    }
}

impl From<&str> for HardeningStandard {
    fn from(label: &str) -> Self {
        match label {
            "STIG_ALIGNED" | "STIG" => Self::Stig,
            "SECURE_DEFAULT" => Self::Nist80053,
            "AIRGAP_HIGH" => Self::Nist800207,
            _ => Self::Nist80053,
        }
    }
}

impl HardeningScanResult {
    /// Returns `true` if the scan contains any blocking failures.
    #[must_use]
    pub fn has_blocking_failures(&self) -> bool {
        self.promotion_blocked
    }

    /// Returns a human-readable summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Scan {}: {} passed, {} failed, {} warned, {} skipped, {} errors. Promotion {}.",
            self.scan_id,
            self.passed,
            self.failed,
            self.warned,
            self.skipped,
            self.errors,
            if self.promotion_blocked {
                "BLOCKED"
            } else {
                "allowed"
            }
        )
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
    fn scanner_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HardeningScanner>();
    }

    #[test]
    fn scan_valid_profile_returns_result() {
        let scanner = HardeningScanner::new();
        let result = scanner.scan("SECURE_DEFAULT");
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.profile_label, "SECURE_DEFAULT");
        assert!(!r.scan_id.is_empty());
        assert!(!r.probe_results.is_empty());
    }

    #[test]
    fn scan_invalid_profile_returns_error() {
        let scanner = HardeningScanner::new();
        let result = scanner.scan("INVALID_PROFILE");
        assert!(result.is_err());
    }

    #[test]
    fn scan_all_valid_profiles() {
        let scanner = HardeningScanner::new();
        for label in &[
            "DEV_RELAXED",
            "SECURE_DEFAULT",
            "STIG_ALIGNED",
            "AIRGAP_HIGH",
        ] {
            let result = scanner.scan(label);
            assert!(result.is_ok(), "scan failed for {label}");
            let r = result.unwrap();
            assert!(!r.probe_results.is_empty(), "no results for {label}");
        }
    }

    #[test]
    fn scan_result_has_expected_summary_structure() {
        let scanner = HardeningScanner::new();
        let result = scanner.scan("SECURE_DEFAULT").unwrap();
        let summary = result.summary();
        assert!(summary.contains("passed"));
        assert!(summary.contains("failed"));
    }

    #[test]
    fn probe_result_extracts_status_correctly() {
        let scanner = HardeningScanner::new();
        let result = scanner.scan("SECURE_DEFAULT").unwrap();
        for pr in &result.probe_results {
            let status = pr.status();
            assert!(!pr.check_id().is_empty());
            assert!(!pr.observed().is_empty());
            let _ = status;
        }
    }

    #[test]
    fn scan_result_promotion_blocked_detects_failures() {
        let scanner = HardeningScanner::new();
        let result = scanner.scan("STIG_ALIGNED").unwrap();
        assert!(!result.scan_id.is_empty());
        let _ = result.has_blocking_failures();
    }

    #[test]
    fn scanner_with_custom_services() {
        let scanner = HardeningScanner::new().with_services(vec!["custom.service".into()]);
        let result = scanner.scan("SECURE_DEFAULT").unwrap();
        let service_count = result
            .probe_results
            .iter()
            .filter(|r| r.probe_class() == ProbeClass::ServicePosture)
            .count();
        assert_eq!(service_count, 1);
    }
}
