use crate::enums::{HardeningProbeStatus, ProbeClass};
use crate::error::HardeningError;

/// Result of a cryptographic posture check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoResult {
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

/// FIPS-approved symmetric algorithms.
const FIPS_APPROVED_SYMMETRIC: &[&str] = &[
    "aes-128-cbc",
    "aes-192-cbc",
    "aes-256-cbc",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-gcm",
    "aes-256-gcm",
    "aes-128-ecb",
    "aes-256-ecb",
];

/// FIPS-approved hash algorithms.
const FIPS_APPROVED_HASHES: &[&str] = &[
    "sha-256", "sha-384", "sha-512", "sha3-256", "sha3-384", "sha3-512",
];

/// Known weak or deprecated algorithms.
const WEAK_ALGORITHMS: &[&str] = &[
    "md5",
    "sha1",
    "sha-1",
    "rc4",
    "des",
    "3des",
    "blowfish",
    "ecb",
];

/// Cryptographic posture probe.
///
/// Validates FIPS-approved algorithm usage, detects weak ciphers,
/// and checks FIPS mode overlay status.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoProbe;

impl CryptoProbe {
    /// Create a new crypto probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Check the kernel FIPS mode status.
    ///
    /// Reads `/proc/sys/crypto/fips_enabled` to determine whether the
    /// kernel is operating in FIPS mode.
    ///
    /// # Errors
    ///
    /// Returns [`HardeningError::FeatureUnavailable`] if the procfs
    /// interface is not mounted.
    pub fn check_fips_enabled(&self) -> Result<CryptoResult, HardeningError> {
        let fips_path = std::path::Path::new("/proc/sys/crypto/fips_enabled");
        let (status, observed, remediation) = if fips_path.exists() {
            let val = std::fs::read_to_string(fips_path).unwrap_or_default();
            let enabled = val.trim() == "1";
            if enabled {
                (
                    HardeningProbeStatus::Passed,
                    "Kernel FIPS mode is enabled".to_string(),
                    None,
                )
            } else {
                (
                    HardeningProbeStatus::Failed,
                    "Kernel FIPS mode is disabled".to_string(),
                    Some("Enable FIPS mode via kernel command line: fips=1".to_string()),
                )
            }
        } else {
            (
                HardeningProbeStatus::Skipped,
                "Kernel FIPS interface not available".to_string(),
                Some("Kernel may not be compiled with CONFIG_CRYPTO_FIPS".to_string()),
            )
        };

        Ok(CryptoResult {
            probe_class: ProbeClass::CryptoPosture,
            check_id: "aios.check.crypto.fips_enabled".into(),
            status,
            observed,
            expected: "Kernel FIPS mode is enabled".into(),
            remediation_hint: remediation,
        })
    }

    /// Validate that a given cipher list only contains FIPS-approved
    /// algorithms.
    ///
    /// Returns `Passed` if all algorithms are in the FIPS-approved set,
    /// `Failed` if any weak algorithm is detected, `Warn` if any algorithm
    /// is unknown but not known-weak.
    pub fn check_algorithm_compliance(
        &self,
        algorithms: &[String],
    ) -> Result<CryptoResult, HardeningError> {
        if algorithms.is_empty() {
            return Ok(CryptoResult {
                probe_class: ProbeClass::CryptoPosture,
                check_id: "aios.check.crypto.algorithm_compliance".into(),
                status: HardeningProbeStatus::Skipped,
                observed: "No algorithms provided for validation".into(),
                expected: "All algorithms are FIPS-approved".into(),
                remediation_hint: None,
            });
        }

        let approved_norm: Vec<String> = FIPS_APPROVED_SYMMETRIC
            .iter()
            .chain(FIPS_APPROVED_HASHES.iter())
            .map(|s| s.to_lowercase())
            .collect();

        let weak_norm: Vec<String> = WEAK_ALGORITHMS
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        let mut weak_found = Vec::new();
        let mut unknown_found = Vec::new();
        let mut approved_count = 0_usize;

        for alg in algorithms {
            let norm = alg.to_lowercase();

            if weak_norm.iter().any(|w| norm.contains(w.as_str())) {
                weak_found.push(alg.clone());
            } else if approved_norm.iter().any(|a| norm.contains(a.as_str())) {
                approved_count = approved_count.wrapping_add(1);
            } else {
                unknown_found.push(alg.clone());
            }
        }

        let (status, observed, remediation) = if !weak_found.is_empty() {
            (
                HardeningProbeStatus::Failed,
                format!("Weak algorithms detected: {}", weak_found.join(", ")),
                Some("Replace weak algorithms with FIPS-approved alternatives (e.g. AES-256-GCM, SHA-384)".to_string()),
            )
        } else if !unknown_found.is_empty() {
            (
                HardeningProbeStatus::Warn,
                format!(
                    "Unknown algorithms detected: {} ({} approved)",
                    unknown_found.join(", "),
                    approved_count,
                ),
                Some("Verify unknown algorithms against FIPS 140-3 approved list".to_string()),
            )
        } else {
            (
                HardeningProbeStatus::Passed,
                format!("All {approved_count} algorithm(s) are FIPS-approved"),
                None,
            )
        };

        Ok(CryptoResult {
            probe_class: ProbeClass::CryptoPosture,
            check_id: "aios.check.crypto.algorithm_compliance".into(),
            status,
            observed,
            expected: "All algorithms are FIPS 140-3 approved".into(),
            remediation_hint: remediation,
        })
    }

    /// Check OpenSSL FIPS provider availability.
    ///
    /// Reads `/etc/crypto-policies/back-ends/opensslcnf.config` or
    /// `/etc/ssl/openssl.cnf` for FIPS configuration directives.
    pub fn check_openssl_fips_provider(&self) -> Result<CryptoResult, HardeningError> {
        let config_paths = [
            "/etc/crypto-policies/back-ends/opensslcnf.config",
            "/etc/ssl/openssl.cnf",
        ];

        let mut found_config = None;
        let mut fips_present = false;

        for path in &config_paths {
            let p = std::path::Path::new(path);
            if p.exists() {
                if let Ok(contents) = std::fs::read_to_string(p) {
                    fips_present = contents.contains("fips_sect")
                        || contents.contains("fipsmodule.cnf")
                        || contents.contains("fips = fips_sect");
                    found_config = Some((*path, contents));
                }
            }
        }

        match found_config {
            Some((path, _contents)) if fips_present => Ok(CryptoResult {
                probe_class: ProbeClass::CryptoPosture,
                check_id: "aios.check.crypto.openssl_fips".into(),
                status: HardeningProbeStatus::Passed,
                observed: format!("FIPS provider configured in {path}"),
                expected: "OpenSSL FIPS provider enabled".into(),
                remediation_hint: None,
            }),
            Some((path, _contents)) => Ok(CryptoResult {
                probe_class: ProbeClass::CryptoPosture,
                check_id: "aios.check.crypto.openssl_fips".into(),
                status: HardeningProbeStatus::Failed,
                observed: format!("OpenSSL config found at {path} but FIPS provider not configured"),
                expected: "OpenSSL FIPS provider enabled".into(),
                remediation_hint: Some(
                    "Configure OpenSSL FIPS provider: add 'fips = fips_sect' to openssl.cnf".into(),
                ),
            }),
            None => Ok(CryptoResult {
                probe_class: ProbeClass::CryptoPosture,
                check_id: "aios.check.crypto.openssl_fips".into(),
                status: HardeningProbeStatus::Skipped,
                observed: "No OpenSSL configuration file found".into(),
                expected: "OpenSSL FIPS provider enabled".into(),
                remediation_hint: None,
            }),
        }
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
        assert_send_sync::<CryptoProbe>();
    }

    #[test]
    fn check_fips_enabled_returns_result_with_correct_class() {
        let probe = CryptoProbe::new();
        let result = probe.check_fips_enabled();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.probe_class, ProbeClass::CryptoPosture);
        assert_eq!(r.check_id, "aios.check.crypto.fips_enabled");
        assert!(!r.observed.is_empty());
    }

    #[test]
    fn check_algorithm_compliance_with_fips_approved() {
        let probe = CryptoProbe::new();
        let result = probe.check_algorithm_compliance(&[
            "aes-256-gcm".to_string(),
            "sha-384".to_string(),
        ]);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.status, HardeningProbeStatus::Passed);
    }

    #[test]
    fn check_algorithm_compliance_with_weak_algos() {
        let probe = CryptoProbe::new();
        let result = probe.check_algorithm_compliance(&[
            "md5".to_string(),
            "aes-256-gcm".to_string(),
        ]);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.status, HardeningProbeStatus::Failed);
        assert!(r.observed.to_lowercase().contains("weak"));
    }

    #[test]
    fn check_algorithm_compliance_empty_list() {
        let probe = CryptoProbe::new();
        let result = probe.check_algorithm_compliance(&[]);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.status, HardeningProbeStatus::Skipped);
    }

    #[test]
    fn check_algorithm_compliance_with_des() {
        let probe = CryptoProbe::new();
        let result = probe.check_algorithm_compliance(&["3des".to_string()]);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.status, HardeningProbeStatus::Failed);
    }

    #[test]
    fn check_openssl_fips_returns_result() {
        let probe = CryptoProbe::new();
        let result = probe.check_openssl_fips_provider();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.probe_class, ProbeClass::CryptoPosture);
        assert!(!r.observed.is_empty());
    }
}
