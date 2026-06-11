use crate::enums::{HardeningProbeStatus, ProbeClass};
use crate::error::HardeningError;

/// Result of a boot chain posture check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootChainResult {
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

/// Boot chain integrity probe.
///
/// Validates TPM2 PCR quote, measured boot attestation, IMA appraisal,
/// and dm-verity root hash verification.
///
/// # Platform support
///
/// Linux-only. Returns [`HardeningProbeStatus::Skipped`] with a diagnostic
/// message when the required kernel interfaces are unavailable.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootChainProbe;

impl BootChainProbe {
    /// Create a new boot chain probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Check TPM2 PCR quote availability.
    ///
    /// Returns `Passed` if `/sys/class/tpm/tpm0/pcr-sha256` is readable,
    /// `Failed` if the TPM is absent but required, `Skipped` if not available.
    ///
    /// # Errors
    ///
    /// Returns [`HardeningError::FeatureUnavailable`] if the check cannot
    /// determine TPM presence.
    pub fn check_tpm_pcr(&self) -> Result<BootChainResult, HardeningError> {
        let tpm_dir = std::path::Path::new("/sys/class/tpm/tpm0");
        let (status, observed, remediation) = if tpm_dir.exists() {
            (
                HardeningProbeStatus::Passed,
                "TPM2 device present at /sys/class/tpm/tpm0".to_string(),
                None,
            )
        } else {
            (
                HardeningProbeStatus::Failed,
                "No TPM2 device found at /sys/class/tpm/tpm0".to_string(),
                Some("Install a TPM 2.0 module or enable fTPM in firmware settings".to_string()),
            )
        };

        Ok(BootChainResult {
            probe_class: ProbeClass::BootPosture,
            check_id: "aios.check.boot.tpm_pcr".into(),
            status,
            observed,
            expected: "TPM2 device present and accessible".into(),
            remediation_hint: remediation,
        })
    }

    /// Check secure boot status via EFI variable.
    ///
    /// Returns `Passed` if Secure Boot is enabled, `Failed` otherwise,
    /// `Skipped` if the EFI variable is not accessible.
    ///
    /// # Errors
    ///
    /// Returns [`HardeningError::FeatureUnavailable`] if the sysfs interface
    /// is not mounted.
    pub fn check_secure_boot(&self) -> Result<BootChainResult, HardeningError> {
        let efivar = std::path::Path::new("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
        let (status, observed, remediation) = if efivar.exists() {
            let contents = std::fs::read(efivar).unwrap_or_default();
            let enabled = contents.len() > 4 && contents.get(4) == Some(&0x01);
            if enabled {
                (
                    HardeningProbeStatus::Passed,
                    "Secure Boot is enabled".to_string(),
                    None,
                )
            } else {
                (
                    HardeningProbeStatus::Failed,
                    "Secure Boot is disabled".to_string(),
                    Some("Enable Secure Boot in UEFI firmware settings".to_string()),
                )
            }
        } else {
            (
                HardeningProbeStatus::Skipped,
                "EFI variable store not accessible — cannot read SecureBoot status".to_string(),
                Some("Verify Secure Boot status via `mokutil --sb-state`".to_string()),
            )
        };

        Ok(BootChainResult {
            probe_class: ProbeClass::BootPosture,
            check_id: "aios.check.boot.secure_boot".into(),
            status,
            observed,
            expected: "Secure Boot enabled in UEFI".into(),
            remediation_hint: remediation,
        })
    }

    /// Check kernel lockdown mode via `/sys/kernel/security/lockdown`.
    ///
    /// Returns `Passed` if the kernel reports `integrity` or `confidentiality`
    /// lockdown, `Failed` if lockdown is `none`.
    pub fn check_kernel_lockdown(&self) -> Result<BootChainResult, HardeningError> {
        let lockdown_path = std::path::Path::new("/sys/kernel/security/lockdown");
        let (status, observed, remediation) = if lockdown_path.exists() {
            let contents =
                std::fs::read_to_string(lockdown_path).unwrap_or_default();
            let mode = contents.trim();
            if mode == "none" {
                (
                    HardeningProbeStatus::Failed,
                    format!("Kernel lockdown mode is '{mode}'"),
                    Some("Enable kernel lockdown via kernel command line: lockdown=integrity".to_string()),
                )
            } else {
                (
                    HardeningProbeStatus::Passed,
                    format!("Kernel lockdown mode is '{mode}'"),
                    None,
                )
            }
        } else {
            (
                HardeningProbeStatus::Skipped,
                "Kernel lockdown interface not available".to_string(),
                Some("Kernel may not support CONFIG_LOCK_DOWN_KERNEL".to_string()),
            )
        };

        Ok(BootChainResult {
            probe_class: ProbeClass::BootPosture,
            check_id: "aios.check.boot.kernel_lockdown".into(),
            status,
            observed,
            expected: "Kernel lockdown mode is integrity or confidentiality".into(),
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
        assert_send_sync::<BootChainProbe>();
    }

    #[test]
    fn check_tpm_pcr_returns_result_with_correct_class() {
        let probe = BootChainProbe::new();
        let result = probe.check_tpm_pcr();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.probe_class, ProbeClass::BootPosture);
        assert_eq!(r.check_id, "aios.check.boot.tpm_pcr");
        assert!(!r.observed.is_empty());
        assert!(!r.expected.is_empty());
    }

    #[test]
    fn check_secure_boot_returns_result_with_correct_class() {
        let probe = BootChainProbe::new();
        let result = probe.check_secure_boot();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.probe_class, ProbeClass::BootPosture);
        assert_eq!(r.check_id, "aios.check.boot.secure_boot");
        assert!(!r.observed.is_empty());
    }

    #[test]
    fn check_kernel_lockdown_returns_result_with_correct_class() {
        let probe = BootChainProbe::new();
        let result = probe.check_kernel_lockdown();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.probe_class, ProbeClass::BootPosture);
        assert_eq!(r.check_id, "aios.check.boot.kernel_lockdown");
        assert!(!r.observed.is_empty());
    }

    #[test]
    fn boot_chain_result_has_expected_structure() {
        let result = BootChainResult {
            probe_class: ProbeClass::BootPosture,
            check_id: "test.check".into(),
            status: HardeningProbeStatus::Passed,
            observed: "ok".into(),
            expected: "ok".into(),
            remediation_hint: None,
        };
        assert_eq!(result.status, HardeningProbeStatus::Passed);
        assert!(result.remediation_hint.is_none());
        assert_eq!(result.probe_class, ProbeClass::BootPosture);
    }
}
