use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// External compliance standard recognized by the hardening scanner.
///
/// Maps to the standards tracked in `aios-integration::standard_registry`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
    Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HardeningStandard {
    /// DISA Security Technical Implementation Guide.
    Stig,
    /// NIST Special Publication 800-53 Rev.5.
    #[serde(rename = "NIST_800_53")]
    Nist80053,
    /// Center for Internet Security Controls v8.
    CisV8,
    /// FIPS 140-3 cryptographic module validation.
    #[serde(rename = "FIPS_140_3")]
    Fips1403,
    /// EU AI Act compliance controls.
    EuAiAct,
    /// NIST SP 800-207 Zero Trust Architecture.
    #[serde(rename = "NIST_800_207")]
    Nist800207,
    /// NIST SP 800-193 Platform Firmware Resiliency.
    #[serde(rename = "NIST_800_193")]
    Nist800193,
}

impl HardeningStandard {
    /// Return the canonical display label (e.g. `"DISA STIG"`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stig => "DISA STIG",
            Self::Nist80053 => "NIST SP 800-53",
            Self::CisV8 => "CIS Controls v8",
            Self::Fips1403 => "FIPS 140-3",
            Self::EuAiAct => "EU AI Act",
            Self::Nist800207 => "NIST SP 800-207",
            Self::Nist800193 => "NIST SP 800-193",
        }
    }
}

impl std::fmt::Display for HardeningStandard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Severity of a single hardening probe outcome.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
    Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeSeverity {
    /// Probe passed — the control is satisfied.
    Pass,
    /// Probe failed — the control is violated.
    Fail,
    /// Probe passed with warnings — operator should review.
    Warn,
    /// Probe does not apply to the current profile.
    NotApplicable,
}

impl ProbeSeverity {
    /// Return the canonical label (e.g. `"PASS"`, `"FAIL"`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Warn => "WARN",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }

    /// Returns `true` if this severity blocks promotion.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Fail)
    }
}

impl std::fmt::Display for ProbeSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Class of hardening probe — corresponds to a system posture domain.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
    Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProbeClass {
    /// Boot chain integrity, measured boot, TPM attestation.
    BootPosture,
    /// SELinux / MAC enforcement status.
    MacPosture,
    /// systemd service hardening score.
    ServicePosture,
    /// Package signatures, SBOM, provenance.
    PackagePosture,
    /// FIPS-approved crypto, weak cipher detection.
    CryptoPosture,
    /// Network exposure, mTLS, WireGuard posture.
    NetworkPosture,
    /// Evidence log, retention, data classification.
    DataGovernance,
    /// AI-specific controls (model provenance, inference audit).
    AiControls,
    /// Cross-host fleet sandbox floor verification.
    FleetPosture,
}

impl ProbeClass {
    /// Return the canonical label (e.g. `"BOOT_POSTURE"`, `"MAC_POSTURE"`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BootPosture => "BOOT_POSTURE",
            Self::MacPosture => "MAC_POSTURE",
            Self::ServicePosture => "SERVICE_POSTURE",
            Self::PackagePosture => "PACKAGE_POSTURE",
            Self::CryptoPosture => "CRYPTO_POSTURE",
            Self::NetworkPosture => "NETWORK_POSTURE",
            Self::DataGovernance => "DATA_GOVERNANCE",
            Self::AiControls => "AI_CONTROLS",
            Self::FleetPosture => "FLEET_POSTURE",
        }
    }
}

impl std::fmt::Display for ProbeClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Outcome of a single hardening probe execution.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HardeningProbeStatus {
    /// Probe passed — evidence collected.
    Passed,
    /// Probe failed — violation detected.
    Failed,
    /// Probe produced a warning — operator attention recommended.
    Warn,
    /// Probe was skipped (e.g., probe not applicable to profile).
    Skipped,
    /// Probe encountered a runtime error during execution.
    Error,
}

impl HardeningProbeStatus {
    /// Return the canonical label (e.g. `"PASSED"`, `"FAILED"`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
            Self::Warn => "WARN",
            Self::Skipped => "SKIPPED",
            Self::Error => "ERROR",
        }
    }

    /// Map to the canonical [`ProbeSeverity`].
    #[must_use]
    pub const fn severity(self) -> ProbeSeverity {
        match self {
            Self::Passed => ProbeSeverity::Pass,
            Self::Failed => ProbeSeverity::Fail,
            Self::Warn => ProbeSeverity::Warn,
            Self::Skipped | Self::Error => ProbeSeverity::NotApplicable,
        }
    }
}

impl std::fmt::Display for HardeningProbeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use strum::{EnumCount, IntoEnumIterator};

    use super::*;

    #[test]
    fn hardening_standard_is_exhaustive() {
        let count = HardeningStandard::iter().count();
        assert_eq!(count, HardeningStandard::COUNT);
        assert_eq!(HardeningStandard::COUNT, 7);
    }

    #[test]
    fn hardening_standard_serde_round_trip() {
        let standards = [
            HardeningStandard::Stig,
            HardeningStandard::Nist80053,
            HardeningStandard::CisV8,
            HardeningStandard::Fips1403,
            HardeningStandard::EuAiAct,
            HardeningStandard::Nist800207,
            HardeningStandard::Nist800193,
        ];
        for s in &standards {
            let json = serde_json::to_string(s).unwrap();
            let back: HardeningStandard = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn hardening_standard_screaming_snake_case_serde() {
        let json = serde_json::to_string(&HardeningStandard::Nist80053).unwrap();
        assert_eq!(json, "\"NIST_800_53\"");
        let json = serde_json::to_string(&HardeningStandard::EuAiAct).unwrap();
        assert_eq!(json, "\"EU_AI_ACT\"");
        let json = serde_json::to_string(&HardeningStandard::Fips1403).unwrap();
        assert_eq!(json, "\"FIPS_140_3\"");
        let json = serde_json::to_string(&HardeningStandard::Nist800207).unwrap();
        assert_eq!(json, "\"NIST_800_207\"");
        let json = serde_json::to_string(&HardeningStandard::Nist800193).unwrap();
        assert_eq!(json, "\"NIST_800_193\"");
    }

    #[test]
    fn probe_severity_is_exhaustive() {
        let count = ProbeSeverity::iter().count();
        assert_eq!(count, ProbeSeverity::COUNT);
        assert_eq!(ProbeSeverity::COUNT, 4);
    }

    #[test]
    fn probe_severity_serde_round_trip() {
        for s in ProbeSeverity::iter() {
            let json = serde_json::to_string(&s).unwrap();
            let back: ProbeSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn probe_severity_blocking_semantics() {
        assert!(ProbeSeverity::Fail.is_blocking());
        assert!(!ProbeSeverity::Pass.is_blocking());
        assert!(!ProbeSeverity::Warn.is_blocking());
        assert!(!ProbeSeverity::NotApplicable.is_blocking());
    }

    #[test]
    fn probe_class_is_exhaustive() {
        let count = ProbeClass::iter().count();
        assert_eq!(count, ProbeClass::COUNT);
        assert_eq!(ProbeClass::COUNT, 9);
    }

    #[test]
    fn probe_class_serde_round_trip() {
        for c in ProbeClass::iter() {
            let json = serde_json::to_string(&c).unwrap();
            let back: ProbeClass = serde_json::from_str(&json).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn hardening_probe_status_is_exhaustive() {
        let count = HardeningProbeStatus::iter().count();
        assert_eq!(count, HardeningProbeStatus::COUNT);
        assert_eq!(HardeningProbeStatus::COUNT, 5);
    }

    #[test]
    fn hardening_probe_status_serde_round_trip() {
        for s in HardeningProbeStatus::iter() {
            let json = serde_json::to_string(&s).unwrap();
            let back: HardeningProbeStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn hardening_probe_status_severity_mapping() {
        assert_eq!(
            HardeningProbeStatus::Passed.severity(),
            ProbeSeverity::Pass
        );
        assert_eq!(
            HardeningProbeStatus::Failed.severity(),
            ProbeSeverity::Fail
        );
        assert_eq!(
            HardeningProbeStatus::Warn.severity(),
            ProbeSeverity::Warn
        );
        assert_eq!(
            HardeningProbeStatus::Skipped.severity(),
            ProbeSeverity::NotApplicable
        );
        assert_eq!(
            HardeningProbeStatus::Error.severity(),
            ProbeSeverity::NotApplicable
        );
    }

    #[test]
    fn enums_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HardeningStandard>();
        assert_send_sync::<ProbeSeverity>();
        assert_send_sync::<ProbeClass>();
        assert_send_sync::<HardeningProbeStatus>();
    }
}
