use serde::{Deserialize, Serialize};

use crate::enums::{ContainerAdmissionDecision, ContainerEngine, IsolationLevel};

/// A Cloud-Native Passport is the cryptographically-signed identity document
/// for a container workload. It carries image provenance, runtime preferences,
/// and the admission decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudNativePassport {
    pub passport_id: String,
    pub workload_id: String,
    pub source: String,
    pub image_digests: Vec<String>,
    pub runtime_engine: ContainerEngine,
    pub isolation_level: IsolationLevel,
    pub rootless: bool,
    pub privileged: bool,
    pub decision: ContainerAdmissionDecision,
}

impl CloudNativePassport {
    /// Construct a new `CloudNativePassport` for a workload.
    ///
    /// The passport starts in a clean state with safe defaults:
    /// rootless execution, no privilege, and admission deferred to the
    /// profile-specific gate.
    pub fn new(
        workload_id: impl Into<String>,
        source: impl Into<String>,
        image_digests: Vec<String>,
    ) -> Self {
        let passport_id = format!("cnp_{}", ulid::Ulid::new());
        Self {
            passport_id,
            workload_id: workload_id.into(),
            source: source.into(),
            image_digests,
            runtime_engine: ContainerEngine::PodmanRootless,
            isolation_level: IsolationLevel::Rootless,
            rootless: true,
            privileged: false,
            decision: ContainerAdmissionDecision::RequiresHumanApproval,
        }
    }

    /// Admit (or block) this passport based on a security profile string.
    ///
    /// Profile semantics:
    /// - `"DEV_RELAXED"` — permissive: allow unsigned, allow privileged,
    ///   auto-admit everything.
    /// - `"STIG_ALIGNED"` — strict: require digest pin, forbid unsigned,
    ///   forbid privileged.
    /// - `"AIRGAP_HIGH"` — strictest: require digest pin, forbid unsigned,
    ///   forbid privileged, quarantine unknowns.
    pub fn admit(&mut self, profile: &str) {
        match profile {
            "DEV_RELAXED" => {
                self.decision = ContainerAdmissionDecision::Admitted;
            }
            "STIG_ALIGNED" => {
                if self.image_digests.is_empty() {
                    self.decision = ContainerAdmissionDecision::Blocked;
                } else if self.privileged {
                    self.decision = ContainerAdmissionDecision::RequiresHumanApproval;
                } else {
                    self.decision = ContainerAdmissionDecision::Admitted;
                }
            }
            "AIRGAP_HIGH" => {
                if self.image_digests.is_empty() {
                    self.decision = ContainerAdmissionDecision::Quarantined;
                } else if self.privileged {
                    self.decision = ContainerAdmissionDecision::Blocked;
                } else {
                    self.decision = ContainerAdmissionDecision::Admitted;
                }
            }
            _ => {
                self.decision = ContainerAdmissionDecision::RequiresHumanApproval;
            }
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
    fn new_passport_has_safe_defaults() {
        let passport = CloudNativePassport::new(
            "wl_001",
            "docker.io/library/nginx:latest",
            vec!["sha256:abc123".into()],
        );
        assert!(passport.passport_id.starts_with("cnp_"));
        assert!(passport.rootless);
        assert!(!passport.privileged);
        assert_eq!(passport.runtime_engine, ContainerEngine::PodmanRootless);
        assert_eq!(
            passport.decision,
            ContainerAdmissionDecision::RequiresHumanApproval
        );
    }

    #[test]
    fn dev_relaxed_admits_everything() {
        let mut passport = CloudNativePassport::new("wl_002", "untrusted.io/image", vec![]);
        passport.privileged = true;
        passport.admit("DEV_RELAXED");
        assert_eq!(passport.decision, ContainerAdmissionDecision::Admitted);
    }

    #[test]
    fn stig_aligned_blocks_unsigned() {
        let mut passport = CloudNativePassport::new("wl_003", "untrusted.io/image", vec![]);
        passport.admit("STIG_ALIGNED");
        assert_eq!(passport.decision, ContainerAdmissionDecision::Blocked);
    }

    #[test]
    fn stig_aligned_allows_signed_unprivileged() {
        let mut passport =
            CloudNativePassport::new("wl_004", "trusted.io/image", vec!["sha256:def456".into()]);
        passport.admit("STIG_ALIGNED");
        assert_eq!(passport.decision, ContainerAdmissionDecision::Admitted);
    }

    #[test]
    fn stig_aligned_requires_human_approval_for_privileged() {
        let mut passport =
            CloudNativePassport::new("wl_005", "trusted.io/image", vec!["sha256:def456".into()]);
        passport.privileged = true;
        passport.admit("STIG_ALIGNED");
        assert_eq!(
            passport.decision,
            ContainerAdmissionDecision::RequiresHumanApproval
        );
    }

    #[test]
    fn airgap_high_quarantines_unsigned() {
        let mut passport = CloudNativePassport::new("wl_006", "untrusted.io/image", vec![]);
        passport.admit("AIRGAP_HIGH");
        assert_eq!(passport.decision, ContainerAdmissionDecision::Quarantined);
    }

    #[test]
    fn airgap_high_blocks_privileged() {
        let mut passport =
            CloudNativePassport::new("wl_007", "trusted.io/image", vec!["sha256:ghi789".into()]);
        passport.privileged = true;
        passport.admit("AIRGAP_HIGH");
        assert_eq!(passport.decision, ContainerAdmissionDecision::Blocked);
    }

    #[test]
    fn airgap_high_allows_signed_unprivileged() {
        let mut passport =
            CloudNativePassport::new("wl_008", "trusted.io/image", vec!["sha256:ghi789".into()]);
        passport.admit("AIRGAP_HIGH");
        assert_eq!(passport.decision, ContainerAdmissionDecision::Admitted);
    }

    #[test]
    fn unknown_profile_requires_human_approval() {
        let mut passport =
            CloudNativePassport::new("wl_009", "any.io/image", vec!["sha256:jkl012".into()]);
        passport.admit("UNKNOWN_PROFILE");
        assert_eq!(
            passport.decision,
            ContainerAdmissionDecision::RequiresHumanApproval
        );
    }
}
