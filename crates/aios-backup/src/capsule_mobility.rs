use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::enums::CapsuleImportDecision;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleExport {
    pub export_id: String,
    pub capsule_id: String,
    pub source_host_id: String,
    pub bundle_root_hash: String,
    pub profile_floor: String,
}

impl CapsuleExport {
    pub fn new(
        capsule_id: String,
        source_host_id: String,
        bundle_root_hash: String,
        profile_floor: String,
    ) -> Self {
        let export_id = format!("cexp_{}", Ulid::new());
        Self {
            export_id,
            capsule_id,
            source_host_id,
            bundle_root_hash,
            profile_floor,
        }
    }

    pub fn is_compatible_with_profile(&self, target_profile: &str) -> bool {
        match self.profile_floor.as_str() {
            "DEV_RELAXED" => true,
            "SECURE_DEFAULT" => {
                matches!(
                    target_profile,
                    "SECURE_DEFAULT" | "STIG_ALIGNED" | "AIRGAP_HIGH"
                )
            }
            "STIG_ALIGNED" => matches!(target_profile, "STIG_ALIGNED" | "AIRGAP_HIGH"),
            "AIRGAP_HIGH" => target_profile == "AIRGAP_HIGH",
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleImport {
    pub import_id: String,
    pub export_id: String,
    pub target_host_id: String,
    pub decision: CapsuleImportDecision,
    pub landed_capsule_id: Option<String>,
}

impl CapsuleImport {
    pub fn new(
        export_id: String,
        target_host_id: String,
        decision: CapsuleImportDecision,
        landed_capsule_id: Option<String>,
    ) -> Self {
        let import_id = format!("cimp_{}", Ulid::new());
        Self {
            import_id,
            export_id,
            target_host_id,
            decision,
            landed_capsule_id,
        }
    }

    pub fn decide_import(export: &CapsuleExport, target_profile: &str) -> CapsuleImportDecision {
        if ![
            "DEV_RELAXED",
            "SECURE_DEFAULT",
            "STIG_ALIGNED",
            "AIRGAP_HIGH",
        ]
        .contains(&target_profile)
        {
            return CapsuleImportDecision::Quarantine;
        }
        if export.is_compatible_with_profile(target_profile) {
            CapsuleImportDecision::Accept
        } else if export.profile_floor == "SECURE_DEFAULT" && target_profile == "DEV_RELAXED" {
            CapsuleImportDecision::AcceptDegraded
        } else {
            CapsuleImportDecision::BlockWithReason
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_relaxed_accepts_any_profile() {
        let export = CapsuleExport::new(
            "capsule-1".into(),
            "host-src".into(),
            "abc123".into(),
            "DEV_RELAXED".into(),
        );

        assert!(export.is_compatible_with_profile("DEV_RELAXED"));
        assert!(export.is_compatible_with_profile("SECURE_DEFAULT"));
        assert!(export.is_compatible_with_profile("STIG_ALIGNED"));
        assert!(export.is_compatible_with_profile("AIRGAP_HIGH"));
    }

    #[test]
    fn secure_default_accepts_equal_or_higher() {
        let export = CapsuleExport::new(
            "capsule-1".into(),
            "host-src".into(),
            "abc123".into(),
            "SECURE_DEFAULT".into(),
        );

        assert!(!export.is_compatible_with_profile("DEV_RELAXED"));
        assert!(export.is_compatible_with_profile("SECURE_DEFAULT"));
        assert!(export.is_compatible_with_profile("STIG_ALIGNED"));
        assert!(export.is_compatible_with_profile("AIRGAP_HIGH"));
    }

    #[test]
    fn stig_aligned_accepts_equal_or_higher() {
        let export = CapsuleExport::new(
            "capsule-1".into(),
            "host-src".into(),
            "abc123".into(),
            "STIG_ALIGNED".into(),
        );

        assert!(!export.is_compatible_with_profile("DEV_RELAXED"));
        assert!(!export.is_compatible_with_profile("SECURE_DEFAULT"));
        assert!(export.is_compatible_with_profile("STIG_ALIGNED"));
        assert!(export.is_compatible_with_profile("AIRGAP_HIGH"));
    }

    #[test]
    fn airgap_high_only_accepts_airgap_high() {
        let export = CapsuleExport::new(
            "capsule-1".into(),
            "host-src".into(),
            "abc123".into(),
            "AIRGAP_HIGH".into(),
        );

        assert!(!export.is_compatible_with_profile("DEV_RELAXED"));
        assert!(!export.is_compatible_with_profile("SECURE_DEFAULT"));
        assert!(!export.is_compatible_with_profile("STIG_ALIGNED"));
        assert!(export.is_compatible_with_profile("AIRGAP_HIGH"));
    }

    #[test]
    fn decide_import_accept_when_compatible() {
        let export = CapsuleExport::new(
            "capsule-1".into(),
            "host-src".into(),
            "abc123".into(),
            "SECURE_DEFAULT".into(),
        );
        let decision = CapsuleImport::decide_import(&export, "STIG_ALIGNED");
        assert_eq!(decision, CapsuleImportDecision::Accept);
    }

    #[test]
    fn decide_import_accept_degraded_for_minor_mismatch() {
        let export = CapsuleExport::new(
            "capsule-1".into(),
            "host-src".into(),
            "abc123".into(),
            "SECURE_DEFAULT".into(),
        );
        let decision = CapsuleImport::decide_import(&export, "DEV_RELAXED");
        assert_eq!(decision, CapsuleImportDecision::AcceptDegraded);
    }

    #[test]
    fn decide_import_block_when_below_floor() {
        let export = CapsuleExport::new(
            "capsule-1".into(),
            "host-src".into(),
            "abc123".into(),
            "STIG_ALIGNED".into(),
        );
        let decision = CapsuleImport::decide_import(&export, "DEV_RELAXED");
        assert_eq!(decision, CapsuleImportDecision::BlockWithReason);
    }

    #[test]
    fn decide_import_quarantine_unknown_profile() {
        let export = CapsuleExport::new(
            "capsule-1".into(),
            "host-src".into(),
            "abc123".into(),
            "DEV_RELAXED".into(),
        );
        let decision = CapsuleImport::decide_import(&export, "CUSTOM_WEIRD");
        assert_eq!(decision, CapsuleImportDecision::Quarantine);
    }

    #[test]
    fn capsule_import_has_distinct_ids() {
        let imp1 = CapsuleImport::new(
            "cexp_01".into(),
            "host-1".into(),
            CapsuleImportDecision::Accept,
            None,
        );
        let imp2 = CapsuleImport::new(
            "cexp_01".into(),
            "host-2".into(),
            CapsuleImportDecision::Accept,
            Some("capsule-landed-1".into()),
        );
        assert_ne!(imp1.import_id, imp2.import_id);
    }
}
