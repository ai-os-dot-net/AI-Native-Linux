use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionalBackupContract {
    pub contract_id: String,
    pub host_id: String,
    pub encrypt_at_source: bool,
    pub per_subject_keys: bool,
    pub rollback_anchor: bool,
    pub targets: Vec<String>,
}

impl ConstitutionalBackupContract {
    pub fn new(
        host_id: String,
        per_subject_keys: bool,
        rollback_anchor: bool,
        targets: Vec<String>,
    ) -> Self {
        let contract_id = format!("cbc_{}", Ulid::new());
        Self {
            contract_id,
            host_id,
            encrypt_at_source: true,
            per_subject_keys,
            rollback_anchor,
            targets,
        }
    }

    pub fn has_off_host_target(&self) -> bool {
        self.targets.iter().any(|t| t != "self" && t != "local")
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.encrypt_at_source {
            return Err("INV-033 violation: encrypt_at_source must ALWAYS be true".to_string());
        }
        if !self.has_off_host_target() {
            return Err("INV-033 violation: at least one OFF_HOST target is required".to_string());
        }
        if self.targets.is_empty() {
            return Err("at least one target must be specified".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_contract_encrypt_at_source_always_true() {
        let contract = ConstitutionalBackupContract::new(
            "host-1".into(),
            true,
            true,
            vec!["off-host-s3".into()],
        );
        assert!(contract.encrypt_at_source);
    }

    #[test]
    fn validate_rejects_false_encrypt() {
        let mut contract = ConstitutionalBackupContract::new(
            "host-1".into(),
            true,
            true,
            vec!["off-host-s3".into()],
        );
        contract.encrypt_at_source = false;
        assert!(contract.validate().is_err());
    }

    #[test]
    fn validate_rejects_no_off_host_target() {
        let contract =
            ConstitutionalBackupContract::new("host-1".into(), true, true, vec!["self".into()]);
        assert!(contract.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_targets() {
        let contract = ConstitutionalBackupContract::new("host-1".into(), true, true, vec![]);
        assert!(contract.validate().is_err());
    }

    #[test]
    fn has_off_host_target_detects_remote() {
        let contract = ConstitutionalBackupContract::new(
            "host-1".into(),
            true,
            true,
            vec!["s3://bucket".into()],
        );
        assert!(contract.has_off_host_target());
    }

    #[test]
    fn has_off_host_target_rejects_local() {
        let contract =
            ConstitutionalBackupContract::new("host-1".into(), true, true, vec!["local".into()]);
        assert!(!contract.has_off_host_target());
    }

    #[test]
    fn validate_passes_for_valid_contract() {
        let contract = ConstitutionalBackupContract::new(
            "host-1".into(),
            true,
            true,
            vec!["s3://bucket".into(), "nfs://remote".into()],
        );
        assert!(contract.validate().is_ok());
    }
}
