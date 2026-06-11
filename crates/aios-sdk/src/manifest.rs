//! Capability manifest types — the signed declaration every capsule ships.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::enums::CapabilityDeclarationFormat;

/// A serialisable error type for manifest validation failures.
///
/// Produced by [`ManifestValidator`] methods; never panics on invalid input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestValidationError {
    /// A required field is missing or empty.
    MissingField(String),
    /// The manifest signature is invalid or missing.
    InvalidSignature(String),
    /// Required capabilities are absent from the declaration.
    MissingCapabilities(Vec<String>),
    /// Evidence categories declared do not match observed evidence.
    EvidenceMismatch {
        /// Categories that were declared but not observed.
        missing: Vec<String>,
        /// Categories that were observed but not declared.
        undeclared: Vec<String>,
    },
}

/// A structured, typed action declaration within a capability manifest.
///
/// Each entry maps a named action to the evidence record types the capsule
/// promises to emit when that action is executed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedActionDeclaration {
    /// The action name (e.g. `"service.restart"`).
    pub action_name: String,
    /// Human-readable description.
    pub description: String,
    /// Evidence record type identifiers this action emits.
    pub evidence_record_types: Vec<String>,
}

/// An evidence record declaration — the capsule promises to emit these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecordDeclaration {
    /// The evidence category (e.g. `"action_completed"`, `"audit_log"`).
    pub category: String,
    /// Schema version for this record type.
    pub schema_version: String,
    /// Human-readable description.
    pub description: String,
}

/// Runtime requirement entry — what the capsule needs to execute.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRequirement {
    /// Requirement name (e.g. `"gpu"`, `"network:outbound"`).
    pub name: String,
    /// Minimum version or constraint string.
    pub version_constraint: Option<String>,
    /// Whether this requirement is mandatory.
    pub required: bool,
}

/// The capability manifest — the signed declaration every capsule ships.
///
/// This is the AIOS equivalent of a Flatpak manifest or AndroidManifest.xml:
/// it declares what the capsule does, what evidence it emits, what it needs
/// to run, and who signed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    /// Unique manifest identifier (ULID-formatted).
    pub manifest_id: String,
    /// Human-readable capsule name.
    pub name: String,
    /// Semver version string.
    pub version: String,
    /// Publisher identifier (e.g. `"publisher:neurocad"`).
    pub publisher_id: String,
    /// Action names this capsule can perform.
    pub capabilities: Vec<String>,
    /// Reference to a sandbox profile definition.
    pub sandbox_profile_ref: Option<String>,
    /// Evidence categories the capsule promises to emit.
    pub evidence_categories: Vec<String>,
    /// Runtime requirements for capsule execution.
    pub runtime_requirements: Vec<RuntimeRequirement>,
    /// Typed action declarations with evidence linkage.
    pub declared_typed_actions: Vec<TypedActionDeclaration>,
    /// Evidence record declarations.
    pub declared_evidence_records: Vec<EvidenceRecordDeclaration>,
    /// Ed25519 signature over the canonical manifest content.
    pub signature: Option<Vec<u8>>,
    /// When the manifest was created or last updated.
    pub updated_at: DateTime<Utc>,
    /// The manifest file format this was parsed from / will be written to.
    pub format: CapabilityDeclarationFormat,
}

/// Validates a [`CapabilityManifest`] for structural correctness and completeness.
#[derive(Clone, Debug, Default)]
pub struct ManifestValidator;

impl ManifestValidator {
    /// Create a new validator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Validate the structural integrity of a manifest.
    ///
    /// Checks: name non-empty, version present, publisher_id non-empty,
    /// at least one capability declared, evidence_categories non-empty.
    ///
    /// Returns `Ok(())` when all checks pass; otherwise returns the first
    /// encountered error.
    pub fn validate(&self, manifest: &CapabilityManifest) -> Result<(), ManifestValidationError> {
        if manifest.name.is_empty() {
            return Err(ManifestValidationError::MissingField("name".into()));
        }
        if manifest.version.is_empty() {
            return Err(ManifestValidationError::MissingField("version".into()));
        }
        if manifest.publisher_id.is_empty() {
            return Err(ManifestValidationError::MissingField("publisher_id".into()));
        }
        if manifest.capabilities.is_empty() {
            return Err(ManifestValidationError::MissingCapabilities(vec![
                "no capabilities declared".into(),
            ]));
        }
        if manifest.evidence_categories.is_empty() {
            return Err(ManifestValidationError::MissingField(
                "evidence_categories".into(),
            ));
        }
        Ok(())
    }

    /// Check that every declared evidence category has a matching record declaration.
    ///
    /// Returns a list of categories that are declared in `evidence_categories`
    /// but have no corresponding entry in `declared_evidence_records`.
    #[must_use]
    pub fn check_completeness(&self, manifest: &CapabilityManifest) -> Vec<String> {
        let declared: std::collections::HashSet<&str> = manifest
            .declared_evidence_records
            .iter()
            .map(|r| r.category.as_str())
            .collect();
        manifest
            .evidence_categories
            .iter()
            .filter(|cat| !declared.contains(cat.as_str()))
            .cloned()
            .collect()
    }

    /// Detect evidence categories that should be present based on declared
    /// typed actions but are missing from the evidence_categories list.
    #[must_use]
    pub fn detect_missing_evidence(&self, manifest: &CapabilityManifest) -> Vec<String> {
        let declared_categories: std::collections::HashSet<&str> = manifest
            .evidence_categories
            .iter()
            .map(String::as_str)
            .collect();

        let mut missing = Vec::new();
        for action in &manifest.declared_typed_actions {
            for record_type in &action.evidence_record_types {
                if !declared_categories.contains(record_type.as_str()) {
                    missing.push(format!(
                        "action {action} references evidence record {record_type} not in categories",
                        action = action.action_name,
                        record_type = record_type,
                    ));
                }
            }
        }
        missing
    }

    /// Check whether the manifest has a valid signature.
    ///
    /// Returns `true` when `signature` is `Some` and non-empty.
    /// Full Ed25519 verification requires the publisher's public key
    /// and canonical content bytes — performed by [`crate::publish::PublishPipeline`].
    #[must_use]
    pub fn has_signature(&self, manifest: &CapabilityManifest) -> bool {
        manifest
            .signature
            .as_ref()
            .is_some_and(|sig| !sig.is_empty())
    }
}

/// Generates a [`CapabilityManifest`] from a template or defaults.
#[derive(Clone, Debug, Default)]
pub struct ManifestGenerator;

impl ManifestGenerator {
    /// Create a new manifest generator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Generate a bare minimum manifest from a set of template parameters.
    ///
    /// The generated manifest passes [`ManifestValidator::validate`] when
    /// the required fields are non-empty and at least one capability is provided.
    ///
    /// Returns `Err` when the inputs are structurally invalid (e.g. empty name).
    pub fn generate_from_template(
        &self,
        name: &str,
        version: &str,
        publisher_id: &str,
        capabilities: Vec<String>,
        evidence_categories: Vec<String>,
        format: CapabilityDeclarationFormat,
    ) -> Result<CapabilityManifest, ManifestValidationError> {
        if name.is_empty() {
            return Err(ManifestValidationError::MissingField("name".into()));
        }
        if version.is_empty() {
            return Err(ManifestValidationError::MissingField("version".into()));
        }
        if publisher_id.is_empty() {
            return Err(ManifestValidationError::MissingField("publisher_id".into()));
        }
        if capabilities.is_empty() {
            return Err(ManifestValidationError::MissingCapabilities(vec![
                "at least one capability required".into(),
            ]));
        }

        let manifest_id = ulid::Ulid::new().to_string().to_lowercase();

        let declared_evidence_records: Vec<EvidenceRecordDeclaration> = evidence_categories
            .iter()
            .map(|cat| EvidenceRecordDeclaration {
                category: cat.clone(),
                schema_version: "v1alpha1".into(),
                description: format!("Evidence record for category {cat}"),
            })
            .collect();

        Ok(CapabilityManifest {
            manifest_id,
            name: name.to_owned(),
            version: version.to_owned(),
            publisher_id: publisher_id.to_owned(),
            capabilities,
            sandbox_profile_ref: None,
            evidence_categories,
            runtime_requirements: Vec::new(),
            declared_typed_actions: Vec::new(),
            declared_evidence_records,
            signature: None,
            updated_at: Utc::now(),
            format,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    fn make_valid_manifest() -> CapabilityManifest {
        ManifestGenerator::new()
            .generate_from_template(
                "test-capsule",
                "1.0.0",
                "publisher:test",
                vec!["service.restart".into(), "fs.write".into()],
                vec!["action_completed".into(), "audit_log".into()],
                CapabilityDeclarationFormat::JsonManifest,
            )
            .expect("template generation should succeed")
    }

    #[test]
    fn manifest_generator_produces_valid_manifest() {
        let manifest = make_valid_manifest();
        let validator = ManifestValidator::new();
        validator
            .validate(&manifest)
            .expect("generated manifest must pass validation");
        assert!(!manifest.manifest_id.is_empty());
        assert_eq!(manifest.name, "test-capsule");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.capabilities.len(), 2);
        assert_eq!(manifest.evidence_categories.len(), 2);
    }

    #[test]
    fn manifest_generator_rejects_empty_name() {
        let result = ManifestGenerator::new().generate_from_template(
            "",
            "1.0.0",
            "publisher:test",
            vec!["service.restart".into()],
            vec!["audit".into()],
            CapabilityDeclarationFormat::JsonManifest,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            ManifestValidationError::MissingField(field) => assert_eq!(field, "name"),
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[test]
    fn manifest_generator_rejects_empty_capabilities() {
        let result = ManifestGenerator::new().generate_from_template(
            "test",
            "1.0.0",
            "publisher:test",
            vec![],
            vec!["audit".into()],
            CapabilityDeclarationFormat::JsonManifest,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            ManifestValidationError::MissingCapabilities(_) => {}
            other => panic!("expected MissingCapabilities, got {other:?}"),
        }
    }

    #[test]
    fn manifest_validator_rejects_empty_name() {
        let mut manifest = make_valid_manifest();
        manifest.name.clear();
        let err = ManifestValidator::new()
            .validate(&manifest)
            .expect_err("empty name should fail");
        assert!(matches!(err, ManifestValidationError::MissingField(ref f) if f == "name"));
    }

    #[test]
    fn manifest_validator_rejects_empty_publisher_id() {
        let mut manifest = make_valid_manifest();
        manifest.publisher_id.clear();
        let err = ManifestValidator::new()
            .validate(&manifest)
            .expect_err("empty publisher_id should fail");
        assert!(
            matches!(err, ManifestValidationError::MissingField(ref f) if f == "publisher_id")
        );
    }

    #[test]
    fn manifest_validator_rejects_empty_capabilities() {
        let mut manifest = make_valid_manifest();
        manifest.capabilities.clear();
        let err = ManifestValidator::new()
            .validate(&manifest)
            .expect_err("empty capabilities should fail");
        assert!(matches!(err, ManifestValidationError::MissingCapabilities(_)));
    }

    #[test]
    fn manifest_validator_rejects_empty_evidence_categories() {
        let mut manifest = make_valid_manifest();
        manifest.evidence_categories.clear();
        let err = ManifestValidator::new()
            .validate(&manifest)
            .expect_err("empty evidence categories should fail");
        assert!(
            matches!(err, ManifestValidationError::MissingField(ref f) if f == "evidence_categories")
        );
    }

    #[test]
    fn check_completeness_reports_missing_evidence_records() {
        let mut manifest = make_valid_manifest();
        manifest.declared_evidence_records.clear();
        let missing = ManifestValidator::new().check_completeness(&manifest);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"action_completed".to_owned()));
        assert!(missing.contains(&"audit_log".to_owned()));
    }

    #[test]
    fn check_completeness_returns_empty_when_all_categories_covered() {
        let manifest = make_valid_manifest();
        let missing = ManifestValidator::new().check_completeness(&manifest);
        assert!(
            missing.is_empty(),
            "all evidence categories should be covered, got {missing:?}"
        );
    }

    #[test]
    fn detect_missing_evidence_finds_undeclared_records() {
        let mut manifest = make_valid_manifest();
        manifest.declared_typed_actions = vec![TypedActionDeclaration {
            action_name: "service.restart".into(),
            description: "Restarts a service".into(),
            evidence_record_types: vec!["undeclared_category".into()],
        }];
        let missing = ManifestValidator::new().detect_missing_evidence(&manifest);
        assert!(!missing.is_empty());
        assert!(missing.iter().any(|m| m.contains("undeclared_category")));
    }

    #[test]
    fn detect_missing_evidence_returns_empty_when_consistent() {
        let mut manifest = make_valid_manifest();
        manifest.declared_typed_actions = vec![TypedActionDeclaration {
            action_name: "service.restart".into(),
            description: "Restarts a service".into(),
            evidence_record_types: vec!["action_completed".into()],
        }];
        let missing = ManifestValidator::new().detect_missing_evidence(&manifest);
        assert!(missing.is_empty());
    }

    #[test]
    fn has_signature_returns_false_when_no_signature() {
        let manifest = make_valid_manifest();
        assert!(!ManifestValidator::new().has_signature(&manifest));
    }

    #[test]
    fn has_signature_returns_true_when_signature_present() {
        let mut manifest = make_valid_manifest();
        manifest.signature = Some(vec![1, 2, 3, 4]);
        assert!(ManifestValidator::new().has_signature(&manifest));
    }

    #[test]
    fn has_signature_returns_false_when_signature_is_empty_vec() {
        let mut manifest = make_valid_manifest();
        manifest.signature = Some(Vec::new());
        assert!(!ManifestValidator::new().has_signature(&manifest));
    }

    #[test]
    fn capability_manifest_serde_round_trips() {
        let manifest = make_valid_manifest();
        let json = serde_json::to_string_pretty(&manifest).expect("serialize");
        let parsed: CapabilityManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(manifest.manifest_id, parsed.manifest_id);
        assert_eq!(manifest.name, parsed.name);
        assert_eq!(manifest.capabilities, parsed.capabilities);
    }

    #[test]
    fn runtime_requirement_serde_round_trips() {
        let req = RuntimeRequirement {
            name: "gpu".into(),
            version_constraint: Some(">=2.0".into()),
            required: true,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let parsed: RuntimeRequirement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req, parsed);
    }
}
