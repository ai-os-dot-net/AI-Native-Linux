//! SBOM / provenance / VEX module for AIOS supply-chain evidence (S16.6).
#![allow(clippy::doc_markdown, clippy::missing_const_for_fn)]

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

// ─────────────────────────────────────────────────────────────────────────────
// Closed enums — every variant SCREAMING_SNAKE_CASE on the wire (S16.6 §4–§8)
// ─────────────────────────────────────────────────────────────────────────────

/// SBOM document format — SPDX 2.3 / 3.0 or CycloneDX 1.5 / 1.6 (S16.6 §4).
///
/// Unknown values are rejected by the normalizer; an artifact with an unknown
/// format is treated as having no valid SBOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(non_camel_case_types)]
pub enum SbomFormat {
    Spdx_2_3,
    Spdx_3_0,
    Cyclonedx_1_5,
    Cyclonedx_1_6,
}

/// SLSA build level — provenance strength ladder (S16.6 §5).
///
/// Level 0 = no provenance; Level 4 = hermetic, fully isolated, non-falsifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SlcaProvenanceLevel {
    Level0,
    Level1,
    Level2,
    Level3,
    Level4,
}

impl SlcaProvenanceLevel {
    #[must_use]
    pub fn is_verifiable(&self) -> bool {
        !matches!(self, Self::Level0)
    }

    #[must_use]
    pub fn meets_floor(&self, floor: Self) -> bool {
        (*self as u8) >= (floor as u8)
    }
}

/// VEX vulnerability status per OpenVEX / CSAF 2.0 mapping (S16.6 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VexStatus {
    Affected,
    NotAffected,
    Fixed,
    UnderInvestigation,
}

/// VEX justification — required when status is `NotAffected` (S16.6 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VexJustification {
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist,
}

/// SBOM relationship direction between components (S16.6 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SbomRelationshipKind {
    DependsOn,
    Contains,
    BuildDependency,
    DevDependency,
    RuntimeDependency,
    GeneratedFrom,
    Describes,
}

/// Reproducible-build outcome (S16.6 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReproStatus {
    BitIdentical,
    NormalizedIdentical,
    NotReproducible,
    NotAttempted,
}

/// Supply-chain evidence record types emitted to the Evidence Log (S16.6 §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupplyChainEvidenceRecordType {
    SbomGenerated,
    ProvenanceAttested,
    VexPublished,
    ReproducibleBuildVerified,
}

// ─────────────────────────────────────────────────────────────────────────────
// SBOM component and document model (S16.6 §4)
// ─────────────────────────────────────────────────────────────────────────────

/// A single component entry inside an SBOM document.
///
/// Every component carries at minimum a name, version, and at least one hash
/// or purl for correlation against vulnerability feeds (S16.6 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub supplier: String,
    pub sha256: String,
    /// SPDX license identifier, e.g. `"MIT"`, `"Apache-2.0"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Package-URL for the component (canonical `pkg:…` string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

impl SbomComponent {
    pub fn new(name: String, version: String, supplier: String, sha256: String) -> Self {
        Self { name, version, supplier, sha256, license: None, purl: None }
    }

    #[must_use]
    pub fn with_license(mut self, license: String) -> Self {
        self.license = Some(license);
        self
    }

    #[must_use]
    pub fn with_purl(mut self, purl: String) -> Self {
        self.purl = Some(purl);
        self
    }

    /// Returns `true` when the component has either a purl or a hash,
    /// satisfying the S16.6 §4 correlatability requirement.
    #[must_use]
    pub fn is_correlatable(&self) -> bool {
        self.purl.is_some() || !self.sha256.is_empty()
    }
}

/// A directed relationship between two SBOM components (S16.6 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomRelationship {
    pub from_bom_ref: String,
    pub to_bom_ref: String,
    pub kind: SbomRelationshipKind,
}

impl SbomRelationship {
    pub fn new(from_bom_ref: String, to_bom_ref: String, kind: SbomRelationshipKind) -> Self {
        Self { from_bom_ref, to_bom_ref, kind }
    }
}

/// Internal AIOS SBOM document — normalised from SPDX or CycloneDX input.
///
/// Every artifact admitted under `STIG_ALIGNED` or `AIRGAP_HIGH` must carry
/// a valid `SbomDocument` whose components are all correlatable (§4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomDocument {
    pub components: Vec<SbomComponent>,
    pub format: SbomFormat,
    /// SBOM specification version string (e.g. `"2.3"`, `"3.0"`, `"1.6"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spdx_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cyclonedx_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<SbomRelationship>,
    /// UNIX epoch seconds at which the SBOM was generated / ingested.
    pub generated_at: u64,
    /// RFC 3339 wall-clock timestamp (optional companion to `generated_at`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_timestamp: Option<DateTime<Utc>>,
    pub signature: Option<Vec<u8>>,
}

impl SbomDocument {
    pub fn new(components: Vec<SbomComponent>, format: SbomFormat, generated_at: u64) -> Self {
        Self {
            components,
            format,
            spdx_version: None,
            cyclonedx_version: None,
            relationships: Vec::new(),
            generated_at,
            creation_timestamp: None,
            signature: None,
        }
    }

    pub fn sign(&mut self, signature: Vec<u8>) { self.signature = Some(signature); }

    pub fn verify_signature(&self, expected: &[u8]) -> bool {
        match &self.signature { Some(sig) => sig == expected, None => false }
    }

    pub fn component_count(&self) -> usize { self.components.len() }

    /// Returns `true` iff every component satisfies the S16.6 §4
    /// correlatability requirement (purl or hash present).
    #[must_use]
    pub fn all_components_correlatable(&self) -> bool {
        self.components.iter().all(SbomComponent::is_correlatable)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SLSA provenance attestation (S16.6 §5)
// ─────────────────────────────────────────────────────────────────────────────

/// SLSA-style, in-toto-shaped provenance attestation.
///
/// Must verify against an S11.1 trust root before any field is trusted.
/// A subject-digest mismatch is a hard reject (digest-confusion attack).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlcaProvenanceAttestation {
    pub builder_id: String,
    pub build_type: String,
    /// Free-form build invocation parameters (command-line, config hash, …).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub invocation_params: String,
    /// Hex-encoded hash of the build materials / inputs.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub materials_hash: String,
    /// Map of artifact path → hex-encoded digest for every subject produced.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub subject_digests: HashMap<String, String>,
    pub slsa_level: SlcaProvenanceLevel,
    /// Base64-encoded signed DSSE / in-toto envelope, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_envelope: Option<String>,
    /// Legacy `SlsaProvenance` fields preserved for backward compatibility.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_repo: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build_command: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub output_hashes: HashMap<String, String>,
}

impl SlcaProvenanceAttestation {
    pub fn new(
        builder_id: String,
        build_type: String,
        slsa_level: SlcaProvenanceLevel,
    ) -> Self {
        Self {
            builder_id,
            build_type,
            invocation_params: String::new(),
            materials_hash: String::new(),
            subject_digests: HashMap::new(),
            slsa_level,
            signed_envelope: None,
            source_repo: String::new(),
            build_command: String::new(),
            output_hashes: HashMap::new(),
        }
    }

    pub fn with_source_repo(mut self, repo: String) -> Self {
        self.source_repo = repo;
        self
    }

    pub fn with_build_command(mut self, cmd: String) -> Self {
        self.build_command = cmd;
        self
    }

    pub fn add_subject_digest(&mut self, artifact_path: String, digest: String) {
        self.subject_digests.insert(artifact_path, digest);
    }

    pub fn add_output_hash(&mut self, filename: String, hash: String) {
        self.output_hashes.insert(filename, hash);
    }

    #[must_use]
    pub fn verify_builder(&self, expected_builder: &str) -> bool {
        self.builder_id == expected_builder
    }

    #[must_use]
    pub fn verify_output(&self, filename: &str, expected_hash: &str) -> bool {
        self.output_hashes
            .get(filename)
            .map_or(false, |h| h == expected_hash)
    }

    /// Verifies that a subject digest matches; returns `false` when the
    /// artifact is missing from the attestation (digest-confusion defense).
    #[must_use]
    pub fn verify_subject_digest(&self, artifact_path: &str, expected_digest: &str) -> bool {
        self.subject_digests
            .get(artifact_path)
            .map_or(false, |d| d == expected_digest)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy SlsaProvenance (preserved for backward compatibility)
// ─────────────────────────────────────────────────────────────────────────────

/// Retained for existing callers; new code should use
/// [`SlcaProvenanceAttestation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlsaProvenance {
    pub builder_id: String,
    pub source_repo: String,
    pub build_command: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub output_hashes: HashMap<String, String>,
}

impl SlsaProvenance {
    pub fn new(builder_id: String, source_repo: String, build_command: String) -> Self {
        Self { builder_id, source_repo, build_command, output_hashes: HashMap::new() }
    }

    pub fn add_output_hash(&mut self, filename: String, hash: String) {
        self.output_hashes.insert(filename, hash);
    }

    #[must_use]
    pub fn verify_builder(&self, expected_builder: &str) -> bool {
        self.builder_id == expected_builder
    }

    #[must_use]
    pub fn verify_output(&self, filename: &str, expected_hash: &str) -> bool {
        self.output_hashes.get(filename).map_or(false, |h| h == expected_hash)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VEX statement (S16.6 §6)
// ─────────────────────────────────────────────────────────────────────────────

/// Single signed VEX statement declaring the impact of one vulnerability on
/// one artifact (S16.6 §6).
///
/// Conditional-field enforcement:
/// - `NotAffected` → justification REQUIRED
/// - `Affected` → action_statement RECOMMENDED
/// - `UnderInvestigation` → no gating relief granted
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VexStatement {
    /// CVE / GHSA / AIOS-VULN identifier.
    pub vulnerability_id: String,
    /// The affected component name (bom_ref from the SBOM).
    pub component_name: String,
    pub status: VexStatus,
    pub justification: String,
    /// Product identifier (package URL or canonical name).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub product_id: String,
    /// RFC 3339 timestamp of statement issuance / last update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    /// Human-readable action statement (required when status is `Affected`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_statement: Option<String>,
}

impl VexStatement {
    pub fn new(
        vuln_id: String,
        component: String,
        status: VexStatus,
        justification: String,
    ) -> Self {
        Self {
            vulnerability_id: vuln_id,
            component_name: component,
            status,
            justification,
            product_id: String::new(),
            timestamp: None,
            action_statement: None,
        }
    }

    #[must_use]
    pub fn is_fixed(&self) -> bool { self.status == VexStatus::Fixed }

    #[must_use]
    pub fn is_affected(&self) -> bool { self.status == VexStatus::Affected }

    /// Returns `true` when the VEX statement *may* relieve a CVE for gating:
    /// `NotAffected` with a non-empty justification, or `Fixed`.
    #[must_use]
    pub fn relieves_cve(&self) -> bool {
        match self.status {
            VexStatus::NotAffected => !self.justification.is_empty(),
            VexStatus::Fixed => true,
            VexStatus::Affected | VexStatus::UnderInvestigation => false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reproducible build receipt (S16.6 §7)
// ─────────────────────────────────────────────────────────────────────────────

/// Records an independent rebuild and its bit-for-bit comparison result.
///
/// This is the strongest available evidence that the shipped binary matches
/// the attested source (S16.6 §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproducibleBuildReceipt {
    /// Hex-encoded hash of all build inputs (toolchain, base image, …).
    pub build_inputs_hash: String,
    /// Hex-encoded hash of the build output artifact.
    pub build_output_hash: String,
    /// `true` when an independent rebuild produced a bit-identical artifact.
    pub reproducibility_verified: bool,
    /// Rebuild outcome status (S16.6 §7 closed enum).
    pub repro_status: ReproStatus,
    /// Rebuilder identifier (e.g. `"aios-rebuilder"`, `"third-party-ref"`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rebuilder_id: String,
    /// RFC 3339 timestamp of the rebuild.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuilt_at: Option<DateTime<Utc>>,
}

impl ReproducibleBuildReceipt {
    pub fn new(
        build_inputs_hash: String,
        build_output_hash: String,
        repro_status: ReproStatus,
    ) -> Self {
        Self {
            build_inputs_hash,
            build_output_hash,
            reproducibility_verified: matches!(
                repro_status,
                ReproStatus::BitIdentical | ReproStatus::NormalizedIdentical
            ),
            repro_status,
            rebuilder_id: String::new(),
            rebuilt_at: None,
        }
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.reproducibility_verified
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SBOM Generator facade (S16.6 §4–§8 orchestration)
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level orchestrator for SBOM, provenance, and VEX generation.
///
/// The generator constructs typed supply-chain evidence documents;
/// it does **not** write to the Evidence Log — the caller feeds the
/// resulting documents to the [`crate::EvidenceEmitter`].
#[derive(Debug, Clone)]
pub struct SbomGenerator {
    builder_id: String,
}

impl SbomGenerator {
    pub fn new(builder_id: String) -> Self {
        Self { builder_id }
    }

    /// Generate an SBOM document from a list of components.
    ///
    /// Returns `None` when the component list is empty (no meaningful SBOM).
    #[must_use]
    pub fn generate_sbom(
        &self,
        components: Vec<SbomComponent>,
        format: SbomFormat,
    ) -> Option<SbomDocument> {
        if components.is_empty() {
            return None;
        }
        let now = current_epoch_secs();
        let mut doc = SbomDocument::new(components, format, now);
        doc.creation_timestamp = Some(Utc::now());
        Some(doc)
    }

    /// Generate a SLSA provenance attestation for a given build.
    #[must_use]
    pub fn generate_provenance(
        &self,
        build_type: String,
        slsa_level: SlcaProvenanceLevel,
    ) -> SlcaProvenanceAttestation {
        SlcaProvenanceAttestation::new(self.builder_id.clone(), build_type, slsa_level)
    }

    /// Generate a VEX statement for a single vulnerability.
    ///
    /// Returns `None` when the vulnerability ID is empty (S16.6 §6 requires
    /// a non-empty CVE/GHSA identifier).
    #[must_use]
    pub fn generate_vex(
        &self,
        vulnerability_id: String,
        component_name: String,
        status: VexStatus,
        justification: String,
    ) -> Option<VexStatement> {
        if vulnerability_id.is_empty() {
            return None;
        }
        let mut stmt = VexStatement::new(vulnerability_id, component_name, status, justification);
        stmt.timestamp = Some(Utc::now());
        Some(stmt)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn current_epoch_secs() -> u64 {
    #[allow(clippy::cast_sign_loss)]
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use strum::EnumCount;

    // ── retained tests from the original module ──

    #[test] fn sbom_generation() {
        let components = vec![
            SbomComponent::new("libc".into(), "2.35".into(), "GNU".into(), "abc123".into()),
        ];
        let doc = SbomDocument::new(components, SbomFormat::Spdx_2_3, 1000);
        assert_eq!(doc.component_count(), 1);
        assert_eq!(doc.format, SbomFormat::Spdx_2_3);
    }

    #[test] fn sbom_signature_verification() {
        let mut doc = SbomDocument::new(vec![], SbomFormat::Cyclonedx_1_6, 1000);
        assert!(!doc.verify_signature(b"sig"));
        doc.sign(b"sig".to_vec());
        assert!(doc.verify_signature(b"sig"));
        assert!(!doc.verify_signature(b"wrong"));
    }

    #[test] fn slsa_builder_verification() {
        let provenance =
            SlsaProvenance::new("github-actions".into(), "repo".into(), "make".into());
        assert!(provenance.verify_builder("github-actions"));
        assert!(!provenance.verify_builder("other"));
    }

    #[test] fn slsa_output_hash_verification() {
        let mut p = SlsaProvenance::new("b".into(), "r".into(), "c".into());
        p.add_output_hash("binary".into(), "hash123".into());
        assert!(p.verify_output("binary", "hash123"));
        assert!(!p.verify_output("binary", "wrong"));
        assert!(!p.verify_output("missing", "hash"));
    }

    #[test] fn vex_status_detection() {
        let fixed = VexStatement::new(
            "CVE-2024-0001".into(),
            "libc".into(),
            VexStatus::Fixed,
            "patched".into(),
        );
        assert!(fixed.is_fixed());
        let affected = VexStatement::new(
            "CVE-2024-0002".into(),
            "openssl".into(),
            VexStatus::Affected,
            "pending".into(),
        );
        assert!(!affected.is_fixed());
    }

    #[test] fn sbom_multiple_components() {
        let comps: Vec<_> = (0..3)
            .map(|i| {
                SbomComponent::new(
                    format!("pkg{i}"),
                    "1.0".into(),
                    "test".into(),
                    "h".into(),
                )
            })
            .collect();
        let doc = SbomDocument::new(comps, SbomFormat::Spdx_2_3, 1000);
        assert_eq!(doc.component_count(), 3);
    }

    #[test] fn sbom_format_enum() {
        assert_ne!(SbomFormat::Spdx_2_3, SbomFormat::Cyclonedx_1_6);
    }

    // ── new tests — S16.6 coverage ──

    #[test]
    fn sbom_format_count() {
        assert_eq!(SbomFormat::COUNT, 4);
    }

    #[test]
    fn slca_level_count_and_floor() {
        assert_eq!(SlcaProvenanceLevel::COUNT, 5);
        assert!(SlcaProvenanceLevel::Level3.meets_floor(SlcaProvenanceLevel::Level2));
        assert!(!SlcaProvenanceLevel::Level1.meets_floor(SlcaProvenanceLevel::Level2));
        assert!(!SlcaProvenanceLevel::Level0.is_verifiable());
        assert!(SlcaProvenanceLevel::Level2.is_verifiable());
    }

    #[test]
    fn sbom_component_correlatability() {
        let with_hash = SbomComponent::new("a".into(), "1".into(), "s".into(), "sha".into());
        assert!(with_hash.is_correlatable());

        let with_purl = SbomComponent::new("a".into(), "1".into(), "s".into(), String::new())
            .with_purl("pkg:generic/a@1".into());
        assert!(with_purl.is_correlatable());

        let uncorrelated =
            SbomComponent::new("a".into(), "1".into(), "s".into(), String::new());
        assert!(!uncorrelated.is_correlatable());
    }

    #[test]
    fn sbom_document_correlatability_check() {
        let comps = vec![
            SbomComponent::new("a".into(), "1".into(), "s".into(), "sha".into()),
            SbomComponent::new("b".into(), "1".into(), "s".into(), String::new())
                .with_purl("pkg:generic/b@1".into()),
        ];
        let doc = SbomDocument::new(comps, SbomFormat::Spdx_3_0, 1000);
        assert!(doc.all_components_correlatable());
    }

    #[test]
    fn sbom_document_fails_correlatability() {
        let comps = vec![
            SbomComponent::new("a".into(), "1".into(), "s".into(), "sha".into()),
            SbomComponent::new("b".into(), "1".into(), "s".into(), String::new()),
        ];
        let doc = SbomDocument::new(comps, SbomFormat::Spdx_3_0, 1000);
        assert!(!doc.all_components_correlatable());
    }

    #[test]
    fn slca_provenance_attestation_new() {
        let att =
            SlcaProvenanceAttestation::new("gh".into(), "hermetic".into(), SlcaProvenanceLevel::Level3);
        assert!(att.verify_builder("gh"));
        assert!(!att.verify_builder("other"));
    }

    #[test]
    fn slca_provenance_attestation_subject_digest() {
        let mut att =
            SlcaProvenanceAttestation::new("gh".into(), "hermetic".into(), SlcaProvenanceLevel::Level3);
        att.add_subject_digest("binary".into(), "abc123".into());
        assert!(att.verify_subject_digest("binary", "abc123"));
        assert!(!att.verify_subject_digest("binary", "wrong"));
        assert!(!att.verify_subject_digest("missing", "abc123"));
    }

    #[test]
    fn vex_relieves_cve_requires_justification() {
        let stmt = VexStatement::new(
            "CVE-2026-X".into(),
            "lib".into(),
            VexStatus::NotAffected,
            "code not present".into(),
        );
        assert!(stmt.relieves_cve());

        let no_just = VexStatement::new(
            "CVE-2026-Y".into(),
            "lib".into(),
            VexStatus::NotAffected,
            String::new(),
        );
        assert!(!no_just.relieves_cve());
    }

    #[test]
    fn vex_under_investigation_does_not_relieve() {
        let stmt = VexStatement::new(
            "CVE-2026-Z".into(),
            "lib".into(),
            VexStatus::UnderInvestigation,
            String::new(),
        );
        assert!(!stmt.relieves_cve());
        assert!(!stmt.is_fixed());
    }

    #[test]
    fn repro_build_receipt_verified() {
        let receipt = ReproducibleBuildReceipt::new(
            "input_hash".into(),
            "output_hash".into(),
            ReproStatus::BitIdentical,
        );
        assert!(receipt.is_verified());
    }

    #[test]
    fn repro_build_receipt_not_reproducible() {
        let receipt = ReproducibleBuildReceipt::new(
            "input_hash".into(),
            "output_hash".into(),
            ReproStatus::NotReproducible,
        );
        assert!(!receipt.is_verified());
    }

    #[test]
    fn sbom_generator_produces_valid_documents() {
        let gen = SbomGenerator::new("aios-builder".into());

        let comps = vec![
            SbomComponent::new("my-app".into(), "1.0".into(), "org".into(), "aaa".into()),
        ];
        let sbom = gen
            .generate_sbom(comps, SbomFormat::Cyclonedx_1_5)
            .expect("non-empty component list must produce an SBOM");
        assert_eq!(sbom.component_count(), 1);
        assert_eq!(sbom.format, SbomFormat::Cyclonedx_1_5);

        let provenance = gen.generate_provenance("hermetic-v1".into(), SlcaProvenanceLevel::Level3);
        assert_eq!(provenance.slsa_level, SlcaProvenanceLevel::Level3);
        assert_eq!(provenance.builder_id, "aios-builder");

        let vex = gen
            .generate_vex(
                "CVE-2026-0001".into(),
                "my-app".into(),
                VexStatus::Fixed,
                "patched in v2".into(),
            )
            .expect("valid vuln id must produce a VEX statement");
        assert!(vex.relieves_cve());

        let empty_vex = gen.generate_vex(
            String::new(),
            "app".into(),
            VexStatus::Fixed,
            String::new(),
        );
        assert!(empty_vex.is_none());
    }

    #[test]
    fn sbom_component_with_license_and_purl() {
        let comp = SbomComponent::new("pkg".into(), "1.0".into(), "org".into(), "h".into())
            .with_license("MIT".into())
            .with_purl("pkg:generic/pkg@1.0".into());
        assert_eq!(comp.license.as_deref(), Some("MIT"));
        assert_eq!(comp.purl.as_deref(), Some("pkg:generic/pkg@1.0"));
    }

    #[test]
    fn sbom_relationship_enum_and_struct() {
        let rel = SbomRelationship::new(
            "comp-0".into(),
            "comp-1".into(),
            SbomRelationshipKind::DependsOn,
        );
        assert_eq!(rel.from_bom_ref, "comp-0");
        assert_eq!(rel.to_bom_ref, "comp-1");
        assert_eq!(rel.kind, SbomRelationshipKind::DependsOn);
    }

    #[test]
    fn evidence_record_types_count() {
        assert_eq!(SupplyChainEvidenceRecordType::COUNT, 4);
    }

    #[test]
    fn sbom_document_serialization_roundtrip() {
        let mut doc = SbomDocument::new(
            vec![SbomComponent::new(
                "p".into(),
                "1".into(),
                "s".into(),
                "h".into(),
            )],
            SbomFormat::Spdx_3_0,
            1700000000,
        );
        doc.relationships.push(SbomRelationship::new(
            "c0".into(),
            "c1".into(),
            SbomRelationshipKind::RuntimeDependency,
        ));

        let json = serde_json::to_string(&doc).expect("serialize");
        let back: SbomDocument = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.components.len(), 1);
        assert_eq!(back.format, SbomFormat::Spdx_3_0);
        assert_eq!(back.component_count(), 1);
    }

    #[test]
    fn slca_attestation_serialization_roundtrip() {
        let mut att =
            SlcaProvenanceAttestation::new("b".into(), "t".into(), SlcaProvenanceLevel::Level2);
        att.add_subject_digest("bin".into(), "dd".into());
        att.add_output_hash("bin".into(), "dd".into());

        let json = serde_json::to_string(&att).expect("serialize");
        let back: SlcaProvenanceAttestation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.slsa_level, SlcaProvenanceLevel::Level2);
        assert!(back.verify_subject_digest("bin", "dd"));
    }

    #[test]
    fn vex_statement_serialization_roundtrip() {
        let stmt = VexStatement::new(
            "CVE-2026-A".into(),
            "c".into(),
            VexStatus::NotAffected,
            "not present".into(),
        );
        let json = serde_json::to_string(&stmt).expect("serialize");
        let back: VexStatement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.vulnerability_id, "CVE-2026-A");
        assert_eq!(back.status, VexStatus::NotAffected);
    }

    #[test]
    fn repro_receipt_serialization_roundtrip() {
        let receipt = ReproducibleBuildReceipt::new(
            "in".into(),
            "out".into(),
            ReproStatus::NormalizedIdentical,
        );
        let json = serde_json::to_string(&receipt).expect("serialize");
        let back: ReproducibleBuildReceipt = serde_json::from_str(&json).expect("deserialize");
        assert!(back.is_verified());
        assert_eq!(back.repro_status, ReproStatus::NormalizedIdentical);
    }
}
