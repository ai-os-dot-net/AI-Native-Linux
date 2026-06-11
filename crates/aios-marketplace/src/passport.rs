use chrono::{DateTime, Utc};
use ulid::Ulid;

/// An app passport — the operator-facing bundle of trust, provenance, and
/// compatibility metadata for a single marketplace capsule (S27 §11).
#[derive(Debug, Clone)]
pub struct AppPassport {
    /// Unique passport identifier (`pass_` + ULID).
    pub passport_id: String,
    /// The capsule (app/package) this passport describes.
    pub capsule_id: String,
    /// Ed25519 signature from the publisher over the passport canonical bytes.
    pub publisher_signature: Option<Vec<u8>>,
    /// Blake3 digest of the capability manifest.
    pub capability_manifest_hash: String,
    /// Reference to the SBOM (Software Bill of Materials).
    pub sbom_ref: Option<String>,
    /// Reference to the in-toto / SLSA provenance attestation.
    pub provenance_ref: Option<String>,
    /// Whether the capsule is compatible with the active security profile.
    pub security_profile_compatible: bool,
    /// Required runtime environment identifiers (e.g. ["linux-native", "flatpak"]).
    pub runtime_requirements: Vec<String>,
    /// SLSA provenance level (0–4).
    pub slsa_level: u8,
    /// When the passport was issued.
    pub published_at: DateTime<Utc>,
    /// Signed envelope bytes (opaque for downstream verification).
    pub signed_envelope: Option<Vec<u8>>,
}

impl AppPassport {
    #[must_use]
    pub fn new(
        capsule_id: impl Into<String>,
        capability_manifest_hash: impl Into<String>,
        slsa_level: u8,
    ) -> Self {
        Self {
            passport_id: format!("pass_{}", Ulid::new()),
            capsule_id: capsule_id.into(),
            publisher_signature: None,
            capability_manifest_hash: capability_manifest_hash.into(),
            sbom_ref: None,
            provenance_ref: None,
            security_profile_compatible: false,
            runtime_requirements: Vec::new(),
            slsa_level,
            published_at: Utc::now(),
            signed_envelope: None,
        }
    }

    pub fn set_publisher_signature(&mut self, signature: Vec<u8>) {
        self.publisher_signature = Some(signature);
    }

    pub fn set_sbom_ref(&mut self, sbom_ref: impl Into<String>) {
        self.sbom_ref = Some(sbom_ref.into());
    }

    pub fn set_provenance_ref(&mut self, provenance_ref: impl Into<String>) {
        self.provenance_ref = Some(provenance_ref.into());
    }

    pub fn set_security_compatible(&mut self, compatible: bool) {
        self.security_profile_compatible = compatible;
    }

    pub fn add_runtime_requirement(&mut self, runtime: impl Into<String>) {
        let r = runtime.into();
        if !self.runtime_requirements.contains(&r) {
            self.runtime_requirements.push(r);
        }
    }

    pub fn seal(&mut self, envelope: Vec<u8>) {
        self.signed_envelope = Some(envelope);
    }

    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.signed_envelope.is_some()
    }

    #[must_use]
    pub fn is_signed_by_publisher(&self) -> bool {
        self.publisher_signature.is_some()
    }

    #[must_use]
    pub fn has_provenance_link(&self) -> bool {
        self.sbom_ref.is_some() && self.provenance_ref.is_some()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn new_passport_has_correct_defaults() {
        let p = AppPassport::new("capsule-1", "deadbeef", 3);
        assert!(p.passport_id.starts_with("pass_"));
        assert_eq!(p.capsule_id, "capsule-1");
        assert_eq!(p.capability_manifest_hash, "deadbeef");
        assert_eq!(p.slsa_level, 3);
        assert!(!p.is_sealed());
        assert!(!p.is_signed_by_publisher());
        assert!(!p.has_provenance_link());
        assert!(!p.security_profile_compatible);
    }

    #[test]
    fn set_publisher_signature_updates_flag() {
        let mut p = AppPassport::new("c1", "hash1", 2);
        p.set_publisher_signature(vec![1, 2, 3]);
        assert!(p.is_signed_by_publisher());
    }

    #[test]
    fn seal_updates_flag() {
        let mut p = AppPassport::new("c1", "hash1", 2);
        p.seal(vec![4, 5, 6]);
        assert!(p.is_sealed());
    }

    #[test]
    fn provenance_link_detected_when_both_set() {
        let mut p = AppPassport::new("c1", "hash1", 2);
        assert!(!p.has_provenance_link());
        p.set_sbom_ref("sbom:xyz");
        assert!(!p.has_provenance_link());
        p.set_provenance_ref("prov:xyz");
        assert!(p.has_provenance_link());
    }

    #[test]
    fn add_runtime_requirement_deduplicates() {
        let mut p = AppPassport::new("c1", "h", 2);
        p.add_runtime_requirement("linux-native");
        p.add_runtime_requirement("linux-native");
        assert_eq!(p.runtime_requirements.len(), 1);
    }

    #[test]
    fn security_compatible_flag_toggle() {
        let mut p = AppPassport::new("c1", "h", 2);
        assert!(!p.security_profile_compatible);
        p.set_security_compatible(true);
        assert!(p.security_profile_compatible);
    }

    #[test]
    fn slsa_level_clamped_to_storage() {
        let p = AppPassport::new("c1", "h", 0);
        assert_eq!(p.slsa_level, 0);
        let p = AppPassport::new("c1", "h", 4);
        assert_eq!(p.slsa_level, 4);
    }
}
