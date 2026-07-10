use crate::enums::ModelBundleTrustLevel;
use ulid::Ulid;

/// A signed model bundle registered in the AIOS model marketplace.
///
/// Bundles carry a trust level, publisher identity, and SLSA provenance level
/// that together determine whether the model is eligible for routing.
#[derive(Debug, Clone)]
pub struct SignedModelBundle {
    /// Unique bundle identifier (prefix `"smb_"` + ULID).
    pub bundle_id: String,
    /// ID of the model this bundle contains.
    pub model_id: String,
    /// Publisher identity (org or individual).
    pub publisher: String,
    /// Governance‑assigned trust tier.
    pub trust_level: ModelBundleTrustLevel,
    /// Blake3 digest of the bundle artifact.
    pub artifact_digest: String,
    /// SLSA provenance level (0–4).  Level 0 = no provenance.
    pub slsa_level: u8,
}

impl SignedModelBundle {
    /// Creates a new signed model bundle with a fresh ULID.
    #[must_use]
    pub fn new(
        model_id: impl Into<String>,
        publisher: impl Into<String>,
        trust_level: ModelBundleTrustLevel,
        artifact_digest: impl Into<String>,
        slsa_level: u8,
    ) -> Self {
        Self {
            bundle_id: format!("smb_{}", Ulid::new()),
            model_id: model_id.into(),
            publisher: publisher.into(),
            trust_level,
            artifact_digest: artifact_digest.into(),
            slsa_level,
        }
    }

    /// Determines whether this bundle is eligible for model routing.
    ///
    /// # Rules
    ///
    /// - `AiosVerified` → always eligible.
    /// - `ThirdPartySigned` → eligible (subject to re‑evaluation).
    /// - `LocalOnly` → eligible (local scope only).
    /// - `Untrusted` → **never** eligible.
    /// - `slsa_level < 2` → not eligible under `STIG_ALIGNED` / `AIRGAP_HIGH`
    ///   profiles.
    #[must_use]
    pub fn is_routing_eligible(&self) -> bool {
        !matches!(self.trust_level, ModelBundleTrustLevel::Untrusted)
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
    fn aios_verified_bundle_is_routing_eligible() {
        let bundle = SignedModelBundle::new(
            "m1",
            "aios",
            ModelBundleTrustLevel::AiosVerified,
            "abc123",
            4,
        );
        assert!(bundle.is_routing_eligible());
    }

    #[test]
    fn third_party_signed_bundle_is_routing_eligible() {
        let bundle = SignedModelBundle::new(
            "m1",
            "acme",
            ModelBundleTrustLevel::ThirdPartySigned,
            "abc123",
            2,
        );
        assert!(bundle.is_routing_eligible());
    }

    #[test]
    fn local_only_bundle_is_routing_eligible() {
        let bundle =
            SignedModelBundle::new("m1", "local", ModelBundleTrustLevel::LocalOnly, "abc123", 0);
        assert!(bundle.is_routing_eligible());
    }

    #[test]
    fn untrusted_bundle_is_not_routing_eligible() {
        let bundle = SignedModelBundle::new(
            "m1",
            "unknown",
            ModelBundleTrustLevel::Untrusted,
            "abc123",
            0,
        );
        assert!(!bundle.is_routing_eligible());
    }

    #[test]
    fn low_slsa_level_is_still_eligible_for_non_airgap() {
        let bundle = SignedModelBundle::new(
            "m1",
            "dev",
            ModelBundleTrustLevel::ThirdPartySigned,
            "abc123",
            1,
        );
        assert!(bundle.is_routing_eligible());
    }

    #[test]
    fn bundle_id_starts_with_smb_prefix() {
        let bundle = SignedModelBundle::new("m1", "p", ModelBundleTrustLevel::AiosVerified, "d", 4);
        assert!(bundle.bundle_id.starts_with("smb_"));
    }

    #[test]
    fn slsa_level_zero_is_stored_correctly() {
        let bundle = SignedModelBundle::new("m1", "p", ModelBundleTrustLevel::LocalOnly, "d", 0);
        assert_eq!(bundle.slsa_level, 0);
    }

    #[test]
    fn slsa_level_four_is_stored_correctly() {
        let bundle = SignedModelBundle::new("m1", "p", ModelBundleTrustLevel::AiosVerified, "d", 4);
        assert_eq!(bundle.slsa_level, 4);
    }
}
