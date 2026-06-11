use serde::{Deserialize, Serialize};
use std::fmt;

/// A globally-unique identifier for a subject within a federated realm architecture.
///
/// `FederatedSubjectId = (home_realm, local_id)` per S25 §7 / INV-032.
/// Foreign-realm subjects are resolved through the [`FederatedIdentityResolver`]
/// and capped at the [`CrossOrgTrustDelegation`] ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FederatedSubjectId {
    /// The realm that owns this subject's identity (e.g. `"realm:default"`).
    pub home_realm: String,
    /// The realm-local identifier (e.g. `"subject-42"`, `"family:alice"`).
    pub local_id: String,
}

impl fmt::Display for FederatedSubjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.home_realm, self.local_id)
    }
}

/// A bundle of federated identity assertions for a cluster onboarding event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedIdentityBundle {
    /// The unique bundle identifier.
    pub bundle_id: String,
    /// The realm this bundle originates from.
    pub home_realm: String,
    /// The cluster the subjects are being attested for.
    pub cluster_id: String,
    /// Hex-encoded Ed25519 root public key of the realm.
    pub realm_root_pubkey: String,
    /// Pairs of `(FederatedSubjectId, is_admin)` for each attested subject.
    pub subjects: Vec<(FederatedSubjectId, bool)>,
}

impl FederatedIdentityBundle {
    /// Creates a new federated identity bundle.
    #[must_use]
    pub fn new(
        bundle_id: String,
        home_realm: String,
        cluster_id: String,
        realm_root_pubkey: String,
        subjects: Vec<(FederatedSubjectId, bool)>,
    ) -> Self {
        Self {
            bundle_id,
            home_realm,
            cluster_id,
            realm_root_pubkey,
            subjects,
        }
    }
}

impl FederatedSubjectId {
    /// Creates a new federated subject id with the given realm and local id.
    #[must_use]
    pub fn new(home_realm: String, local_id: String) -> Self {
        Self {
            home_realm,
            local_id,
        }
    }

    /// Backward-compatible legacy resolution shim per S25 §7.
    ///
    /// Wraps a legacy plain id into `(realm:default, legacy_id)`.
    /// This implements the loss-free round-trip invariant INV-032:
    /// `(realm:default, old_id) ↔ old_id`.
    #[must_use]
    pub fn resolve_legacy(legacy_id: &str) -> Self {
        Self {
            home_realm: "realm:default".into(),
            local_id: legacy_id.into(),
        }
    }

    /// Returns `true` if the subject belongs to the default realm (legacy shim).
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        self.home_realm == "realm:default"
    }

    /// Returns `true` if the subject belongs to a foreign (non-default) realm.
    #[must_use]
    pub fn is_foreign_realm(&self) -> bool {
        self.home_realm != "realm:default"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_format() {
        let sid = FederatedSubjectId {
            home_realm: "realm:aios-alpha".into(),
            local_id: "subject-42".into(),
        };
        assert_eq!(sid.to_string(), "realm:aios-alpha:subject-42");
    }

    #[test]
    fn resolve_legacy_wraps_in_realm_default() {
        let sid = FederatedSubjectId::resolve_legacy("user-99");
        assert_eq!(sid.home_realm, "realm:default");
        assert_eq!(sid.local_id, "user-99");
        assert_eq!(sid.to_string(), "realm:default:user-99");
    }

    #[test]
    fn is_legacy_true_for_default_realm() {
        let sid = FederatedSubjectId::resolve_legacy("s1");
        assert!(sid.is_legacy());
    }

    #[test]
    fn is_legacy_false_for_foreign_realm() {
        let sid = FederatedSubjectId::new("realm:other".into(), "s1".into());
        assert!(!sid.is_legacy());
        assert!(sid.is_foreign_realm());
    }

    #[test]
    fn serde_roundtrip() {
        let sid = FederatedSubjectId::new("realm:x".into(), "sub-y".into());
        let json = serde_json::to_string(&sid).unwrap();
        let parsed: FederatedSubjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(sid, parsed);
    }

    #[test]
    fn bundle_new_stores_subjects() {
        let sid = FederatedSubjectId {
            home_realm: "realm:x".into(),
            local_id: "s1".into(),
        };
        let bundle = FederatedIdentityBundle::new(
            "bndl_01".into(),
            "realm:x".into(),
            "clr_01".into(),
            "pk_hex".into(),
            vec![(sid, true)],
        );
        assert_eq!(bundle.bundle_id, "bndl_01");
        assert_eq!(bundle.subjects.len(), 1);
        assert!(bundle.subjects[0].1);
    }

    #[test]
    fn hash_equality() {
        use std::collections::HashSet;
        let a = FederatedSubjectId::new("realm:a".into(), "s1".into());
        let b = FederatedSubjectId::new("realm:a".into(), "s1".into());
        let c = FederatedSubjectId::new("realm:b".into(), "s1".into());
        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }
}
