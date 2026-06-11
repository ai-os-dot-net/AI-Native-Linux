use serde::{Deserialize, Serialize};

use crate::enums::TrustDelegationDirection;

/// A cross-organisation trust delegation per S25 §5.
///
/// Grants a foreign realm a bounded set of capabilities on the local cluster.
/// The delegation ceiling caps what foreign subjects can do — they cannot escalate
/// beyond the grant. INV-032 enforces this ceiling at resolution time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CrossOrgTrustDelegation {
    /// Unique delegation identifier.
    pub delegation_id: String,
    /// The realm that grants the delegation.
    pub from_realm: String,
    /// The realm that receives the delegation.
    pub to_realm: String,
    /// Direction of trust flow.
    pub direction: TrustDelegationDirection,
    /// When `true`, AI subjects are forbidden under this delegation.
    pub forbid_ai_subjects: bool,
    /// When `true`, admin actions are forbidden under this delegation.
    pub forbid_admin_actions: bool,
    /// Maximum number of delegation hops permitted (default: 0 = direct only).
    pub max_hops: u32,
}

impl CrossOrgTrustDelegation {
    /// Creates a new cross-org trust delegation with safe defaults.
    #[must_use]
    pub fn new(
        delegation_id: String,
        from_realm: String,
        to_realm: String,
        direction: TrustDelegationDirection,
    ) -> Self {
        Self {
            delegation_id,
            from_realm,
            to_realm,
            direction,
            forbid_ai_subjects: true,
            forbid_admin_actions: true,
            max_hops: 0,
        }
    }

    /// Returns `true` when both AI subjects and admin actions are forbidden.
    #[must_use]
    pub fn is_delegation_safe(&self) -> bool {
        self.forbid_ai_subjects && self.forbid_admin_actions
    }

    /// Returns `true` when the delegation allows multi-hop transitive trust.
    #[must_use]
    pub fn allows_transitive(&self) -> bool {
        self.max_hops > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_delegation() -> CrossOrgTrustDelegation {
        CrossOrgTrustDelegation::new(
            "del_01".into(),
            "realm:a".into(),
            "realm:b".into(),
            TrustDelegationDirection::Bidirectional,
        )
    }

    #[test]
    fn new_delegation_forbids_ai_subjects() {
        let d = mk_delegation();
        assert!(d.forbid_ai_subjects);
    }

    #[test]
    fn new_delegation_forbids_admin_actions() {
        let d = mk_delegation();
        assert!(d.forbid_admin_actions);
    }

    #[test]
    fn delegation_is_safe_by_default() {
        let d = mk_delegation();
        assert!(d.is_delegation_safe());
    }

    #[test]
    fn delegation_unsafe_if_ai_not_forbidden() {
        let mut d = mk_delegation();
        d.forbid_ai_subjects = false;
        assert!(!d.is_delegation_safe());
    }

    #[test]
    fn delegation_unsafe_if_admin_not_forbidden() {
        let mut d = mk_delegation();
        d.forbid_admin_actions = false;
        assert!(!d.is_delegation_safe());
    }

    #[test]
    fn delegation_transitive_when_max_hops_nonzero() {
        let mut d = mk_delegation();
        d.max_hops = 2;
        assert!(d.allows_transitive());
    }

    #[test]
    fn delegation_direct_by_default() {
        let d = mk_delegation();
        assert!(!d.allows_transitive());
    }

    #[test]
    fn serde_roundtrip() {
        let d = mk_delegation();
        let json = serde_json::to_string(&d).unwrap();
        let parsed: CrossOrgTrustDelegation = serde_json::from_str(&json).unwrap();
        assert_eq!(d, parsed);
    }
}
