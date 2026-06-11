//! Fleet-scope hard-deny policy enforcement per S25 §12.
//!
//! Implements the 9 mechanically enforced hard-deny rules of the S25 fleet policy.
//! These rules are part of L0 constitutional truth — they cannot be overridden
//! by any bundle, operator override, or cluster vote.
//!
//! # Architecture
//!
//! Each rule is enforced by a dedicated function (`enforce_*`) that returns
//! `Result<(), FleetPolicyError>`. The `FleetPolicyGate::evaluate_cluster_action`
//! method runs all active rules and collects every denial into a single error
//! containing the complete list of violated rules.

use std::fmt;

use crate::enums::FleetMembershipState;
use crate::federated_identity::FederatedSubjectId;
use crate::trust_delegation::CrossOrgTrustDelegation;
use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};
use thiserror::Error;

// ---------------------------------------------------------------------------
// FleetHardDenyRule — 9 constitutional hard-deny rules from S25 §12
// ---------------------------------------------------------------------------

/// The 9 fleet-scope hard-deny rules enumerated in S25 §12.
///
/// Each variant maps 1:1 to a row in the spec table. The serde wire format uses
/// the spec's `hd.s25.<snake_case>` policy id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
pub enum FleetHardDenyRule {
    /// `hd.s25.cluster_override_host_policy` — INV-026: cluster cannot override host policy.
    #[serde(rename = "hd.s25.cluster_override_host_policy")]
    ClusterOverrideHostPolicy,
    /// `hd.s25.cluster_weaken_profile` — cluster cannot weaken a host security profile.
    #[serde(rename = "hd.s25.cluster_weaken_profile")]
    ClusterWeakenProfile,
    /// `hd.s25.cluster_mutate_host_evidence` — cluster cannot mutate host evidence records.
    #[serde(rename = "hd.s25.cluster_mutate_host_evidence")]
    ClusterMutateHostEvidence,
    /// `hd.s25.cluster_become_root` — cluster subject cannot escalate to root on the host.
    #[serde(rename = "hd.s25.cluster_become_root")]
    ClusterBecomeRoot,
    /// `hd.s25.ai_author_checkpoint` — AI subject cannot author a cluster checkpoint.
    #[serde(rename = "hd.s25.ai_author_checkpoint")]
    AiAuthorCheckpoint,
    /// `hd.s25.ai_approve_routing` — AI subject cannot approve remote routing decisions.
    #[serde(rename = "hd.s25.ai_approve_routing")]
    AiApproveRouting,
    /// `hd.s25.foreign_subject_admin` — foreign-realm subjects cannot be granted admin.
    #[serde(rename = "hd.s25.foreign_subject_admin")]
    ForeignSubjectAdmin,
    /// `hd.s25.transitive_delegation_unsigned` — multi-hop delegation requires signature at each hop.
    #[serde(rename = "hd.s25.transitive_delegation_unsigned")]
    TransitiveDelegationUnsigned,
    /// `hd.s25.silent_legacy_id_collision` — legacy id collision must be detected, not silently aliased.
    #[serde(rename = "hd.s25.silent_legacy_id_collision")]
    SilentLegacyIdCollision,
}

impl fmt::Display for FleetHardDenyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClusterOverrideHostPolicy => write!(f, "hd.s25.cluster_override_host_policy"),
            Self::ClusterWeakenProfile => write!(f, "hd.s25.cluster_weaken_profile"),
            Self::ClusterMutateHostEvidence => write!(f, "hd.s25.cluster_mutate_host_evidence"),
            Self::ClusterBecomeRoot => write!(f, "hd.s25.cluster_become_root"),
            Self::AiAuthorCheckpoint => write!(f, "hd.s25.ai_author_checkpoint"),
            Self::AiApproveRouting => write!(f, "hd.s25.ai_approve_routing"),
            Self::ForeignSubjectAdmin => write!(f, "hd.s25.foreign_subject_admin"),
            Self::TransitiveDelegationUnsigned => write!(f, "hd.s25.transitive_delegation_unsigned"),
            Self::SilentLegacyIdCollision => write!(f, "hd.s25.silent_legacy_id_collision"),
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterAction — the subject-requested cluster action being evaluated
// ---------------------------------------------------------------------------

/// A subject-requested cluster action that must be checked against hard-deny rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClusterAction {
    /// Override a host-level policy from the cluster layer.
    OverrideHostPolicy,
    /// Weaken a host security profile.
    WeakenProfile,
    /// Mutate host evidence records.
    MutateHostEvidence,
    /// Escalate to root on a fleet host.
    BecomeRoot,
    /// Author a cluster-wide checkpoint.
    AuthorCheckpoint,
    /// Approve a remote workload routing decision.
    ApproveRouting,
    /// Grant admin rights on this cluster to the given federated subject.
    GrantAdmin {
        /// The subject being granted admin.
        target: FederatedSubjectId,
    },
    /// Perform a transitive (multi-hop) delegation across realms.
    TransitiveDelegation {
        /// The chain of delegations from origin to target realm.
        delegation_chain: Vec<CrossOrgTrustDelegation>,
    },
    /// Resolve a legacy (pre-federation) subject id in the given home realm.
    ResolveLegacyId {
        /// The legacy (pre-federation) identifier string.
        legacy_id: String,
        /// The realm in which the legacy id must be resolved.
        home_realm: String,
    },
}

// ---------------------------------------------------------------------------
// SecurityProfile — host security posture
// ---------------------------------------------------------------------------

/// A host's security profile against which cluster actions are evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityProfile {
    /// The profile's identifier.
    pub profile_id: String,
    /// Minimum required posture level (0-255).
    pub posture_floor: u8,
    /// Current posture level of the host.
    pub current_posture: u8,
    /// Whether the profile is active on the host.
    pub active: bool,
    /// Whether this profile was set by the host (true) or the cluster (false).
    pub host_originated: bool,
}

impl SecurityProfile {
    /// Creates a new security profile.
    #[must_use]
    pub fn new(
        profile_id: String,
        posture_floor: u8,
        current_posture: u8,
    ) -> Self {
        Self {
            profile_id,
            posture_floor,
            current_posture,
            active: true,
            host_originated: true,
        }
    }

    /// Returns `true` when the current posture meets or exceeds the floor.
    #[must_use]
    pub fn posture_satisfies_floor(&self) -> bool {
        self.current_posture >= self.posture_floor
    }

    /// Returns `true` when weakening this profile would drop below the floor.
    #[must_use]
    pub fn would_violate_floor_if_weakened(&self, new_floor: u8) -> bool {
        self.current_posture < new_floor
    }
}

// ---------------------------------------------------------------------------
// Subject — the actor performing the cluster action
// ---------------------------------------------------------------------------

/// The actor (subject) requesting a cluster action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// Canonical subject identifier.
    pub canonical_id: String,
    /// Federated identity id.
    pub federated_id: FederatedSubjectId,
    /// `true` when the subject is an AI agent or application.
    pub is_ai: bool,
    /// `true` when the subject holds admin rights on the cluster.
    pub is_admin: bool,
    /// `true` when the subject is the cluster root (coordinator).
    pub is_cluster_root: bool,
    /// The subject's membership state within the fleet.
    pub membership_state: FleetMembershipState,
    /// Whether the subject belongs to the local (default) realm.
    pub is_local_realm: bool,
    /// Optional delegation ceiling that caps this subject's authority.
    pub delegation_ceiling: Option<CrossOrgTrustDelegation>,
}

impl Subject {
    /// Creates a new local-realm subject.
    #[must_use]
    pub fn new_local(canonical_id: String, local_id: String) -> Self {
        Self {
            canonical_id,
            federated_id: FederatedSubjectId::resolve_legacy(&local_id),
            is_ai: false,
            is_admin: false,
            is_cluster_root: false,
            membership_state: FleetMembershipState::Enrolled,
            is_local_realm: true,
            delegation_ceiling: None,
        }
    }

    /// Creates a new AI subject.
    #[must_use]
    pub fn new_ai(canonical_id: String, local_id: String) -> Self {
        Self {
            canonical_id: format!("agent:{}", local_id),
            federated_id: FederatedSubjectId::resolve_legacy(&local_id),
            is_ai: true,
            is_admin: false,
            is_cluster_root: false,
            membership_state: FleetMembershipState::Enrolled,
            is_local_realm: true,
            delegation_ceiling: None,
        }
        .with_canonical_id(canonical_id)
    }

    /// Creates a new foreign-realm subject.
    #[must_use]
    pub fn new_foreign(
        canonical_id: String,
        home_realm: String,
        local_id: String,
        delegation: Option<CrossOrgTrustDelegation>,
    ) -> Self {
        Self {
            canonical_id,
            federated_id: FederatedSubjectId::new(home_realm, local_id),
            is_ai: false,
            is_admin: false,
            is_cluster_root: false,
            membership_state: FleetMembershipState::Enrolled,
            is_local_realm: false,
            delegation_ceiling: delegation,
        }
    }

    /// Sets the canonical id and returns self for builder pattern use.
    fn with_canonical_id(mut self, id: String) -> Self {
        self.canonical_id = id;
        self
    }

    /// Marks this subject as a cluster root (coordinator).
    #[must_use]
    pub fn as_cluster_root(mut self) -> Self {
        self.is_cluster_root = true;
        self.is_admin = true;
        self
    }

    /// Marks this subject as an admin.
    #[must_use]
    pub fn as_admin(mut self) -> Self {
        self.is_admin = true;
        self
    }

    /// Returns `true` when the subject is a foreign-realm subject.
    #[must_use]
    pub fn is_foreign(&self) -> bool {
        !self.is_local_realm
    }

    /// Returns `true` when the subject is enrolled in the fleet.
    #[must_use]
    pub fn is_enrolled(&self) -> bool {
        self.membership_state == FleetMembershipState::Enrolled
    }
}

// ---------------------------------------------------------------------------
// FleetPolicyError — detailed denial information
// ---------------------------------------------------------------------------

/// A single denial recorded by the fleet policy gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetPolicyDenial {
    /// The hard-deny rule that was violated.
    pub rule: FleetHardDenyRule,
    /// A human-readable reason for the denial.
    pub reason: String,
}

impl FleetPolicyDenial {
    /// Creates a new policy denial record.
    #[must_use]
    pub fn new(rule: FleetHardDenyRule, reason: String) -> Self {
        Self { rule, reason }
    }
}

/// Error returned when one or more fleet hard-deny rules block an action.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[error("fleet policy denied action: {} denial(s)", denials.len())]
pub struct FleetPolicyError {
    /// The list of individual denials that were triggered.
    pub denials: Vec<FleetPolicyDenial>,
}

impl FleetPolicyError {
    /// Creates a new fleet policy error with the given denials.
    #[must_use]
    pub fn new(denials: Vec<FleetPolicyDenial>) -> Self {
        Self { denials }
    }

    /// Returns the count of denial rules triggered.
    #[must_use]
    pub fn denial_count(&self) -> usize {
        self.denials.len()
    }
}

// ---------------------------------------------------------------------------
// FleetPolicyGate — the policy gate for cluster actions
// ---------------------------------------------------------------------------

/// The fleet-scope policy gate that enforces S25 §12 hard-deny rules.
///
/// Construct a gate with desired active rules and call
/// [`evaluate_cluster_action`](Self::evaluate_cluster_action) to check whether
/// a subject's proposed cluster action is permitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetPolicyGate {
    /// The set of hard-deny rules active on this gate.
    pub rules: Vec<FleetHardDenyRule>,
    /// Whether the gate is currently active (evaluating actions).
    pub active: bool,
}

impl FleetPolicyGate {
    /// Creates a new fleet policy gate with all 9 hard-deny rules active.
    #[must_use]
    pub fn full() -> Self {
        use strum::IntoEnumIterator;
        Self {
            rules: FleetHardDenyRule::iter().collect(),
            active: true,
        }
    }

    /// Creates a new fleet policy gate with no rules (everything allowed).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            active: true,
        }
    }

    /// Creates a new fleet policy gate with only the given rules.
    #[must_use]
    pub fn with_rules(rules: Vec<FleetHardDenyRule>) -> Self {
        Self { rules, active: true }
    }

    /// Returns `true` when the given rule is active on this gate.
    #[must_use]
    pub fn has_rule(&self, rule: FleetHardDenyRule) -> bool {
        self.rules.contains(&rule)
    }

    /// Evaluate a subject's proposed cluster action against all active hard-deny rules.
    ///
    /// Returns `Ok(())` when the action is permitted. Returns `Err(FleetPolicyError)`
    /// with all triggered denials when one or more rules block the action.
    ///
    /// # S25 §12 enforcement logic
    ///
    /// 1. **INV-026:** Cluster cannot override host policy.
    /// 2. Cluster cannot weaken a host security profile.
    /// 3. Cluster cannot mutate host evidence records.
    /// 4. Cluster subject cannot escalate to root on the host.
    /// 5. AI cannot author a cluster checkpoint.
    /// 6. AI cannot approve remote routing.
    /// 7. Foreign-realm subjects cannot be granted admin.
    /// 8. Transitive delegation must be signed at each hop.
    /// 9. Legacy id collision must be detected.
    pub fn evaluate_cluster_action(
        &self,
        action: &ClusterAction,
        subject: &Subject,
        profile: &SecurityProfile,
    ) -> Result<(), FleetPolicyError> {
        if !self.active {
            return Ok(());
        }

        let mut denials: Vec<FleetPolicyDenial> = Vec::new();

        enforce_host_sovereignty(action, subject, profile, &self.rules, &mut denials);

        enforce_ai_denials(action, subject, &self.rules, &mut denials);

        enforce_foreign_subject_cap(
            action,
            subject,
            subject.delegation_ceiling.as_ref(),
            &self.rules,
            &mut denials,
        );

        enforce_transitive_delegation(action, &self.rules, &mut denials);

        enforce_legacy_id_collision(action, &self.rules, &mut denials);

        if denials.is_empty() {
            Ok(())
        } else {
            Err(FleetPolicyError::new(denials))
        }
    }
}

// ---------------------------------------------------------------------------
// Individual enforcement functions
// ---------------------------------------------------------------------------

/// Enforces INV-026 and related host-sovereignty rules.
///
/// Rules checked:
/// - `ClusterOverrideHostPolicy` — cluster cannot override host-originated policy
/// - `ClusterWeakenProfile` — cluster cannot weaken a host security profile
/// - `ClusterMutateHostEvidence` — cluster cannot mutate host evidence
/// - `ClusterBecomeRoot` — cluster subject cannot escalate to root on host
fn enforce_host_sovereignty(
    action: &ClusterAction,
    subject: &Subject,
    profile: &SecurityProfile,
    rules: &[FleetHardDenyRule],
    denials: &mut Vec<FleetPolicyDenial>,
) {
    match action {
        ClusterAction::OverrideHostPolicy => {
            if rules.contains(&FleetHardDenyRule::ClusterOverrideHostPolicy) {
                denials.push(FleetPolicyDenial::new(
                    FleetHardDenyRule::ClusterOverrideHostPolicy,
                    "INV-026: cluster cannot override host policy — host sovereignty is constitutional".into(),
                ));
            }
        }
        ClusterAction::WeakenProfile => {
            if rules.contains(&FleetHardDenyRule::ClusterWeakenProfile) {
                if profile.host_originated {
                    denials.push(FleetPolicyDenial::new(
                        FleetHardDenyRule::ClusterWeakenProfile,
                        format!(
                            "cluster cannot weaken host-originated security profile '{}' (posture floor: {})",
                            profile.profile_id, profile.posture_floor,
                        ),
                    ));
                }
            }
        }
        ClusterAction::MutateHostEvidence => {
            if rules.contains(&FleetHardDenyRule::ClusterMutateHostEvidence) {
                denials.push(FleetPolicyDenial::new(
                    FleetHardDenyRule::ClusterMutateHostEvidence,
                    "cluster cannot mutate host evidence records — evidence sovereignty is constitutional".into(),
                ));
            }
        }
        ClusterAction::BecomeRoot => {
            if rules.contains(&FleetHardDenyRule::ClusterBecomeRoot) {
                if !subject.is_cluster_root {
                    denials.push(FleetPolicyDenial::new(
                        FleetHardDenyRule::ClusterBecomeRoot,
                        format!(
                            "subject '{}' cannot escalate to root on the host — only the cluster root may perform BecomeRoot",
                            subject.canonical_id,
                        ),
                    ));
                }
                // Cluster root's own actions are not censored by BecomeRoot.
                // A cluster root subject is allowed to BecomeRoot.
            }
        }
        _ => {}
    }
}

/// Enforces AI-subject denials.
///
/// Rules checked:
/// - `AiAuthorCheckpoint` — AI cannot author a cluster checkpoint
/// - `AiApproveRouting` — AI cannot approve remote routing
fn enforce_ai_denials(
    action: &ClusterAction,
    subject: &Subject,
    rules: &[FleetHardDenyRule],
    denials: &mut Vec<FleetPolicyDenial>,
) {
    if !subject.is_ai {
        return;
    }

    match action {
        ClusterAction::AuthorCheckpoint => {
            if rules.contains(&FleetHardDenyRule::AiAuthorCheckpoint) {
                denials.push(FleetPolicyDenial::new(
                    FleetHardDenyRule::AiAuthorCheckpoint,
                    format!(
                        "AI subject '{}' cannot author a cluster checkpoint — checkpoint authorship is reserved for human operators",
                        subject.canonical_id,
                    ),
                ));
            }
        }
        ClusterAction::ApproveRouting => {
            if rules.contains(&FleetHardDenyRule::AiApproveRouting) {
                denials.push(FleetPolicyDenial::new(
                    FleetHardDenyRule::AiApproveRouting,
                    format!(
                        "AI subject '{}' cannot approve remote routing — routing approval is reserved for human operators",
                        subject.canonical_id,
                    ),
                ));
            }
        }
        _ => {}
    }
}

/// Enforces foreign-subject capability ceiling.
///
/// Rules checked:
/// - `ForeignSubjectAdmin` — foreign-realm subjects cannot be granted admin
fn enforce_foreign_subject_cap(
    action: &ClusterAction,
    subject: &Subject,
    delegation: Option<&CrossOrgTrustDelegation>,
    rules: &[FleetHardDenyRule],
    denials: &mut Vec<FleetPolicyDenial>,
) {
    if !rules.contains(&FleetHardDenyRule::ForeignSubjectAdmin) {
        return;
    }

    // Rule: GrantAdmin of a foreign-realm target is always denied (regardless of actor realm).
    if let ClusterAction::GrantAdmin { target } = action {
        if target.is_foreign_realm() {
            let reason = if subject.is_foreign() {
                if let Some(del) = delegation {
                    if del.forbid_admin_actions {
                        format!(
                            "foreign-realm subject '{}' (realm: {}) cannot be granted admin — delegation '{}' forbids admin actions",
                            target, target.home_realm, del.delegation_id,
                        )
                    } else {
                        format!(
                            "foreign-realm subject '{}' (realm: {}) cannot be granted admin — foreign subject admin is constitutionally denied",
                            target, target.home_realm,
                        )
                    }
                } else {
                    format!(
                        "foreign-realm subject '{}' (realm: {}) cannot be granted admin — no delegation exists and foreign subject admin is constitutionally denied",
                        target, target.home_realm,
                    )
                }
            } else {
                format!(
                    "foreign-realm subject '{}' (realm: {}) cannot be granted admin — foreign subject admin is constitutionally denied",
                    target, target.home_realm,
                )
            };
            denials.push(FleetPolicyDenial::new(
                FleetHardDenyRule::ForeignSubjectAdmin,
                reason,
            ));
        }
        return;
    }

    // Non-GrantAdmin actions: foreign subjects are capped by delegation ceiling.
    if !subject.is_foreign() {
        return;
    }

    if let Some(del) = delegation {
        if del.forbid_admin_actions && subject.is_admin {
            denials.push(FleetPolicyDenial::new(
                FleetHardDenyRule::ForeignSubjectAdmin,
                format!(
                    "foreign-realm subject '{}' with admin rights is acting beyond delegation '{}' ceiling",
                    subject.canonical_id, del.delegation_id,
                ),
            ));
        }
    }
}

/// Enforces transitive delegation signature requirements.
///
/// Rules checked:
/// - `TransitiveDelegationUnsigned` — multi-hop delegation must be signed at each hop
fn enforce_transitive_delegation(
    action: &ClusterAction,
    rules: &[FleetHardDenyRule],
    denials: &mut Vec<FleetPolicyDenial>,
) {
    if !rules.contains(&FleetHardDenyRule::TransitiveDelegationUnsigned) {
        return;
    }

    if let ClusterAction::TransitiveDelegation { delegation_chain } = action {
        if delegation_chain.len() < 2 {
            return;
        }

        let unsupported_hops: Vec<String> = delegation_chain
            .iter()
            .enumerate()
            .filter(|(_, d)| !d.allows_transitive())
            .map(|(i, d)| format!("hop {}: delegation '{}' (max_hops: {})", i + 1, d.delegation_id, d.max_hops))
            .collect();

        if !unsupported_hops.is_empty() {
            denials.push(FleetPolicyDenial::new(
                FleetHardDenyRule::TransitiveDelegationUnsigned,
                format!(
                    "transitive delegation chain of {} hops requires each hop to be signed and permit multi-hop: {}",
                    delegation_chain.len(),
                    unsupported_hops.join("; "),
                ),
            ));
            return;
        }

        let mut seen_realms = std::collections::HashSet::new();
        for (i, d) in delegation_chain.iter().enumerate() {
            if !seen_realms.insert(&d.from_realm) {
                denials.push(FleetPolicyDenial::new(
                    FleetHardDenyRule::TransitiveDelegationUnsigned,
                    format!(
                        "transitive delegation chain has a cyclic trust path at hop {} (realm '{}' appears more than once)",
                        i + 1,
                        d.from_realm,
                    ),
                ));
                return;
            }
        }
    }
}

/// Enforces legacy id collision detection.
///
/// Rules checked:
/// - `SilentLegacyIdCollision` — legacy id collision must be detected, not silently aliased
fn enforce_legacy_id_collision(
    action: &ClusterAction,
    rules: &[FleetHardDenyRule],
    denials: &mut Vec<FleetPolicyDenial>,
) {
    if !rules.contains(&FleetHardDenyRule::SilentLegacyIdCollision) {
        return;
    }

    if let ClusterAction::ResolveLegacyId {
        legacy_id,
        home_realm,
    } = action
    {
        if home_realm == "realm:default" {
            let fid = FederatedSubjectId::resolve_legacy(legacy_id);
            let expected_local = legacy_id.as_str();
            if fid.local_id != expected_local {
                denials.push(FleetPolicyDenial::new(
                    FleetHardDenyRule::SilentLegacyIdCollision,
                    format!(
                        "legacy id collision detected: '{}' resolved to FederatedSubjectId({}:{}) but expected local_id '{}'",
                        legacy_id, fid.home_realm, fid.local_id, expected_local,
                    ),
                ));
            }
        }

        if legacy_id.contains(':') {
            let parts: Vec<&str> = legacy_id.splitn(3, ':').collect();
            if parts.len() >= 2 {
                let candidate_realm = format!("{}:{}", parts[0], parts[1]);
                if candidate_realm == *home_realm {
                    denials.push(FleetPolicyDenial::new(
                        FleetHardDenyRule::SilentLegacyIdCollision,
                        format!(
                            "legacy id '{}' contains a realm prefix '{}' that collides with the explicit home_realm '{}' — this is an ambiguous silent collision",
                            legacy_id, candidate_realm, home_realm,
                        ),
                    ));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustDelegationDirection;

    // --- Helpers ---

    fn local_human(canonical_id: &str) -> Subject {
        Subject::new_local(canonical_id.into(), canonical_id.into())
    }

    fn local_admin(canonical_id: &str) -> Subject {
        local_human(canonical_id).as_admin()
    }

    fn local_ai() -> Subject {
        Subject::new_ai("agent:dev:01ABC".into(), "agent:dev:01ABC".into())
    }

    fn cluster_root() -> Subject {
        local_admin("root").as_cluster_root()
    }

    fn host_profile() -> SecurityProfile {
        SecurityProfile::new("prof_host_01".into(), 60, 80)
    }

    fn gate_with(rule: FleetHardDenyRule) -> FleetPolicyGate {
        FleetPolicyGate::with_rules(vec![rule])
    }

    // --- INV-026: Cluster override host policy — DENIED ---

    #[test]
    fn inv_026_cluster_override_host_policy_denied() {
        let gate = FleetPolicyGate::full();
        let subject = local_human("worker");
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::OverrideHostPolicy,
            &subject,
            &profile,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.denial_count(), 1);
        assert_eq!(err.denials[0].rule, FleetHardDenyRule::ClusterOverrideHostPolicy);
    }

    // --- Cluster weaken profile — DENIED ---

    #[test]
    fn cluster_weaken_profile_denied() {
        let gate = FleetPolicyGate::full();
        let subject = local_human("worker");
        let profile = SecurityProfile::new("prof_host_01".into(), 80, 80);
        let result = gate.evaluate_cluster_action(
            &ClusterAction::WeakenProfile,
            &subject,
            &profile,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().denials[0].rule, FleetHardDenyRule::ClusterWeakenProfile);
    }

    // --- Cluster mutate host evidence — DENIED ---

    #[test]
    fn cluster_mutate_host_evidence_denied() {
        let gate = FleetPolicyGate::full();
        let subject = local_human("worker");
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::MutateHostEvidence,
            &subject,
            &profile,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().denials[0].rule, FleetHardDenyRule::ClusterMutateHostEvidence);
    }

    // --- Cluster BecomeRoot — non-root denied, root allowed ---

    #[test]
    fn cluster_become_root_non_root_denied() {
        let gate = FleetPolicyGate::full();
        let subject = local_human("worker");
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::BecomeRoot,
            &subject,
            &profile,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().denials[0].rule, FleetHardDenyRule::ClusterBecomeRoot);
    }

    #[test]
    fn cluster_root_become_root_allowed() {
        let gate = FleetPolicyGate::full();
        let subject = cluster_root();
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::BecomeRoot,
            &subject,
            &profile,
        );
        assert!(result.is_ok());
    }

    // --- AI author checkpoint — DENIED ---

    #[test]
    fn ai_author_checkpoint_denied() {
        let gate = FleetPolicyGate::full();
        let subject = local_ai();
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::AuthorCheckpoint,
            &subject,
            &profile,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().denials[0].rule, FleetHardDenyRule::AiAuthorCheckpoint);
    }

    // --- AI approve routing — DENIED ---

    #[test]
    fn ai_approve_routing_denied() {
        let gate = FleetPolicyGate::full();
        let subject = local_ai();
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::ApproveRouting,
            &subject,
            &profile,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().denials[0].rule, FleetHardDenyRule::AiApproveRouting);
    }


    #[test]
    fn human_author_checkpoint_allowed() {
        let gate = FleetPolicyGate::full();
        let subject = local_admin("human_admin");
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::AuthorCheckpoint,
            &subject,
            &profile,
        );
        assert!(result.is_ok());
    }


    #[test]
    fn human_approve_routing_allowed() {
        let gate = FleetPolicyGate::full();
        let subject = local_admin("human_admin");
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::ApproveRouting,
            &subject,
            &profile,
        );
        assert!(result.is_ok());
    }

    // --- Foreign subject admin grant — DENIED ---

    #[test]
    fn foreign_subject_admin_grant_denied() {
        let gate = FleetPolicyGate::full();
        let subject = local_admin("admin");
        let profile = host_profile();
        let foreign_id = FederatedSubjectId::new("realm:other".into(), "foreign-admin".into());
        let result = gate.evaluate_cluster_action(
            &ClusterAction::GrantAdmin {
                target: foreign_id,
            },
            &subject,
            &profile,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().denials[0].rule, FleetHardDenyRule::ForeignSubjectAdmin);
    }

    // --- Foreign subject with ceiling — within ceiling ALLOWED ---

    #[test]
    fn foreign_subject_within_ceiling_allowed() {
        let gate = gate_with(FleetHardDenyRule::ForeignSubjectAdmin);
        let mut delegation = CrossOrgTrustDelegation::new(
            "del_01".into(),
            "realm:default".into(),
            "realm:other".into(),
            TrustDelegationDirection::Bidirectional,
        );
        delegation.forbid_admin_actions = false;
        delegation.forbid_ai_subjects = true;

        let subject = Subject::new_foreign(
            "foreign_user".into(),
            "realm:other".into(),
            "foreign_user".into(),
            Some(delegation),
        );
        let profile = host_profile();
        let local_id = FederatedSubjectId::resolve_legacy("local_user");
        let result = gate.evaluate_cluster_action(
            &ClusterAction::GrantAdmin {
                target: local_id,
            },
            &subject,
            &profile,
        );
        // Target is local, so ForeignSubjectAdmin should NOT trigger
        assert!(result.is_ok());
    }

    // --- Foreign subject beyond delegation ceiling — DENIED ---

    #[test]
    fn foreign_subject_beyond_ceiling_denied() {
        let gate = FleetPolicyGate::full();
        let delegation = CrossOrgTrustDelegation::new(
            "del_02".into(),
            "realm:default".into(),
            "realm:other".into(),
            TrustDelegationDirection::InboundAccept,
        );
        // delegation.forbid_admin_actions is true by default

        let subject = Subject::new_foreign(
            "foreign_admin".into(),
            "realm:other".into(),
            "foreign_admin".into(),
            Some(delegation),
        )
        .as_admin();

        let profile = host_profile();
        let foreign_id = FederatedSubjectId::new("realm:remote".into(), "bad-admin".into());
        let result = gate.evaluate_cluster_action(
            &ClusterAction::GrantAdmin {
                target: foreign_id,
            },
            &subject,
            &profile,
        );
        assert!(result.is_err());
        // Both ForeignSubjectAdmin should fire (target is foreign, and subject is foreign admin beyond ceiling)
        let err = result.unwrap_err();
        assert!(err.denials.iter().any(|d| d.rule == FleetHardDenyRule::ForeignSubjectAdmin));
    }

    // --- Transitive delegation unsigned — DENIED ---

    #[test]
    fn transitive_delegation_unsigned_denied() {
        let gate = FleetPolicyGate::full();
        let subject = local_admin("admin");
        let profile = host_profile();

        let d1 = CrossOrgTrustDelegation::new(
            "del_01".into(), "realm:a".into(), "realm:b".into(),
            TrustDelegationDirection::OutboundVouch,
        );
        let d2 = CrossOrgTrustDelegation::new(
            "del_02".into(), "realm:b".into(), "realm:c".into(),
            TrustDelegationDirection::OutboundVouch,
        );
        // d1.max_hops = 0, d2.max_hops = 0 — both forbid transitive

        let result = gate.evaluate_cluster_action(
            &ClusterAction::TransitiveDelegation {
                delegation_chain: vec![d1, d2],
            },
            &subject,
            &profile,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().denials[0].rule,
            FleetHardDenyRule::TransitiveDelegationUnsigned,
        );
    }

    // --- Transitive delegation with proper hops — ALLOWED ---

    #[test]
    fn transitive_delegation_signed_allowed() {
        let gate = FleetPolicyGate::full();
        let subject = local_admin("admin");
        let profile = host_profile();

        let mut d1 = CrossOrgTrustDelegation::new(
            "del_01".into(), "realm:a".into(), "realm:b".into(),
            TrustDelegationDirection::OutboundVouch,
        );
        d1.max_hops = 2;
        let mut d2 = CrossOrgTrustDelegation::new(
            "del_02".into(), "realm:b".into(), "realm:c".into(),
            TrustDelegationDirection::OutboundVouch,
        );
        d2.max_hops = 2;

        let result = gate.evaluate_cluster_action(
            &ClusterAction::TransitiveDelegation {
                delegation_chain: vec![d1, d2],
            },
            &subject,
            &profile,
        );
        assert!(result.is_ok());
    }

    // --- Silent legacy ID collision — DETECTED ---

    #[test]
    fn silent_legacy_id_collision_detected() {
        let gate = FleetPolicyGate::full();
        let subject = local_human("worker");
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::ResolveLegacyId {
                legacy_id: "realm:default:duplicate".into(),
                home_realm: "realm:default".into(),
            },
            &subject,
            &profile,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().denials[0].rule,
            FleetHardDenyRule::SilentLegacyIdCollision,
        );
    }

    // --- Local admin subject action — ALLOWED ---

    #[test]
    fn local_admin_action_allowed() {
        let gate = FleetPolicyGate::full();
        let subject = local_admin("admin");
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::AuthorCheckpoint,
            &subject,
            &profile,
        );
        assert!(result.is_ok());
    }

    // --- Empty policy gate — all allowed ---

    #[test]
    fn empty_policy_gate_all_allowed() {
        let gate = FleetPolicyGate::empty();
        let subject = local_ai();
        let profile = host_profile();

        let actions = vec![
            ClusterAction::OverrideHostPolicy,
            ClusterAction::WeakenProfile,
            ClusterAction::MutateHostEvidence,
            ClusterAction::BecomeRoot,
            ClusterAction::AuthorCheckpoint,
            ClusterAction::ApproveRouting,
        ];

        for action in &actions {
            let result = gate.evaluate_cluster_action(action, &subject, &profile);
            assert!(result.is_ok(), "empty gate should allow {:?}", action);
        }
    }

    // --- Multiple simultaneous denials ---

    #[test]
    fn multiple_simultaneous_denials() {
        let gate = FleetPolicyGate::full();
        let subject = local_ai();
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::OverrideHostPolicy,
            &subject,
            &profile,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        // ClusterOverrideHostPolicy fires + AI checks don't fire for OverrideHostPolicy
        assert_eq!(err.denial_count(), 1, "OverrideHostPolicy triggers 1 denial");
    }

    #[test]
    fn ai_author_checkpoint_triggers_exactly_ai_denial() {
        let gate = FleetPolicyGate::full();
        let subject = local_ai();
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::AuthorCheckpoint,
            &subject,
            &profile,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.denial_count(), 1);
        assert_eq!(err.denials[0].rule, FleetHardDenyRule::AiAuthorCheckpoint);
    }

    // --- All 9 hard-deny rules exercisable individually ---

    #[test]
    fn all_nine_rules_individually_enforceable() {
        use strum::IntoEnumIterator;
        let variants: Vec<_> = FleetHardDenyRule::iter().collect();
        assert_eq!(variants.len(), 9, "S25 §12 defines exactly 9 hard-deny rules");

        for rule in &variants {
            let gate = FleetPolicyGate::with_rules(vec![*rule]);
            assert!(gate.has_rule(*rule), "gate should contain rule {}", rule);
        }
    }

    // --- inactive gate passes everything ---

    #[test]
    fn inactive_gate_passes_everything() {
        let mut gate = FleetPolicyGate::full();
        gate.active = false;
        let subject = local_ai();
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::OverrideHostPolicy,
            &subject,
            &profile,
        );
        assert!(result.is_ok());
    }

    // --- SecurityProfile posture checks ---

    #[test]
    fn posture_satisfies_floor() {
        let profile = SecurityProfile::new("p1".into(), 50, 75);
        assert!(profile.posture_satisfies_floor());
    }

    #[test]
    fn posture_below_floor() {
        let profile = SecurityProfile::new("p1".into(), 80, 60);
        assert!(!profile.posture_satisfies_floor());
    }

    #[test]
    fn would_violate_floor_if_weakened() {
        let profile = SecurityProfile::new("p1".into(), 50, 60);
        assert!(profile.would_violate_floor_if_weakened(65));
        assert!(!profile.would_violate_floor_if_weakened(55));
    }

    // --- Federated identity resolve correct local_id ---

    #[test]
    fn federated_identity_resolve_correct_local_id() {
        let sid = FederatedSubjectId::new("realm:default".into(), "family:alice".into());
        assert_eq!(sid.local_id, "family:alice");
        assert_eq!(sid.home_realm, "realm:default");
        assert!(sid.is_legacy());
    }

    // --- Federated identity round-trip loss-free INV-032 ---

    #[test]
    fn federated_identity_round_trip_loss_free() {
        let original_id = "family:alice";
        let fid = FederatedSubjectId::resolve_legacy(original_id);
        assert_eq!(fid.home_realm, "realm:default");
        assert_eq!(fid.local_id, original_id);
        assert_eq!(fid.to_string(), format!("realm:default:{}", original_id));
    }

    // --- Legacy shim: "family:alice" → FederatedSubjectId ---

    #[test]
    fn legacy_shim_family_alice_to_federated() {
        let fid = FederatedSubjectId::resolve_legacy("family:alice");
        assert_eq!(fid.home_realm, "realm:default");
        assert_eq!(fid.local_id, "family:alice");
    }

    // --- Delegation ceiling: foreign subject within ceiling — ALLOWED ---

    #[test]
    fn delegation_ceiling_foreign_subject_within_ceiling() {
        let gate = gate_with(FleetHardDenyRule::ForeignSubjectAdmin);
        let mut del = CrossOrgTrustDelegation::new(
            "del_01".into(),
            "realm:default".into(),
            "realm:partner".into(),
            TrustDelegationDirection::Bidirectional,
        );
        del.forbid_admin_actions = false;

        let subject = Subject::new_foreign(
            "partner_user".into(),
            "realm:partner".into(),
            "partner_user".into(),
            Some(del),
        );
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::AuthorCheckpoint,
            &subject,
            &profile,
        );
        assert!(result.is_ok());
    }

    // --- Delegation ceiling: foreign subject beyond ceiling — DENIED ---

    #[test]
    fn delegation_ceiling_foreign_subject_beyond_ceiling() {
        let gate = FleetPolicyGate::full();
        let del = CrossOrgTrustDelegation::new(
            "del_02".into(),
            "realm:default".into(),
            "realm:other".into(),
            TrustDelegationDirection::InboundAccept,
        );

        let subject = Subject::new_foreign(
            "bad_foreign".into(),
            "realm:other".into(),
            "bad_foreign".into(),
            Some(del),
        )
        .as_admin();

        let profile = host_profile();
        let foreign_id = FederatedSubjectId::new("realm:remote".into(), "evil-admin".into());
        let result = gate.evaluate_cluster_action(
            &ClusterAction::GrantAdmin {
                target: foreign_id,
            },
            &subject,
            &profile,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().denials.iter().any(|d| d.rule == FleetHardDenyRule::ForeignSubjectAdmin));
    }

    // --- Cluster root's own actions not censored ---

    #[test]
    fn cluster_root_own_actions_not_censored_by_become_root() {
        let gate = FleetPolicyGate::full();
        let subject = cluster_root();
        let profile = host_profile();
        let result = gate.evaluate_cluster_action(
            &ClusterAction::BecomeRoot,
            &subject,
            &profile,
        );
        assert!(result.is_ok());
    }
}
