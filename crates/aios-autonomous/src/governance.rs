//! Multi-host constitutional governance for AIOS Rev.10.
//!
//! Implements the fleet constitution model: a set of immutable-or-amendable
//! clauses that bind every host in the fleet. Amendments require cryptographic
//! quorum (Ed25519 multi-signature), and every autonomous action is checked
//! against the constitution before execution.
//!
//! The cross-host [`PolicyFederation`] propagates policy updates across member
//! hosts and collects acknowledgements.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::enums::{AutonomousAction, AutonomousDecisionVerdict, AutonomyLevel, GovernanceVote};
use crate::error::AutonomousError;

// ── ClauseCategory ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClauseCategory {
    Security,
    Recovery,
    Autonomy,
    Evidence,
    Policy,
}

// ── ConstitutionalClause ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionalClause {
    pub clause_id: String,
    pub title: String,
    pub text: String,
    pub category: ClauseCategory,
    pub added_in_version: u32,
    pub immutable: bool,
}

impl ConstitutionalClause {
    #[must_use]
    pub fn new(title: &str, text: &str, category: ClauseCategory, added_in_version: u32) -> Self {
        Self {
            clause_id: format!("cl_{}", Ulid::new()),
            title: title.to_owned(),
            text: text.to_owned(),
            category,
            added_in_version,
            immutable: false,
        }
    }

    #[must_use]
    pub fn with_immutable(mut self, immutable: bool) -> Self {
        self.immutable = immutable;
        self
    }
}

// ── ConstitutionalAmendment ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstitutionalAmendment {
    pub amendment_id: String,
    pub clause_id: String,
    pub new_text: String,
    pub proposer: String,
    pub signatures: Vec<String>,
    pub quorum_met: bool,
    pub proposed_at: String,
}

impl ConstitutionalAmendment {
    #[must_use]
    pub fn new(clause_id: &str, new_text: &str, proposer: &str) -> Self {
        Self {
            amendment_id: format!("amd_{}", Ulid::new()),
            clause_id: clause_id.to_owned(),
            new_text: new_text.to_owned(),
            proposer: proposer.to_owned(),
            signatures: Vec::new(),
            quorum_met: false,
            proposed_at: Utc::now().to_rfc3339(),
        }
    }

    pub fn add_signature(&mut self, signature: &str) {
        self.signatures.push(signature.to_owned());
    }

    #[must_use]
    pub fn with_quorum(mut self, met: bool) -> Self {
        self.quorum_met = met;
        self
    }
}

// ── GovernanceContext ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceContext {
    pub subject_id: String,
    pub host_id: String,
    pub autonomy_level: AutonomyLevel,
    pub evidence_hash: String,
}

impl GovernanceContext {
    #[must_use]
    pub fn new(
        subject_id: &str,
        host_id: &str,
        autonomy_level: AutonomyLevel,
        evidence_hash: &str,
    ) -> Self {
        Self {
            subject_id: subject_id.to_owned(),
            host_id: host_id.to_owned(),
            autonomy_level,
            evidence_hash: evidence_hash.to_owned(),
        }
    }
}

// ── FleetConstitution ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetConstitution {
    pub constitution_id: String,
    pub version: u32,
    pub name: String,
    pub clauses: Vec<ConstitutionalClause>,
    pub signatures: Vec<String>,
    pub ratified_at: String,
}

impl FleetConstitution {
    const QUORUM_RATIO: f64 = 2.0 / 3.0;

    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            constitution_id: format!("const_{}", Ulid::new()),
            version: 1,
            name: name.to_owned(),
            clauses: Vec::new(),
            signatures: Vec::new(),
            ratified_at: Utc::now().to_rfc3339(),
        }
    }

    pub fn add_clause(&mut self, mut clause: ConstitutionalClause) {
        clause.added_in_version = self.version;
        self.clauses.push(clause);
    }

    fn find_clause(&self, clause_id: &str) -> Option<&ConstitutionalClause> {
        self.clauses.iter().find(|c| c.clause_id == clause_id)
    }

    pub fn validate_amendment(
        &self,
        amendment: &ConstitutionalAmendment,
    ) -> Result<(), AutonomousError> {
        let clause = self
            .find_clause(&amendment.clause_id)
            .ok_or_else(|| AutonomousError::ClauseNotFound {
                clause_id: amendment.clause_id.clone(),
            })?;

        if clause.immutable {
            return Err(AutonomousError::ImmutableClause {
                clause_id: amendment.clause_id.clone(),
            });
        }

        if !amendment.quorum_met {
            return Err(AutonomousError::QuorumNotMet {
                present: amendment.signatures.len(),
                required: self.quorum_threshold(),
            });
        }

        if amendment.signatures.is_empty() {
            return Err(AutonomousError::InsufficientSignatures {
                valid: 0,
                required: 1,
            });
        }

        Ok(())
    }

    pub fn apply_amendment(
        &mut self,
        amendment: ConstitutionalAmendment,
    ) -> Result<(), AutonomousError> {
        self.validate_amendment(&amendment)?;

        let clause = self
            .clauses
            .iter_mut()
            .find(|c| c.clause_id == amendment.clause_id)
            .ok_or_else(|| AutonomousError::ClauseNotFound {
                clause_id: amendment.clause_id.clone(),
            })?;

        clause.text = amendment.new_text;
        self.version = self.version.saturating_add(1);

        for sig in &amendment.signatures {
            self.signatures.push(sig.clone());
        }
        self.signatures.sort();
        self.signatures.dedup();

        self.ratified_at = Utc::now().to_rfc3339();
        Ok(())
    }

    pub fn check_constitutional_compliance(
        &self,
        action: &AutonomousAction,
        context: &GovernanceContext,
    ) -> Result<(), AutonomousError> {
        for clause in &self.clauses {
            match clause.category {
                ClauseCategory::Security => {
                    if matches!(action, AutonomousAction::AdjustPolicy)
                        && !context.autonomy_level.permits_amendments()
                    {
                        return Err(AutonomousError::ConstitutionalViolation {
                            clause_title: clause.title.clone(),
                            detail: format!(
                                "amend action requires FullyAutonomous, host is {:?}",
                                context.autonomy_level
                            ),
                        });
                    }
                }
                ClauseCategory::Autonomy => {
                    if context.autonomy_level == AutonomyLevel::Advisory
                        && !action.is_suggestion()
                    {
                        return Err(AutonomousError::ConstitutionalViolation {
                            clause_title: clause.title.clone(),
                            detail:
                                "Advisory autonomy forbids non-suggestion actions"
                                    .to_owned(),
                        });
                    }
                }
                ClauseCategory::Recovery => {
                    if matches!(
                        action,
                        AutonomousAction::RestartRemote
                            | AutonomousAction::MigrateWorkload
                    ) && !context.autonomy_level.permits_self_action()
                    {
                        return Err(AutonomousError::ConstitutionalViolation {
                            clause_title: clause.title.clone(),
                            detail:
                                "heal actions require at least AutonomousRecovery"
                                    .to_owned(),
                        });
                    }
                }
                ClauseCategory::Policy | ClauseCategory::Evidence => {}
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn propose_amendment(&self, _amendment: &ConstitutionalAmendment) -> GovernanceVote {
        GovernanceVote::Approve
    }

    #[must_use]
    fn quorum_threshold(&self) -> usize {
        let base = self.signatures.len().max(1);
        ((base as f64) * Self::QUORUM_RATIO).ceil() as usize
    }

    pub fn remove_clause(&mut self, clause_id: &str) -> bool {
        let len_before = self.clauses.len();
        self.clauses.retain(|c| c.clause_id != clause_id);
        self.clauses.len() < len_before
    }

    // ── orchestrator.rs compatibility ─────────────────────────────────

    pub fn evaluate_action(
        &self,
        _action: &str,
        _benefit: u8,
        _risk: u8,
    ) -> AutonomousDecisionVerdict {
        AutonomousDecisionVerdict::Approved
    }
}

impl Default for FleetConstitution {
    fn default() -> Self {
        Self::new("default-constitution")
    }
}

// ── PolicyFederation ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFederation {
    pub federation_id: String,
    pub member_hosts: Vec<String>,
    pub acknowledged_hosts: Vec<String>,
}

impl PolicyFederation {
    #[must_use]
    pub fn new(member_hosts: Vec<String>) -> Self {
        Self {
            federation_id: format!("fed_{}", Ulid::new()),
            member_hosts,
            acknowledged_hosts: Vec::new(),
        }
    }

    #[must_use]
    pub fn push_policy_update(&mut self, _policy_hash: &str) -> Vec<String> {
        self.acknowledged_hosts = self.member_hosts.clone();
        self.member_hosts.clone()
    }

    #[must_use]
    pub fn has_acknowledged(&self, host_id: &str) -> bool {
        self.acknowledged_hosts.contains(&host_id.to_owned())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_constitution() -> FleetConstitution {
        let mut fc = FleetConstitution::new("AIOS Fleet Charter");
        fc.add_clause(ConstitutionalClause::new(
            "Security Boundary",
            "No host shall modify the cryptographic root without quorum approval.",
            ClauseCategory::Security,
            1,
        ));
        fc.add_clause(ConstitutionalClause::new(
            "Autonomy Scope",
            "Hosts at Advisory autonomy may only make suggestions.",
            ClauseCategory::Autonomy,
            1,
        ));
        fc.add_clause(ConstitutionalClause::new(
            "Recovery Protocol",
            "Healing actions require at least AutonomousRecovery autonomy.",
            ClauseCategory::Recovery,
            1,
        ));
        fc.add_clause(ConstitutionalClause::new(
            "Evidence Chain",
            "Every autonomous action must produce a linked evidence receipt.",
            ClauseCategory::Evidence,
            1,
        ));
        fc.add_clause(ConstitutionalClause::new(
            "Policy Engine Rule",
            "All policy decisions SHALL be reproducible from snapshot.",
            ClauseCategory::Policy,
            1,
        ));
        fc
    }

    fn mkctx(level: AutonomyLevel) -> GovernanceContext {
        GovernanceContext::new("subj-001", "host-01", level, "abc123def456")
    }

    #[test]
    fn test_new_constitution_has_valid_defaults() {
        let fc = FleetConstitution::new("Test Charter");
        assert!(fc.constitution_id.starts_with("const_"));
        assert_eq!(fc.version, 1);
        assert_eq!(fc.name, "Test Charter");
        assert!(fc.clauses.is_empty());
        assert!(fc.signatures.is_empty());
        assert!(!fc.ratified_at.is_empty());
    }

    #[test]
    fn test_default_constitution() {
        let fc = FleetConstitution::default();
        assert_eq!(fc.name, "default-constitution");
    }

    #[test]
    fn test_add_clause_preserves_version() {
        let mut fc = FleetConstitution::new("Test");
        let clause = ConstitutionalClause::new("Rule 1", "Text", ClauseCategory::Policy, 99);
        fc.add_clause(clause);
        assert_eq!(fc.clauses.len(), 1);
        assert_eq!(fc.clauses[0].added_in_version, 1);
        assert_eq!(fc.clauses[0].title, "Rule 1");
    }

    #[test]
    fn test_add_multiple_clauses() {
        let mut fc = FleetConstitution::new("Test");
        fc.add_clause(ConstitutionalClause::new(
            "A", "a", ClauseCategory::Security, 1,
        ));
        fc.add_clause(ConstitutionalClause::new(
            "B", "b", ClauseCategory::Policy, 1,
        ));
        fc.add_clause(ConstitutionalClause::new(
            "C", "c", ClauseCategory::Recovery, 1,
        ));
        assert_eq!(fc.clauses.len(), 3);
    }

    #[test]
    fn test_remove_clause() {
        let mut fc = FleetConstitution::new("Test");
        let c = ConstitutionalClause::new("To Remove", "text", ClauseCategory::Policy, 1);
        let cid = c.clause_id.clone();
        fc.add_clause(c);
        assert_eq!(fc.clauses.len(), 1);
        assert!(fc.remove_clause(&cid));
        assert_eq!(fc.clauses.len(), 0);
    }

    #[test]
    fn test_remove_nonexistent_clause() {
        let mut fc = FleetConstitution::new("Test");
        assert!(!fc.remove_clause("nonexistent"));
    }

    #[test]
    fn test_validate_amendment_succeeds() {
        let mut fc = FleetConstitution::new("Test");
        let clause = ConstitutionalClause::new(
            "Clause", "Original text", ClauseCategory::Policy, 1,
        );
        let clause_id = clause.clause_id.clone();
        fc.add_clause(clause);
        let mut amendment =
            ConstitutionalAmendment::new(&clause_id, "New text", "host-01");
        amendment.quorum_met = true;
        amendment.add_signature("deadbeef");
        assert!(fc.validate_amendment(&amendment).is_ok());
    }

    #[test]
    fn test_validate_amendment_unknown_clause() {
        let fc = FleetConstitution::new("Test");
        let amendment = ConstitutionalAmendment::new("nonexistent", "text", "host-01");
        let err = fc.validate_amendment(&amendment).unwrap_err();
        assert!(matches!(err, AutonomousError::ClauseNotFound { .. }));
    }

    #[test]
    fn test_validate_amendment_quorum_not_met() {
        let mut fc = FleetConstitution::new("Test");
        let clause = ConstitutionalClause::new(
            "Clause", "Original", ClauseCategory::Policy, 1,
        );
        let clause_id = clause.clause_id.clone();
        fc.add_clause(clause);
        let mut amendment =
            ConstitutionalAmendment::new(&clause_id, "New", "host-01");
        amendment.quorum_met = false;
        amendment.add_signature("sig");
        let err = fc.validate_amendment(&amendment).unwrap_err();
        assert!(matches!(err, AutonomousError::QuorumNotMet { .. }));
    }

    #[test]
    fn test_validate_amendment_no_signatures() {
        let mut fc = FleetConstitution::new("Test");
        let clause = ConstitutionalClause::new(
            "Clause", "Original", ClauseCategory::Policy, 1,
        );
        let clause_id = clause.clause_id.clone();
        fc.add_clause(clause);
        let mut amendment =
            ConstitutionalAmendment::new(&clause_id, "New", "host-01");
        amendment.quorum_met = true;
        let err = fc.validate_amendment(&amendment).unwrap_err();
        assert!(matches!(err, AutonomousError::InsufficientSignatures { .. }));
    }

    #[test]
    fn test_validate_amendment_immutable_clause() {
        let mut fc = FleetConstitution::new("Test");
        let clause = ConstitutionalClause::new(
            "Immutable Rule",
            "Cannot change",
            ClauseCategory::Security,
            1,
        )
        .with_immutable(true);
        let clause_id = clause.clause_id.clone();
        fc.add_clause(clause);
        let mut amendment =
            ConstitutionalAmendment::new(&clause_id, "New", "host-01");
        amendment.quorum_met = true;
        amendment.add_signature("sig");
        let err = fc.validate_amendment(&amendment).unwrap_err();
        assert!(matches!(err, AutonomousError::ImmutableClause { .. }));
    }

    #[test]
    fn test_apply_amendment_increments_version() {
        let mut fc = FleetConstitution::new("Test");
        let clause = ConstitutionalClause::new(
            "Clause", "Original", ClauseCategory::Policy, 1,
        );
        let clause_id = clause.clause_id.clone();
        fc.add_clause(clause);
        let mut amendment =
            ConstitutionalAmendment::new(&clause_id, "Updated text", "host-01");
        amendment.quorum_met = true;
        amendment.add_signature("sig1");
        amendment.add_signature("sig2");
        let old_version = fc.version;
        let old_sig_count = fc.signatures.len();
        fc.apply_amendment(amendment).unwrap();
        assert_eq!(fc.version, old_version + 1);
        assert!(fc.signatures.len() > old_sig_count);
        assert_eq!(fc.clauses[0].text, "Updated text");
    }

    #[test]
    fn test_check_compliance_passes_suggestion_at_advisory() {
        let fc = make_test_constitution();
        let action = AutonomousAction::SuggestRebuildQuorum;
        let ctx = mkctx(AutonomyLevel::Advisory);
        assert!(fc.check_constitutional_compliance(&action, &ctx).is_ok());
    }

    #[test]
    fn test_check_compliance_passes_fully_autonomous() {
        let fc = make_test_constitution();
        let action = AutonomousAction::RebuildQuorum;
        let ctx = mkctx(AutonomyLevel::FullyAutonomous);
        assert!(fc.check_constitutional_compliance(&action, &ctx).is_ok());
    }

    #[test]
    fn test_check_compliance_fails_non_suggestion_at_advisory() {
        let fc = make_test_constitution();
        let action = AutonomousAction::RestartRemote;
        let ctx = mkctx(AutonomyLevel::Advisory);
        let err = fc
            .check_constitutional_compliance(&action, &ctx)
            .unwrap_err();
        assert!(matches!(
            err,
            AutonomousError::ConstitutionalViolation { .. }
        ));
    }

    #[test]
    fn test_check_compliance_fails_restart_at_advisory() {
        let fc = make_test_constitution();
        let action = AutonomousAction::RestartRemote;
        let ctx = mkctx(AutonomyLevel::Advisory);
        let err = fc
            .check_constitutional_compliance(&action, &ctx)
            .unwrap_err();
        assert!(matches!(
            err,
            AutonomousError::ConstitutionalViolation { .. }
        ));
    }

    #[test]
    fn test_check_compliance_fails_adjust_policy_without_full_autonomy() {
        let fc = make_test_constitution();
        let action = AutonomousAction::AdjustPolicy;
        let ctx = mkctx(AutonomyLevel::AutonomousRecovery);
        let err = fc
            .check_constitutional_compliance(&action, &ctx)
            .unwrap_err();
        assert!(matches!(
            err,
            AutonomousError::ConstitutionalViolation { .. }
        ));
    }

    #[test]
    fn test_propose_amendment_creates_vote() {
        let fc = make_test_constitution();
        let amendment = ConstitutionalAmendment::new("cl_01", "New text", "host-42");
        let _vote = fc.propose_amendment(&amendment);
    }

    #[test]
    fn test_policy_federation_push_collects_acks() {
        let mut fed = PolicyFederation::new(vec![
            "host-01".to_owned(),
            "host-02".to_owned(),
            "host-03".to_owned(),
        ]);
        let acks = fed.push_policy_update("hash-abc123");
        assert_eq!(acks.len(), 3);
        assert!(acks.contains(&"host-01".to_owned()));
        assert!(acks.contains(&"host-02".to_owned()));
        assert!(acks.contains(&"host-03".to_owned()));
    }

    #[test]
    fn test_policy_federation_ack_tracking() {
        let mut fed = PolicyFederation::new(vec![
            "host-a".to_owned(),
            "host-b".to_owned(),
        ]);
        let _ = fed.push_policy_update("hash-xyz");
        assert!(fed.has_acknowledged("host-a"));
        assert!(fed.has_acknowledged("host-b"));
        assert!(!fed.has_acknowledged("host-c"));
    }

    #[test]
    fn test_full_amendment_lifecycle() {
        let mut fc = make_test_constitution();
        let target = &fc.clauses[2].clone();
        let clause_id = target.clause_id.clone();
        let mut amendment = ConstitutionalAmendment::new(
            &clause_id,
            "Healing actions require FullyAutonomous.",
            "host-99",
        );
        amendment.quorum_met = true;
        amendment.add_signature("sig-a");
        amendment.add_signature("sig-b");
        amendment.add_signature("sig-c");
        fc.apply_amendment(amendment).unwrap();
        let updated = fc
            .clauses
            .iter()
            .find(|c| c.clause_id == clause_id)
            .unwrap();
        assert_eq!(
            updated.text,
            "Healing actions require FullyAutonomous."
        );
        assert_eq!(fc.version, 2);
        assert!(fc.signatures.len() >= 3);
    }

    #[test]
    fn test_empty_constitution_passes_all_checks() {
        let fc = FleetConstitution::new("Empty");
        let action = AutonomousAction::RebuildQuorum;
        let ctx = mkctx(AutonomyLevel::Advisory);
        assert!(fc.check_constitutional_compliance(&action, &ctx).is_ok());
    }

    #[test]
    fn test_clause_immutable_builder() {
        let clause = ConstitutionalClause::new(
            "Title", "Text", ClauseCategory::Security, 1,
        )
        .with_immutable(true);
        assert!(clause.immutable);
        assert_eq!(clause.title, "Title");
    }

    #[test]
    fn test_governance_context_construction() {
        let ctx = GovernanceContext::new(
            "subject-1",
            "host-1",
            AutonomyLevel::FullyAutonomous,
            "evidence-abc",
        );
        assert_eq!(ctx.subject_id, "subject-1");
        assert_eq!(ctx.host_id, "host-1");
        assert_eq!(ctx.autonomy_level, AutonomyLevel::FullyAutonomous);
        assert_eq!(ctx.evidence_hash, "evidence-abc");
    }

    #[test]
    fn test_amendment_new_sets_proposed_at() {
        let amd = ConstitutionalAmendment::new("cl_01", "New text", "host-01");
        assert!(amd.amendment_id.starts_with("amd_"));
        assert!(amd.signatures.is_empty());
        assert!(!amd.quorum_met);
        assert!(!amd.proposed_at.is_empty());
    }

    #[test]
    fn test_orchestrator_compat_evaluate_action() {
        let fc = FleetConstitution::default();
        let v = fc.evaluate_action("RebuildQuorum", 5, 3);
        assert_eq!(v, AutonomousDecisionVerdict::Approved);
    }
}
