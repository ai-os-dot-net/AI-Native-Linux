use chrono::Utc;

use crate::error::AutonomousError;
use crate::enums::{
    AutonomousAction, AutonomousDecisionVerdict, AutonomyLevel, FleetHealthAggregate,
};
use crate::governance::FleetConstitution;

#[derive(Debug, Clone)]
pub struct FleetHealthSnapshot {
    pub healthy_count: u32,
    pub degraded_count: u32,
    pub critical_count: u32,
    pub quorum_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutonomyEvidence {
    pub timestamp: chrono::DateTime<Utc>,
    pub action: AutonomousAction,
    pub verdict: AutonomousDecisionVerdict,
}

impl AutonomyEvidence {
    #[must_use]
    pub fn new(action: AutonomousAction, verdict: AutonomousDecisionVerdict) -> Self {
        Self {
            timestamp: Utc::now(),
            action,
            verdict,
        }
    }

    #[must_use]
    pub fn to_evidence_string(&self) -> String {
        format!(
            "[{}] action={:?} verdict={}",
            self.timestamp.to_rfc3339(),
            self.action,
            self.verdict,
        )
    }
}

#[derive(Debug)]
pub struct AutonomyEngine {
    pub fleet_state: FleetHealthAggregate,
    pub autonomy_level: AutonomyLevel,
    pub policy: FleetConstitution,
    pub evidence_log: Vec<AutonomyEvidence>,
}

impl AutonomyEngine {
    #[must_use]
    pub fn new(level: AutonomyLevel) -> Self {
        Self {
            fleet_state: FleetHealthAggregate::Healthy {
                resource_imbalance: false,
            },
            autonomy_level: level,
            policy: FleetConstitution::default(),
            evidence_log: Vec::new(),
        }
    }

    pub fn evaluate_health(snapshot: FleetHealthSnapshot) -> FleetHealthAggregate {
        if !snapshot.quorum_active {
            FleetHealthAggregate::QuorumLost
        } else if snapshot.critical_count > 0 {
            FleetHealthAggregate::Critical
        } else if snapshot.degraded_count > 0 {
            FleetHealthAggregate::Degraded
        } else {
            FleetHealthAggregate::Healthy {
                resource_imbalance: false,
            }
        }
    }

    #[must_use]
    pub fn decide_action(&self, health: FleetHealthAggregate) -> Vec<AutonomousAction> {
        match health {
            FleetHealthAggregate::QuorumLost => vec![AutonomousAction::RebuildQuorum],
            FleetHealthAggregate::Critical => match self.autonomy_level {
                AutonomyLevel::FullyAutonomous => vec![AutonomousAction::RebuildQuorum],
                _ => vec![AutonomousAction::PromoteCoordinator],
            },
            FleetHealthAggregate::Degraded => vec![AutonomousAction::RestartRemote],
            FleetHealthAggregate::Healthy { .. } => vec![],
        }
    }

    pub fn execute_action(
        &mut self,
        action: AutonomousAction,
    ) -> Result<AutonomousDecisionVerdict, AutonomousError> {
        let allowed = match self.autonomy_level {
            AutonomyLevel::Advisory | AutonomyLevel::Assisted => false,
            AutonomyLevel::AutonomousRecovery => matches!(
                action,
                AutonomousAction::RebuildQuorum
                    | AutonomousAction::RestartRemote
                    | AutonomousAction::MigrateWorkload
            ),
            AutonomyLevel::FullyAutonomous => true,
        };

        if !allowed {
            let verdict = AutonomousDecisionVerdict::DeniedAutonomy;
            self.evidence_log
                .push(AutonomyEvidence::new(action, verdict));
            return Err(AutonomousError::AutonomyForbidden {
                level: self.autonomy_level.to_string(),
            });
        }

        self.apply_governance(action)
    }

    #[must_use]
    pub fn run_autonomy_loop(&mut self) -> Vec<AutonomousAction> {
        let actions = self.decide_action(self.fleet_state);
        self.fleet_state = FleetHealthAggregate::Healthy {
            resource_imbalance: false,
        };

        actions
    }

    #[must_use]
    pub fn generate_candidate_actions(&self) -> Vec<AutonomousAction> {
        self.decide_action(self.fleet_state)
    }

    #[must_use]
    pub fn is_recovery_action(&self, action: &AutonomousAction) -> bool {
        matches!(
            action,
            AutonomousAction::RestartRemote
                | AutonomousAction::MigrateWorkload
                | AutonomousAction::FailoverComponent
        )
    }

    pub fn score_action(&self, _action: &AutonomousAction) -> (u8, u8) {
        (5, 3)
    }

    fn apply_governance(
        &mut self,
        action: AutonomousAction,
    ) -> Result<AutonomousDecisionVerdict, AutonomousError> {
        let action_name = format!("{action:?}");
        let gov_verdict = self.policy.evaluate_action(&action_name, 0, 0);
        if gov_verdict == AutonomousDecisionVerdict::Approved {
            self.evidence_log
                .push(AutonomyEvidence::new(action, gov_verdict.clone()));
            Ok(gov_verdict)
        } else {
            self.evidence_log
                .push(AutonomyEvidence::new(action, gov_verdict));
            Err(AutonomousError::GovernanceVeto {
                action: action_name,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_health_quorum_lost() {
        let snap = FleetHealthSnapshot {
            healthy_count: 5,
            degraded_count: 2,
            critical_count: 0,
            quorum_active: false,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::QuorumLost
        );
    }

    #[test]
    fn evaluate_health_critical_any_count() {
        let snap = FleetHealthSnapshot {
            healthy_count: 5,
            degraded_count: 0,
            critical_count: 1,
            quorum_active: true,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::Critical
        );
    }

    #[test]
    fn evaluate_health_degraded_when_degraded_present() {
        let snap = FleetHealthSnapshot {
            healthy_count: 8,
            degraded_count: 3,
            critical_count: 0,
            quorum_active: true,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::Degraded
        );
    }

    #[test]
    fn evaluate_health_healthy_when_none_down() {
        let snap = FleetHealthSnapshot {
            healthy_count: 10,
            degraded_count: 0,
            critical_count: 0,
            quorum_active: true,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::Healthy { resource_imbalance: false }        );
    }

    #[test]
    fn evaluate_health_empty_fleet_is_healthy() {
        let snap = FleetHealthSnapshot {
            healthy_count: 0,
            degraded_count: 0,
            critical_count: 0,
            quorum_active: true,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::Healthy { resource_imbalance: false }        );
    }

    #[test]
    fn evaluate_health_critical_overrides_degraded() {
        let snap = FleetHealthSnapshot {
            healthy_count: 5,
            degraded_count: 10,
            critical_count: 3,
            quorum_active: true,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::Critical
        );
    }

    #[test]
    fn evaluate_health_quorum_lost_overrides_all() {
        let snap = FleetHealthSnapshot {
            healthy_count: 100,
            degraded_count: 50,
            critical_count: 30,
            quorum_active: false,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::QuorumLost
        );
    }

    #[test]
    fn decide_quorum_lost_always_rebuild_quorum() {
        let engine = AutonomyEngine::new(AutonomyLevel::Advisory);
        let actions = engine.decide_action(FleetHealthAggregate::QuorumLost);
        assert_eq!(actions, vec![AutonomousAction::RebuildQuorum]);
    }

    #[test]
    fn decide_quorum_lost_rebuild_regardless_of_level() {
        for level in &[
            AutonomyLevel::Advisory,
            AutonomyLevel::Assisted,
            AutonomyLevel::AutonomousRecovery,
            AutonomyLevel::FullyAutonomous,
        ] {
            let engine = AutonomyEngine::new(*level);
            let actions = engine.decide_action(FleetHealthAggregate::QuorumLost);
            assert_eq!(actions, vec![AutonomousAction::RebuildQuorum]);
        }
    }

    #[test]
    fn decide_critical_fully_autonomous_rebuilds_quorum() {
        let engine = AutonomyEngine::new(AutonomyLevel::FullyAutonomous);
        let actions = engine.decide_action(FleetHealthAggregate::Critical);
        assert_eq!(actions, vec![AutonomousAction::RebuildQuorum]);
    }

    #[test]
    fn decide_critical_advisory_promotes_coordinator() {
        let engine = AutonomyEngine::new(AutonomyLevel::Advisory);
        let actions = engine.decide_action(FleetHealthAggregate::Critical);
        assert_eq!(actions, vec![AutonomousAction::PromoteCoordinator]);
    }

    #[test]
    fn decide_critical_autonomous_recovery_promotes_coordinator() {
        let engine = AutonomyEngine::new(AutonomyLevel::AutonomousRecovery);
        let actions = engine.decide_action(FleetHealthAggregate::Critical);
        assert_eq!(actions, vec![AutonomousAction::PromoteCoordinator]);
    }

    #[test]
    fn decide_degraded_suggests_restart_remote() {
        let engine = AutonomyEngine::new(AutonomyLevel::Advisory);
        let actions = engine.decide_action(FleetHealthAggregate::Degraded);
        assert_eq!(actions, vec![AutonomousAction::RestartRemote]);
    }

    #[test]
    fn decide_healthy_balanced_no_action() {
        let engine = AutonomyEngine::new(AutonomyLevel::FullyAutonomous);
        let actions = engine.decide_action(FleetHealthAggregate::Healthy { resource_imbalance: false });
        assert!(actions.is_empty());
    }

    #[test]
    fn execute_advisory_denies_rebuild_quorum() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::Advisory);
        let result = engine.execute_action(AutonomousAction::RebuildQuorum);
        assert!(result.is_err());
    }

    #[test]
    fn execute_assisted_denies_promote_coordinator() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::Assisted);
        let result = engine.execute_action(AutonomousAction::PromoteCoordinator);
        assert!(result.is_err());
    }

    #[test]
    fn execute_fully_autonomous_approves_rebuild_quorum() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::FullyAutonomous);
        let result = engine.execute_action(AutonomousAction::RebuildQuorum);
        assert_eq!(result.unwrap(), AutonomousDecisionVerdict::Approved);
    }

    #[test]
    fn execute_autonomous_recovery_allows_rebuild_quorum() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::AutonomousRecovery);
        let result = engine.execute_action(AutonomousAction::RebuildQuorum);
        assert_eq!(result.unwrap(), AutonomousDecisionVerdict::Approved);
    }

    #[test]
    fn execute_autonomous_recovery_allows_restart_remote() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::AutonomousRecovery);
        let result = engine.execute_action(AutonomousAction::RestartRemote);
        assert_eq!(result.unwrap(), AutonomousDecisionVerdict::Approved);
    }

    #[test]
    fn execute_autonomous_recovery_allows_migrate_workload() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::AutonomousRecovery);
        let result = engine.execute_action(AutonomousAction::MigrateWorkload);
        assert_eq!(result.unwrap(), AutonomousDecisionVerdict::Approved);
    }

    #[test]
    fn execute_autonomous_recovery_denies_promote_coordinator() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::AutonomousRecovery);
        let result = engine.execute_action(AutonomousAction::PromoteCoordinator);
        assert!(result.is_err());
    }

    #[test]
    fn run_autonomy_loop_returns_decided_actions() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::Advisory);
        engine.fleet_state = FleetHealthAggregate::Degraded;
        let actions = engine.run_autonomy_loop();
        assert_eq!(actions, vec![AutonomousAction::RestartRemote]);
    }

    #[test]
    fn evidence_to_evidence_string_contains_action_and_verdict() {
        let ev = AutonomyEvidence::new(
            AutonomousAction::RebuildQuorum,
            AutonomousDecisionVerdict::Approved,
        );
        let s = ev.to_evidence_string();
        assert!(s.contains("RebuildQuorum"));
        assert!(s.contains("APPROVED"));
        assert!(s.contains(&ev.timestamp.to_rfc3339()));
    }

    #[test]
    fn snapshot_defaults_accessible() {
        let snap = FleetHealthSnapshot {
            healthy_count: 10,
            degraded_count: 0,
            critical_count: 0,
            quorum_active: true,
        };
        assert_eq!(snap.healthy_count, 10);
        assert!(snap.quorum_active);
    }

    #[test]
    fn evidence_log_accumulates_across_multiple_execute_calls() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::FullyAutonomous);
        engine.execute_action(AutonomousAction::RestartRemote).ok();
        engine.execute_action(AutonomousAction::MigrateWorkload).ok();
        assert_eq!(engine.evidence_log.len(), 2);
    }

    #[test]
    fn engine_new_starts_healthy() {
        let engine = AutonomyEngine::new(AutonomyLevel::FullyAutonomous);
        assert_eq!(engine.fleet_state, FleetHealthAggregate::Healthy { resource_imbalance: false });
        assert_eq!(engine.autonomy_level, AutonomyLevel::FullyAutonomous);
        assert!(engine.evidence_log.is_empty());
    }

    #[test]
    fn evidence_action_and_verdict_accessible() {
        let ev = AutonomyEvidence::new(
            AutonomousAction::RebuildQuorum,
            AutonomousDecisionVerdict::Approved,
        );
        assert_eq!(ev.action, AutonomousAction::RebuildQuorum);
        assert_eq!(ev.verdict, AutonomousDecisionVerdict::Approved);
    }

    #[test]
    fn evaluate_health_single_healthy_node() {
        let snap = FleetHealthSnapshot {
            healthy_count: 1,
            degraded_count: 0,
            critical_count: 0,
            quorum_active: true,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::Healthy { resource_imbalance: false }        );
    }

    #[test]
    fn evaluate_health_all_degraded() {
        let snap = FleetHealthSnapshot {
            healthy_count: 0,
            degraded_count: 3,
            critical_count: 0,
            quorum_active: true,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::Degraded
        );
    }

    #[test]
    fn evaluate_health_critical_without_healthy_nodes() {
        let snap = FleetHealthSnapshot {
            healthy_count: 0,
            degraded_count: 0,
            critical_count: 5,
            quorum_active: true,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::Critical
        );
    }

    #[test]
    fn execute_advisory_evidence_logged_on_denial() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::Advisory);
        let _ = engine.execute_action(AutonomousAction::RebuildQuorum);
        assert_eq!(engine.evidence_log.len(), 1);
        assert_eq!(
            engine.evidence_log[0].verdict,
            AutonomousDecisionVerdict::DeniedAutonomy
        );
    }

    #[test]
    fn run_autonomy_loop_resets_to_healthy_after_run() {
        let mut engine = AutonomyEngine::new(AutonomyLevel::FullyAutonomous);
        engine.fleet_state = FleetHealthAggregate::Critical;
        let _ = engine.run_autonomy_loop();
        assert_eq!(engine.fleet_state, FleetHealthAggregate::Healthy { resource_imbalance: false });
    }

    #[test]
    fn evaluate_health_degraded_single_node() {
        let snap = FleetHealthSnapshot {
            healthy_count: 0,
            degraded_count: 1,
            critical_count: 0,
            quorum_active: true,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::Degraded
        );
    }

    #[test]
    fn evaluate_health_critical_with_mixed_state() {
        let snap = FleetHealthSnapshot {
            healthy_count: 10,
            degraded_count: 5,
            critical_count: 2,
            quorum_active: true,
        };
        assert_eq!(
            AutonomyEngine::evaluate_health(snap),
            FleetHealthAggregate::Critical
        );
    }

    #[test]
    fn decide_degraded_fully_autonomous_suggests_restart() {
        let engine = AutonomyEngine::new(AutonomyLevel::FullyAutonomous);
        let actions = engine.decide_action(FleetHealthAggregate::Degraded);
        assert_eq!(actions, vec![AutonomousAction::RestartRemote]);
    }
}
