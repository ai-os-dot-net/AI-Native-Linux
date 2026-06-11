//! AIOS Rev.10 — Master Orchestrator Daemon

use crate::enums::{AutonomousDecisionVerdict, FleetHealthAggregate, OrchestratorMode};
use crate::AutonomyEngine;
use crate::CrossMachineHealing;
use crate::FleetConstitution;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct OrchestratorReport {
    pub cycle_number: u64,
    pub mode: OrchestratorMode,
    pub fleet_health: String,
    pub actions_evaluated: u32,
    pub actions_executed: u32,
    pub actions_blocked: u32,
    pub duration_ms: u64,
    pub errors: Vec<String>,
}

impl OrchestratorReport {
    pub fn empty() -> Self {
        Self { cycle_number: 0, mode: OrchestratorMode::Disabled, fleet_health: "N/A".into(),
            actions_evaluated: 0, actions_executed: 0, actions_blocked: 0, duration_ms: 0, errors: vec![] }
    }
}

fn fleet_health_from_str(s: &str) -> FleetHealthAggregate {
    match s {
        "Healthy" => FleetHealthAggregate::Healthy { resource_imbalance: false },
        "Degraded" => FleetHealthAggregate::Degraded,
        "Critical" => FleetHealthAggregate::Critical,
        "QuorumLost" => FleetHealthAggregate::QuorumLost,
        _ => FleetHealthAggregate::Healthy { resource_imbalance: false },
    }
}

fn autonomy_level_from_mode(mode: OrchestratorMode) -> crate::enums::AutonomyLevel {
    use crate::enums::AutonomyLevel;
    match mode {
        OrchestratorMode::Disabled | OrchestratorMode::MonitorOnly => AutonomyLevel::Assisted,
        OrchestratorMode::Suggest => AutonomyLevel::Advisory,
        OrchestratorMode::ExecuteRecovery => AutonomyLevel::AutonomousRecovery,
        OrchestratorMode::FullAutonomy => AutonomyLevel::FullyAutonomous,
    }
}

pub struct AutonomousOrchestrator {
    mode: OrchestratorMode,
    autonomy_engine: AutonomyEngine,
    healing: CrossMachineHealing,
    constitution: FleetConstitution,
    run_interval_secs: u64,
    consecutive_cycles: u64,
    last_cycle_at: String,
    paused: bool,
}

impl AutonomousOrchestrator {
    pub fn new(mode: OrchestratorMode) -> Self {
        let level = autonomy_level_from_mode(mode);
        Self { mode, autonomy_engine: AutonomyEngine::new(level), healing: CrossMachineHealing::new(),
            constitution: FleetConstitution::default(), run_interval_secs: 30, consecutive_cycles: 0,
            last_cycle_at: String::new(), paused: false }
    }

    pub fn cycle(&mut self) -> OrchestratorReport {
        let started_at = Instant::now();
        if self.paused || self.mode == OrchestratorMode::Disabled {
            let report = OrchestratorReport { cycle_number: self.consecutive_cycles, mode: self.mode,
                fleet_health: String::new(), duration_ms: started_at.elapsed().as_millis() as u64,
                ..OrchestratorReport::empty() };
            self.consecutive_cycles = self.consecutive_cycles.wrapping_add(1);
            return report;
        }
        let fleet_health = self.healing.fleet_health();
        let health_agg = fleet_health_from_str(&fleet_health);
        self.autonomy_engine.fleet_state = health_agg;

        let candidate_actions = self.autonomy_engine.run_autonomy_loop();

        if self.mode == OrchestratorMode::MonitorOnly {
            let report = OrchestratorReport { cycle_number: self.consecutive_cycles, mode: self.mode,
                fleet_health, actions_evaluated: candidate_actions.len() as u32,
                duration_ms: started_at.elapsed().as_millis() as u64, ..OrchestratorReport::empty() };
            self.consecutive_cycles = self.consecutive_cycles.wrapping_add(1);
            return report;
        }

        let mut actions_evaluated: u32 = 0;
        let mut actions_executed: u32 = 0;
        let mut actions_blocked: u32 = 0;
        let mut errors: Vec<String> = vec![];

        for action in &candidate_actions {
            actions_evaluated += 1;
            let result = self.autonomy_engine.execute_action(action.clone());
            match result {
                Ok(verdict) if verdict == AutonomousDecisionVerdict::Approved => {
                    actions_executed += 1;
                }
                Ok(_) => {
                    actions_blocked += 1;
                    errors.push(format!("action '{action:?}' blocked: unexpected verdict"));
                }
                Err(e) => {
                    actions_blocked += 1;
                    errors.push(format!("action '{action:?}' denied: {e}"));
                }
            }
        }

        let duration_ms = started_at.elapsed().as_millis() as u64;
        let report = OrchestratorReport { cycle_number: self.consecutive_cycles, mode: self.mode,
            fleet_health, actions_evaluated, actions_executed, actions_blocked, duration_ms, errors };

        self.last_cycle_at = chrono::Utc::now().to_rfc3339();
        self.consecutive_cycles = self.consecutive_cycles.wrapping_add(1);
        report
    }

    pub fn set_mode(&mut self, mode: OrchestratorMode) {
        self.mode = mode;
        self.autonomy_engine.autonomy_level = autonomy_level_from_mode(mode);
    }
    pub fn get_mode(&self) -> OrchestratorMode { self.mode }
    pub fn pause(&mut self) { self.paused = true; }
    pub fn resume(&mut self) { self.paused = false; }
    pub fn is_paused(&self) -> bool { self.paused }
    pub fn consecutive_cycles_count(&self) -> u64 { self.consecutive_cycles }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn disabled_mode_noops() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::Disabled);let r=o.cycle();assert_eq!(r.actions_evaluated,0);assert_eq!(r.actions_executed,0); }
    #[test] fn monitor_only_observes() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::MonitorOnly);let r=o.cycle();assert_eq!(r.actions_executed,0);assert!(!r.fleet_health.is_empty()); }
    #[test] fn suggest_mode_returns_suggestions() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::Suggest);let r=o.cycle();assert_eq!(r.actions_executed,0); }
    #[test] fn execute_recovery_allows_recovery_actions() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::ExecuteRecovery);let r=o.cycle();assert_eq!(r.actions_executed,0); }
    #[test] fn full_autonomy_allows_all() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::FullAutonomy);let r=o.cycle();assert!(r.errors.is_empty()); }
    #[test] fn consecutive_cycles_increment() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::FullAutonomy);assert_eq!(o.consecutive_cycles_count(),0);o.cycle();assert_eq!(o.consecutive_cycles_count(),1);o.cycle();assert_eq!(o.consecutive_cycles_count(),2); }
    #[test] fn pause_stops_cycle_execution() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::FullAutonomy);assert!(!o.is_paused());o.pause();assert!(o.is_paused());let r=o.cycle();assert_eq!(r.actions_evaluated,0); }
    #[test] fn resume_re_enables_cycle_execution() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::FullAutonomy);o.pause();o.cycle();o.resume();assert!(!o.is_paused());let r=o.cycle();assert_eq!(r.mode,OrchestratorMode::FullAutonomy); }
    #[test] fn is_paused_persists() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::FullAutonomy);o.pause();o.cycle();o.cycle();o.cycle();assert!(o.is_paused()); }
    #[test] fn report_structure_validation() { let r=OrchestratorReport{cycle_number:7,mode:OrchestratorMode::ExecuteRecovery,fleet_health:"Degraded".into(),actions_evaluated:12,actions_executed:3,actions_blocked:9,duration_ms:145,errors:vec!["test".into()]};assert_eq!(r.cycle_number,7);assert_eq!(r.actions_evaluated,12);assert_eq!(r.errors.len(),1); }
    #[test] fn empty_report_all_zero() { let r=OrchestratorReport::empty();assert_eq!(r.cycle_number,0);assert_eq!(r.actions_evaluated,0); }
    #[test] fn set_mode_changes_mode() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::Disabled);o.set_mode(OrchestratorMode::FullAutonomy);assert_eq!(o.get_mode(),OrchestratorMode::FullAutonomy); }
    #[test] fn get_mode_returns_initial() { assert_eq!(AutonomousOrchestrator::new(OrchestratorMode::Suggest).get_mode(),OrchestratorMode::Suggest); }
    #[test] fn is_paused_false_after_new() { assert!(!AutonomousOrchestrator::new(OrchestratorMode::FullAutonomy).is_paused()); }
    #[test] fn consecutive_cycles_starts_at_zero() { assert_eq!(AutonomousOrchestrator::new(OrchestratorMode::FullAutonomy).consecutive_cycles_count(),0); }
    #[test] fn disabled_mode_still_counts_cycles() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::Disabled);o.cycle();assert_eq!(o.consecutive_cycles_count(),1); }
    #[test] fn paused_still_counts_cycles() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::FullAutonomy);o.pause();o.cycle();assert_eq!(o.consecutive_cycles_count(),1); }
    #[test] fn disabled_report_has_timing() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::Disabled);assert!(o.cycle().duration_ms<50); }
    #[test] fn monitor_only_report_includes_health() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::MonitorOnly);assert_eq!(o.cycle().fleet_health,"Unknown"); }
    #[test] fn suggest_report_zero_executed() { let mut o=AutonomousOrchestrator::new(OrchestratorMode::Suggest);assert_eq!(o.cycle().actions_executed,0); }
}
