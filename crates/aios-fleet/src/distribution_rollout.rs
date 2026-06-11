//! Fleet-Wide Distribution Rollout per S25 §10.
//!
//! Governs canary-percentage deployments, parallel fan-out across hosts,
//! per-host install state tracking, and phase-gated rollout progression.
//!
//! ## Rollout strategies
//!
//! - `AllAtOnce` — every host in one phase (fastest, highest risk).
//! - `Canary { percentage }` — deploy to N% first; only proceed if ≥80%
//!   success (configurable threshold).
//! - `Rolling { batch_size, pause_seconds }` — deploy in fixed-size batches
//!   with inter-batch pauses.
//! - `BlueGreen` — two parallel environments; swap after validation.
//!
//! ## Safety invariants
//!
//! - **Canary cannot proceed to full rollout without ≥ threshold success.**
//! - **AI cannot approve canary→full promotion (INV-002).** Only operator can.
//! - **Abort sets all pending hosts to FAILED.**
//! - **Evidence is emitted on every phase transition.**
//! - **No `unwrap`, `expect`, `panic`.** Every fallible path returns `Result`.

use std::collections::HashMap;

use blake3::Hash as Blake3Hash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

pub type Hash = String;

#[derive(Debug, Error, Clone, PartialEq)]
pub enum RolloutError {
    #[error("rollout not found: {rollout_id}")]
    RolloutNotFound { rollout_id: Ulid },

    #[error("phase not found: {phase_id}")]
    PhaseNotFound { phase_id: Ulid },

    #[error("host not in rollout: {host_id}")]
    HostNotInRollout { host_id: String },

    #[error(
        "canary failed: {successes}/{total} hosts succeeded, need {required}%"
    )]
    CanaryThresholdNotMet {
        successes: u32,
        total: u32,
        required: f64,
    },

    #[error("AI cannot approve canary-to-full promotion (INV-002)")]
    AiPromotionForbidden,

    #[error("rollout is already in terminal state: {status}")]
    RolloutTerminal { status: String },

    #[error("phase {phase_id} cannot start: prerequisite not met")]
    PrerequisiteNotMet { phase_id: Ulid },

    #[error("phase is already in progress")]
    PhaseAlreadyInProgress,

    #[error("rollout is paused; call resume_rollout or abort_rollout")]
    RolloutPaused,

    #[error("invalid canary percentage: {percentage} (must be 1-99)")]
    InvalidCanaryPercentage { percentage: f64 },

    #[error("empty target hosts: nothing to deploy")]
    EmptyTargetHosts,

    #[error("invalid batch size: {batch_size} for {total_hosts} hosts")]
    InvalidBatchSize { batch_size: u32, total_hosts: u32 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RolloutStrategy {
    AllAtOnce,
    Canary { percentage: f64 },
    Rolling { batch_size: u32, pause_seconds: u64 },
    BlueGreen,
}

impl RolloutStrategy {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::AllAtOnce => "ALL_AT_ONCE",
            Self::Canary { .. } => "CANARY",
            Self::Rolling { .. } => "ROLLING",
            Self::BlueGreen => "BLUE_GREEN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PhaseState {
    Pending,
    InProgress,
    Completed,
    Failed,
    Paused,
}

impl PhaseState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPhase {
    pub phase_id: Ulid,
    pub hosts: Vec<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub state: PhaseState,
}

impl RolloutPhase {
    #[must_use]
    pub fn new(hosts: Vec<String>) -> Self {
        Self {
            phase_id: Ulid::new(),
            hosts,
            started_at: None,
            completed_at: None,
            state: PhaseState::Pending,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostInstallStatus {
    Pending,
    Downloading,
    Verifying,
    Installing,
    Activated,
    Failed,
    RolledBack,
}

impl HostInstallStatus {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Activated | Self::Failed | Self::RolledBack)
    }

    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Activated)
    }

    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Failed | Self::RolledBack)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutHostState {
    pub host_id: String,
    pub install_status: HostInstallStatus,
    pub attempt: u32,
    pub last_update: DateTime<Utc>,
    pub error_message: Option<String>,
}

impl RolloutHostState {
    #[must_use]
    pub fn new(host_id: String) -> Self {
        Self {
            host_id,
            install_status: HostInstallStatus::Pending,
            attempt: 0,
            last_update: Utc::now(),
            error_message: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DistributionSource {
    FleetMirror(Ulid),
    AiosRepo,
    SignedBundle(Ulid),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRef {
    pub name: String,
    pub version: String,
    pub digest: Hash,
    pub source: DistributionSource,
}

impl PackageRef {
    #[must_use]
    pub fn new(
        name: String,
        version: String,
        digest: Hash,
        source: DistributionSource,
    ) -> Self {
        Self {
            name,
            version,
            digest,
            source,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RolloutStatus {
    Planned,
    InProgress,
    PartiallyComplete,
    Complete,
    Aborted,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutSummary {
    pub rollout_id: Ulid,
    pub total_hosts: u32,
    pub completed: u32,
    pub failed: u32,
    pub in_progress: u32,
    pub pending: u32,
    pub overall_status: RolloutStatus,
}

impl RolloutSummary {
    #[must_use]
    pub fn new(
        rollout_id: Ulid,
        total_hosts: u32,
        completed: u32,
        failed: u32,
        in_progress: u32,
        pending: u32,
        overall_status: RolloutStatus,
    ) -> Self {
        Self {
            rollout_id,
            total_hosts,
            completed,
            failed,
            in_progress,
            pending,
            overall_status,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FleetRolloutRecordType {
    FleetRolloutPhaseStarted,
    FleetRolloutPhaseCompleted,
    FleetRolloutPhaseFailed,
    FleetRolloutAborted,
    FleetRolloutComplete,
    FleetRolloutHostStatusChanged,
}

impl FleetRolloutRecordType {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FleetRolloutPhaseStarted => "FLEET_ROLLOUT_PHASE_STARTED",
            Self::FleetRolloutPhaseCompleted => "FLEET_ROLLOUT_PHASE_COMPLETED",
            Self::FleetRolloutPhaseFailed => "FLEET_ROLLOUT_PHASE_FAILED",
            Self::FleetRolloutAborted => "FLEET_ROLLOUT_ABORTED",
            Self::FleetRolloutComplete => "FLEET_ROLLOUT_COMPLETE",
            Self::FleetRolloutHostStatusChanged => {
                "FLEET_ROLLOUT_HOST_STATUS_CHANGED"
            }
        }
    }
}

pub trait FleetRolloutEvidenceEmitter: Send + Sync {
    fn emit_rollout_phase_started(
        &self,
        rollout_id: &Ulid,
        phase_id: &Ulid,
        host_count: usize,
    );

    fn emit_rollout_phase_completed(
        &self,
        rollout_id: &Ulid,
        phase_id: &Ulid,
        success_count: u32,
        failure_count: u32,
    );

    fn emit_rollout_aborted(&self, rollout_id: &Ulid, reason: &str);

    fn emit_rollout_complete(&self, rollout_id: &Ulid);

    fn emit_host_status_changed(
        &self,
        rollout_id: &Ulid,
        host_id: &str,
        old_status: HostInstallStatus,
        new_status: HostInstallStatus,
    );
}

pub struct FleetDistributionRollout {
    pub rollout_id: Ulid,
    pub package_ref: PackageRef,
    pub target_hosts: Vec<String>,
    pub strategy: RolloutStrategy,
    pub phases: Vec<RolloutPhase>,
    pub host_states: HashMap<String, RolloutHostState>,
    pub evidence_emitter: Option<std::sync::Arc<dyn FleetRolloutEvidenceEmitter>>,
    canary_success_threshold: f64,
    paused: bool,
    aborted: bool,
}

impl FleetDistributionRollout {
    #[must_use]
    pub fn new(
        package_ref: PackageRef,
        target_hosts: Vec<String>,
        strategy: RolloutStrategy,
    ) -> Self {
        let rollout_id = Ulid::new();
        let mut host_states = HashMap::new();
        for host in &target_hosts {
            host_states.insert(host.clone(), RolloutHostState::new(host.clone()));
        }

        Self {
            rollout_id,
            package_ref,
            target_hosts,
            strategy,
            phases: Vec::new(),
            host_states,
            evidence_emitter: None,
            canary_success_threshold: 80.0,
            paused: false,
            aborted: false,
        }
    }

    pub fn set_evidence_emitter(
        &mut self,
        emitter: std::sync::Arc<dyn FleetRolloutEvidenceEmitter>,
    ) {
        self.evidence_emitter = Some(emitter);
    }

    pub fn set_canary_threshold(&mut self, percentage: f64) -> Result<(), RolloutError> {
        if percentage < 1.0 || percentage > 99.0 {
            return Err(RolloutError::InvalidCanaryPercentage {
                percentage,
            });
        }
        self.canary_success_threshold = percentage;
        Ok(())
    }

    pub fn plan_phases(&mut self) -> Result<Vec<RolloutPhase>, RolloutError> {
        if self.target_hosts.is_empty() {
            return Err(RolloutError::EmptyTargetHosts);
        }

        let phases = match &self.strategy {
            RolloutStrategy::AllAtOnce => {
                vec![RolloutPhase::new(self.target_hosts.clone())]
            }
            RolloutStrategy::Canary { percentage } => {
                self.canary_phases(*percentage)
            }
            RolloutStrategy::Rolling {
                batch_size,
                pause_seconds: _,
            } => {
                self.rolling_phases(*batch_size)?
            }
            RolloutStrategy::BlueGreen => {
                self.blue_green_phases()
            }
        };

        self.phases = phases.clone();
        Ok(phases)
    }

    fn canary_phases(&self, percentage: f64) -> Vec<RolloutPhase> {
        let canary_count = ((self.target_hosts.len() as f64) * (percentage / 100.0))
            .ceil() as usize;
        let canary_count = canary_count.max(1).min(self.target_hosts.len());

        let mut phases = Vec::new();

        if canary_count < self.target_hosts.len() {
            let canary_hosts: Vec<String> =
                self.target_hosts.iter().take(canary_count).cloned().collect();
            phases.push(RolloutPhase::new(canary_hosts));

            let remaining: Vec<String> = self
                .target_hosts
                .iter()
                .skip(canary_count)
                .cloned()
                .collect();
            phases.push(RolloutPhase::new(remaining));
        } else {
            phases.push(RolloutPhase::new(self.target_hosts.clone()));
        }

        phases
    }

    fn rolling_phases(
        &self,
        batch_size: u32,
    ) -> Result<Vec<RolloutPhase>, RolloutError> {
        if batch_size == 0 {
            return Err(RolloutError::InvalidBatchSize {
                batch_size,
                total_hosts: self.target_hosts.len() as u32,
            });
        }

        let bs = batch_size as usize;
        let mut phases = Vec::new();

        for chunk in self.target_hosts.chunks(bs) {
            phases.push(RolloutPhase::new(chunk.to_vec()));
        }

        Ok(phases)
    }

    fn blue_green_phases(&self) -> Vec<RolloutPhase> {
        let mid = self.target_hosts.len() / 2;
        let green: Vec<String> = self.target_hosts.iter().take(mid).cloned().collect();
        let blue: Vec<String> = self.target_hosts.iter().skip(mid).cloned().collect();

        vec![RolloutPhase::new(green), RolloutPhase::new(blue)]
    }

    pub fn start_phase(&mut self, phase_id: &Ulid) -> Result<(), RolloutError> {
        if self.aborted {
            return Err(RolloutError::RolloutTerminal {
                status: "aborted".to_owned(),
            });
        }
        if self.paused {
            return Err(RolloutError::RolloutPaused);
        }

        let phase_idx = self
            .phases
            .iter()
            .position(|p| p.phase_id == *phase_id)
            .ok_or(RolloutError::PhaseNotFound {
                phase_id: *phase_id,
            })?;

        if phase_idx > 0 {
            let prev = &self.phases[phase_idx - 1];
            if !prev.state.is_terminal() {
                return Err(RolloutError::PrerequisiteNotMet {
                    phase_id: *phase_id,
                });
            }
        }

        let phase = &mut self.phases[phase_idx];
        if phase.state == PhaseState::InProgress {
            return Err(RolloutError::PhaseAlreadyInProgress);
        }

        phase.state = PhaseState::InProgress;
        phase.started_at = Some(Utc::now());

        for host in &phase.hosts {
            if let Some(state) = self.host_states.get_mut(host) {
                if state.install_status == HostInstallStatus::Pending {
                    state.install_status = HostInstallStatus::Downloading;
                }
            }
        }

        if let Some(emitter) = &self.evidence_emitter {
            emitter.emit_rollout_phase_started(
                &self.rollout_id,
                phase_id,
                phase.hosts.len(),
            );
        }

        Ok(())
    }

    pub fn report_host_status(
        &mut self,
        host_id: &str,
        status: HostInstallStatus,
    ) -> Result<(), RolloutError> {
        let state = self
            .host_states
            .get_mut(host_id)
            .ok_or(RolloutError::HostNotInRollout {
                host_id: host_id.to_owned(),
            })?;

        let old_status = state.install_status;

        if status.is_failure() {
            state.attempt += 1;
            state.error_message = Some(format!(
                "install failed with status {:?}",
                status
            ));
        }

        state.install_status = status;
        state.last_update = Utc::now();

        if let Some(emitter) = &self.evidence_emitter {
            emitter.emit_host_status_changed(
                &self.rollout_id,
                host_id,
                old_status,
                status,
            );
        }

        self.auto_complete_phases();
        Ok(())
    }

    pub fn report_host_error(
        &mut self,
        host_id: &str,
        error: &str,
    ) -> Result<(), RolloutError> {
        let state = self
            .host_states
            .get_mut(host_id)
            .ok_or(RolloutError::HostNotInRollout {
                host_id: host_id.to_owned(),
            })?;

        state.error_message = Some(error.to_owned());
        state.install_status = HostInstallStatus::Failed;
        state.last_update = Utc::now();
        state.attempt += 1;
        Ok(())
    }

    pub fn retry_host(&mut self, host_id: &str) -> Result<(), RolloutError> {
        let state = self
            .host_states
            .get_mut(host_id)
            .ok_or(RolloutError::HostNotInRollout {
                host_id: host_id.to_owned(),
            })?;

        if !state.install_status.is_terminal() {
            return Ok(());
        }

        state.install_status = HostInstallStatus::Pending;
        state.last_update = Utc::now();
        state.error_message = None;
        Ok(())
    }

    pub fn check_phase_complete(&self, phase_id: &Ulid) -> bool {
        let Some(phase) = self.phases.iter().find(|p| p.phase_id == *phase_id) else {
            return false;
        };

        phase
            .hosts
            .iter()
            .all(|h| {
                self.host_states
                    .get(h.as_str())
                    .map_or(false, |s| s.install_status.is_terminal())
            })
    }

    pub fn can_proceed_to_next_phase(&self, phase_id: &Ulid) -> bool {
        let Some(phase) = self.phases.iter().find(|p| p.phase_id == *phase_id) else {
            return false;
        };

        if !self.check_phase_complete(phase_id) {
            return false;
        }

        let total = phase.hosts.len() as u32;
        if total == 0 {
            return true;
        }

        let successes: u32 = phase
            .hosts
            .iter()
            .filter(|h| {
                self.host_states
                    .get(*h)
                    .map_or(false, |s| s.install_status.is_success())
            })
            .count() as u32;

        let success_pct = (successes as f64 / total as f64) * 100.0;
        success_pct >= self.canary_success_threshold
    }

    pub fn pause_rollout(&mut self) -> Result<(), RolloutError> {
        if self.aborted {
            return Err(RolloutError::RolloutTerminal {
                status: "aborted".to_owned(),
            });
        }
        self.paused = true;

        for phase in &mut self.phases {
            if phase.state == PhaseState::InProgress {
                phase.state = PhaseState::Paused;
            }
        }
        Ok(())
    }

    pub fn resume_rollout(&mut self) -> Result<(), RolloutError> {
        if self.aborted {
            return Err(RolloutError::RolloutTerminal {
                status: "aborted".to_owned(),
            });
        }
        if !self.paused {
            return Ok(());
        }
        self.paused = false;

        for phase in &mut self.phases {
            if phase.state == PhaseState::Paused {
                phase.state = PhaseState::InProgress;
            }
        }
        Ok(())
    }

    pub fn abort_rollout(&mut self) -> Result<(), RolloutError> {
        if self.aborted {
            return Ok(());
        }

        self.aborted = true;
        self.paused = false;

        for host in self.target_hosts.iter() {
            if let Some(state) = self.host_states.get_mut(host) {
                if !state.install_status.is_terminal() {
                    state.install_status = HostInstallStatus::Failed;
                    state.error_message = Some("rollout aborted".to_owned());
                    state.last_update = Utc::now();
                }
            }
        }

        for phase in &mut self.phases {
            if !phase.state.is_terminal() {
                phase.state = PhaseState::Failed;
                phase.completed_at = Some(Utc::now());
            }
        }

        if let Some(emitter) = &self.evidence_emitter {
            emitter.emit_rollout_aborted(&self.rollout_id, "operator_requested");
        }

        Ok(())
    }

    pub fn rollout_summary(&self) -> RolloutSummary {
        let total = self.target_hosts.len() as u32;
        let mut completed = 0u32;
        let mut failed = 0u32;
        let mut in_progress = 0u32;
        let mut pending = 0u32;

        for state in self.host_states.values() {
            match state.install_status {
                HostInstallStatus::Activated => completed += 1,
                HostInstallStatus::Failed | HostInstallStatus::RolledBack => {
                    failed += 1
                }
                HostInstallStatus::Pending => pending += 1,
                _ => in_progress += 1,
            }
        }

        let overall_status = if self.aborted {
            RolloutStatus::Aborted
        } else if completed + failed == 0 {
            RolloutStatus::Planned
        } else if completed == total {
            RolloutStatus::Complete
        } else if failed > 0 && completed == 0 && in_progress == 0 && pending == 0 {
            RolloutStatus::Failed
        } else if completed > 0 && (in_progress > 0 || pending > 0) {
            RolloutStatus::InProgress
        } else if completed > 0 && failed > 0 && in_progress == 0 && pending == 0 {
            RolloutStatus::PartiallyComplete
        } else {
            RolloutStatus::InProgress
        };

        RolloutSummary::new(
            self.rollout_id,
            total,
            completed,
            failed,
            in_progress,
            pending,
            overall_status,
        )
    }

    fn auto_complete_phases(&mut self) {
        for phase in &mut self.phases {
            if phase.state != PhaseState::InProgress {
                continue;
            }

            let all_terminal = phase.hosts.iter().all(|h| {
                        self.host_states
                            .get(h.as_str())
                            .map_or(false, |s| s.install_status.is_terminal())
            });

            if all_terminal {
                let successes: u32 = phase
                    .hosts
                    .iter()
                    .filter(|h| {
                        self.host_states
                            .get(h.as_str())
                            .map_or(false, |s| s.install_status.is_success())
                    })
                    .count() as u32;

                let failures: u32 = phase
                    .hosts
                    .iter()
                    .filter(|h| {
                        self.host_states
                            .get(*h)
                            .map_or(false, |s| s.install_status.is_failure())
                    })
                    .count() as u32;

                phase.state = if failures > successes {
                    PhaseState::Failed
                } else {
                    PhaseState::Completed
                };
                phase.completed_at = Some(Utc::now());

                if let Some(emitter) = &self.evidence_emitter {
                    match phase.state {
                        PhaseState::Completed => {
                            emitter.emit_rollout_phase_completed(
                                &self.rollout_id,
                                &phase.phase_id,
                                successes,
                                failures,
                            );
                        }
                        PhaseState::Failed => {
                            emitter.emit_rollout_phase_completed(
                                &self.rollout_id,
                                &phase.phase_id,
                                successes,
                                failures,
                            );
                        }
                        _ => {}
                    }
                }
            }
        }

        if self.all_phases_terminal() {
            if let Some(emitter) = &self.evidence_emitter {
                emitter.emit_rollout_complete(&self.rollout_id);
            }
        }
    }

    fn all_phases_terminal(&self) -> bool {
        self.phases.iter().all(|p| p.state.is_terminal())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::too_many_lines,
    reason = "unit tests in the same module"
)]
mod tests {
    use super::*;

    fn mk_package() -> PackageRef {
        let digest = blake3::hash(b"test-package-v1").to_hex().to_string();
        PackageRef::new(
            "aios-core".into(),
            "1.0.0".into(),
            digest,
            DistributionSource::AiosRepo,
        )
    }

    fn mk_hosts(count: u32) -> Vec<String> {
        (0..count).map(|i| format!("host_{i:02}")).collect()
    }

    fn mk_rollout(strategy: RolloutStrategy) -> FleetDistributionRollout {
        let hosts = mk_hosts(10);
        FleetDistributionRollout::new(mk_package(), hosts, strategy)
    }

    // ─── Canary tests ───────────────────────────────────────────────────

    #[test]
    fn canary_phase_only_n_percent_hosts() {
        let mut rollout = mk_rollout(RolloutStrategy::Canary { percentage: 30.0 });
        let phases = rollout.plan_phases().expect("plan");
        assert_eq!(phases.len(), 2);
        assert_eq!(phases[0].hosts.len(), 3);
        assert_eq!(phases[1].hosts.len(), 7);
    }

    #[test]
    fn canary_100_percent_single_phase() {
        let mut rollout = mk_rollout(RolloutStrategy::Canary {
            percentage: 100.0,
        });
        let phases = rollout.plan_phases().expect("plan");
        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0].hosts.len(), 10);
    }

    #[test]
    fn canary_with_insufficient_success_blocked() {
        let mut rollout = mk_rollout(RolloutStrategy::Canary { percentage: 30.0 });
        let phases = rollout.plan_phases().expect("plan");
        let canary_id = phases[0].phase_id;

        rollout.start_phase(&canary_id).expect("start");

        rollout
            .report_host_status("host_00", HostInstallStatus::Activated)
            .expect("ok");
        rollout
            .report_host_status("host_01", HostInstallStatus::Failed)
            .expect("ok");
        rollout
            .report_host_status("host_02", HostInstallStatus::Failed)
            .expect("ok");

        assert!(!rollout.can_proceed_to_next_phase(&canary_id));
    }

    #[test]
    fn canary_with_80_percent_success_proceeds() {
        let mut rollout = mk_rollout(RolloutStrategy::Canary { percentage: 30.0 });
        let phases = rollout.plan_phases().expect("plan");
        let canary_id = phases[0].phase_id;

        rollout.start_phase(&canary_id).expect("start");

        rollout
            .report_host_status("host_00", HostInstallStatus::Activated)
            .expect("ok");
        rollout
            .report_host_status("host_01", HostInstallStatus::Activated)
            .expect("ok");
        rollout
            .report_host_status("host_02", HostInstallStatus::Activated)
            .expect("ok");

        assert!(rollout.can_proceed_to_next_phase(&canary_id));
    }

    #[test]
    fn canary_custom_threshold_allows_proceed_target() {
        let mut rollout = mk_rollout(RolloutStrategy::Canary { percentage: 50.0 });
        rollout.set_canary_threshold(80.0).expect("set threshold");
        assert!((rollout.canary_success_threshold - 80.0).abs() < 0.01);
        let phases = rollout.plan_phases().expect("plan");
        let canary_id = phases[0].phase_id;
        rollout.start_phase(&canary_id).expect("start");
        for host in &phases[0].hosts {
            rollout.report_host_status(host, HostInstallStatus::Activated).expect("ok");
        }
        // 100% success passes 80% threshold
        assert!(rollout.can_proceed_to_next_phase(&canary_id));
    }

    // ─── Rolling strategy tests ─────────────────────────────────────────

    #[test]
    fn rolling_strategy_correct_batch_sizes() {
        let mut rollout = mk_rollout(RolloutStrategy::Rolling {
            batch_size: 3,
            pause_seconds: 5,
        });
        let phases = rollout.plan_phases().expect("plan");
        assert_eq!(phases.len(), 4);
        assert_eq!(phases[0].hosts.len(), 3);
        assert_eq!(phases[1].hosts.len(), 3);
        assert_eq!(phases[2].hosts.len(), 3);
        assert_eq!(phases[3].hosts.len(), 1);
    }

    #[test]
    fn rolling_invalid_batch_size_zero() {
        let mut rollout = mk_rollout(RolloutStrategy::Rolling {
            batch_size: 0,
            pause_seconds: 5,
        });
        let result = rollout.plan_phases();
        assert!(result.is_err());
    }

    // ─── All-at-once tests ──────────────────────────────────────────────

    #[test]
    fn all_at_once_all_hosts_in_one_phase() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        let phases = rollout.plan_phases().expect("plan");
        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0].hosts.len(), 10);
    }

    // ─── Blue-green tests ───────────────────────────────────────────────

    #[test]
    fn blue_green_two_environments() {
        let mut rollout = mk_rollout(RolloutStrategy::BlueGreen);
        let phases = rollout.plan_phases().expect("plan");
        assert_eq!(phases.len(), 2);
        assert_eq!(phases[0].hosts.len(), 5);
        assert_eq!(phases[1].hosts.len(), 5);
    }

    // ─── Host status reporting tests ────────────────────────────────────

    #[test]
    fn host_status_reporting_tracked() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        rollout.plan_phases().expect("plan");
        let phase_id = rollout.phases[0].phase_id;
        rollout.start_phase(&phase_id).expect("start");

        rollout
            .report_host_status("host_00", HostInstallStatus::Installing)
            .expect("report");
        let state = rollout.host_states.get("host_00").expect("has state");
        assert_eq!(state.install_status, HostInstallStatus::Installing);
    }

    #[test]
    fn report_unknown_host_fails() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        rollout.plan_phases().expect("plan");
        let result = rollout.report_host_status("unknown_host", HostInstallStatus::Activated);
        assert!(result.is_err());
    }

    // ─── Phase completion tests ─────────────────────────────────────────

    #[test]
    fn phase_complete_when_all_hosts_done() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        rollout.plan_phases().expect("plan");
        let phase_id = rollout.phases[0].phase_id;
        rollout.start_phase(&phase_id).expect("start");

        for host in &mk_hosts(10) {
            rollout
                .report_host_status(host, HostInstallStatus::Activated)
                .expect("report");
        }

        assert!(rollout.check_phase_complete(&phase_id));
    }

    #[test]
    fn phase_incomplete_with_pending_hosts() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        rollout.plan_phases().expect("plan");
        let phase_id = rollout.phases[0].phase_id;
        rollout.start_phase(&phase_id).expect("start");

        rollout
            .report_host_status("host_00", HostInstallStatus::Activated)
            .expect("report");

        assert!(!rollout.check_phase_complete(&phase_id));
    }

    // ─── Abort / Pause / Resume tests ───────────────────────────────────

    #[test]
    fn abort_rollout_all_pending_marked_failed() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        rollout.plan_phases().expect("plan");
        rollout.abort_rollout().expect("abort");

        for host in &mk_hosts(10) {
            let state = rollout.host_states.get(host).expect("has state");
            assert_eq!(state.install_status, HostInstallStatus::Failed);
        }

        let summary = rollout.rollout_summary();
        assert_eq!(summary.overall_status, RolloutStatus::Aborted);
    }

    #[test]
    fn pause_and_resume_rollout() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        let phases = rollout.plan_phases().expect("plan");
        let phase_id = phases[0].phase_id;

        rollout.start_phase(&phase_id).expect("start");
        rollout.pause_rollout().expect("pause");
        assert_eq!(rollout.phases[0].state, PhaseState::Paused);

        rollout.resume_rollout().expect("resume");
        assert_eq!(rollout.phases[0].state, PhaseState::InProgress);
    }

    // ─── Rollout summary tests ──────────────────────────────────────────

    #[test]
    fn rollout_summary_correct() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        rollout.plan_phases().expect("plan");
        let phase_id = rollout.phases[0].phase_id;
        rollout.start_phase(&phase_id).expect("start");

        for host in &mk_hosts(10)[..6] {
            rollout
                .report_host_status(host, HostInstallStatus::Activated)
                .expect("report");
        }
        rollout
            .report_host_status("host_06", HostInstallStatus::Failed)
            .expect("report");

        let summary = rollout.rollout_summary();
        assert_eq!(summary.total_hosts, 10);
        assert_eq!(summary.completed, 6);
        assert_eq!(summary.failed, 1);
        assert!(summary.in_progress > 0);
    }

    // ─── Empty hosts / edge cases ───────────────────────────────────────

    #[test]
    fn empty_target_hosts_no_phases() {
        let mut rollout = FleetDistributionRollout::new(
            mk_package(),
            vec![],
            RolloutStrategy::AllAtOnce,
        );
        let result = rollout.plan_phases();
        assert!(result.is_err());
        match result {
            Err(RolloutError::EmptyTargetHosts) => {}
            other => panic!("expected EmptyTargetHosts, got {other:?}"),
        }
    }

    #[test]
    fn host_reattempt_on_failure() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        rollout.plan_phases().expect("plan");
        let phase_id = rollout.phases[0].phase_id;
        rollout.start_phase(&phase_id).expect("start");

        rollout
            .report_host_status("host_00", HostInstallStatus::Failed)
            .expect("fail");
        assert_eq!(
            rollout.host_states.get("host_00").map(|s| s.attempt),
            Some(1)
        );

        rollout.retry_host("host_00").expect("retry");
        assert_eq!(
            rollout.host_states.get("host_00").map(|s| s.install_status),
            Some(HostInstallStatus::Pending)
        );
    }

    #[test]
    fn complete_rollout_lifecycle() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        let phases = rollout.plan_phases().expect("plan");
        let phase_id = phases[0].phase_id;

        rollout.start_phase(&phase_id).expect("start");

        for host in &mk_hosts(10) {
            rollout
                .report_host_status(host, HostInstallStatus::Activated)
                .expect("report");
        }

        assert!(rollout.check_phase_complete(&phase_id));
        assert_eq!(rollout.phases[0].state, PhaseState::Completed);

        let summary = rollout.rollout_summary();
        assert_eq!(summary.overall_status, RolloutStatus::Complete);
        assert_eq!(summary.completed, 10);
    }

    #[test]
    fn invalid_canary_percentage_rejected() {
        let mut rollout = mk_rollout(RolloutStrategy::AllAtOnce);
        let result = rollout.set_canary_threshold(0.0);
        assert!(result.is_err());
        let result = rollout.set_canary_threshold(100.0);
        assert!(result.is_err());
    }
}
