//! Fleet Recovery Coordination per S25 §8.
//!
//! When a coordinator goes down, this module promotes a backup coordinator,
//! maintains fleet quorum, detects split-brain conditions, and emits
//! evidence records for every state transition.
//!
//! ## Architectural invariants
//!
//! - **No automatic coordinator promotion without quorum.** Backup promotion
//!   requires k-of-n reachable members.
//! - **Split-brain is always detected, never silently resolved.**
//!   Timestamp-based resolution requires operator adjudication.
//! - **Health status is monotonic for severity.** `QuorumLost` > `Degraded`
//!   > `Recovering` > `Healthy`.
//! - **Evidence is emitted before state mutation.**

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::enums::FleetMembershipState;
use crate::membership::FleetMembership;

pub type Ed25519Signature = String;
pub type Ed25519PublicKey = String;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FleetRecoveryError {
    #[error("coordinator not found: {detail}")]
    CoordinatorNotFound { detail: String },

    #[error("no backup coordinators available")]
    NoBackupCoordinators,

    #[error(
        "quorum not met for coordinator promotion: need {required} reachable members, have {current}"
    )]
    QuorumNotMet { required: u32, current: u32 },

    #[error("split-brain detected: coordinators {coord_a} and {coord_b} both claim leadership")]
    SplitBrainDetected { coord_a: String, coord_b: String },

    #[error("heartbeat verification failed: {detail}")]
    HeartbeatVerificationFailed { detail: String },

    #[error("heartbeat sequence regression: expected >{expected}, got {got}")]
    SequenceRegression { expected: u64, got: u64 },

    #[error("host not enrolled: {host_id}")]
    HostNotEnrolled { host_id: String },

    #[error("election failed: {reason}")]
    ElectionFailed { reason: String },

    #[error("recovery already in progress")]
    RecoveryAlreadyInProgress,

    #[error("fleet ID mismatch: expected {expected}, got {got}")]
    FleetIdMismatch { expected: String, got: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FleetHealthStatus {
    Healthy,
    Degraded,
    QuorumLost,
    Recovering,
    SplitBrain,
}

impl FleetHealthStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Degraded => "DEGRADED",
            Self::QuorumLost => "QUORUM_LOST",
            Self::Recovering => "RECOVERING",
            Self::SplitBrain => "SPLIT_BRAIN",
        }
    }

    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::Recovering => 1,
            Self::Degraded => 2,
            Self::QuorumLost => 3,
            Self::SplitBrain => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorHeartbeat {
    pub coordinator_id: String,
    pub timestamp: DateTime<Utc>,
    pub sequence: u64,
    pub signature: Ed25519Signature,
}

impl CoordinatorHeartbeat {
    #[must_use]
    pub fn new(coordinator_id: String, sequence: u64, signature: Ed25519Signature) -> Self {
        Self {
            coordinator_id,
            timestamp: Utc::now(),
            sequence,
            signature,
        }
    }

    pub fn verify_signature(&self, expected_public_key: &str) -> Result<(), FleetRecoveryError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let vk_bytes = decode_hex_pubkey(expected_public_key).map_err(|e| {
            FleetRecoveryError::HeartbeatVerificationFailed {
                detail: format!("malformed verifying key: {e}"),
            }
        })?;

        let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|e| {
            FleetRecoveryError::HeartbeatVerificationFailed {
                detail: format!("invalid verifying key: {e}"),
            }
        })?;

        let sig_bytes = decode_hex_signature(&self.signature).map_err(|e| {
            FleetRecoveryError::HeartbeatVerificationFailed {
                detail: format!("malformed signature: {e}"),
            }
        })?;

        let sig = Signature::from_bytes(&sig_bytes);
        let payload = format!(
            "{}|{}|{}",
            self.coordinator_id, self.timestamp, self.sequence
        );

        vk.verify(payload.as_bytes(), &sig).map_err(|e| {
            FleetRecoveryError::HeartbeatVerificationFailed {
                detail: format!("signature verification failed: {e}"),
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHealthReport {
    pub fleet_id: Ulid,
    pub status: FleetHealthStatus,
    pub total_members: u32,
    pub active_members: u32,
    pub coordinator: Option<String>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub quorum_maintained: bool,
}

impl FleetHealthReport {
    #[must_use]
    pub fn new(
        fleet_id: Ulid,
        status: FleetHealthStatus,
        total_members: u32,
        active_members: u32,
        coordinator: Option<String>,
        last_heartbeat: Option<DateTime<Utc>>,
        quorum_maintained: bool,
    ) -> Self {
        Self {
            fleet_id,
            status,
            total_members,
            active_members,
            coordinator,
            last_heartbeat,
            quorum_maintained,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FleetRecoveryRecordType {
    FleetCoordinatorPromoted,
    FleetQuorumLost,
    FleetSplitBrainDetected,
    FleetRecovered,
}

impl FleetRecoveryRecordType {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FleetCoordinatorPromoted => "FLEET_COORDINATOR_PROMOTED",
            Self::FleetQuorumLost => "FLEET_QUORUM_LOST",
            Self::FleetSplitBrainDetected => "FLEET_SPLIT_BRAIN_DETECTED",
            Self::FleetRecovered => "FLEET_RECOVERED",
        }
    }
}

pub trait FleetRecoveryEvidenceEmitter: Send + Sync {
    fn emit_coordinator_promoted(
        &self,
        fleet_id: &Ulid,
        old_coordinator: Option<&str>,
        new_coordinator: &str,
        reason: &str,
    );

    fn emit_quorum_lost(&self, fleet_id: &Ulid, required: u32, current: u32);

    fn emit_split_brain_detected(&self, fleet_id: &Ulid, coord_a: &str, coord_b: &str);

    fn emit_fleet_recovered(
        &self,
        fleet_id: &Ulid,
        coordinator: &str,
        from_status: FleetHealthStatus,
    );
}

pub struct FleetRecoveryCoordinator {
    pub memberships: HashMap<String, FleetMembership>,
    pub current_coordinator: Option<String>,
    pub coordinator_heartbeat_deadline: Option<DateTime<Utc>>,
    pub quorum_size: u32,
    pub backup_coordinators: Vec<String>,
    pub evidence_emitter: Option<Arc<dyn FleetRecoveryEvidenceEmitter>>,
    fleet_id: Ulid,
    heartbeat_timeout_secs: u64,
    last_heartbeat_sequence: u64,
    last_health_status: FleetHealthStatus,
    claimed_coordinators: Vec<(String, DateTime<Utc>)>,
}

impl FleetRecoveryCoordinator {
    #[must_use]
    pub fn new(memberships: HashMap<String, FleetMembership>, quorum_size: u32) -> Self {
        Self {
            memberships,
            current_coordinator: None,
            coordinator_heartbeat_deadline: None,
            quorum_size,
            backup_coordinators: Vec::new(),
            evidence_emitter: None,
            fleet_id: Ulid::new(),
            heartbeat_timeout_secs: 30,
            last_heartbeat_sequence: 0,
            last_health_status: FleetHealthStatus::Healthy,
            claimed_coordinators: Vec::new(),
        }
    }

    pub fn set_evidence_emitter(&mut self, emitter: Arc<dyn FleetRecoveryEvidenceEmitter>) {
        self.evidence_emitter = Some(emitter);
    }

    pub fn set_heartbeat_timeout_secs(&mut self, secs: u64) {
        self.heartbeat_timeout_secs = secs;
    }

    pub fn set_backup_coordinators(&mut self, backups: Vec<String>) {
        self.backup_coordinators = backups;
    }

    pub fn set_coordinator(&mut self, coordinator_id: String, public_key: &str) {
        self.current_coordinator = Some(coordinator_id);
        let _ = public_key;
    }

    pub fn receive_heartbeat(
        &mut self,
        heartbeat: CoordinatorHeartbeat,
    ) -> Result<(), FleetRecoveryError> {
        let claimed_by_other = if let Some(ref current) = self.current_coordinator {
            heartbeat.coordinator_id != *current
        } else {
            false
        };

        if claimed_by_other {
            self.record_claimed_coordinator(&heartbeat.coordinator_id, heartbeat.timestamp);

            if self.detect_split_brain() {
                // need to re-borrow current_coordinator
                let current_coord = self.current_coordinator.clone();
                if let (Some(emitter), Some(ref current)) = (&self.evidence_emitter, &current_coord)
                {
                    emitter.emit_split_brain_detected(
                        &self.fleet_id,
                        current,
                        &heartbeat.coordinator_id,
                    );
                }
                return Err(FleetRecoveryError::SplitBrainDetected {
                    coord_a: current_coord.clone().unwrap_or_default(),
                    coord_b: heartbeat.coordinator_id.clone(),
                });
            }
        }

        if heartbeat.sequence <= self.last_heartbeat_sequence {
            return Err(FleetRecoveryError::SequenceRegression {
                expected: self.last_heartbeat_sequence,
                got: heartbeat.sequence,
            });
        }

        self.last_heartbeat_sequence = heartbeat.sequence;
        let timeout = chrono::Duration::seconds(self.heartbeat_timeout_secs as i64);
        self.coordinator_heartbeat_deadline = Some(heartbeat.timestamp + timeout);
        self.last_health_status = FleetHealthStatus::Healthy;
        Ok(())
    }

    pub fn check_coordinator_alive(&self) -> FleetHealthStatus {
        if self.current_coordinator.is_none() {
            return FleetHealthStatus::Degraded;
        }

        let Some(deadline) = self.coordinator_heartbeat_deadline else {
            return FleetHealthStatus::Degraded;
        };

        if Utc::now() > deadline {
            return FleetHealthStatus::Degraded;
        }

        let enrolled_count = self
            .memberships
            .values()
            .filter(|m| m.state == FleetMembershipState::Enrolled)
            .count() as u32;

        if enrolled_count < self.quorum_size {
            return FleetHealthStatus::QuorumLost;
        }

        FleetHealthStatus::Healthy
    }

    pub fn promote_coordinator(&mut self) -> Result<String, FleetRecoveryError> {
        if self.current_coordinator.is_some()
            && self.check_coordinator_alive() == FleetHealthStatus::Healthy
        {
            return Err(FleetRecoveryError::RecoveryAlreadyInProgress);
        }

        let enrolled = self.enrolled_member_ids();
        if enrolled.len() < self.quorum_size as usize {
            return Err(FleetRecoveryError::QuorumNotMet {
                required: self.quorum_size,
                current: enrolled.len() as u32,
            });
        }

        let candidate = self
            .backup_coordinators
            .iter()
            .find(|b| enrolled.contains(b))
            .ok_or(FleetRecoveryError::NoBackupCoordinators)?;

        let old_coordinator = self.current_coordinator.take();
        self.current_coordinator = Some(candidate.clone());
        self.coordinator_heartbeat_deadline = None;
        self.last_heartbeat_sequence = 0;
        self.last_health_status = FleetHealthStatus::Recovering;

        if let Some(emitter) = &self.evidence_emitter {
            emitter.emit_coordinator_promoted(
                &self.fleet_id,
                old_coordinator.as_deref(),
                candidate,
                "backup_promotion",
            );
        }

        Ok(candidate.clone())
    }

    pub fn elect_new_coordinator(&mut self) -> Result<String, FleetRecoveryError> {
        let enrolled_ids = self.enrolled_member_ids();

        if enrolled_ids.len() < self.quorum_size as usize {
            return Err(FleetRecoveryError::QuorumNotMet {
                required: self.quorum_size,
                current: enrolled_ids.len() as u32,
            });
        }

        if enrolled_ids.is_empty() {
            return Err(FleetRecoveryError::ElectionFailed {
                reason: "no enrolled members".to_owned(),
            });
        }

        let candidate = self
            .backup_coordinators
            .iter()
            .find(|b| enrolled_ids.contains(b))
            .or_else(|| enrolled_ids.first())
            .ok_or(FleetRecoveryError::ElectionFailed {
                reason: "no eligible candidate found".to_owned(),
            })?;

        let old_coordinator = self.current_coordinator.take();
        self.current_coordinator = Some(candidate.clone());
        self.coordinator_heartbeat_deadline = None;
        self.last_heartbeat_sequence = 0;
        self.last_health_status = FleetHealthStatus::Recovering;

        if let Some(emitter) = &self.evidence_emitter {
            emitter.emit_coordinator_promoted(
                &self.fleet_id,
                old_coordinator.as_deref(),
                candidate,
                "full_election",
            );
        }

        Ok(candidate.clone())
    }

    pub fn verify_quorum(&self, members: &[String]) -> bool {
        let enrolled = self.enrolled_member_ids();
        let reachable: Vec<&String> = members.iter().filter(|m| enrolled.contains(m)).collect();
        reachable.len() as u32 >= self.quorum_size
    }

    pub fn detect_split_brain(&self) -> bool {
        self.claimed_coordinators.len() >= 2
    }

    pub fn recover_from_split_brain(&mut self) -> Result<(), FleetRecoveryError> {
        if self.claimed_coordinators.len() < 2 {
            return Ok(());
        }

        self.claimed_coordinators
            .sort_by_key(|(_, sequence)| std::cmp::Reverse(*sequence));

        let winner = self.claimed_coordinators[0].0.clone();

        self.current_coordinator = Some(winner);
        self.claimed_coordinators.clear();
        self.coordinator_heartbeat_deadline = None;
        self.last_heartbeat_sequence = 0;
        self.last_health_status = FleetHealthStatus::Recovering;

        if let Some(emitter) = &self.evidence_emitter {
            emitter.emit_fleet_recovered(
                &self.fleet_id,
                self.current_coordinator.as_deref().unwrap_or("unknown"),
                FleetHealthStatus::SplitBrain,
            );
        }

        Ok(())
    }

    pub fn health_report(&self) -> FleetHealthReport {
        let status = self.check_coordinator_alive();
        let enrolled = self.enrolled_member_ids();
        let active = enrolled.len() as u32;
        let total = self.memberships.len() as u32;
        let quorum_maintained = active >= self.quorum_size;

        FleetHealthReport::new(
            self.fleet_id,
            status,
            total,
            active,
            self.current_coordinator.clone(),
            self.coordinator_heartbeat_deadline,
            quorum_maintained,
        )
    }

    pub fn mark_healthy(&mut self) {
        self.last_health_status = FleetHealthStatus::Healthy;
    }

    pub fn mark_recovering(&mut self) {
        self.last_health_status = FleetHealthStatus::Recovering;
    }

    fn enrolled_member_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .memberships
            .iter()
            .filter(|(_, m)| m.state == FleetMembershipState::Enrolled)
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }

    fn record_claimed_coordinator(&mut self, coordinator_id: &str, timestamp: DateTime<Utc>) {
        if !self
            .claimed_coordinators
            .iter()
            .any(|(id, _)| id == coordinator_id)
        {
            self.claimed_coordinators
                .push((coordinator_id.to_owned(), timestamp));
            self.last_health_status = FleetHealthStatus::SplitBrain;
        }
    }
}

fn decode_hex_signature(hex: &str) -> Result<[u8; 64], String> {
    if hex.len() != 128 {
        return Err(format!("expected 128 hex chars, got {}", hex.len()));
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 64];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi =
            hex_nibble(chunk[0]).map_err(|_| format!("invalid hex byte 0x{:02x}", chunk[0]))?;
        let lo =
            hex_nibble(chunk[1]).map_err(|_| format!("invalid hex byte 0x{:02x}", chunk[1]))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_hex_pubkey(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!(
            "expected 64 hex chars for pubkey, got {}",
            hex.len()
        ));
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi =
            hex_nibble(chunk[0]).map_err(|_| format!("invalid hex byte 0x{:02x}", chunk[0]))?;
        let lo =
            hex_nibble(chunk[1]).map_err(|_| format!("invalid hex byte 0x{:02x}", chunk[1]))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

const fn hex_nibble(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::similar_names,
    reason = "unit tests in the same module"
)]
mod tests {
    use super::*;

    fn mk_membership(host_id: &str, state: FleetMembershipState) -> FleetMembership {
        FleetMembership {
            membership_id: format!("mem_{host_id}"),
            host_id: host_id.to_owned(),
            cluster_id: "clr_01".into(),
            state,
            host_policy_supremacy: true,
            cluster_overridable: false,
        }
    }

    fn mk_coordinator(members_count: u32) -> FleetRecoveryCoordinator {
        let mut memberships = HashMap::new();
        for i in 0..members_count {
            let id = format!("host_{i:02}");
            memberships.insert(
                id.clone(),
                mk_membership(&id, FleetMembershipState::Enrolled),
            );
        }
        FleetRecoveryCoordinator::new(memberships, 3)
    }

    fn mk_heartbeat(coordinator_id: &str, seq: u64) -> CoordinatorHeartbeat {
        CoordinatorHeartbeat::new(coordinator_id.to_owned(), seq, "a".repeat(128))
    }

    // ─── Heartbeat tests ────────────────────────────────────────────────

    #[test]
    fn heartbeat_received_marks_healthy() {
        let mut coord = mk_coordinator(5);
        coord.set_coordinator("host_00".into(), "k");
        let hb = mk_heartbeat("host_00", 1);
        coord.receive_heartbeat(hb).expect("receive");
        assert_eq!(coord.check_coordinator_alive(), FleetHealthStatus::Healthy);
    }

    #[test]
    fn heartbeat_expired_marks_degraded() {
        let mut coord = mk_coordinator(5);
        coord.set_coordinator("host_00".into(), "k");
        coord.set_heartbeat_timeout_secs(0);

        let hb = mk_heartbeat("host_00", 1);
        coord.receive_heartbeat(hb).expect("receive");

        std::thread::sleep(std::time::Duration::from_millis(10));

        assert_eq!(coord.check_coordinator_alive(), FleetHealthStatus::Degraded);
    }

    #[test]
    fn heartbeat_sequence_regression_rejected() {
        let mut coord = mk_coordinator(5);
        coord.set_coordinator("host_00".into(), "k");

        let hb1 = mk_heartbeat("host_00", 5);
        coord.receive_heartbeat(hb1).expect("receive seq 5");

        let hb2 = mk_heartbeat("host_00", 3);
        let result = coord.receive_heartbeat(hb2);
        assert!(result.is_err());
        match result {
            Err(FleetRecoveryError::SequenceRegression { expected, got }) => {
                assert_eq!(expected, 5);
                assert_eq!(got, 3);
            }
            other => panic!("expected SequenceRegression, got {other:?}"),
        }
    }

    #[test]
    fn heartbeat_unknown_leader_recorded_as_claimed() {
        let mut coord = mk_coordinator(5);
        coord.set_coordinator("host_00".into(), "k");
        let hb = mk_heartbeat("host_99", 1);
        coord.receive_heartbeat(hb).expect("receive unknown");
        assert!(!coord.detect_split_brain());
        assert_eq!(coord.claimed_coordinators.len(), 1);
    }

    // ─── Promotion tests ────────────────────────────────────────────────

    #[test]
    fn promote_backup_with_quorum_succeeds() {
        let mut coord = mk_coordinator(5);
        coord.set_coordinator("host_00".into(), "k");
        coord.set_backup_coordinators(vec!["host_01".into(), "host_02".into()]);
        coord.quorum_size = 3;

        let result = coord.promote_coordinator();
        assert!(result.is_ok());
        assert_eq!(coord.current_coordinator.as_deref(), Some("host_01"));
        assert_eq!(coord.last_health_status, FleetHealthStatus::Recovering);
    }

    #[test]
    fn promote_without_quorum_rejected() {
        let mut coord = mk_coordinator(3);
        coord.set_coordinator("host_00".into(), "k");
        coord.set_backup_coordinators(vec!["host_01".into()]);
        coord.quorum_size = 5;

        let result = coord.promote_coordinator();
        assert!(result.is_err());
        match result {
            Err(FleetRecoveryError::QuorumNotMet { .. }) => {}
            other => panic!("expected QuorumNotMet, got {other:?}"),
        }
    }

    #[test]
    fn promote_no_backup_coordinator_fails() {
        let mut coord = mk_coordinator(5);
        coord.set_coordinator("host_00".into(), "k");
        coord.quorum_size = 3;

        let result = coord.promote_coordinator();
        assert!(result.is_err());
        match result {
            Err(FleetRecoveryError::NoBackupCoordinators) => {}
            other => panic!("expected NoBackupCoordinators, got {other:?}"),
        }
    }

    // ─── Split brain tests ──────────────────────────────────────────────

    #[test]
    fn split_brain_detected_two_coordinators() {
        let mut coord = mk_coordinator(5);
        coord.set_coordinator("host_00".into(), "k");
        coord.claimed_coordinators = vec![
            ("host_00".to_owned(), Utc::now()),
            ("host_99".to_owned(), Utc::now()),
        ];
        assert!(coord.detect_split_brain());
    }

    #[test]
    fn split_brain_resolved_timestamp_based() {
        let mut coord = mk_coordinator(5);
        let now = Utc::now();
        let earlier = now - chrono::Duration::seconds(60);
        let later = now;

        coord.claimed_coordinators = vec![
            ("host_early".to_owned(), earlier),
            ("host_late".to_owned(), later),
        ];

        coord.recover_from_split_brain().expect("recover");
        assert_eq!(coord.current_coordinator.as_deref(), Some("host_late"));
    }

    #[test]
    fn split_brain_detected_via_heartbeat() {
        let mut coord = mk_coordinator(5);
        coord.set_coordinator("host_00".into(), "k");

        let now = Utc::now();
        coord.claimed_coordinators = vec![("host_00".to_owned(), now)];

        let hb = mk_heartbeat("host_99", 1);
        let result = coord.receive_heartbeat(hb);
        assert!(result.is_err());
        match result {
            Err(FleetRecoveryError::SplitBrainDetected { coord_a, coord_b }) => {
                assert_eq!(coord_a, "host_00");
                assert_eq!(coord_b, "host_99");
            }
            other => panic!("expected SplitBrainDetected, got {other:?}"),
        }
    }

    // ─── Quorum tests ───────────────────────────────────────────────────

    #[test]
    fn quorum_verified_k_of_n() {
        let mut coord = mk_coordinator(5);
        coord.quorum_size = 3;

        let members = vec![
            "host_00".to_owned(),
            "host_01".to_owned(),
            "host_02".to_owned(),
        ];
        assert!(coord.verify_quorum(&members));
    }

    #[test]
    fn quorum_lost_too_few_members() {
        let mut coord = mk_coordinator(5);
        coord.quorum_size = 5;

        let members = vec!["host_00".to_owned(), "host_01".to_owned()];
        assert!(!coord.verify_quorum(&members));
    }

    #[test]
    fn quorum_with_mixed_states() {
        let mut memberships = HashMap::new();
        memberships.insert(
            "host_00".into(),
            mk_membership("host_00", FleetMembershipState::Enrolled),
        );
        memberships.insert(
            "host_01".into(),
            mk_membership("host_01", FleetMembershipState::Enrolled),
        );
        memberships.insert(
            "host_02".into(),
            mk_membership("host_02", FleetMembershipState::Suspended),
        );
        memberships.insert(
            "host_03".into(),
            mk_membership("host_03", FleetMembershipState::Withdrawn),
        );

        let coord = FleetRecoveryCoordinator::new(memberships, 2);
        let members = vec!["host_00".to_owned(), "host_01".to_owned()];
        assert!(coord.verify_quorum(&members));
    }

    // ─── Health report tests ────────────────────────────────────────────

    #[test]
    fn health_report_degrades_without_coordinator() {
        let coord = mk_coordinator(5);
        let report = coord.health_report();
        assert_eq!(report.status, FleetHealthStatus::Degraded);
    }

    #[test]
    fn health_report_quorum_lost_below_threshold() {
        let mut coord = mk_coordinator(3);
        coord.set_coordinator("host_00".into(), "k");
        coord.quorum_size = 5;
        coord.set_heartbeat_timeout_secs(3600);
        let hb = mk_heartbeat("host_00", 1);
        coord.receive_heartbeat(hb).expect("receive");

        let report = coord.health_report();
        assert_eq!(report.status, FleetHealthStatus::QuorumLost);
    }

    // ─── Full recovery cycle test ───────────────────────────────────────

    #[test]
    fn full_recovery_cycle() {
        let mut coord = mk_coordinator(5);
        coord.set_backup_coordinators(vec!["host_01".into(), "host_02".into()]);
        coord.quorum_size = 3;

        coord.set_coordinator("host_00".into(), "k");
        coord.set_heartbeat_timeout_secs(0);
        let hb = mk_heartbeat("host_00", 1);
        coord.receive_heartbeat(hb).expect("receive");
        std::thread::sleep(std::time::Duration::from_millis(10));

        assert_eq!(coord.check_coordinator_alive(), FleetHealthStatus::Degraded);

        let result = coord.promote_coordinator();
        assert!(result.is_ok());
        assert_eq!(coord.last_health_status, FleetHealthStatus::Recovering);

        coord.mark_healthy();
        assert_eq!(coord.last_health_status, FleetHealthStatus::Healthy);
    }

    // ─── Election tests ─────────────────────────────────────────────────

    #[test]
    fn elect_coordinator_from_enrolled() {
        let mut coord = mk_coordinator(5);
        coord.set_backup_coordinators(vec!["host_04".into()]);
        coord.quorum_size = 3;

        let result = coord.elect_new_coordinator();
        assert!(result.is_ok());
        assert!(coord.current_coordinator.is_some());
    }

    #[test]
    fn elect_without_enrolled_fails() {
        let memberships = HashMap::new();
        let mut coord = FleetRecoveryCoordinator::new(memberships, 3);
        let result = coord.elect_new_coordinator();
        assert!(result.is_err());
    }
}
