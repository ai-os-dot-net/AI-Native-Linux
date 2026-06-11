//! AIOS Rev.10 — Autonomous Failover Engine
//!
//! Blast-radius-gated autonomous failover coordination. Evaluates host health,
//! decides failover urgency (NoAction / WarmStandby / ActiveFailover /
//! FullPromote), and executes within the configured simultaneous-failover limit.
//!
//! ## Decision thresholds
//!
//! | Score         | Decision        |
//! |---------------|-----------------|
//! | `0..=24`      | `NoAction`      |
//! | `25..=49`     | `WarmStandby`   |
//! | `50..=74`     | `ActiveFailover`|
//! | `75..=100`    | `FullPromote`   |
//!
//! ## Blast radius
//!
//! `max_simultaneous_failovers` (default 3) gates concurrent failovers —
//! `can_execute_more()` returns `false` while the limit is reached.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::cross_machine_healing::HealthState;
use crate::enums::{FailoverPhase, HealthTrend};
use crate::error::AutonomousError;

// ── Scoring ────────────────────────────────────────────────────────────────

/// Component-level scores that feed into the failover urgency computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverScoring {
    /// Aggregate urgency score 0–100.
    pub urgency_score: u32,
    /// Raw health score (0 = dead, 100 = pristine).
    pub health_score: u32,
    /// Resource availability score (0 = depleted, 100 = abundant).
    pub resource_score: u32,
    /// Cognitive / operational load score (0 = idle, 100 = overloaded).
    pub cognitive_load_score: u32,
    /// Trend direction over recent observations.
    pub trend: HealthTrend,
}

impl Default for FailoverScoring {
    fn default() -> Self {
        Self {
            urgency_score: 0,
            health_score: 100,
            resource_score: 100,
            cognitive_load_score: 0,
            trend: HealthTrend::Stable,
        }
    }
}

// ── Decision ───────────────────────────────────────────────────────────────

/// The engine's decision after evaluating a host's failover score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailoverDecision {
    /// No action required — host is healthy enough.
    NoAction,
    /// Prepare the named host as a warm standby.
    WarmStandby(String),
    /// Initiate active failover to the named host.
    ActiveFailover(String),
    /// Promote the named host to fleet coordinator.
    FullPromote(String),
}

// ── Score output ───────────────────────────────────────────────────────────

/// Result of [`AutonomousFailoverEngine::evaluate_host_health`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverScore {
    /// Overall urgency 0–100.
    pub score: u32,
    /// Breakdown of the component scores.
    pub components: FailoverScoring,
    /// Recommendation derived from the score.
    pub recommendation: FailoverDecision,
}

// ── Active failover ────────────────────────────────────────────────────────

/// A failover currently in progress, tracked to enforce blast-radius limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveFailover {
    /// Unique failover identifier (ULID).
    pub failover_id: String,
    /// Host from which components are being moved.
    pub source_host: String,
    /// Host to which components are being moved.
    pub target_host: String,
    /// Current lifecycle phase of the failover.
    pub phase: FailoverPhase,
    /// Timestamp when the failover was initiated.
    pub started_at: DateTime<Utc>,
    /// List of component ids already migrated.
    pub components_migrated: Vec<String>,
    /// Blake3 hash of critical evidence for audit trail.
    pub evidence_hash: String,
}

// ── Historical record ──────────────────────────────────────────────────────

/// A completed (or abandoned) failover stored for audit and analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverRecord {
    /// Unique failover identifier (ULID).
    pub failover_id: String,
    /// Host from which components were moved.
    pub source_host: String,
    /// Host to which components were moved.
    pub target_host: String,
    /// Whether the failover completed successfully.
    pub success: bool,
    /// Timestamp when the failover was initiated.
    pub started_at: DateTime<Utc>,
    /// Timestamp when the failover was finalised (set on completion).
    pub completed_at: Option<DateTime<Utc>>,
    /// List of component ids affected by this failover.
    pub affected_components: Vec<String>,
}

impl FailoverRecord {
    fn new(
        failover_id: String,
        source_host: String,
        target_host: String,
        started_at: DateTime<Utc>,
        affected_components: Vec<String>,
    ) -> Self {
        Self {
            failover_id,
            source_host,
            target_host,
            success: false,
            started_at,
            completed_at: None,
            affected_components,
        }
    }
}

// ── Engine ─────────────────────────────────────────────────────────────────

/// Autonomous failover engine — evaluates host health, decides failover
/// actions, and gates execution within a configurable blast-radius limit.
pub struct AutonomousFailoverEngine {
    /// Current failover lifecycle phase.
    pub phase: FailoverPhase,
    /// Aggregate scoring state used for trend tracking.
    pub scoring: FailoverScoring,
    /// In-flight failovers keyed by `failover_id`.
    pub active_failovers: HashMap<String, ActiveFailover>,
    /// Completed and abandoned failovers for audit trail.
    pub failover_history: Vec<FailoverRecord>,
    /// Maximum concurrent active failovers (blast-radius cap).
    pub max_simultaneous_failovers: u32,
}

impl AutonomousFailoverEngine {
    /// Create a new failover engine with sensible defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phase: FailoverPhase::Monitoring,
            scoring: FailoverScoring::default(),
            active_failovers: HashMap::new(),
            failover_history: Vec::new(),
            max_simultaneous_failovers: 3,
        }
    }

    // ── helpers ────────────────────────────────────────────────────────

    /// Compute a Blake3 evidence hash from failover metadata.
    fn compute_evidence_hash(
        source: &str,
        target: &str,
        started_at: &DateTime<Utc>,
        components: &[String],
    ) -> String {
        let mut hasher = Hasher::new();
        hasher.update(source.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update(started_at.to_rfc3339().as_bytes());
        for c in components {
            hasher.update(c.as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Derive a failover target host from the source host.
    fn derive_target_host(host_id: &str) -> String {
        format!("failover-target-{host_id}")
    }

    /// Map a [`HealthState`] variant to numeric (health, resource, cognitive) scores.
    const fn health_state_to_scores(state: HealthState) -> (u32, u32, u32) {
        match state {
            HealthState::Healthy => (90, 90, 10),
            HealthState::Degraded => (50, 50, 50),
            HealthState::Failed => (10, 30, 80),
            HealthState::Unknown => (40, 40, 40),
        }
    }

    // ── public API ─────────────────────────────────────────────────────

    /// Evaluate a host's health and return a failover urgency score with
    /// a recommendation.
    ///
    /// The urgency is computed by inverting the health and resource scores
    /// (what is broken), adding cognitive load, and weighting by trend.
    #[must_use]
    pub fn evaluate_host_health(
        &mut self,
        host_id: &str,
        health: HealthState,
    ) -> FailoverScore {
        let (health_score, resource_score, cognitive_load_score) =
            Self::health_state_to_scores(health);

        // Invert health & resource (bad → urgent), cognitive load is direct.
        let health_inv = 100u32.saturating_sub(health_score);
        let resource_inv = 100u32.saturating_sub(resource_score);
        let cognitive = cognitive_load_score;

        let base_urgency = health_inv / 3 + resource_inv / 3 + cognitive / 3;

        let trend_multiplier: f64 = match health.trend() {
            HealthTrend::Critical => 2.0,
            HealthTrend::Degrading => 1.5,
            HealthTrend::Stable => 1.0,
            HealthTrend::Improving => 0.7,
        };

        let urgency_score =
            ((base_urgency as f64) * trend_multiplier).min(100.0) as u32;

        let components = FailoverScoring {
            urgency_score,
            health_score,
            resource_score,
            cognitive_load_score,
            trend: health.trend(),
        };

        let recommendation = match urgency_score {
            0..=24 => FailoverDecision::NoAction,
            25..=49 => {
                FailoverDecision::WarmStandby(Self::derive_target_host(host_id))
            }
            50..=74 => {
                FailoverDecision::ActiveFailover(Self::derive_target_host(host_id))
            }
            _ => FailoverDecision::FullPromote(Self::derive_target_host(host_id)),
        };

        self.scoring = components.clone();

        FailoverScore {
            score: urgency_score,
            components,
            recommendation,
        }
    }

    /// Decide a failover action based on a previously computed score.
    ///
    /// Returns `None` only if the recommendation is already `NoAction`.
    #[must_use]
    pub fn decide_failover(
        &self,
        host_id: &str,
        score: FailoverScore,
    ) -> Option<FailoverDecision> {
        if score.score < 25 {
            return Some(FailoverDecision::NoAction);
        }
        let target = Self::derive_target_host(host_id);
        match score.score {
            0..=24 => Some(FailoverDecision::NoAction),
            25..=49 => Some(FailoverDecision::WarmStandby(target)),
            50..=74 => Some(FailoverDecision::ActiveFailover(target)),
            _ => Some(FailoverDecision::FullPromote(target)),
        }
    }

    /// Execute a failover decision, creating an active failover entry.
    ///
    /// # Errors
    ///
    /// Returns [`AutonomousError::InvalidFailoverState`] if `NoAction` is
    /// passed, and [`AutonomousError::FailoverLimitExceeded`] if the blast
    /// radius limit is reached.
    pub fn execute_failover(
        &mut self,
        decision: FailoverDecision,
    ) -> Result<ActiveFailover, AutonomousError> {
        let (source_host, target_host, phase) = match &decision {
            FailoverDecision::NoAction => {
                return Err(AutonomousError::InvalidFailoverState(
                    "cannot execute NoAction decision".into(),
                ));
            }
            FailoverDecision::WarmStandby(target) => (
                "auto-detected".to_string(),
                target.clone(),
                FailoverPhase::WarmStandby,
            ),
            FailoverDecision::ActiveFailover(target) => (
                "auto-detected".to_string(),
                target.clone(),
                FailoverPhase::ActiveFailover,
            ),
            FailoverDecision::FullPromote(target) => (
                "fleet-coordinator".to_string(),
                target.clone(),
                FailoverPhase::ActiveFailover,
            ),
        };

        if !self.can_execute_more() {
            return Err(AutonomousError::FailoverLimitExceeded {
                max: self.max_simultaneous_failovers,
                current: self.active_failovers.len(),
            });
        }

        let failover_id = Ulid::new().to_string();
        let started_at = Utc::now();
        let components_migrated: Vec<String> = Vec::new();
        let evidence_hash = Self::compute_evidence_hash(
            &source_host,
            &target_host,
            &started_at,
            &components_migrated,
        );

        let active = ActiveFailover {
            failover_id: failover_id.clone(),
            source_host,
            target_host,
            phase,
            started_at,
            components_migrated,
            evidence_hash,
        };

        self.active_failovers
            .insert(failover_id.clone(), active.clone());
        self.phase = phase;

        Ok(active)
    }

    /// Check whether the blast-radius limit still permits new failovers.
    #[must_use]
    pub fn can_execute_more(&self) -> bool {
        (self.active_failovers.len() as u32) < self.max_simultaneous_failovers
    }

    /// Promote a host to fleet coordinator.
    ///
    /// Clears all active failovers, records the promotion in history, and
    /// resets the engine phase to [`FailoverPhase::Monitoring`].
    ///
    /// # Errors
    ///
    /// Returns [`AutonomousError::CoordinatorPromotionFailed`] if the
    /// coordinator name is empty.
    pub fn promote_coordinator(
        &mut self,
        new_coordinator: &str,
    ) -> Result<(), AutonomousError> {
        if new_coordinator.is_empty() {
            return Err(AutonomousError::CoordinatorPromotionFailed(
                "coordinator name cannot be empty".into(),
            ));
        }

        let failover_id = Ulid::new().to_string();
        let started_at = Utc::now();
        let _evidence_hash = Self::compute_evidence_hash(
            "fleet-coordinator",
            new_coordinator,
            &started_at,
            &[],
        );

        let mut record = FailoverRecord::new(
            failover_id,
            "fleet-coordinator".to_string(),
            new_coordinator.to_string(),
            started_at,
            vec!["coordinator-role".to_string()],
        );
        record.success = true;
        record.completed_at = Some(Utc::now());

        self.failover_history.push(record);
        self.active_failovers.clear();
        self.phase = FailoverPhase::Monitoring;

        Ok(())
    }

    /// Complete (or abandon) an active failover.
    ///
    /// Removes the failover from the active set, records its outcome in
    /// [`Self::failover_history`], and updates the engine phase.
    ///
    /// # Errors
    ///
    /// Returns [`AutonomousError::FailoverNotFound`] if the failover id
    /// is not found in the active registry.
    pub fn complete_failover(
        &mut self,
        failover_id: &str,
        success: bool,
    ) -> Result<(), AutonomousError> {
        let active = self
            .active_failovers
            .remove(failover_id)
            .ok_or_else(|| AutonomousError::FailoverNotFound(failover_id.to_string()))?;

        let record = FailoverRecord {
            failover_id: active.failover_id.clone(),
            source_host: active.source_host.clone(),
            target_host: active.target_host.clone(),
            success,
            started_at: active.started_at,
            completed_at: Some(Utc::now()),
            affected_components: active.components_migrated.clone(),
        };

        self.failover_history.push(record);

        self.phase = if success && self.active_failovers.is_empty() {
            FailoverPhase::Monitoring
        } else if !success {
            FailoverPhase::RolledBack
        } else {
            FailoverPhase::ActiveFailover
        };

        Ok(())
    }

    /// Return a reference to the full failover history.
    #[must_use]
    pub fn get_failover_history(&self) -> &[FailoverRecord] {
        &self.failover_history
    }
}

impl Default for AutonomousFailoverEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── HealthState helper ─────────────────────────────────────────────────────

/// Extension trait to derive a [`HealthTrend`] from a [`HealthState`].
trait HealthStateExt {
    fn trend(&self) -> HealthTrend;
}

impl HealthStateExt for HealthState {
    fn trend(&self) -> HealthTrend {
        match self {
            Self::Healthy => HealthTrend::Improving,
            Self::Degraded => HealthTrend::Degrading,
            Self::Failed => HealthTrend::Critical,
            Self::Unknown => HealthTrend::Stable,
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Health evaluation ──────────────────────────────────────────────

    #[test]
    fn healthy_host_produces_low_score() {
        let mut engine = AutonomousFailoverEngine::new();
        let score = engine.evaluate_host_health("host-1", HealthState::Healthy);
        assert!(score.score < 25, "healthy host score={}", score.score);
        assert_eq!(score.recommendation, FailoverDecision::NoAction);
    }

    #[test]
    fn failed_host_produces_high_score() {
        let mut engine = AutonomousFailoverEngine::new();
        let score = engine.evaluate_host_health("host-1", HealthState::Failed);
        assert!(score.score > 50, "failed host score={}", score.score);
    }

    #[test]
    fn degraded_host_is_boosted_by_degrading_trend() {
        // Direct HealthState::Degraded implies Degrading trend.
        let mut engine = AutonomousFailoverEngine::new();
        let score = engine.evaluate_host_health("host-1", HealthState::Degraded);
        // Inverted: (100-50)/3 + (100-50)/3 + 50/3 ≈ 16+16+16=48 × 1.5 ≈ 72
        assert!(score.score >= 50, "degraded host score={}", score.score);
    }

    #[test]
    fn healthy_host_is_reduced_by_improving_trend() {
        let mut engine = AutonomousFailoverEngine::new();
        let score = engine.evaluate_host_health("host-1", HealthState::Healthy);
        // Inverted: (100-90)/3=3, resource (100-90)/3=3, cog=10/3=3 → 9 × 0.7 ≈ 6
        assert!(score.score < 15, "healthy host score={}", score.score);
    }

    #[test]
    fn unknown_health_defaults_to_stable_trend() {
        let mut engine = AutonomousFailoverEngine::new();
        let score = engine.evaluate_host_health("host-1", HealthState::Unknown);
        // Inverted: (100-40)/3=20, (100-40)/3=20, 40/3≈13 → 53 × 1.0 = 53
        assert!(score.score >= 40 && score.score <= 60,
            "unknown host score={}", score.score);
    }

    // ── Decision thresholds ────────────────────────────────────────────

    #[test]
    fn score_below_25_decides_no_action() {
        let engine = AutonomousFailoverEngine::new();
        let score = FailoverScore {
            score: 20,
            components: FailoverScoring::default(),
            recommendation: FailoverDecision::NoAction,
        };
        let decision = engine.decide_failover("host-1", score);
        assert_eq!(decision, Some(FailoverDecision::NoAction));
    }

    #[test]
    fn score_25_to_49_decides_warm_standby() {
        let engine = AutonomousFailoverEngine::new();
        let score = FailoverScore {
            score: 40,
            components: FailoverScoring::default(),
            recommendation: FailoverDecision::NoAction,
        };
        let decision = engine.decide_failover("host-1", score);
        assert!(matches!(decision, Some(FailoverDecision::WarmStandby(_))));
    }

    #[test]
    fn score_50_to_74_decides_active_failover() {
        let engine = AutonomousFailoverEngine::new();
        let score = FailoverScore {
            score: 60,
            components: FailoverScoring::default(),
            recommendation: FailoverDecision::NoAction,
        };
        let decision = engine.decide_failover("host-1", score);
        assert!(matches!(decision, Some(FailoverDecision::ActiveFailover(_))));
    }

    #[test]
    fn score_above_75_decides_full_promote() {
        let engine = AutonomousFailoverEngine::new();
        let score = FailoverScore {
            score: 85,
            components: FailoverScoring::default(),
            recommendation: FailoverDecision::NoAction,
        };
        let decision = engine.decide_failover("host-1", score);
        assert!(matches!(decision, Some(FailoverDecision::FullPromote(_))));
    }

    // ── Blast radius limit ─────────────────────────────────────────────

    #[test]
    fn new_engine_can_execute_more() {
        let engine = AutonomousFailoverEngine::new();
        assert!(engine.can_execute_more());
    }

    #[test]
    fn cannot_execute_when_at_limit() {
        let mut engine = AutonomousFailoverEngine::new();
        // Fill to max.
        for i in 0..engine.max_simultaneous_failovers {
            engine
                .execute_failover(FailoverDecision::WarmStandby(format!("t-{i}")))
                .unwrap();
        }
        assert!(!engine.can_execute_more());
    }

    #[test]
    fn execute_failover_respects_blast_radius() {
        let mut engine = AutonomousFailoverEngine::new();
        engine.max_simultaneous_failovers = 2;

        engine
            .execute_failover(FailoverDecision::WarmStandby("t-1".into()))
            .unwrap();
        engine
            .execute_failover(FailoverDecision::ActiveFailover("t-2".into()))
            .unwrap();

        let result =
            engine.execute_failover(FailoverDecision::WarmStandby("t-3".into()));
        assert!(result.is_err());
        match result.unwrap_err() {
            AutonomousError::FailoverLimitExceeded { max, current } => {
                assert_eq!(max, 2);
                assert_eq!(current, 2);
            }
            _ => panic!("expected FailoverLimitExceeded"),
        }
    }

    // ── History tracking ───────────────────────────────────────────────

    #[test]
    fn history_empty_on_new_engine() {
        let engine = AutonomousFailoverEngine::new();
        assert!(engine.get_failover_history().is_empty());
    }

    #[test]
    fn complete_failover_adds_to_history() {
        let mut engine = AutonomousFailoverEngine::new();
        let active = engine
            .execute_failover(FailoverDecision::ActiveFailover("t-1".into()))
            .unwrap();
        let fid = active.failover_id.clone();

        engine.complete_failover(&fid, true).unwrap();

        let history = engine.get_failover_history();
        assert_eq!(history.len(), 1);
        assert!(history[0].success);
        assert!(history[0].completed_at.is_some());
        assert_eq!(history[0].target_host, "t-1");
    }

    #[test]
    fn complete_failover_removes_from_active() {
        let mut engine = AutonomousFailoverEngine::new();
        let active = engine
            .execute_failover(FailoverDecision::WarmStandby("t-1".into()))
            .unwrap();
        let fid = active.failover_id.clone();

        assert_eq!(engine.active_failovers.len(), 1);
        engine.complete_failover(&fid, true).unwrap();
        assert!(engine.active_failovers.is_empty());
    }

    #[test]
    fn complete_failover_records_failure() {
        let mut engine = AutonomousFailoverEngine::new();
        let active = engine
            .execute_failover(FailoverDecision::ActiveFailover("t-1".into()))
            .unwrap();
        let fid = active.failover_id.clone();

        engine.complete_failover(&fid, false).unwrap();

        let history = engine.get_failover_history();
        assert!(!history[0].success);
        assert_eq!(engine.phase, FailoverPhase::RolledBack);
    }

    #[test]
    fn complete_nonexistent_failover_returns_error() {
        let mut engine = AutonomousFailoverEngine::new();
        let result = engine.complete_failover("nonexistent", true);
        assert!(result.is_err());
        match result.unwrap_err() {
            AutonomousError::FailoverNotFound(id) => {
                assert_eq!(id, "nonexistent");
            }
            _ => panic!("expected FailoverNotFound"),
        }
    }

    // ── Coordinator promotion ──────────────────────────────────────────

    #[test]
    fn promote_coordinator_adds_history_record() {
        let mut engine = AutonomousFailoverEngine::new();
        // Add a dummy active failover first.
        engine
            .execute_failover(FailoverDecision::WarmStandby("t-1".into()))
            .unwrap();

        engine.promote_coordinator("host-alpha").unwrap();

        let history = engine.get_failover_history();
        let promo = history.iter().find(|r| r.source_host == "fleet-coordinator");
        assert!(promo.is_some(), "promotion should appear in history");
        assert_eq!(promo.unwrap().target_host, "host-alpha");
        assert!(promo.unwrap().success);
    }

    #[test]
    fn promote_coordinator_clears_active_failovers() {
        let mut engine = AutonomousFailoverEngine::new();
        engine
            .execute_failover(FailoverDecision::WarmStandby("t-1".into()))
            .unwrap();
        engine
            .execute_failover(FailoverDecision::ActiveFailover("t-2".into()))
            .unwrap();
        assert_eq!(engine.active_failovers.len(), 2);

        engine.promote_coordinator("host-alpha").unwrap();
        assert!(engine.active_failovers.is_empty());
        assert_eq!(engine.phase, FailoverPhase::Monitoring);
    }

    #[test]
    fn promote_coordinator_rejects_empty_name() {
        let mut engine = AutonomousFailoverEngine::new();
        let result = engine.promote_coordinator("");
        assert!(result.is_err());
        match result.unwrap_err() {
            AutonomousError::CoordinatorPromotionFailed(msg) => {
                assert!(msg.contains("empty"));
            }
            _ => panic!("expected CoordinatorPromotionFailed"),
        }
    }

    // ── Failover execution details ─────────────────────────────────────

    #[test]
    fn execute_no_action_returns_error() {
        let mut engine = AutonomousFailoverEngine::new();
        let result = engine.execute_failover(FailoverDecision::NoAction);
        assert!(result.is_err());
        match result.unwrap_err() {
            AutonomousError::InvalidFailoverState(msg) => {
                assert!(msg.contains("NoAction"));
            }
            _ => panic!("expected InvalidFailoverState"),
        }
    }

    #[test]
    fn active_failover_has_correct_phase() {
        let mut engine = AutonomousFailoverEngine::new();
        let af = engine
            .execute_failover(FailoverDecision::ActiveFailover("t-1".into()))
            .unwrap();
        assert_eq!(af.phase, FailoverPhase::ActiveFailover);
        assert_eq!(engine.phase, FailoverPhase::ActiveFailover);
    }

    #[test]
    fn warm_standby_sets_warm_standby_phase() {
        let mut engine = AutonomousFailoverEngine::new();
        let af = engine
            .execute_failover(FailoverDecision::WarmStandby("t-1".into()))
            .unwrap();
        assert_eq!(af.phase, FailoverPhase::WarmStandby);
    }

    #[test]
    fn failover_evidence_hash_is_computed() {
        let mut engine = AutonomousFailoverEngine::new();
        let af = engine
            .execute_failover(FailoverDecision::ActiveFailover("t-1".into()))
            .unwrap();
        assert!(!af.evidence_hash.is_empty());
        assert_eq!(af.evidence_hash.len(), 64); // Blake3 hex = 64 chars
    }

    #[test]
    fn multiple_completions_produce_multiple_history_entries() {
        let mut engine = AutonomousFailoverEngine::new();
        let a1 = engine
            .execute_failover(FailoverDecision::WarmStandby("t-1".into()))
            .unwrap();
        engine.complete_failover(&a1.failover_id, true).unwrap();

        let a2 = engine
            .execute_failover(FailoverDecision::ActiveFailover("t-2".into()))
            .unwrap();
        engine.complete_failover(&a2.failover_id, false).unwrap();

        assert_eq!(engine.get_failover_history().len(), 2);
    }

    #[test]
    fn get_failover_history_returns_immutable_ref() {
        let mut engine = AutonomousFailoverEngine::new();
        let af = engine
            .execute_failover(FailoverDecision::WarmStandby("t-1".into()))
            .unwrap();
        engine.complete_failover(&af.failover_id, true).unwrap();

        let history = engine.get_failover_history();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn full_evaluate_to_execute_cycle() {
        let mut engine = AutonomousFailoverEngine::new();

        let score = engine.evaluate_host_health("host-critical", HealthState::Failed);
        assert!(score.score > 50);

        let decision = engine
            .decide_failover("host-critical", score)
            .unwrap();
        assert!(matches!(decision, FailoverDecision::FullPromote(_)));

        let af = engine.execute_failover(decision).unwrap();
        assert!(af.source_host.contains("fleet-coordinator")
            || af.source_host.contains("auto-detected"));
    }
}
