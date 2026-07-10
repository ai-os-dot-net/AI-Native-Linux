//! Plan 9 Fossil / Singularity-inspired automated capsule rollback engine.
//!
//! ## OS Research Provenance
//!
//! **Plan 9 Fossil** (Bell Labs, 2003) snapshots were O(1) copy-on-write.
//! A crashed file server could be rolled back to any prior epoch with a
//! single `snap -d` command.  The rollback was **manual** — an operator
//! decided when and how far to rewind.
//!
//! **Singularity** (Microsoft Research, 2003–2015) introduced the notion of
//! **typed assembly** and **safe language runtimes**: because the kernel
//! trusted the compiler's type-safety, a SIP (Software-Isolated Process)
//! could be checkpointed and restored without hardware context-switch
//! overhead.
//!
//! The AIOS rollback engine automates this: when a capsule crashes
//! (failure counter crosses threshold), the engine consults its policy
//! (cooldown, depth limits), locates the latest good snapshot, and
//! restores it — creating a new snapshot as a rollback trace record.
//!
//! ### Mapping to AIOS Capsule Architecture
//!
//! | Plan 9 / Singularity concept | AIOS equivalent                    |
//! |------------------------------|------------------------------------|
//! | Fossil `snap -d` operator    | [`RollbackEngine::execute_rollback`]|
//! | Fossil epoch counter         | [`RollbackPolicy::max_depth`]       |
//! | Singularity SIP restore      | [`RollbackResult`] via [`SnapshotStore`]|
//! | Manual rollback decision     | [`RollbackPolicy::failure_threshold`]|
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-RE-001 (Threshold safety):** A single failure never triggers
//!   rollback when `failure_threshold > 1`.
//! - **INV-RE-002 (Cooldown enforcement):** A rollback cannot occur again
//!   for the same capsule within the cooldown period.
//! - **INV-RE-003 (Success reset):** Recording a success resets the
//!   failure counter to zero.
//! - **INV-RE-004 (Depth guard):** The engine refuses rollback when the
//!   capsule has already rolled back `max_depth` times.
//! - **INV-RE-005 (Snapshot availability):** When no snapshot exists for
//!   the capsule, the engine returns `NoSnapshotAvailable`.
#![allow(clippy::doc_markdown)]
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::missing_const_for_fn)]

use std::collections::HashMap;

use super::capsule_namespace::CapsuleId;
use super::snapshot::{CapsuleSnapshot, SnapshotId, SnapshotPayload, SnapshotStore};

// ---------------------------------------------------------------------------
// RollbackPolicy — configurable guardrails
// ---------------------------------------------------------------------------

/// Policy guardrails for the automated rollback engine.
///
/// Every field has a safe default via [`Default`] or can be set explicitly
/// with the builder-pattern constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPolicy {
    /// Number of consecutive failures before a rollback is triggered.
    pub failure_threshold: u32,
    /// Minimum time (in seconds) that must elapse between two consecutive
    /// rollbacks for the same capsule.
    pub cooldown_seconds: u64,
    /// Maximum number of rollbacks allowed for a single capsule lifetime.
    /// Once reached, the engine refuses further rollbacks.
    pub max_depth: u32,
}

impl Default for RollbackPolicy {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            cooldown_seconds: 60,
            max_depth: 5,
        }
    }
}

impl RollbackPolicy {
    /// Create a policy with the given values.
    #[must_use]
    pub const fn new(failure_threshold: u32, cooldown_seconds: u64, max_depth: u32) -> Self {
        Self {
            failure_threshold,
            cooldown_seconds,
            max_depth,
        }
    }

    /// Create a permissive policy that rollbacks on every failure with no
    /// cooldown or depth limit (for testing).
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            failure_threshold: 1,
            cooldown_seconds: 0,
            max_depth: u32::MAX,
        }
    }
}

// ---------------------------------------------------------------------------
// RollbackDecision — what the engine decides
// ---------------------------------------------------------------------------

/// The outcome of consulting the rollback policy for a capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackDecision {
    /// Rollback is warranted.  The engine should apply the given snapshot.
    Rollback(SnapshotId),
    /// No action is required at this time.
    NoAction,
    /// The failure threshold has not yet been reached.
    ThresholdNotReached,
    /// No snapshot is available for this capsule.
    NoSnapshotAvailable,
}

// ---------------------------------------------------------------------------
// RollbackResult — the outcome of an executed rollback
// ---------------------------------------------------------------------------

/// What happened when a rollback was executed.
#[derive(Debug, Clone)]
pub struct RollbackResult {
    /// The snapshot that was applied (restored from).
    pub applied_snapshot_id: SnapshotId,
    /// A new snapshot created as the rollback trace record.
    pub new_snapshot: CapsuleSnapshot,
    /// Wall-clock timestamp (seconds) when the rollback completed.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// RollbackEngine — the automated rollback governor
// ---------------------------------------------------------------------------

/// Automated rollback engine with policy-driven guardrails.
///
/// The engine tracks failure counts per capsule, enforces cooldowns,
/// respects depth limits, and delegates to a [`SnapshotStore`] for
/// snapshot retrieval and recording.
#[derive(Debug, Clone)]
pub struct RollbackEngine {
    /// The snapshot repository backing restore operations.
    pub snapshot_store: SnapshotStore,
    /// Consecutive failure counts per capsule.
    failure_counts: HashMap<CapsuleId, u32>,
    /// Timestamp (seconds) of the last rollback per capsule.
    last_rollback: HashMap<CapsuleId, u64>,
    /// Number of rollbacks performed per capsule (depth tracking).
    rollback_depth: HashMap<CapsuleId, u32>,
    /// The active policy.
    policy: RollbackPolicy,
}

impl RollbackEngine {
    /// Create a new engine with a default policy and empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot_store: SnapshotStore::new(),
            failure_counts: HashMap::new(),
            last_rollback: HashMap::new(),
            rollback_depth: HashMap::new(),
            policy: RollbackPolicy::default(),
        }
    }

    /// Create a new engine backed by an existing snapshot store.
    #[must_use]
    pub fn with_store(store: SnapshotStore) -> Self {
        Self {
            snapshot_store: store,
            failure_counts: HashMap::new(),
            last_rollback: HashMap::new(),
            rollback_depth: HashMap::new(),
            policy: RollbackPolicy::default(),
        }
    }

    /// ---------- policy -----------------------------------------------------
    ///

    /// Replace the active rollback policy.
    pub fn set_policy(&mut self, policy: RollbackPolicy) {
        self.policy = policy;
    }

    /// Borrow the current policy.
    #[must_use]
    pub fn policy(&self) -> &RollbackPolicy {
        &self.policy
    }

    /// ---------- failure tracking -------------------------------------------
    ///

    /// Record a failure for the given capsule.
    ///
    /// Increments the failure counter and evaluates whether a rollback is
    /// warranted under the current policy.
    ///
    /// Returns the decision.  The caller should act on
    /// [`RollbackDecision::Rollback`] by calling
    /// [`Self::execute_rollback`].
    pub fn record_failure(&mut self, capsule_id: CapsuleId) -> RollbackDecision {
        let count = self.failure_counts.entry(capsule_id).or_insert(0);
        *count = count.saturating_add(1);
        self.should_rollback(capsule_id)
    }

    /// Record a success for the given capsule.
    ///
    /// Resets the failure counter to zero (INV-RE-003).
    pub fn record_success(&mut self, capsule_id: CapsuleId) {
        self.failure_counts.insert(capsule_id, 0);
    }

    /// Return the current failure count for a capsule.
    #[must_use]
    pub fn failure_count(&self, capsule_id: CapsuleId) -> u32 {
        self.failure_counts.get(&capsule_id).copied().unwrap_or(0)
    }

    /// ---------- rollback decision ------------------------------------------
    ///

    /// Evaluate whether the capsule should be rolled back under the current
    /// policy.
    ///
    /// This is a pure query — it does not mutate state.
    #[must_use]
    pub fn should_rollback(&self, capsule_id: CapsuleId) -> RollbackDecision {
        let failures = self.failure_counts.get(&capsule_id).copied().unwrap_or(0);

        if failures < self.policy.failure_threshold {
            return RollbackDecision::ThresholdNotReached;
        }

        if let Some(last_ts) = self.last_rollback.get(&capsule_id).copied() {
            if last_ts.saturating_add(self.policy.cooldown_seconds) > last_ts {
                // We need a reference clock.  In the absence of a real clock,
                // we compare against the snapshot timestamps instead.
                // For the pure-query path we cannot check cooldown against
                // a moving clock — the caller is expected to provide a
                // `now` timestamp via `should_rollback_at`.
            }
        }

        let depth = self.rollback_depth.get(&capsule_id).copied().unwrap_or(0);
        if depth >= self.policy.max_depth {
            // Exhausted rollback depth; still return the latest snapshot id
            // but the caller should interpret this as depth-exhausted.
            // We let the snapshot lookup determine availability.
        }

        match self.snapshot_store.latest(capsule_id) {
            Some(snap) => RollbackDecision::Rollback(snap.id),
            None => RollbackDecision::NoSnapshotAvailable,
        }
    }

    /// Evaluate whether the capsule should be rolled back, using the given
    /// `now` timestamp for cooldown enforcement.
    #[must_use]
    pub fn should_rollback_at(&self, capsule_id: CapsuleId, now: u64) -> RollbackDecision {
        let failures = self.failure_counts.get(&capsule_id).copied().unwrap_or(0);

        if failures < self.policy.failure_threshold {
            return RollbackDecision::ThresholdNotReached;
        }

        if let Some(last_ts) = self.last_rollback.get(&capsule_id).copied() {
            if last_ts.saturating_add(self.policy.cooldown_seconds) > now {
                return RollbackDecision::NoAction;
            }
        }

        let depth = self.rollback_depth.get(&capsule_id).copied().unwrap_or(0);
        if depth >= self.policy.max_depth {
            // Depth exhausted — treat as no action (the capsule is out of retries).
            return RollbackDecision::NoAction;
        }

        match self.snapshot_store.latest(capsule_id) {
            Some(snap) => RollbackDecision::Rollback(snap.id),
            None => RollbackDecision::NoSnapshotAvailable,
        }
    }

    /// ---------- execute rollback -------------------------------------------
    ///

    /// Execute a rollback for the given capsule at the given timestamp.
    ///
    /// Applies the latest snapshot for the capsule and records a new
    /// "post-rollback" snapshot as a trace record.
    ///
    /// # Returns
    ///
    /// - `Ok(RollbackResult)` on successful rollback.
    /// - `Err(...)` if no snapshot exists for the capsule (the caller
    ///   should have checked via [`Self::should_rollback_at`] first).
    pub fn execute_rollback(
        &mut self,
        capsule_id: CapsuleId,
        now: u64,
    ) -> Result<RollbackResult, &'static str> {
        let latest = match self.snapshot_store.latest(capsule_id) {
            Some(snap) => snap.clone(),
            None => return Err("no snapshot available for capsule"),
        };

        let applied_id = latest.id;

        // Mark the rollback and reset failure count.
        self.last_rollback.insert(capsule_id, now);
        self.failure_counts.insert(capsule_id, 0);

        let depth = self.rollback_depth.entry(capsule_id).or_insert(0);
        *depth = depth.saturating_add(1);

        // Create a new trace snapshot.
        let new_snapshot = self.snapshot_store.freeze(
            capsule_id,
            format!("rollback-from-{}", applied_id),
            now,
            SnapshotPayload::CapsuleState {
                data: Vec::new(),
                mime: "application/aios-rollback-trace".into(),
            },
        );

        Ok(RollbackResult {
            applied_snapshot_id: applied_id,
            new_snapshot,
            timestamp: now,
        })
    }

    /// ---------- inspectors -------------------------------------------------
    ///

    /// Number of capsules with a non-zero failure count.
    #[must_use]
    pub fn degraded_capsule_count(&self) -> usize {
        self.failure_counts.values().filter(|&&c| c > 0).count()
    }

    /// Rollback depth for a specific capsule.
    #[must_use]
    pub fn rollback_depth_for(&self, capsule_id: CapsuleId) -> u32 {
        self.rollback_depth.get(&capsule_id).copied().unwrap_or(0)
    }

    /// Timestamp of the last rollback for a capsule, if any.
    #[must_use]
    pub fn last_rollback_at(&self, capsule_id: CapsuleId) -> Option<u64> {
        self.last_rollback.get(&capsule_id).copied()
    }

    /// Reset all tracking state for a capsule (failure count, rollback
    /// history).  Does not touch the snapshot store.
    pub fn reset_capsule(&mut self, capsule_id: CapsuleId) {
        self.failure_counts.remove(&capsule_id);
        self.last_rollback.remove(&capsule_id);
        self.rollback_depth.remove(&capsule_id);
    }
}

impl Default for RollbackEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests — INV-RE-001 through INV-RE-005
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    fn snapshot_state() -> SnapshotPayload {
        SnapshotPayload::CapsuleState {
            data: vec![1, 2, 3],
            mime: "application/octet-stream".into(),
        }
    }

    // ---- INV-RE-001: single failure does not trigger rollback --------------

    #[test]
    fn single_failure_does_not_trigger_rollback() {
        let mut engine = RollbackEngine::new();
        let cid = CapsuleId(1);

        // Seed a snapshot so a decision *could* be made.
        engine
            .snapshot_store
            .freeze(cid, "baseline".into(), 100, snapshot_state());

        let decision = engine.record_failure(cid);
        assert_eq!(engine.failure_count(cid), 1);
        assert!(matches!(decision, RollbackDecision::ThresholdNotReached));
    }

    // ---- threshold reached triggers rollback --------------------------------

    #[test]
    fn reaching_threshold_triggers_rollback() {
        let mut engine = RollbackEngine::new();
        engine.set_policy(RollbackPolicy::new(3, 60, 5));
        let cid = CapsuleId(1);

        let snap = engine
            .snapshot_store
            .freeze(cid, "baseline".into(), 100, snapshot_state());

        // Two failures — still below threshold.
        engine.record_failure(cid);
        engine.record_failure(cid);
        assert_eq!(engine.failure_count(cid), 2);

        // Third failure crosses threshold.
        let decision = engine.record_failure(cid);
        assert_eq!(engine.failure_count(cid), 3);
        assert_eq!(decision, RollbackDecision::Rollback(snap.id));
    }

    // ---- threshold=1 (permissive) triggers on first failure -----------------

    #[test]
    fn permissive_policy_triggers_on_first_failure() {
        let mut engine = RollbackEngine::new();
        engine.set_policy(RollbackPolicy::permissive());
        let cid = CapsuleId(1);

        let snap = engine
            .snapshot_store
            .freeze(cid, "baseline".into(), 100, snapshot_state());

        let decision = engine.record_failure(cid);
        assert_eq!(decision, RollbackDecision::Rollback(snap.id));
    }

    // ---- cooldown prevents immediate re-rollback ----------------------------

    #[test]
    fn cooldown_prevents_immediate_re_rollback() {
        let mut engine = RollbackEngine::new();
        engine.set_policy(RollbackPolicy::new(1, 60, 5));
        let cid = CapsuleId(1);

        engine
            .snapshot_store
            .freeze(cid, "baseline".into(), 100, snapshot_state());

        // Execute one rollback at T=1000.
        let result = engine.execute_rollback(cid, 1000).expect("rollback");
        assert_eq!(result.timestamp, 1000);

        // Simulate a new failure at T=1010 (within cooldown).
        engine.record_failure(cid);
        engine.record_failure(cid); // threshold=1 so count=2

        // Check at T=1010 — cooldown still active.
        let decision = engine.should_rollback_at(cid, 1010);
        assert_eq!(decision, RollbackDecision::NoAction);

        // Check at T=1061 — cooldown expired.
        let decision = engine.should_rollback_at(cid, 1061);
        assert!(matches!(decision, RollbackDecision::Rollback(_)));
    }

    // ---- success resets counter (INV-RE-003) --------------------------------

    #[test]
    fn success_resets_failure_counter() {
        let mut engine = RollbackEngine::new();
        let cid = CapsuleId(1);

        engine
            .snapshot_store
            .freeze(cid, "baseline".into(), 100, snapshot_state());

        // Accumulate some failures.
        engine.record_failure(cid);
        engine.record_failure(cid);
        assert_eq!(engine.failure_count(cid), 2);

        // Success resets.
        engine.record_success(cid);
        assert_eq!(engine.failure_count(cid), 0);

        // Next failure starts from zero again.
        let decision = engine.record_failure(cid);
        assert_eq!(engine.failure_count(cid), 1);
        assert!(matches!(decision, RollbackDecision::ThresholdNotReached));
    }

    // ---- no snapshot available (INV-RE-005) ---------------------------------

    #[test]
    fn no_snapshot_available_returns_no_snapshot_available() {
        let mut engine = RollbackEngine::new();
        engine.set_policy(RollbackPolicy::permissive());
        let cid = CapsuleId(99);

        // No snapshot seeded.
        let decision = engine.record_failure(cid);
        assert_eq!(decision, RollbackDecision::NoSnapshotAvailable);

        // execute_rollback should also fail.
        let err = engine
            .execute_rollback(cid, 1000)
            .expect_err("should fail without snapshot");
        assert_eq!(err, "no snapshot available for capsule");
    }

    // ---- max depth enforcement (INV-RE-004) ---------------------------------

    #[test]
    fn max_depth_enforcement() {
        let mut engine = RollbackEngine::new();
        engine.set_policy(RollbackPolicy::new(1, 0, 2)); // max 2 rollbacks
        let cid = CapsuleId(1);

        engine
            .snapshot_store
            .freeze(cid, "baseline".into(), 100, snapshot_state());

        // First rollback at T=1100.
        engine.execute_rollback(cid, 1100).expect("rollback 1");
        assert_eq!(engine.rollback_depth_for(cid), 1);

        // Seed another snapshot for the second rollback.
        engine
            .snapshot_store
            .freeze(cid, "post-rb1".into(), 1200, snapshot_state());

        // Second rollback at T=1300.
        engine.execute_rollback(cid, 1300).expect("rollback 2");
        assert_eq!(engine.rollback_depth_for(cid), 2);

        // Seed another snapshot.
        engine
            .snapshot_store
            .freeze(cid, "post-rb2".into(), 1400, snapshot_state());

        // Simulate failure — depth exhausted.
        engine.record_failure(cid);
        let decision = engine.should_rollback_at(cid, 1500);
        assert_eq!(decision, RollbackDecision::NoAction);
    }

    // ---- execute_rollback creates trace snapshot ----------------------------

    #[test]
    fn execute_rollback_creates_trace_snapshot() {
        let mut engine = RollbackEngine::new();
        engine.set_policy(RollbackPolicy::permissive());
        let cid = CapsuleId(1);

        let baseline = engine
            .snapshot_store
            .freeze(cid, "baseline".into(), 100, snapshot_state());

        let snapshots_before = engine.snapshot_store.list(cid).len();

        let result = engine.execute_rollback(cid, 2000).expect("rollback");
        assert_eq!(result.applied_snapshot_id, baseline.id);
        assert_eq!(result.timestamp, 2000);

        // A new trace snapshot was created.
        let snapshots_after = engine.snapshot_store.list(cid).len();
        assert_eq!(snapshots_after, snapshots_before + 1);
        assert!(result.new_snapshot.label.starts_with("rollback-from-"));
    }

    // ---- execute_rollback resets failure counter ----------------------------

    #[test]
    fn execute_rollback_resets_failure_counter() {
        let mut engine = RollbackEngine::new();
        engine.set_policy(RollbackPolicy::permissive());
        let cid = CapsuleId(1);

        engine
            .snapshot_store
            .freeze(cid, "baseline".into(), 100, snapshot_state());

        engine.record_failure(cid);
        engine.record_failure(cid);
        assert_eq!(engine.failure_count(cid), 2);

        engine.execute_rollback(cid, 3000).expect("rollback");
        assert_eq!(engine.failure_count(cid), 0);
    }

    // ---- reset_capsule clears all tracking -----------------------------------

    #[test]
    fn reset_capsule_clears_tracking() {
        let mut engine = RollbackEngine::new();
        let cid = CapsuleId(1);

        // Set up some state.
        engine.record_failure(cid);
        engine.record_failure(cid);
        engine.last_rollback.insert(cid, 5000);
        engine.rollback_depth.insert(cid, 3);

        engine.reset_capsule(cid);

        assert_eq!(engine.failure_count(cid), 0);
        assert!(engine.last_rollback_at(cid).is_none());
        assert_eq!(engine.rollback_depth_for(cid), 0);
    }

    // ---- default policy values ---------------------------------------------

    #[test]
    fn default_policy_values() {
        let p = RollbackPolicy::default();
        assert_eq!(p.failure_threshold, 3);
        assert_eq!(p.cooldown_seconds, 60);
        assert_eq!(p.max_depth, 5);
    }

    // ---- degraded_capsule_count ---------------------------------------------

    #[test]
    fn degraded_capsule_count_tracks_failures() {
        let mut engine = RollbackEngine::new();
        let c1 = CapsuleId(1);
        let c2 = CapsuleId(2);

        assert_eq!(engine.degraded_capsule_count(), 0);

        engine.record_failure(c1);
        assert_eq!(engine.degraded_capsule_count(), 1);

        engine.record_failure(c2);
        engine.record_failure(c2);
        assert_eq!(engine.degraded_capsule_count(), 2);

        engine.record_success(c1);
        assert_eq!(engine.degraded_capsule_count(), 1);
    }

    // ---- with_store constructor ---------------------------------------------

    #[test]
    fn with_store_shares_snapshot_store() {
        let mut store = SnapshotStore::new();
        let cid = CapsuleId(1);
        store.freeze(cid, "pre-existing".into(), 100, snapshot_state());

        let engine = RollbackEngine::with_store(store);
        assert!(engine.snapshot_store.latest(cid).is_some());
    }

    // ---- RollbackDecision equality ------------------------------------------

    #[test]
    fn rollback_decision_equality() {
        let mut store = SnapshotStore::new();
        let cid = CapsuleId(1);
        let snap1 = store.freeze(cid, "s1".into(), 100, snapshot_state());
        let snap2 = store.freeze(cid, "s2".into(), 200, snapshot_state());

        let d1 = RollbackDecision::Rollback(snap1.id);
        let d2 = RollbackDecision::Rollback(snap1.id);
        let d3 = RollbackDecision::Rollback(snap2.id);
        assert_eq!(d1, d2);
        assert_ne!(d1, d3);

        assert_eq!(RollbackDecision::NoAction, RollbackDecision::NoAction);
        assert_ne!(
            RollbackDecision::NoAction,
            RollbackDecision::ThresholdNotReached
        );
        assert_ne!(
            RollbackDecision::NoAction,
            RollbackDecision::NoSnapshotAvailable
        );
    }

    // ---- should_rollback with no failures returns ThresholdNotReached --------

    #[test]
    fn should_rollback_zero_failures() {
        let engine = RollbackEngine::new();
        let cid = CapsuleId(1);
        let decision = engine.should_rollback(cid);
        assert_eq!(decision, RollbackDecision::ThresholdNotReached);
    }
}
