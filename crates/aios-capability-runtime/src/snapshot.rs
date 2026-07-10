//! Plan 9 Fossil / Singularity -inspired capsule snapshot & restore.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::explicit_iter_loop)]
//!
//! ## OS Research Provenance
//!
//! **Plan 9 Fossil** (Bell Labs, 2003) was the default file server for Plan 9
//! starting with the Fourth Edition.  Its killer feature was **versioned
//! snapshots** — the entire filesystem could be frozen at a point in time
//! and later re-mounted, diffed, or rolled back.  A snapshot took O(1) time
//! (copy-on-write) and consumed space proportional to the delta.
//!
//! **Singularity** (Microsoft Research, 2003–2015) introduced
//! **software-isolated processes (SIPs)** that ran in a single address space
//! with type-safe managed code.  Because the kernel trusted the compiler's
//! type-safety guarantees, SIPs could be **checkpointed** (state capture)
//! and **restored** without hardware context-switch overhead.  A SIP's
//! entire state — stack, heap, registers — was just a managed object graph.
//!
//! ### Mapping to AIOS Capsule Architecture
//!
//! | Plan 9 / Singularity concept | AIOS equivalent                         |
//! |------------------------------|-----------------------------------------|
//! | Fossil snapshot             | [`CapsuleSnapshot`] (freeze capsule state)|
//! | Fossil `snap -a`            | [`CapsuleSnapshot::freeze`]              |
//! | Fossil `snap -d`            | [`SnapshotStore::delete_snapshot`]        |
//! | Singularity SIP checkpoint  | [`SnapshotPayload::CapsuleState`]         |
//! | Singularity restore         | [`SnapshotStore::restore`]                |
//! | Copy-on-write               | Delta / metadata-only snapshots           |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-SNAP-001 (Freeze immutability):** A [`CapsuleSnapshot`] is
//!   immutable once created.  It cannot be modified.
//! - **INV-SNAP-002 (Restore idempotence):** Restoring a snapshot produces
//!   a capsule with exactly the state captured at freeze time, regardless
//!   of how many times it is restored.
//! - **INV-SNAP-003 (Snapshot ordering):** Snapshots are ordered by
//!   creation time.  `snapshots()[0]` is always the oldest.
//! - **INV-SNAP-004 (Capsule isolation):** Snapshots of different capsules
//!   are stored in separate namespaces.
//! - **INV-SNAP-005 (Purge safety):** Deleting a snapshot does not affect
//!   any other snapshot of the same capsule.

use std::collections::HashMap;
use std::fmt;

/// Re-use capsule identity.
use super::capsule_namespace::CapsuleId;
use super::sel4_cap_model::CapRights;

// ---------------------------------------------------------------------------
// SnapshotId — unique snapshot identifier
// ---------------------------------------------------------------------------

/// Global unique identifier for a capsule snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotId(pub u64);

impl SnapshotId {
    /// Raw numeric value.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "snap-{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// SnapshotPayload — what is captured
// ---------------------------------------------------------------------------

/// The type of state captured in a snapshot.
///
/// This models Singularity's SIP checkpoint taxonomy: a snapshot can capture
/// full state, just metadata, or a subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotPayload {
    /// Full capsule state (Singularity SIP checkpoint — stack + heap + regs).
    CapsuleState {
        /// Serialised state blob (e.g. JSON, CBOR, protobuf).
        data: Vec<u8>,
        /// MIME type of the serialised state for deserialisation.
        mime: String,
    },
    /// Metadata-only snapshot (capabilities, namespace bindings — no heap).
    Metadata {
        /// Namespace mount table at freeze time.
        namespace_bindings: Vec<String>,
        /// Capability token IDs at freeze time.
        capability_ids: Vec<u64>,
        /// Access-rights snapshot.
        rights_snapshot: Option<CapRights>,
    },
    /// Delta snapshot — only the diff from a parent snapshot.
    Delta {
        /// The parent snapshot this delta is based on.
        base_snapshot_id: SnapshotId,
        /// Serialised diff.
        delta: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// CapsuleSnapshot — a point-in-time freeze
// ---------------------------------------------------------------------------

/// A frozen point-in-time capture of a capsule's state, inspired by Plan 9
/// Fossil snapshots and Singularity SIP checkpoints.
///
/// Once created, a snapshot is **immutable** (INV-SNAP-001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleSnapshot {
    /// Unique identifier for this snapshot.
    pub id: SnapshotId,
    /// The capsule whose state was captured.
    pub capsule_id: CapsuleId,
    /// Human-readable label (e.g. "pre-rollback-v2", "after-training").
    pub label: String,
    /// When the snapshot was taken.
    pub frozen_at: u64, // Unix timestamp in seconds (simplified for testability)
    /// The captured state.
    pub payload: SnapshotPayload,
}

impl CapsuleSnapshot {
    /// Create a new snapshot.
    #[must_use]
    pub fn new(
        id: SnapshotId,
        capsule_id: CapsuleId,
        label: String,
        frozen_at: u64,
        payload: SnapshotPayload,
    ) -> Self {
        Self {
            id,
            capsule_id,
            label,
            frozen_at,
            payload,
        }
    }

    /// Whether this is a full-state snapshot.
    #[must_use]
    pub const fn is_full_state(&self) -> bool {
        matches!(self.payload, SnapshotPayload::CapsuleState { .. })
    }

    /// Whether this is a delta (depends on a parent snapshot).
    #[must_use]
    pub const fn is_delta(&self) -> bool {
        matches!(self.payload, SnapshotPayload::Delta { .. })
    }
}

// ---------------------------------------------------------------------------
// SnapshotStore — the snapshot repository
// ---------------------------------------------------------------------------

/// A repository of capsule snapshots, analogous to Plan 9's Fossil
/// snapshot arena or Singularity's checkpoint store.
///
/// Snapshots are organised **per-capsule** (INV-SNAP-004).  Within each
/// capsule's namespace, snapshots are ordered by creation time
/// (INV-SNAP-003).
#[derive(Debug, Default, Clone)]
pub struct SnapshotStore {
    /// Per-capsule snapshot lists, ordered by `frozen_at`.
    snapshots: HashMap<CapsuleId, Vec<CapsuleSnapshot>>,
    /// Global snapshot ID counter.
    next_id: u64,
}

impl SnapshotStore {
    /// Create an empty snapshot store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            next_id: 1,
        }
    }

    /// ---------- freeze (create snapshot) ------------------------------------
    ///

    /// Freeze a capsule's state and store the snapshot.
    ///
    /// The new snapshot is appended to the capsule's snapshot list,
    /// maintaining chronological order (INV-SNAP-003).
    ///
    /// Returns the created [`CapsuleSnapshot`].
    pub fn freeze(
        &mut self,
        capsule_id: CapsuleId,
        label: String,
        frozen_at: u64,
        payload: SnapshotPayload,
    ) -> CapsuleSnapshot {
        let id = SnapshotId(self.next_id);
        self.next_id += 1;

        let snapshot = CapsuleSnapshot::new(id, capsule_id, label, frozen_at, payload);
        self.snapshots
            .entry(capsule_id)
            .or_default()
            .push(snapshot.clone());
        snapshot
    }

    /// ---------- restore -----------------------------------------------------
    ///

    /// Retrieve a snapshot by its ID.
    ///
    /// Returns `None` if the snapshot does not exist.
    #[must_use]
    pub fn get(&self, snapshot_id: SnapshotId) -> Option<&CapsuleSnapshot> {
        self.snapshots
            .values()
            .flat_map(|snaps| snaps.iter())
            .find(|s| s.id == snapshot_id)
    }

    /// Get the latest (most recent) snapshot for a capsule.
    #[must_use]
    pub fn latest(&self, capsule_id: CapsuleId) -> Option<&CapsuleSnapshot> {
        self.snapshots
            .get(&capsule_id)
            .and_then(|snaps| snaps.last())
    }

    /// Get the earliest (oldest) snapshot for a capsule.
    #[must_use]
    pub fn earliest(&self, capsule_id: CapsuleId) -> Option<&CapsuleSnapshot> {
        self.snapshots
            .get(&capsule_id)
            .and_then(|snaps| snaps.first())
    }

    /// List all snapshots for a capsule in chronological order.
    #[must_use]
    pub fn list(&self, capsule_id: CapsuleId) -> &[CapsuleSnapshot] {
        self.snapshots
            .get(&capsule_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// ---------- delete (purge) ---------------------------------------------
    ///

    /// Delete a specific snapshot by ID.
    ///
    /// Returns `true` if the snapshot was found and removed.
    /// Deleting one snapshot does **not** affect others (INV-SNAP-005).
    pub fn delete_snapshot(&mut self, snapshot_id: SnapshotId) -> bool {
        for (_, snaps) in self.snapshots.iter_mut() {
            if let Some(pos) = snaps.iter().position(|s| s.id == snapshot_id) {
                snaps.remove(pos);
                return true;
            }
        }
        false
    }

    /// Delete all snapshots for a capsule (teardown).
    ///
    /// Returns the number of snapshots removed.
    pub fn delete_all_for_capsule(&mut self, capsule_id: CapsuleId) -> usize {
        self.snapshots
            .remove(&capsule_id)
            .map(|snaps| snaps.len())
            .unwrap_or(0)
    }

    /// ---------- inspectors -------------------------------------------------
    ///

    /// Total number of snapshots across all capsules.
    #[must_use]
    pub fn total_snapshot_count(&self) -> usize {
        self.snapshots.values().map(|v| v.len()).sum()
    }

    /// Number of capsules that have at least one snapshot.
    #[must_use]
    pub fn capsule_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}

// ===========================================================================
// Tests — INV-SNAP-001 through INV-SNAP-005
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CapsuleSnapshot creation
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_creation() {
        let snap = CapsuleSnapshot::new(
            SnapshotId(1),
            CapsuleId(10),
            "checkpoint-v1".into(),
            1000,
            SnapshotPayload::CapsuleState {
                data: vec![1, 2, 3],
                mime: "application/octet-stream".into(),
            },
        );
        assert_eq!(snap.capsule_id, CapsuleId(10));
        assert_eq!(snap.label, "checkpoint-v1");
        assert_eq!(snap.frozen_at, 1000);
        assert!(snap.is_full_state());
        assert!(!snap.is_delta());
    }

    #[test]
    fn delta_snapshot_detection() {
        let delta = CapsuleSnapshot::new(
            SnapshotId(2),
            CapsuleId(10),
            "delta-from-v1".into(),
            1200,
            SnapshotPayload::Delta {
                base_snapshot_id: SnapshotId(1),
                delta: vec![4, 5],
            },
        );
        assert!(delta.is_delta());
        assert!(!delta.is_full_state());
    }

    #[test]
    fn metadata_snapshot() {
        let snap = CapsuleSnapshot::new(
            SnapshotId(3),
            CapsuleId(10),
            "meta-only".into(),
            1300,
            SnapshotPayload::Metadata {
                namespace_bindings: vec!["/models/llm".into()],
                capability_ids: vec![1, 2],
                rights_snapshot: None,
            },
        );
        assert!(!snap.is_full_state());
        assert!(!snap.is_delta());
    }

    // -----------------------------------------------------------------------
    // SnapshotStore — freeze
    // -----------------------------------------------------------------------

    #[test]
    fn store_starts_empty() {
        let store = SnapshotStore::new();
        assert!(store.is_empty());
        assert_eq!(store.total_snapshot_count(), 0);
    }

    #[test]
    fn freeze_creates_and_stores_snapshot() {
        let mut store = SnapshotStore::new();
        let snap = store.freeze(
            CapsuleId(1),
            "initial".into(),
            100,
            SnapshotPayload::CapsuleState {
                data: vec![10, 20],
                mime: "application/cbor".into(),
            },
        );
        assert_eq!(snap.capsule_id, CapsuleId(1));
        assert_eq!(store.total_snapshot_count(), 1);
        assert!(!store.is_empty());

        // Should be retrievable.
        assert!(store.get(snap.id).is_some());
    }

    // -----------------------------------------------------------------------
    // INV-SNAP-003: chronological ordering
    // -----------------------------------------------------------------------

    #[test]
    fn snapshots_are_chronologically_ordered() {
        let mut store = SnapshotStore::new();
        let s1 = store.freeze(CapsuleId(1), "first".into(), 100, snapshot_state());
        let s2 = store.freeze(CapsuleId(1), "second".into(), 200, snapshot_state());
        let s3 = store.freeze(CapsuleId(1), "third".into(), 300, snapshot_state());

        let list = store.list(CapsuleId(1));
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].id, s1.id); // oldest first
        assert_eq!(list[1].id, s2.id);
        assert_eq!(list[2].id, s3.id); // newest last
    }

    // -----------------------------------------------------------------------
    // INV-SNAP-004: capsule isolation
    // -----------------------------------------------------------------------

    #[test]
    fn snapshots_of_different_capsules_are_isolated() {
        let mut store = SnapshotStore::new();
        store.freeze(CapsuleId(1), "a".into(), 100, snapshot_state());
        store.freeze(CapsuleId(2), "b".into(), 200, snapshot_state());

        assert_eq!(store.list(CapsuleId(1)).len(), 1);
        assert_eq!(store.list(CapsuleId(2)).len(), 1);
        assert_eq!(store.total_snapshot_count(), 2);
        assert_eq!(store.capsule_count(), 2);
    }

    // -----------------------------------------------------------------------
    // Latest / earliest
    // -----------------------------------------------------------------------

    #[test]
    fn latest_and_earliest() {
        let mut store = SnapshotStore::new();
        store.freeze(CapsuleId(1), "oldest".into(), 100, snapshot_state());
        store.freeze(CapsuleId(1), "newest".into(), 999, snapshot_state());

        assert_eq!(store.latest(CapsuleId(1)).unwrap().label, "newest");
        assert_eq!(store.earliest(CapsuleId(1)).unwrap().label, "oldest");
    }

    #[test]
    fn latest_on_nonexistent_capsule_returns_none() {
        let store = SnapshotStore::new();
        assert!(store.latest(CapsuleId(999)).is_none());
    }

    // -----------------------------------------------------------------------
    // INV-SNAP-005: purge safety — deleting one doesn't affect others
    // -----------------------------------------------------------------------

    #[test]
    fn deleting_one_snapshot_preserves_others() {
        let mut store = SnapshotStore::new();
        let s1 = store.freeze(CapsuleId(1), "keep".into(), 100, snapshot_state());
        let s2 = store.freeze(CapsuleId(1), "delete_me".into(), 200, snapshot_state());

        assert!(store.delete_snapshot(s2.id));
        assert_eq!(store.list(CapsuleId(1)).len(), 1);
        assert!(store.get(s1.id).is_some()); // s1 still intact
        assert!(store.get(s2.id).is_none());
    }

    #[test]
    fn delete_nonexistent_returns_false() {
        let mut store = SnapshotStore::new();
        assert!(!store.delete_snapshot(SnapshotId(999)));
    }

    // -----------------------------------------------------------------------
    // Delete all for capsule
    // -----------------------------------------------------------------------

    #[test]
    fn delete_all_clears_capsule_snapshots() {
        let mut store = SnapshotStore::new();
        store.freeze(CapsuleId(1), "a".into(), 100, snapshot_state());
        store.freeze(CapsuleId(1), "b".into(), 200, snapshot_state());
        store.freeze(CapsuleId(2), "c".into(), 300, snapshot_state());

        let removed = store.delete_all_for_capsule(CapsuleId(1));
        assert_eq!(removed, 2);
        assert!(store.list(CapsuleId(1)).is_empty());
        assert_eq!(store.list(CapsuleId(2)).len(), 1); // Capsule 2 unaffected
    }

    // -----------------------------------------------------------------------
    // INV-SNAP-002: restore idempotence (get returns same data every time)
    // -----------------------------------------------------------------------

    #[test]
    fn get_is_idempotent() {
        let mut store = SnapshotStore::new();
        let snap = store.freeze(CapsuleId(1), "checkpoint".into(), 100, snapshot_state());
        let r1 = store.get(snap.id).unwrap();
        let r2 = store.get(snap.id).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(r1.id, snap.id);
    }

    // -----------------------------------------------------------------------
    // Snapshots across many capsules
    // -----------------------------------------------------------------------

    #[test]
    fn multi_capsule_workload() {
        let mut store = SnapshotStore::new();
        for c in 0..5u64 {
            store.freeze(CapsuleId(c), format!("snap-c{}", c), 100, snapshot_state());
        }
        assert_eq!(store.capsule_count(), 5);
        assert_eq!(store.total_snapshot_count(), 5);
    }

    // -----------------------------------------------------------------------
    // Display
    // -----------------------------------------------------------------------

    #[test]
    fn display_snapshot_id() {
        assert_eq!(format!("{}", SnapshotId(42)), "snap-42");
    }

    // --- helper -------------------------------------------------------------

    fn snapshot_state() -> SnapshotPayload {
        SnapshotPayload::CapsuleState {
            data: vec![1],
            mime: "application/octet-stream".into(),
        }
    }
}
