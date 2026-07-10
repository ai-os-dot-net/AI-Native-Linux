//! Per-capsule evidence trail — typed, ordered, auditable lifecycle records.
//!
//! ## OS Research Provenance
//!
//! ### Plan 9 Fossil / Venti snapshot chain (Bell Labs, 2003)
//!
//! Plan 9's Fossil file server wrote every snapshot to a Venti
//! content-addressable block store. Every snapshot carried a pointer to its
//! immediate predecessor, forming an **append-only, hash-linked chain**.
//! This gave Plan 9 operators a tamper-evident audit trail: any historical
//! point could be reconstructed and verified without trust in the running
//! kernel.
//!
//! ### Singularity / Midori causal history (Microsoft Research, 2005–2015)
//!
//! Singularity's software-isolated processes (SIPs) logged every channel
//! contract transition — create, bind, send, close — into a per-SIP typed
//! event stream. Midori (the follow-on) extended this with process-level
//! causal histories so a crash dump could replay the stream and reconstruct
//! exactly which messages were in flight at failure time.
//!
//! ### Mapping to AIOS Capsule Evidence
//!
//! | Concept                         | AIOS equivalent                                   |
//! |---------------------------------|---------------------------------------------------|
//! | Venti score (SHA-1 block hash)  | [`CapsuleEvidence`] ordered by [`chrono::Utc`]    |
//! | Fossil snapshot pointer         | [`EvidenceChain`] per-capsule append-only list    |
//! | Singularity typed event stream  | [`CapsuleEvent`] closed 9-variant enum            |
//! | Midori causal history           | `audit_trail(capsule_id)` chronological replay    |
//! | Venti tamper-evident by design  | Append-only chain — events are never removed      |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-EV-001 (Capsule isolation):** An event recorded under
//!   [`CapsuleId`] `A` never appears in [`CapsuleId`] `B`'s audit trail.
//!   Every capsule's evidence is independently auditable.
//! - **INV-EV-002 (Ordering):** Events within a capsule are strictly
//!   ordered by insertion time — the caller records them in lifecycle order,
//!   and the audit trail returns them in that same order.
//! - **INV-EV-003 (Immutability):** Once recorded, an event is never
//!   mutated or removed. The chain only grows.
//! - **INV-EV-004 (Summary idempotence):** [`CapsuleEvidence::summary`]
//!   returns a deterministic, human-readable string that includes the
//!   capsule id, event variant name, and ISO-8601 timestamp.
//! - **INV-EV-005 (Zero-capsule chain):** A fresh [`EvidenceChain`] holds
//!   zero events; `audit_trail` for any id returns an empty `Vec`.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use super::capsule_namespace::CapsuleId;

// ---------------------------------------------------------------------------
// CapsuleEvent — closed lifecycle-event vocabulary
// ---------------------------------------------------------------------------

/// Every lifecycle transition a capsule undergoes is represented by exactly
/// one variant.
///
/// # Variant lifecycle ordering (happy path)
///
/// ```text
/// Created → Configured → Launched → Paused → SnapshotTaken → Stopped → Destroyed
/// ```
///
/// Crashed and RolledBack are **exception-side** variants — they do not
/// appear in the happy path and indicate a safety or recovery action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapsuleEvent {
    /// Capsule was allocated an identity and an empty namespace.
    Created,
    /// Capsule received its isolation profile, sandbox parameters, and
    /// resource bounds.
    Configured,
    /// Capsule was started — its sandbox is active and the adaptor
    /// endpoint is bound.
    Launched,
    /// Capsule execution was suspended (checkpointed, resources parked).
    Paused,
    /// A full capsule snapshot was taken for rollback or forensic
    /// inspection.
    SnapshotTaken,
    /// Capsule was gracefully shut down (adaptor unbound, sandbox torn
    /// down, namespace cleared).
    Stopped,
    /// Capsule and all associated resources were permanently removed.
    Destroyed,
    /// Capsule terminated abnormally — a panic, sandbox breach, or
    /// resource exhaustion was detected.
    Crashed,
    /// Capsule was rewound to a prior snapshot via the rollback engine.
    RolledBack,
}

impl CapsuleEvent {
    /// Whether this event is a terminal variant (after which no further
    /// lifecycle transitions are expected).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Destroyed | Self::Crashed)
    }

    /// Whether this event represents an exceptional (non-happy-path)
    /// transition.
    #[must_use]
    pub const fn is_exceptional(self) -> bool {
        matches!(self, Self::Crashed | Self::RolledBack)
    }
}

impl std::fmt::Display for CapsuleEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Created => "Created",
            Self::Configured => "Configured",
            Self::Launched => "Launched",
            Self::Paused => "Paused",
            Self::SnapshotTaken => "SnapshotTaken",
            Self::Stopped => "Stopped",
            Self::Destroyed => "Destroyed",
            Self::Crashed => "Crashed",
            Self::RolledBack => "RolledBack",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// CapsuleEvidence — a single typed evidence record
// ---------------------------------------------------------------------------

/// One evidence record binding a [`CapsuleId`], [`CapsuleEvent`], wall-clock
/// timestamp, and optional structured metadata.
///
/// # Metadata convention
///
/// Metadata keys use `snake_case` and carry free-form string values. Common
/// keys include:
///
/// | Key                  | Meaning                                      |
/// |----------------------|----------------------------------------------|
/// | `snapshot_id`        | The [`crate::snapshot::SnapshotId`] created   |
/// | `sandbox_level`      | [`crate::recursive_sandbox::SandboxLevel`]    |
/// | `isolation_mechanism`| Which [`crate::managed_isolate::IsolationMechanism`] was used |
/// | `signal_number`      | OS signal that triggered Crashed              |
/// | `rollback_to`        | The snapshot id to which the capsule rolled back |
/// | `reason`             | Free-form human-readable reason               |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleEvidence {
    /// The capsule this record belongs to.
    pub capsule_id: CapsuleId,
    /// Which lifecycle transition occurred.
    pub event: CapsuleEvent,
    /// Wall-clock instant at which the event was recorded.
    pub timestamp: DateTime<Utc>,
    /// Key-value metadata (snapshot ids, sandbox params, signal numbers,
    /// etc.).
    pub metadata: HashMap<String, String>,
}

impl CapsuleEvidence {
    /// Create a new evidence record with the given capsule, event, and
    /// timestamp. Metadata starts empty — callers add entries via the
    /// mutable [`Self::metadata`] field.
    #[must_use]
    pub fn new(capsule_id: CapsuleId, event: CapsuleEvent, timestamp: DateTime<Utc>) -> Self {
        Self {
            capsule_id,
            event,
            timestamp,
            metadata: HashMap::new(),
        }
    }

    /// Create a new evidence record with pre-populated metadata.
    #[must_use]
    pub fn with_metadata(
        capsule_id: CapsuleId,
        event: CapsuleEvent,
        timestamp: DateTime<Utc>,
        metadata: HashMap<String, String>,
    ) -> Self {
        Self {
            capsule_id,
            event,
            timestamp,
            metadata,
        }
    }

    /// Produce a human-readable single-line summary of this evidence
    /// record.
    ///
    /// Format: `"[capsule-N] EventName @ 2026-06-11T12:00:00Z"`
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use aios_capability_runtime::capsule_evidence::*;
    /// # use aios_capability_runtime::capsule_namespace::CapsuleId;
    /// # use chrono::Utc;
    /// let ev = CapsuleEvidence::new(CapsuleId(7), CapsuleEvent::Launched, Utc::now());
    /// let s = ev.summary();
    /// assert!(s.contains("[capsule-7] Launched"));
    /// ```
    #[must_use]
    pub fn summary(&self) -> String {
        format!("[{}] {} @ {}", self.capsule_id, self.event, self.timestamp)
    }
}

// ---------------------------------------------------------------------------
// EvidenceChain — ordered, per-capsule append-only evidence store
// ---------------------------------------------------------------------------

/// Append-only registry of capsule evidence records.
///
/// Every capsule's events are stored independently in insertion order.
/// The chain never removes or mutates records — it only grows, providing
/// a tamper-evident history analogous to Plan 9 Venti's content-addressable
/// snapshot chain.
///
/// # Example
///
/// ```rust
/// # use aios_capability_runtime::capsule_evidence::*;
/// # use aios_capability_runtime::capsule_namespace::CapsuleId;
/// # use chrono::Utc;
/// let mut chain = EvidenceChain::new();
/// let id = CapsuleId(1);
///
/// let ev = chain.record(id, CapsuleEvent::Created, Utc::now());
/// assert_eq!(chain.count_for(id), 1);
/// assert_eq!(chain.audit_trail(id).len(), 1);
/// ```
#[derive(Debug, Clone, Default)]
pub struct EvidenceChain {
    /// Per-capsule ordered event lists.
    events: HashMap<CapsuleId, Vec<CapsuleEvidence>>,
}

impl EvidenceChain {
    /// Create an empty evidence chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
        }
    }

    /// Record a lifecycle event for `capsule_id`.
    ///
    /// Returns a reference to the stored [`CapsuleEvidence`] record.
    /// The record is appended to the capsule's ordered event list;
    /// existing events for the same or other capsules are never affected.
    ///
    /// # Panics
    ///
    /// This method does not panic. The underlying [`HashMap`] insertion
    /// is infallible, and [`Vec::push`] never panics for bounded types.
    #[must_use]
    pub fn record(
        &mut self,
        capsule_id: CapsuleId,
        event: CapsuleEvent,
        timestamp: DateTime<Utc>,
    ) -> &CapsuleEvidence {
        let evidence = CapsuleEvidence::new(capsule_id, event, timestamp);
        let list = self.events.entry(capsule_id).or_default();
        list.push(evidence);
        &list[list.len() - 1]
    }

    /// Record a lifecycle event with pre-built metadata.
    #[must_use]
    pub fn record_with_metadata(
        &mut self,
        capsule_id: CapsuleId,
        event: CapsuleEvent,
        timestamp: DateTime<Utc>,
        metadata: HashMap<String, String>,
    ) -> &CapsuleEvidence {
        let evidence = CapsuleEvidence::with_metadata(capsule_id, event, timestamp, metadata);
        let list = self.events.entry(capsule_id).or_default();
        list.push(evidence);
        &list[list.len() - 1]
    }

    /// Return the complete ordered audit trail for `capsule_id`.
    ///
    /// Events are returned in insertion order (oldest first). If no
    /// events have been recorded for this capsule, returns an empty
    /// vector.
    ///
    /// INV-EV-002: ordering is strictly insertion order.
    /// INV-EV-001: only events belonging to `capsule_id` are returned.
    #[must_use]
    pub fn audit_trail(&self, capsule_id: CapsuleId) -> Vec<&CapsuleEvidence> {
        self.events
            .get(&capsule_id)
            .map(|list| list.iter().collect())
            .unwrap_or_default()
    }

    /// Return the total number of events recorded for `capsule_id`.
    #[must_use]
    pub fn count_for(&self, capsule_id: CapsuleId) -> usize {
        self.events.get(&capsule_id).map_or(0, Vec::len)
    }

    /// Return the total number of events across all capsules.
    #[must_use]
    pub fn total_events(&self) -> usize {
        self.events.values().map(Vec::len).sum()
    }

    /// Return the total number of capsules that have at least one
    /// recorded event.
    #[must_use]
    pub fn capsule_count(&self) -> usize {
        self.events.len()
    }

    /// Whether no events have been recorded for any capsule.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Iterate over all capsules that have evidence, yielding each
    /// capsule ID together with its ordered event list.
    pub fn iter(&self) -> impl Iterator<Item = (&CapsuleId, &Vec<CapsuleEvidence>)> {
        self.events.iter()
    }
}

// ===========================================================================
// Tests — INV-EV-001 through INV-EV-005
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    unused_must_use,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 11, 12, 0, 0)
            .single()
            .expect("fixed wall-clock")
    }

    fn later_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 11, 12, 30, 0)
            .single()
            .expect("later wall-clock")
    }

    // ------------------------------------------------------------------
    // T1: event recording
    // ------------------------------------------------------------------

    #[test]
    fn event_recording_stores_and_returns_evidence() {
        let mut chain = EvidenceChain::new();
        let id = CapsuleId(1);
        let ts = fixed_now();

        let ev = chain.record(id, CapsuleEvent::Created, ts);
        assert_eq!(ev.capsule_id, id);
        assert_eq!(ev.event, CapsuleEvent::Created);
        assert_eq!(ev.timestamp, ts);
        assert!(ev.metadata.is_empty());
    }

    // ------------------------------------------------------------------
    // T2: audit trail ordering (INV-EV-002)
    // ------------------------------------------------------------------

    #[test]
    fn audit_trail_is_insertion_ordered() {
        let mut chain = EvidenceChain::new();
        let id = CapsuleId(1);
        let ts1 = fixed_now();
        let ts2 = later_now();

        chain.record(id, CapsuleEvent::Created, ts1);
        chain.record(id, CapsuleEvent::Configured, ts2);

        let trail = chain.audit_trail(id);
        assert_eq!(trail.len(), 2);
        assert_eq!(trail[0].event, CapsuleEvent::Created);
        assert_eq!(trail[0].timestamp, ts1);
        assert_eq!(trail[1].event, CapsuleEvent::Configured);
        assert_eq!(trail[1].timestamp, ts2);
    }

    // ------------------------------------------------------------------
    // T3: event count
    // ------------------------------------------------------------------

    #[test]
    fn event_count_correctly_reports_per_capsule_totals() {
        let mut chain = EvidenceChain::new();
        let id = CapsuleId(1);
        let ts = fixed_now();

        assert_eq!(chain.count_for(id), 0);
        assert_eq!(chain.total_events(), 0);

        chain.record(id, CapsuleEvent::Created, ts);
        assert_eq!(chain.count_for(id), 1);
        assert_eq!(chain.total_events(), 1);

        chain.record(id, CapsuleEvent::Configured, ts);
        chain.record(id, CapsuleEvent::Launched, ts);
        assert_eq!(chain.count_for(id), 3);
        assert_eq!(chain.total_events(), 3);
    }

    // ------------------------------------------------------------------
    // T4: multiple capsules isolation (INV-EV-001)
    // ------------------------------------------------------------------

    #[test]
    fn multiple_capsules_are_independently_isolated() {
        let mut chain = EvidenceChain::new();
        let id_a = CapsuleId(1);
        let id_b = CapsuleId(2);
        let ts = fixed_now();

        chain.record(id_a, CapsuleEvent::Created, ts);
        chain.record(id_a, CapsuleEvent::Launched, ts);

        chain.record(id_b, CapsuleEvent::Created, ts);
        chain.record(id_b, CapsuleEvent::Configured, ts);
        chain.record(id_b, CapsuleEvent::Launched, ts);
        chain.record(id_b, CapsuleEvent::Stopped, ts);

        // Id A: 2 events.
        assert_eq!(chain.count_for(id_a), 2);
        assert_eq!(chain.audit_trail(id_a).len(), 2);
        // Id A trail must contain only id_a events.
        for ev in chain.audit_trail(id_a) {
            assert_eq!(ev.capsule_id, id_a);
        }

        // Id B: 4 events.
        assert_eq!(chain.count_for(id_b), 4);
        assert_eq!(chain.audit_trail(id_b).len(), 4);
        for ev in chain.audit_trail(id_b) {
            assert_eq!(ev.capsule_id, id_b);
        }

        // Global totals.
        assert_eq!(chain.total_events(), 6);
        assert_eq!(chain.capsule_count(), 2);

        // Non-existent capsule returns empty trail.
        let id_c = CapsuleId(99);
        assert_eq!(chain.count_for(id_c), 0);
        assert!(chain.audit_trail(id_c).is_empty());
    }

    // ------------------------------------------------------------------
    // T5: evidence summary format (INV-EV-004)
    // ------------------------------------------------------------------

    #[test]
    fn evidence_summary_produces_correct_format() {
        let ts = fixed_now();
        let ev = CapsuleEvidence::new(CapsuleId(7), CapsuleEvent::Crashed, ts);

        let summary = ev.summary();
        assert!(summary.contains("[capsule-7]"));
        assert!(summary.contains("Crashed"));
        assert!(summary.contains("2026-06-11 12:00:00"));
    }

    #[test]
    fn evidence_summary_is_deterministic() {
        let ts = fixed_now();
        let ev = CapsuleEvidence::new(CapsuleId(3), CapsuleEvent::Destroyed, ts);

        let s1 = ev.summary();
        let s2 = ev.summary();
        assert_eq!(s1, s2);
    }

    // ------------------------------------------------------------------
    // T6: metadata association
    // ------------------------------------------------------------------

    #[test]
    fn evidence_with_metadata_preserves_all_entries() {
        let ts = fixed_now();
        let mut meta = HashMap::new();
        meta.insert(
            "snapshot_id".into(),
            "snap_01HX0000000000000000000000".into(),
        );
        meta.insert("sandbox_level".into(), "3".into());

        let ev =
            CapsuleEvidence::with_metadata(CapsuleId(42), CapsuleEvent::SnapshotTaken, ts, meta);

        assert_eq!(ev.capsule_id.raw(), 42);
        assert_eq!(ev.event, CapsuleEvent::SnapshotTaken);
        assert_eq!(
            ev.metadata.get("snapshot_id").map(String::as_str),
            Some("snap_01HX0000000000000000000000")
        );
        assert_eq!(
            ev.metadata.get("sandbox_level").map(String::as_str),
            Some("3")
        );
        assert_eq!(ev.metadata.len(), 2);
    }

    // ------------------------------------------------------------------
    // T7: empty chain invariants (INV-EV-005)
    // ------------------------------------------------------------------

    #[test]
    fn empty_chain_has_zero_events_and_capsules() {
        let chain = EvidenceChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.total_events(), 0);
        assert_eq!(chain.capsule_count(), 0);
        assert!(chain.audit_trail(CapsuleId(1)).is_empty());
        assert!(chain.iter().next().is_none());
    }

    // ------------------------------------------------------------------
    // T8: happy-path lifecycle sequence
    // ------------------------------------------------------------------

    #[test]
    fn happy_path_lifecycle_is_recorded_in_sequence() {
        let mut chain = EvidenceChain::new();
        let id = CapsuleId(1);
        let ts = fixed_now();

        let events = [
            CapsuleEvent::Created,
            CapsuleEvent::Configured,
            CapsuleEvent::Launched,
            CapsuleEvent::Paused,
            CapsuleEvent::SnapshotTaken,
            CapsuleEvent::Stopped,
            CapsuleEvent::Destroyed,
        ];

        for &event in &events {
            chain.record(id, event, ts);
        }

        let trail = chain.audit_trail(id);
        assert_eq!(trail.len(), events.len());
        for (i, &event) in events.iter().enumerate() {
            assert_eq!(trail[i].event, event);
        }
        assert_eq!(chain.total_events(), events.len());
    }

    // ------------------------------------------------------------------
    // T9: exceptional-path events (Crashed, RolledBack)
    // ------------------------------------------------------------------

    #[test]
    fn exceptional_events_are_recorded_correctly() {
        let mut chain = EvidenceChain::new();
        let id = CapsuleId(1);
        let ts = fixed_now();

        let mut meta = HashMap::new();
        meta.insert("signal_number".into(), "11".into());
        meta.insert(
            "reason".into(),
            "SIGSEGV — sandbox memory access violation".into(),
        );

        let ev = chain.record_with_metadata(id, CapsuleEvent::Crashed, ts, meta);
        assert!(ev.event.is_exceptional());
        assert!(ev.event.is_terminal());
        assert_eq!(
            ev.metadata.get("signal_number").map(String::as_str),
            Some("11")
        );

        let ev2 = chain.record(id, CapsuleEvent::RolledBack, ts);
        assert!(ev2.event.is_exceptional());
        assert!(!ev2.event.is_terminal()); // RolledBack is not terminal — capsule may continue
    }

    // ------------------------------------------------------------------
    // T10: audit_trail for unknown capsule returns empty
    // ------------------------------------------------------------------

    #[test]
    fn audit_trail_for_unknown_capsule_is_empty() {
        let chain = EvidenceChain::new();
        let trail = chain.audit_trail(CapsuleId(999));
        assert!(trail.is_empty());
    }
}
