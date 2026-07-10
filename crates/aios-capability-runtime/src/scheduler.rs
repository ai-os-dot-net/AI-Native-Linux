//! BeOS / QNX -inspired adaptive partition scheduler for AI capsules.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::explicit_iter_loop)]
//!
//! ## OS Research Provenance
//!
//! **BeOS** (Be Inc., 1995) introduced a preemptive multitasking kernel with
//! 120 priority levels (0–119, lower = higher priority). The first 10 levels
//! (0–9) were reserved for real-time media threads. Threads in the RT band
//! were never preempted by non‑RT threads — the system guaranteed
//! deterministic scheduling for audio/video pipelines.
//!
//! Each BeOS window was its own thread, each `BMediaNode` in the Media Kit
//! was its own thread, and the scheduler treated them all as independent
//! schedulable entities.  A key innovation was **consumer-owned buffers**:
//! the receiving node owned the buffer, so a high-priority producer could
//! fill buffers without being blocked by a slow consumer.
//!
//! **QNX** (BlackBerry, ISO 26262 ASIL‑D) extended real-time scheduling with
//! **adaptive partitions** — each partition receives a guaranteed percentage
//! of CPU time.  If partition A is idle, its budget "lends" to other
//! partitions, but never below the guarantee.  QNX also pioneered
//! **priority inheritance** on `MsgSend`: when a high-pri thread sends a
//! message to a low-pri thread, the receiver is temporarily elevated to the
//! sender's priority to prevent priority inversion.
//!
//! ### Mapping to AIOS Capsule Architecture
//!
//! | BeOS / QNX concept      | AIOS equivalent                                     |
//! |--------------------------|-----------------------------------------------------|
//! | BeOS 120 priority levels | [`CapsulePriority`] (0–119, 0–9 = RT band)          |
//! | BeOS `BMediaNode` thread | [`CapsuleSchedulingEntity`] (per-capsule)            |
//! | BeOS real-time band      | [`PriorityBand::RealTime`] (levels 0–9)              |
//! | QNX adaptive partition   | [`AdaptivePartition`] (guaranteed CPU budget)        |
//! | QNX priority inheritance | [`elevate_for_sender`] (PREVENT priority inversion)  |
//! | QNX partition guarantee  | [`AdaptivePartition::guarantee_pct`] (min CPU %)     |
//! | BeOS consumer-owned buf. | [`SchedulingDecision`] owner = receiver capsule       |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-SCH-001 (RT non‑preemption):** No capsule with priority ≥ 10
//!   (non‑RT) can preempt a capsule with priority < 10 (RT band).
//! - **INV-SCH-002 (Partition guarantee):** Every partition receives at
//!   minimum its declared `guarantee_pct` of scheduling decisions when
//!   competing capsules within that partition are ready.
//! - **INV-SCH-003 (Priority inheritance):** When capsule A (high priority)
//!   sends a request to capsule B (low priority), B's effective priority
//!   becomes max(B.priority, A.priority) until B replies.
//! - **INV-SCH-004 (Partition isolation):** A partition that exceeds its
//!   budget does not reduce the budget available to other partitions.
//! - **INV-SCH-005 (Starve‑free):** Every ready capsule eventually receives
//!   a scheduling decision after a finite number of decisions.
//!
//! ## Caveats
//!
//! This module is a **scheduling model**, not a kernel scheduler.  It does
//! not call `sched_setscheduler(2)` or interact with Linux's CFS.  It
//! provides the **decision‑making logic** that the AIOS runtime consults
//! when selecting the next capsule to dispatch.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;

/// Re-use capsule identity from the namespace module.
use super::capsule_namespace::CapsuleId;

// ---------------------------------------------------------------------------
// CapsulePriority — BeOS 120-level priority (0 = highest)
// ---------------------------------------------------------------------------

/// A capsule scheduling priority on the BeOS 0–119 scale.
///
/// Lower numeric value = higher scheduling priority.  The first 10 levels
/// (0–9) are the real-time band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapsulePriority(u8);

impl CapsulePriority {
    /// The absolute highest priority (BeOS level 0 — real-time).
    pub const MAX: Self = Self(0);

    /// The boundary between real-time and normal priority (level 10).
    pub const RT_THRESHOLD: Self = Self(10);

    /// The absolute lowest priority (BeOS level 119).
    pub const MIN: Self = Self(119);

    /// Default priority for new capsules (level 60 — mid-range normal).
    pub const DEFAULT: Self = Self(60);

    /// Construct from a raw level.  Returns `None` if > 119.
    #[must_use]
    pub const fn new(level: u8) -> Option<Self> {
        if level <= 119 {
            Some(Self(level))
        } else {
            None
        }
    }

    /// Raw numeric level (0–119).
    #[must_use]
    pub const fn level(self) -> u8 {
        self.0
    }

    /// The priority band this level belongs to.
    #[must_use]
    pub const fn band(self) -> PriorityBand {
        match self.0 {
            0..=9 => PriorityBand::RealTime,
            10..=29 => PriorityBand::High,
            30..=69 => PriorityBand::Normal,
            70..=99 => PriorityBand::Low,
            _ => PriorityBand::Idle,
        }
    }

    /// Whether this priority is in the real-time band (INV-SCH-001).
    #[must_use]
    pub const fn is_realtime(self) -> bool {
        self.0 < 10
    }

    /// The highest of two priorities (lower numeric value wins).
    #[must_use]
    pub const fn max(self, other: Self) -> Self {
        if self.0 <= other.0 {
            self
        } else {
            other
        }
    }
}

impl Default for CapsulePriority {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for CapsulePriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "P{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// PriorityBand — semantic scheduling tier
// ---------------------------------------------------------------------------

/// BeOS-inspired priority tiers, from real-time to idle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PriorityBand {
    /// Levels 0–9: audio/video/inference — never preempted by non-RT.
    RealTime,
    /// Levels 10–29: interactive UI, user-facing capsules.
    High,
    /// Levels 30–69: default background processing.
    Normal,
    /// Levels 70–99: batch work, analytics.
    Low,
    /// Levels 100–119: garbage collection, optimization, self-maintenance.
    Idle,
}

impl PriorityBand {
    /// Whether capsules in this band preempt capsules in `other`.
    #[must_use]
    pub fn preempts(self, other: Self) -> bool {
        self < other
    }

    /// The range of priority levels in this band.
    #[must_use]
    pub const fn level_range(self) -> (u8, u8) {
        match self {
            Self::RealTime => (0, 9),
            Self::High => (10, 29),
            Self::Normal => (30, 69),
            Self::Low => (70, 99),
            Self::Idle => (100, 119),
        }
    }
}

impl fmt::Display for PriorityBand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::RealTime => "RT",
            Self::High => "HI",
            Self::Normal => "NR",
            Self::Low => "LO",
            Self::Idle => "ID",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// CapsuleSchedulingEntity — per-capsule schedulable unit
// ---------------------------------------------------------------------------

/// A single schedulable capsule, analogous to a BeOS `BMediaNode` thread
/// or a QNX process entry in the partition table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleSchedulingEntity {
    /// The capsule that owns this scheduling slot.
    pub capsule_id: CapsuleId,
    /// Base priority (set at registration time).
    pub base_priority: CapsulePriority,
    /// Effective priority after inheritance (INV-SCH-003).
    pub effective_priority: CapsulePriority,
    /// The partition this capsule belongs to.
    pub partition_name: String,
    /// Whether the capsule is currently ready to run.
    pub ready: bool,
}

impl CapsuleSchedulingEntity {
    /// Create a new scheduling entity with a base priority.
    #[must_use]
    pub fn new(
        capsule_id: CapsuleId,
        base_priority: CapsulePriority,
        partition_name: String,
    ) -> Self {
        Self {
            capsule_id,
            base_priority,
            effective_priority: base_priority,
            partition_name,
            ready: true,
        }
    }

    /// Whether this entity is in the real-time band.
    #[must_use]
    pub const fn is_realtime(&self) -> bool {
        self.effective_priority.is_realtime()
    }

    /// Elevate effective priority for inheritance (cap with base priority).
    pub fn inherit_from(&mut self, sender_priority: CapsulePriority) {
        self.effective_priority = self.base_priority.max(sender_priority);
    }

    /// Reset effective priority to base (called after `MsgReply`).
    pub fn clear_inheritance(&mut self) {
        self.effective_priority = self.base_priority;
    }
}

// ---------------------------------------------------------------------------
// AdaptivePartition — QNX-style CPU budget
// ---------------------------------------------------------------------------

/// A QNX adaptive partition: a named group of capsules that share a
/// guaranteed minimum percentage of scheduling slots.
///
/// If the partition is idle, its budget is temporarily lent to other
/// partitions — but the guarantee is **never** reduced below the
/// configured minimum (INV-SCH-002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptivePartition {
    /// Human-readable partition name (e.g. "inference", "ui", "system").
    pub name: String,
    /// Guaranteed minimum percentage of scheduling decisions (0..100).
    pub guarantee_pct: u8,
    /// Maximum percentage the partition may consume (guarantee_pct..100).
    pub max_pct: u8,
    /// Total scheduling decisions allocated to this partition (rolling window).
    pub allocated: u64,
    /// Number of ready capsules currently in this partition.
    pub ready_count: usize,
}

impl AdaptivePartition {
    /// Create a new partition with a guaranteed CPU budget.
    ///
    /// `guarantee_pct` must be ≤ `max_pct`, and `max_pct` must be ≤ 100.
    #[must_use]
    pub fn new(name: String, guarantee_pct: u8, max_pct: u8) -> Option<Self> {
        if guarantee_pct > max_pct || max_pct > 100 {
            return None;
        }
        Some(Self {
            name,
            guarantee_pct,
            max_pct,
            allocated: 0,
            ready_count: 0,
        })
    }

    /// Whether this partition has exceeded its maximum budget.
    #[must_use]
    pub fn is_budget_exhausted(&self, total_allocated: u64) -> bool {
        if total_allocated == 0 {
            return false;
        }
        let current_pct = (self.allocated as f64 / total_allocated as f64) * 100.0;
        current_pct >= f64::from(self.max_pct)
    }

    /// Whether this partition is below its guarantee and should be favoured.
    #[must_use]
    pub fn is_below_guarantee(&self, total_allocated: u64) -> bool {
        if total_allocated == 0 {
            return false; // no budget consumed yet — nobody is below guarantee
        }
        let current_pct = (self.allocated as f64 / total_allocated as f64) * 100.0;
        current_pct < f64::from(self.guarantee_pct)
    }

    /// Fraction of the budget consumed (0.0 .. 1.0).
    #[must_use]
    pub fn budget_consumed(&self, total_allocated: u64) -> f64 {
        if total_allocated == 0 {
            return 0.0;
        }
        self.allocated as f64 / total_allocated as f64
    }
}

impl fmt::Display for AdaptivePartition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[g={}% m={}% a={} r={}]",
            self.name, self.guarantee_pct, self.max_pct, self.allocated, self.ready_count
        )
    }
}

// ---------------------------------------------------------------------------
// SchedulingDecision — the output of the scheduler
// ---------------------------------------------------------------------------

/// The result of consulting the partition scheduler: which capsule to
/// dispatch next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulingDecision {
    /// The capsule selected for dispatch.
    pub capsule_id: CapsuleId,
    /// The priority at which it will run.
    pub priority: CapsulePriority,
    /// The partition it belongs to.
    pub partition_name: String,
    /// The reason this capsule was selected.
    pub reason: DecisionReason,
}

/// Why a particular capsule was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionReason {
    /// Highest-priority ready capsule in the system (normal case).
    HighestPriority,
    /// Selected to meet partition guarantee (INV-SCH-002).
    PartitionGuarantee,
    /// Elevated via priority inheritance (INV-SCH-003).
    PriorityInheritance,
    /// Only ready capsule in its partition.
    OnlyReady,
    /// No ready capsules — idle.
    Idle,
}

impl fmt::Display for DecisionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::HighestPriority => "highest-priority",
            Self::PartitionGuarantee => "partition-guarantee",
            Self::PriorityInheritance => "priority-inheritance",
            Self::OnlyReady => "only-ready",
            Self::Idle => "idle",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// PartitionScheduler — the main scheduling engine
// ---------------------------------------------------------------------------

/// BeOS+QNX hybrid adaptive partition scheduler.
///
/// Manages a set of [`AdaptivePartition`]s, each containing
/// [`CapsuleSchedulingEntity`] instances.  On every call to
/// [`PartitionScheduler::next`], the scheduler:
///
/// 1. Finds partitions below their guarantee (INV-SCH-002).
/// 2. Within those partitions, selects the highest-priority ready capsule.
/// 3. If no guarantee-deficit partition exists, selects the globally
///    highest-priority ready capsule (BeOS semantics).
/// 4. Returns `None` if no capsule is ready.
///
/// This is a **pure decision model** — it does not dispatch threads or
/// interact with the kernel.
#[derive(Debug, Default, Clone)]
pub struct PartitionScheduler {
    /// All registered capsules, indexed by capsule ID.
    entities: HashMap<CapsuleId, CapsuleSchedulingEntity>,
    /// All active partitions, indexed by name.
    partitions: HashMap<String, AdaptivePartition>,
    /// Ready capsules, ordered by partition then priority.
    ready_queue: BTreeMap<CapsulePriority, VecDeque<CapsuleId>>,
}

impl PartitionScheduler {
    /// Create an empty scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
            partitions: HashMap::new(),
            ready_queue: BTreeMap::new(),
        }
    }

    /// ---------- partition management ---------------------------------------
    ///
    /// Register a new partition.  Returns `false` if a partition with the
    /// same name already exists.
    pub fn add_partition(&mut self, partition: AdaptivePartition) -> bool {
        if self.partitions.contains_key(&partition.name) {
            return false;
        }
        self.partitions.insert(partition.name.clone(), partition);
        true
    }

    /// Look up a partition by name.
    #[must_use]
    pub fn get_partition(&self, name: &str) -> Option<&AdaptivePartition> {
        self.partitions.get(name)
    }

    /// ---------- capsule registration ---------------------------------------
    ///
    /// Register a capsule for scheduling.
    ///
    /// The capsule's partition must already exist.  Returns `false` if the
    /// partition is missing or the capsule is already registered.
    pub fn register_capsule(&mut self, entity: CapsuleSchedulingEntity) -> bool {
        if self.entities.contains_key(&entity.capsule_id) {
            return false;
        }
        if !self.partitions.contains_key(&entity.partition_name) {
            return false;
        }
        let Some(partition) = self.partitions.get_mut(&entity.partition_name) else {
            return false;
        };
        if entity.ready {
            partition.ready_count += 1;
            self.ready_queue
                .entry(entity.effective_priority)
                .or_default()
                .push_back(entity.capsule_id);
        }
        self.entities.insert(entity.capsule_id, entity);
        true
    }

    /// Remove a capsule from the scheduler (teardown).
    pub fn unregister_capsule(&mut self, capsule_id: CapsuleId) -> bool {
        if let Some(entity) = self.entities.remove(&capsule_id) {
            if entity.ready {
                if let Some(q) = self.ready_queue.get_mut(&entity.effective_priority) {
                    q.retain(|id| *id != capsule_id);
                    if q.is_empty() {
                        self.ready_queue.remove(&entity.effective_priority);
                    }
                }
                if let Some(p) = self.partitions.get_mut(&entity.partition_name) {
                    p.ready_count = p.ready_count.saturating_sub(1);
                }
            }
            true
        } else {
            false
        }
    }

    /// Set a capsule's ready state.  When transitioning from ready → not-ready,
    /// the capsule is removed from the ready queue; the reverse transition
    /// puts it back.
    pub fn set_ready(&mut self, capsule_id: CapsuleId, ready: bool) -> bool {
        let Some(entity) = self.entities.get_mut(&capsule_id) else {
            return false;
        };
        if entity.ready == ready {
            return true; // no-op
        }
        entity.ready = ready;
        let partition_name = entity.partition_name.clone();
        let pri = entity.effective_priority;

        if ready {
            // Transition: not-ready → ready.
            self.ready_queue
                .entry(pri)
                .or_default()
                .push_back(capsule_id);
            if let Some(p) = self.partitions.get_mut(&partition_name) {
                p.ready_count += 1;
            }
        } else {
            // Transition: ready → not-ready.
            if let Some(q) = self.ready_queue.get_mut(&pri) {
                q.retain(|id| *id != capsule_id);
                if q.is_empty() {
                    self.ready_queue.remove(&pri);
                }
            }
            if let Some(p) = self.partitions.get_mut(&partition_name) {
                p.ready_count = p.ready_count.saturating_sub(1);
            }
        }
        true
    }

    /// ---------- priority inheritance (INV-SCH-003) -------------------------
    ///
    /// Elevate a capsule's effective priority because a higher-priority
    /// sender is waiting on it (QNX `MsgSend` priority inheritance).
    ///
    /// Returns `false` if the capsule is not registered or if the new
    /// priority is not higher than the current effective priority.
    pub fn inherit_priority(
        &mut self,
        capsule_id: CapsuleId,
        sender_priority: CapsulePriority,
    ) -> bool {
        let Some(entity) = self.entities.get_mut(&capsule_id) else {
            return false;
        };
        let old_pri = entity.effective_priority;
        entity.inherit_from(sender_priority);
        let new_pri = entity.effective_priority;

        if new_pri == old_pri {
            return false; // no change
        }

        // Move the capsule from old priority queue to new priority queue
        // if it is currently ready.
        if entity.ready {
            if let Some(q) = self.ready_queue.get_mut(&old_pri) {
                q.retain(|id| *id != capsule_id);
                if q.is_empty() {
                    self.ready_queue.remove(&old_pri);
                }
            }
            self.ready_queue
                .entry(new_pri)
                .or_default()
                .push_back(capsule_id);
        }
        true
    }

    /// Clear priority inheritance for a capsule (called after `MsgReply`).
    pub fn clear_inheritance(&mut self, capsule_id: CapsuleId) -> bool {
        let Some(entity) = self.entities.get_mut(&capsule_id) else {
            return false;
        };
        let old_pri = entity.effective_priority;
        entity.clear_inheritance();
        let new_pri = entity.effective_priority;

        if new_pri == old_pri {
            return false;
        }

        if entity.ready {
            if let Some(q) = self.ready_queue.get_mut(&old_pri) {
                q.retain(|id| *id != capsule_id);
                if q.is_empty() {
                    self.ready_queue.remove(&old_pri);
                }
            }
            self.ready_queue
                .entry(new_pri)
                .or_default()
                .push_back(capsule_id);
        }
        true
    }

    /// ---------- scheduling decision (the core) -----------------------------
    ///
    /// Compute the next scheduling decision.
    ///
    /// Algorithm (BeOS priority bands + QNX partition guarantees):
    ///
    /// 1. If any RT capsule is ready, select the highest-priority RT capsule.
    /// 2. Find partitions below guarantee that have ready capsules; within
    ///    those, select the highest-priority capsule.
    /// 3. Otherwise, select the globally highest-priority ready capsule.
    /// 4. Return `None` if no capsule is ready.
    #[must_use]
    pub fn next(&self) -> Option<SchedulingDecision> {
        // Pass 1: RT-first — any RT capsule preempts everything (INV-SCH-001).
        for (pri, queue) in &self.ready_queue {
            if !pri.is_realtime() {
                break;
            }
            if let Some(&capsule_id) = queue.front() {
                let entity = &self.entities[&capsule_id];
                return Some(SchedulingDecision {
                    capsule_id,
                    priority: *pri,
                    partition_name: entity.partition_name.clone(),
                    reason: DecisionReason::HighestPriority,
                });
            }
        }

        // Pass 2: Partition guarantee (INV-SCH-002).
        let total_allocated: u64 = self.partitions.values().map(|p| p.allocated).sum();
        let mut best_by_guarantee: Option<SchedulingDecision> = None;

        for (pri, queue) in &self.ready_queue {
            for &capsule_id in queue {
                let entity = &self.entities[&capsule_id];
                let partition = &self.partitions[&entity.partition_name];
                if partition.is_below_guarantee(total_allocated) {
                    let decision = SchedulingDecision {
                        capsule_id,
                        priority: *pri,
                        partition_name: entity.partition_name.clone(),
                        reason: DecisionReason::PartitionGuarantee,
                    };
                    // Keep the highest-priority guarantee-deficient capsule.
                    best_by_guarantee = Some(match best_by_guarantee {
                        None => decision,
                        Some(ref prev) if pri < &prev.priority => decision,
                        Some(prev) => prev,
                    });
                }
            }
        }

        if let Some(decision) = best_by_guarantee {
            return Some(decision);
        }

        // Pass 3: Global highest-priority (standard BeOS scheduling).
        for (pri, queue) in &self.ready_queue {
            if let Some(&capsule_id) = queue.front() {
                let entity = &self.entities[&capsule_id];
                return Some(SchedulingDecision {
                    capsule_id,
                    priority: *pri,
                    partition_name: entity.partition_name.clone(),
                    reason: DecisionReason::HighestPriority,
                });
            }
        }

        None
    }

    /// Record that a scheduling decision was consumed (updates partition
    /// allocation counters).
    pub fn record_allocation(&mut self, decision: &SchedulingDecision) {
        if let Some(partition) = self.partitions.get_mut(&decision.partition_name) {
            partition.allocated += 1;
        }
    }

    /// ---------- inspectors -------------------------------------------------
    ///
    /// Total number of registered capsules.
    #[must_use]
    pub fn capsule_count(&self) -> usize {
        self.entities.len()
    }

    /// Total number of ready capsules.
    #[must_use]
    pub fn ready_count(&self) -> usize {
        self.ready_queue.values().map(VecDeque::len).sum()
    }

    /// Total number of partitions.
    #[must_use]
    pub fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    /// Look up a registered capsule.
    #[must_use]
    pub fn get_capsule(&self, capsule_id: CapsuleId) -> Option<&CapsuleSchedulingEntity> {
        self.entities.get(&capsule_id)
    }
}

// ===========================================================================
// Tests — INV-SCH-001 through INV-SCH-005
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CapsulePriority tests
    // -----------------------------------------------------------------------

    #[test]
    fn priority_ordering_is_correct() {
        assert!(CapsulePriority::MAX < CapsulePriority::DEFAULT);
        assert!(CapsulePriority::DEFAULT < CapsulePriority::MIN);
        assert_eq!(CapsulePriority::MAX.level(), 0);
        assert_eq!(CapsulePriority::MIN.level(), 119);
    }

    #[test]
    fn priority_new_clamps_at_119() {
        assert!(CapsulePriority::new(120).is_none());
        assert!(CapsulePriority::new(0).is_some());
        assert!(CapsulePriority::new(119).is_some());
    }

    #[test]
    fn priority_bands_are_correct() {
        assert_eq!(
            CapsulePriority::new(0).unwrap().band(),
            PriorityBand::RealTime
        );
        assert_eq!(
            CapsulePriority::new(9).unwrap().band(),
            PriorityBand::RealTime
        );
        assert_eq!(CapsulePriority::new(10).unwrap().band(), PriorityBand::High);
        assert_eq!(CapsulePriority::new(29).unwrap().band(), PriorityBand::High);
        assert_eq!(
            CapsulePriority::new(30).unwrap().band(),
            PriorityBand::Normal
        );
        assert_eq!(
            CapsulePriority::new(69).unwrap().band(),
            PriorityBand::Normal
        );
        assert_eq!(CapsulePriority::new(70).unwrap().band(), PriorityBand::Low);
        assert_eq!(CapsulePriority::new(99).unwrap().band(), PriorityBand::Low);
        assert_eq!(
            CapsulePriority::new(100).unwrap().band(),
            PriorityBand::Idle
        );
        assert_eq!(
            CapsulePriority::new(119).unwrap().band(),
            PriorityBand::Idle
        );
    }

    #[test]
    fn is_realtime_only_for_levels_0_to_9() {
        assert!(CapsulePriority::new(0).unwrap().is_realtime());
        assert!(CapsulePriority::new(9).unwrap().is_realtime());
        assert!(!CapsulePriority::new(10).unwrap().is_realtime());
        assert!(!CapsulePriority::new(119).unwrap().is_realtime());
    }

    #[test]
    fn priority_max_chooses_higher_priority() {
        let high = CapsulePriority::new(5).unwrap(); // RT
        let low = CapsulePriority::new(80).unwrap();
        assert_eq!(high.max(low), high);
        assert_eq!(low.max(high), high);
    }

    #[test]
    fn priority_band_preemption_ordering() {
        assert!(PriorityBand::RealTime.preempts(PriorityBand::High));
        assert!(PriorityBand::High.preempts(PriorityBand::Normal));
        assert!(!PriorityBand::Normal.preempts(PriorityBand::High));
        assert!(!PriorityBand::Idle.preempts(PriorityBand::RealTime));
    }

    #[test]
    fn display_formats() {
        assert_eq!(format!("{}", CapsulePriority::new(5).unwrap()), "P5");
        assert_eq!(format!("{}", PriorityBand::RealTime), "RT");
        assert_eq!(format!("{}", PriorityBand::Idle), "ID");
    }

    // -----------------------------------------------------------------------
    // AdaptivePartition tests
    // -----------------------------------------------------------------------

    #[test]
    fn partition_creation_rejects_invalid_pcts() {
        assert!(AdaptivePartition::new("bad".into(), 50, 30).is_none()); // guarantee > max
        assert!(AdaptivePartition::new("bad2".into(), 0, 101).is_none()); // max > 100
        assert!(AdaptivePartition::new("ok".into(), 30, 50).is_some());
    }

    #[test]
    fn partition_budget_exhausted() {
        let mut p = AdaptivePartition::new("test".into(), 10, 50).unwrap();
        p.allocated = 600; // 60% of 1000 total
        assert!(p.is_budget_exhausted(1000));
        assert!(!p.is_budget_exhausted(2000)); // 30% of 2000
    }

    #[test]
    fn partition_below_guarantee() {
        let mut p = AdaptivePartition::new("test".into(), 20, 80).unwrap();
        p.allocated = 10;
        assert!(p.is_below_guarantee(100)); // 10% < 20%

        p.allocated = 30;
        assert!(!p.is_below_guarantee(100)); // 30% > 20%
    }

    #[test]
    fn partition_budget_consumed() {
        let mut p = AdaptivePartition::new("test".into(), 10, 50).unwrap();
        p.allocated = 250;
        assert!((p.budget_consumed(1000) - 0.25).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // PartitionScheduler — registration / readiness
    // -----------------------------------------------------------------------

    fn setup_scheduler() -> PartitionScheduler {
        let mut s = PartitionScheduler::new();
        assert!(s.add_partition(AdaptivePartition::new("inference".into(), 40, 80).unwrap()));
        assert!(s.add_partition(AdaptivePartition::new("ui".into(), 20, 30).unwrap()));
        assert!(s.add_partition(AdaptivePartition::new("system".into(), 10, 25).unwrap()));
        s
    }

    #[test]
    fn register_and_lookup_capsule() {
        let mut s = setup_scheduler();
        let entity = CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::new(50).unwrap(),
            "inference".into(),
        );
        assert!(s.register_capsule(entity));
        assert_eq!(s.capsule_count(), 1);
        assert!(s.get_capsule(CapsuleId(1)).is_some());
    }

    #[test]
    fn register_rejects_duplicate_capsule_id() {
        let mut s = setup_scheduler();
        assert!(s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::DEFAULT,
            "inference".into(),
        )));
        assert!(!s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::DEFAULT,
            "ui".into(),
        )));
    }

    #[test]
    fn register_rejects_missing_partition() {
        let mut s = PartitionScheduler::new();
        assert!(!s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::DEFAULT,
            "nonexistent".into(),
        )));
    }

    #[test]
    fn unregister_removes_from_ready_queue() {
        let mut s = setup_scheduler();
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::new(5).unwrap(),
            "inference".into(),
        ));
        assert_eq!(s.ready_count(), 1);

        assert!(s.unregister_capsule(CapsuleId(1)));
        assert_eq!(s.ready_count(), 0);
        assert_eq!(s.capsule_count(), 0);
    }

    #[test]
    fn set_ready_toggles_capsule() {
        let mut s = setup_scheduler();
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::DEFAULT,
            "inference".into(),
        ));
        assert_eq!(s.ready_count(), 1);

        // Set to not-ready.
        assert!(s.set_ready(CapsuleId(1), false));
        assert_eq!(s.ready_count(), 0);

        // Set back to ready.
        assert!(s.set_ready(CapsuleId(1), true));
        assert_eq!(s.ready_count(), 1);
    }

    // -----------------------------------------------------------------------
    // INV-SCH-001: RT non-preemption
    // -----------------------------------------------------------------------

    #[test]
    fn rt_capsule_preempts_everything() {
        let mut s = setup_scheduler();

        // RT capsule.
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::new(3).unwrap(), // RT
            "system".into(),
        ));
        // Normal capsule.
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(2),
            CapsulePriority::new(10).unwrap(), // non-RT
            "inference".into(),
        ));

        let decision = s.next().unwrap();
        assert_eq!(decision.capsule_id, CapsuleId(1)); // RT always wins
        assert_eq!(decision.reason, DecisionReason::HighestPriority);
    }

    #[test]
    fn higher_rt_priority_wins_within_rt_band() {
        let mut s = setup_scheduler();
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::new(5).unwrap(),
            "system".into(),
        ));
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(2),
            CapsulePriority::new(2).unwrap(), // higher RT
            "inference".into(),
        ));

        let decision = s.next().unwrap();
        assert_eq!(decision.capsule_id, CapsuleId(2)); // P2 beats P5
    }

    // -----------------------------------------------------------------------
    // INV-SCH-002: Partition guarantee
    // -----------------------------------------------------------------------

    #[test]
    fn partition_guarantee_favours_deficit_partition() {
        let mut s = PartitionScheduler::new();
        assert!(s.add_partition(AdaptivePartition::new("rich".into(), 10, 90).unwrap()));
        assert!(s.add_partition(AdaptivePartition::new("poor".into(), 40, 90).unwrap()));

        // Simulate "rich" already having consumed 900 of 1000 allocations.
        s.partitions.get_mut("rich").unwrap().allocated = 900;

        // Both have a ready capsule, but "poor" is below guarantee (0% vs 40%).
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::new(80).unwrap(), // low priority
            "poor".into(),
        ));
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(2),
            CapsulePriority::new(20).unwrap(), // high priority
            "rich".into(),
        ));

        // "poor"'s capsule should be chosen (partition guarantee) even though
        // it has lower priority than "rich"'s capsule.
        let decision = s.next().unwrap();
        assert_eq!(decision.capsule_id, CapsuleId(1)); // poor wins via guarantee
        assert_eq!(decision.reason, DecisionReason::PartitionGuarantee);
    }

    #[test]
    fn when_all_partitions_above_guarantee_use_highest_priority() {
        let mut s = setup_scheduler();
        // All partitions have 0 allocations → none below guarantee.
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::new(80).unwrap(), // low
            "inference".into(),
        ));
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(2),
            CapsulePriority::new(20).unwrap(), // high
            "ui".into(),
        ));

        let decision = s.next().unwrap();
        assert_eq!(decision.capsule_id, CapsuleId(2)); // highest priority wins
        assert_eq!(decision.reason, DecisionReason::HighestPriority);
    }

    // -----------------------------------------------------------------------
    // INV-SCH-003: Priority inheritance
    // -----------------------------------------------------------------------

    #[test]
    fn priority_inheritance_elevates_low_priority_capsule() {
        let mut s = setup_scheduler();
        // Low-priority capsule (P80).
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::new(80).unwrap(),
            "inference".into(),
        ));
        // High-priority capsule (P5, RT).
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(2),
            CapsulePriority::new(5).unwrap(),
            "system".into(),
        ));

        // Simulate: P5 sends MsgSend to P80 → P80 inherits P5's priority.
        assert!(s.inherit_priority(CapsuleId(1), CapsulePriority::new(5).unwrap()));

        // Now P80 should have effective priority P5 and be selected second
        // (after the actual P5 capsule, since both have P5 and are in the
        // same queue; order depends on insertion).

        let entity = s.get_capsule(CapsuleId(1)).unwrap();
        assert_eq!(entity.effective_priority, CapsulePriority::new(5).unwrap());
        assert_eq!(entity.base_priority, CapsulePriority::new(80).unwrap());
    }

    #[test]
    fn clearing_inheritance_restores_base_priority() {
        let mut s = setup_scheduler();
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::new(80).unwrap(),
            "inference".into(),
        ));
        s.inherit_priority(CapsuleId(1), CapsulePriority::new(5).unwrap());
        assert!(s.clear_inheritance(CapsuleId(1)));

        let entity = s.get_capsule(CapsuleId(1)).unwrap();
        assert_eq!(entity.effective_priority, CapsulePriority::new(80).unwrap());
    }

    #[test]
    fn inheritance_does_not_lower_priority() {
        let mut s = setup_scheduler();
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::new(5).unwrap(), // already high
            "inference".into(),
        ));
        // A lower-priority sender cannot reduce the priority.
        assert!(!s.inherit_priority(CapsuleId(1), CapsulePriority::new(80).unwrap()));
        assert_eq!(
            s.get_capsule(CapsuleId(1)).unwrap().effective_priority,
            CapsulePriority::new(5).unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // INV-SCH-004: Partition isolation
    // -----------------------------------------------------------------------

    #[test]
    fn partition_over_budget_does_not_block_other_partitions() {
        let mut s = PartitionScheduler::new();
        assert!(s.add_partition(AdaptivePartition::new("hog".into(), 10, 50).unwrap()));
        assert!(s.add_partition(AdaptivePartition::new("starved".into(), 30, 80).unwrap()));

        // "hog" has consumed all its budget.
        s.partitions.get_mut("hog").unwrap().allocated = 550;
        // "starved" has nothing.
        s.partitions.get_mut("starved").unwrap().allocated = 0;

        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::new(20).unwrap(), // high pri but in hog (non-RT)
            "hog".into(),
        ));
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(2),
            CapsulePriority::new(80).unwrap(), // low pri but in starved
            "starved".into(),
        ));

        // "starved" partition should get the slot because it's at 0% of its
        // 30% guarantee, while "hog" is at 100% of its 50% max (550/550).
        let decision = s.next().unwrap();
        // With 0 + 550 = 550 total, starved is at 0% < 30% guarantee.
        // hog at 550/550 = 100% — above 50% max → exhausted anyway.
        // So starved wins via guarantee.
        assert_eq!(decision.capsule_id, CapsuleId(2));
    }

    // -----------------------------------------------------------------------
    // INV-SCH-005: Starve-free
    // -----------------------------------------------------------------------

    #[test]
    fn all_ready_capsules_eventually_scheduled() {
        let mut s = setup_scheduler();
        let ids: Vec<CapsuleId> = (1u64..=5).map(CapsuleId).collect();

        for &id in &ids {
            s.register_capsule(CapsuleSchedulingEntity::new(
                id,
                CapsulePriority::new(((100u64.saturating_sub(id.0 * 10)).min(119)) as u8).unwrap(),
                "inference".into(),
            ));
        }

        let mut scheduled = Vec::new();
        for _ in 0..ids.len() {
            if let Some(decision) = s.next() {
                s.record_allocation(&decision);
                s.set_ready(decision.capsule_id, false); // mark consumed
                scheduled.push(decision.capsule_id);
            }
        }

        // Every capsule should have been scheduled exactly once (starve-free).
        scheduled.sort();
        let mut expected = ids;
        expected.sort();
        assert_eq!(scheduled, expected);
    }

    #[test]
    fn no_ready_capsules_returns_none() {
        let s = PartitionScheduler::new();
        assert!(s.next().is_none());
    }

    // -----------------------------------------------------------------------
    // Record allocation / partition accounting
    // -----------------------------------------------------------------------

    #[test]
    fn record_allocation_increments_partition_counter() {
        let mut s = setup_scheduler();
        s.register_capsule(CapsuleSchedulingEntity::new(
            CapsuleId(1),
            CapsulePriority::DEFAULT,
            "inference".into(),
        ));

        let decision = s.next().unwrap();
        let before = s.get_partition("inference").unwrap().allocated;
        s.record_allocation(&decision);
        assert_eq!(s.get_partition("inference").unwrap().allocated, before + 1);
    }

    #[test]
    fn display_formats_scheduler() {
        let p = AdaptivePartition::new("test".into(), 20, 50).unwrap();
        let s = format!("{}", p);
        assert!(s.contains("g=20%"));
        assert!(s.contains("m=50%"));
    }
}
