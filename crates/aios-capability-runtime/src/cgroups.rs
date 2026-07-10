//! Linux cgroups v2 resource quota model for AIOS capsules.
//!
//! ## OS Research Provenance
//!
//! **cgroups v2** (Linux kernel 4.5+, unified hierarchy) provides per-process
//! resource controllers — CPU, memory, I/O, PIDs, and more — via a single
//! pseudo‑filesystem at `/sys/fs/cgroup`.  Each controller exposes a `.max`
//! or `.weight` knob.  AIOS uses this to enforce per‑capsule resource quotas
//! without a hypervisor.
//!
//! | cgroups v2 file        | This model               |
//! |------------------------|--------------------------|
//! | `cpu.weight`           | [`ResourceQuota::cpu_shares`] |
//! | `memory.max`           | [`ResourceQuota::memory_limit_bytes`] |
//! | `io.weight`            | [`ResourceQuota::io_weight`] |
//! | `memory.current`       | [`ResourceUsage::memory_usage_bytes`] |
//! | `cpu.stat` usage_usec  | [`ResourceUsage::cpu_usage_usec`] |
//!
//! ## Scope
//!
//! This is a **pure model layer** — no actual cgroupfs writes.  It provides
//! the types needed for capsule resource governance: quota definition,
//! usage tracking, violation detection, and enforcement decision logic.
//!
//! ## Constitutional invariants
//!
//! - **INV-CG-001 (Quota range):** `cpu_shares` ∈ [1, 10000], `io_weight` ∈ [1, 10000],
//!   `memory_limit_bytes` > 0.
//! - **INV-CG-002 (Hard memory = Kill):** Hard enforcement on memory exhaustion
//!   always yields [`EnforcementAction::Kill`] (OOM semantics).
//! - **INV-CG-003 (Soft degradation):** Soft enforcement never kills — it always
//!   throttles or warns.
//! - **INV-CG-004 (Idempotent check):** Two consecutive calls to
//!   [`CgroupProfile::check_violation`] with identical usage return the same
//!   violation (or `None`).

use std::fmt;

use super::capsule_namespace::CapsuleId;

// ---------------------------------------------------------------------------
// ResourceQuota — per‑capsule cgroups v2 limits
// ---------------------------------------------------------------------------

/// Per‑capsule resource limits mirroring cgroups v2 controller knobs.
///
/// # cgroups v2 mapping
///
/// | Field                 | cgroups v2 file   | Range       |
/// |-----------------------|-------------------|-------------|
/// | `cpu_shares`          | `cpu.weight`      | 1 – 10 000  |
/// | `memory_limit_bytes`  | `memory.max`      | > 0         |
/// | `io_weight`           | `io.weight`       | 1 – 10 000  |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceQuota {
    /// Relative CPU weight (cgroups v2 `cpu.weight`).
    ///
    /// Higher values receive proportionally more CPU time under contention.
    /// Default (100) represents neutral weighting.
    pub cpu_shares: u32,

    /// Hard memory limit in bytes (cgroups v2 `memory.max`).
    ///
    /// A capsule exceeding this limit triggers an OOM‑dependent enforcement
    /// path (kill under [`EnforcementMode::Hard`]).
    pub memory_limit_bytes: u64,

    /// Relative I/O weight (cgroups v2 `io.weight`).
    ///
    /// Controls proportional I/O bandwidth allocation.
    pub io_weight: u32,
}

impl ResourceQuota {
    /// Conservative default suitable for a typical AI inference capsule.
    pub const DEFAULT: Self = Self {
        cpu_shares: 512,
        memory_limit_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
        io_weight: 500,
    };

    /// Generous default for a privileged system capsule.
    pub const PRIVILEGED: Self = Self {
        cpu_shares: 2048,
        memory_limit_bytes: 8 * 1024 * 1024 * 1024, // 8 GiB
        io_weight: 1000,
    };

    // ---------- validation (INV-CG-001) ------------------------------------

    /// Validate that all quota fields are within cgroups v2 spec ranges.
    ///
    /// Returns `true` iff:
    /// - `cpu_shares` ∈ [1, 10 000]
    /// - `memory_limit_bytes` > 0
    /// - `io_weight` ∈ [1, 10 000]
    #[must_use]
    pub fn validate(&self) -> bool {
        self.cpu_shares >= 1
            && self.cpu_shares <= 10_000
            && self.memory_limit_bytes > 0
            && self.io_weight >= 1
            && self.io_weight <= 10_000
    }

    /// Normalised CPU fraction this quota represents (0.0 … 1.0).
    ///
    /// Computed as `cpu_shares / 10 000`.
    #[must_use]
    pub fn cpu_fraction(&self) -> f64 {
        f64::from(self.cpu_shares) / 10_000.0
    }
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for ResourceQuota {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cpu={} mem={} io={}",
            self.cpu_shares, self.memory_limit_bytes, self.io_weight
        )
    }
}

// ---------------------------------------------------------------------------
// ResourceUsage — real‑time capsule resource snapshot
// ---------------------------------------------------------------------------

/// Snapshot of a capsule's current resource consumption.
///
/// Mirrors the aggregation of `cpu.stat`, `memory.current`, and `io.stat`
/// from the capsule's cgroup directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceUsage {
    /// CPU time consumed in microseconds (cgroups v2 `cpu.stat` → `usage_usec`).
    pub cpu_usage_usec: u64,

    /// Current memory footprint in bytes (cgroups v2 `memory.current`).
    pub memory_usage_bytes: u64,

    /// Total I/O bytes read (cgroups v2 `io.stat` → `rbytes`).
    pub io_read_bytes: u64,

    /// Total I/O bytes written (cgroups v2 `io.stat` → `wbytes`).
    pub io_write_bytes: u64,
}

impl ResourceUsage {
    /// Zero‑usage sentinel.
    pub const ZERO: Self = Self {
        cpu_usage_usec: 0,
        memory_usage_bytes: 0,
        io_read_bytes: 0,
        io_write_bytes: 0,
    };

    /// Combined I/O bytes (read + write).
    #[must_use]
    pub const fn io_total_bytes(&self) -> u64 {
        self.io_read_bytes.saturating_add(self.io_write_bytes)
    }
}

// ---------------------------------------------------------------------------
// ResourceType — tagged resource dimension
// ---------------------------------------------------------------------------

/// Which resource dimension triggered a violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    /// CPU time (cgroups v2 `cpu` controller).
    Cpu,
    /// Physical memory (cgroups v2 `memory` controller).
    Memory,
    /// Block I/O (cgroups v2 `io` controller).
    Io,
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cpu => write!(f, "cpu"),
            Self::Memory => write!(f, "memory"),
            Self::Io => write!(f, "io"),
        }
    }
}

// ---------------------------------------------------------------------------
// EnforcementMode — how strictly the quota is enforced
// ---------------------------------------------------------------------------

/// Enforcement strictness for a [`CgroupProfile`].
///
/// Maps to the AIOS policy plane's graduated enforcement model (§ S2.3):
/// - `Hard` → immediate action (throttle / kill).
/// - `Soft` → graceful degradation.
/// - `Warn` → observability‑only (log, emit evidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnforcementMode {
    /// Immediate enforcement — throttle CPU/IO, kill on memory exhaustion.
    Hard,
    /// Graceful enforcement — throttle before hard limits are reached.
    Soft,
    /// Observability‑only — log violation, take no automated action.
    Warn,
}

impl fmt::Display for EnforcementMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hard => write!(f, "hard"),
            Self::Soft => write!(f, "soft"),
            Self::Warn => write!(f, "warn"),
        }
    }
}

// ---------------------------------------------------------------------------
// QuotaViolation — a specific resource limit breach
// ---------------------------------------------------------------------------

/// A detected resource limit breach for a specific capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaViolation {
    /// The capsule that exceeded its quota.
    pub capsule_id: CapsuleId,

    /// Which resource was exhausted.
    pub resource: ResourceType,

    /// The configured limit that was exceeded.
    pub limit: u64,

    /// The actual observed usage at the time of violation.
    pub actual: u64,

    /// The enforcement mode under which this violation was detected.
    pub mode: EnforcementMode,
}

impl QuotaViolation {
    /// How far over the limit the usage is (0..1).  0.0 = exactly at limit.
    #[must_use]
    pub fn excess_ratio(&self) -> f64 {
        if self.limit == 0 {
            return f64::INFINITY;
        }
        (self.actual.saturating_sub(self.limit)) as f64 / self.limit as f64
    }

    /// Human‑readable violation description.
    #[must_use]
    pub fn description(&self) -> String {
        format!(
            "capsule {} exceeded {} limit: {} > {} ({:.1}% over)",
            self.capsule_id,
            self.resource,
            self.actual,
            self.limit,
            self.excess_ratio() * 100.0
        )
    }
}

impl fmt::Display for QuotaViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ---------------------------------------------------------------------------
// EnforcementAction — the decision produced by the enforcement engine
// ---------------------------------------------------------------------------

/// Action to take in response to a [`QuotaViolation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementAction {
    /// Reduce the offending resource's weight (new value provided).
    ///
    /// For CPU: the new `cpu.weight` to apply (lower = less CPU time).
    /// For I/O: the new `io.weight` to apply.
    Throttle(u32),

    /// Terminate the capsule (OOM semantics for memory exhaustion).
    Kill,

    /// Log the violation with a human‑readable message (no automated action).
    Warn(String),
}

impl fmt::Display for EnforcementAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Throttle(new_weight) => write!(f, "throttle({new_weight})"),
            Self::Kill => write!(f, "kill"),
            Self::Warn(msg) => write!(f, "warn: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// CgroupProfile — capsule‑bound quota + enforcement policy
// ---------------------------------------------------------------------------

/// A cgroup profile tying a capsule to its resource quota and enforcement
/// behaviour.
///
/// This is the main entry point for the resource‑governance subsystem:
/// - [`check_violation`](Self::check_violation) compares a [`ResourceUsage`]
///   snapshot against the profile's quota.
/// - [`enforce`](Self::enforce) maps a detected [`QuotaViolation`] to a
///   concrete [`EnforcementAction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupProfile {
    /// The capsule governed by this profile.
    pub capsule_id: CapsuleId,

    /// Resource limits for this capsule.
    pub quota: ResourceQuota,

    /// Enforcement strictness.
    pub mode: EnforcementMode,
}

impl CgroupProfile {
    /// Create a new profile for a capsule.
    #[must_use]
    pub const fn new(capsule_id: CapsuleId, quota: ResourceQuota, mode: EnforcementMode) -> Self {
        Self {
            capsule_id,
            quota,
            mode,
        }
    }

    // ---------- violation detection -----------------------------------------

    /// Compare actual resource usage against this profile's quota.
    ///
    /// Returns the first detected violation, or `None` if all resources are
    /// within limits.
    ///
    /// # Detection rules
    ///
    /// | Resource | Check                                                    |
    /// |----------|----------------------------------------------------------|
    /// | CPU      | `cpu_usage_usec` > `cpu_shares × CPU_USEC_PER_SHARE`    |
    /// | Memory   | `memory_usage_bytes` > `memory_limit_bytes`              |
    /// | I/O      | combined I/O bytes > `io_weight × IO_BYTES_PER_WEIGHT`  |
    #[must_use]
    pub fn check_violation(&self, usage: &ResourceUsage) -> Option<QuotaViolation> {
        // CPU — each cpu_share unit maps to 10 ms of CPU time in a 1 s window.
        let cpu_limit_usec = u64::from(self.quota.cpu_shares) * CPU_USEC_PER_SHARE;
        if usage.cpu_usage_usec > cpu_limit_usec {
            return Some(QuotaViolation {
                capsule_id: self.capsule_id,
                resource: ResourceType::Cpu,
                limit: cpu_limit_usec,
                actual: usage.cpu_usage_usec,
                mode: self.mode,
            });
        }

        // Memory — byte‑for‑byte comparison with the hard limit.
        if usage.memory_usage_bytes > self.quota.memory_limit_bytes {
            return Some(QuotaViolation {
                capsule_id: self.capsule_id,
                resource: ResourceType::Memory,
                limit: self.quota.memory_limit_bytes,
                actual: usage.memory_usage_bytes,
                mode: self.mode,
            });
        }

        // I/O — each io_weight unit maps to 1 MiB of I/O.
        let io_limit_bytes = u64::from(self.quota.io_weight) * IO_BYTES_PER_WEIGHT;
        let io_total = usage.io_total_bytes();
        if io_total > io_limit_bytes {
            return Some(QuotaViolation {
                capsule_id: self.capsule_id,
                resource: ResourceType::Io,
                limit: io_limit_bytes,
                actual: io_total,
                mode: self.mode,
            });
        }

        None
    }

    // ---------- enforcement (INV-CG-002, INV-CG-003) ------------------------

    /// Map a detected violation to a concrete enforcement action.
    ///
    /// # Enforcement matrix
    ///
    /// | Resource \ Mode | Hard          | Soft           | Warn          |
    /// |-----------------|---------------|----------------|---------------|
    /// | CPU             | Throttle(100) | Throttle(50%)  | Warn(msg)     |
    /// | Memory          | Kill          | Throttle(100)  | Warn(msg)     |
    /// | I/O             | Throttle(100) | Throttle(50%)  | Warn(msg)     |
    #[must_use]
    pub fn enforce(&self, violation: QuotaViolation) -> EnforcementAction {
        match self.mode {
            EnforcementMode::Hard => match violation.resource {
                ResourceType::Cpu => EnforcementAction::Throttle(HARD_CPU_THROTTLE),
                ResourceType::Memory => EnforcementAction::Kill,
                ResourceType::Io => EnforcementAction::Throttle(HARD_IO_THROTTLE),
            },
            EnforcementMode::Soft => match violation.resource {
                ResourceType::Cpu => {
                    let soft = (self.quota.cpu_shares / 2).max(1);
                    EnforcementAction::Throttle(soft)
                }
                ResourceType::Memory => EnforcementAction::Throttle(SOFT_MEM_THROTTLE),
                ResourceType::Io => {
                    let soft = (self.quota.io_weight / 2).max(1);
                    EnforcementAction::Throttle(soft)
                }
            },
            EnforcementMode::Warn => EnforcementAction::Warn(violation.description()),
        }
    }
}

impl fmt::Display for CgroupProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} quota=[{}] mode={}",
            self.capsule_id, self.quota, self.mode
        )
    }
}

// ---------------------------------------------------------------------------
// Constants — scaling factors for the model
// ---------------------------------------------------------------------------

/// Each `cpu.weight` share unit yields this many microseconds of CPU budget
/// in a 1 s accounting window.  With this constant, `cpu_shares=100` (default
/// weight) yields 100 ms/s = 10% CPU, and `cpu_shares=1000` yields 1 s/s =
/// 100% CPU.
const CPU_USEC_PER_SHARE: u64 = 1_000; // 1 ms per share unit

/// Each `io.weight` unit yields this many bytes of combined I/O budget.
/// With this constant, `io_weight=500` (default) yields 500 MiB of I/O.
const IO_BYTES_PER_WEIGHT: u64 = 1_048_576; // 1 MiB per weight unit

/// Hard‑mode throttled CPU weight (nearly idle — 1% of maximum).
const HARD_CPU_THROTTLE: u32 = 100;

/// Hard‑mode throttled I/O weight (nearly idle).
const HARD_IO_THROTTLE: u32 = 100;

/// Soft‑mode memory throttle weight (does not kill).
const SOFT_MEM_THROTTLE: u32 = 10;

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ResourceQuota validation
    // -----------------------------------------------------------------------

    #[test]
    fn valid_quota_passes_validation() {
        let q = ResourceQuota {
            cpu_shares: 512,
            memory_limit_bytes: 2 * 1024 * 1024 * 1024,
            io_weight: 500,
        };
        assert!(q.validate());
    }

    #[test]
    fn quota_validation_rejects_out_of_range_cpu() {
        // cpu_shares = 0 → invalid (below 1)
        assert!(!ResourceQuota {
            cpu_shares: 0,
            memory_limit_bytes: 1024,
            io_weight: 500,
        }
        .validate());

        // cpu_shares = 10001 → invalid (above 10000)
        assert!(!ResourceQuota {
            cpu_shares: 10_001,
            memory_limit_bytes: 1024,
            io_weight: 500,
        }
        .validate());
    }

    #[test]
    fn quota_validation_rejects_zero_memory() {
        assert!(!ResourceQuota {
            cpu_shares: 512,
            memory_limit_bytes: 0,
            io_weight: 500,
        }
        .validate());
    }

    #[test]
    fn quota_validation_rejects_out_of_range_io() {
        assert!(!ResourceQuota {
            cpu_shares: 512,
            memory_limit_bytes: 1024,
            io_weight: 0,
        }
        .validate());

        assert!(!ResourceQuota {
            cpu_shares: 512,
            memory_limit_bytes: 1024,
            io_weight: 10_001,
        }
        .validate());
    }

    #[test]
    fn boundary_values_pass_validation() {
        // Minimum valid values.
        assert!(ResourceQuota {
            cpu_shares: 1,
            memory_limit_bytes: 1,
            io_weight: 1,
        }
        .validate());

        // Maximum valid values.
        assert!(ResourceQuota {
            cpu_shares: 10_000,
            memory_limit_bytes: u64::MAX,
            io_weight: 10_000,
        }
        .validate());
    }

    // -----------------------------------------------------------------------
    // Violation detection — CPU
    // -----------------------------------------------------------------------

    #[test]
    fn cpu_violation_when_usage_exceeds_limit() {
        let quota = ResourceQuota {
            cpu_shares: 100, // 100 × 1000 = 100_000 usec limit
            memory_limit_bytes: u64::MAX,
            io_weight: 10_000,
        };
        let profile = CgroupProfile::new(CapsuleId(1), quota, EnforcementMode::Hard);

        // Under limit — no violation.
        let usage_ok = ResourceUsage {
            cpu_usage_usec: 99_999,
            memory_usage_bytes: 0,
            io_read_bytes: 0,
            io_write_bytes: 0,
        };
        assert!(profile.check_violation(&usage_ok).is_none());

        // Over limit — violation.
        let usage_over = ResourceUsage {
            cpu_usage_usec: 100_001,
            memory_usage_bytes: 0,
            io_read_bytes: 0,
            io_write_bytes: 0,
        };
        let v = profile.check_violation(&usage_over);
        assert!(v.is_some());
        let v = v.unwrap();
        assert_eq!(v.resource, ResourceType::Cpu);
        assert_eq!(v.capsule_id, CapsuleId(1));
        assert_eq!(v.limit, 100_000);
        assert_eq!(v.actual, 100_001);
        assert_eq!(v.mode, EnforcementMode::Hard);
    }

    // -----------------------------------------------------------------------
    // Violation detection — Memory
    // -----------------------------------------------------------------------

    #[test]
    fn memory_violation_when_usage_exceeds_limit() {
        let quota = ResourceQuota {
            cpu_shares: 10_000,
            memory_limit_bytes: 1024 * 1024 * 1024, // 1 GiB
            io_weight: 10_000,
        };
        let profile = CgroupProfile::new(CapsuleId(2), quota, EnforcementMode::Soft);

        // Exactly at limit — no violation.
        let usage_at = ResourceUsage {
            cpu_usage_usec: 0,
            memory_usage_bytes: 1024 * 1024 * 1024,
            io_read_bytes: 0,
            io_write_bytes: 0,
        };
        assert!(profile.check_violation(&usage_at).is_none());

        // Over limit.
        let usage_over = ResourceUsage {
            cpu_usage_usec: 0,
            memory_usage_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
            io_read_bytes: 0,
            io_write_bytes: 0,
        };
        let v = profile.check_violation(&usage_over).unwrap();
        assert_eq!(v.resource, ResourceType::Memory);
        assert_eq!(v.limit, 1024 * 1024 * 1024);
        assert_eq!(v.actual, 2 * 1024 * 1024 * 1024);
        assert_eq!(v.mode, EnforcementMode::Soft);
    }

    // -----------------------------------------------------------------------
    // Violation detection — I/O
    // -----------------------------------------------------------------------

    #[test]
    fn io_violation_when_combined_io_exceeds_limit() {
        let quota = ResourceQuota {
            cpu_shares: 10_000,
            memory_limit_bytes: u64::MAX,
            io_weight: 100, // 100 × 1 MiB = 100 MiB limit
        };
        let profile = CgroupProfile::new(CapsuleId(3), quota, EnforcementMode::Warn);

        let usage_over = ResourceUsage {
            cpu_usage_usec: 0,
            memory_usage_bytes: 0,
            io_read_bytes: 80 * 1024 * 1024,  // 80 MiB
            io_write_bytes: 40 * 1024 * 1024, // 40 MiB → total 120 MiB > 100 MiB
        };
        let v = profile.check_violation(&usage_over).unwrap();
        assert_eq!(v.resource, ResourceType::Io);
        assert_eq!(v.limit, 100 * 1024 * 1024);
        assert_eq!(v.actual, 120 * 1024 * 1024);
    }

    // -----------------------------------------------------------------------
    // Soft vs Hard enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn hard_cpu_enforcement_throttles_to_minimum() {
        let quota = ResourceQuota::default();
        let profile = CgroupProfile::new(CapsuleId(1), quota, EnforcementMode::Hard);
        let violation = QuotaViolation {
            capsule_id: CapsuleId(1),
            resource: ResourceType::Cpu,
            limit: 500_000,
            actual: 600_000,
            mode: EnforcementMode::Hard,
        };

        let action = profile.enforce(violation);
        assert_eq!(action, EnforcementAction::Throttle(HARD_CPU_THROTTLE));
    }

    #[test]
    fn hard_memory_enforcement_kills() {
        let quota = ResourceQuota::default();
        let profile = CgroupProfile::new(CapsuleId(1), quota, EnforcementMode::Hard);
        let violation = QuotaViolation {
            capsule_id: CapsuleId(1),
            resource: ResourceType::Memory,
            limit: 1024 * 1024 * 1024,
            actual: 2 * 1024 * 1024 * 1024,
            mode: EnforcementMode::Hard,
        };

        let action = profile.enforce(violation);
        assert_eq!(action, EnforcementAction::Kill);
    }

    #[test]
    fn soft_cpu_enforcement_throttles_to_half_weight() {
        let quota = ResourceQuota {
            cpu_shares: 600,
            memory_limit_bytes: 1024,
            io_weight: 500,
        };
        let profile = CgroupProfile::new(CapsuleId(2), quota, EnforcementMode::Soft);
        let violation = QuotaViolation {
            capsule_id: CapsuleId(2),
            resource: ResourceType::Cpu,
            limit: 500_000,
            actual: 600_000,
            mode: EnforcementMode::Soft,
        };

        let action = profile.enforce(violation);
        // Soft → cpu_shares / 2 → 300.
        assert_eq!(action, EnforcementAction::Throttle(300));
    }

    #[test]
    fn soft_io_enforcement_throttles_to_half_weight() {
        let quota = ResourceQuota {
            cpu_shares: 512,
            memory_limit_bytes: 1024,
            io_weight: 400,
        };
        let profile = CgroupProfile::new(CapsuleId(3), quota, EnforcementMode::Soft);
        let violation = QuotaViolation {
            capsule_id: CapsuleId(3),
            resource: ResourceType::Io,
            limit: 400 * 1024 * 1024,
            actual: 500 * 1024 * 1024,
            mode: EnforcementMode::Soft,
        };

        let action = profile.enforce(violation);
        assert_eq!(action, EnforcementAction::Throttle(200)); // 400 / 2
    }

    #[test]
    fn soft_memory_enforcement_throttles_instead_of_killing() {
        let quota = ResourceQuota::default();
        let profile = CgroupProfile::new(CapsuleId(1), quota, EnforcementMode::Soft);
        let violation = QuotaViolation {
            capsule_id: CapsuleId(1),
            resource: ResourceType::Memory,
            limit: 1024 * 1024 * 1024,
            actual: 2 * 1024 * 1024 * 1024,
            mode: EnforcementMode::Soft,
        };

        let action = profile.enforce(violation);
        // Soft mode never kills (INV-CG-003).
        assert!(matches!(action, EnforcementAction::Throttle(_)));
        assert_ne!(action, EnforcementAction::Kill);
    }

    #[test]
    fn warn_mode_always_warns() {
        let quota = ResourceQuota::default();
        let profile = CgroupProfile::new(CapsuleId(1), quota, EnforcementMode::Warn);

        for resource in [ResourceType::Cpu, ResourceType::Memory, ResourceType::Io] {
            let violation = QuotaViolation {
                capsule_id: CapsuleId(1),
                resource,
                limit: 100,
                actual: 200,
                mode: EnforcementMode::Warn,
            };
            let action = profile.enforce(violation);
            assert!(
                matches!(action, EnforcementAction::Warn(_)),
                "Warn mode should produce Warn for {resource:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Multiple resource types — first violation wins
    // -----------------------------------------------------------------------

    #[test]
    fn first_violation_detected_is_returned() {
        let quota = ResourceQuota {
            cpu_shares: 10, // Very tight CPU — 10_000 usec
            memory_limit_bytes: 1024,
            io_weight: 10_000,
        };
        let profile = CgroupProfile::new(CapsuleId(1), quota, EnforcementMode::Hard);

        let usage = ResourceUsage {
            cpu_usage_usec: 50_000,   // CPU violated
            memory_usage_bytes: 2048, // Memory also violated
            io_read_bytes: 0,
            io_write_bytes: 0,
        };

        // CPU is checked first, so CPU violation fires.
        let v = profile.check_violation(&usage).unwrap();
        assert_eq!(v.resource, ResourceType::Cpu);
    }

    // -----------------------------------------------------------------------
    // No violation when all resources within limits
    // -----------------------------------------------------------------------

    #[test]
    fn no_violation_when_all_within_limits() {
        let quota = ResourceQuota {
            cpu_shares: 10_000,
            memory_limit_bytes: 8 * 1024 * 1024 * 1024,
            io_weight: 10_000,
        };
        let profile = CgroupProfile::new(CapsuleId(1), quota, EnforcementMode::Hard);

        let usage = ResourceUsage {
            cpu_usage_usec: 5_000_000,
            memory_usage_bytes: 4 * 1024 * 1024 * 1024,
            io_read_bytes: 50 * 1024 * 1024,
            io_write_bytes: 50 * 1024 * 1024,
        };

        assert!(profile.check_violation(&usage).is_none());
    }

    // -----------------------------------------------------------------------
    // QuotaViolation helpers
    // -----------------------------------------------------------------------

    #[test]
    fn excess_ratio_computes_correctly() {
        let v = QuotaViolation {
            capsule_id: CapsuleId(1),
            resource: ResourceType::Memory,
            limit: 1000,
            actual: 1500,
            mode: EnforcementMode::Hard,
        };
        assert!((v.excess_ratio() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn excess_ratio_zero_when_at_limit() {
        let v = QuotaViolation {
            capsule_id: CapsuleId(1),
            resource: ResourceType::Cpu,
            limit: 1000,
            actual: 1000,
            mode: EnforcementMode::Hard,
        };
        // actual == limit → no excess → ratio = 0.0.
        assert!((v.excess_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn excess_ratio_infinity_when_zero_limit() {
        let v = QuotaViolation {
            capsule_id: CapsuleId(1),
            resource: ResourceType::Io,
            limit: 0,
            actual: 100,
            mode: EnforcementMode::Hard,
        };
        assert!(v.excess_ratio().is_infinite());
    }

    // -----------------------------------------------------------------------
    // Display / Default / Convenience
    // -----------------------------------------------------------------------

    #[test]
    fn resource_type_display() {
        assert_eq!(format!("{}", ResourceType::Cpu), "cpu");
        assert_eq!(format!("{}", ResourceType::Memory), "memory");
        assert_eq!(format!("{}", ResourceType::Io), "io");
    }

    #[test]
    fn enforcement_mode_display() {
        assert_eq!(format!("{}", EnforcementMode::Hard), "hard");
        assert_eq!(format!("{}", EnforcementMode::Soft), "soft");
        assert_eq!(format!("{}", EnforcementMode::Warn), "warn");
    }

    #[test]
    fn enforcement_action_display() {
        assert_eq!(
            format!("{}", EnforcementAction::Throttle(200)),
            "throttle(200)"
        );
        assert_eq!(format!("{}", EnforcementAction::Kill), "kill");
        let w = EnforcementAction::Warn("limit exceeded".into());
        assert_eq!(format!("{w}"), "warn: limit exceeded");
    }

    #[test]
    fn quota_violation_description() {
        let v = QuotaViolation {
            capsule_id: CapsuleId(7),
            resource: ResourceType::Memory,
            limit: 1000,
            actual: 1200,
            mode: EnforcementMode::Hard,
        };
        let desc = v.description();
        assert!(desc.contains("capsule-7"));
        assert!(desc.contains("memory"));
        assert!(desc.contains("1200"));
        assert!(desc.contains("1000"));
        assert!(desc.contains("20.0%"));
    }

    #[test]
    fn resource_usage_io_total_saturating() {
        let u = ResourceUsage {
            cpu_usage_usec: 0,
            memory_usage_bytes: 0,
            io_read_bytes: u64::MAX,
            io_write_bytes: 100,
        };
        assert_eq!(u.io_total_bytes(), u64::MAX); // saturating
    }

    #[test]
    fn default_quota_is_valid() {
        assert!(ResourceQuota::default().validate());
        assert!(ResourceQuota::PRIVILEGED.validate());
    }

    #[test]
    fn cpu_fraction_is_normalized() {
        assert!((ResourceQuota::default().cpu_fraction() - 0.0512).abs() < 0.001);
        assert!((ResourceQuota::PRIVILEGED.cpu_fraction() - 0.2048).abs() < 0.001);
    }
}
