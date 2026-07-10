//! Service hardening score gates — S16.7 measurable, scored, gated
//! hardening posture for long-running AIOS systemd services.
//!
//! ## Product principle
//!
//! A service is allowed to run with broad privilege only if someone proved it
//! _needs_ that privilege and recorded the proof. The default posture is
//! "minimal exposure, scored, and gated."
//!
//! ## Architecture
//!
//! ```text
//! service unit defined
//!   -> derive ServiceClass
//!   -> measure HardeningScore (named sub-checks)
//!   -> compare against class floor for active SecurityProfile
//!   -> emit SERVICE_HARDENING_SCORE_COMPUTED evidence
//!   -> at or above floor: allow promotion to active
//!   -> below floor: block, show fix
//! ```
//!
//! ## Constitutional invariants
//!
//! - **INV-SEC-007:** An AIOS-owned service in `unconfined_t` is a hard deny
//!   in all profiles (DEV_FIXTURE exempt only under DEV_RELAXED).
//! - **INV-SEC-008:** Under STIG_ALIGNED / AIRGAP_HIGH any numeric floor miss
//!   blocks promotion.
//! - **INV-SEC-009:** No AI subject may set, edit, relax, or approve a floor,
//!   class assignment, directive waiver, or hardening exception.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

use crate::security_profile::SecurityProfile;

// ---------------------------------------------------------------------------
// HardeningDirective — closed 19-variant set per S16.7 §6
// ---------------------------------------------------------------------------

/// Every systemd hardening directive the scorer evaluates.
///
/// The variant set is closed and maps to the named sub-check ids in
/// the `ServiceHardeningSubCheck` enumeration from S16.7 §6. Adding,
/// removing, or reordering a variant is a breaking spec change.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HardeningDirective {
    /// `NoNewPrivileges=yes` — prevents privilege escalation via setuid.
    NoNewPrivileges,
    /// `ProtectSystem=strict` — read-only mount namespace for /usr, /etc.
    ProtectSystem,
    /// `ProtectHome=true` — make /home, /root, /run/user inaccessible.
    ProtectHome,
    /// `PrivateTmp=true` — per-service private /tmp and /var/tmp.
    PrivateTmp,
    /// `PrivateDevices=true` — minimal, CAP_MKNOD-less /dev.
    PrivateDevices,
    /// `ProtectKernelTunables=true` — sysctl and kernel tunables RO.
    ProtectKernelTunables,
    /// `ProtectKernelModules=true` — deny module loading.
    ProtectKernelModules,
    /// `ProtectKernelLogs=true` — restrict kernel log access.
    ProtectKernelLogs,
    /// `ProtectControlGroups=true` — cgroupfs mounted read-only.
    ProtectControlGroups,
    /// `RestrictNamespaces=true` — deny CLONE_NEW*.
    RestrictNamespaces,
    /// `RestrictRealtime=true` — deny real-time scheduling.
    RestrictRealtime,
    /// `RestrictSUIDSGID=true` — deny setuid/setgid bit creation.
    RestrictSUIDSGID,
    /// `LockPersonality=true` — lock personality(2) after first call.
    LockPersonality,
    /// `MemoryDenyWriteExecute=true` — W^X policy for process memory.
    MemoryDenyWriteExecute,
    /// `CapabilityBoundingSet=...` — bounding capabilities for execve'd
    /// processes. Empty string means "drop all."
    CapabilityBoundingSet,
    /// `SystemCallFilter=...` — seccomp syscall filter (allowlist or @set).
    SystemCallFilter,
    /// `SystemCallArchitectures=native` — restrict to native ABI only.
    SystemCallArchitectures,
    /// `RestrictAddressFamilies=...` — restrict socket address families.
    RestrictAddressFamilies,
    /// `SELinuxContext=...` — MAC confinement domain per S16.2.
    SELinuxConfinement,
}

impl HardeningDirective {
    /// Human-readable label matching the systemd unit directive.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::NoNewPrivileges => "NoNewPrivileges",
            Self::ProtectSystem => "ProtectSystem",
            Self::ProtectHome => "ProtectHome",
            Self::PrivateTmp => "PrivateTmp",
            Self::PrivateDevices => "PrivateDevices",
            Self::ProtectKernelTunables => "ProtectKernelTunables",
            Self::ProtectKernelModules => "ProtectKernelModules",
            Self::ProtectKernelLogs => "ProtectKernelLogs",
            Self::ProtectControlGroups => "ProtectControlGroups",
            Self::RestrictNamespaces => "RestrictNamespaces",
            Self::RestrictRealtime => "RestrictRealtime",
            Self::RestrictSUIDSGID => "RestrictSUIDSGID",
            Self::LockPersonality => "LockPersonality",
            Self::MemoryDenyWriteExecute => "MemoryDenyWriteExecute",
            Self::CapabilityBoundingSet => "CapabilityBoundingSet",
            Self::SystemCallFilter => "SystemCallFilter",
            Self::SystemCallArchitectures => "SystemCallArchitectures",
            Self::RestrictAddressFamilies => "RestrictAddressFamilies",
            Self::SELinuxConfinement => "SELinuxConfinement",
        }
    }

    /// The default weight this directive contributes to the score.
    /// Higher-weight directives cause larger score deductions when missing.
    #[must_use]
    pub fn default_weight(self) -> u32 {
        match self {
            Self::SELinuxConfinement => 10,
            Self::CapabilityBoundingSet => 8,
            Self::SystemCallFilter => 8,
            Self::NoNewPrivileges => 7,
            Self::ProtectSystem => 7,
            Self::MemoryDenyWriteExecute => 7,
            Self::ProtectHome => 5,
            Self::PrivateTmp => 5,
            Self::PrivateDevices => 5,
            Self::ProtectKernelTunables => 5,
            Self::ProtectKernelModules => 5,
            Self::ProtectKernelLogs => 4,
            Self::ProtectControlGroups => 4,
            Self::RestrictNamespaces => 4,
            Self::RestrictRealtime => 4,
            Self::RestrictSUIDSGID => 4,
            Self::LockPersonality => 2,
            Self::SystemCallArchitectures => 3,
            Self::RestrictAddressFamilies => 3,
        }
    }

    /// All available directives, in definition order.
    #[must_use]
    pub fn all() -> Vec<Self> {
        use strum::IntoEnumIterator;
        Self::iter().collect()
    }

    /// The total number of directive variants (compile-time constant).
    #[must_use]
    pub fn count() -> usize {
        use strum::EnumCount;
        Self::COUNT
    }
}

// ---------------------------------------------------------------------------
// HardeningDirectiveValue — the expected value for a directive
// ---------------------------------------------------------------------------

/// The expected or observed value for a single hardening directive.
///
/// Different directives accept different value shapes:
/// - Boolean directives (`NoNewPrivileges`, etc.) use [`YesNo`].
/// - Path-based directives use [`PathList`].
/// - Capability/syscall/address-family lists use their respective variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HardeningDirectiveValue {
    /// A boolean directive (`yes` / `true` vs `no` / `false`).
    YesNo(bool),
    /// A list of filesystem paths (e.g. `ReadOnlyPaths`, `InaccessiblePaths`).
    PathList(Vec<String>),
    /// A list of Linux capabilities (e.g. `CAP_NET_BIND_SERVICE`).
    CapabilitySet(Vec<String>),
    /// A list of seccomp syscall names or `@set` tokens.
    SyscallSet(Vec<String>),
    /// A list of address family names (e.g. `AF_UNIX`, `AF_INET`).
    AddressFamilySet(Vec<String>),
}

impl HardeningDirectiveValue {
    /// Convenience constructor for a boolean `true` value.
    #[must_use]
    pub fn yes() -> Self {
        Self::YesNo(true)
    }

    /// Convenience constructor for a boolean `false` value.
    #[must_use]
    pub fn no() -> Self {
        Self::YesNo(false)
    }

    /// Whether this is a "true" value (satisfies the directive).
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::YesNo(v) => *v,
            Self::PathList(v) => !v.is_empty(),
            Self::CapabilitySet(v) => v.iter().any(|c| !c.is_empty()),
            Self::SyscallSet(v) => !v.is_empty(),
            Self::AddressFamilySet(v) => !v.is_empty(),
        }
    }

    /// A human-readable representation for evidence records.
    #[must_use]
    pub fn to_display_string(&self) -> String {
        match self {
            Self::YesNo(v) => {
                if *v {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            Self::PathList(paths) => paths.join(", "),
            Self::CapabilitySet(caps) => caps.join(", "),
            Self::SyscallSet(calls) => calls.join(", "),
            Self::AddressFamilySet(fams) => fams.join(", "),
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceClass — closed per S16.7 §4
// ---------------------------------------------------------------------------

/// The security tier of an AIOS-owned systemd unit.
///
/// Every unit is assigned exactly one class. The class drives the
/// hardening floor, the mandatory/forbidden directive set, and the
/// promotion gate severity.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceClass {
    /// Most-hardened; touches constitutional truth. Policy Kernel, Evidence Log.
    ConstitutionalCore,
    /// Owns secret material; strictest memory and filesystem isolation.
    SecurityBroker,
    /// Executes typed actions; broad-but-bounded.
    CapabilityRuntime,
    /// AI-facing; no privilege escalation, no eBPF authorship (INV-025).
    AiPlane,
    /// Untrusted-input-facing renderers, bridges, voice services.
    RendererSurface,
    /// Read-mostly telemetry, scanners, log shippers.
    Observability,
    /// Orchestrators, schedulers; no direct mutation authority.
    SystemIntegration,
    /// Recovery-path units; must boot without the Cognitive Core.
    RecoveryService,
    /// Dev-only test/mock units; permitted only under DEV_RELAXED.
    DevFixture,
}

impl ServiceClass {
    /// Human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ConstitutionalCore => "CONSTITUTIONAL_CORE",
            Self::SecurityBroker => "SECURITY_BROKER",
            Self::CapabilityRuntime => "CAPABILITY_RUNTIME",
            Self::AiPlane => "AI_PLANE",
            Self::RendererSurface => "RENDERER_SURFACE",
            Self::Observability => "OBSERVABILITY",
            Self::SystemIntegration => "SYSTEM_INTEGRATION",
            Self::RecoveryService => "RECOVERY_SERVICE",
            Self::DevFixture => "DEV_FIXTURE",
        }
    }

    /// All service classes in definition order.
    #[must_use]
    pub fn all() -> Vec<Self> {
        use strum::IntoEnumIterator;
        Self::iter().collect()
    }
}

// ---------------------------------------------------------------------------
// HardeningBaseline — four-level hardening posture
// ---------------------------------------------------------------------------

/// Pre-defined hardening baselines that correspond to the four
/// [`SecurityProfile`] levels.
///
/// Each baseline carries a set of mandatory directives and a default
/// floor that tightens as the profile becomes stricter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardeningBaseline {
    /// Developer workstation — warn on numeric misses; DEV_FIXTURE permitted.
    DevRelaxed,
    /// Production baseline — warn on numeric, block on structural hard deny.
    SecureDefault,
    /// DISA STIG-aligned — block on any miss; exceptions only via S16.3 register.
    StigAligned,
    /// Air-gapped high-assurance — block on any miss; no live exception.
    AirgapHigh,
}

impl HardeningBaseline {
    /// Map a [`SecurityProfile`] to its corresponding baseline.
    #[must_use]
    pub fn from_profile(profile: SecurityProfile) -> Self {
        match profile {
            SecurityProfile::DevRelaxed => Self::DevRelaxed,
            SecurityProfile::SecureDefault => Self::SecureDefault,
            SecurityProfile::StigAligned => Self::StigAligned,
            SecurityProfile::AirgapHigh => Self::AirgapHigh,
        }
    }

    /// Human-readable label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::DevRelaxed => "DEV_RELAXED",
            Self::SecureDefault => "SECURE_DEFAULT",
            Self::StigAligned => "STIG_ALIGNED",
            Self::AirgapHigh => "AIRGAP_HIGH",
        }
    }

    /// Whether this baseline blocks (not just warns) on numeric floor miss.
    #[must_use]
    pub fn blocks_on_numeric_miss(&self) -> bool {
        matches!(self, Self::StigAligned | Self::AirgapHigh)
    }

    /// Whether this baseline blocks (not just warns) on structural hard deny.
    #[must_use]
    pub fn blocks_on_structural_deny(&self) -> bool {
        matches!(
            self,
            Self::SecureDefault | Self::StigAligned | Self::AirgapHigh
        )
    }

    /// Whether DEV_FIXTURE is permitted under this baseline.
    #[must_use]
    pub fn allows_dev_fixture(&self) -> bool {
        matches!(self, Self::DevRelaxed)
    }

    /// The mandatory set of directives for the most hardened class
    /// (CONSTITUTIONAL_CORE) under this baseline.
    ///
    /// Stricter baselines add directives; no baseline removes a directive
    /// required by a weaker baseline (monotonicity per INV-SEC-001).
    #[must_use]
    pub fn core_mandatory_directives(&self) -> Vec<HardeningDirective> {
        use HardeningDirective::*;
        match self {
            Self::DevRelaxed => vec![NoNewPrivileges, MemoryDenyWriteExecute, SELinuxConfinement],
            Self::SecureDefault => vec![
                NoNewPrivileges,
                ProtectSystem,
                PrivateTmp,
                ProtectKernelTunables,
                ProtectKernelModules,
                MemoryDenyWriteExecute,
                SystemCallFilter,
                CapabilityBoundingSet,
                SELinuxConfinement,
            ],
            Self::StigAligned | Self::AirgapHigh => Self::all(),
        }
    }

    /// Every directive the scorer knows about.
    #[must_use]
    fn all() -> Vec<HardeningDirective> {
        HardeningDirective::all()
    }
}

// ---------------------------------------------------------------------------
// DirectiveResult — per-directive scoring outcome
// ---------------------------------------------------------------------------

/// The scoring outcome for a single hardening directive check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectiveResult {
    /// The directive that was checked.
    pub directive: HardeningDirective,
    /// Human-readable representation of the observed value.
    pub observed: String,
    /// Whether the observed value satisfies the requirement.
    pub satisfied: bool,
    /// The weight this directive contributed to scoring.
    pub weight: u32,
    /// The points deducted from the base score (`0` when satisfied).
    pub deduction: u32,
}

// ---------------------------------------------------------------------------
// ServiceHardeningPolicy — per-class floor + mandatory directives
// ---------------------------------------------------------------------------

/// Per-service-class hardening policy that combines a minimum score floor
/// with the mandatory and forbidden directive sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHardeningPolicy {
    /// The service class this policy governs.
    pub service_class: ServiceClass,
    /// The security profile this policy applies to.
    pub profile: SecurityProfile,
    /// Minimum score (0–100) required for promotion.  Higher is better.
    pub minimum_score: u32,
    /// Directives that must be present (with a truthy value).
    pub mandatory_directives: Vec<HardeningDirective>,
    /// Directives that must NOT be present (hard deny).
    pub forbidden_directives: Vec<HardeningDirective>,
}

impl ServiceHardeningPolicy {
    /// Build a policy for the given class and profile using the canonical
    /// S16.7 floor table.
    ///
    /// Floors are derived from S16.7 §7:
    ///
    /// | Class                | DEV_RELAXED | SECURE_DEFAULT | STIG_ALIGNED | AIRGAP_HIGH |
    /// |----------------------|-------------|----------------|--------------|-------------|
    /// | CONSTITUTIONAL_CORE  | 70          | 75             | 80           | 85          |
    /// | SECURITY_BROKER      | 70          | 75             | 80           | 85          |
    /// | RECOVERY_SERVICE     | 65          | 70             | 75           | 80          |
    /// | AI_PLANE             | 60          | 65             | 70           | 75          |
    /// | CAPABILITY_RUNTIME   | 55          | 60             | 65           | 70          |
    /// | SYSTEM_INTEGRATION   | 55          | 60             | 65           | 70          |
    /// | OBSERVABILITY        | 50          | 55             | 60           | 65          |
    /// | RENDERER_SURFACE     | 50          | 55             | 60           | 65          |
    #[must_use]
    pub fn canonical(service_class: ServiceClass, profile: SecurityProfile) -> Option<Self> {
        let floor = Self::floor_for(service_class, profile)?;

        let baseline = HardeningBaseline::from_profile(profile);
        let mut mandatory = baseline.core_mandatory_directives();

        // DEV_FIXTURE relaxes mandatory directives under DEV_RELAXED.
        if service_class == ServiceClass::DevFixture && baseline == HardeningBaseline::DevRelaxed {
            mandatory = vec![HardeningDirective::NoNewPrivileges];
        }

        let forbidden = Self::forbidden_directives(service_class, &baseline);

        Some(Self {
            service_class,
            profile,
            minimum_score: floor,
            mandatory_directives: mandatory,
            forbidden_directives: forbidden,
        })
    }

    /// Look up the canonical floor for a (class, profile) pair.
    ///
    /// Returns `None` when the class is not permitted under this profile
    /// (e.g. `DevFixture` outside `DEV_RELAXED`).
    #[must_use]
    fn floor_for(service_class: ServiceClass, profile: SecurityProfile) -> Option<u32> {
        match (service_class, profile) {
            // DEV_FIXTURE only under DEV_RELAXED
            (ServiceClass::DevFixture, SecurityProfile::DevRelaxed) => Some(20),
            (ServiceClass::DevFixture, _) => None,

            (ServiceClass::ConstitutionalCore, SecurityProfile::DevRelaxed) => Some(70),
            (ServiceClass::ConstitutionalCore, SecurityProfile::SecureDefault) => Some(75),
            (ServiceClass::ConstitutionalCore, SecurityProfile::StigAligned) => Some(80),
            (ServiceClass::ConstitutionalCore, SecurityProfile::AirgapHigh) => Some(85),

            (ServiceClass::SecurityBroker, SecurityProfile::DevRelaxed) => Some(70),
            (ServiceClass::SecurityBroker, SecurityProfile::SecureDefault) => Some(75),
            (ServiceClass::SecurityBroker, SecurityProfile::StigAligned) => Some(80),
            (ServiceClass::SecurityBroker, SecurityProfile::AirgapHigh) => Some(85),

            (ServiceClass::RecoveryService, SecurityProfile::DevRelaxed) => Some(65),
            (ServiceClass::RecoveryService, SecurityProfile::SecureDefault) => Some(70),
            (ServiceClass::RecoveryService, SecurityProfile::StigAligned) => Some(75),
            (ServiceClass::RecoveryService, SecurityProfile::AirgapHigh) => Some(80),

            (ServiceClass::AiPlane, SecurityProfile::DevRelaxed) => Some(60),
            (ServiceClass::AiPlane, SecurityProfile::SecureDefault) => Some(65),
            (ServiceClass::AiPlane, SecurityProfile::StigAligned) => Some(70),
            (ServiceClass::AiPlane, SecurityProfile::AirgapHigh) => Some(75),

            (ServiceClass::CapabilityRuntime, SecurityProfile::DevRelaxed) => Some(55),
            (ServiceClass::CapabilityRuntime, SecurityProfile::SecureDefault) => Some(60),
            (ServiceClass::CapabilityRuntime, SecurityProfile::StigAligned) => Some(65),
            (ServiceClass::CapabilityRuntime, SecurityProfile::AirgapHigh) => Some(70),

            (ServiceClass::SystemIntegration, SecurityProfile::DevRelaxed) => Some(55),
            (ServiceClass::SystemIntegration, SecurityProfile::SecureDefault) => Some(60),
            (ServiceClass::SystemIntegration, SecurityProfile::StigAligned) => Some(65),
            (ServiceClass::SystemIntegration, SecurityProfile::AirgapHigh) => Some(70),

            (ServiceClass::Observability, SecurityProfile::DevRelaxed) => Some(50),
            (ServiceClass::Observability, SecurityProfile::SecureDefault) => Some(55),
            (ServiceClass::Observability, SecurityProfile::StigAligned) => Some(60),
            (ServiceClass::Observability, SecurityProfile::AirgapHigh) => Some(65),

            (ServiceClass::RendererSurface, SecurityProfile::DevRelaxed) => Some(50),
            (ServiceClass::RendererSurface, SecurityProfile::SecureDefault) => Some(55),
            (ServiceClass::RendererSurface, SecurityProfile::StigAligned) => Some(60),
            (ServiceClass::RendererSurface, SecurityProfile::AirgapHigh) => Some(65),
        }
    }

    /// Build the forbidden directive set for a class under a baseline.
    #[must_use]
    fn forbidden_directives(
        _service_class: ServiceClass,
        _baseline: &HardeningBaseline,
    ) -> Vec<HardeningDirective> {
        // For now the forbidden set is empty — the spec's forbidden_directives
        // such as "PrivilegedTrue" and "CapabilityBoundingSet=~" are structural
        // denies that the runtime checks inline during unit parsing.
        vec![]
    }
}

// ---------------------------------------------------------------------------
// HardeningScore — per-service computed hardening posture
// ---------------------------------------------------------------------------

/// The computed hardening score for a single service.
///
/// The total score ranges from `0` (completely unhardened) to `100`
/// (fully hardened per the class baseline). Each mandatory directive
/// that is missing or unsatisfied subtracts its weight from 100.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningScore {
    /// The service unit name (e.g. `aios-policy-kernel.service`).
    pub service_name: String,
    /// The assigned service class.
    pub service_class: ServiceClass,
    /// The active security profile at scoring time.
    pub profile: SecurityProfile,
    /// Total score from 0 (worst) to 100 (best).
    pub total_score: u32,
    /// Per-directive check results.
    pub directive_results: Vec<DirectiveResult>,
    /// Whether promotion is currently blocked.
    pub promotion_blocked: bool,
    /// Human-readable reasons why promotion is blocked.
    pub blocked_reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// GateVerdict — promotion gate outcome
// ---------------------------------------------------------------------------

/// The outcome of the promotion gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GateVerdict {
    /// Hardening score meets or exceeds the floor; allow activation.
    Pass,
    /// Numeric miss under DEV_RELAXED; warn but allow.
    Warn,
    /// Numeric or structural miss; block activation.
    Fail,
}

// ---------------------------------------------------------------------------
// ServiceHardeningScoredEvidence — S16.7 evidence record
// ---------------------------------------------------------------------------

/// Evidence record emitted on every hardening score computation.
///
/// Per S16.7 §11, `SERVICE_HARDENING_SCORED` is appended to the Evidence Log
/// as an append-only, AI-immutable record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceHardeningScoredEvidence {
    /// Service unit name.
    pub unit: String,
    /// Resolved service class.
    pub service_class: String,
    /// Active security profile.
    pub profile_id: String,
    /// Total hardening score (0–100).
    pub exposure_score: u32,
    /// Rating derived from the score.
    pub overall_rating: String,
    /// Floor that was applied.
    pub floor_applied: u32,
    /// Gate verdict.
    pub gate_verdict: String,
    /// Unsatisfied sub-check directive labels.
    pub unsatisfied_sub_checks: Vec<String>,
    /// Structural denies encountered (e.g. "unconfined_t").
    pub structural_denies: Vec<String>,
    /// ISO-8601 timestamp of measurement.
    pub measured_at: String,
}

// ---------------------------------------------------------------------------
// HardeningScoreCalculator — deterministic scorer
// ---------------------------------------------------------------------------

/// Computes hardening scores against a policy.
///
/// The calculator is deterministic: the same effective directives and
/// policy always produce the same score (S16.7 §6).
#[derive(Debug, Clone)]
pub struct HardeningScoreCalculator;

impl HardeningScoreCalculator {
    /// Compute the hardening score for a service given its observed
    /// directive → value map and the governing policy.
    ///
    /// Scoring algorithm:
    /// 1. Start at 100.
    /// 2. For each mandatory directive, subtract its weight if missing
    ///    or not truthy.
    /// 3. Clamp to [0, 100].
    /// 4. Structural hard denies (DEV_FIXTURE outside DEV_RELAXED,
    ///    SELinuxConfinement = false) can block promotion regardless
    ///    of numeric score.
    #[must_use]
    pub fn calculate_score(
        service_name: impl Into<String>,
        service_class: ServiceClass,
        profile: SecurityProfile,
        observed_directives: &HashMap<HardeningDirective, HardeningDirectiveValue>,
        policy: &ServiceHardeningPolicy,
    ) -> HardeningScore {
        let name: String = service_name.into();
        let baseline = HardeningBaseline::from_profile(profile);
        let mut blocked_reasons: Vec<String> = Vec::new();
        let mut directive_results: Vec<DirectiveResult> = Vec::new();
        let mut total_score: i32 = 100;

        for directive in &policy.mandatory_directives {
            let weight = directive.default_weight();
            let observed = observed_directives.get(directive);
            let (satisfied, display_str) = match observed {
                Some(val) => (val.is_truthy(), val.to_display_string()),
                None => (false, "(not set)".to_string()),
            };

            if !satisfied {
                // Subtraction model: each missing mandatory directive reduces
                // the score by its weight.
                total_score = (total_score - weight as i32).max(0);
            }

            directive_results.push(DirectiveResult {
                directive: *directive,
                observed: display_str,
                satisfied,
                weight,
                deduction: if satisfied { 0 } else { weight },
            });
        }

        // ── Structural hard denies ────────────────────────────────────

        // DEV_FIXTURE is only permitted under DEV_RELAXED.
        if service_class == ServiceClass::DevFixture && !baseline.allows_dev_fixture() {
            blocked_reasons.push(format!(
                "DEV_FIXTURE class not permitted under {}; \
                 promotion blocked per INV-SEC-007",
                baseline.label(),
            ));
        }

        // SELinux confinement: AIOS-owned services MUST run in a confined
        // domain (forbid_unconfined_t). DEV_FIXTURE exempt under DEV_RELAXED.
        let is_dev_fixture_exempt =
            service_class == ServiceClass::DevFixture && baseline == HardeningBaseline::DevRelaxed;

        if !is_dev_fixture_exempt {
            let selinux_observed = observed_directives.get(&HardeningDirective::SELinuxConfinement);
            let selinux_confined = selinux_observed.map(|v| v.is_truthy()).unwrap_or(false);

            if !selinux_confined {
                blocked_reasons.push(
                    "SELinuxConfinement is not set; AIOS-owned services \
                     must not run in unconfined_t per INV-SEC-007"
                        .to_string(),
                );
            }
        }

        // ── Assemble score ────────────────────────────────────────────

        let final_score = u32::try_from(total_score.clamp(0, 100)).unwrap_or_default();
        let floor = policy.minimum_score;
        let numeric_pass = final_score >= floor;
        let has_structural_denies = !blocked_reasons.is_empty();

        let promotion_blocked = if has_structural_denies && baseline.blocks_on_structural_deny() {
            true
        } else if !numeric_pass && baseline.blocks_on_numeric_miss() {
            blocked_reasons.push(format!(
                "score {final_score} is below floor {floor} for class {} \
                 under profile {}",
                service_class.label(),
                profile.label(),
            ));
            true
        } else {
            false
        };

        HardeningScore {
            service_name: name,
            service_class,
            profile,
            total_score: final_score,
            directive_results,
            promotion_blocked,
            blocked_reasons,
        }
    }

    /// Whether the computed score admits the service for promotion.
    ///
    /// Returns `true` when `promotion_blocked` is `false`.
    #[must_use]
    pub fn admits_service(score: &HardeningScore) -> bool {
        !score.promotion_blocked
    }

    /// Produce a human-readable blocker report from the score.
    #[must_use]
    pub fn promotion_blocker_report(score: &HardeningScore) -> Vec<String> {
        if score.promotion_blocked {
            score.blocked_reasons.clone()
        } else {
            vec![]
        }
    }

    /// Derive the gate verdict (PASS / WARN / FAIL) for the score.
    #[must_use]
    pub fn gate_verdict(score: &HardeningScore, policy: &ServiceHardeningPolicy) -> GateVerdict {
        let baseline = HardeningBaseline::from_profile(score.profile);
        let numeric_pass = score.total_score >= policy.minimum_score;
        let has_structural_denies = !score.blocked_reasons.is_empty();

        if numeric_pass && !has_structural_denies {
            return GateVerdict::Pass;
        }

        if baseline == HardeningBaseline::DevRelaxed {
            GateVerdict::Warn
        } else if baseline == HardeningBaseline::SecureDefault {
            if has_structural_denies {
                GateVerdict::Fail
            } else {
                GateVerdict::Warn
            }
        } else {
            // STIG_ALIGNED or AIRGAP_HIGH
            GateVerdict::Fail
        }
    }

    /// Build an evidence record from the computed score.
    #[must_use]
    pub fn build_evidence(
        score: &HardeningScore,
        policy: &ServiceHardeningPolicy,
    ) -> ServiceHardeningScoredEvidence {
        let verdict = Self::gate_verdict(score, policy);

        let unsatisfied: Vec<String> = score
            .directive_results
            .iter()
            .filter(|r| !r.satisfied)
            .map(|r| r.directive.label().to_string())
            .collect();

        let rating = Self::rating_label(score.total_score);

        ServiceHardeningScoredEvidence {
            unit: score.service_name.clone(),
            service_class: score.service_class.label().to_string(),
            profile_id: score.profile.label().to_string(),
            exposure_score: score.total_score,
            overall_rating: rating.to_string(),
            floor_applied: policy.minimum_score,
            gate_verdict: match verdict {
                GateVerdict::Pass => "PASS".to_string(),
                GateVerdict::Warn => "WARN".to_string(),
                GateVerdict::Fail => "FAIL".to_string(),
            },
            unsatisfied_sub_checks: unsatisfied,
            structural_denies: score.blocked_reasons.clone(),
            measured_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Map a numeric score (0–100) to a rating label.
    #[must_use]
    fn rating_label(score: u32) -> &'static str {
        // Score is always clamped to [0, 100] by calculate_score.
        // The wildcard arm protects against future refactors.
        #[allow(clippy::match_same_arms)]
        match score {
            0..=20 => "DANGEROUS",
            21..=40 => "HIGH_EXPOSURE",
            41..=60 => "MEDIUM_EXPOSURE",
            61..=80 => "ACCEPTABLE",
            81..=100 | 101..=u32::MAX => "HARDENED",
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // HardeningDirective properties
    // -----------------------------------------------------------------------

    #[test]
    fn directive_count_is_19() {
        assert_eq!(HardeningDirective::count(), 19);
        assert_eq!(HardeningDirective::all().len(), 19);
    }

    #[test]
    fn every_directive_has_a_label() {
        for d in HardeningDirective::all() {
            let label = d.label();
            assert!(!label.is_empty(), "directive {d:?} has empty label");
        }
    }

    #[test]
    fn every_directive_has_a_nonzero_weight() {
        for d in HardeningDirective::all() {
            assert!(d.default_weight() > 0, "directive {d:?} has zero weight");
        }
    }

    #[test]
    fn directive_weights_sum_to_100() {
        let sum: u32 = HardeningDirective::all()
            .iter()
            .map(|d| d.default_weight())
            .sum();
        assert_eq!(sum, 100, "directive weights must sum to 100");
    }

    // -----------------------------------------------------------------------
    // ServiceClass
    // -----------------------------------------------------------------------

    #[test]
    fn service_class_count_is_9() {
        assert_eq!(ServiceClass::all().len(), 9);
    }

    #[test]
    fn service_class_labels_are_unique() {
        let mut labels: Vec<&str> = ServiceClass::all().iter().map(|c| c.label()).collect();
        let original_len = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(
            labels.len(),
            original_len,
            "service class labels must be unique"
        );
    }

    // -----------------------------------------------------------------------
    // HardeningBaseline
    // -----------------------------------------------------------------------

    #[test]
    fn baseline_is_monotonic_in_mandatory_directives() {
        let dev = HardeningBaseline::DevRelaxed.core_mandatory_directives();
        let sec = HardeningBaseline::SecureDefault.core_mandatory_directives();
        let stig = HardeningBaseline::StigAligned.core_mandatory_directives();
        let air = HardeningBaseline::AirgapHigh.core_mandatory_directives();

        assert!(
            dev.len() <= sec.len(),
            "DEV_RELAXED should have ≤ mandatory directives than SECURE_DEFAULT"
        );
        assert!(
            sec.len() <= stig.len(),
            "SECURE_DEFAULT should have ≤ mandatory directives than STIG_ALIGNED"
        );
        assert!(
            stig.len() <= air.len(),
            "STIG_ALIGNED should have ≤ mandatory directives than AIRGAP_HIGH"
        );
        assert_eq!(
            air.len(),
            19,
            "AIRGAP_HIGH should mandate all 19 directives"
        );
    }

    #[test]
    fn only_dev_relaxed_allows_dev_fixture() {
        assert!(HardeningBaseline::DevRelaxed.allows_dev_fixture());
        assert!(!HardeningBaseline::SecureDefault.allows_dev_fixture());
        assert!(!HardeningBaseline::StigAligned.allows_dev_fixture());
        assert!(!HardeningBaseline::AirgapHigh.allows_dev_fixture());
    }

    #[test]
    fn stig_and_airgap_block_on_numeric_miss() {
        assert!(!HardeningBaseline::DevRelaxed.blocks_on_numeric_miss());
        assert!(!HardeningBaseline::SecureDefault.blocks_on_numeric_miss());
        assert!(HardeningBaseline::StigAligned.blocks_on_numeric_miss());
        assert!(HardeningBaseline::AirgapHigh.blocks_on_numeric_miss());
    }

    // -----------------------------------------------------------------------
    // HardeningScoreCalculator — score computation
    // -----------------------------------------------------------------------

    fn all_present(
        directives: &[HardeningDirective],
    ) -> HashMap<HardeningDirective, HardeningDirectiveValue> {
        let mut map = HashMap::new();
        for d in directives {
            map.insert(*d, HardeningDirectiveValue::yes());
        }
        map
    }

    #[test]
    fn fully_hardened_constitutional_core_scores_100() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::ConstitutionalCore,
            SecurityProfile::AirgapHigh,
        )
        .expect("policy for CONSTITUTIONAL_CORE under AIRGAP_HIGH");

        let observed = all_present(&policy.mandatory_directives);

        let score = HardeningScoreCalculator::calculate_score(
            "aios-policy-kernel.service",
            ServiceClass::ConstitutionalCore,
            SecurityProfile::AirgapHigh,
            &observed,
            &policy,
        );

        assert_eq!(score.total_score, 100);
        assert!(!score.promotion_blocked);
        assert!(HardeningScoreCalculator::admits_service(&score));
    }

    #[test]
    fn missing_mandatory_directives_reduce_score() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::ConstitutionalCore,
            SecurityProfile::StigAligned,
        )
        .expect("policy for CONSTITUTIONAL_CORE under STIG_ALIGNED");

        // Only provide NoNewPrivileges — the rest are missing.
        let mut observed = HashMap::new();
        observed.insert(
            HardeningDirective::NoNewPrivileges,
            HardeningDirectiveValue::yes(),
        );
        // Also need SELinuxConfinement to avoid structural deny.
        observed.insert(
            HardeningDirective::SELinuxConfinement,
            HardeningDirectiveValue::yes(),
        );

        let score = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::ConstitutionalCore,
            SecurityProfile::StigAligned,
            &observed,
            &policy,
        );

        // Only NoNewPrivileges (7) + SELinuxConfinement (10) are present.
        // All other mandatory directives subtract their weights.
        // 19 mandatory directives total for STIG_ALIGNED.
        // We only have 2 present → 17 missing → total weight of all = 100
        // Present: 7 + 10 = 17. Score = 17.
        assert!(score.total_score < 100, "score should be reduced");
        assert_eq!(
            score.directive_results.len(),
            policy.mandatory_directives.len()
        );
    }

    #[test]
    fn dev_fixture_blocked_outside_dev_relaxed() {
        let profile = SecurityProfile::SecureDefault;
        let policy = ServiceHardeningPolicy::canonical(ServiceClass::DevFixture, profile);

        // DevFixture under anything except DEV_RELAXED returns None
        // because floor_for returns None.
        assert!(
            policy.is_none(),
            "DEV_FIXTURE must be None outside DEV_RELAXED"
        );
    }

    #[test]
    fn dev_fixture_allowed_under_dev_relaxed() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::DevFixture,
            SecurityProfile::DevRelaxed,
        )
        .expect("DEV_FIXTURE should be allowed under DEV_RELAXED");

        assert_eq!(policy.minimum_score, 20);
        assert_eq!(policy.mandatory_directives.len(), 1);
        assert_eq!(
            policy.mandatory_directives[0],
            HardeningDirective::NoNewPrivileges
        );
    }

    #[test]
    fn selinux_missing_triggers_structural_deny() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::ConstitutionalCore,
            SecurityProfile::StigAligned,
        )
        .expect("policy exists");

        // All directives present EXCEPT SELinuxConfinement.
        let mut observed = all_present(&policy.mandatory_directives);
        observed.remove(&HardeningDirective::SELinuxConfinement);

        let score = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::ConstitutionalCore,
            SecurityProfile::StigAligned,
            &observed,
            &policy,
        );

        assert!(score.promotion_blocked);
        assert!(
            score
                .blocked_reasons
                .iter()
                .any(|r| r.contains("unconfined_t")),
            "should block on missing SELinux confinement"
        );
    }

    #[test]
    fn gate_verdict_pass_when_score_exceeds_floor() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::ConstitutionalCore,
            SecurityProfile::StigAligned,
        )
        .expect("policy");

        let observed = all_present(&policy.mandatory_directives);
        let score = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::ConstitutionalCore,
            SecurityProfile::StigAligned,
            &observed,
            &policy,
        );

        let verdict = HardeningScoreCalculator::gate_verdict(&score, &policy);
        assert_eq!(verdict, GateVerdict::Pass);
    }

    #[test]
    fn gate_verdict_fail_when_score_below_floor_under_stig() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::Observability,
            SecurityProfile::StigAligned,
        )
        .expect("policy for OBSERVABILITY under STIG_ALIGNED");

        // Only provide half the mandatory directives.
        let half: Vec<HardeningDirective> = policy
            .mandatory_directives
            .iter()
            .take(policy.mandatory_directives.len() / 2)
            .copied()
            .collect();
        let observed = all_present(&half);

        let score = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::Observability,
            SecurityProfile::StigAligned,
            &observed,
            &policy,
        );

        let verdict = HardeningScoreCalculator::gate_verdict(&score, &policy);
        assert_eq!(verdict, GateVerdict::Fail);
    }

    #[test]
    fn gate_verdict_warn_under_dev_relaxed() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::ConstitutionalCore,
            SecurityProfile::DevRelaxed,
        )
        .expect("policy");

        // Provide only NoNewPrivileges. Missing MemoryDenyWriteExecute (7)
        // and SELinuxConfinement (10) → score 83, structural deny from
        // missing SELinux. Under DevRelaxed, structural denies warn.
        let mut observed = HashMap::new();
        observed.insert(
            HardeningDirective::NoNewPrivileges,
            HardeningDirectiveValue::yes(),
        );

        let score = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::ConstitutionalCore,
            SecurityProfile::DevRelaxed,
            &observed,
            &policy,
        );

        let verdict = HardeningScoreCalculator::gate_verdict(&score, &policy);
        assert_eq!(verdict, GateVerdict::Warn);
    }

    #[test]
    fn evidence_record_is_built_from_score() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::ConstitutionalCore,
            SecurityProfile::AirgapHigh,
        )
        .expect("policy");

        let observed = all_present(&policy.mandatory_directives);
        let score = HardeningScoreCalculator::calculate_score(
            "aios-policy-kernel.service",
            ServiceClass::ConstitutionalCore,
            SecurityProfile::AirgapHigh,
            &observed,
            &policy,
        );

        let evidence = HardeningScoreCalculator::build_evidence(&score, &policy);

        assert_eq!(evidence.unit, "aios-policy-kernel.service");
        assert_eq!(evidence.service_class, "CONSTITUTIONAL_CORE");
        assert_eq!(evidence.profile_id, "AIRGAP_HIGH");
        assert_eq!(evidence.gate_verdict, "PASS");
        assert_eq!(evidence.overall_rating, "HARDENED");
        assert_eq!(evidence.exposure_score, 100);
        assert!(!evidence.measured_at.is_empty());
    }

    // -----------------------------------------------------------------------
    // Score determinism
    // -----------------------------------------------------------------------

    #[test]
    fn score_is_deterministic() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::SecurityBroker,
            SecurityProfile::StigAligned,
        )
        .expect("policy");

        let observed = all_present(&policy.mandatory_directives);

        let s1 = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::SecurityBroker,
            SecurityProfile::StigAligned,
            &observed,
            &policy,
        );
        let s2 = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::SecurityBroker,
            SecurityProfile::StigAligned,
            &observed,
            &policy,
        );

        assert_eq!(s1.total_score, s2.total_score);
        assert_eq!(s1.promotion_blocked, s2.promotion_blocked);
        assert_eq!(s1.blocked_reasons, s2.blocked_reasons);
    }

    // -----------------------------------------------------------------------
    // Score rating bands
    // -----------------------------------------------------------------------

    #[test]
    fn score_rating_bands_match_spec() {
        // S16.7 §6 rating ladder mapped to 0–100 integer scale:
        // DANGEROUS       : 0-20
        // HIGH_EXPOSURE   : 21-40
        // MEDIUM_EXPOSURE : 41-60
        // ACCEPTABLE      : 61-80
        // HARDENED        : 81-100
        let test_cases = [
            (0, "DANGEROUS"),
            (10, "DANGEROUS"),
            (20, "DANGEROUS"),
            (21, "HIGH_EXPOSURE"),
            (35, "HIGH_EXPOSURE"),
            (40, "HIGH_EXPOSURE"),
            (41, "MEDIUM_EXPOSURE"),
            (55, "MEDIUM_EXPOSURE"),
            (60, "MEDIUM_EXPOSURE"),
            (61, "ACCEPTABLE"),
            (75, "ACCEPTABLE"),
            (80, "ACCEPTABLE"),
            (81, "HARDENED"),
            (95, "HARDENED"),
            (100, "HARDENED"),
        ];

        for (score, expected_rating) in &test_cases {
            let rating = HardeningScoreCalculator::rating_label(*score);
            assert_eq!(
                rating, *expected_rating,
                "score {score} should map to {expected_rating}, got {rating}",
            );
        }
    }

    // -----------------------------------------------------------------------
    // HardeningDirectiveValue
    // -----------------------------------------------------------------------

    #[test]
    fn directive_value_truthy() {
        assert!(HardeningDirectiveValue::yes().is_truthy());
        assert!(!HardeningDirectiveValue::no().is_truthy());
        assert!(HardeningDirectiveValue::PathList(vec!["/var".into()]).is_truthy());
        assert!(!HardeningDirectiveValue::PathList(vec![]).is_truthy());
        assert!(HardeningDirectiveValue::CapabilitySet(vec!["CAP_SYS_ADMIN".into()]).is_truthy());
        assert!(HardeningDirectiveValue::SyscallSet(vec!["@system-service".into()]).is_truthy());
    }

    // -----------------------------------------------------------------------
    // All policies exist for canonical (class, profile) combos
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_policies_exist_for_all_valid_combos() {
        let mut count = 0;
        for sc in ServiceClass::all() {
            for profile in &[
                SecurityProfile::DevRelaxed,
                SecurityProfile::SecureDefault,
                SecurityProfile::StigAligned,
                SecurityProfile::AirgapHigh,
            ] {
                let policy = ServiceHardeningPolicy::canonical(sc, *profile);
                if policy.is_some() {
                    count += 1;
                }
            }
        }
        // 8 non-DEV_FIXTURE classes × 4 profiles = 32
        // + 1 DEV_FIXTURE × 1 (DEV_RELAXED) = 1
        // Total = 33 policies
        assert_eq!(count, 33, "expected 33 valid canonical policies");
    }

    // -----------------------------------------------------------------------
    // DevFixture is rejected in all profiles except DEV_RELAXED
    // -----------------------------------------------------------------------

    #[test]
    fn dev_fixture_rejected_in_secure_default_and_above() {
        for profile in &[
            SecurityProfile::SecureDefault,
            SecurityProfile::StigAligned,
            SecurityProfile::AirgapHigh,
        ] {
            assert!(
                ServiceHardeningPolicy::canonical(ServiceClass::DevFixture, *profile).is_none(),
                "DEV_FIXTURE should be None under {profile:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Promotion blocker report
    // -----------------------------------------------------------------------

    #[test]
    fn promotion_blocker_report_empty_when_not_blocked() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::ConstitutionalCore,
            SecurityProfile::AirgapHigh,
        )
        .expect("policy");
        let observed = all_present(&policy.mandatory_directives);
        let score = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::ConstitutionalCore,
            SecurityProfile::AirgapHigh,
            &observed,
            &policy,
        );

        let report = HardeningScoreCalculator::promotion_blocker_report(&score);
        assert!(report.is_empty(), "report should be empty when not blocked");
    }

    #[test]
    fn promotion_blocker_report_populated_when_blocked() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::ConstitutionalCore,
            SecurityProfile::StigAligned,
        )
        .expect("policy");

        // No SELinux confinement — structural deny.
        let mut observed = all_present(&policy.mandatory_directives);
        observed.remove(&HardeningDirective::SELinuxConfinement);

        let score = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::ConstitutionalCore,
            SecurityProfile::StigAligned,
            &observed,
            &policy,
        );

        let report = HardeningScoreCalculator::promotion_blocker_report(&score);
        assert!(
            !report.is_empty(),
            "report should have entries when blocked"
        );
        assert!(report.iter().any(|r| r.contains("unconfined_t")));
    }

    // -----------------------------------------------------------------------
    // CLI-friendly admission check
    // -----------------------------------------------------------------------

    #[test]
    fn admits_service_returns_false_for_blocked() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::ConstitutionalCore,
            SecurityProfile::StigAligned,
        )
        .expect("policy");

        let mut observed = all_present(&policy.mandatory_directives);
        observed.remove(&HardeningDirective::SELinuxConfinement);

        let score = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::ConstitutionalCore,
            SecurityProfile::StigAligned,
            &observed,
            &policy,
        );

        assert!(!HardeningScoreCalculator::admits_service(&score));
    }

    #[test]
    fn admits_service_returns_true_when_clear() {
        let policy = ServiceHardeningPolicy::canonical(
            ServiceClass::ConstitutionalCore,
            SecurityProfile::AirgapHigh,
        )
        .expect("policy");

        let observed = all_present(&policy.mandatory_directives);
        let score = HardeningScoreCalculator::calculate_score(
            "test.service",
            ServiceClass::ConstitutionalCore,
            SecurityProfile::AirgapHigh,
            &observed,
            &policy,
        );

        assert!(HardeningScoreCalculator::admits_service(&score));
    }
}
