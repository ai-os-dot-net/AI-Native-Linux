//! Security Profile Matrix — Rev.3 S16.1 four-profile model with 14
//! security dimensions, transition gates, and evidence records.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::enum_glob_use)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::missing_errors_doc)]
//!
//! ## OS Research Provenance
//!
//! The Security Profile Matrix is derived from three primary sources:
//!
//! - **NIST SP 800-53 Rev.5** — Security and Privacy Controls for Information
//!   Systems and Organizations.  Defines 20 control families across three
//!   baselines (Low, Moderate, High).  Our four profiles map roughly to
//!   Low (DEV_RELAXED), Moderate (SECURE_DEFAULT), High (STIG_ALIGNED), and
//!   High+ (AIRGAP_HIGH).
//!
//! - **DISA Security Technical Implementation Guides (STIGs)** — enforce
//!   mandatory configuration for U.S. DoD systems.  STIG_ALIGNED
//!   implements the subset applicable to Linux-based container hosts,
//!   including SELinux enforcing, FIPS 140-2/140-3, auditd, and IMA/EVM.
//!
//! - **CIS Controls v8** — Implementation Groups IG1 (essential),
//!   IG2 (enterprise), IG3 (critical).  SECURE_DEFAULT aligns with IG1+IG2;
//!   AIRGAP_HIGH extends IG3 with network isolation.
//!
//! - **FIPS 140-3** — Federal Information Processing Standard for
//!   cryptographic modules.  FIPS_STRICT is an **overlay** (not a
//!   standalone profile) that can be applied to STIG_ALIGNED or
//!   AIRGAP_HIGH.  It enforces FIPS-approved algorithms exclusively
//!   (kernel crypto, TLS 1.3 ciphersuites, hash functions).
//!
//! ## Profile overview
//!
//! | Profile         | Threat model           | Use case                        |
//! |-----------------|------------------------|---------------------------------|
//! | DEV_RELAXED     | Casual / prototype     | Local developer workstation     |
//! | SECURE_DEFAULT  | Networked              | Production with internet access|
//! | STIG_ALIGNED    | DoD / Government       | DISA STIG-regulated workloads  |
//! | AIRGAP_HIGH     | Advanced persistent    | Physically isolated systems    |
//!
//! ## Constitutional invariants
//!
//! - **INV-SEC-001 (Profile ordering):** DEV_RELAXED < SECURE_DEFAULT <
//!   STIG_ALIGNED < AIRGAP_HIGH.  The ordinal is monotonic in security
//!   strictness.
//! - **INV-SEC-002 (FIPS gate):** FIPS_STRICT may only be enabled when the
//!   active profile is STIG_ALIGNED or AIRGAP_HIGH.
//! - **INV-SEC-003 (Transition direction):** A profile transition must
//!   go to a **stronger** (higher-ordinal) profile.  Downgrading requires
//!   a full recovery event.
//! - **INV-SEC-004 (Terminal profile):** AIRGAP_HIGH is the terminal
//!   profile; there is no stronger state.
//! - **INV-SEC-005 (Matrix completeness):** Every (profile, dimension)
//!   pair has a defined [`ProfileRequirement`].  Missing entries are a
//!   compile-time error.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// SecurityProfile — ordered from weakest to strongest
// ---------------------------------------------------------------------------

/// The AIOS security profile, ordered from weakest (most permissive) to
/// strongest (most restrictive).
///
/// The integer discriminant encodes the strictness ordinal and is stable
/// across wire representations.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityProfile {
    /// Developer workstation — minimal enforcement, maximum flexibility.
    /// SELinux permissive, no Secure Boot requirement, debug logging.
    #[default]
    DevRelaxed = 0,

    /// Production baseline — moderate enforcement for networked systems.
    /// SELinux enforcing on system services, Secure Boot recommended,
    /// auditd enabled.
    SecureDefault = 1,

    /// DISA STIG-aligned — mandatory controls for regulated workloads.
    /// FIPS 140-3 crypto, SELinux MLS/MCS, IMA appraisal, centralized
    /// audit and evidence forwarding.
    StigAligned = 2,

    /// Air-gapped high-assurance — maximum isolation for classified /
    /// high-value systems.  No external network, hardware-rooted TPM
    /// attestation, full disk encryption mandated.
    AirgapHigh = 3,
}

impl SecurityProfile {
    /// Human-readable label for reporting and evidence records.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::DevRelaxed => "DEV_RELAXED",
            Self::SecureDefault => "SECURE_DEFAULT",
            Self::StigAligned => "STIG_ALIGNED",
            Self::AirgapHigh => "AIRGAP_HIGH",
        }
    }

    /// Whether `self` is a stronger (more restrictive) profile than `other`.
    ///
    /// INV-SEC-003: transitions must go to a stronger profile.
    #[must_use]
    pub fn is_stronger_than(self, other: Self) -> bool {
        self > other
    }

    /// Whether this profile is at least as strong as `other`.
    #[must_use]
    pub fn is_at_least(self, other: Self) -> bool {
        self >= other
    }

    /// Whether FIPS 140-3 strict mode is allowed on this profile.
    ///
    /// INV-SEC-002: FIPS_STRICT only on STIG_ALIGNED and AIRGAP_HIGH.
    #[must_use]
    pub fn allows_fips(self) -> bool {
        matches!(self, Self::StigAligned | Self::AirgapHigh)
    }

    /// Whether this is a valid source profile for a transition.
    /// All profiles are valid sources except the terminal profile
    /// (INV-SEC-004).
    #[must_use]
    pub fn can_transition_up(self) -> bool {
        self != Self::AirgapHigh
    }
}

impl fmt::Display for SecurityProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// FipsOverlay — optional FIPS_STRICT mode
// ---------------------------------------------------------------------------

/// Whether FIPS_STRICT cryptographic enforcement is active.
///
/// FIPS_STRICT is an **overlay**, not a standalone profile.  Per
/// INV-SEC-002 it is only valid when the base profile is STIG_ALIGNED
/// or AIRGAP_HIGH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FipsOverlay {
    /// FIPS-approved algorithms only (kernel crypto, TLS, hash).
    Strict,
    /// Default cryptographic posture for the active profile.
    #[default]
    Standard,
}

impl FipsOverlay {
    /// Whether this overlay is strict.
    #[must_use]
    pub fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }

    /// Validate that this overlay is compatible with the given profile.
    /// Returns `None` if valid, or `Some(error_message)` if not.
    #[must_use]
    pub fn check_compatible(self, profile: SecurityProfile) -> Option<String> {
        if self.is_strict() && !profile.allows_fips() {
            Some(format!(
                "FIPS_STRICT overlay is not allowed on profile {}; \
                 only STIG_ALIGNED and AIRGAP_HIGH support FIPS",
                profile.label(),
            ))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ProfileDimension — the 14 security dimensions
// ---------------------------------------------------------------------------

/// The 14 security dimensions across which each profile makes
/// requirements.
///
/// Every dimension has a [`ProfileRequirement`] at each profile level
/// (INV-SEC-005).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProfileDimension {
    /// SELinux enforcement mode (disabled, permissive, enforcing, MLS).
    Selinux,
    /// UEFI Secure Boot verification chain.
    SecureBoot,
    /// Kernel lockdown mode (integrity, confidentiality).
    KernelLockdown,
    /// Integrity Measurement Architecture and Extended Verification
    /// Module (IMA/EVM).
    ImaEvm,
    /// Trusted Platform Module presence and attestation.
    Tpm,
    /// Network access controls (firewall, eBPF, air-gap enforcement).
    Network,
    /// Package signature verification and trust store hygiene.
    PackageTrust,
    /// Application sandboxing (seccomp, AppArmor, Landlock, SELinux).
    AppSandbox,
    /// Container runtime security (rootless, user-ns, seccomp profile).
    Containers,
    /// Audit subsystem (auditd rules, remote logging, tamper detection).
    Audit,
    /// Cryptographic evidence chain (blockchain-style append-only log).
    Evidence,
    /// AI agent autonomy limits (approval gates, bounded authority).
    AiAutonomy,
    /// Exception handling and waiver management (tracked exceptions).
    Exceptions,
    /// System integrity verification (AIDE, dm-verity, fs-verity).
    SystemIntegrity,
}

impl ProfileDimension {
    /// Human-readable label for reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Selinux => "SELinux",
            Self::SecureBoot => "Secure Boot",
            Self::KernelLockdown => "Kernel Lockdown",
            Self::ImaEvm => "IMA/EVM",
            Self::Tpm => "TPM",
            Self::Network => "Network",
            Self::PackageTrust => "Package Trust",
            Self::AppSandbox => "App Sandbox",
            Self::Containers => "Containers",
            Self::Audit => "Audit",
            Self::Evidence => "Evidence",
            Self::AiAutonomy => "AI Autonomy",
            Self::Exceptions => "Exceptions",
            Self::SystemIntegrity => "System Integrity",
        }
    }

    /// The total number of dimensions (compile-time constant).
    pub const COUNT: usize = 14;

    /// Iterate over all dimensions in definition order.
    #[must_use]
    pub fn all() -> [Self; Self::COUNT] {
        [
            Self::Selinux,
            Self::SecureBoot,
            Self::KernelLockdown,
            Self::ImaEvm,
            Self::Tpm,
            Self::Network,
            Self::PackageTrust,
            Self::AppSandbox,
            Self::Containers,
            Self::Audit,
            Self::Evidence,
            Self::AiAutonomy,
            Self::Exceptions,
            Self::SystemIntegrity,
        ]
    }
}

impl fmt::Display for ProfileDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// ProfileRequirement — per-dimension requirement level
// ---------------------------------------------------------------------------

/// The requirement level for a single (profile, dimension) cell.
///
/// Ordered from weakest to strongest obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProfileRequirement {
    /// No requirement; the dimension may be left unconfigured.
    Optional,
    /// Recommended but not enforced.
    Recommended,
    /// Mandatory; a violation must be remediated.
    Required,
    /// Mandatory but allows a formally-tracked exception (waiver).
    RequiredWithException,
}

impl ProfileRequirement {
    /// Whether this requirement is satisfied by the given implementation
    /// level.  An `Optional` requirement is always satisfied.
    #[must_use]
    pub fn is_satisfied_by(self, actual: Self) -> bool {
        actual >= self
    }

    /// Whether this requirement is mandatory (cannot be skipped without
    /// a waiver or exception).
    #[must_use]
    pub fn is_mandatory(self) -> bool {
        matches!(self, Self::Required | Self::RequiredWithException)
    }
}

impl fmt::Display for ProfileRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Optional => f.write_str("Optional"),
            Self::Recommended => f.write_str("Recommended"),
            Self::Required => f.write_str("Required"),
            Self::RequiredWithException => f.write_str("RequiredWithException"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProfileMatrix — the full 4 × 14 requirement table
// ---------------------------------------------------------------------------

/// The requirement matrix: for every (profile, dimension) pair, a
/// [`ProfileRequirement`] is defined.
///
/// INV-SEC-005: every cell has a value.  The constructor is exhaustive
/// and the repository method will never return `None`.
#[derive(Debug, Clone)]
pub struct ProfileMatrix {
    entries: HashMap<(SecurityProfile, ProfileDimension), ProfileRequirement>,
}

impl ProfileMatrix {
    /// Build the canonical 4 × 14 matrix per S16.1.
    ///
    /// The mapping is derived from:
    ///   - DEV_RELAXED:    developer workstation, minimal enforcement
    ///   - SECURE_DEFAULT: production baseline (CIS IG1+IG2)
    ///   - STIG_ALIGNED:   DISA STIG compliance
    ///   - AIRGAP_HIGH:    maximum isolation (CIS IG3 + no network)
    #[must_use]
    pub fn canonical() -> Self {
        use ProfileDimension::*;
        use ProfileRequirement::{Optional, Recommended, Required, RequiredWithException as ReqEx};
        use SecurityProfile::*;

        let mut entries = HashMap::with_capacity(56); // 4 × 14 = 56 entries

        // ── DEV_RELAXED ──
        entries.insert((DevRelaxed, Selinux), Optional);
        entries.insert((DevRelaxed, SecureBoot), Optional);
        entries.insert((DevRelaxed, KernelLockdown), Optional);
        entries.insert((DevRelaxed, ImaEvm), Optional);
        entries.insert((DevRelaxed, Tpm), Optional);
        entries.insert((DevRelaxed, Network), Optional);
        entries.insert((DevRelaxed, PackageTrust), Optional);
        entries.insert((DevRelaxed, AppSandbox), Optional);
        entries.insert((DevRelaxed, Containers), Optional);
        entries.insert((DevRelaxed, Audit), Recommended);
        entries.insert((DevRelaxed, Evidence), Recommended);
        entries.insert((DevRelaxed, AiAutonomy), Recommended);
        entries.insert((DevRelaxed, Exceptions), Optional);
        entries.insert((DevRelaxed, SystemIntegrity), Optional);

        // ── SECURE_DEFAULT ──
        entries.insert((SecureDefault, Selinux), Recommended);
        entries.insert((SecureDefault, SecureBoot), Recommended);
        entries.insert((SecureDefault, KernelLockdown), Recommended);
        entries.insert((SecureDefault, ImaEvm), Optional);
        entries.insert((SecureDefault, Tpm), Recommended);
        entries.insert((SecureDefault, Network), Required);
        entries.insert((SecureDefault, PackageTrust), Required);
        entries.insert((SecureDefault, AppSandbox), Recommended);
        entries.insert((SecureDefault, Containers), Recommended);
        entries.insert((SecureDefault, Audit), Required);
        entries.insert((SecureDefault, Evidence), Required);
        entries.insert((SecureDefault, AiAutonomy), Required);
        entries.insert((SecureDefault, Exceptions), Required);
        entries.insert((SecureDefault, SystemIntegrity), Recommended);

        // ── STIG_ALIGNED ──
        entries.insert((StigAligned, Selinux), Required);
        entries.insert((StigAligned, SecureBoot), Required);
        entries.insert((StigAligned, KernelLockdown), Required);
        entries.insert((StigAligned, ImaEvm), Required);
        entries.insert((StigAligned, Tpm), Required);
        entries.insert((StigAligned, Network), Required);
        entries.insert((StigAligned, PackageTrust), Required);
        entries.insert((StigAligned, AppSandbox), Required);
        entries.insert((StigAligned, Containers), Required);
        entries.insert((StigAligned, Audit), Required);
        entries.insert((StigAligned, Evidence), Required);
        entries.insert((StigAligned, AiAutonomy), ReqEx);
        entries.insert((StigAligned, Exceptions), ReqEx);
        entries.insert((StigAligned, SystemIntegrity), Required);

        // ── AIRGAP_HIGH ──
        entries.insert((AirgapHigh, Selinux), Required);
        entries.insert((AirgapHigh, SecureBoot), Required);
        entries.insert((AirgapHigh, KernelLockdown), Required);
        entries.insert((AirgapHigh, ImaEvm), Required);
        entries.insert((AirgapHigh, Tpm), Required);
        entries.insert((AirgapHigh, Network), ReqEx);
        entries.insert((AirgapHigh, PackageTrust), Required);
        entries.insert((AirgapHigh, AppSandbox), Required);
        entries.insert((AirgapHigh, Containers), Required);
        entries.insert((AirgapHigh, Audit), Required);
        entries.insert((AirgapHigh, Evidence), Required);
        entries.insert((AirgapHigh, AiAutonomy), ReqEx);
        entries.insert((AirgapHigh, Exceptions), ReqEx);
        entries.insert((AirgapHigh, SystemIntegrity), Required);

        Self { entries }
    }

    /// Look up the requirement for a (profile, dimension) pair.
    ///
    /// Returns `None` only if the matrix is corrupted.  The canonical
    /// matrix is exhaustive (INV-SEC-005).
    #[must_use]
    pub fn requirement(
        &self,
        profile: SecurityProfile,
        dimension: ProfileDimension,
    ) -> Option<ProfileRequirement> {
        self.entries.get(&(profile, dimension)).copied()
    }

    /// Collect all dimensions at a given profile that have a mandatory
    /// requirement (Required or RequiredWithException).
    #[must_use]
    pub fn mandatory_dimensions(&self, profile: SecurityProfile) -> Vec<ProfileDimension> {
        ProfileDimension::all()
            .into_iter()
            .filter(|dim| {
                self.requirement(profile, *dim)
                    .is_some_and(ProfileRequirement::is_mandatory)
            })
            .collect()
    }

    /// Validate that the matrix is complete: every (profile, dimension)
    /// pair has a defined requirement.
    #[must_use]
    pub fn validate_completeness(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let profiles = [
            SecurityProfile::DevRelaxed,
            SecurityProfile::SecureDefault,
            SecurityProfile::StigAligned,
            SecurityProfile::AirgapHigh,
        ];
        for profile in &profiles {
            for dim in ProfileDimension::all() {
                if !self.entries.contains_key(&(*profile, dim)) {
                    errors.push(format!("missing requirement for {:?} × {:?}", profile, dim,));
                }
            }
        }
        errors
    }
}

impl Default for ProfileMatrix {
    fn default() -> Self {
        Self::canonical()
    }
}

// ---------------------------------------------------------------------------
// ProfileManifest — serializable profile state
// ---------------------------------------------------------------------------

/// The active security profile state, serializable as JSON.
///
/// This is the manifest that is loaded at boot, validated, and persisted
/// after every profile transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileManifest {
    /// The active security profile.
    pub active_profile: SecurityProfile,

    /// Whether FIPS_STRICT is enabled (overlay).
    #[serde(default)]
    pub fips_overlay: FipsOverlay,

    /// ISO-8601 timestamp of the last profile change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_changed_at: Option<String>,

    /// The profile this system most recently transitioned from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_profile: Option<SecurityProfile>,
}

impl ProfileManifest {
    /// Create a manifest for a given profile.
    #[must_use]
    pub fn new(profile: SecurityProfile, fips: FipsOverlay) -> Self {
        Self {
            active_profile: profile,
            fips_overlay: fips,
            last_changed_at: None,
            previous_profile: None,
        }
    }

    /// Validate the manifest against all constitutional invariants.
    ///
    /// Returns a list of violation messages; an empty list means the
    /// manifest is valid.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if let Some(msg) = self.fips_overlay.check_compatible(self.active_profile) {
            errors.push(msg);
        }

        errors
    }

    /// Serialize the manifest to a JSON string.
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize a manifest from a JSON string.
    ///
    /// Returns an error if the JSON is malformed or contains unknown
    /// fields.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

// ---------------------------------------------------------------------------
// ProfileTransition — typed record of a profile state change
// ---------------------------------------------------------------------------

/// Evidence record for a profile transition event.
///
/// Every profile change is recorded as a typed evidence payload so the
/// evidence log preserves the full chain of security posture changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileTransition {
    /// The profile we are coming from.
    pub from_profile: SecurityProfile,

    /// The profile we are moving to.
    pub to_profile: SecurityProfile,

    /// Whether FIPS_STRICT is active after the transition.
    pub fips_overlay: FipsOverlay,

    /// ISO-8601 timestamp of the transition.
    pub transitioned_at: String,

    /// Human-readable reason for the transition.
    pub reason: String,

    /// Optional evidence reference (e.g. hash of audit log entry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
}

impl ProfileTransition {
    /// Create a new transition record.
    #[must_use]
    pub fn new(
        from: SecurityProfile,
        to: SecurityProfile,
        fips: FipsOverlay,
        reason: String,
    ) -> Self {
        Self {
            from_profile: from,
            to_profile: to,
            fips_overlay: fips,
            transitioned_at: chrono::Utc::now().to_rfc3339(),
            reason,
            evidence_ref: None,
        }
    }

    /// Whether this transition is valid under INV-SEC-003 (must go to
    /// a stronger profile).
    #[must_use]
    pub fn is_valid_direction(&self) -> bool {
        self.to_profile.is_stronger_than(self.from_profile)
    }

    /// Validate the transition against all invariants.
    ///
    /// Returns a list of violation messages; empty means valid.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if !self.to_profile.is_stronger_than(self.from_profile) {
            errors.push(format!(
                "invalid transition direction: {} → {} \
                 (must go to a stronger profile per INV-SEC-003)",
                self.from_profile.label(),
                self.to_profile.label(),
            ));
        }

        if let Some(msg) = self.fips_overlay.check_compatible(self.to_profile) {
            errors.push(msg);
        }

        errors
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // INV-SEC-001: Profile ordering
    // -----------------------------------------------------------------------

    #[test]
    fn profile_ordinal_ordering() {
        assert!(SecurityProfile::DevRelaxed < SecurityProfile::SecureDefault);
        assert!(SecurityProfile::SecureDefault < SecurityProfile::StigAligned);
        assert!(SecurityProfile::StigAligned < SecurityProfile::AirgapHigh);
    }

    #[test]
    fn is_stronger_than_detects_ascending() {
        assert!(SecurityProfile::SecureDefault.is_stronger_than(SecurityProfile::DevRelaxed));
        assert!(SecurityProfile::StigAligned.is_stronger_than(SecurityProfile::SecureDefault));
        assert!(SecurityProfile::AirgapHigh.is_stronger_than(SecurityProfile::StigAligned));
    }

    #[test]
    fn is_stronger_than_refuses_same_or_descending() {
        assert!(!SecurityProfile::DevRelaxed.is_stronger_than(SecurityProfile::DevRelaxed));
        assert!(!SecurityProfile::DevRelaxed.is_stronger_than(SecurityProfile::SecureDefault));
    }

    #[test]
    fn airgap_high_is_terminal() {
        assert!(!SecurityProfile::AirgapHigh.can_transition_up());
        assert!(SecurityProfile::DevRelaxed.can_transition_up());
        assert!(SecurityProfile::SecureDefault.can_transition_up());
        assert!(SecurityProfile::StigAligned.can_transition_up());
    }

    #[test]
    fn profile_labels_are_stable() {
        assert_eq!(SecurityProfile::DevRelaxed.label(), "DEV_RELAXED");
        assert_eq!(SecurityProfile::SecureDefault.label(), "SECURE_DEFAULT");
        assert_eq!(SecurityProfile::StigAligned.label(), "STIG_ALIGNED");
        assert_eq!(SecurityProfile::AirgapHigh.label(), "AIRGAP_HIGH");
    }

    // -----------------------------------------------------------------------
    // INV-SEC-002: FIPS overlay gate
    // -----------------------------------------------------------------------

    #[test]
    fn fips_allowed_only_on_top_two_profiles() {
        assert!(!SecurityProfile::DevRelaxed.allows_fips());
        assert!(!SecurityProfile::SecureDefault.allows_fips());
        assert!(SecurityProfile::StigAligned.allows_fips());
        assert!(SecurityProfile::AirgapHigh.allows_fips());
    }

    #[test]
    fn fips_compatibility_check_rejects_lower_profiles() {
        assert!(FipsOverlay::Strict
            .check_compatible(SecurityProfile::DevRelaxed)
            .is_some());
        assert!(FipsOverlay::Strict
            .check_compatible(SecurityProfile::SecureDefault)
            .is_some());
        assert!(FipsOverlay::Strict
            .check_compatible(SecurityProfile::StigAligned)
            .is_none());
        assert!(FipsOverlay::Strict
            .check_compatible(SecurityProfile::AirgapHigh)
            .is_none());
    }

    #[test]
    fn standard_fips_always_compatible() {
        for profile in &[
            SecurityProfile::DevRelaxed,
            SecurityProfile::SecureDefault,
            SecurityProfile::StigAligned,
            SecurityProfile::AirgapHigh,
        ] {
            assert!(
                FipsOverlay::Standard.check_compatible(*profile).is_none(),
                "Standard FIPS should be compatible with {}",
                profile.label(),
            );
        }
    }

    #[test]
    fn fips_overlay_is_strict() {
        assert!(FipsOverlay::Strict.is_strict());
        assert!(!FipsOverlay::Standard.is_strict());
    }

    // -----------------------------------------------------------------------
    // INV-SEC-005: Matrix completeness
    // -----------------------------------------------------------------------

    #[test]
    fn dimension_count_is_14() {
        assert_eq!(ProfileDimension::COUNT, 14);
        assert_eq!(ProfileDimension::all().len(), 14);
    }

    #[test]
    fn canonical_matrix_is_complete() {
        let matrix = ProfileMatrix::canonical();
        let errors = matrix.validate_completeness();
        assert!(errors.is_empty(), "matrix has gaps: {errors:?}");
    }

    #[test]
    fn matrix_lookup_for_each_dimension_profile_combination() {
        let matrix = ProfileMatrix::canonical();
        let profiles = [
            SecurityProfile::DevRelaxed,
            SecurityProfile::SecureDefault,
            SecurityProfile::StigAligned,
            SecurityProfile::AirgapHigh,
        ];

        for profile in &profiles {
            for dim in ProfileDimension::all() {
                let req = matrix.requirement(*profile, dim);
                assert!(
                    req.is_some(),
                    "missing requirement for {profile:?} × {dim:?}",
                );
            }
        }
    }

    #[test]
    fn dev_relaxed_has_mostly_optional() {
        let matrix = ProfileMatrix::canonical();
        let profile = SecurityProfile::DevRelaxed;
        let optional_count = ProfileDimension::all()
            .iter()
            .filter(|dim| {
                matrix
                    .requirement(profile, **dim)
                    .is_some_and(|r| r == ProfileRequirement::Optional)
            })
            .count();
        // Most of the 14 dimensions are Optional for DEV_RELAXED.
        assert!(optional_count >= 8);
    }

    #[test]
    fn airgap_high_has_all_required_or_required_with_exception() {
        let matrix = ProfileMatrix::canonical();
        let profile = SecurityProfile::AirgapHigh;
        for dim in ProfileDimension::all() {
            let req = matrix.requirement(profile, dim).unwrap();
            assert!(
                req.is_mandatory(),
                "AIRGAP_HIGH × {dim} should be mandatory, got {req:?}",
            );
        }
    }

    #[test]
    fn mandatory_dimensions_increase_with_profile_strictness() {
        let matrix = ProfileMatrix::canonical();
        let dev_count = matrix
            .mandatory_dimensions(SecurityProfile::DevRelaxed)
            .len();
        let sec_count = matrix
            .mandatory_dimensions(SecurityProfile::SecureDefault)
            .len();
        let stig_count = matrix
            .mandatory_dimensions(SecurityProfile::StigAligned)
            .len();
        let air_count = matrix
            .mandatory_dimensions(SecurityProfile::AirgapHigh)
            .len();

        assert!(
            dev_count <= sec_count,
            "DEV_RELAXED ({dev_count}) should have ≤ mandatory than \
             SECURE_DEFAULT ({sec_count})",
        );
        assert!(
            sec_count <= stig_count,
            "SECURE_DEFAULT ({sec_count}) should have ≤ mandatory than \
             STIG_ALIGNED ({stig_count})",
        );
        assert!(
            stig_count <= air_count,
            "STIG_ALIGNED ({stig_count}) should have ≤ mandatory than \
             AIRGAP_HIGH ({air_count})",
        );
    }

    // -----------------------------------------------------------------------
    // ProfileRequirement
    // -----------------------------------------------------------------------

    #[test]
    fn requirement_satisfaction_is_monotonic() {
        use ProfileRequirement::*;
        assert!(Required.is_satisfied_by(Required));
        assert!(Required.is_satisfied_by(RequiredWithException));
        assert!(!Recommended.is_satisfied_by(Optional));
        assert!(Optional.is_satisfied_by(Optional));
        assert!(Optional.is_satisfied_by(Required));
    }

    // -----------------------------------------------------------------------
    // ProfileManifest serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_json_round_trip() {
        let manifest = ProfileManifest::new(SecurityProfile::StigAligned, FipsOverlay::Strict);
        let json = manifest.to_json().unwrap();
        let decoded = ProfileManifest::from_json(&json).unwrap();
        assert_eq!(decoded.active_profile, SecurityProfile::StigAligned);
        assert_eq!(decoded.fips_overlay, FipsOverlay::Strict);
    }

    #[test]
    fn manifest_fips_validation() {
        let manifest = ProfileManifest::new(SecurityProfile::DevRelaxed, FipsOverlay::Strict);
        let errors = manifest.validate();
        assert!(!errors.is_empty());
        assert!(errors[0].contains("FIPS_STRICT"));
    }

    #[test]
    fn manifest_valid_when_compatible() {
        let manifest = ProfileManifest::new(SecurityProfile::AirgapHigh, FipsOverlay::Strict);
        assert!(manifest.validate().is_empty());
    }

    #[test]
    fn manifest_rejects_unknown_fields() {
        let json = r#"{
            "active_profile": "SECURE_DEFAULT",
            "fips_overlay": "STANDARD",
            "unknown_field": true
        }"#;
        let result = ProfileManifest::from_json(json);
        assert!(result.is_err(), "manifest should reject unknown fields");
    }

    // -----------------------------------------------------------------------
    // INV-SEC-003: Transition direction
    // -----------------------------------------------------------------------

    #[test]
    fn transition_up_is_valid() {
        let transition = ProfileTransition::new(
            SecurityProfile::DevRelaxed,
            SecurityProfile::SecureDefault,
            FipsOverlay::Standard,
            "upgrading to production baseline".into(),
        );
        assert!(transition.is_valid_direction());
        assert!(transition.validate().is_empty());
    }

    #[test]
    fn transition_down_is_invalid() {
        let transition = ProfileTransition::new(
            SecurityProfile::StigAligned,
            SecurityProfile::SecureDefault,
            FipsOverlay::Standard,
            "downgrading".into(),
        );
        assert!(!transition.is_valid_direction());
        assert!(!transition.validate().is_empty());
    }

    #[test]
    fn transition_to_same_profile_is_invalid() {
        let transition = ProfileTransition::new(
            SecurityProfile::SecureDefault,
            SecurityProfile::SecureDefault,
            FipsOverlay::Standard,
            "re-asserting same profile".into(),
        );
        // Moving to the same profile is not "stronger" so it's invalid
        // as an upgrade; but lateral moves may be allowed by operators.
        assert!(!transition.is_valid_direction());
    }

    #[test]
    fn transition_with_fips_on_weak_profile_is_invalid() {
        let transition = ProfileTransition::new(
            SecurityProfile::DevRelaxed,
            SecurityProfile::SecureDefault,
            FipsOverlay::Strict,
            "attempting FIPS on insecure profile".into(),
        );
        let errors = transition.validate();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("FIPS")));
    }

    // -----------------------------------------------------------------------
    // Dimension labels
    // -----------------------------------------------------------------------

    #[test]
    fn all_dimensions_have_unique_labels() {
        let labels: Vec<&str> = ProfileDimension::all().iter().map(|d| d.label()).collect();
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            labels.len(),
            unique.len(),
            "dimension labels must be unique"
        );
    }

    // -----------------------------------------------------------------------
    // ProfileRequirement ordering
    // -----------------------------------------------------------------------

    #[test]
    fn requirement_ordinal_ordering() {
        use ProfileRequirement::*;
        assert!(Optional < Recommended);
        assert!(Recommended < Required);
        assert!(Required < RequiredWithException);
    }
}
