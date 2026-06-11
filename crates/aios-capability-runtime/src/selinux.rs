#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_const_for_fn,
    clippy::too_long_first_doc_paragraph,
    reason = "lints that conflict with OS-RESEARCH module prose conventions"
)]
//! SELinux MAC Policy Plane — mandatory access control backend for
//! STIG_ALIGNED and AIRGAP_HIGH profiles (S16.2).
//!
//! ## OS Research Provenance
//!
//! NSA's Security-Enhanced Linux (SELinux), first publicly released in 2000,
//! introduced **Mandatory Access Control (MAC)** into the Linux kernel via
//! the Linux Security Modules (LSM) framework. Its design draws on the
//! **Flask** security architecture (Spencer et al., 1999), which separates
//! *security policy logic* from *enforcement* through a well-defined
//! interface between the security server and the object manager.
//!
//! Key architectural decisions inherited from Flask:
//!
//! 1. **Type Enforcement (TE)** — every subject (process) and object (file,
//!    socket, etc.) is assigned a *type*. Access is granted solely through
//!    explicit `allow` rules between source and target types.
//! 2. **Role-Based Access Control (RBAC)** — users are mapped to roles;
//!    roles are authorized for a set of types, constraining which domains a
//!    user can enter.
//! 3. **Multi-Level Security (MLS) / Multi-Category Security (MCS)** — every
//!    subject and object has a sensitivity *level* and a *category* set.
//!    Access requires both the TE rule to pass AND the MLS constraints
//!    (`dominates` / `equals`) to hold.
//! 4. **AVC (Access Vector Cache)** — the kernel caches access decisions
//!    in a hash table. Denials are logged as `avc: denied` messages;
//!    every denial is an auditable security event.
//!
//! ### Mapping to AIOS Capsule Architecture
//!
//! | SELinux / Flask concept    | AIOS equivalent                          |
//! |----------------------------|------------------------------------------|
//! | Domain (`*_t`)              | [`SeLinuxDomain`] — per-capsule domain   |
//! | Security context (quad)    | [`SeLinuxContext`]                        |
//! | `allow` rule               | [`SeLinuxRule`]                           |
//! | MLS/MCS sensitivity level  | [`SeLinuxContext::level`]                 |
//! | MLS/MCS category set       | [`SeLinuxContext::categories`]            |
//! | AVC denial                 | [`AvcDenial`] — typed evidence record     |
//! | Policy module / bundle     | [`SePolicyBundle`]                        |
//! | `setenforce` / `getenforce` | [`SePolicyValidator`]                    |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-SEL-001 (Domain naming):** Every capsule domain must follow the
//!   pattern `aios_capsule_N_t` where N is the capsule's numeric id.
//! - **INV-SEL-002 (No unconfined):** No AIOS service or capsule may run as
//!   `unconfined_t`. Any rule that references `unconfined_t` in any field
//!   is rejected at validation time.
//! - **INV-SEL-003 (Least privilege):** Every rule must list explicit
//!   permissions; wildcard / blanket `*` allow rules are rejected.
//! - **INV-SEL-004 (Context validity):** Every [`SeLinuxContext`] must
//!   contain non-empty `user`, `role`, `type`, and a well-formed `level`
//!   (sensitivity `s0`..`s15` plus optional category list `c0..c1023`).
//! - **INV-SEL-005 (AVC audit integrity):** Every denial captured in an
//!   [`AvcDenial`] must carry a non-zero timestamp, non-empty source/target
//!   domain references, and a non-empty permission set.

use std::fmt;

use super::capsule_namespace::CapsuleId;

// ---------------------------------------------------------------------------
// SeLinuxDomain — per-capsule domain name
// ---------------------------------------------------------------------------

/// A per-capsule SELinux domain name.
///
/// Every AIOS capsule gets its own SELinux type, following the naming
/// convention `aios_capsule_N_t`. This type is the primary subject label
/// for all processes running within that capsule.
///
/// # Examples
///
/// ```rust
/// # use aios_capability_runtime::capsule_namespace::CapsuleId;
/// # use aios_capability_runtime::selinux::SeLinuxDomain;
/// let domain = SeLinuxDomain::from_capsule_id(CapsuleId(7));
/// assert_eq!(domain.as_str(), "aios_capsule_7_t");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeLinuxDomain {
    /// The canonical domain name (e.g. `"aios_capsule_7_t"`).
    name: String,
    /// MLS sensitivity level (e.g. `"s0"`). `None` if MLS is not configured.
    pub mls_level: Option<String>,
    /// MCS category set for isolation (e.g. `[0, 1, 5]`).
    pub mcs_categories: Vec<u16>,
    /// Domain names this capsule is authorized to transition into.
    pub allowed_transitions: Vec<String>,
    /// SELinux booleans enabled for this domain.
    pub allowed_booleans: Vec<String>,
    /// File context patterns applicable to this domain.
    pub allowed_file_contexts: Vec<String>,
}

impl SeLinuxDomain {
    /// Construct a domain from a pre-validated string with all secondary
    /// fields set to defaults.
    ///
    /// Returns `None` if the string does not match the `aios_capsule_N_t`
    /// pattern.
    #[must_use]
    pub fn new(raw: &str) -> Option<Self> {
        if !raw.starts_with("aios_capsule_") || !raw.ends_with("_t") {
            return None;
        }
        let body = &raw["aios_capsule_".len()..raw.len() - 2]; // strip suffix _t
        if body.is_empty() {
            return None;
        }
        for ch in body.chars() {
            if !ch.is_ascii_digit() {
                return None;
            }
        }
        Some(Self {
            name: raw.into(),
            mls_level: None,
            mcs_categories: Vec::new(),
            allowed_transitions: Vec::new(),
            allowed_booleans: Vec::new(),
            allowed_file_contexts: Vec::new(),
        })
    }

    /// Construct a domain from a [`CapsuleId`].
    #[must_use]
    pub fn from_capsule_id(id: CapsuleId) -> Self {
        Self {
            name: format!("aios_capsule_{}_t", id.raw()),
            mls_level: None,
            mcs_categories: Vec::new(),
            allowed_transitions: Vec::new(),
            allowed_booleans: Vec::new(),
            allowed_file_contexts: Vec::new(),
        }
    }

    /// The canonical domain string (e.g. `"aios_capsule_7_t"`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Extract the numeric capsule id from the domain name.
    #[must_use]
    pub fn capsule_id(&self) -> Option<u64> {
        let body = &self.name["aios_capsule_".len()..self.name.len() - 2];
        body.parse::<u64>().ok()
    }

    /// Set the MLS sensitivity level for this domain.
    #[must_use]
    pub fn with_mls_level(mut self, level: &str) -> Self {
        self.mls_level = Some(level.into());
        self
    }

    /// Set the MCS categories for this domain.
    #[must_use]
    pub fn with_mcs_categories(mut self, categories: Vec<u16>) -> Self {
        self.mcs_categories = categories;
        self
    }

    /// Add an allowed domain transition target.
    pub fn add_transition(mut self, domain: &str) -> Self {
        self.allowed_transitions.push(domain.into());
        self
    }

    /// Add an allowed SELinux boolean for this domain.
    pub fn add_boolean(mut self, boolean: &str) -> Self {
        self.allowed_booleans.push(boolean.into());
        self
    }

    /// Add an allowed file context pattern for this domain.
    pub fn add_file_context(mut self, ctx: &str) -> Self {
        self.allowed_file_contexts.push(ctx.into());
        self
    }

    /// Returns `true` if MLS is configured on this domain.
    #[must_use]
    pub fn has_mls(&self) -> bool {
        self.mls_level.is_some()
    }

    /// Number of configured transitions.
    #[must_use]
    pub fn transition_count(&self) -> usize {
        self.allowed_transitions.len()
    }
}

impl fmt::Display for SeLinuxDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Canonical domain for a typed file object used by all AIOS capsules.
pub const AIOS_DATA_DOMAIN: &str = "aios_data_t";
/// Canonical domain for the AIOS system orchestrator process.
pub const AIOS_SYSTEM_DOMAIN: &str = "aios_system_t";

// ---------------------------------------------------------------------------
// SeLinuxContext — user:role:type:level security quad
// ---------------------------------------------------------------------------

/// A full SELinux security context: `user:role:type:level`.
///
/// The fields directly correspond to the SELinux security attribute quad:
///
/// - `user` — SELinux user (e.g. `system_u`)
/// - `role` — SELinux role (e.g. `object_r`)
/// - `type_` — the domain / type (e.g. `aios_data_t`)
/// - `level` — MLS/MCS sensitivity + categories (e.g. `s0`, `s0:c0,c1`)
///
/// # Examples
///
/// ```rust
/// # use aios_capability_runtime::selinux::SeLinuxContext;
/// let ctx = SeLinuxContext {
///     user: "system_u".into(),
///     role: "object_r".into(),
///     type_: "aios_data_t".into(),
///     level: "s0".into(),
/// };
/// assert_eq!(ctx.to_string(), "system_u:object_r:aios_data_t:s0");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SeLinuxContext {
    /// SELinux user identity (e.g. `system_u`, `staff_u`).
    pub user: String,
    /// SELinux role (e.g. `object_r`, `system_r`).
    pub role: String,
    /// SELinux type / domain (e.g. `aios_capsule_7_t`).
    pub type_: String,
    /// MLS/MCS level: sensitivity plus optional categories
    /// (e.g. `s0`, `s1:c0,c2`).
    pub level: String,
}

impl SeLinuxContext {
    /// Create a context from individual components, returning `None` if any
    /// component is empty or the level is malformed.
    #[must_use]
    pub fn new(user: &str, role: &str, type_: &str, level: &str) -> Option<Self> {
        if user.is_empty() || role.is_empty() || type_.is_empty() || level.is_empty() {
            return None;
        }
        if !Self::is_valid_level(level) {
            return None;
        }
        Some(Self {
            user: user.into(),
            role: role.into(),
            type_: type_.into(),
            level: level.into(),
        })
    }

    /// Create a context for a capsule domain.
    #[must_use]
    pub fn for_capsule(domain: &SeLinuxDomain, sensitivity: &str, categories: &[u16]) -> Self {
        let cats: Vec<String> = categories.iter().map(|c| format!("c{c}")).collect();
        let level = if cats.is_empty() {
            sensitivity.to_string()
        } else {
            format!("{}:{}", sensitivity, cats.join(","))
        };
        Self {
            user: "system_u".into(),
            role: "system_r".into(),
            type_: domain.as_str().into(),
            level,
        }
    }

    /// Create a file context for an object accessible by a specific capsule.
    #[must_use]
    pub fn for_file(domain: &SeLinuxDomain) -> Self {
        Self {
            user: "system_u".into(),
            role: "object_r".into(),
            type_: domain.as_str().into(),
            level: "s0".into(),
        }
    }

    /// Validate the MLS/MCS level string.
    ///
    /// Acceptable forms:
    /// - `sN` where N is 0..15 (sensitivity)
    /// - `sN:cA,cB,...` where each category is `c0`..`c1023`
    #[must_use]
    pub fn is_valid_level(level: &str) -> bool {
        let (sens_part, cats_part) = match level.split_once(':') {
            Some((s, rest)) => (s, Some(rest)),
            None => (level, None),
        };

        // Sensitivity must be s0..s15.
        if !sens_part.starts_with('s') {
            return false;
        }
        if sens_part[1..].parse::<u8>().map_or(true, |n| n > 15) {
            return false;
        }

        // Optional categories: c0..c1023, comma-separated.
        if let Some(cats) = cats_part {
            if cats.is_empty() {
                return false;
            }
            for cat in cats.split(',') {
                if !cat.starts_with('c') {
                    return false;
                }
                if cat[1..].parse::<u16>().map_or(true, |n| n > 1023) {
                    return false;
                }
            }
        }

        true
    }
}

impl fmt::Display for SeLinuxContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.user, self.role, self.type_, self.level
        )
    }
}

// ---------------------------------------------------------------------------
// SeLinuxPermission — allowed operations
// ---------------------------------------------------------------------------

/// Individual operation a capsule may be authorized to perform on a target.
///
/// The permission set mirrors the standard SELinux object-class permission
/// vocabulary, scoped to the AIOS capsule interaction model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SeLinuxPermission {
    /// Read data from the target.
    Read,
    /// Write / modify data on the target.
    Write,
    /// Execute / invoke the target (for executable files or capsule entrypoints).
    Execute,
    /// Append data (write without overwrite).
    Append,
    /// Create new resources within the target context.
    Create,
    /// Delete resources within the target context.
    Delete,
    /// Open the target (e.g., file descriptor, socket).
    Open,
    /// Transition into the target domain (domain transition).
    Transition,
    /// Get or set attributes on the target.
    GetAttr,
    /// Set attributes on the target.
    SetAttr,
}

impl SeLinuxPermission {
    /// Human-readable wire-form name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Append => "append",
            Self::Create => "create",
            Self::Delete => "delete",
            Self::Open => "open",
            Self::Transition => "transition",
            Self::GetAttr => "getattr",
            Self::SetAttr => "setattr",
        }
    }

    /// All available permissions, for policy-bundle composition.
    #[must_use]
    pub const fn all() -> [Self; 10] {
        [
            Self::Read,
            Self::Write,
            Self::Execute,
            Self::Append,
            Self::Create,
            Self::Delete,
            Self::Open,
            Self::Transition,
            Self::GetAttr,
            Self::SetAttr,
        ]
    }
}

impl fmt::Display for SeLinuxPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SeLinuxRule — a single allow rule
// ---------------------------------------------------------------------------

/// A single SELinux `allow` rule: *source domain* is permitted *permissions*
/// on *target domain*.
///
/// # Examples
///
/// ```rust
/// # use aios_capability_runtime::selinux::{SeLinuxRule, SeLinuxPermission};
/// let rule = SeLinuxRule::new(
///     "aios_capsule_7_t",
///     "aios_data_t",
///     &[SeLinuxPermission::Read, SeLinuxPermission::Open],
/// );
/// assert!(rule.is_some());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeLinuxRule {
    /// The source domain (subject) requesting access.
    pub source_domain: String,
    /// The target domain (object / resource).
    pub target_domain: String,
    /// The set of permissions granted.
    pub permissions: Vec<SeLinuxPermission>,
    /// Optional human-readable justification for the rule.
    pub justification: Option<String>,
}

impl SeLinuxRule {
    /// Create a new rule.
    ///
    /// Returns `None` if the source or target domain is empty, or the
    /// permission set is empty.
    #[must_use]
    pub fn new(
        source: &str,
        target: &str,
        permissions: &[SeLinuxPermission],
    ) -> Option<Self> {
        if source.is_empty() || target.is_empty() || permissions.is_empty() {
            return None;
        }
        Some(Self {
            source_domain: source.into(),
            target_domain: target.into(),
            permissions: permissions.to_vec(),
            justification: None,
        })
    }

    /// Create a new rule with a justification annotation.
    #[must_use]
    pub fn with_justification(
        source: &str,
        target: &str,
        permissions: &[SeLinuxPermission],
        justification: &str,
    ) -> Option<Self> {
        Self::new(source, target, permissions).map(|mut r| {
            r.justification = Some(justification.into());
            r
        })
    }

    /// Whether the rule references `unconfined_t` in any field.
    #[must_use]
    pub fn references_unconfined(&self) -> bool {
        self.source_domain == "unconfined_t" || self.target_domain == "unconfined_t"
    }

    /// Number of permissions granted by this rule.
    #[must_use]
    pub const fn permission_count(&self) -> usize {
        self.permissions.len()
    }
}

// ---------------------------------------------------------------------------
// SePolicyBundle — policy rules for a single capsule
// ---------------------------------------------------------------------------

/// A collection of SELinux rules and domain definitions for a capsule.
///
/// Each capsule that requires inter-capsule interaction gets a
/// [`SePolicyBundle`] that declares:
/// - Its own domain name.
/// - The set of `allow` rules authorizing operations on other domains.
/// - The set of domain transitions (entrypoints) for capsule-to-capsule
///   interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SePolicyBundle {
    /// The capsule this policy bundle belongs to.
    pub capsule_id: CapsuleId,
    /// The capsule's own SELinux domain.
    pub domain: SeLinuxDomain,
    /// MCS/MLS sensitivity label for this capsule.
    pub sensitivity: String,
    /// MCS category set for this capsule.
    pub categories: Vec<u16>,
    /// Set of `allow` rules.
    pub rules: Vec<SeLinuxRule>,
    /// Domain transition entrypoints — target domains this capsule is
    /// authorized to transition into.
    pub transitions: Vec<SeLinuxDomain>,
    /// Unique bundle identifier (e.g. `"aios.selinux.core"`).
    pub bundle_id: Option<String>,
    /// File context definitions in this bundle.
    pub file_contexts: Vec<String>,
    /// SELinux booleans defined in this bundle.
    pub booleans: Vec<String>,
    /// Network port definitions in this bundle.
    pub ports: Vec<String>,
    /// Policy module version string (e.g. `"2026.05.rev3"`).
    pub version: Option<String>,
    /// Cryptographic signature over the policy bundle content.
    pub signature: Option<String>,
}

impl SePolicyBundle {
    /// Generate a policy bundle for a capsule with the given rules.
    #[must_use]
    pub fn generate_for_capsule(
        capsule_id: CapsuleId,
        sensitivity: &str,
        categories: Vec<u16>,
        rules: Vec<SeLinuxRule>,
        transitions: Vec<SeLinuxDomain>,
    ) -> Self {
        let domain = SeLinuxDomain::from_capsule_id(capsule_id);
        Self {
            capsule_id,
            domain,
            sensitivity: sensitivity.into(),
            categories,
            rules,
            transitions,
            bundle_id: None,
            file_contexts: Vec::new(),
            booleans: Vec::new(),
            ports: Vec::new(),
            version: None,
            signature: None,
        }
    }

    /// Total number of rules in the bundle.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Total number of individual permissions across all rules.
    #[must_use]
    pub fn total_permissions(&self) -> usize {
        self.rules.iter().map(SeLinuxRule::permission_count).sum()
    }

    /// Whether any rule references `unconfined_t`.
    #[must_use]
    pub fn contains_unconfined(&self) -> bool {
        self.rules.iter().any(SeLinuxRule::references_unconfined)
    }

    /// The full SELinux context for this capsule.
    #[must_use]
    pub fn context(&self) -> SeLinuxContext {
        SeLinuxContext::for_capsule(&self.domain, &self.sensitivity, &self.categories)
    }

    /// Set the bundle identifier.
    #[must_use]
    pub fn with_bundle_id(mut self, id: &str) -> Self {
        self.bundle_id = Some(id.into());
        self
    }

    /// Set the policy version string.
    #[must_use]
    pub fn with_version(mut self, ver: &str) -> Self {
        self.version = Some(ver.into());
        self
    }

    /// Add a file context definition.
    pub fn add_file_context(mut self, ctx: &str) -> Self {
        self.file_contexts.push(ctx.into());
        self
    }

    /// Add a boolean definition.
    pub fn add_boolean(mut self, b: &str) -> Self {
        self.booleans.push(b.into());
        self
    }

    /// Add a port definition.
    pub fn add_port(mut self, port: &str) -> Self {
        self.ports.push(port.into());
        self
    }

    /// Attach a cryptographic signature.
    #[must_use]
    pub fn with_signature(mut self, sig: &str) -> Self {
        self.signature = Some(sig.into());
        self
    }

    /// Returns `true` if the bundle has a signature attached.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Number of file contexts defined in this bundle.
    #[must_use]
    pub fn file_context_count(&self) -> usize {
        self.file_contexts.len()
    }
}

// ---------------------------------------------------------------------------
// AvcDenial — typed AVC denial evidence record
// ---------------------------------------------------------------------------

/// A typed evidence record capturing a single SELinux AVC denial.
///
/// Every denial is an auditable security event. The record carries enough
/// forensic detail to reconstruct the access attempt, the SELinux context
/// in effect at the time, and the exact permission that was blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvcDenial {
    /// Unix epoch timestamp of the denial event (seconds since 1970-01-01).
    pub timestamp_secs: u64,
    /// The SELinux context of the subject that attempted the access.
    pub source_context: SeLinuxContext,
    /// The SELinux context of the target object.
    pub target_context: SeLinuxContext,
    /// The specific permission(s) that were denied.
    pub denied_permissions: Vec<SeLinuxPermission>,
    /// The SELinux enforcement result — always `"denied"` for an AVC denial.
    pub result: String,
    /// The `comm` field (process name) from the denial message.
    pub comm: String,
    /// Executable path of the process that triggered the denial.
    pub exe_path: Option<String>,
    /// SELinux policy name in effect at the time.
    pub policy_name: String,
}

impl AvcDenial {
    /// Create a new AVC denial record.
    ///
    /// Returns `None` if permissions are empty, timestamp is zero, or any
    /// context field is empty.
    #[must_use]
    pub fn new(
        timestamp_secs: u64,
        source_context: SeLinuxContext,
        target_context: SeLinuxContext,
        denied_permissions: Vec<SeLinuxPermission>,
        comm: &str,
        exe_path: Option<String>,
        policy_name: &str,
    ) -> Option<Self> {
        if timestamp_secs == 0
            || denied_permissions.is_empty()
            || comm.is_empty()
            || policy_name.is_empty()
        {
            return None;
        }
        Some(Self {
            timestamp_secs,
            source_context,
            target_context,
            denied_permissions,
            result: "denied".into(),
            comm: comm.into(),
            exe_path,
            policy_name: policy_name.into(),
        })
    }

    /// Format the denial as a human-readable summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        let perms: Vec<&str> = self
            .denied_permissions
            .iter()
            .map(SeLinuxPermission::as_str)
            .collect();
        format!(
            "AVC denied [{}] {} -> {} : {{{}}}",
            self.comm,
            self.source_context,
            self.target_context,
            perms.join(" ")
        )
    }

    /// Whether this denial involves the `unconfined_t` type.
    #[must_use]
    pub fn involves_unconfined(&self) -> bool {
        self.source_context.type_ == "unconfined_t"
            || self.target_context.type_ == "unconfined_t"
    }
}

// ---------------------------------------------------------------------------
// SePolicyValidator — policy bundle validation
// ---------------------------------------------------------------------------

/// Validates [`SePolicyBundle`] instances against AIOS constitutional
/// invariants.
///
/// The validator checks:
/// - No rule references `unconfined_t` (INV-SEL-002).
/// - Every rule has explicit, non-empty permissions (INV-SEL-003).
/// - Rule source/target domains are non-empty.
/// - At least one rule is present (a policy bundle with zero rules is
///   effectively `unconfined` by omission).
#[derive(Debug, Default, Clone)]
pub struct SePolicyValidator;

/// Errors collected by the validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// The bundle contains no rules.
    EmptyRuleset,
    /// A rule references `unconfined_t`.
    UnconfinedReference(String),
    /// A rule has an empty source or target domain.
    MissingDomain(String),
    /// A rule has no permissions.
    EmptyPermissions(String),
    /// The bundle references a non-AIOS domain name.
    ForeignDomain(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRuleset => write!(f, "policy bundle has no rules"),
            Self::UnconfinedReference(msg) => write!(f, "unconfined_t reference: {msg}"),
            Self::MissingDomain(msg) => write!(f, "empty domain: {msg}"),
            Self::EmptyPermissions(msg) => write!(f, "empty permissions: {msg}"),
            Self::ForeignDomain(msg) => write!(f, "foreign domain: {msg}"),
        }
    }
}

impl SePolicyValidator {
    /// Create a new validator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validate a policy bundle against AIOS invariants.
    ///
    /// Returns `Ok(())` if the bundle passes all checks, or `Err(Vec<String>)`
    /// with a human-readable description of each violation.
    pub fn validate(bundle: &SePolicyBundle) -> Result<(), Vec<String>> {
        let mut errors: Vec<String> = Vec::new();

        if bundle.rule_count() == 0 {
            errors.push(ValidationError::EmptyRuleset.to_string());
            return Err(errors);
        }

        for (i, rule) in bundle.rules.iter().enumerate() {
            if rule.references_unconfined() {
                errors.push(
                    ValidationError::UnconfinedReference(format!(
                        "rule[{i}] references unconfined_t (INV-SEL-002)"
                    ))
                    .to_string(),
                );
            }

            if rule.source_domain.is_empty() || rule.target_domain.is_empty() {
                errors.push(
                    ValidationError::MissingDomain(format!(
                        "rule[{i}] has empty source or target domain"
                    ))
                    .to_string(),
                );
            }

            if rule.permissions.is_empty() {
                errors.push(
                    ValidationError::EmptyPermissions(format!(
                        "rule[{i}] has no permissions (INV-SEL-003)"
                    ))
                    .to_string(),
                );
            }

            // INV-SEL-003: reject blanket wildcard patterns.
            // We don't have a literal `*` in the permission enum, but a rule
            // with all 10 permissions without justification is suspicious.
            if rule.permission_count() == SeLinuxPermission::all().len()
                && rule.justification.is_none()
            {
                errors.push(format!(
                    "rule[{}] grants all {} permissions without justification (INV-SEL-003 least privilege)",
                    i,
                    SeLinuxPermission::all().len(),
                ));
            }

            // Check that source/target match AIOS domain patterns.
            for (field, domain_str) in &[
                ("source", &rule.source_domain),
                ("target", &rule.target_domain),
            ] {
                if !domain_str.starts_with("aios_") && *domain_str != "self" {
                    // Non-AIOS domains are allowed for interop (e.g. kernel_t,
                    // init_t) but flagged for review.
                    errors.push(format!(
                        "rule[{i}] {field}_domain '{domain_str}' does not follow aios_* naming convention"
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ===========================================================================
// Rev.8 — SELinux MAC Policy Engine
// ===========================================================================
//
// New types added per S16.2:
// - MacPolicyLifecycle: draft → compiled → loaded → enforcing lifecycle.
// - MacPolicyCompiler: compiles, validates, loads, enforces policy bundles.
// - AvcDecision: computed access decision (Allowed/Denied/Audited).
// - AvcAuditEngine: captures denials, tracks rate, enforces alert thresholds.
// - McsLabel: Multi-Category Security label for capsule isolation.
// - MlsLabel: Multi-Level Security label for cross-domain flows.
// - SelinuxPolicyGate: profile ↔ MAC policy requirement bridge.
// - SelinuEvidenceEvent: typed evidence for policy lifecycle events.

use chrono::{DateTime, Utc};
use strum_macros::{EnumCount, EnumIter};

use super::security_profile::SecurityProfile;

// ---------------------------------------------------------------------------
// MacPolicyLifecycle — policy state machine
// ---------------------------------------------------------------------------

/// The lifecycle states of a SELinux MAC policy bundle.
///
/// Transitions follow the compile→validate→load→enforce chain.
/// `Permissive` is a valid runtime state for debugging; `Expired` and
/// `Revoked` are terminal states for policy abandonment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, EnumCount)]
pub enum MacPolicyLifecycle {
    /// Policy source exists but has not been compiled.
    Draft,
    /// Policy has been compiled but not yet validated.
    Compiled,
    /// Policy has passed validation and been loaded into the kernel.
    Loaded,
    /// Policy is loaded and in enforcing mode.
    Enforcing,
    /// Policy is loaded but in permissive mode (logs only, no enforcement).
    Permissive,
    /// Policy enforcement is disabled.
    Disabled,
    /// Policy has exceeded its validity window.
    Expired,
    /// Policy has been explicitly revoked.
    Revoked,
}

impl MacPolicyLifecycle {
    /// Human-readable label for evidence records.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::Compiled => "COMPILED",
            Self::Loaded => "LOADED",
            Self::Enforcing => "ENFORCING",
            Self::Permissive => "PERMISSIVE",
            Self::Disabled => "DISABLED",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
        }
    }

    /// Whether this state represents an active (loaded) policy.
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Loaded | Self::Enforcing | Self::Permissive)
    }

    /// Whether this state is a terminal (non-transitionable) state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Expired | Self::Revoked)
    }

    /// Whether this is an enforcing state.
    #[must_use]
    pub fn is_enforcing(self) -> bool {
        matches!(self, Self::Enforcing)
    }

    /// Valid forward transitions from this state.
    #[must_use]
    pub fn allowed_next(self) -> Vec<Self> {
        match self {
            Self::Draft => vec![Self::Compiled],
            Self::Compiled => vec![Self::Loaded],
            Self::Loaded => vec![Self::Enforcing, Self::Permissive],
            Self::Enforcing => vec![Self::Permissive, Self::Disabled],
            Self::Permissive => vec![Self::Enforcing, Self::Disabled],
            Self::Disabled => vec![Self::Loaded],
            Self::Expired | Self::Revoked => vec![],
        }
    }
}

impl fmt::Display for MacPolicyLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// MacPolicyCompiler — policy compilation & enforcement engine
// ---------------------------------------------------------------------------

/// Compiles, validates, loads, and enforces a [`SePolicyBundle`].
///
/// The compiler drives the [`MacPolicyLifecycle`] state machine and produces
/// evidence at each transition boundary.
pub struct MacPolicyCompiler {
    /// Current lifecycle state.
    pub state: MacPolicyLifecycle,
    /// The policy bundle being managed.
    pub bundle: SePolicyBundle,
    /// Accumulated validation errors, if any.
    pub validation_errors: Vec<String>,
    /// The compiled CIL output, if available.
    pub compiled_output: Option<String>,
    /// Timestamp of the last load operation.
    pub loaded_at: Option<DateTime<Utc>>,
    /// Timestamp of the last enforcement operation.
    pub enforced_at: Option<DateTime<Utc>>,
}

impl MacPolicyCompiler {
    /// Create a new compiler for a policy bundle, starting in `Draft`.
    #[must_use]
    pub fn new(bundle: SePolicyBundle) -> Self {
        Self {
            state: MacPolicyLifecycle::Draft,
            bundle,
            validation_errors: Vec::new(),
            compiled_output: None,
            loaded_at: None,
            enforced_at: None,
        }
    }

    /// Compile the policy bundle into CIL format.
    ///
    /// Transitions `Draft → Compiled`. Returns an error if the current state
    /// does not permit compilation.
    ///
    /// # Errors
    ///
    /// Returns `Err(message)` if already beyond `Draft` or if the bundle
    /// has no rules.
    pub fn compile_policy(&mut self) -> Result<(), String> {
        if self.state != MacPolicyLifecycle::Draft {
            return Err(format!(
                "cannot compile from state {}; expected Draft",
                self.state.label()
            ));
        }

        if self.bundle.rule_count() == 0 {
            return Err("cannot compile policy with zero rules".into());
        }

        // Reject bundles referencing unconfined_t at compile time.
        if self.bundle.contains_unconfined() {
            return Err(
                "policy bundle references unconfined_t; rejected at compile time (INV-SEL-002)"
                    .into(),
            );
        }

        // Synthesize CIL output from the rule set.
        let cil = Self::synthesize_cil(&self.bundle);
        self.compiled_output = Some(cil);
        self.state = MacPolicyLifecycle::Compiled;
        Ok(())
    }

    /// Validate the compiled policy against AIOS invariants.
    ///
    /// Updates `validation_errors` with any violations found. Does not
    /// change the lifecycle state.
    ///
    /// Returns `Ok(())` if validation passes, `Err(Vec<String>)` with
    /// a list of violations otherwise.
    pub fn validate_policy(&mut self) -> Result<(), Vec<String>> {
        let mut errors: Vec<String> = Vec::new();

        if let Some(ref cil) = self.compiled_output {
            if cil.is_empty() {
                errors.push("compiled CIL output is empty".into());
            }

            if !cil.contains("(type") {
                errors.push("compiled CIL output contains no type declarations".into());
            }

            if !cil.contains("(allow") {
                errors.push(
                    "compiled CIL output contains no allow rules (INV-SEL-003)".into(),
                );
            }

            if cil.contains("unconfined_t") {
                errors.push("compiled CIL output references unconfined_t (INV-SEL-002)".into());
            }
        } else {
            errors.push("no compiled output available; run compile_policy() first".into());
        }

        // Validate the bundle through SePolicyValidator as well.
        if let Err(bundle_errs) = SePolicyValidator::validate(&self.bundle) {
            errors.extend(bundle_errs);
        }

        // Validate file context consistency.
        for ctx in &self.bundle.file_contexts {
            if ctx.is_empty() {
                errors.push("empty file context definition".into());
            }
        }

        // Validate booleans are non-empty.
        for b in &self.bundle.booleans {
            if b.is_empty() {
                errors.push("empty boolean name in bundle".into());
            }
        }

        self.validation_errors = errors.clone();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Load the policy into the SELinux subsystem.
    ///
    /// Transitions `Compiled → Loaded`. Requires `compile_policy()` to have
    /// succeeded first.
    ///
    /// # Errors
    ///
    /// Returns `Err(message)` if the current state does not permit loading.
    pub fn load_policy(&mut self) -> Result<(), String> {
        if self.state != MacPolicyLifecycle::Compiled {
            return Err(format!(
                "cannot load from state {}; expected Compiled",
                self.state.label()
            ));
        }

        if self.compiled_output.is_none() {
            return Err(
                "no compiled output available; run compile_policy() before load_policy()".into(),
            );
        }

        // Verify signature is present if the bundle declares one.
        if self.bundle.signature.is_some() && self.bundle.signature.as_deref() == Some("") {
            return Err("policy bundle signature is empty".into());
        }

        self.state = MacPolicyLifecycle::Loaded;
        self.loaded_at = Some(Utc::now());
        Ok(())
    }

    /// Transition the policy to enforcing mode.
    ///
    /// Transitions `Loaded → Enforcing`.
    ///
    /// # Errors
    ///
    /// Returns `Err(message)` if the current state does not permit
    /// enforcement or if validation has not passed.
    pub fn enforce_policy(&mut self) -> Result<(), String> {
        if self.state != MacPolicyLifecycle::Loaded {
            return Err(format!(
                "cannot enforce from state {}; expected Loaded",
                self.state.label()
            ));
        }

        if !self.validation_errors.is_empty() {
            return Err(format!(
                "cannot enforce policy with {} validation errors",
                self.validation_errors.len()
            ));
        }

        self.state = MacPolicyLifecycle::Enforcing;
        self.enforced_at = Some(Utc::now());
        Ok(())
    }

    /// Set the policy to permissive mode (log-only, no enforcement).
    ///
    /// Transitions `Enforcing → Permissive` or `Loaded → Permissive`.
    ///
    /// # Errors
    ///
    /// Returns `Err(message)` if the current state does not permit
    /// permissive mode.
    pub fn set_permissive(&mut self) -> Result<(), String> {
        match self.state {
            MacPolicyLifecycle::Enforcing | MacPolicyLifecycle::Loaded => {
                self.state = MacPolicyLifecycle::Permissive;
                Ok(())
            }
            other => Err(format!(
                "cannot set permissive from state {}; expected Enforcing or Loaded",
                other.label()
            )),
        }
    }

    /// Check whether the policy enforces STIG-level requirements.
    #[must_use]
    pub fn meets_stig_requirements(&self) -> bool {
        self.state == MacPolicyLifecycle::Enforcing
            && !self.bundle.contains_unconfined()
            && self.bundle.rule_count() > 0
    }

    /// Synthesize CIL (Common Intermediate Language) output from a bundle.
    fn synthesize_cil(bundle: &SePolicyBundle) -> String {
        let mut cil = String::new();

        // Header.
        cil.push_str(";; AIOS-generated SELinux CIL policy\n");
        if let Some(ref id) = bundle.bundle_id {
            cil.push_str(&format!(";; bundle_id: {id}\n"));
        }
        if let Some(ref ver) = bundle.version {
            cil.push_str(&format!(";; version: {ver}\n"));
        }

        // Domain type declaration.
        cil.push_str(&format!(
            "(type {})\n",
            bundle.domain.as_str()
        ));

        // File context declarations.
        for ctx in &bundle.file_contexts {
            cil.push_str(&format!("(filecon \"{}\" any (system_u object_r {} (s0)))\n", ctx, bundle.domain.as_str()));
        }

        // Boolean declarations.
        for b in &bundle.booleans {
            cil.push_str(&format!("(boolean {} true)\n", b));
        }

        // Port declarations.
        for p in &bundle.ports {
            cil.push_str(&format!("(portcon {} tcp (system_u object_r {} (s0)))\n", p, bundle.domain.as_str()));
        }

        // Allow rules.
        for rule in &bundle.rules {
            for perm in &rule.permissions {
                cil.push_str(&format!(
                    "(allow {} {} ({} ({})))\n",
                    rule.source_domain,
                    rule.target_domain,
                    Self::cil_object_class(&rule.target_domain),
                    perm.as_str(),
                ));
            }
        }

        // Domain transitions.
        for transition in &bundle.transitions {
            cil.push_str(&format!(
                "(typetransition {} {} process {})\n",
                bundle.domain.as_str(),
                transition.as_str(),
                transition.as_str(),
            ));
        }

        cil
    }

    /// Map a domain name to a CIL object class.
    fn cil_object_class(domain: &str) -> &'static str {
        if domain.contains("file") || domain.contains("data") || domain.contains("exec") {
            "file"
        } else if domain.contains("sock") {
            "sock_file"
        } else if domain.contains("port") {
            "tcp_socket"
        } else {
            "process"
        }
    }
}

// ---------------------------------------------------------------------------
// AvcDecision — computed access control decision
// ---------------------------------------------------------------------------

/// The result of an access vector computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, EnumCount)]
pub enum AvcDecisionKind {
    /// Access is explicitly allowed by policy.
    Allowed,
    /// Access is explicitly denied by policy.
    Denied,
    /// Access is allowed but audited for compliance.
    Audited,
}

impl AvcDecisionKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Audited => "audited",
        }
    }
}

impl fmt::Display for AvcDecisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A single access vector cache decision record.
///
/// Represents the kernel's decision on whether a subject (source domain)
/// may perform an operation (permission) on an object (target domain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvcDecision {
    /// The source domain (subject) requesting access.
    pub source_domain: String,
    /// The target domain (object) being accessed.
    pub target_domain: String,
    /// The SELinux object class (e.g. `"file"`, `"process"`, `"tcp_socket"`).
    pub object_class: String,
    /// The specific permission being evaluated.
    pub permission: String,
    /// The computed decision.
    pub decision: AvcDecisionKind,
}

impl AvcDecision {
    /// Create a new AVC decision record.
    ///
    /// Returns `None` if any field is empty.
    #[must_use]
    pub fn new(
        source_domain: &str,
        target_domain: &str,
        object_class: &str,
        permission: &str,
        decision: AvcDecisionKind,
    ) -> Option<Self> {
        if source_domain.is_empty()
            || target_domain.is_empty()
            || object_class.is_empty()
            || permission.is_empty()
        {
            return None;
        }
        Some(Self {
            source_domain: source_domain.into(),
            target_domain: target_domain.into(),
            object_class: object_class.into(),
            permission: permission.into(),
            decision,
        })
    }

    /// Whether this decision is a denial.
    #[must_use]
    pub fn is_denial(&self) -> bool {
        self.decision == AvcDecisionKind::Denied
    }

    /// Format the decision as a human-readable line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "AVC {} {} {}:{} : {}",
            self.decision,
            self.source_domain,
            self.target_domain,
            self.object_class,
            self.permission,
        )
    }
}

// ---------------------------------------------------------------------------
// AvcAuditEngine — AVC denial capture, rate tracking & alerting
// ---------------------------------------------------------------------------

/// Captures AVC denials, computes denial rates, and enforces alert
/// thresholds for security monitoring.
#[derive(Debug, Clone)]
pub struct AvcAuditEngine {
    /// Collected AVC denial records.
    denials: Vec<AvcDenial>,
    /// Start of the current rate window.
    pub window_start: DateTime<Utc>,
    /// Maximum denials per window before alerting.
    pub alert_threshold: usize,
}

impl AvcAuditEngine {
    /// Create a new audit engine with the given alert threshold.
    #[must_use]
    pub fn new(alert_threshold: usize) -> Self {
        Self {
            denials: Vec::new(),
            window_start: Utc::now(),
            alert_threshold,
        }
    }

    /// Capture an AVC denial event.
    ///
    /// Returns the total number of denials captured in the current window.
    pub fn capture_avc_denial(&mut self, denial: AvcDenial) -> usize {
        self.denials.push(denial);
        self.denials.len()
    }

    /// The denial rate: number of denials per second since the window
    /// started, or `0.0` if the window has just started.
    #[must_use]
    pub fn avc_denial_rate(&self) -> f64 {
        let elapsed_secs = (Utc::now() - self.window_start)
            .num_seconds()
            .max(1) as f64;
        self.denials.len() as f64 / elapsed_secs
    }

    /// Number of denials captured in the current window.
    #[must_use]
    pub fn denial_count(&self) -> usize {
        self.denials.len()
    }

    /// Whether the alert threshold has been exceeded.
    #[must_use]
    pub fn is_alert_threshold_exceeded(&self) -> bool {
        self.denials.len() > self.alert_threshold
    }

    /// Reset the rate window and clear accumulated denials.
    pub fn reset_window(&mut self) {
        self.denials.clear();
        self.window_start = Utc::now();
    }

    /// Retrieve all captured denials.
    #[must_use]
    pub fn denials(&self) -> &[AvcDenial] {
        &self.denials
    }

    /// Count denial events involving a specific source domain.
    #[must_use]
    pub fn count_by_source_domain(&self, domain: &str) -> usize {
        self.denials
            .iter()
            .filter(|d| d.source_context.type_ == domain)
            .count()
    }

    /// Set a new alert threshold.
    pub fn set_alert_threshold(&mut self, threshold: usize) {
        self.alert_threshold = threshold;
    }

    /// Get the current alert threshold.
    #[must_use]
    pub fn avc_denial_alert_threshold(&self) -> usize {
        self.alert_threshold
    }
}

// ---------------------------------------------------------------------------
// McsLabel — Multi-Category Security label (capsule isolation)
// ---------------------------------------------------------------------------

/// A Multi-Category Security (MCS) label, binding a sensitivity level
/// to a set of categories for capsule-level isolation.
///
/// MCS is the dominant scheme for NG-SELinux container/capsule isolation:
/// each capsule gets its own category set, and cross-capsule interaction
/// requires category overlap (explicitly granted).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct McsLabel {
    /// Sensitivity level (`s0`..`s15`).
    pub sensitivity_level: u8,
    /// MCS category set (`c0`..`c1023`).
    pub categories: Vec<u16>,
}

impl McsLabel {
    /// Create a new MCS label.
    ///
    /// Returns `None` if the sensitivity level exceeds 15 or any category
    /// exceeds 1023.
    #[must_use]
    pub fn new(sensitivity_level: u8, categories: Vec<u16>) -> Option<Self> {
        if sensitivity_level > 15 {
            return None;
        }
        for &cat in &categories {
            if cat > 1023 {
                return None;
            }
        }
        Some(Self {
            sensitivity_level,
            categories,
        })
    }

    /// Format the label as a SELinux level string (e.g. `"s0:c0,c1"`).
    #[must_use]
    pub fn to_level_string(&self) -> String {
        if self.categories.is_empty() {
            format!("s{}", self.sensitivity_level)
        } else {
            let cats: Vec<String> = self.categories.iter().map(|c| format!("c{c}")).collect();
            format!("s{}:{}", self.sensitivity_level, cats.join(","))
        }
    }

    /// Whether this label's categories overlap with another label's categories.
    ///
    /// MCS requires category overlap for cross-capsule interaction.
    #[must_use]
    pub fn categories_overlap(&self, other: &Self) -> bool {
        self.categories.iter().any(|c| other.categories.contains(c))
    }

    /// Whether this label dominates another label (all of other's categories
    /// are present in self's categories, and sensitivity >= other's).
    #[must_use]
    pub fn dominates(&self, other: &Self) -> bool {
        self.sensitivity_level >= other.sensitivity_level
            && other
                .categories
                .iter()
                .all(|c| self.categories.contains(c))
    }

    /// Number of categories in this label.
    #[must_use]
    pub fn category_count(&self) -> usize {
        self.categories.len()
    }
}

impl fmt::Display for McsLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_level_string())
    }
}

// ---------------------------------------------------------------------------
// MlsLabel — Multi-Level Security label (cross-domain flows)
// ---------------------------------------------------------------------------

/// A Multi-Level Security (MLS) label with clearance and current operating
/// level, used for cross-domain information flow control.
///
/// MLS adds hierarchical sensitivity beyond MCS categories. A subject
/// with clearance `s5` operating at `s3` can read `s0..s3` ("read down")
/// and write `s3..s5` ("write up") — the classic Bell-LaPadula model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlsLabel {
    /// Maximum sensitivity the subject is cleared for.
    pub clearance: u8,
    /// Current operating sensitivity level.
    pub current_level: u8,
}

impl MlsLabel {
    /// Create a new MLS label.
    ///
    /// Returns `None` if clearance or level exceeds 15, or if `current_level`
    /// exceeds `clearance`.
    #[must_use]
    pub fn new(clearance: u8, current_level: u8) -> Option<Self> {
        if clearance > 15 || current_level > 15 {
            return None;
        }
        if current_level > clearance {
            return None;
        }
        Some(Self {
            clearance,
            current_level,
        })
    }

    /// Whether this subject is allowed to read an object at `object_level`
    /// (Bell-LaPadula "no read up" — subject must dominate object).
    #[must_use]
    pub fn can_read(&self, object_level: u8) -> bool {
        self.current_level >= object_level
    }

    /// Whether this subject is allowed to write to an object at `object_level`
    /// (Bell-LaPadula "no write down" — object must dominate subject).
    #[must_use]
    pub fn can_write(&self, object_level: u8) -> bool {
        object_level >= self.current_level && object_level <= self.clearance
    }

    /// Format the label as a range string (e.g. `"s3-s5"`).
    #[must_use]
    pub fn to_range_string(&self) -> String {
        if self.current_level == self.clearance {
            format!("s{}", self.current_level)
        } else {
            format!("s{}-s{}", self.current_level, self.clearance)
        }
    }
}

impl fmt::Display for MlsLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_range_string())
    }
}

// ---------------------------------------------------------------------------
// SelinuxPolicyGate — security profile ↔ MAC policy bridge
// ---------------------------------------------------------------------------

/// The MAC policy requirement derived from a [`SecurityProfile`].
///
/// Each profile maps to a specific SELinux enforcement posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacPolicyRequirement {
    /// SELinux enforcement is not required.
    None,
    /// SELinux should be permissive (log-only).
    Permissive,
    /// SELinux must be enforcing on system domains.
    Enforcing,
    /// SELinux must be enforcing with full MLS/MCS isolation.
    EnforcingMls,
}

impl MacPolicyRequirement {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Permissive => "PERMISSIVE",
            Self::Enforcing => "ENFORCING",
            Self::EnforcingMls => "ENFORCING_MLS",
        }
    }
}

impl fmt::Display for MacPolicyRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Bridges [`SecurityProfile`] to SELinux MAC policy requirements.
///
/// `SelinuxPolicyGate` answers: given an active security profile, what MAC
/// policy posture is required, and is the current SELinux state compliant?
pub struct SelinuxPolicyGate;

impl SelinuxPolicyGate {
    /// Map a security profile to its required MAC policy posture.
    #[must_use]
    pub fn required_mac_profile(profile: SecurityProfile) -> MacPolicyRequirement {
        match profile {
            SecurityProfile::DevRelaxed => MacPolicyRequirement::None,
            SecurityProfile::SecureDefault => MacPolicyRequirement::Permissive,
            SecurityProfile::StigAligned => MacPolicyRequirement::Enforcing,
            SecurityProfile::AirgapHigh => MacPolicyRequirement::EnforcingMls,
        }
    }

    /// Check whether the given SELinux lifecycle state satisfies the
    /// requirements of the specified security profile.
    #[must_use]
    pub fn check_compliance(
        profile: SecurityProfile,
        state: MacPolicyLifecycle,
    ) -> bool {
        let required = Self::required_mac_profile(profile);
        match required {
            MacPolicyRequirement::None => true,
            MacPolicyRequirement::Permissive => {
                matches!(
                    state,
                    MacPolicyLifecycle::Enforcing
                        | MacPolicyLifecycle::Permissive
                        | MacPolicyLifecycle::Loaded
                )
            }
            MacPolicyRequirement::Enforcing => {
                matches!(state, MacPolicyLifecycle::Enforcing)
            }
            MacPolicyRequirement::EnforcingMls => {
                matches!(state, MacPolicyLifecycle::Enforcing)
            }
        }
    }

    /// Returns `true` if the profile requires SELinux to be active.
    #[must_use]
    pub fn requires_selinux(profile: SecurityProfile) -> bool {
        !matches!(
            Self::required_mac_profile(profile),
            MacPolicyRequirement::None
        )
    }

    /// Returns `true` if MLS/MCS labeling is required for the profile.
    #[must_use]
    pub fn requires_mls(profile: SecurityProfile) -> bool {
        matches!(
            Self::required_mac_profile(profile),
            MacPolicyRequirement::EnforcingMls
        )
    }
}

// ---------------------------------------------------------------------------
// SelinuEvidenceEvent — typed evidence for policy lifecycle events
// ---------------------------------------------------------------------------

/// Typed evidence events emitted by the SELinux MAC policy plane.
///
/// Each variant corresponds to a distinct auditable event in the policy
/// lifecycle, matching the evidence vocabulary defined in S16.2 §5 and §8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelinuEvidenceEvent {
    /// A policy bundle was loaded into the kernel.
    /// Carries the bundle_id and timestamp.
    PolicyLoaded {
        bundle_id: String,
        version: String,
    },
    /// Policy transitioned to enforcing mode.
    PolicyEnforcing {
        bundle_id: String,
        enforced_at: String,
    },
    /// An AVC denial was captured.
    AvcDenial {
        source_domain: String,
        target_domain: String,
        permission: String,
        timestamp_secs: u64,
    },
    /// A SELinux boolean was changed.
    BooleanChanged {
        boolean_name: String,
        old_value: bool,
        new_value: bool,
    },
}

impl SelinuEvidenceEvent {
    /// Evidence-type tag for filtering and routing.
    #[must_use]
    pub fn event_tag(&self) -> &'static str {
        match self {
            Self::PolicyLoaded { .. } => "SELINUX_POLICY_LOADED",
            Self::PolicyEnforcing { .. } => "SELINUX_POLICY_ENFORCING",
            Self::AvcDenial { .. } => "SELINUX_AVC_DENIAL",
            Self::BooleanChanged { .. } => "SELINUX_BOOLEAN_CHANGED",
        }
    }

    /// Format as a compact evidence-line JSON-like string.
    #[must_use]
    pub fn to_evidence_line(&self) -> String {
        match self {
            Self::PolicyLoaded {
                bundle_id,
                version,
            } => format!(
                "SELINUX_POLICY_LOADED bundle_id={} version={}",
                bundle_id, version
            ),
            Self::PolicyEnforcing {
                bundle_id,
                enforced_at,
            } => format!(
                "SELINUX_POLICY_ENFORCING bundle_id={} enforced_at={}",
                bundle_id, enforced_at
            ),
            Self::AvcDenial {
                source_domain,
                target_domain,
                permission,
                timestamp_secs,
            } => format!(
                "SELINUX_AVC_DENIAL source={} target={} permission={} ts={}",
                source_domain, target_domain, permission, timestamp_secs
            ),
            Self::BooleanChanged {
                boolean_name,
                old_value,
                new_value,
            } => format!(
                "SELINUX_BOOLEAN_CHANGED boolean={} old={} new={}",
                boolean_name, old_value, new_value
            ),
        }
    }
}

// ===========================================================================
// Tests — INV-SEL-001 through INV-SEL-005
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;
    use strum::EnumCount;

    // -------------------------------------------------------------------
    // INV-SEL-001: Domain naming convention
    // -------------------------------------------------------------------

    #[test]
    fn domain_from_capsule_id_follows_convention() {
        let d = SeLinuxDomain::from_capsule_id(CapsuleId(7));
        assert_eq!(d.as_str(), "aios_capsule_7_t");
    }

    #[test]
    fn domain_new_rejects_invalid_patterns() {
        assert!(SeLinuxDomain::new("aios_capsule_7_t").is_some());
        assert!(SeLinuxDomain::new("random_domain_t").is_none());
        assert!(SeLinuxDomain::new("aios_capsule_abc_t").is_none());
        assert!(SeLinuxDomain::new("unconfined_t").is_none());
        assert!(SeLinuxDomain::new("").is_none());
    }

    #[test]
    fn domain_capsule_id_round_trip() {
        for n in [1, 42, 999, 1000000] {
            let d = SeLinuxDomain::from_capsule_id(CapsuleId(n));
            assert_eq!(d.capsule_id(), Some(n));
        }
    }

    #[test]
    fn domain_display() {
        let d = SeLinuxDomain::from_capsule_id(CapsuleId(3));
        assert_eq!(format!("{}", d), "aios_capsule_3_t");
    }

    // -------------------------------------------------------------------
    // INV-SEL-004: Context validity
    // -------------------------------------------------------------------

    #[test]
    fn context_new_rejects_empty_fields() {
        assert!(SeLinuxContext::new("", "r", "t", "s0").is_none());
        assert!(SeLinuxContext::new("u", "", "t", "s0").is_none());
        assert!(SeLinuxContext::new("u", "r", "", "s0").is_none());
        assert!(SeLinuxContext::new("u", "r", "t", "").is_none());
    }

    #[test]
    fn context_validates_level_correctly() {
        // Valid.
        assert!(SeLinuxContext::is_valid_level("s0"));
        assert!(SeLinuxContext::is_valid_level("s15"));
        assert!(SeLinuxContext::is_valid_level("s0:c0"));
        assert!(SeLinuxContext::is_valid_level("s1:c0,c1,c100"));
        assert!(SeLinuxContext::is_valid_level("s5:c1023"));
        // Invalid.
        assert!(!SeLinuxContext::is_valid_level(""));
        assert!(!SeLinuxContext::is_valid_level("s16"));
        assert!(!SeLinuxContext::is_valid_level("x0"));
        assert!(!SeLinuxContext::is_valid_level("s0:"));
        assert!(!SeLinuxContext::is_valid_level("s0:c1024"));
        assert!(!SeLinuxContext::is_valid_level("s0:d0"));
    }

    #[test]
    fn context_display_format() {
        let ctx = SeLinuxContext {
            user: "system_u".into(),
            role: "object_r".into(),
            type_: "aios_data_t".into(),
            level: "s0:c0,c1".into(),
        };
        assert_eq!(
            ctx.to_string(),
            "system_u:object_r:aios_data_t:s0:c0,c1"
        );
    }

    #[test]
    fn context_for_capsule_sets_correct_type() {
        let domain = SeLinuxDomain::from_capsule_id(CapsuleId(42));
        let ctx = SeLinuxContext::for_capsule(&domain, "s2", &[0, 1, 5]);
        assert_eq!(ctx.user, "system_u");
        assert_eq!(ctx.role, "system_r");
        assert_eq!(ctx.type_, "aios_capsule_42_t");
        assert_eq!(ctx.level, "s2:c0,c1,c5");
    }

    #[test]
    fn context_for_file_sets_object_r() {
        let domain = SeLinuxDomain::from_capsule_id(CapsuleId(7));
        let ctx = SeLinuxContext::for_file(&domain);
        assert_eq!(ctx.role, "object_r");
        assert_eq!(ctx.type_, domain.as_str());
    }

    // -------------------------------------------------------------------
    // SeLinuxRule
    // -------------------------------------------------------------------

    #[test]
    fn rule_new_rejects_empty_inputs() {
        assert!(SeLinuxRule::new("", "tgt", &[SeLinuxPermission::Read]).is_none());
        assert!(SeLinuxRule::new("src", "", &[SeLinuxPermission::Read]).is_none());
        assert!(SeLinuxRule::new("src", "tgt", &[]).is_none());
    }

    #[test]
    fn rule_detects_unconfined() {
        let r = SeLinuxRule::new("unconfined_t", "aios_data_t", &[SeLinuxPermission::Read])
            .unwrap();
        assert!(r.references_unconfined());

        let r2 = SeLinuxRule::new("aios_capsule_1_t", "unconfined_t", &[SeLinuxPermission::Read])
            .unwrap();
        assert!(r2.references_unconfined());

        let r3 = SeLinuxRule::new("aios_capsule_1_t", "aios_data_t", &[SeLinuxPermission::Read])
            .unwrap();
        assert!(!r3.references_unconfined());
    }

    // -------------------------------------------------------------------
    // INV-SEL-002 & INV-SEL-003: Validator
    // -------------------------------------------------------------------

    #[test]
    fn validator_rejects_empty_ruleset() {
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![],
            vec![],
        );
        let result = SePolicyValidator::validate(&bundle);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("no rules")));
    }

    #[test]
    fn validator_rejects_unconfined_t() {
        let rule = SeLinuxRule::new(
            "unconfined_t",
            "aios_data_t",
            &[SeLinuxPermission::Read],
        )
        .unwrap();
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![rule],
            vec![],
        );
        let result = SePolicyValidator::validate(&bundle);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("unconfined_t")));
    }

    #[test]
    fn validator_rejects_blanket_permissions_without_justification() {
        let all_perms = Vec::from(SeLinuxPermission::all());
        let rule = SeLinuxRule::new("aios_capsule_1_t", "aios_data_t", &all_perms).unwrap();
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![rule],
            vec![],
        );
        let result = SePolicyValidator::validate(&bundle);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs
            .iter()
            .any(|e| e.contains("without justification")));
    }

    #[test]
    fn validator_accepts_valid_bundle() {
        let rule = SeLinuxRule::with_justification(
            "aios_capsule_1_t",
            "aios_data_t",
            &[SeLinuxPermission::Read, SeLinuxPermission::Open],
            "capsule needs read access to AIOS shared data",
        )
        .unwrap();
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![rule],
            vec![],
        );
        let result = SePolicyValidator::validate(&bundle);
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------
    // Policy bundle sizing / tracking
    // -------------------------------------------------------------------

    #[test]
    fn policy_bundle_tracks_size() {
        let rules = vec![
            SeLinuxRule::new(
                "aios_capsule_1_t",
                "aios_data_t",
                &[SeLinuxPermission::Read, SeLinuxPermission::Open],
            )
            .unwrap(),
            SeLinuxRule::new(
                "aios_capsule_1_t",
                "aios_system_t",
                &[SeLinuxPermission::Write],
            )
            .unwrap(),
        ];
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            rules,
            vec![],
        );
        assert_eq!(bundle.rule_count(), 2);
        assert_eq!(bundle.total_permissions(), 3);
    }

    #[test]
    fn policy_bundle_contains_unconfined_detection() {
        let rules = vec![
            SeLinuxRule::new(
                "aios_capsule_1_t",
                "aios_data_t",
                &[SeLinuxPermission::Read],
            )
            .unwrap(),
        ];
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            rules,
            vec![],
        );
        assert!(!bundle.contains_unconfined());

        let dirty_rules = vec![
            SeLinuxRule::new(
                "unconfined_t",
                "aios_data_t",
                &[SeLinuxPermission::Read],
            )
            .unwrap(),
        ];
        let dirty_bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            dirty_rules,
            vec![],
        );
        assert!(dirty_bundle.contains_unconfined());
    }

    // -------------------------------------------------------------------
    // INV-SEL-005: AVC denial evidence record
    // -------------------------------------------------------------------

    #[test]
    fn avc_denial_new_rejects_invalid_inputs() {
        let src = SeLinuxContext {
            user: "system_u".into(),
            role: "system_r".into(),
            type_: "aios_capsule_7_t".into(),
            level: "s0".into(),
        };
        let tgt = SeLinuxContext {
            user: "system_u".into(),
            role: "object_r".into(),
            type_: "aios_data_t".into(),
            level: "s0".into(),
        };

        assert!(AvcDenial::new(0, src.clone(), tgt.clone(), vec![SeLinuxPermission::Read], "myproc", None, "aios").is_none());
        assert!(AvcDenial::new(1000, src.clone(), tgt.clone(), vec![], "myproc", None, "aios").is_none());
        assert!(AvcDenial::new(1000, src.clone(), tgt.clone(), vec![SeLinuxPermission::Read], "", None, "aios").is_none());
        assert!(AvcDenial::new(1000, src.clone(), tgt.clone(), vec![SeLinuxPermission::Read], "myproc", None, "").is_none());
        assert!(AvcDenial::new(1000, src, tgt, vec![SeLinuxPermission::Read, SeLinuxPermission::Write], "myproc", None, "aios").is_some());
    }

    #[test]
    fn avc_denial_summary_format() {
        let src = SeLinuxContext {
            user: "system_u".into(),
            role: "system_r".into(),
            type_: "aios_capsule_7_t".into(),
            level: "s0".into(),
        };
        let tgt = SeLinuxContext {
            user: "system_u".into(),
            role: "object_r".into(),
            type_: "aios_data_t".into(),
            level: "s0".into(),
        };
        let denial = AvcDenial::new(
            1700000000,
            src,
            tgt,
            vec![SeLinuxPermission::Write, SeLinuxPermission::Delete],
            "capsule-agent",
            Some("/usr/bin/capsule".into()),
            "aios",
        )
        .unwrap();
        let summary = denial.summary();
        assert!(summary.contains("AVC denied"));
        assert!(summary.contains("capsule-agent"));
        assert!(summary.contains("aios_capsule_7_t"));
        assert!(summary.contains("aios_data_t"));
        assert!(summary.contains("write"));
        assert!(summary.contains("delete"));
    }

    #[test]
    fn avc_denial_involves_unconfined_detection() {
        let src_unconf = SeLinuxContext {
            user: "system_u".into(),
            role: "system_r".into(),
            type_: "unconfined_t".into(),
            level: "s0".into(),
        };
        let tgt = SeLinuxContext {
            user: "system_u".into(),
            role: "object_r".into(),
            type_: "aios_data_t".into(),
            level: "s0".into(),
        };
        let denial = AvcDenial::new(
            1000,
            src_unconf,
            tgt,
            vec![SeLinuxPermission::Read],
            "proc",
            None,
            "aios",
        )
        .unwrap();
        assert!(denial.involves_unconfined());
    }

    // -------------------------------------------------------------------
    // Cross-cutting: domain transitions
    // -------------------------------------------------------------------

    #[test]
    fn bundle_transitions_tracked_correctly() {
        let t1 = SeLinuxDomain::from_capsule_id(CapsuleId(10));
        let t2 = SeLinuxDomain::from_capsule_id(CapsuleId(20));
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![0, 1],
            vec![SeLinuxRule::new(
                "aios_capsule_1_t",
                "aios_data_t",
                &[SeLinuxPermission::Read],
            )
            .unwrap()],
            vec![t1.clone(), t2.clone()],
        );
        assert_eq!(bundle.transitions.len(), 2);
        assert_eq!(bundle.transitions[0], t1);
        assert_eq!(bundle.transitions[1], t2);
    }

    // -------------------------------------------------------------------
    // Edge: validator with justification bypass for blanket perms
    // -------------------------------------------------------------------

    #[test]
    fn validator_accepts_blanket_with_justification() {
        let all_perms = Vec::from(SeLinuxPermission::all());
        let rule = SeLinuxRule::with_justification(
            "aios_capsule_1_t",
            "aios_system_t",
            &all_perms,
            "system capsule requires full access to orchestrator API",
        )
        .unwrap();
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![rule],
            vec![],
        );
        let result = SePolicyValidator::validate(&bundle);
        assert!(result.is_ok());
    }

    // ===================================================================
    // Rev.8 — SELinux MAC Policy Engine tests (min 15)
    // ===================================================================

    // ── SeLinuxDomain extension (MLS/MCS/transitions/booleans) ──

    #[test]
    fn domain_builder_pattern_sets_all_fields() {
        let domain = SeLinuxDomain::from_capsule_id(CapsuleId(42))
            .with_mls_level("s3")
            .with_mcs_categories(vec![0, 1, 2])
            .add_transition("aios_data_t")
            .add_boolean("allow_user_exec_domain")
            .add_file_context("/usr/lib/aios(/.*)?");
        assert_eq!(domain.as_str(), "aios_capsule_42_t");
        assert_eq!(domain.mls_level, Some("s3".into()));
        assert_eq!(domain.mcs_categories, vec![0, 1, 2]);
        assert_eq!(domain.allowed_transitions, vec!["aios_data_t"]);
        assert_eq!(domain.allowed_booleans, vec!["allow_user_exec_domain"]);
        assert_eq!(
            domain.allowed_file_contexts,
            vec!["/usr/lib/aios(/.*)?"]
        );
        assert!(domain.has_mls());
        assert_eq!(domain.transition_count(), 1);
    }

    #[test]
    fn domain_default_has_no_mls() {
        let domain = SeLinuxDomain::from_capsule_id(CapsuleId(1));
        assert!(!domain.has_mls());
        assert!(domain.mls_level.is_none());
        assert!(domain.mcs_categories.is_empty());
        assert!(domain.allowed_transitions.is_empty());
    }

    // ── SePolicyBundle extension (bundle_id, version, signature) ──

    #[test]
    fn policy_bundle_extended_fields() {
        let rule = SeLinuxRule::new(
            "aios_capsule_1_t",
            "aios_data_t",
            &[SeLinuxPermission::Read],
        )
        .unwrap();
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![rule],
            vec![],
        )
        .with_bundle_id("aios.selinux.core")
        .with_version("2026.05.rev3")
        .add_file_context("/var/lib/aios(/.*)?")
        .add_boolean("allow_user_exec_content")
        .add_port("8080")
        .with_signature("sha256:abcdef");
        assert_eq!(bundle.bundle_id, Some("aios.selinux.core".into()));
        assert_eq!(bundle.version, Some("2026.05.rev3".into()));
        assert_eq!(bundle.file_contexts.len(), 1);
        assert_eq!(bundle.booleans.len(), 1);
        assert_eq!(bundle.ports.len(), 1);
        assert!(bundle.is_signed());
        assert_eq!(bundle.file_context_count(), 1);
    }

    #[test]
    fn policy_bundle_defaults_to_unsigned() {
        let rule = SeLinuxRule::new(
            "aios_capsule_1_t",
            "aios_data_t",
            &[SeLinuxPermission::Read],
        )
        .unwrap();
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![rule],
            vec![],
        );
        assert!(!bundle.is_signed());
        assert!(bundle.bundle_id.is_none());
        assert!(bundle.version.is_none());
    }

    // ── MacPolicyLifecycle ──

    #[test]
    fn mac_policy_lifecycle_labels_are_stable() {
        assert_eq!(MacPolicyLifecycle::Draft.label(), "DRAFT");
        assert_eq!(MacPolicyLifecycle::Compiled.label(), "COMPILED");
        assert_eq!(MacPolicyLifecycle::Loaded.label(), "LOADED");
        assert_eq!(MacPolicyLifecycle::Enforcing.label(), "ENFORCING");
        assert_eq!(MacPolicyLifecycle::Permissive.label(), "PERMISSIVE");
        assert_eq!(MacPolicyLifecycle::Disabled.label(), "DISABLED");
        assert_eq!(MacPolicyLifecycle::Expired.label(), "EXPIRED");
        assert_eq!(MacPolicyLifecycle::Revoked.label(), "REVOKED");
    }

    #[test]
    fn mac_policy_lifecycle_active_states() {
        assert!(MacPolicyLifecycle::Loaded.is_active());
        assert!(MacPolicyLifecycle::Enforcing.is_active());
        assert!(MacPolicyLifecycle::Permissive.is_active());
        assert!(!MacPolicyLifecycle::Draft.is_active());
        assert!(!MacPolicyLifecycle::Compiled.is_active());
        assert!(!MacPolicyLifecycle::Disabled.is_active());
    }

    #[test]
    fn mac_policy_lifecycle_terminal_states() {
        assert!(MacPolicyLifecycle::Expired.is_terminal());
        assert!(MacPolicyLifecycle::Revoked.is_terminal());
        assert!(!MacPolicyLifecycle::Enforcing.is_terminal());
    }

    #[test]
    fn mac_policy_lifecycle_counts_match_enum_count() {
        // Verify the enum has 8 variants (matching EnumCount).
        assert_eq!(MacPolicyLifecycle::COUNT, 8);
    }

    // ── MacPolicyCompiler ──

    #[test]
    fn compiler_full_lifecycle_compile_load_enforce() {
        let rule = SeLinuxRule::with_justification(
            "aios_capsule_1_t",
            "aios_data_t",
            &[SeLinuxPermission::Read, SeLinuxPermission::Open],
            "capsule needs read access to shared data",
        )
        .unwrap();
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![rule],
            vec![],
        );
        let mut compiler = MacPolicyCompiler::new(bundle);
        assert_eq!(compiler.state, MacPolicyLifecycle::Draft);

        // Compile.
        assert!(compiler.compile_policy().is_ok());
        assert_eq!(compiler.state, MacPolicyLifecycle::Compiled);
        assert!(compiler.compiled_output.is_some());
        let cil = compiler.compiled_output.as_ref().unwrap();
        assert!(cil.contains("(type aios_capsule_1_t)"));
        assert!(cil.contains("(allow"));

        // Validate.
        assert!(compiler.validate_policy().is_ok());
        assert!(compiler.validation_errors.is_empty());

        // Load.
        assert!(compiler.load_policy().is_ok());
        assert_eq!(compiler.state, MacPolicyLifecycle::Loaded);
        assert!(compiler.loaded_at.is_some());

        // Enforce.
        assert!(compiler.enforce_policy().is_ok());
        assert_eq!(compiler.state, MacPolicyLifecycle::Enforcing);
        assert!(compiler.enforced_at.is_some());
        assert!(compiler.meets_stig_requirements());
    }

    #[test]
    fn compiler_rejects_compile_from_wrong_state() {
        let rule = SeLinuxRule::new(
            "aios_capsule_1_t",
            "aios_data_t",
            &[SeLinuxPermission::Read],
        )
        .unwrap();
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![rule],
            vec![],
        );
        let mut compiler = MacPolicyCompiler::new(bundle);
        assert!(compiler.compile_policy().is_ok());
        // Second compile should fail.
        let result = compiler.compile_policy();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot compile from state"));
    }

    #[test]
    fn compiler_rejects_compile_with_unconfined() {
        let rule = SeLinuxRule::new(
            "unconfined_t",
            "aios_data_t",
            &[SeLinuxPermission::Read],
        )
        .unwrap();
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![rule],
            vec![],
        );
        let mut compiler = MacPolicyCompiler::new(bundle);
        let result = compiler.compile_policy();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unconfined_t"));
    }

    #[test]
    fn compiler_set_permissive_from_enforcing() {
        let rule = SeLinuxRule::new(
            "aios_capsule_1_t",
            "aios_data_t",
            &[SeLinuxPermission::Read],
        )
        .unwrap();
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![rule],
            vec![],
        );
        let mut compiler = MacPolicyCompiler::new(bundle);
        compiler.compile_policy().unwrap();
        compiler.validate_policy().unwrap();
        compiler.load_policy().unwrap();
        compiler.enforce_policy().unwrap();
        assert!(compiler.set_permissive().is_ok());
        assert_eq!(compiler.state, MacPolicyLifecycle::Permissive);
    }

    #[test]
    fn compiler_cannot_enforce_with_validation_errors() {
        let bundle = SePolicyBundle::generate_for_capsule(
            CapsuleId(1),
            "s0",
            vec![],
            vec![],
            vec![],
        );
        let mut compiler = MacPolicyCompiler::new(bundle);
        // Skip compile, manually set state and inject errors.
        compiler.state = MacPolicyLifecycle::Loaded;
        compiler.validation_errors
            .push("mock validation error".into());
        let result = compiler.enforce_policy();
        assert!(result.is_err());
    }

    // ── AvcDecision ──

    #[test]
    fn avc_decision_new_rejects_empty_fields() {
        assert!(AvcDecision::new("", "tgt", "file", "read", AvcDecisionKind::Denied).is_none());
        assert!(AvcDecision::new("src", "", "file", "read", AvcDecisionKind::Denied).is_none());
        assert!(AvcDecision::new("src", "tgt", "", "read", AvcDecisionKind::Denied).is_none());
        assert!(AvcDecision::new("src", "tgt", "file", "", AvcDecisionKind::Denied).is_none());
        assert!(AvcDecision::new("src", "tgt", "file", "read", AvcDecisionKind::Denied).is_some());
    }

    #[test]
    fn avc_decision_is_denial() {
        let d = AvcDecision::new("aios_agent_t", "aios_vault_t", "file", "read", AvcDecisionKind::Denied).unwrap();
        assert!(d.is_denial());
        let allowed = AvcDecision::new("aios_agent_t", "aios_data_t", "file", "read", AvcDecisionKind::Allowed).unwrap();
        assert!(!allowed.is_denial());
    }

    // ── AvcAuditEngine ──

    #[test]
    fn audit_engine_captures_denials_and_computes_rate() {
        let mut engine = AvcAuditEngine::new(5);
        assert_eq!(engine.denial_count(), 0);
        assert!(!engine.is_alert_threshold_exceeded());
        assert_eq!(engine.avc_denial_alert_threshold(), 5);

        let src = SeLinuxContext {
            user: "system_u".into(),
            role: "system_r".into(),
            type_: "aios_capsule_7_t".into(),
            level: "s0".into(),
        };
        let tgt = SeLinuxContext {
            user: "system_u".into(),
            role: "object_r".into(),
            type_: "aios_data_t".into(),
            level: "s0".into(),
        };
        let denial = AvcDenial::new(
            1700000000,
            src,
            tgt,
            vec![SeLinuxPermission::Write],
            "capsule-agent",
            None,
            "aios",
        )
        .unwrap();

        engine.capture_avc_denial(denial);
        assert_eq!(engine.denial_count(), 1);
        // Rate should be non-negative.
        assert!(engine.avc_denial_rate() >= 0.0);
    }

    #[test]
    fn audit_engine_alert_threshold() {
        let mut engine = AvcAuditEngine::new(2);

        let src = SeLinuxContext {
            user: "system_u".into(),
            role: "system_r".into(),
            type_: "aios_capsule_7_t".into(),
            level: "s0".into(),
        };
        let tgt = SeLinuxContext {
            user: "system_u".into(),
            role: "object_r".into(),
            type_: "aios_data_t".into(),
            level: "s0".into(),
        };

        // 2 denials: threshold not exceeded (>, not >=).
        engine.capture_avc_denial(
            AvcDenial::new(1000, src.clone(), tgt.clone(), vec![SeLinuxPermission::Read], "p1", None, "aios").unwrap(),
        );
        engine.capture_avc_denial(
            AvcDenial::new(1000, src.clone(), tgt.clone(), vec![SeLinuxPermission::Write], "p1", None, "aios").unwrap(),
        );
        assert!(!engine.is_alert_threshold_exceeded());

        // 3rd denial: threshold exceeded.
        engine.capture_avc_denial(
            AvcDenial::new(1000, src, tgt, vec![SeLinuxPermission::Execute], "p1", None, "aios").unwrap(),
        );
        assert!(engine.is_alert_threshold_exceeded());
    }

    // ── McsLabel ──

    #[test]
    fn mcs_label_format_and_validation() {
        let label = McsLabel::new(2, vec![0, 1, 5]).unwrap();
        assert_eq!(label.to_level_string(), "s2:c0,c1,c5");
        assert_eq!(label.category_count(), 3);

        // Invalid: sensitivity > 15.
        assert!(McsLabel::new(16, vec![0]).is_none());
        // Invalid: category > 1023.
        assert!(McsLabel::new(0, vec![1024]).is_none());
    }

    #[test]
    fn mcs_label_dominance_and_overlap() {
        let label_a = McsLabel::new(2, vec![0, 1, 2]).unwrap();
        let label_b = McsLabel::new(1, vec![0, 1]).unwrap();
        let label_c = McsLabel::new(0, vec![5, 6]).unwrap();

        assert!(label_a.dominates(&label_b));
        assert!(!label_b.dominates(&label_a));
        assert!(label_a.categories_overlap(&label_b));
        assert!(!label_a.categories_overlap(&label_c));
        assert!(!label_b.categories_overlap(&label_c));
    }

    // ── MlsLabel ──

    #[test]
    fn mls_label_bell_lapadula_rules() {
        let subject = MlsLabel::new(5, 3).unwrap();
        // "read down" — subject at s3 can read s0..s3.
        assert!(subject.can_read(0));
        assert!(subject.can_read(3));
        assert!(!subject.can_read(5)); // cannot read up.
        // "write up" — subject at s3 can write to s3..s5.
        assert!(subject.can_write(3));
        assert!(subject.can_write(5));
        assert!(!subject.can_write(1)); // cannot write down.
    }

    #[test]
    fn mls_label_rejects_invalid_levels() {
        assert!(MlsLabel::new(16, 0).is_none());
        assert!(MlsLabel::new(0, 16).is_none());
        // current_level > clearance.
        assert!(MlsLabel::new(3, 5).is_none());
        assert!(MlsLabel::new(5, 5).is_some());
    }

    // ── SelinuxPolicyGate ──

    #[test]
    fn policy_gate_maps_profiles_to_requirements() {
        assert_eq!(
            SelinuxPolicyGate::required_mac_profile(SecurityProfile::DevRelaxed),
            MacPolicyRequirement::None
        );
        assert_eq!(
            SelinuxPolicyGate::required_mac_profile(SecurityProfile::SecureDefault),
            MacPolicyRequirement::Permissive
        );
        assert_eq!(
            SelinuxPolicyGate::required_mac_profile(SecurityProfile::StigAligned),
            MacPolicyRequirement::Enforcing
        );
        assert_eq!(
            SelinuxPolicyGate::required_mac_profile(SecurityProfile::AirgapHigh),
            MacPolicyRequirement::EnforcingMls
        );
    }

    #[test]
    fn policy_gate_compliance_checks() {
        assert!(SelinuxPolicyGate::check_compliance(
            SecurityProfile::DevRelaxed,
            MacPolicyLifecycle::Draft,
        ));
        assert!(SelinuxPolicyGate::check_compliance(
            SecurityProfile::SecureDefault,
            MacPolicyLifecycle::Enforcing,
        ));
        assert!(!SelinuxPolicyGate::check_compliance(
            SecurityProfile::StigAligned,
            MacPolicyLifecycle::Permissive,
        ));
        assert!(SelinuxPolicyGate::check_compliance(
            SecurityProfile::AirgapHigh,
            MacPolicyLifecycle::Enforcing,
        ));
    }

    #[test]
    fn policy_gate_requires_selinux_flag() {
        assert!(!SelinuxPolicyGate::requires_selinux(
            SecurityProfile::DevRelaxed
        ));
        assert!(SelinuxPolicyGate::requires_selinux(
            SecurityProfile::SecureDefault
        ));
        assert!(SelinuxPolicyGate::requires_selinux(
            SecurityProfile::StigAligned
        ));
    }

    #[test]
    fn policy_gate_requires_mls_flag() {
        assert!(!SelinuxPolicyGate::requires_mls(
            SecurityProfile::SecureDefault
        ));
        assert!(!SelinuxPolicyGate::requires_mls(
            SecurityProfile::StigAligned
        ));
        assert!(SelinuxPolicyGate::requires_mls(
            SecurityProfile::AirgapHigh
        ));
    }

    // ── SelinuEvidenceEvent ──

    #[test]
    fn evidence_event_tag_mapping() {
        let loaded = SelinuEvidenceEvent::PolicyLoaded {
            bundle_id: "aios.selinux.core".into(),
            version: "2026.05".into(),
        };
        assert_eq!(loaded.event_tag(), "SELINUX_POLICY_LOADED");

        let enforcing = SelinuEvidenceEvent::PolicyEnforcing {
            bundle_id: "aios.selinux.core".into(),
            enforced_at: "2026-06-11T00:00:00Z".into(),
        };
        assert_eq!(enforcing.event_tag(), "SELINUX_POLICY_ENFORCING");

        let avc = SelinuEvidenceEvent::AvcDenial {
            source_domain: "aios_agent_t".into(),
            target_domain: "aios_vault_t".into(),
            permission: "read".into(),
            timestamp_secs: 1700000000,
        };
        assert_eq!(avc.event_tag(), "SELINUX_AVC_DENIAL");

        let bool_change = SelinuEvidenceEvent::BooleanChanged {
            boolean_name: "allow_user_exec_content".into(),
            old_value: true,
            new_value: false,
        };
        assert_eq!(bool_change.event_tag(), "SELINUX_BOOLEAN_CHANGED");
    }

    #[test]
    fn evidence_event_line_format() {
        let event = SelinuEvidenceEvent::PolicyLoaded {
            bundle_id: "aios.selinux.core".into(),
            version: "2026.05".into(),
        };
        let line = event.to_evidence_line();
        assert!(line.contains("SELINUX_POLICY_LOADED"));
        assert!(line.contains("aios.selinux.core"));

        let avc = SelinuEvidenceEvent::AvcDenial {
            source_domain: "aios_agent_t".into(),
            target_domain: "aios_vault_t".into(),
            permission: "read".into(),
            timestamp_secs: 1700000000,
        };
        let avc_line = avc.to_evidence_line();
        assert!(avc_line.contains("SELINUX_AVC_DENIAL"));
        assert!(avc_line.contains("aios_agent_t"));
        assert!(avc_line.contains("aios_vault_t"));
    }
}
