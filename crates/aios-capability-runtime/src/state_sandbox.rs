//! Qubes OS / Capsicum-inspired capsule-state sandbox for file isolation.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
//!
//! ## OS Research Provenance
//!
//! **Qubes OS** (Invisible Things Lab, 2010–present) pioneered the concept of
//! **security-by-compartmentalization**: every application / domain runs in
//! its own lightweight VM (AppVM), and the **qrexec** policy engine
//! explicitly controls which domains can access which files, pipes, and
//! services.  No implicit sharing — every cross-domain interaction must be
//! declared in `/etc/qubes/policy.conf`.
//!
//! **Capsicum** (University of Cambridge / FreeBSD, 2011–present) introduced
//! **capability mode** for UNIX processes: once a process enters capability
//! mode (`cap_enter()`), it can only access file descriptors it already
//! holds.  The kernel enforces a strict "no new global namespaces" rule —
//! no `open(2)`, no `socket(2)`, no `connect(2)`.
//!
//! ### Mapping to AIOS Capsule Architecture
//!
//! | Qubes / Capsicum concept | AIOS equivalent                               |
//! |---------------------------|-----------------------------------------------|
//! | Qubes AppVM isolation     | [`StateSandbox`] — per-capsule file access matrix |
//! | qrexec policy             | [`FileAccessRule`] — explicit source→target grants |
//! | Policy deny-by-default    | Missing rule → [`AccessDecision::Denied`]        |
//! | Qubes qubesctl policy     | [`StateSandbox::allow`] / [`StateSandbox::deny`] |
//! | Capsicum capability mode  | Capsule cannot access files outside its sandbox |
//! | Capsicum cap_rights_limit | [`FilePermission`] — Read, Write, Execute mask   |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-SS-001 (Deny-by-default):** A path with no explicit rule returns
//!   [`AccessDecision::Denied`].
//! - **INV-SS-002 (Explicit allow):** A path governed by an explicit
//!   [`FileAccessRule`] returns [`AccessDecision::Allowed`] only if the
//!   requested operation is covered by the rule's permissions.
//! - **INV-SS-003 (Revocation is immediate):** [`StateSandbox::deny`]
//!   removes the rule; a subsequent [`StateSandbox::evaluate`] for the
//!   same capsule+path returns [`AccessDecision::Denied`].
//! - **INV-SS-004 (Violation recording):** Every [`AccessDecision::Denied`]
//!   result is appended to the internal violations log and retrievable via
//!   [`StateSandbox::get_violations`].
//! - **INV-SS-005 (Per-capsule isolation):** An allow rule for capsule A
//!   does not grant access for capsule B; capsule B must have its own
//!   explicit rule.
//! - **INV-SS-006 (No ambient authority):** A newly-created [`StateSandbox`]
//!   contains zero access rules — every path must be explicitly allowed.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::capsule_namespace::CapsuleId;

// ---------------------------------------------------------------------------
// FilePermission — operation mask for file access
// ---------------------------------------------------------------------------

/// File access operation (Qubes qrexec / Capsicum rights bitmask).
///
/// Each variant corresponds to the lowest-level file operation a capsule
/// may request.  A [`FileAccessRule`] carries a subset of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilePermission {
    /// Read file contents.
    Read,
    /// Write / modify file contents.
    Write,
    /// Execute file (for binary / script capsules).
    Execute,
}

impl FilePermission {
    /// Human-readable label for the permission.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Write => "Write",
            Self::Execute => "Execute",
        }
    }
}

// ---------------------------------------------------------------------------
// R3-W2: AccessMode — filesystem operation intent
// ---------------------------------------------------------------------------

/// Filesystem access mode for sandboxed state operations.
///
/// Represents the *intent* of the caller rather than the *grant*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessMode {
    /// Reading file contents or metadata (stat, open O_RDONLY).
    ReadOnly,
    /// Writing, creating, or deleting files (open O_WRONLY, O_RDWR).
    ReadWrite,
    /// Explicit denial — any attempt is rejected immediately.
    Deny,
}

impl fmt::Display for AccessMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ReadOnly => "read-only",
            Self::ReadWrite => "read-write",
            Self::Deny => "deny",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// AccessDecision — result of an access evaluation
// ---------------------------------------------------------------------------

/// The outcome of evaluating an access request against the sandbox policy.
///
/// This is the AIOS analogue of Qubes OS's qrexec policy verdict or
/// SELinux's AVC decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    /// Access is explicitly permitted by a matching [`FileAccessRule`].
    Allowed,
    /// Access is explicitly denied (no rule matches, or an explicit deny
    /// rule applies).
    Denied { reason: String },
    /// Access is allowed but every attempt is logged for audit purposes
    /// (analogous to SELinux permissive mode).
    LoggedOnly { reason: String },
}

impl AccessDecision {
    /// Whether the decision permits the operation.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Whether the decision denies the operation.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }
}

// ---------------------------------------------------------------------------
// R3-W2: CapsuleStateRoot — capsule ID → filesystem root path
// ---------------------------------------------------------------------------

/// The private state root for a single capsule.
///
/// Every capsule gets a dedicated directory under the system state
/// root (e.g. `/capsule/007/` for capsule id 7).  Only the owning
/// capsule may access this subtree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapsuleStateRoot {
    /// The capsule that owns this state root.
    pub capsule_id: CapsuleId,
    /// The absolute filesystem path that serves as the capsule's root
    /// for state operations (reads, writes, snapshots).
    pub root_path: PathBuf,
}

impl CapsuleStateRoot {
    /// Construct a state root from a [`CapsuleId`].
    ///
    /// The path follows the convention `/capsule/{id}/` where `{id}` is
    /// the numeric capsule identifier (e.g. `/capsule/7` for id 7).
    #[must_use]
    pub fn from_capsule_id(id: CapsuleId) -> Self {
        let root_path = PathBuf::from(format!("/capsule/{}", id.raw()));
        Self {
            capsule_id: id,
            root_path,
        }
    }

    /// Construct a state root with a custom base directory
    /// (e.g. `/tmp/test-capsules/42` for testing).
    #[must_use]
    pub fn with_base(id: CapsuleId, base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        let root_path = base.join(id.raw().to_string());
        Self {
            capsule_id: id,
            root_path,
        }
    }

    /// Returns `true` when `path` resides inside this capsule's root.
    #[must_use]
    pub fn contains(&self, path: &Path) -> bool {
        path.starts_with(&self.root_path)
    }

    /// Extract the owning [`CapsuleId`] from a path, assuming the
    /// `/capsule/{id}/...` convention.
    ///
    /// Returns `None` if the path doesn't match the expected pattern.
    #[must_use]
    pub fn capsule_id_from_path(path: &Path) -> Option<CapsuleId> {
        let s = path.to_str()?;
        let rest = s.strip_prefix("/capsule/")?;
        let id_str = rest.split('/').next()?;
        let id: u64 = id_str.parse().ok()?;
        Some(CapsuleId(id))
    }
}

impl fmt::Display for CapsuleStateRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} → {}", self.capsule_id, self.root_path.display())
    }
}

// ---------------------------------------------------------------------------
// FileAccessRule — a single entry in the sandbox access matrix
// ---------------------------------------------------------------------------

/// A rule that grants a source capsule access to a target path with
/// specific permissions.
///
/// Analogous to a Qubes `/etc/qubes/policy.conf` line or a Capsicum
/// `cap_rights_limit(2)` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccessRule {
    /// The capsule that is being granted access.
    pub source_capsule: CapsuleId,
    /// The file-system path the capsule may access.
    pub target_path: String,
    /// The set of permitted operations.
    pub permissions: Vec<FilePermission>,
}

impl FileAccessRule {
    /// Create a new access rule.
    #[must_use]
    pub fn new(
        source_capsule: CapsuleId,
        target_path: String,
        permissions: Vec<FilePermission>,
    ) -> Self {
        Self {
            source_capsule,
            target_path,
            permissions,
        }
    }

    /// Whether this rule covers the requested operation.
    #[must_use]
    pub fn permits(&self, path: &str, permission: FilePermission) -> bool {
        self.target_path == path && self.permissions.contains(&permission)
    }

    /// Whether this rule covers any access to the given path.
    #[must_use]
    pub fn covers_path(&self, path: &str) -> bool {
        self.target_path == path
    }

    /// Whether this rule matches the given capsule.
    #[must_use]
    pub fn covers_capsule(&self, capsule_id: CapsuleId) -> bool {
        self.source_capsule == capsule_id
    }
}

// ---------------------------------------------------------------------------
// SandboxViolation — typed evidence of an unauthorized access attempt
// ---------------------------------------------------------------------------

/// A recorded violation when a capsule attempts an unauthorized file access.
///
/// Every violation is timestamped and carries the full context of the
/// attempt for forensic audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxViolation {
    /// The capsule that attempted the access.
    pub capsule_id: CapsuleId,
    /// The target path the capsule tried to access.
    pub target_path: String,
    /// The operation that was attempted.
    pub operation: FilePermission,
    /// The reason the access was denied.
    pub reason: String,
    /// Timestamp of the violation (seconds since UNIX epoch).
    pub timestamp_secs: u64,
}

impl SandboxViolation {
    /// Create a new violation record.
    #[must_use]
    pub fn new(
        capsule_id: CapsuleId,
        target_path: String,
        operation: FilePermission,
        reason: String,
    ) -> Self {
        let timestamp_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            capsule_id,
            target_path,
            operation,
            reason,
            timestamp_secs,
        }
    }
}

// ---------------------------------------------------------------------------
// StateSandbox — per-capsule file access matrix
// ---------------------------------------------------------------------------

/// The core sandbox policy engine that controls which capsule can access
/// which filesystem paths.
///
/// # Design
///
/// [`StateSandbox`] maintains a set of [`FileAccessRule`] instances that
/// form an access matrix.  By default, **every path is denied** for every
/// capsule (INV-SS-001).  Access must be explicitly granted via
/// [`Self::allow`].
///
/// # Example
///
/// ```rust
/// # use aios_capability_runtime::state_sandbox::*;
/// # use aios_capability_runtime::capsule_namespace::CapsuleId;
/// let mut sb = StateSandbox::new();
/// sb.allow(CapsuleId(1), "/data/capsule-a".into(), vec![FilePermission::Read, FilePermission::Write]);
/// let result = sb.evaluate(CapsuleId(1), "/data/capsule-a", FilePermission::Read);
/// assert!(result.is_allowed());
/// ```
#[derive(Debug, Default, Clone)]
pub struct StateSandbox {
    rules: Vec<FileAccessRule>,
    violations: Vec<SandboxViolation>,
    /// R3-W2: optional per-capsule state-root for path-containment checks.
    state_root: Option<CapsuleStateRoot>,
    /// R3-W2: explicitly denied sub-paths inside the capsule's own root.
    denied_paths: Vec<PathBuf>,
}

impl StateSandbox {
    /// Create an empty sandbox with zero access rules (INV-SS-006: no
    /// ambient authority).
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            violations: Vec::new(),
            state_root: None,
            denied_paths: Vec::new(),
        }
    }

    /// Create a new sandbox with a state-root for path-containment checks
    /// (R3-W2 per-capsule filesystem isolation).
    #[must_use]
    pub fn with_root(capsule_id: CapsuleId, state_root: CapsuleStateRoot) -> Self {
        assert_eq!(
            capsule_id, state_root.capsule_id,
            "capsule_id must match state_root.capsule_id"
        );
        Self {
            rules: Vec::new(),
            violations: Vec::new(),
            state_root: Some(state_root),
            denied_paths: Vec::new(),
        }
    }

    /// ---------- R3-W2 check_access ----------------------------------------
    ///
    /// Verify that `capsule_id` is allowed to access `target` with the
    /// requested [`AccessMode`] based on the state-root containment model.
    ///
    /// # Checks performed (in order)
    ///
    /// 1. **Capsule match** — `capsule_id` must equal the sandbox's
    ///    owning capsule; otherwise cross-capsule access is denied.
    /// 2. **Deny mode** — a [`AccessMode::Deny`] request is always rejected.
    /// 3. **Containment** — `target` must reside inside the capsule's
    ///    `state_root`.
    /// 4. **Deny-list** — even if contained, explicitly denied sub-paths
    ///    are rejected.
    ///
    /// # Returns
    ///
    /// - `Ok(())` when access is permitted.
    /// - `Err(SandboxViolation)` detailing the denial, which is also
    ///   appended to the internal violation log.
    pub fn check_access(
        &mut self,
        capsule_id: CapsuleId,
        target: impl AsRef<Path>,
        mode: AccessMode,
    ) -> Result<(), SandboxViolation> {
        let target = target.as_ref();
        let owner_id = self
            .state_root
            .as_ref()
            .map(|r| r.capsule_id)
            .unwrap_or(capsule_id);

        if capsule_id != owner_id {
            let v = SandboxViolation::new(
                capsule_id,
                target.to_string_lossy().into_owned(),
                FilePermission::Read,
                format!(
                    "cross-capsule access denied: capsule {} attempted {} access to {}",
                    capsule_id,
                    mode,
                    target.display(),
                ),
            );
            self.violations.push(v.clone());
            return Err(v);
        }

        if mode == AccessMode::Deny {
            let v = SandboxViolation::new(
                capsule_id,
                target.to_string_lossy().into_owned(),
                FilePermission::Read,
                format!("access denied by AccessMode::Deny for {}", target.display()),
            );
            self.violations.push(v.clone());
            return Err(v);
        }

        if let Some(ref root) = self.state_root {
            if !root.contains(target) {
                let v = SandboxViolation::new(
                    capsule_id,
                    target.to_string_lossy().into_owned(),
                    FilePermission::Read,
                    format!(
                        "path {} is outside capsule root {}",
                        target.display(),
                        root.root_path.display(),
                    ),
                );
                self.violations.push(v.clone());
                return Err(v);
            }
        }

        for denied in &self.denied_paths {
            if target.starts_with(denied) || target == denied {
                let v = SandboxViolation::new(
                    capsule_id,
                    target.to_string_lossy().into_owned(),
                    FilePermission::Read,
                    format!("path {} is in explicit deny-list", target.display()),
                );
                self.violations.push(v.clone());
                return Err(v);
            }
        }

        Ok(())
    }

    /// Add an explicitly denied sub-path (R3-W2 deny-list).
    pub fn deny_path(&mut self, path: impl Into<PathBuf>) {
        self.denied_paths.push(path.into());
    }

    /// The capsule ID for state-root-based sandbox (R3-W2).
    #[must_use]
    pub fn capsule_id(&self) -> Option<CapsuleId> {
        self.state_root.as_ref().map(|r| r.capsule_id)
    }

    /// ---------- access control --------------------------------------------
    ///
    /// Grant a capsule access to a file path with a set of permissions.
    ///
    /// If a rule already exists for this (capsule, path) pair, it is
    /// **replaced** with the new permissions (non-destructive update).
    pub fn allow(&mut self, capsule_id: CapsuleId, path: String, permissions: Vec<FilePermission>) {
        self.rules
            .retain(|r| !(r.source_capsule == capsule_id && r.target_path == path));
        self.rules
            .push(FileAccessRule::new(capsule_id, path, permissions));
    }

    /// Revoke all access for a capsule to a specific path.
    ///
    /// Removes every [`FileAccessRule`] matching the (capsule, path) pair.
    /// Returns `true` if at least one rule was removed (INV-SS-003).
    pub fn deny(&mut self, capsule_id: CapsuleId, path: &str) -> bool {
        let len_before = self.rules.len();
        self.rules
            .retain(|r| !(r.source_capsule == capsule_id && r.target_path == path));
        self.rules.len() < len_before
    }

    /// Evaluate whether a capsule may perform an operation on a path.
    ///
    /// # Returns
    ///
    /// - [`AccessDecision::Allowed`] if a matching rule exists that covers
    ///   the operation.
    /// - [`AccessDecision::Denied`] otherwise (INV-SS-001).  The denial is
    ///   automatically recorded as a [`SandboxViolation`] (INV-SS-004).
    pub fn evaluate(
        &mut self,
        capsule_id: CapsuleId,
        path: &str,
        operation: FilePermission,
    ) -> AccessDecision {
        let matching = self
            .rules
            .iter()
            .find(|r| r.permits(path, operation) && r.covers_capsule(capsule_id));

        match matching {
            Some(_) => AccessDecision::Allowed,
            None => {
                let reason = format!(
                    "capsule {} has no permission {:?} for path {:?}",
                    capsule_id, operation, path
                );
                self.violations.push(SandboxViolation::new(
                    capsule_id,
                    path.to_string(),
                    operation,
                    reason.clone(),
                ));
                AccessDecision::Denied { reason }
            }
        }
    }

    /// ---------- inspection ------------------------------------------------
    ///
    /// Return all recorded violations.
    ///
    /// The violations log grows monotonically and is never automatically
    /// purged (the operator may call [`Self::clear_violations`] to reset).
    #[must_use]
    pub fn get_violations(&self) -> &[SandboxViolation] {
        &self.violations
    }

    /// Clear the violations log (e.g., after rotating to an audit sink).
    pub fn clear_violations(&mut self) {
        self.violations.clear();
    }

    /// Count of active access rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Count of recorded violations.
    #[must_use]
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }

    /// Whether the sandbox has any access rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Iterate over all access rules.
    pub fn iter_rules(&self) -> impl Iterator<Item = &FileAccessRule> {
        self.rules.iter()
    }

    /// Find all rules that apply to a specific capsule.
    #[must_use]
    pub fn rules_for_capsule(&self, capsule_id: CapsuleId) -> Vec<&FileAccessRule> {
        self.rules
            .iter()
            .filter(|r| r.covers_capsule(capsule_id))
            .collect()
    }

    /// Find the rule governing a specific (capsule, path) pair, if any.
    #[must_use]
    pub fn find_rule(&self, capsule_id: CapsuleId, path: &str) -> Option<&FileAccessRule> {
        self.rules
            .iter()
            .find(|r| r.covers_capsule(capsule_id) && r.covers_path(path))
    }

    /// Evaluate an access request and return a custom log-only decision
    /// when the rule matches, without recording a violation.  Useful for
    /// SELinux-style permissive-domain auditing.
    ///
    /// # Returns
    ///
    /// - [`AccessDecision::Allowed`] if a matching rule exists.
    /// - [`AccessDecision::LoggedOnly`] if no rule exists (the attempt is
    ///   allowed but logged with the given reason).
    pub fn evaluate_logged(
        &self,
        capsule_id: CapsuleId,
        path: &str,
        operation: FilePermission,
        log_reason: &str,
    ) -> AccessDecision {
        let matching = self
            .rules
            .iter()
            .find(|r| r.permits(path, operation) && r.covers_capsule(capsule_id));

        match matching {
            Some(_) => AccessDecision::Allowed,
            None => AccessDecision::LoggedOnly {
                reason: log_reason.to_string(),
            },
        }
    }
}

// ===========================================================================
// Tests — INV-SS-001 through INV-SS-006 + R3-W2 isolation tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // FilePermission
    // -----------------------------------------------------------------------

    #[test]
    fn permission_labels_are_correct() {
        assert_eq!(FilePermission::Read.as_str(), "Read");
        assert_eq!(FilePermission::Write.as_str(), "Write");
        assert_eq!(FilePermission::Execute.as_str(), "Execute");
    }

    // -----------------------------------------------------------------------
    // INV-SS-001: Deny-by-default
    // -----------------------------------------------------------------------

    #[test]
    fn deny_by_default_for_any_capsule() {
        let mut sb = StateSandbox::new();
        let result = sb.evaluate(CapsuleId(1), "/data/file.txt", FilePermission::Read);
        assert!(result.is_denied());
        assert!(!result.is_allowed());
    }

    #[test]
    fn deny_by_default_for_any_path() {
        let mut sb = StateSandbox::new();
        let result = sb.evaluate(CapsuleId(42), "/nonexistent/path", FilePermission::Write);
        assert!(result.is_denied());
    }

    // -----------------------------------------------------------------------
    // INV-SS-002: Explicit allow grants access
    // -----------------------------------------------------------------------

    #[test]
    fn explicit_allow_grants_read_access() {
        let mut sb = StateSandbox::new();
        sb.allow(
            CapsuleId(1),
            "/data/capsule-a".into(),
            vec![FilePermission::Read],
        );
        let result = sb.evaluate(CapsuleId(1), "/data/capsule-a", FilePermission::Read);
        assert!(result.is_allowed());
    }

    #[test]
    fn allow_only_covers_granted_operations() {
        let mut sb = StateSandbox::new();
        sb.allow(
            CapsuleId(1),
            "/data/capsule-a".into(),
            vec![FilePermission::Read],
        );

        let read_result = sb.evaluate(CapsuleId(1), "/data/capsule-a", FilePermission::Read);
        assert!(read_result.is_allowed());

        let write_result = sb.evaluate(CapsuleId(1), "/data/capsule-a", FilePermission::Write);
        assert!(write_result.is_denied());
    }

    #[test]
    fn allow_multiple_permissions() {
        let mut sb = StateSandbox::new();
        sb.allow(
            CapsuleId(1),
            "/data/capsule-a".into(),
            vec![FilePermission::Read, FilePermission::Write],
        );
        assert!(sb
            .evaluate(CapsuleId(1), "/data/capsule-a", FilePermission::Read)
            .is_allowed());
        assert!(sb
            .evaluate(CapsuleId(1), "/data/capsule-a", FilePermission::Write)
            .is_allowed());
        assert!(sb
            .evaluate(CapsuleId(1), "/data/capsule-a", FilePermission::Execute)
            .is_denied());
    }

    // -----------------------------------------------------------------------
    // INV-SS-003: Revocation is immediate
    // -----------------------------------------------------------------------

    #[test]
    fn deny_after_allow_revokes_access() {
        let mut sb = StateSandbox::new();
        sb.allow(
            CapsuleId(1),
            "/data/capsule-a".into(),
            vec![FilePermission::Read],
        );
        assert!(sb
            .evaluate(CapsuleId(1), "/data/capsule-a", FilePermission::Read)
            .is_allowed());

        let removed = sb.deny(CapsuleId(1), "/data/capsule-a");
        assert!(removed);

        let result = sb.evaluate(CapsuleId(1), "/data/capsule-a", FilePermission::Read);
        assert!(result.is_denied());
    }

    #[test]
    fn deny_nonexistent_rule_returns_false() {
        let mut sb = StateSandbox::new();
        assert!(!sb.deny(CapsuleId(1), "/nonexistent"));
    }

    #[test]
    fn deny_only_affects_specified_path() {
        let mut sb = StateSandbox::new();
        sb.allow(CapsuleId(1), "/data/a".into(), vec![FilePermission::Read]);
        sb.allow(CapsuleId(1), "/data/b".into(), vec![FilePermission::Read]);

        sb.deny(CapsuleId(1), "/data/a");
        assert_eq!(sb.rule_count(), 1);
        assert!(sb
            .evaluate(CapsuleId(1), "/data/a", FilePermission::Read)
            .is_denied());
        assert!(sb
            .evaluate(CapsuleId(1), "/data/b", FilePermission::Read)
            .is_allowed());
    }

    // -----------------------------------------------------------------------
    // INV-SS-004: Violation recording
    // -----------------------------------------------------------------------

    #[test]
    fn denied_access_records_violation() {
        let mut sb = StateSandbox::new();
        assert_eq!(sb.violation_count(), 0);

        let _ = sb.evaluate(CapsuleId(1), "/secret.txt", FilePermission::Read);
        assert_eq!(sb.violation_count(), 1);

        let violations = sb.get_violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].capsule_id, CapsuleId(1));
        assert_eq!(violations[0].target_path, "/secret.txt");
        assert_eq!(violations[0].operation, FilePermission::Read);
        assert!(!violations[0].reason.is_empty());
    }

    #[test]
    fn violations_accumulate_across_evaluations() {
        let mut sb = StateSandbox::new();

        let _ = sb.evaluate(CapsuleId(1), "/a", FilePermission::Read);
        let _ = sb.evaluate(CapsuleId(2), "/b", FilePermission::Write);
        let _ = sb.evaluate(CapsuleId(3), "/c", FilePermission::Execute);

        assert_eq!(sb.violation_count(), 3);
    }

    #[test]
    fn clear_violations_resets_counter() {
        let mut sb = StateSandbox::new();
        let _ = sb.evaluate(CapsuleId(1), "/a", FilePermission::Read);
        assert_eq!(sb.violation_count(), 1);

        sb.clear_violations();
        assert_eq!(sb.violation_count(), 0);
        assert!(sb.get_violations().is_empty());
    }

    // -----------------------------------------------------------------------
    // INV-SS-005: Per-capsule isolation
    // -----------------------------------------------------------------------

    #[test]
    fn capsule_does_not_see_rules_for_other_capsules() {
        let mut sb = StateSandbox::new();
        sb.allow(
            CapsuleId(1),
            "/data/capsule-a".into(),
            vec![FilePermission::Read],
        );

        // Capsule 2 should NOT be able to access Capsule 1's path.
        let result = sb.evaluate(CapsuleId(2), "/data/capsule-a", FilePermission::Read);
        assert!(result.is_denied());
    }

    #[test]
    fn each_capsule_needs_its_own_rules() {
        let mut sb = StateSandbox::new();
        sb.allow(CapsuleId(1), "/data/a".into(), vec![FilePermission::Read]);
        sb.allow(CapsuleId(2), "/data/b".into(), vec![FilePermission::Read]);

        assert!(sb
            .evaluate(CapsuleId(1), "/data/a", FilePermission::Read)
            .is_allowed());
        assert!(sb
            .evaluate(CapsuleId(2), "/data/b", FilePermission::Read)
            .is_allowed());

        assert!(sb
            .evaluate(CapsuleId(1), "/data/b", FilePermission::Read)
            .is_denied());
        assert!(sb
            .evaluate(CapsuleId(2), "/data/a", FilePermission::Read)
            .is_denied());
    }

    // -----------------------------------------------------------------------
    // FileAccessRule tests
    // -----------------------------------------------------------------------

    #[test]
    fn rule_permits_properly() {
        let rule = FileAccessRule::new(
            CapsuleId(1),
            "/data/file.txt".into(),
            vec![FilePermission::Read, FilePermission::Write],
        );
        assert!(rule.permits("/data/file.txt", FilePermission::Read));
        assert!(rule.permits("/data/file.txt", FilePermission::Write));
        assert!(!rule.permits("/data/file.txt", FilePermission::Execute));
        assert!(!rule.permits("/other/file.txt", FilePermission::Read));
        assert!(rule.covers_path("/data/file.txt"));
        assert!(!rule.covers_path("/other.txt"));
        assert!(rule.covers_capsule(CapsuleId(1)));
        assert!(!rule.covers_capsule(CapsuleId(2)));
    }

    // -----------------------------------------------------------------------
    // Rule replacement on re-allow
    // -----------------------------------------------------------------------

    #[test]
    fn re_allow_replaces_existing_rule() {
        let mut sb = StateSandbox::new();
        sb.allow(CapsuleId(1), "/data/f".into(), vec![FilePermission::Read]);
        assert_eq!(sb.rule_count(), 1);

        sb.allow(
            CapsuleId(1),
            "/data/f".into(),
            vec![FilePermission::Read, FilePermission::Write],
        );
        assert_eq!(sb.rule_count(), 1);

        let result = sb.evaluate(CapsuleId(1), "/data/f", FilePermission::Write);
        assert!(result.is_allowed());
    }

    // -----------------------------------------------------------------------
    // StateSandbox::find_rule / rules_for_capsule / iter_rules
    // -----------------------------------------------------------------------

    #[test]
    fn find_rule_retrieves_existing_rule() {
        let mut sb = StateSandbox::new();
        sb.allow(CapsuleId(1), "/data/f".into(), vec![FilePermission::Read]);
        let rule = sb.find_rule(CapsuleId(1), "/data/f");
        assert!(rule.is_some());
        assert_eq!(rule.map(|r| r.target_path.as_str()), Some("/data/f"));
    }

    #[test]
    fn find_rule_returns_none_for_missing() {
        let sb = StateSandbox::new();
        assert!(sb.find_rule(CapsuleId(1), "/data/f").is_none());
    }

    #[test]
    fn rules_for_capsule_filters_by_capsule() {
        let mut sb = StateSandbox::new();
        sb.allow(CapsuleId(1), "/a".into(), vec![FilePermission::Read]);
        sb.allow(CapsuleId(1), "/b".into(), vec![FilePermission::Read]);
        sb.allow(CapsuleId(2), "/c".into(), vec![FilePermission::Read]);

        let rules_a = sb.rules_for_capsule(CapsuleId(1));
        assert_eq!(rules_a.len(), 2);
        let rules_b = sb.rules_for_capsule(CapsuleId(2));
        assert_eq!(rules_b.len(), 1);
        let rules_c = sb.rules_for_capsule(CapsuleId(3));
        assert!(rules_c.is_empty());
    }

    // -----------------------------------------------------------------------
    // evaluate_logged (permissive-domain auditing)
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_logged_returns_allowed_for_existing_rule() {
        let mut sb = StateSandbox::new();
        sb.allow(CapsuleId(1), "/data/f".into(), vec![FilePermission::Read]);
        let result = sb.evaluate_logged(
            CapsuleId(1),
            "/data/f",
            FilePermission::Read,
            "audit-trail-id-1",
        );
        assert!(result.is_allowed());
    }

    #[test]
    fn evaluate_logged_returns_logged_only_for_missing_rule() {
        let sb = StateSandbox::new();
        let result = sb.evaluate_logged(
            CapsuleId(1),
            "/secret",
            FilePermission::Read,
            "permissive-domain-A",
        );
        assert!(!result.is_allowed());
        assert!(!result.is_denied());
        match result {
            AccessDecision::LoggedOnly { reason } => {
                assert_eq!(reason, "permissive-domain-A");
            }
            _ => panic!("expected LoggedOnly"),
        }
    }

    // -----------------------------------------------------------------------
    // CapsuleStateRoot tests (R3-W2)
    // -----------------------------------------------------------------------

    #[test]
    fn r3w2_state_root_from_capsule_id_uses_convention() {
        let id = CapsuleId(7);
        let root = CapsuleStateRoot::from_capsule_id(id);
        assert_eq!(root.capsule_id, id);
        assert_eq!(root.root_path, PathBuf::from("/capsule/7"));
    }

    #[test]
    fn r3w2_state_root_with_base_joins_correctly() {
        let id = CapsuleId(42);
        let root = CapsuleStateRoot::with_base(id, "/tmp/test-capsules");
        assert_eq!(root.root_path, PathBuf::from("/tmp/test-capsules/42"));
    }

    #[test]
    fn r3w2_state_root_contains_detects_subpath() {
        let root = CapsuleStateRoot::with_base(CapsuleId(1), "/capsule");
        assert!(root.contains(Path::new("/capsule/1/data.txt")));
        assert!(root.contains(Path::new("/capsule/1/sub/deep/file")));
        assert!(!root.contains(Path::new("/capsule/2/secrets.txt")));
        assert!(!root.contains(Path::new("/tmp/other")));
    }

    #[test]
    fn r3w2_capsule_id_from_path_parses_correctly() {
        assert_eq!(
            CapsuleStateRoot::capsule_id_from_path(Path::new("/capsule/7/data.txt")),
            Some(CapsuleId(7))
        );
        assert_eq!(
            CapsuleStateRoot::capsule_id_from_path(Path::new("/capsule/42/sub/file")),
            Some(CapsuleId(42))
        );
        assert_eq!(
            CapsuleStateRoot::capsule_id_from_path(Path::new("/other/path")),
            None
        );
        assert_eq!(
            CapsuleStateRoot::capsule_id_from_path(Path::new("/capsule/not-a-number/file")),
            None
        );
    }

    // -----------------------------------------------------------------------
    // R3-W2: check_access / StateSandbox::with_root isolation tests
    // -----------------------------------------------------------------------

    #[test]
    fn r3w2_same_capsule_access_allowed() {
        let id = CapsuleId(7);
        let root = CapsuleStateRoot::with_base(id, "/capsule");
        let mut sandbox = StateSandbox::with_root(id, root);

        assert!(sandbox
            .check_access(id, "/capsule/7/data.txt", AccessMode::ReadOnly)
            .is_ok());
        assert!(sandbox
            .check_access(id, "/capsule/7/models/weights.bin", AccessMode::ReadWrite)
            .is_ok());
        assert!(sandbox
            .check_access(id, "/capsule/7", AccessMode::ReadOnly)
            .is_ok());

        assert_eq!(sandbox.violation_count(), 0);
    }

    #[test]
    fn r3w2_cross_capsule_access_denied() {
        let id_a = CapsuleId(7);
        let id_b = CapsuleId(8);
        let root = CapsuleStateRoot::with_base(id_a, "/capsule");
        let mut sandbox = StateSandbox::with_root(id_a, root);

        let result = sandbox.check_access(id_b, "/capsule/7/data.txt", AccessMode::ReadOnly);
        assert!(result.is_err());
        assert_eq!(sandbox.violation_count(), 1);
    }

    #[test]
    fn r3w2_cross_capsule_write_also_denied() {
        let id_a = CapsuleId(1);
        let id_b = CapsuleId(2);
        let root = CapsuleStateRoot::with_base(id_a, "/capsule");
        let mut sandbox = StateSandbox::with_root(id_a, root);

        let result = sandbox.check_access(id_b, "/capsule/1/log.txt", AccessMode::ReadWrite);
        assert!(result.is_err());
        assert_eq!(sandbox.violation_count(), 1);
    }

    #[test]
    fn r3w2_deny_mode_always_rejected() {
        let id = CapsuleId(7);
        let root = CapsuleStateRoot::with_base(id, "/capsule");
        let mut sandbox = StateSandbox::with_root(id, root);

        let result = sandbox.check_access(id, "/capsule/7/data.txt", AccessMode::Deny);
        assert!(result.is_err());
        assert_eq!(sandbox.violation_count(), 1);
    }

    #[test]
    fn r3w2_path_outside_own_root_is_denied_for_write() {
        let id = CapsuleId(7);
        let root = CapsuleStateRoot::with_base(id, "/capsule");
        let mut sandbox = StateSandbox::with_root(id, root);

        let result = sandbox.check_access(id, "/capsule/8/secrets.txt", AccessMode::ReadWrite);
        assert!(result.is_err());
        assert_eq!(sandbox.violation_count(), 1);
    }

    #[test]
    fn r3w2_explicit_deny_list_blocks_contained_paths() {
        let id = CapsuleId(7);
        let root = CapsuleStateRoot::with_base(id, "/capsule");
        let mut sandbox = StateSandbox::with_root(id, root);

        sandbox.deny_path("/capsule/7/secrets");

        let result = sandbox.check_access(id, "/capsule/7/secrets/key.pem", AccessMode::ReadOnly);
        assert!(result.is_err());
        assert_eq!(sandbox.violation_count(), 1);

        assert!(sandbox
            .check_access(id, "/capsule/7/data.txt", AccessMode::ReadOnly)
            .is_ok());
        assert_eq!(sandbox.violation_count(), 1);
    }

    #[test]
    fn r3w2_violation_recording_in_check_access() {
        let id = CapsuleId(7);
        let root = CapsuleStateRoot::with_base(id, "/capsule");
        let mut sandbox = StateSandbox::with_root(id, root);

        let _ = sandbox.check_access(CapsuleId(99), "/capsule/7/evil", AccessMode::ReadWrite);

        let violations = sandbox.get_violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].capsule_id, CapsuleId(99));
    }

    #[test]
    fn r3w2_multi_capsule_isolation() {
        let id_a = CapsuleId(100);
        let id_b = CapsuleId(200);

        let root_a = CapsuleStateRoot::with_base(id_a, "/capsule");
        let root_b = CapsuleStateRoot::with_base(id_b, "/capsule");

        let mut sandbox_a = StateSandbox::with_root(id_a, root_a);
        let mut sandbox_b = StateSandbox::with_root(id_b, root_b);

        assert!(sandbox_a
            .check_access(id_a, "/capsule/100/file.txt", AccessMode::ReadWrite)
            .is_ok());
        assert!(sandbox_b
            .check_access(id_b, "/capsule/200/file.txt", AccessMode::ReadWrite)
            .is_ok());

        assert!(sandbox_a
            .check_access(id_a, "/capsule/200/file.txt", AccessMode::ReadOnly)
            .is_err());
        assert!(sandbox_b
            .check_access(id_b, "/capsule/100/file.txt", AccessMode::ReadOnly)
            .is_err());

        assert!(sandbox_a
            .check_access(id_b, "/capsule/100/file.txt", AccessMode::ReadOnly)
            .is_err());

        assert_eq!(sandbox_a.violation_count(), 2);
        assert_eq!(sandbox_b.violation_count(), 1);
    }

    #[test]
    fn r3w2_access_mode_display() {
        assert_eq!(format!("{}", AccessMode::ReadOnly), "read-only");
        assert_eq!(format!("{}", AccessMode::ReadWrite), "read-write");
        assert_eq!(format!("{}", AccessMode::Deny), "deny");
    }
}
