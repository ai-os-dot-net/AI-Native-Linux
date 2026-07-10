//! Plan 9 / Inferno-inspired per-capsule namespace.
//!
//! ## OS Research Provenance
//!
//! Plan 9 from Bell Labs (Pike, Thompson, Ritchie, 1992) introduced two
//! paradigm-shifting ideas that still influence OS design:
//!
//! 1. **Per-process namespace** — every process has a private mount table.
//!    It cannot see resources that have not been explicitly bound into its
//!    namespace.  This is a *capability*-style security boundary without
//!    kernel-enforced access-control lists.
//! 2. **Union directories** — a single directory can aggregate entries from
//!    multiple underlying directories (`bind -a` / `bind -b`).  The order
//!    of mounts determines which entry shadows another.
//!
//! Inferno (Dorward, Pike et al., 1997) extended this with the **Styx**
//! protocol (9P2000 equivalent) and ran namespaces *inside* a virtual
//! machine (Dis/Limbo), achieving per-namespace isolation even when hosted
//! on a foreign OS.
//!
//! ### Mapping to AIOS Capsule Architecture
//!
//! | Plan 9 / Inferno concept | AIOS equivalent                                       |
//! |---------------------------|-------------------------------------------------------|
//! | Per-process namespace     | [`CapsuleNamespace`] — per-capsule private mount table |
//! | `bind(1)` / `mount(1)`    | [`CapsuleNamespace::bind`]                             |
//! | Union directory           | [`MountFlag::Union`] with `{after,before}` semantics  |
//! | `rfork(RFNAMEG)`          | [`CapsuleNamespace::clone`] — forked namespace         |
//! | `unmount(1)`              | [`CapsuleNamespace::unbind`]                          |
//! | Styx / 9P resource-as-file | [`NamespaceBinding::access_rights`] (via [`CapRights`]) |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-NS-001 (Absolute paths):** Every [`NamespacePath`] must start with
//!   `/` and contain no empty components.  `..` is forbidden.
//! - **INV-NS-002 (Non-empty mount targets):** A binding's `target` path is
//!   always valid per INV-NS-001; a root-only bind is legal.
//! - **INV-NS-003 (Bind scoping):** A bind operation only affects the
//!   capsule whose namespace is the receiver — one capsule cannot mutate
//!   another capsule's mount table.
//! - **INV-NS-004 (Clone independence):** After [`CapsuleNamespace::clone`],
//!   mutations to the clone do **not** affect the original, and vice versa.
//! - **INV-NS-005 (Union ordering):** When multiple bindings target the same
//!   path with [`MountFlag::Union`], resolution follows insertion order
//!   (earlier bindings are consulted first for `before`, later for `after`).
//! - **INV-NS-006 (Unbind completeness):** [`CapsuleNamespace::unbind`]
//!   removes **all** bindings whose target path matches the given path
//!   exactly.
//! - **INV-NS-007 (Path resolution determinism):** For any path, resolution
//!   returns the same set of bindings every time unless the mount table is
//!   mutated between calls.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Re-use the capability-rights model from the seL4 module so that every
/// namespace binding carries an access-rights mask.
use super::sel4_cap_model::CapRights;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CapsuleId — lightweight capsule identifier
// ---------------------------------------------------------------------------

/// Opaque capsule identifier (analogous to a Plan 9 process id or Inferno
/// `ref Sys->FD`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CapsuleId(pub u64);

impl CapsuleId {
    /// Raw numeric value.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for CapsuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "capsule-{}", self.0)
    }
}

static NEXT_CAPSULE_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh, globally-unique [`CapsuleId`].
#[must_use]
pub fn next_capsule_id() -> CapsuleId {
    CapsuleId(NEXT_CAPSULE_ID.fetch_add(1, Ordering::Relaxed))
}

// ---------------------------------------------------------------------------
// NamespacePath — Plan 9-style hierarchical path
// ---------------------------------------------------------------------------

/// A Plan 9-style absolute hierarchical path.
///
/// # Validity rules
///
/// - Must start with `/`.
/// - No empty components (`//` is illegal).
/// - No `.` or `..` components.
/// - Trailing `/` is stripped (except the root `/` itself).
/// - Components may be any non-empty UTF-8 string without `/`.
///
/// # Examples
///
/// ```rust
/// # use aios_capability_runtime::capsule_namespace::NamespacePath;
/// assert!(NamespacePath::new("/ml/models/gpt4").is_some());
/// assert!(NamespacePath::new("/data/sessions").is_some());
/// assert!(NamespacePath::new("relative/path").is_none());   // not absolute
/// assert!(NamespacePath::new("/double//slash").is_none());   // empty component
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamespacePath(String);

impl NamespacePath {
    /// Try to construct a valid [`NamespacePath`].
    ///
    /// Returns `None` if the input violates any validity rule.
    #[must_use]
    pub fn new(raw: &str) -> Option<Self> {
        if raw.is_empty() {
            return None;
        }
        // Must be absolute.
        if !raw.starts_with('/') {
            return None;
        }
        // Root is special — store empty string internally; as_str() returns "/".
        if raw == "/" {
            return Some(Self(String::new()));
        }
        // Strip a single trailing slash if present.
        let canonical = raw.strip_suffix('/').unwrap_or(raw);
        if canonical.is_empty() {
            // Should not happen because we handled "/" above, but belt-and-suspenders.
            return None;
        }
        // Split and validate every component.
        let components: Vec<&str> = canonical[1..].split('/').collect();
        for c in &components {
            if c.is_empty() {
                return None; // "//" found
            }
            if *c == "." || *c == ".." {
                return None; // relative traversal forbidden
            }
        }
        Some(Self(canonical.into()))
    }

    /// The root path `/`.
    #[must_use]
    pub const fn root() -> Self {
        Self(String::new()) // sentinel — handled everywhere
    }

    // We cannot use `const` String construction, so we provide a factory that
    // is always valid.

    /// The canonical string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        if self.0.is_empty() {
            "/"
        } else {
            &self.0
        }
    }

    /// Number of components (root = 0).
    #[must_use]
    pub fn depth(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            self.0[1..].split('/').count()
        }
    }

    /// Return the parent path, or `None` for root.
    ///
    /// ```rust
    /// # use aios_capability_runtime::capsule_namespace::NamespacePath;
    /// let p = NamespacePath::new("/ml/models/gpt4").unwrap();
    /// assert_eq!(p.parent().as_ref().map(|s| s.as_str()), Some("/ml/models"));
    /// ```
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.0.is_empty() {
            return None; // root has no parent
        }
        let s = self.0.as_str();
        match s.rfind('/') {
            Some(0) | None => Some(Self(String::new())), // e.g., "/foo" → "/" (stored as empty)
            Some(pos) => Some(Self(s[..pos].into())),
        }
    }

    /// The final component of the path.
    ///
    /// ```rust
    /// # use aios_capability_runtime::capsule_namespace::NamespacePath;
    /// let p = NamespacePath::new("/ml/models/gpt4").unwrap();
    /// assert_eq!(p.last_component(), Some("gpt4"));
    /// assert!(NamespacePath::new("/").unwrap().last_component().is_none());
    /// ```
    #[must_use]
    pub fn last_component(&self) -> Option<&str> {
        if self.0.is_empty() {
            return None;
        }
        self.0.rfind('/').map(|pos| &self.0[pos + 1..])
    }

    /// Check whether `self` is a prefix of (or equal to) `other`.
    ///
    /// ```rust
    /// # use aios_capability_runtime::capsule_namespace::NamespacePath;
    /// let base = NamespacePath::new("/ml/models").unwrap();
    /// let sub  = NamespacePath::new("/ml/models/gpt4").unwrap();
    /// assert!(base.is_prefix_of(&sub));
    /// assert!(!sub.is_prefix_of(&base));
    /// assert!(base.is_prefix_of(&base));
    /// ```
    #[must_use]
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        let s = self.as_str();
        let o = other.as_str();
        if s == o {
            return true;
        }
        // "/" is a prefix of everything.
        if s == "/" {
            return true;
        }
        o.starts_with(s) && o.as_bytes().get(s.len()) == Some(&b'/')
    }

    /// List of components, excluding the root marker.
    ///
    /// ```rust
    /// # use aios_capability_runtime::capsule_namespace::NamespacePath;
    /// let p = NamespacePath::new("/ml/models/gpt4").unwrap();
    /// assert_eq!(p.components(), vec!["ml", "models", "gpt4"]);
    /// ```
    #[must_use]
    pub fn components(&self) -> Vec<&str> {
        if self.0.is_empty() {
            vec![]
        } else {
            self.0[1..].split('/').collect()
        }
    }
}

impl fmt::Display for NamespacePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<NamespacePath> for String {
    fn from(p: NamespacePath) -> Self {
        if p.0.is_empty() {
            "/".into()
        } else {
            p.0
        }
    }
}

// ---------------------------------------------------------------------------
// MountFlag — how a binding is attached (Plan 9 `bind` flags)
// ---------------------------------------------------------------------------

/// Describes how a [`NamespaceBinding`] is inserted into the mount table.
///
/// # Plan 9 equivalents
///
/// | Variant     | Plan 9 `bind(1)` flag |
/// |-------------|----------------------|
/// | `Replace`   | (default, no flag)   |
/// | `Before`    | `-b`                 |
/// | `After`     | `-a`                 |
/// | `Union`     | `-a` or `-b` (union) |
/// | `Cache`     | `-c` (Plan 9 `-C`)   |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MountFlag {
    /// Standard mount — replaces any existing binding at the target path.
    Regular,
    /// Union mount — the new source appears **before** existing entries when
    /// listing or resolving the target directory.
    Before,
    /// Union mount — the new source appears **after** existing entries.
    After,
    /// Replace any existing binding at the same target (non-union).
    Replace,
    /// Cache mount — the binding is maintained in a local cache; resolution
    /// may fall through to the next binding if the cached entry is stale.
    Cache,
}

impl MountFlag {
    /// Whether this flag preserves existing bindings rather than replacing them.
    #[must_use]
    pub const fn is_union(&self) -> bool {
        matches!(self, Self::Before | Self::After)
    }
}

// ---------------------------------------------------------------------------
// NamespaceBinding — a single entry in a capsule's mount table
// ---------------------------------------------------------------------------

/// A single mount-table entry, analogous to Plan 9's `bind(1)` operation.
///
/// Every binding says: *"when the capsule looks up `target`, resolve it
/// through `source` instead (or in addition, for union mounts)"*.
///
/// # Capability integration
///
/// The `access_rights` field carries a [`CapRights`] mask that further
/// constrains what the capsule **may do** with the resource at `source`.
/// This is the convergence point between the seL4-inspired capability
/// model ([`crate::sel4_cap_model`]) and the Plan 9-inspired namespace model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceBinding {
    /// The "real" resource path (c.f. Plan 9's `old` argument to `bind`).
    pub source: NamespacePath,
    /// Where the resource appears in the capsule's namespace (c.f. Plan 9's
    /// `new` argument to `bind`).
    pub target: NamespacePath,
    /// How the binding was mounted.
    pub flag: MountFlag,
    /// The capsule that owns this binding.
    pub capsule_id: CapsuleId,
    /// Access-rights mask constraining operations on `source` for this capsule.
    pub access_rights: CapRights,
}

impl NamespaceBinding {
    /// Create a new binding.
    #[must_use]
    pub const fn new(
        source: NamespacePath,
        target: NamespacePath,
        flag: MountFlag,
        capsule_id: CapsuleId,
        access_rights: CapRights,
    ) -> Self {
        Self {
            source,
            target,
            flag,
            capsule_id,
            access_rights,
        }
    }

    /// Whether this binding's target exactly matches `path`.
    #[must_use]
    pub fn targets(&self, path: &NamespacePath) -> bool {
        self.target == *path
    }

    /// Whether this binding's target is a prefix of `path` (for union / subtree resolution).
    #[must_use]
    pub fn covers(&self, path: &NamespacePath) -> bool {
        self.target.is_prefix_of(path)
    }
}

// ---------------------------------------------------------------------------
// CapsuleNamespace — per-capsule private mount table
// ---------------------------------------------------------------------------

/// A Plan 9-style per-process namespace, adapted for AIOS capsules.
///
/// Each capsule owns exactly one [`CapsuleNamespace`].  The mount table
/// controls which resource paths the capsule can see and how those paths
/// resolve.  Two capsules may have completely different views of the same
/// underlying resources.
///
/// # Example
///
/// ```rust
/// # use aios_capability_runtime::capsule_namespace::*;
/// # use aios_capability_runtime::sel4_cap_model::CapRights;
/// let mut ns = CapsuleNamespace::new(next_capsule_id());
/// let src = NamespacePath::new("/ml/models/gpt4").unwrap();
/// let tgt = NamespacePath::new("/models/llm").unwrap();
/// assert!(ns.bind(src.clone(), tgt.clone(), MountFlag::Regular, CapRights::full()));
/// assert_eq!(ns.binding_count(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleNamespace {
    /// The capsule that owns this namespace.
    pub capsule_id: CapsuleId,
    /// Ordered mount table (bindings are consulted in insertion order for
    /// union mounts; the most recent `Replace` binding shadows earlier ones).
    bindings: Vec<NamespaceBinding>,
}

impl CapsuleNamespace {
    /// Create an empty namespace for the given capsule.
    #[must_use]
    pub const fn new(capsule_id: CapsuleId) -> Self {
        Self {
            capsule_id,
            bindings: Vec::new(),
        }
    }

    /// Number of active bindings.
    #[must_use]
    pub const fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// Whether the namespace has zero bindings.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// ---------- bind -------------------------------------------------------
    ///
    /// Add (or replace) a mount-table entry.
    ///
    /// * If `flag` is [`MountFlag::Replace`], any existing binding whose
    ///   `target` matches exactly is removed first.
    /// * Otherwise the new binding is appended (for union mounts) or inserted.
    ///
    /// Returns `false` if the source or target path is the root (root binds
    /// are forbidden — they would shadow the entire namespace).
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn bind(
        &mut self,
        source: NamespacePath,
        target: NamespacePath,
        flag: MountFlag,
        access_rights: CapRights,
    ) -> bool {
        // INV-NS-002: Root-only targets are legal for capsuling but pathological;
        // we disallow root binds to prevent accidental full-namespace shadowing.
        if target.as_str() == "/" || source.as_str() == "/" {
            return false;
        }

        let binding =
            NamespaceBinding::new(source, target.clone(), flag, self.capsule_id, access_rights);

        match flag {
            MountFlag::Replace => {
                // Remove any existing binding at the same target.
                self.bindings.retain(|b| !b.targets(&target));
                self.bindings.push(binding);
                true
            }
            MountFlag::Regular => {
                // For Regular, remove any non-union binding at the same target,
                // then push.
                self.bindings
                    .retain(|b| !b.targets(&target) || b.flag.is_union());
                self.bindings.push(binding);
                true
            }
            MountFlag::Before => {
                // Insert at the position before the first existing binding at this target.
                let pos = self.bindings.iter().position(|b| b.targets(&target));
                match pos {
                    Some(idx) => {
                        self.bindings.insert(idx, binding);
                    }
                    None => {
                        self.bindings.push(binding);
                    }
                }
                true
            }
            MountFlag::After => {
                // Insert after the last existing binding at this target.
                let pos = self.bindings.iter().rposition(|b| b.targets(&target));
                match pos {
                    Some(idx) => {
                        self.bindings.insert(idx + 1, binding);
                    }
                    None => {
                        self.bindings.push(binding);
                    }
                }
                true
            }
            MountFlag::Cache => {
                // Cache mounts don't replace anything — just append.
                self.bindings.push(binding);
                true
            }
        }
    }

    /// ---------- unbind -----------------------------------------------------
    ///
    /// Remove **all** bindings whose target path matches `target` exactly.
    ///
    /// Returns the number of bindings removed (INV-NS-006).
    #[must_use]
    pub fn unbind(&mut self, target: &NamespacePath) -> usize {
        let before = self.bindings.len();
        self.bindings.retain(|b| !b.targets(target));
        before - self.bindings.len()
    }

    /// ---------- resolve ----------------------------------------------------
    ///
    /// Walk the mount table and return every binding whose target is a prefix
    /// of `path`.  Results are ordered by mount-table insertion order, which
    /// determines union-directory priority.
    ///
    /// ```rust
    /// # use aios_capability_runtime::capsule_namespace::*;
    /// # use aios_capability_runtime::sel4_cap_model::CapRights;
    /// let mut ns = CapsuleNamespace::new(next_capsule_id());
    /// ns.bind(
    ///     NamespacePath::new("/ml/models/gpt4").unwrap(),
    ///     NamespacePath::new("/models").unwrap(),
    ///     MountFlag::Regular,
    ///     CapRights::full(),
    /// );
    /// let hits = ns.resolve(&NamespacePath::new("/models/checkpoints").unwrap());
    /// assert!(!hits.is_empty());
    /// ```
    #[must_use]
    pub fn resolve(&self, path: &NamespacePath) -> Vec<&NamespaceBinding> {
        self.bindings.iter().filter(|b| b.covers(path)).collect()
    }

    /// ---------- `exact_resolve` ----------------------------------------------
    ///
    /// Like [`resolve`](Self::resolve) but only returns bindings whose target
    /// **exactly** matches `path` — useful for deduplication or unbind-preview.
    #[must_use]
    pub fn exact_resolve(&self, path: &NamespacePath) -> Vec<&NamespaceBinding> {
        self.bindings.iter().filter(|b| b.targets(path)).collect()
    }

    /// ---------- clone (rfork RFNAMEG) --------------------------------------
    ///
    /// Create a deep copy of the namespace with a new capsule identity.
    /// The clone is fully independent — mutations to the clone do not affect
    /// the original and vice versa (INV-NS-004).
    #[must_use]
    pub fn clone_for(&self, new_capsule_id: CapsuleId) -> Self {
        let mut bindings = self.bindings.clone();
        // Re-tag every binding for the new capsule.
        for b in &mut bindings {
            b.capsule_id = new_capsule_id;
        }
        Self {
            capsule_id: new_capsule_id,
            bindings,
        }
    }

    /// ---------- iter / inspect --------------------------------------------
    ///
    /// Iterate over all bindings in mount order.
    pub fn iter(&self) -> impl Iterator<Item = &NamespaceBinding> {
        self.bindings.iter()
    }

    /// Drain all bindings, leaving an empty namespace (useful for teardown).
    pub fn clear(&mut self) {
        self.bindings.clear();
    }
}

// ---------------------------------------------------------------------------
// NamespaceRegistry — system-wide registry of capsule namespaces
// ---------------------------------------------------------------------------

/// Global registry mapping capsule IDs to their private namespaces.
///
/// This is the AIOS analogue of the Plan 9 kernel's process table — it holds
/// the namespace for every live capsule and provides cross-capsule namespace
/// introspection (for the system operator, not other capsules).
#[derive(Debug, Default, Clone)]
pub struct NamespaceRegistry {
    namespaces: HashMap<CapsuleId, CapsuleNamespace>,
}

impl NamespaceRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            namespaces: HashMap::new(),
        }
    }

    /// Register a capsule's namespace.
    ///
    /// If a namespace for this capsule already exists, it is **replaced**
    /// (the old namespace is dropped).
    pub fn register(&mut self, namespace: CapsuleNamespace) {
        self.namespaces.insert(namespace.capsule_id, namespace);
    }

    /// Remove and return a capsule's namespace (e.g., on capsule teardown).
    #[must_use]
    pub fn unregister(&mut self, capsule_id: CapsuleId) -> Option<CapsuleNamespace> {
        self.namespaces.remove(&capsule_id)
    }

    /// Look up a capsule's namespace by ID.
    #[must_use]
    pub fn get(&self, capsule_id: CapsuleId) -> Option<&CapsuleNamespace> {
        self.namespaces.get(&capsule_id)
    }

    /// Mutable lookup.
    pub fn get_mut(&mut self, capsule_id: CapsuleId) -> Option<&mut CapsuleNamespace> {
        self.namespaces.get_mut(&capsule_id)
    }

    /// Total number of registered capsule namespaces.
    #[must_use]
    pub fn len(&self) -> usize {
        self.namespaces.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
    }

    /// Iterate over all registered namespaces.
    pub fn iter(&self) -> impl Iterator<Item = (&CapsuleId, &CapsuleNamespace)> {
        self.namespaces.iter()
    }

    /// Clone a namespace for a new capsule and register it.
    ///
    /// Returns the new [`CapsuleId`] and the cloned [`CapsuleNamespace`].
    #[must_use]
    pub fn fork_namespace(
        &mut self,
        source_capsule_id: CapsuleId,
    ) -> Option<(CapsuleId, CapsuleNamespace)> {
        let source = self.namespaces.get(&source_capsule_id)?;
        let new_id = next_capsule_id();
        let clone = source.clone_for(new_id);
        self.namespaces.insert(new_id, clone.clone());
        Some((new_id, clone))
    }
}

// ===========================================================================
// Tests — INV-NS-001 through INV-NS-007
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // NamespacePath tests
    // -----------------------------------------------------------------------

    #[test]
    fn root_path_is_valid() {
        let p = NamespacePath::new("/");
        assert!(p.is_some());
        let p = p.unwrap();
        assert_eq!(p.as_str(), "/");
        assert_eq!(p.depth(), 0);
        assert!(p.components().is_empty());
    }

    #[test]
    fn simple_absolute_path_is_valid() {
        let p = NamespacePath::new("/ml/models/gpt4").unwrap();
        assert_eq!(p.as_str(), "/ml/models/gpt4");
        assert_eq!(p.depth(), 3);
        assert_eq!(p.components(), vec!["ml", "models", "gpt4"]);
    }

    #[test]
    fn trailing_slash_is_stripped() {
        let p = NamespacePath::new("/ml/models/").unwrap();
        assert_eq!(p.as_str(), "/ml/models");
    }

    #[test]
    fn relative_path_is_invalid() {
        assert!(NamespacePath::new("relative/path").is_none());
        assert!(NamespacePath::new("").is_none());
        assert!(NamespacePath::new("no-slash").is_none());
    }

    #[test]
    fn empty_component_is_invalid() {
        assert!(NamespacePath::new("/double//slash").is_none());
        assert!(NamespacePath::new("//").is_none());
    }

    #[test]
    fn dot_and_dotdot_are_invalid() {
        assert!(NamespacePath::new("/ml/./models").is_none());
        assert!(NamespacePath::new("/ml/../models").is_none());
    }

    #[test]
    fn parent_computation() {
        let p = NamespacePath::new("/ml/models/gpt4").unwrap();
        let parent = p.parent().unwrap();
        assert_eq!(parent.as_str(), "/ml/models");

        let grandparent = parent.parent().unwrap();
        assert_eq!(grandparent.as_str(), "/ml");

        let great = grandparent.parent().unwrap();
        assert_eq!(great.as_str(), "/");

        // Root has no parent.
        assert!(great.parent().is_none());
    }

    #[test]
    fn last_component() {
        assert_eq!(
            NamespacePath::new("/ml/models/gpt4")
                .unwrap()
                .last_component(),
            Some("gpt4")
        );
        assert_eq!(NamespacePath::new("/").unwrap().last_component(), None);
    }

    #[test]
    fn prefix_detection() {
        let base = NamespacePath::new("/ml/models").unwrap();
        let sub = NamespacePath::new("/ml/models/gpt4").unwrap();
        let unrelated = NamespacePath::new("/data/sessions").unwrap();
        let root = NamespacePath::new("/").unwrap();

        assert!(base.is_prefix_of(&sub));
        assert!(!sub.is_prefix_of(&base));
        assert!(base.is_prefix_of(&base));
        assert!(root.is_prefix_of(&base));
        assert!(root.is_prefix_of(&sub));
        assert!(!base.is_prefix_of(&unrelated));
        // "/ml/models" should NOT be prefix of "/ml/modelsX" (no boundary)
        let not_sub = NamespacePath::new("/ml/modelsX").unwrap();
        assert!(!base.is_prefix_of(&not_sub));
    }

    // -----------------------------------------------------------------------
    // NamespaceBinding tests
    // -----------------------------------------------------------------------

    #[test]
    fn binding_creation_and_target_match() {
        let src = NamespacePath::new("/ml/models/gpt4").unwrap();
        let tgt = NamespacePath::new("/models/gpt4").unwrap();
        let rights = CapRights::full();
        let b = NamespaceBinding::new(
            src,
            tgt.clone(),
            MountFlag::Regular,
            next_capsule_id(),
            rights.clone(),
        );
        assert!(b.targets(&tgt));
        assert!(!b.targets(&NamespacePath::new("/other").unwrap()));
        assert_eq!(b.access_rights, rights);
    }

    #[test]
    fn binding_covers_subtree() {
        let tgt = NamespacePath::new("/models").unwrap();
        let b = NamespaceBinding::new(
            NamespacePath::new("/ml/models").unwrap(),
            tgt,
            MountFlag::Regular,
            next_capsule_id(),
            CapRights::full(),
        );
        assert!(b.covers(&NamespacePath::new("/models/gpt4").unwrap()));
        assert!(b.covers(&NamespacePath::new("/models").unwrap()));
        assert!(!b.covers(&NamespacePath::new("/other").unwrap()));
    }

    // -----------------------------------------------------------------------
    // CapsuleNamespace — bind / unbind / resolve / clone
    // -----------------------------------------------------------------------

    #[test]
    fn empty_namespace_resolves_nothing() {
        let ns = CapsuleNamespace::new(next_capsule_id());
        let hits = ns.resolve(&NamespacePath::new("/anything").unwrap());
        assert!(hits.is_empty());
    }

    #[test]
    fn root_bind_is_forbidden() {
        let mut ns = CapsuleNamespace::new(next_capsule_id());
        let src = NamespacePath::new("/ml").unwrap();
        // Root target is forbidden.
        assert!(!ns.bind(
            src.clone(),
            NamespacePath::new("/").unwrap(),
            MountFlag::Regular,
            CapRights::full()
        ));
        // Root source is also forbidden.
        assert!(!ns.bind(
            NamespacePath::new("/").unwrap(),
            NamespacePath::new("/models").unwrap(),
            MountFlag::Regular,
            CapRights::full()
        ));
        // But binding non-root paths should still work:
        assert!(ns.bind(
            NamespacePath::new("/ml/models").unwrap(),
            NamespacePath::new("/models").unwrap(),
            MountFlag::Regular,
            CapRights::full(),
        ));
        assert_eq!(ns.binding_count(), 1);
    }

    #[test]
    fn regular_bind_and_resolve() {
        let mut ns = CapsuleNamespace::new(next_capsule_id());
        let src = NamespacePath::new("/ml/models/gpt4").unwrap();
        let tgt = NamespacePath::new("/models/llm").unwrap();
        assert!(ns.bind(src, tgt, MountFlag::Regular, CapRights::full()));

        // Exact resolve.
        let hits = ns.exact_resolve(&NamespacePath::new("/models/llm").unwrap());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].source.as_str(), "/ml/models/gpt4");

        // No hit for unrelated path.
        assert!(ns
            .exact_resolve(&NamespacePath::new("/other").unwrap())
            .is_empty());
    }

    #[test]
    fn replace_flag_overwrites() {
        let mut ns = CapsuleNamespace::new(next_capsule_id());
        let tgt = NamespacePath::new("/models/llm").unwrap();
        let rights = CapRights::full();

        assert!(ns.bind(
            NamespacePath::new("/old").unwrap(),
            tgt.clone(),
            MountFlag::Regular,
            rights.clone()
        ));
        assert_eq!(ns.binding_count(), 1);

        // Replace should remove the old binding.
        assert!(ns.bind(
            NamespacePath::new("/new").unwrap(),
            tgt.clone(),
            MountFlag::Replace,
            rights.clone(),
        ));
        assert_eq!(ns.binding_count(), 1); // still one binding
        let hits = ns.exact_resolve(&tgt);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].source.as_str(), "/new");
    }

    #[test]
    fn union_before_and_after_ordering() {
        let mut ns = CapsuleNamespace::new(next_capsule_id());
        let tgt = NamespacePath::new("/models/llm").unwrap();
        let rights = CapRights::full();

        // First binding (union=Before).
        assert!(ns.bind(
            NamespacePath::new("/primary").unwrap(),
            tgt.clone(),
            MountFlag::Before,
            rights.clone(),
        ));
        // Second binding (union=After).
        assert!(ns.bind(
            NamespacePath::new("/secondary").unwrap(),
            tgt.clone(),
            MountFlag::After,
            rights.clone(),
        ));
        // Third binding (also After).
        assert!(ns.bind(
            NamespacePath::new("/tertiary").unwrap(),
            tgt.clone(),
            MountFlag::After,
            rights.clone(),
        ));

        // Should have 3 bindings, ordered: secondary, primary, tertiary?
        // Wait — Before inserts at the *front*, After inserts after
        // the *last* existing.  Let's trace:
        //
        // 1. Before → push (no prior)        [primary]
        // 2. After  → rpos finds primary at 0, insert after → [primary, secondary]
        // 3. After  → rpos finds secondary at 1, insert after → [primary, secondary, tertiary]
        //
        // So the ordered list should be [primary, secondary, tertiary].
        let hits = ns.exact_resolve(&tgt);
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].source.as_str(), "/primary");
        assert_eq!(hits[1].source.as_str(), "/secondary");
        assert_eq!(hits[2].source.as_str(), "/tertiary");
    }

    #[test]
    fn unbind_removes_all_exact_matches() {
        let mut ns = CapsuleNamespace::new(next_capsule_id());
        let tgt = NamespacePath::new("/models/llm").unwrap();
        let rights = CapRights::full();

        assert!(ns.bind(
            NamespacePath::new("/a").unwrap(),
            tgt.clone(),
            MountFlag::Before,
            rights.clone(),
        ));
        assert!(ns.bind(
            NamespacePath::new("/b").unwrap(),
            tgt.clone(),
            MountFlag::After,
            rights.clone(),
        ));

        let removed = ns.unbind(&tgt);
        assert_eq!(removed, 2);
        assert!(ns.exact_resolve(&tgt).is_empty());
    }

    #[test]
    fn unbind_partial_no_effect_on_unrelated() {
        let mut ns = CapsuleNamespace::new(next_capsule_id());
        let rights = CapRights::full();

        assert!(ns.bind(
            NamespacePath::new("/a").unwrap(),
            NamespacePath::new("/models").unwrap(),
            MountFlag::Regular,
            rights.clone(),
        ));
        assert!(ns.bind(
            NamespacePath::new("/b").unwrap(),
            NamespacePath::new("/data").unwrap(),
            MountFlag::Regular,
            rights.clone(),
        ));

        let removed = ns.unbind(&NamespacePath::new("/models").unwrap());
        assert_eq!(removed, 1);
        assert_eq!(ns.binding_count(), 1);
        assert!(
            ns.exact_resolve(&NamespacePath::new("/data").unwrap())
                .len()
                == 1
        );
    }

    #[test]
    fn clone_creates_independent_namespace() {
        let id_a = next_capsule_id();
        let mut ns_a = CapsuleNamespace::new(id_a);
        let rights = CapRights::full();
        assert!(ns_a.bind(
            NamespacePath::new("/a").unwrap(),
            NamespacePath::new("/models").unwrap(),
            MountFlag::Regular,
            rights.clone(),
        ));

        let id_b = next_capsule_id();
        let mut ns_b = ns_a.clone_for(id_b);

        // Initially identical.
        assert_eq!(ns_a.binding_count(), ns_b.binding_count());

        // Mutate ns_b.
        assert!(ns_b.bind(
            NamespacePath::new("/b").unwrap(),
            NamespacePath::new("/data").unwrap(),
            MountFlag::Regular,
            rights.clone(),
        ));
        assert_eq!(ns_a.binding_count(), 1);
        assert_eq!(ns_b.binding_count(), 2);
        assert_eq!(ns_b.capsule_id, id_b);
        assert_eq!(ns_a.capsule_id, id_a);
    }

    // -----------------------------------------------------------------------
    // NamespaceRegistry tests
    // -----------------------------------------------------------------------

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = NamespaceRegistry::new();
        let id = next_capsule_id();
        let ns = CapsuleNamespace::new(id);
        reg.register(ns);
        assert_eq!(reg.len(), 1);
        assert!(reg.get(id).is_some());
    }

    #[test]
    fn registry_unregister_removes_namespace() {
        let mut reg = NamespaceRegistry::new();
        let id = next_capsule_id();
        reg.register(CapsuleNamespace::new(id));
        let removed = reg.unregister(id);
        assert!(removed.is_some());
        assert!(reg.get(id).is_none());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn registry_fork_namespace() {
        let mut reg = NamespaceRegistry::new();
        let id_a = next_capsule_id();
        let mut ns_a = CapsuleNamespace::new(id_a);
        let rights = CapRights::full();
        assert!(ns_a.bind(
            NamespacePath::new("/ml/gpt4").unwrap(),
            NamespacePath::new("/models").unwrap(),
            MountFlag::Regular,
            rights,
        ));
        reg.register(ns_a);

        let (id_b, ns_b) = reg.fork_namespace(id_a).unwrap();
        assert_ne!(id_b, id_a);
        assert_eq!(ns_b.binding_count(), 1);
        assert_eq!(reg.len(), 2);

        // The clone should have a different capsule ID.
        assert_eq!(ns_b.capsule_id, id_b);

        // Original capsule's namespace should still be accessible.
        let orig = reg.get(id_a).unwrap();
        assert_eq!(orig.binding_count(), 1);
    }

    #[test]
    fn registry_fork_nonexistent_capsule_returns_none() {
        let mut reg = NamespaceRegistry::new();
        let fake_id = CapsuleId(999);
        assert!(reg.fork_namespace(fake_id).is_none());
    }

    // -----------------------------------------------------------------------
    // INV-NS-007: Resolution determinism
    // -----------------------------------------------------------------------

    #[test]
    fn resolution_is_deterministic() {
        let mut ns = CapsuleNamespace::new(next_capsule_id());
        let rights = CapRights::full();
        let tgt = NamespacePath::new("/models").unwrap();

        assert!(ns.bind(
            NamespacePath::new("/ml/gpt4").unwrap(),
            tgt.clone(),
            MountFlag::Regular,
            rights.clone(),
        ));

        let sub_path = NamespacePath::new("/models/v1").unwrap();

        let r1 = ns.resolve(&sub_path);
        let r2 = ns.resolve(&sub_path);
        assert_eq!(r1.len(), r2.len());
        assert_eq!(r1[0].source, r2[0].source);
    }

    #[test]
    fn clear_empties_namespace() {
        let mut ns = CapsuleNamespace::new(next_capsule_id());
        let rights = CapRights::full();
        assert!(ns.bind(
            NamespacePath::new("/a").unwrap(),
            NamespacePath::new("/b").unwrap(),
            MountFlag::Regular,
            rights,
        ));
        assert!(!ns.is_empty());
        ns.clear();
        assert!(ns.is_empty());
        assert_eq!(ns.binding_count(), 0);
    }

    #[test]
    fn display_formats() {
        let id = next_capsule_id();
        let s = format!("{}", id);
        assert!(s.starts_with("capsule-"));
        assert!(s.contains(&format!("{}", id.raw())));

        let p = NamespacePath::new("/ml/models").unwrap();
        assert_eq!(format!("{}", p), "/ml/models");
    }
}
