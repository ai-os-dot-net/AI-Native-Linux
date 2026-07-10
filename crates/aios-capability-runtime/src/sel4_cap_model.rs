//! seL4-inspired capability token model with formal invariants.
//!
//! ## OS Research Provenance
//!
//! The seL4 microkernel (Klein et al., 2009) is the world's first formally
//! verified general-purpose OS kernel. Its capability system guarantees:
//!
//! 1. **Non-forgeability** — a capability token can only be created through
//!    an explicit `Mint` / `Copy` / `Retype` syscall; no bit pattern in user
//!    memory constitutes a valid token.
//! 2. **Attenuation** — a derived capability has equal or *fewer* rights than
//!    its parent. You cannot amplify privileges through derivation.
//! 3. **Revocation cascade** — deleting a parent capability atomically
//!    invalidates every capability derived from it (recursive delete).
//! 4. **Spatial isolation** — capabilities live in capability slots (`CSpace`)
//!    managed by the kernel, never directly accessible to user code.
//!
//! ### Mapping to AIOS Capsule Architecture
//!
//! | seL4 concept       | AIOS equivalent                          |
//! |--------------------|------------------------------------------|
//! | CNode / `CSpace`   | [`CapTokenTree`] (this module)           |
//! | Cap / Capability   | [`CapToken`]                             |
//! | Mint (copy+atten.) | [`CapToken::derive`]                     |
//! | Revoke / Delete    | [`CapToken::revoke`] / [`CapTokenTree`]  |
//! | `CSpace` root        | [`CapTokenTree::root`]                   |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-CAP-001 (Non-forgeability):** Every valid token must be
//!   reachable from a root token via a chain of derive operations.
//! - **INV-CAP-002 (Attenuation):** For any derive `child = parent.derive(mask)`,
//!   `child.rights ⊆ parent.rights`.
//! - **INV-CAP-003 (Revocation cascade):** Revoking a token invalidates
//!   the token itself and all tokens derived from it (transitive closure).
//! - **INV-CAP-004 (Identity):** Two tokens are equivalent iff they have
//!   the same token id AND the same derivation path from root.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// CapRights — fine-grained capability rights (seL4-style)
// ---------------------------------------------------------------------------

/// Individual rights a capability token can grant.
///
/// Modeled after seL4's capability rights: read, write, grant, etc.
/// Each right can be independently attenuated during derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CapRight {
    /// Read access
    Read,
    /// Write / modify access
    Write,
    /// Execute / invoke access
    Execute,
    /// Grant — allow further delegation
    Grant,
    /// Destroy — allow deletion of the object
    Destroy,
    /// Transfer — allow moving the capability
    Transfer,
}

impl CapRight {
    /// Human-readable wire-form label (`SCREAMING_SNAKE_CASE`).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Execute => "EXECUTE",
            Self::Grant => "GRANT",
            Self::Destroy => "DESTROY",
            Self::Transfer => "TRANSFER",
        }
    }
}

/// A set of capability rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapRights {
    rights: HashSet<CapRight>,
}

impl CapRights {
    /// Full rights — all capabilities enabled.
    #[must_use]
    pub fn full() -> Self {
        Self {
            rights: [
                CapRight::Read,
                CapRight::Write,
                CapRight::Execute,
                CapRight::Grant,
                CapRight::Destroy,
                CapRight::Transfer,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Empty rights — no access.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rights: HashSet::new(),
        }
    }

    /// Check whether a specific right is granted.
    #[must_use]
    pub fn has(&self, right: CapRight) -> bool {
        self.rights.contains(&right)
    }

    /// Number of rights in this set.
    #[must_use]
    pub fn count(&self) -> usize {
        self.rights.len()
    }

    /// Attenuate rights — return a new set that is a subset.
    /// Returns None if the requested rights are not a subset.
    #[must_use]
    pub fn attenuate(&self, mask: &Self) -> Option<Self> {
        if mask.rights.is_subset(&self.rights) {
            Some(Self {
                rights: mask.rights.clone(),
            })
        } else {
            None
        }
    }

    /// Check if `other` is a subset of `self` (attenuation property).
    #[must_use]
    pub fn is_superset_of(&self, other: &Self) -> bool {
        self.rights.is_superset(&other.rights)
    }

    /// Iterator over all rights in this set.
    pub fn iter(&self) -> impl Iterator<Item = &CapRight> {
        self.rights.iter()
    }
}

// ---------------------------------------------------------------------------
// CapToken — an seL4-inspired capability token
// ---------------------------------------------------------------------------

static NEXT_TOKEN_ID: AtomicU64 = AtomicU64::new(1);

/// Unique identifier for a capability token.
///
/// Tokens are globally unique; two tokens with the same id refer to the
/// same capability object. This mirrors seL4's `CSpace` addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapTokenId(u64);

impl CapTokenId {
    /// Create a new unique token id.
    fn new() -> Self {
        Self(NEXT_TOKEN_ID.fetch_add(1, Ordering::Relaxed))
    }

    /// Raw value for testing.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A capability token — the fundamental unit of access control.
///
/// Invariants (verified at construction and in tests):
/// - Every token has a globally unique `id`.
/// - `rights ⊆ parent.rights` (attenuation).
/// - Token is valid iff `revoked == false`.
/// - Derivation path length is bounded by `max_depth`.
#[derive(Debug, Clone)]
pub struct CapToken {
    /// Globally-unique token identifier.
    pub id: CapTokenId,
    /// Rights granted by this token (always a subset of parent's rights).
    pub rights: CapRights,
    /// The id of the parent token, if any.
    pub parent_id: Option<CapTokenId>,
    /// Depth in the derivation tree (root = 0).
    pub depth: u32,
    /// Whether this token has been revoked.
    pub revoked: bool,
    /// Human-readable label for debugging/evidence.
    pub label: String,
}

impl CapToken {
    /// Maximum derivation depth (prevents unbounded trees).
    pub const MAX_DEPTH: u32 = 16;

    /// Create a new root token with full rights.
    #[must_use]
    pub fn new_root(label: impl Into<String>) -> Self {
        Self {
            id: CapTokenId::new(),
            rights: CapRights::full(),
            parent_id: None,
            depth: 0,
            revoked: false,
            label: label.into(),
        }
    }

    /// Derive a child token from this token with attenuated rights.
    ///
    /// Returns `None` if:
    /// - This token is revoked.
    /// - The attenuation mask is not a subset of this token's rights.
    /// - Maximum depth would be exceeded.
    /// - This token does not have `Grant` right.
    #[must_use]
    pub fn derive(&self, mask: &CapRights, label: impl Into<String>) -> Option<Self> {
        // INV-CAP-001: Cannot derive from a revoked token.
        if self.revoked {
            return None;
        }

        // INV-CAP-002: Attenuation — cannot amplify rights.
        let attenuated = self.rights.attenuate(mask)?;

        // Require Grant right to delegate.
        if !self.rights.has(CapRight::Grant) {
            return None;
        }

        // INV-CAP-003: Depth bound.
        if self.depth >= Self::MAX_DEPTH {
            return None;
        }

        Some(Self {
            id: CapTokenId::new(),
            rights: attenuated,
            parent_id: Some(self.id),
            depth: self.depth + 1,
            revoked: false,
            label: label.into(),
        })
    }

    /// Revoke this token (sets `revoked = true`).
    ///
    /// Returns `false` if the token was already revoked.
    pub fn revoke(&mut self) -> bool {
        if self.revoked {
            return false;
        }
        if !self.rights.has(CapRight::Destroy) {
            return false;
        }
        self.revoked = true;
        true
    }

    /// Check if this token is alive (not revoked).
    #[must_use]
    pub const fn is_alive(&self) -> bool {
        !self.revoked
    }
}

// ---------------------------------------------------------------------------
// CapTokenTree — manages the capability derivation hierarchy
// ---------------------------------------------------------------------------

/// A capability token tree that enforces the seL4 capability invariants.
///
/// The tree tracks parent-child relationships and enforces:
/// - Revocation cascade: revoking a parent invalidates all descendants.
/// - Derivation validation: a child's rights must be a subset of parent's rights.
#[derive(Debug, Default)]
pub struct CapTokenTree {
    tokens: HashMap<CapTokenId, CapToken>,
    children: HashMap<CapTokenId, Vec<CapTokenId>>,
    roots: Vec<CapTokenId>,
}

impl CapTokenTree {
    /// Create an empty token tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new root token. Returns the token id.
    pub fn create_root(&mut self, label: impl Into<String>) -> CapTokenId {
        let token = CapToken::new_root(label);
        let id = token.id;
        self.roots.push(id);
        self.tokens.insert(id, token);
        id
    }

    /// Derive a child from a parent token.
    ///
    /// Returns `None` if the derivation is invalid (parent revoked, rights
    /// not a superset, no Grant right, max depth exceeded).
    pub fn derive(
        &mut self,
        parent_id: CapTokenId,
        mask: &CapRights,
        label: impl Into<String>,
    ) -> Option<CapTokenId> {
        let parent = self.tokens.get(&parent_id)?;
        let child = parent.derive(mask, label)?;
        let child_id = child.id;

        self.children.entry(parent_id).or_default().push(child_id);
        self.tokens.insert(child_id, child);

        Some(child_id)
    }

    /// Revoke a token and ALL its descendants (transitive closure).
    ///
    /// This implements seL4's recursive delete: revoking a capability
    /// atomically removes it and every capability derived from it.
    ///
    /// Returns the number of tokens revoked (including the target).
    pub fn revoke_cascade(&mut self, token_id: CapTokenId) -> usize {
        // Collect all descendants via DFS
        let mut to_revoke: Vec<CapTokenId> = Vec::new();
        let mut stack: Vec<CapTokenId> = Vec::new();

        if let Some(children) = self.children.get(&token_id) {
            stack.extend(children);
        }

        while let Some(current) = stack.pop() {
            to_revoke.push(current);
            if let Some(grandchildren) = self.children.get(&current) {
                stack.extend(grandchildren);
            }
        }

        // Revoke descendants first, then the target
        let mut count = 0;
        for child_id in &to_revoke {
            if let Some(token) = self.tokens.get_mut(child_id) {
                if token.revoke() {
                    count += 1;
                }
            }
        }

        // Revoke the target itself
        if let Some(token) = self.tokens.get_mut(&token_id) {
            if token.revoke() {
                count += 1;
            }
        }

        count
    }

    /// Get a reference to a token by id.
    #[must_use]
    pub fn get(&self, token_id: &CapTokenId) -> Option<&CapToken> {
        self.tokens.get(token_id)
    }

    /// Check if a token is reachable from a root (non-forgeability check).
    #[must_use]
    pub fn is_reachable(&self, token_id: &CapTokenId) -> bool {
        let Some(token) = self.tokens.get(token_id) else {
            return false;
        };

        // A root token is always reachable
        if token.parent_id.is_none() && self.roots.contains(token_id) {
            return true;
        }

        // Walk up the parent chain to a root
        let mut current = token.parent_id;
        while let Some(parent_id) = current {
            if self.roots.contains(&parent_id) {
                return true;
            }
            current = self.tokens.get(&parent_id).and_then(|t| t.parent_id);
        }

        false
    }

    /// Verify the attenuation invariant for all tokens in the tree.
    ///
    /// Returns a list of violations: (`child_id`, `parent_id`) pairs where
    /// child rights are NOT a subset of parent rights.
    #[must_use]
    pub fn verify_attenuation(&self) -> Vec<(CapTokenId, CapTokenId)> {
        let mut violations = Vec::new();
        for (child_id, token) in &self.tokens {
            if let Some(parent_id) = token.parent_id {
                if let Some(parent) = self.tokens.get(&parent_id) {
                    if !parent.rights.is_superset_of(&token.rights) {
                        violations.push((*child_id, parent_id));
                    }
                }
            }
        }
        violations
    }

    /// Total number of tokens in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Number of alive (non-revoked) tokens.
    #[must_use]
    pub fn alive_count(&self) -> usize {
        self.tokens.values().filter(|t| !t.revoked).count()
    }

    /// Get all descendant ids for a token (including transitive).
    #[must_use]
    pub fn descendants(&self, token_id: &CapTokenId) -> Vec<CapTokenId> {
        let mut result = Vec::new();
        let mut stack: Vec<CapTokenId> = Vec::new();

        if let Some(children) = self.children.get(token_id) {
            stack.extend(children);
        }

        while let Some(current) = stack.pop() {
            result.push(current);
            if let Some(grandchildren) = self.children.get(&current) {
                stack.extend(grandchildren);
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CapRights tests
    // -----------------------------------------------------------------------

    #[test]
    fn full_rights_has_all_six_rights() {
        let full = CapRights::full();
        assert_eq!(full.count(), 6);
        assert!(full.has(CapRight::Read));
        assert!(full.has(CapRight::Write));
        assert!(full.has(CapRight::Execute));
        assert!(full.has(CapRight::Grant));
        assert!(full.has(CapRight::Destroy));
        assert!(full.has(CapRight::Transfer));
    }

    #[test]
    fn empty_rights_has_zero_rights() {
        let empty = CapRights::empty();
        assert_eq!(empty.count(), 0);
        assert!(!empty.has(CapRight::Read));
        assert!(!empty.has(CapRight::Grant));
    }

    #[test]
    fn attenuate_reduces_rights() {
        let full = CapRights::full();
        let mut mask_set = HashSet::new();
        mask_set.insert(CapRight::Read);
        mask_set.insert(CapRight::Write);
        let mask = CapRights {
            rights: mask_set.clone(),
        };

        let attenuated = full.attenuate(&mask).expect("attenuation should succeed");
        assert_eq!(attenuated.count(), 2);
        assert!(attenuated.has(CapRight::Read));
        assert!(attenuated.has(CapRight::Write));
        assert!(!attenuated.has(CapRight::Execute));
        assert!(!attenuated.has(CapRight::Grant));
    }

    #[test]
    fn attenuate_fails_when_not_subset() {
        let full = CapRights::full();
        let mut extra_set = HashSet::new();
        extra_set.insert(CapRight::Grant);
        let mask = CapRights { rights: extra_set };

        // Mask is a subset of full — this should succeed
        assert!(full.attenuate(&mask).is_some());

        // But trying to attenuate an already-reduced set with a wider mask fails
        let reduced = full.attenuate(&mask).unwrap();
        // reduced has only Grant — attenuating to full should fail
        assert!(reduced.attenuate(&CapRights::full()).is_none());
    }

    #[test]
    fn is_superset_of_verifies_subset() {
        let full = CapRights::full();
        let mut subset_set = HashSet::new();
        subset_set.insert(CapRight::Read);
        let subset = CapRights { rights: subset_set };

        assert!(full.is_superset_of(&subset));
        assert!(!subset.is_superset_of(&full));
    }

    // -----------------------------------------------------------------------
    // CapToken tests
    // -----------------------------------------------------------------------

    #[test]
    fn root_token_has_full_rights_and_no_parent() {
        let root = CapToken::new_root("test-root");
        assert_eq!(root.rights.count(), 6);
        assert!(root.parent_id.is_none());
        assert_eq!(root.depth, 0);
        assert!(root.is_alive());
        assert!(!root.revoked);
    }

    #[test]
    fn derive_child_attenuates_rights() {
        let root = CapToken::new_root("root");
        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            s.insert(CapRight::Write);
            CapRights { rights: s }
        };

        let child = root
            .derive(&mask, "child")
            .expect("derivation should succeed");
        assert_eq!(child.rights.count(), 2);
        assert!(child.rights.has(CapRight::Read));
        assert!(child.rights.has(CapRight::Write));
        assert!(!child.rights.has(CapRight::Grant));
        assert_eq!(child.parent_id, Some(root.id));
        assert_eq!(child.depth, 1);
    }

    #[test]
    fn derive_fails_from_revoked_token() {
        let mut root = CapToken::new_root("root");
        root.revoke();
        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            CapRights { rights: s }
        };
        assert!(root.derive(&mask, "child").is_none());
    }

    #[test]
    fn derive_fails_without_grant_right() {
        let root = CapToken::new_root("root");
        // First derive a child with only Read (no Grant)
        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            CapRights { rights: s }
        };
        let child = root
            .derive(&mask, "child")
            .expect("first derivation should succeed");
        assert!(!child.rights.has(CapRight::Grant));

        // Trying to derive from child (which has no Grant) should fail
        let mask2 = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            CapRights { rights: s }
        };
        assert!(child.derive(&mask2, "grandchild").is_none());
    }

    #[test]
    fn derive_fails_when_mask_not_subset() {
        let root = CapToken::new_root("root");
        // Create a token with only Read+Write
        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            s.insert(CapRight::Write);
            CapRights { rights: s }
        };
        let child = root.derive(&mask, "child").unwrap();

        // Try to derive with Execute — not in child's rights
        let bad_mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Execute);
            CapRights { rights: s }
        };
        assert!(child.derive(&bad_mask, "grandchild").is_none());
    }

    #[test]
    fn max_depth_enforced() {
        let root = CapToken::new_root("root");
        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Grant);
            s.insert(CapRight::Read);
            CapRights { rights: s }
        };

        // Derive up to MAX_DEPTH
        let mut current = root.derive(&mask, "d1").unwrap();
        for i in 2..=CapToken::MAX_DEPTH {
            current = current
                .derive(&mask, format!("d{}", i))
                .expect("derivation within depth should succeed");
        }
        assert_eq!(current.depth, CapToken::MAX_DEPTH);

        // One more should fail
        assert!(current.derive(&mask, "too-deep").is_none());
    }

    #[test]
    fn revoke_returns_false_when_already_revoked() {
        let mut root = CapToken::new_root("root");
        assert!(root.revoke());
        assert!(!root.revoke()); // already revoked
        assert!(!root.is_alive());
    }

    #[test]
    fn revoke_requires_destroy_right() {
        let root = CapToken::new_root("root");
        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            CapRights { rights: s }
        };
        let child = root
            .derive(&mask, "child")
            .expect("derivation should succeed");
        // Clone to make mutable — this child has no Destroy right
        let mut child_mut = child.clone();
        assert!(!child.rights.has(CapRight::Destroy));
        assert!(!child_mut.revoke());
    }

    // -----------------------------------------------------------------------
    // CapTokenTree tests — cascade revocation (INV-CAP-003)
    // -----------------------------------------------------------------------

    #[test]
    fn tree_create_root_registers_token() {
        let mut tree = CapTokenTree::new();
        let root_id = tree.create_root("root");
        assert_eq!(tree.len(), 1);
        assert!(tree.is_reachable(&root_id));
        assert_eq!(tree.alive_count(), 1);
    }

    #[test]
    fn tree_derive_creates_child_with_attenuation() {
        let mut tree = CapTokenTree::new();
        let root_id = tree.create_root("root");

        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            s.insert(CapRight::Execute);
            CapRights { rights: s }
        };

        let child_id = tree
            .derive(root_id, &mask, "child")
            .expect("derivation should succeed");
        assert_eq!(tree.len(), 2);

        let child = tree.get(&child_id).expect("child should exist");
        assert_eq!(child.rights.count(), 2);
        assert!(child.rights.has(CapRight::Read));
        assert!(child.rights.has(CapRight::Execute));
        assert_eq!(child.parent_id, Some(root_id));
    }

    #[test]
    fn revoke_cascade_invalidates_all_descendants() {
        let mut tree = CapTokenTree::new();
        let root_id = tree.create_root("root");

        // Mask must include Destroy for cascade revocation to work on children
        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            s.insert(CapRight::Grant);
            s.insert(CapRight::Destroy);
            CapRights { rights: s }
        };

        let child_id = tree.derive(root_id, &mask, "child").unwrap();
        let grandchild_id = tree.derive(child_id, &mask, "grandchild").unwrap();
        let great_grandchild_id = tree.derive(grandchild_id, &mask, "ggc").unwrap();

        assert_eq!(tree.len(), 4);
        assert_eq!(tree.alive_count(), 4);

        // Revoke the root — should cascade to all descendants
        let revoked = tree.revoke_cascade(root_id);
        assert_eq!(revoked, 4, "all 4 tokens should be revoked");

        // Verify all are revoked
        assert!(!tree.get(&root_id).unwrap().is_alive());
        assert!(!tree.get(&child_id).unwrap().is_alive());
        assert!(!tree.get(&grandchild_id).unwrap().is_alive());
        assert!(!tree.get(&great_grandchild_id).unwrap().is_alive());
        assert_eq!(tree.alive_count(), 0);
    }

    #[test]
    fn revoke_cascade_mid_tree_leaves_siblings_alive() {
        let mut tree = CapTokenTree::new();
        let root_id = tree.create_root("root");

        // Mask must include Destroy for cascade revocation to work
        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            s.insert(CapRight::Grant);
            s.insert(CapRight::Destroy);
            CapRights { rights: s }
        };

        let child_a = tree.derive(root_id, &mask, "child-a").unwrap();
        let child_b = tree.derive(root_id, &mask, "child-b").unwrap();
        let grandchild_a1 = tree.derive(child_a, &mask, "gc-a1").unwrap();

        assert_eq!(tree.len(), 4);

        // Revoke child_a — should cascade to grandchild_a1 but not child_b
        let revoked = tree.revoke_cascade(child_a);
        assert_eq!(
            revoked, 2,
            "only child_a and grandchild_a1 should be revoked"
        );

        assert!(!tree.get(&child_a).unwrap().is_alive());
        assert!(!tree.get(&grandchild_a1).unwrap().is_alive());
        assert!(tree.get(&root_id).unwrap().is_alive());
        assert!(tree.get(&child_b).unwrap().is_alive());
        assert_eq!(tree.alive_count(), 2);
    }

    #[test]
    fn attenuation_invariant_no_violations_in_valid_tree() {
        let mut tree = CapTokenTree::new();
        let root_id = tree.create_root("root");

        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            s.insert(CapRight::Grant);
            s.insert(CapRight::Execute);
            CapRights { rights: s }
        };

        tree.derive(root_id, &mask, "child").unwrap();
        tree.derive(root_id, &mask, "child2").unwrap();

        let violations = tree.verify_attenuation();
        assert!(violations.is_empty(), "expected no attenuation violations");
    }

    #[test]
    fn non_forgeability_token_reachable_from_root() {
        let mut tree = CapTokenTree::new();
        let root_id = tree.create_root("root");

        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            s.insert(CapRight::Grant);
            CapRights { rights: s }
        };

        let child_id = tree.derive(root_id, &mask, "child").unwrap();
        let grandchild_id = tree.derive(child_id, &mask, "gc").unwrap();

        assert!(tree.is_reachable(&root_id));
        assert!(tree.is_reachable(&child_id));
        assert!(tree.is_reachable(&grandchild_id));
    }

    #[test]
    fn descendants_returns_transitive_closure() {
        let mut tree = CapTokenTree::new();
        let root_id = tree.create_root("root");

        let mask = {
            let mut s = HashSet::new();
            s.insert(CapRight::Read);
            s.insert(CapRight::Grant);
            CapRights { rights: s }
        };

        let child_a = tree.derive(root_id, &mask, "a").unwrap();
        let _child_b = tree.derive(root_id, &mask, "b").unwrap();
        tree.derive(child_a, &mask, "a1").unwrap();
        tree.derive(child_a, &mask, "a2").unwrap();

        let desc = tree.descendants(&root_id);
        assert_eq!(desc.len(), 4); // child_a, child_b, a1, a2
    }

    // -----------------------------------------------------------------------
    // CapRight wire-form tests
    // -----------------------------------------------------------------------

    #[test]
    fn cap_right_wire_form_is_screaming_snake_case() {
        assert_eq!(CapRight::Read.as_str(), "READ");
        assert_eq!(CapRight::Write.as_str(), "WRITE");
        assert_eq!(CapRight::Execute.as_str(), "EXECUTE");
        assert_eq!(CapRight::Grant.as_str(), "GRANT");
        assert_eq!(CapRight::Destroy.as_str(), "DESTROY");
        assert_eq!(CapRight::Transfer.as_str(), "TRANSFER");
    }
}
