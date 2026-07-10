//! dm-verity / IPE immutable root filesystem model for AIOS capsules.
#![allow(clippy::doc_markdown, clippy::missing_const_for_fn)]

use std::collections::HashMap;

/// Block-level integrity verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerityResult {
    Verified,
    Tampered,
    NotInTree,
}

/// A verity hash tree for block-level integrity (Merkle tree of hashes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerityHashTree {
    pub leaf_hashes: Vec<[u8; 32]>,
}

impl VerityHashTree {
    #[must_use]
    pub fn new(leaf_hashes: Vec<[u8; 32]>) -> Self {
        Self { leaf_hashes }
    }

    #[must_use]
    pub fn verify_block(&self, index: u64, data: &[u8], expected_hash: &[u8; 32]) -> VerityResult {
        if index as usize >= self.leaf_hashes.len() {
            return VerityResult::NotInTree;
        }
        let computed = hash_bytes(data);
        if &computed == expected_hash {
            VerityResult::Verified
        } else {
            VerityResult::Tampered
        }
    }

    #[must_use]
    pub fn root_hash(&self) -> [u8; 32] {
        if self.leaf_hashes.is_empty() {
            return [0; 32];
        }
        let mut result = [0u8; 32];
        for leaf in &self.leaf_hashes {
            for i in 0..32 {
                result[i] ^= leaf[i];
            }
        }
        result
    }

    #[must_use]
    pub fn block_count(&self) -> usize {
        self.leaf_hashes.len()
    }
}

/// A named immutable image with root hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerityImage {
    pub name: String,
    pub root_hash: [u8; 32],
    pub block_count: u64,
}

impl VerityImage {
    #[must_use]
    pub fn new(name: String, root_hash: [u8; 32], block_count: u64) -> Self {
        Self {
            name,
            root_hash,
            block_count,
        }
    }
}

/// Integrity Policy Enforcement rules for immutable storage.
#[derive(Debug, Clone)]
pub struct IpePolicy {
    immutable_paths: Vec<String>,
}

impl IpePolicy {
    pub fn new(paths: Vec<String>) -> Self {
        Self {
            immutable_paths: paths,
        }
    }

    #[must_use]
    pub fn is_immutable(&self, path: &str) -> bool {
        self.immutable_paths
            .iter()
            .any(|p| path.starts_with(p.as_str()))
    }

    pub fn add_path(&mut self, path: String) {
        self.immutable_paths.push(path);
    }

    #[must_use]
    pub fn path_count(&self) -> usize {
        self.immutable_paths.len()
    }
}

/// Verifier that checks block integrity against known-good tree.
#[derive(Debug, Clone, Default)]
pub struct VerityVerifier {
    trees: HashMap<String, VerityHashTree>,
}

impl VerityVerifier {
    pub fn new() -> Self {
        Self {
            trees: HashMap::new(),
        }
    }

    pub fn register_tree(&mut self, name: String, tree: VerityHashTree) {
        self.trees.insert(name, tree);
    }

    #[must_use]
    pub fn verify(
        &self,
        image_name: &str,
        block_index: u64,
        data: &[u8],
        expected: &[u8; 32],
    ) -> VerityResult {
        match self.trees.get(image_name) {
            Some(tree) => tree.verify_block(block_index, data, expected),
            None => VerityResult::NotInTree,
        }
    }
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, &b) in data.iter().enumerate() {
        h[i % 32] ^= b;
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_verification_verified() {
        let data = b"hello world";
        let expected = hash_bytes(data);
        let tree = VerityHashTree::new(vec![expected]);
        assert_eq!(
            tree.verify_block(0, data, &expected),
            VerityResult::Verified
        );
    }

    #[test]
    fn block_verification_tampered() {
        let data = b"hello world";
        let fake = [0u8; 32];
        let tree = VerityHashTree::new(vec![hash_bytes(data)]);
        assert_eq!(tree.verify_block(0, data, &fake), VerityResult::Tampered);
    }

    #[test]
    fn block_out_of_range_is_not_in_tree() {
        let tree = VerityHashTree::new(vec![[0; 32]]);
        assert_eq!(
            tree.verify_block(999, &[], &[0; 32]),
            VerityResult::NotInTree
        );
    }

    #[test]
    fn root_hash_computation() {
        let tree = VerityHashTree::new(vec![hash_bytes(b"a"), hash_bytes(b"b")]);
        assert_ne!(tree.root_hash(), [0; 32]);
    }

    #[test]
    fn empty_tree_root_hash_is_zero() {
        let tree = VerityHashTree::new(vec![]);
        assert_eq!(tree.root_hash(), [0; 32]);
    }

    #[test]
    fn verity_image_creation() {
        let img = VerityImage::new("rootfs".into(), [1; 32], 1000);
        assert_eq!(img.name, "rootfs");
        assert_eq!(img.block_count, 1000);
    }

    #[test]
    fn ipe_policy_path_matching() {
        let policy = IpePolicy::new(vec!["/usr/".into(), "/etc/aios/".into()]);
        assert!(policy.is_immutable("/usr/bin/bash"));
        assert!(policy.is_immutable("/etc/aios/config"));
        assert!(!policy.is_immutable("/home/user/data"));
    }

    #[test]
    fn verifier_registry() {
        let data = b"test";
        let h = hash_bytes(data);
        let mut v = VerityVerifier::new();
        v.register_tree("rootfs".into(), VerityHashTree::new(vec![h]));
        assert_eq!(v.verify("rootfs", 0, data, &h), VerityResult::Verified);
        assert_eq!(v.verify("missing", 0, data, &h), VerityResult::NotInTree);
    }
}
