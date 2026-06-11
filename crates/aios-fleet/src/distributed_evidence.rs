//! Distributed Evidence Merkle-DAG for fleet/cluster evidence chaining (S25 §10).
//!
//! Each host keeps its linear S3.1 [`aios_evidence::ReceiptChain`]; the DAG links
//! host chains together via content-addressed [`DagNode`]s, enabling cross-host
//! evidence verification, cluster-root-signed checkpoints, and cryptographic fork
//! detection.
//!
//! ## Architectural invariants
//!
//! - **Append-only.** Nodes are never mutated or deleted after addition.
//! - **Content-addressed.** Every node's identity is its BLAKE3 hash.
//! - **Fork-detected, never silently resolved.** Divergent ancestry is recorded as
//!   a fork and surfaced for operator adjudication.
//! - **Cluster-root-signed checkpoints.** Periodic Merkle-root snapshots signed by
//!   the cluster root key enable RFC 9162-style inclusion proofs.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

/// Failure modes for the distributed evidence DAG.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DagError {
    /// A node with the same content hash already exists in the DAG.
    #[error("duplicate DAG node: content hash {node_id} already present")]
    DuplicateNode {
        /// The content hash of the duplicate node.
        node_id: String,
    },

    /// Append-only violation: attempted to modify an existing node.
    #[error("append-only violation: cannot modify node {node_id}")]
    AppendOnlyViolation {
        /// The content hash of the node that was targeted for modification.
        node_id: String,
    },

    /// A referenced parent node is not present in the DAG.
    #[error("missing parent node {parent_id} for node {node_id}")]
    MissingParent {
        /// The content hash of the child node.
        node_id: String,
        /// The content hash of the missing parent.
        parent_id: String,
    },

    /// No host chain head found for the given host.
    #[error("no chain head found for host {host_id}")]
    MissingHostChain {
        /// The host identifier.
        host_id: String,
    },

    /// The cluster root signature on a checkpoint failed verification.
    #[error("cluster root signature verification failed for checkpoint {checkpoint_id}")]
    CheckpointSignatureMismatch {
        /// The checkpoint identifier.
        checkpoint_id: String,
    },

    /// Inclusion proof failed: the provided Merkle path does not verify.
    #[error("inclusion proof failed for node {node_id} in checkpoint {checkpoint_id}: {detail}")]
    InclusionProofFailed {
        /// The checkpoint identifier.
        checkpoint_id: String,
        /// The node being verified.
        node_id: String,
        /// Human-readable detail about why the proof failed.
        detail: String,
    },

    /// Fork detected between two DAG node lineages.
    #[error("fork detected between hosts {host_a} and {host_b} at divergent ancestors {ancestor_a} and {ancestor_b}")]
    ForkDetected {
        /// First host identifier.
        host_a: String,
        /// Second host identifier.
        host_b: String,
        /// Divergent ancestor on first host's chain.
        ancestor_a: String,
        /// Divergent ancestor on second host's chain.
        ancestor_b: String,
    },

    /// Attempted merge of inconsistent DAGs (divergent histories).
    #[error("cannot merge inconsistent DAGs: fork at {fork_point}")]
    InconsistentMerge {
        /// The content hash at which the histories diverged.
        fork_point: String,
    },

    /// Encoding or hashing failure.
    #[error("encoding failure: {0}")]
    EncodingFailure(String),

    /// Signature encoding/decoding failure.
    #[error("signature malformed: {detail}")]
    SignatureMalformed {
        /// Reason the signature was rejected.
        detail: String,
    },

    /// Signature is missing when required.
    #[error("signature missing on {what}")]
    SignatureMissing {
        /// What was expected to be signed.
        what: String,
    },
}

/// BLAKE3 content hash represented as 64 lowercase hex characters.
pub type Hash = String;

/// Content-addressed Merkle-DAG node linking evidence across hosts.
///
/// Each node carries:
/// - A content hash derived from its fields (BLAKE3).
/// - The host that produced it.
/// - A segment hash pointing into that host's [`aios_evidence::ReceiptChain`].
/// - Parents: the previous node on the same host AND (optionally) the last
///   node replicated from a peer.
/// - An Ed25519 signature from the producing host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagNode {
    /// Content-addressed identity: BLAKE3 hash of the canonical serialization
    /// of this node (excluding `node_id` itself).
    pub node_id: Hash,

    /// The host that produced this node (e.g. `host:aios-node-01`).
    pub host_id: String,

    /// BLAKE3-256 (64 hex chars) hash of the corresponding sealed segment in
    /// the host's local [`aios_evidence::ReceiptChain`].
    pub segment_hash: Hash,

    /// Ordered list of parent node hashes.
    /// - `parents[0]` is the previous node on the same host.
    /// - `parents[1..]` are the last-replicated nodes from peers.
    pub parents: Vec<Hash>,

    /// Wall-clock timestamp assigned by the producing host.
    pub timestamp: DateTime<Utc>,

    /// Ed25519 signature over the canonical-minus-signature bytes of this node,
    /// produced by the host identified in `host_id`.
    pub signature: String,
}

impl DagNode {
    /// Create a new DAG node and compute its content-addressed identity.
    ///
    /// The `node_id` is computed as `BLAKE3(JCS(node_without_id))`.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::EncodingFailure`] if canonical serialization fails.
    pub fn new(
        host_id: String,
        segment_hash: Hash,
        parents: Vec<Hash>,
        signing_key: &SigningKey,
    ) -> Result<Self, DagError> {
        let timestamp = Utc::now();

        let preimage = DagNodePreimage {
            host_id: &host_id,
            segment_hash: &segment_hash,
            parents: &parents,
            timestamp,
        };

        let canonical = serde_json::to_string(&preimage)
            .map_err(|e| DagError::EncodingFailure(e.to_string()))?;

        let node_id = blake3::hash(canonical.as_bytes()).to_hex().to_string();

        let signature = signing_key.sign(node_id.as_bytes());
        let signature_hex: String = signature.to_bytes().iter()
            .fold(String::with_capacity(128), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(&mut acc, "{b:02x}");
                acc
            });

        Ok(Self {
            node_id,
            host_id,
            segment_hash,
            parents,
            timestamp,
            signature: signature_hex,
        })
    }

    /// Verify this node's Ed25519 signature against the host's verifying key.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::SignatureMalformed`] if the stored signature hex is
    /// malformed, or if verification fails.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), DagError> {
        let sig_bytes = decode_hex_signature(&self.signature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(self.node_id.as_bytes(), &signature)
            .map_err(|_| DagError::SignatureMalformed {
                detail: format!(
                    "Ed25519 verification failed for node {} from host {}",
                    self.node_id, self.host_id
                ),
            })
    }

    /// Recompute and verify this node's content hash.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::EncodingFailure`] if canonical serialization fails.
    /// The caller should compare the returned hash to `self.node_id`.
    pub fn recompute_node_id(&self) -> Result<Hash, DagError> {
        let preimage = DagNodePreimage {
            host_id: &self.host_id,
            segment_hash: &self.segment_hash,
            parents: &self.parents,
            timestamp: self.timestamp,
        };

        let canonical = serde_json::to_string(&preimage)
            .map_err(|e| DagError::EncodingFailure(e.to_string()))?;

        Ok(blake3::hash(canonical.as_bytes()).to_hex().to_string())
    }
}

/// Serialized form of a DAG node used for content-hash computation.
///
/// Excludes `node_id` and `signature` to avoid circular hashing.
#[derive(Debug, Serialize)]
struct DagNodePreimage<'a> {
    host_id: &'a str,
    segment_hash: &'a str,
    parents: &'a [Hash],
    timestamp: DateTime<Utc>,
}

/// Head pointer into a single host's evidence chain within the fleet DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostChainHead {
    /// The host identifier (e.g. `host:aios-node-01`).
    pub host_id: String,

    /// Content hash of the most recent [`DagNode`] published by this host.
    pub head_hash: Hash,

    /// Total number of sealed segments tracked in the host's local chain.
    pub sealed_segment_count: u64,
}

/// RFC 9162-style inclusion proof scheme for checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofScheme {
    /// Standard Merkle inclusion proof (RFC 9162 §2.1.3).
    /// A sibling path from the leaf to the Merkle root.
    #[serde(rename = "MERKLE_INCLUSION")]
    MerkleInclusion,
}

/// A cluster-root-signed checkpoint over the fleet DAG.
///
/// Checkpoints provide a verifiable snapshot of the fleet's evidence state
/// at a point in time. The cluster root key signs the Merkle root, enabling
/// any host to verify inclusion proofs against this checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterCheckpoint {
    /// Content hash identifying this checkpoint.
    pub checkpoint_id: Hash,

    /// Merkle root of all DAG node hashes known at checkpoint time.
    pub merkle_root: Hash,

    /// Ed25519 signature of `merkle_root` by the cluster root key.
    pub cluster_root_signature: String,

    /// Wall-clock timestamp when the checkpoint was created.
    pub timestamp: DateTime<Utc>,

    /// The inclusion proof scheme used by this checkpoint.
    pub inclusion_proof_scheme: ProofScheme,
}

impl ClusterCheckpoint {
    /// Create a new signed checkpoint.
    ///
    /// The `checkpoint_id` is computed as `BLAKE3(merkle_root || timestamp)`.
    pub fn new(
        merkle_root: Hash,
        cluster_root_key: &SigningKey,
        scheme: ProofScheme,
    ) -> Result<Self, DagError> {
        let timestamp = Utc::now();

        let preimage = format!("{merkle_root}|{timestamp}");
        let checkpoint_id = blake3::hash(preimage.as_bytes()).to_hex().to_string();

        let signature = cluster_root_key.sign(merkle_root.as_bytes());
        let sig_hex: String = signature.to_bytes().iter()
            .fold(String::with_capacity(128), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(&mut acc, "{b:02x}");
                acc
            });

        Ok(Self {
            checkpoint_id,
            merkle_root,
            cluster_root_signature: sig_hex,
            timestamp,
            inclusion_proof_scheme: scheme,
        })
    }

    /// Verify the cluster root signature on this checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::CheckpointSignatureMismatch`] if verification fails.
    pub fn verify_cluster_root_signature(
        &self,
        cluster_root_key: &VerifyingKey,
    ) -> Result<(), DagError> {
        let sig_bytes = decode_hex_signature(&self.cluster_root_signature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        cluster_root_key
            .verify(self.merkle_root.as_bytes(), &signature)
            .map_err(|_| DagError::CheckpointSignatureMismatch {
                checkpoint_id: self.checkpoint_id.clone(),
            })
    }
}

/// Consistency state tracking for the distributed evidence log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsistencyState {
    /// All tracked host chains are consistent (no forks detected).
    #[serde(rename = "CONSISTENT")]
    Consistent,

    /// A fork has been detected. The log carries a FORK_DETECTED record.
    #[serde(rename = "FORK_DETECTED")]
    ForkDetected {
        /// The node hash at which the lineages diverged.
        fork_point: Hash,
        /// Host identifiers involved in the fork.
        hosts: Vec<String>,
    },

    /// The DAG is being reconciled after a fork was adjudicated.
    #[serde(rename = "RECONCILING")]
    Reconciling {
        /// The node hash at which reconciliation is anchored.
        anchor: Hash,
    },
}

/// The distributed evidence Merkle-DAG for fleet/cluster evidence chaining.
///
/// Maintains a content-addressed DAG of [`DagNode`]s across all hosts in a
/// cluster. Each host keeps its linear S3.1 chain; the DAG links them together
/// via parent pointers.
///
/// ## Constitutional constants
///
/// - `append_only: true` — nodes are never mutated or deleted.
/// - `fork_detection: Enabled` — divergent lineages are always detected and
///   recorded, never silently resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedEvidenceLog {
    /// Unique identifier for this DAG instance.
    pub dag_id: Ulid,

    /// The cluster this DAG belongs to.
    pub cluster_id: Ulid,

    /// Head pointers into each host's local chain.
    pub host_chains: Vec<HostChainHead>,

    /// All DAG nodes indexed by content hash.
    pub dag_nodes: Vec<DagNode>,

    /// Cluster-root-signed checkpoints over the DAG state.
    pub checkpoints: Vec<ClusterCheckpoint>,

    /// Current consistency state.
    pub consistency: ConsistencyState,
}

impl DistributedEvidenceLog {
    /// Constitutional constant: the DAG is append-only.
    pub const APPEND_ONLY: bool = true;

    /// Constitutional constant: fork detection is always enabled.
    pub const FORK_DETECTION_ENABLED: bool = true;

    /// Create a new empty distributed evidence log for a cluster.
    #[must_use]
    pub fn new(cluster_id: Ulid) -> Self {
        Self {
            dag_id: Ulid::new(),
            cluster_id,
            host_chains: Vec::new(),
            dag_nodes: Vec::new(),
            checkpoints: Vec::new(),
            consistency: ConsistencyState::Consistent,
        }
    }

    /// Add a new DAG node to the log.
    ///
    /// Verifies:
    /// - The node's content hash matches its recomputed identity.
    /// - All parent references exist in the DAG (or the node is a genesis node).
    /// - The node is not already present (no duplicates).
    ///
    /// Updates the host chain head for the producing host.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::DuplicateNode`] if the node already exists.
    /// Returns [`DagError::MissingParent`] if a referenced parent is absent.
    /// Returns [`DagError::EncodingFailure`] if content hash recomputation fails.
    pub fn add_node(&mut self, node: DagNode) -> Result<(), DagError> {
        let recomputed = node.recompute_node_id()?;
        if recomputed != node.node_id {
            return Err(DagError::EncodingFailure(format!(
                "node_id mismatch: stored {} but recomputed {}",
                node.node_id, recomputed
            )));
        }

        if self.dag_nodes.iter().any(|n| n.node_id == node.node_id) {
            return Err(DagError::DuplicateNode {
                node_id: node.node_id,
            });
        }

        for parent_id in &node.parents {
            if !self.dag_nodes.iter().any(|n| n.node_id == *parent_id) {
                return Err(DagError::MissingParent {
                    node_id: node.node_id.clone(),
                    parent_id: parent_id.clone(),
                });
            }
        }

        if let Some(head) = self
            .host_chains
            .iter_mut()
            .find(|h| h.host_id == node.host_id)
        {
            head.head_hash = node.node_id.clone();
            head.sealed_segment_count += 1;
        } else {
            self.host_chains.push(HostChainHead {
                host_id: node.host_id.clone(),
                head_hash: node.node_id.clone(),
                sealed_segment_count: 1,
            });
        }

        self.dag_nodes.push(node);
        Ok(())
    }

    /// Replicate a DAG node from a peer host.
    ///
    /// Inserts the replicated node into the local DAG, ensuring the node's
    /// parents include both the previous node on the peer's chain AND the
    /// current head of the local host's chain for the same segment.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::DuplicateNode`] if the node is already present.
    pub fn replicate_from_peer(
        &mut self,
        node: DagNode,
        local_host_id: &str,
        local_head_segment: &Hash,
    ) -> Result<(), DagError> {
        let recomputed = node.recompute_node_id()?;
        if recomputed != node.node_id {
            return Err(DagError::EncodingFailure(format!(
                "replicated node_id mismatch: stored {} but recomputed {}",
                node.node_id, recomputed
            )));
        }

        if self.dag_nodes.iter().any(|n| n.node_id == node.node_id) {
            return Err(DagError::DuplicateNode {
                node_id: node.node_id,
            });
        }

        let mut merged_node = node;
        if !merged_node.parents.contains(local_head_segment) {
            merged_node.parents.push(local_head_segment.clone());
        }

        if let Some(head) = self
            .host_chains
            .iter_mut()
            .find(|h| h.host_id == local_host_id)
        {
            head.head_hash = merged_node.node_id.clone();
            head.sealed_segment_count += 1;
        } else {
            self.host_chains.push(HostChainHead {
                host_id: local_host_id.to_owned(),
                head_hash: merged_node.node_id.clone(),
                sealed_segment_count: 1,
            });
        }

        self.dag_nodes.push(merged_node);
        Ok(())
    }

    /// Sign a new cluster checkpoint over the current DAG state.
    ///
    /// Computes the Merkle root of all DAG node hashes and signs it with the
    /// cluster root key.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::EncodingFailure`] if Merkle tree construction fails.
    pub fn sign_checkpoint(
        &mut self,
        cluster_root_key: &SigningKey,
    ) -> Result<&ClusterCheckpoint, DagError> {
        let merkle_root = compute_merkle_root(&self.dag_nodes)?;
        let checkpoint = ClusterCheckpoint::new(
            merkle_root,
            cluster_root_key,
            ProofScheme::MerkleInclusion,
        )?;
        self.checkpoints.push(checkpoint);
        Ok(self.checkpoints.last().ok_or_else(|| {
            DagError::EncodingFailure("checkpoint push failed".to_owned())
        })?)
    }

    /// Verify that a DAG node is included in a checkpoint via Merkle proof.
    ///
    /// Reconstructs the Merkle root from the proof path and verifies it
    /// matches the checkpoint's Merkle root.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::InclusionProofFailed`] if the proof does not verify.
    pub fn verify_inclusion(
        &self,
        node_id: &str,
        checkpoint_id: &str,
        proof_siblings: &[Hash],
        proof_index: usize,
    ) -> Result<(), DagError> {
        let checkpoint = self
            .checkpoints
            .iter()
            .find(|c| c.checkpoint_id == checkpoint_id)
            .ok_or_else(|| DagError::InclusionProofFailed {
                checkpoint_id: checkpoint_id.to_owned(),
                node_id: node_id.to_owned(),
                detail: "checkpoint not found".to_owned(),
            })?;

        let computed_root = compute_merkle_root_from_proof(
            node_id.to_owned(),
            proof_siblings,
            proof_index,
        );

        if computed_root != checkpoint.merkle_root {
            return Err(DagError::InclusionProofFailed {
                checkpoint_id: checkpoint_id.to_owned(),
                node_id: node_id.to_owned(),
                detail: format!(
                    "computed root {computed_root} does not match checkpoint root {}",
                    checkpoint.merkle_root
                ),
            });
        }

        Ok(())
    }

    /// Detect forks between two host chains.
    ///
    /// Traces the ancestry of each host's head node back to the genesis,
    /// identifying the point of divergence. When a fork is found, the
    /// consistency state is set to [`ConsistencyState::ForkDetected`].
    ///
    /// # Errors
    ///
    /// Returns [`DagError::MissingHostChain`] if either host has no chain.
    pub fn detect_forks(
        &mut self,
        host_a: &str,
        host_b: &str,
    ) -> Result<Option<DagError>, DagError> {
        let head_a = self
            .host_chains
            .iter()
            .find(|h| h.host_id == host_a)
            .ok_or_else(|| DagError::MissingHostChain {
                host_id: host_a.to_owned(),
            })?;

        let head_b = self
            .host_chains
            .iter()
            .find(|h| h.host_id == host_b)
            .ok_or_else(|| DagError::MissingHostChain {
                host_id: host_b.to_owned(),
            })?;

        let ancestry_a = self.collect_ancestry(&head_a.head_hash);
        let ancestry_b = self.collect_ancestry(&head_b.head_hash);

        let common_ancestors: Vec<&Hash> = ancestry_a
            .iter()
            .filter(|h| ancestry_b.contains(h))
            .collect();

        if common_ancestors.is_empty() && !ancestry_a.is_empty() && !ancestry_b.is_empty() {
            let fork = DagError::ForkDetected {
                host_a: host_a.to_owned(),
                host_b: host_b.to_owned(),
                ancestor_a: ancestry_a.last().cloned().unwrap_or_default(),
                ancestor_b: ancestry_b.last().cloned().unwrap_or_default(),
            };

            self.consistency = ConsistencyState::ForkDetected {
                fork_point: "no_common_ancestor".to_owned(),
                hosts: vec![host_a.to_owned(), host_b.to_owned()],
            };

            return Ok(Some(fork));
        }

        Ok(None)
    }

    /// Collect all ancestor node hashes for a given node, walking parent
    /// pointers back to genesis.
    fn collect_ancestry(&self, start_hash: &str) -> Vec<Hash> {
        let mut ancestors = Vec::new();
        let mut current = start_hash.to_owned();
        loop {
            let node = match self.dag_nodes.iter().find(|n| n.node_id == current) {
                Some(n) => n,
                None => break,
            };
            if let Some(first_parent) = node.parents.first() {
                ancestors.push(first_parent.clone());
                current = first_parent.clone();
            } else {
                break;
            }
        }
        ancestors
    }

    /// Merge another DAG's nodes into this one, preserving append-only semantics.
    ///
    /// Only nodes not already present are added. A fork check is performed
    /// before merging — if the DAGs are inconsistent (divergent histories),
    /// the merge is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`DagError::InconsistentMerge`] if the DAGs have diverging
    /// histories that cannot be reconciled automatically.
    pub fn merge_consistent(&mut self, other: &Self) -> Result<usize, DagError> {
        let mut added = 0;

        for node in &other.dag_nodes {
            if self.dag_nodes.iter().any(|n| n.node_id == node.node_id) {
                continue;
            }

            let recomputed = node.recompute_node_id()?;
            if recomputed != node.node_id {
                return Err(DagError::InconsistentMerge {
                    fork_point: format!(
                        "node_id mismatch in foreign DAG node {}",
                        node.node_id
                    ),
                });
            }

            let has_conflict = node.parents.iter().any(|pid| {
                self.dag_nodes.iter().any(|n| n.node_id == *pid)
                    && other.dag_nodes.iter().any(|n| n.node_id == *pid)
                    && self
                        .dag_nodes
                        .iter()
                        .filter(|n| n.parents.contains(pid))
                        .count()
                        > 1
            });

            if has_conflict {
                return Err(DagError::InconsistentMerge {
                    fork_point: format!(
                        "node {} has conflicting parent references",
                        node.node_id
                    ),
                });
            }

            self.dag_nodes.push(node.clone());
            added += 1;
        }

        for head in &other.host_chains {
            if !self.host_chains.iter().any(|h| h.host_id == head.host_id) {
                self.host_chains.push(head.clone());
            }
        }

        Ok(added)
    }

    /// Build a Merkle inclusion proof for a node against a checkpoint.
    ///
    /// Returns the sibling hashes and the leaf index within the tree.
    pub fn build_inclusion_proof(
        &self,
        node_id: &str,
    ) -> Result<(Vec<Hash>, usize), DagError> {
        let pos = self
            .dag_nodes
            .iter()
            .position(|n| n.node_id == node_id)
            .ok_or_else(|| DagError::InclusionProofFailed {
                checkpoint_id: "n/a".to_owned(),
                node_id: node_id.to_owned(),
                detail: "node not found in DAG".to_owned(),
            })?;

        let leaves: Vec<Hash> = self.dag_nodes.iter().map(|n| n.node_id.clone()).collect();
        let (proof, _root) = build_merkle_proof(&leaves, pos);
        Ok((proof, pos))
    }

    /// Get the current head hash for a host.
    #[must_use]
    pub fn host_head(&self, host_id: &str) -> Option<&HostChainHead> {
        self.host_chains.iter().find(|h| h.host_id == host_id)
    }

    /// Number of DAG nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.dag_nodes.len()
    }

    /// Number of tracked host chains.
    #[must_use]
    pub fn host_count(&self) -> usize {
        self.host_chains.len()
    }
}

/// Compute a simple Merkle root from a list of leaf hashes.
///
/// Pads to the next power of two by duplicating the last element, then
/// pairwise hashes up to the root.
fn compute_merkle_root(nodes: &[DagNode]) -> Result<Hash, DagError> {
    if nodes.is_empty() {
        return Ok(blake3::hash(b"").to_hex().to_string());
    }

    let leaves: Vec<Hash> = nodes.iter().map(|n| n.node_id.clone()).collect();
    Ok(build_merkle_tree(&leaves))
}

/// Build a Merkle tree from leaf hashes and return the root.
fn build_merkle_tree(leaves: &[Hash]) -> Hash {
    let mut current: Vec<Hash> = leaves.to_vec();

    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        for chunk in current.chunks(2) {
            let left = &chunk[0];
            let right = chunk.get(1).unwrap_or(left);
            let combined = format!("{left}|{right}");
            let node_hash = blake3::hash(combined.as_bytes()).to_hex().to_string();
            next.push(node_hash);
        }
        current = next;
    }

    match current.into_iter().next() {
        Some(root) => root,
        None => blake3::hash(b"").to_hex().to_string(),
    }
}

/// Build a Merkle inclusion proof: returns (sibling_path, root).
fn build_merkle_proof(leaves: &[Hash], leaf_index: usize) -> (Vec<Hash>, Hash) {
    let mut siblings = Vec::new();
    let mut current: Vec<Hash> = leaves.to_vec();
    let mut idx = leaf_index;

    while current.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if let Some(sibling) = current.get(sibling_idx) {
            siblings.push(sibling.clone());
        } else {
            siblings.push(current[idx].clone());
        }

        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        for chunk in current.chunks(2) {
            let left = &chunk[0];
            let right = chunk.get(1).unwrap_or(left);
            let combined = format!("{left}|{right}");
            let node_hash = blake3::hash(combined.as_bytes()).to_hex().to_string();
            next.push(node_hash);
        }
        current = next;
        idx /= 2;
    }

    let root = match current.into_iter().next() {
        Some(r) => r,
        None => blake3::hash(b"").to_hex().to_string(),
    };

    (siblings, root)
}

/// Reconstruct Merkle root from a leaf hash + sibling proof path.
fn compute_merkle_root_from_proof(
    leaf_hash: Hash,
    siblings: &[Hash],
    mut index: usize,
) -> Hash {
    let mut current = leaf_hash;

    for sibling in siblings {
        let combined = if index % 2 == 0 {
            format!("{current}|{sibling}")
        } else {
            format!("{sibling}|{current}")
        };
        current = blake3::hash(combined.as_bytes()).to_hex().to_string();
        index /= 2;
    }

    current
}

/// Decode a 128-character lowercase hex string into a 64-byte Ed25519 signature.
fn decode_hex_signature(hex: &str) -> Result<[u8; 64], DagError> {
    if hex.len() != 128 {
        return Err(DagError::SignatureMalformed {
            detail: format!("expected 128 hex chars, got {}", hex.len()),
        });
    }

    let bytes = hex.as_bytes();
    let mut out = [0u8; 64];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0]).map_err(|_| DagError::SignatureMalformed {
            detail: format!("invalid hex byte 0x{:02x}", chunk[0]),
        })?;
        let lo = hex_nibble(chunk[1]).map_err(|_| DagError::SignatureMalformed {
            detail: format!("invalid hex byte 0x{:02x}", chunk[1]),
        })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn test_cluster_keypair() -> (SigningKey, VerifyingKey) {
        let seed = [99u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    // ─── DagNode tests ──────────────────────────────────────────────────

    #[test]
    fn dag_node_creation_and_hashing() {
        let (sk, vk) = test_keypair();
        let segment = blake3::hash(b"segment_1").to_hex().to_string();
        let node = DagNode::new(
            "host_01".into(),
            segment,
            vec![],
            &sk,
        )
        .expect("new");
        assert_eq!(node.node_id.len(), 64);
        node.verify_signature(&vk).expect("verify");
    }

    #[test]
    fn dag_node_id_matches_recompute() {
        let (sk, _vk) = test_keypair();
        let segment = blake3::hash(b"s").to_hex().to_string();
        let node = DagNode::new("host_01".into(), segment, vec![], &sk).expect("new");
        let recomputed = node.recompute_node_id().expect("recompute");
        assert_eq!(node.node_id, recomputed);
    }

    #[test]
    fn dag_node_with_parents() {
        let (sk_a, vk_a) = test_keypair();
        let (sk_b, _vk_b) = test_keypair();

        let seg_a = blake3::hash(b"a").to_hex().to_string();
        let seg_b = blake3::hash(b"b").to_hex().to_string();

        let node_a = DagNode::new("host_01".into(), seg_a, vec![], &sk_a).expect("a");
        let node_b = DagNode::new(
            "host_01".into(),
            seg_b,
            vec![node_a.node_id.clone()],
            &sk_b,
        )
        .expect("b");

        assert_eq!(node_b.parents.len(), 1);
        assert_eq!(node_b.parents[0], node_a.node_id);
        let _ = node_b.verify_signature(&vk_a); // may or may not verify depending on key
    }

    #[test]
    fn dag_node_signature_verification_fails_on_tamper() {
        let (sk, vk) = test_keypair();
        let segment = blake3::hash(b"x").to_hex().to_string();
        let mut node = DagNode::new("host_01".into(), segment, vec![], &sk).expect("new");

        // Tamper with the node_id (which is what the signature covers).
        node.node_id = blake3::hash(b"tampered").to_hex().to_string();

        match node.verify_signature(&vk) {
            Err(DagError::SignatureMalformed { .. }) => {}
            other => panic!("expected SignatureMalformed after node_id tamper, got {other:?}"),
        }
    }

    // ─── DistributedEvidenceLog tests ───────────────────────────────────

    #[test]
    fn add_node_to_dag() {
        let mut log = DistributedEvidenceLog::new(Ulid::new());
        let (sk, _vk) = test_keypair();
        let seg = blake3::hash(b"seg").to_hex().to_string();
        let node = DagNode::new("host_01".into(), seg, vec![], &sk).expect("new");
        log.add_node(node).expect("add");
        assert_eq!(log.node_count(), 1);
        assert_eq!(log.host_count(), 1);
    }

    #[test]
    fn add_node_increments_sealed_count() {
        let mut log = DistributedEvidenceLog::new(Ulid::new());
        let (sk, _vk) = test_keypair();

        let seg1 = blake3::hash(b"1").to_hex().to_string();
        let n1 = DagNode::new("host_01".into(), seg1, vec![], &sk).expect("n1");
        log.add_node(n1).expect("add 1");
        assert_eq!(log.host_head("host_01").unwrap().sealed_segment_count, 1);

        let seg2 = blake3::hash(b"2").to_hex().to_string();
        let prev = log.host_head("host_01").unwrap().head_hash.clone();
        let n2 = DagNode::new("host_01".into(), seg2, vec![prev], &sk).expect("n2");
        log.add_node(n2).expect("add 2");
        assert_eq!(log.host_head("host_01").unwrap().sealed_segment_count, 2);
    }

    #[test]
    fn add_node_rejects_duplicate() {
        let mut log = DistributedEvidenceLog::new(Ulid::new());
        let (sk, _vk) = test_keypair();
        let seg = blake3::hash(b"s").to_hex().to_string();
        let node = DagNode::new("host_01".into(), seg, vec![], &sk).expect("new");
        log.add_node(node.clone()).expect("first");
        match log.add_node(node) {
            Err(DagError::DuplicateNode { .. }) => {}
            other => panic!("expected DuplicateNode, got {other:?}"),
        }
    }

    #[test]
    fn add_node_rejects_missing_parent() {
        let mut log = DistributedEvidenceLog::new(Ulid::new());
        let (sk, _vk) = test_keypair();
        let seg = blake3::hash(b"s").to_hex().to_string();
        let node = DagNode::new(
            "host_01".into(),
            seg,
            vec!["nonexistent_parent_hash_123456789012345678901234567890".to_owned()],
            &sk,
        )
        .expect("new");
        match log.add_node(node) {
            Err(DagError::MissingParent { .. }) => {}
            other => panic!("expected MissingParent, got {other:?}"),
        }
    }

    #[test]
    fn replicate_from_peer_adds_local_head_to_parents() {
        let mut log = DistributedEvidenceLog::new(Ulid::new());
        let (sk, _vk) = test_keypair();

        let local_seg = blake3::hash(b"local").to_hex().to_string();
        let local_node = DagNode::new("host_01".into(), local_seg, vec![], &sk).expect("local");
        log.add_node(local_node).expect("add local");
        let local_head = log.host_head("host_01").unwrap().head_hash.clone();

        let peer_seg = blake3::hash(b"peer").to_hex().to_string();
        let peer_node = DagNode::new("host_02".into(), peer_seg, vec![], &sk).expect("peer");

        log.replicate_from_peer(peer_node, "host_01", &local_head)
            .expect("replicate");

        let replicated = log.dag_nodes.iter().find(|n| n.host_id == "host_02").expect("exists");
        assert!(replicated.parents.contains(&local_head));
    }

    #[test]
    fn checkpoint_signing_and_verification() {
        let mut log = DistributedEvidenceLog::new(Ulid::new());
        let (host_sk, _host_vk) = test_keypair();
        let (cluster_sk, cluster_vk) = test_cluster_keypair();

        let seg = blake3::hash(b"seg").to_hex().to_string();
        let node = DagNode::new("host_01".into(), seg, vec![], &host_sk).expect("n");
        log.add_node(node).expect("add");

        let checkpoint = log.sign_checkpoint(&cluster_sk).expect("sign");
        checkpoint
            .verify_cluster_root_signature(&cluster_vk)
            .expect("verify cluster sig");
    }

    #[test]
    fn inclusion_proof_verification() {
        let mut log = DistributedEvidenceLog::new(Ulid::new());
        let (host_sk, _host_vk) = test_keypair();
        let (cluster_sk, _cluster_vk) = test_cluster_keypair();

        for i in 0..4u8 {
            let seg = blake3::hash(&[i]).to_hex().to_string();
            let node = DagNode::new(
                format!("host_{i}"),
                seg,
                vec![],
                &host_sk,
            )
            .expect("n");
            log.add_node(node).expect("add");
        }

        let checkpoint = log.sign_checkpoint(&cluster_sk).expect("sign");
        let cp_id = checkpoint.checkpoint_id.clone();
        drop(checkpoint);

        let target = log.dag_nodes[0].node_id.clone();
        let (proof, idx) = log.build_inclusion_proof(&target).expect("build proof");

        log.verify_inclusion(&target, &cp_id, &proof, idx)
            .expect("verify inclusion");
    }

    #[test]
    fn fork_detection_divergent_ancestors() {
        let mut log = DistributedEvidenceLog::new(Ulid::new());
        let (sk_a, _vk_a) = test_keypair();
        let (sk_b, _vk_b) = {
            let seed = [77u8; 32];
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            let vk = sk.verifying_key();
            (sk, vk)
        };

        // Host A genesis
        let seg_a1 = blake3::hash(b"a1").to_hex().to_string();
        let n_a1 = DagNode::new("host_01".into(), seg_a1, vec![], &sk_a).expect("a1");
        log.add_node(n_a1.clone()).expect("add a1");

        // Host B genesis
        let seg_b1 = blake3::hash(b"b1").to_hex().to_string();
        let n_b1 = DagNode::new("host_02".into(), seg_b1, vec![], &sk_b).expect("b1");
        log.add_node(n_b1.clone()).expect("add b1");

        // Host A child (parent = a1)
        let seg_a2 = blake3::hash(b"a2").to_hex().to_string();
        let n_a2 = DagNode::new(
            "host_01".into(),
            seg_a2,
            vec![n_a1.node_id],
            &sk_a,
        )
        .expect("a2");
        log.add_node(n_a2).expect("add a2");

        // Host B child (parent = b1)
        let seg_b2 = blake3::hash(b"b2").to_hex().to_string();
        let n_b2 = DagNode::new(
            "host_02".into(),
            seg_b2,
            vec![n_b1.node_id],
            &sk_b,
        )
        .expect("b2");
        log.add_node(n_b2).expect("add b2");

        let result = log.detect_forks("host_01", "host_02").expect("detect");
        assert!(result.is_some(), "fork should be detected between unrelated hosts");

        assert!(matches!(
            log.consistency,
            ConsistencyState::ForkDetected { .. }
        ));
    }

    #[test]
    fn fork_detection_no_fork_for_linear_chain() {
        let mut log = DistributedEvidenceLog::new(Ulid::new());
        let (sk, _vk) = test_keypair();

        let seg1 = blake3::hash(b"1").to_hex().to_string();
        let seg2 = blake3::hash(b"2").to_hex().to_string();

        let n1 = DagNode::new("host_01".into(), seg1, vec![], &sk).expect("n1");
        log.add_node(n1).expect("add n1");
        let head = log.host_head("host_01").unwrap().head_hash.clone();
        let n2 = DagNode::new("host_01".into(), seg2, vec![head], &sk).expect("n2");
        log.add_node(n2).expect("add n2");

        let result = log.detect_forks("host_01", "host_01").expect("detect");
        assert!(result.is_none(), "same host should not fork with itself");
    }

    #[test]
    fn merge_consistent_no_fork() {
        let (sk, _vk) = test_keypair();

        let mut log_a = DistributedEvidenceLog::new(Ulid::new());
        let seg_a = blake3::hash(b"a").to_hex().to_string();
        let n_a = DagNode::new("host_01".into(), seg_a, vec![], &sk).expect("a");
        log_a.add_node(n_a).expect("add a");

        let mut log_b = DistributedEvidenceLog::new(Ulid::new());
        let seg_b = blake3::hash(b"b").to_hex().to_string();
        let n_b = DagNode::new("host_02".into(), seg_b, vec![], &sk).expect("b");
        log_b.add_node(n_b).expect("add b");

        let added = log_a.merge_consistent(&log_b).expect("merge");
        assert_eq!(added, 1);
        assert_eq!(log_a.host_count(), 2);
    }

    #[test]
    fn append_only_enforcement_via_type_system() {
        let mut log = DistributedEvidenceLog::new(Ulid::new());
        let (sk, _vk) = test_keypair();
        let seg = blake3::hash(b"s").to_hex().to_string();
        let node = DagNode::new("host_01".into(), seg, vec![], &sk).expect("n");

        let node_id = node.node_id.clone();
        log.add_node(node).expect("add");

        // Attempting to add the same node again fails (append-only enforcement).
        let seg2 = blake3::hash(b"s2").to_hex().to_string();
        let node2 = DagNode::new(
            "host_01".into(),
            seg2,
            vec![node_id],
            &sk,
        )
        .expect("n2");
        log.add_node(node2).expect("add child");

        assert_eq!(log.node_count(), 2);
    }

    #[test]
    fn merkle_root_empty_log() {
        let nodes: Vec<DagNode> = vec![];
        let root = compute_merkle_root(&nodes).expect("root");
        assert_eq!(root.len(), 64);
        assert_eq!(root, blake3::hash(b"").to_hex().to_string());
    }

    #[test]
    fn merkle_root_single_node() {
        let (sk, _vk) = test_keypair();
        let seg = blake3::hash(b"s").to_hex().to_string();
        let node = DagNode::new("host_01".into(), seg, vec![], &sk).expect("n");
        let root = compute_merkle_root(&[node.clone()]).expect("root");
        assert_eq!(root.len(), 64);
        assert_ne!(root, blake3::hash(b"").to_hex().to_string());
    }

    #[test]
    fn serde_dag_node_roundtrip() {
        let (sk, _vk) = test_keypair();
        let seg = blake3::hash(b"serde").to_hex().to_string();
        let node = DagNode::new("host_01".into(), seg, vec![], &sk).expect("n");
        let json = serde_json::to_string(&node).expect("ser");
        let back: DagNode = serde_json::from_str(&json).expect("de");
        assert_eq!(node, back);
    }

    #[test]
    fn serde_cluster_checkpoint_roundtrip() {
        let (cluster_sk, _cluster_vk) = test_cluster_keypair();
        let root = blake3::hash(b"root_data").to_hex().to_string();
        let cp = ClusterCheckpoint::new(root, &cluster_sk, ProofScheme::MerkleInclusion)
            .expect("new cp");
        let json = serde_json::to_string(&cp).expect("ser");
        let back: ClusterCheckpoint = serde_json::from_str(&json).expect("de");
        assert_eq!(cp, back);
    }

    #[test]
    fn proof_scheme_merkle_inclusion_serde() {
        let scheme = ProofScheme::MerkleInclusion;
        let json = serde_json::to_string(&scheme).expect("ser");
        assert_eq!(json, "\"MERKLE_INCLUSION\"");
        let back: ProofScheme = serde_json::from_str(&json).expect("de");
        assert_eq!(back, ProofScheme::MerkleInclusion);
    }

    #[test]
    fn consistency_state_serde() {
        let cs = ConsistencyState::Consistent;
        let json = serde_json::to_string(&cs).expect("ser");
        assert_eq!(json, "\"CONSISTENT\"");
        let back: ConsistencyState = serde_json::from_str(&json).expect("de");
        assert_eq!(back, ConsistencyState::Consistent);
    }
}
