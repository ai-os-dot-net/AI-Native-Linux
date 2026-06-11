//! Fleet evidence record types extending the S3.1 evidence vocabulary (S25 §10).
//!
//! Defines 14 new [`FleetRecordType`] variants for fleet/cluster operations that
//! fall outside the single-host [`aios_evidence::record::RecordType`] vocabulary.
//! These are serialized with `SCREAMING_SNAKE_CASE` names and emitted through
//! the fleet evidence pipeline.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// Fleet-specific evidence record types for cluster operations.
///
/// These 14 variants extend the single-host `RecordType` vocabulary (427 entries)
/// with fleet/cluster lifecycle events. They are serialized as standalone
/// `SCREAMING_SNAKE_CASE` strings compatible with the S3.1 evidence log wire format.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FleetRecordType {
    /// A host has been enrolled into the fleet cluster.
    FleetHostEnrolled,

    /// A host has been suspended from active duty.
    FleetHostSuspended,

    /// A host has been permanently withdrawn from the fleet.
    FleetHostWithdrawn,

    /// The cluster root key signed a new checkpoint.
    ClusterRootSigned,

    /// The cluster root key has been rotated to a new key.
    ClusterRootRotated,

    /// A workload was routed to a remote host for execution.
    RemoteWorkloadRouted,

    /// A remote workload execution result was received.
    RemoteWorkloadResult,

    /// Evidence DAG nodes were replicated from a peer host.
    EvidenceDagReplicated,

    /// A cluster checkpoint was signed over the evidence DAG.
    EvidenceDagCheckpointSigned,

    /// A fork was detected in the distributed evidence DAG.
    EvidenceDagForkDetected,

    /// A federated identity was resolved across realms.
    FederatedIdentityResolved,

    /// A cross-org trust delegation was granted.
    CrossOrgDelegationGranted,

    /// A cross-org trust delegation was revoked.
    CrossOrgDelegationRevoked,

    /// A host policy override from the cluster was denied due to host policy supremacy.
    HostPolicyOverrideDenied,
}

impl FleetRecordType {
    /// Return the canonical `SCREAMING_SNAKE_CASE` wire name.
    #[must_use]
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::FleetHostEnrolled => "FLEET_HOST_ENROLLED",
            Self::FleetHostSuspended => "FLEET_HOST_SUSPENDED",
            Self::FleetHostWithdrawn => "FLEET_HOST_WITHDRAWN",
            Self::ClusterRootSigned => "CLUSTER_ROOT_SIGNED",
            Self::ClusterRootRotated => "CLUSTER_ROOT_ROTATED",
            Self::RemoteWorkloadRouted => "REMOTE_WORKLOAD_ROUTED",
            Self::RemoteWorkloadResult => "REMOTE_WORKLOAD_RESULT",
            Self::EvidenceDagReplicated => "EVIDENCE_DAG_REPLICATED",
            Self::EvidenceDagCheckpointSigned => "EVIDENCE_DAG_CHECKPOINT_SIGNED",
            Self::EvidenceDagForkDetected => "EVIDENCE_DAG_FORK_DETECTED",
            Self::FederatedIdentityResolved => "FEDERATED_IDENTITY_RESOLVED",
            Self::CrossOrgDelegationGranted => "CROSS_ORG_DELEGATION_GRANTED",
            Self::CrossOrgDelegationRevoked => "CROSS_ORG_DELEGATION_REVOKED",
            Self::HostPolicyOverrideDenied => "HOST_POLICY_OVERRIDE_DENIED",
        }
    }
}

// ─── Typed payload structs ──────────────────────────────────────────────

/// Payload for `FLEET_HOST_ENROLLED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHostEnrolledPayload {
    pub host_id: String,
    pub cluster_id: String,
    pub membership_id: String,
    pub authorized_by: String,
}

/// Payload for `FLEET_HOST_SUSPENDED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHostSuspendedPayload {
    pub host_id: String,
    pub cluster_id: String,
    pub reason: String,
    pub authorized_by: String,
}

/// Payload for `FLEET_HOST_WITHDRAWN`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHostWithdrawnPayload {
    pub host_id: String,
    pub cluster_id: String,
    pub voluntary: bool,
    pub reason: String,
}

/// Payload for `CLUSTER_ROOT_SIGNED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterRootSignedPayload {
    pub cluster_id: String,
    pub checkpoint_id: String,
    pub rotation_index: u64,
}

/// Payload for `CLUSTER_ROOT_ROTATED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterRootRotatedPayload {
    pub cluster_id: String,
    pub old_rotation_index: u64,
    pub new_rotation_index: u64,
    pub new_key_fingerprint: String,
}

/// Payload for `REMOTE_WORKLOAD_ROUTED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWorkloadRoutedPayload {
    pub source_host_id: String,
    pub target_host_id: String,
    pub action_id: String,
    pub routing_reason: String,
}

/// Payload for `REMOTE_WORKLOAD_RESULT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWorkloadResultPayload {
    pub source_host_id: String,
    pub executor_host_id: String,
    pub action_id: String,
    pub success: bool,
    pub result_summary: Option<String>,
}

/// Payload for `EVIDENCE_DAG_REPLICATED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceDagReplicatedPayload {
    pub target_host_id: String,
    pub source_host_id: String,
    pub node_count: u64,
    pub last_node_hash: String,
}

/// Payload for `EVIDENCE_DAG_CHECKPOINT_SIGNED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceDagCheckpointSignedPayload {
    pub cluster_id: String,
    pub checkpoint_id: String,
    pub merkle_root: String,
    pub node_count: u64,
}

/// Payload for `EVIDENCE_DAG_FORK_DETECTED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceDagForkDetectedPayload {
    pub cluster_id: String,
    pub involved_hosts: Vec<String>,
    pub fork_point: String,
    pub divergent_ancestors: Vec<String>,
}

/// Payload for `FEDERATED_IDENTITY_RESOLVED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedIdentityResolvedPayload {
    pub source_realm: String,
    pub local_subject_id: String,
    pub federated_subject_id: String,
    pub cluster_id: String,
}

/// Payload for `CROSS_ORG_DELEGATION_GRANTED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossOrgDelegationGrantedPayload {
    pub source_org: String,
    pub target_org: String,
    pub delegated_by: String,
    pub delegated_to: String,
    pub ttl: Option<String>,
}

/// Payload for `CROSS_ORG_DELEGATION_REVOKED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossOrgDelegationRevokedPayload {
    pub source_org: String,
    pub target_org: String,
    pub revoked_by: String,
    pub revoked_from: String,
}

/// Payload for `HOST_POLICY_OVERRIDE_DENIED`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPolicyOverrideDeniedPayload {
    pub host_id: String,
    pub cluster_id: String,
    pub denied_action: String,
    pub reason: String,
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
    use strum::IntoEnumIterator;

    #[test]
    fn fleet_record_type_count_is_14() {
        let variants: Vec<_> = FleetRecordType::iter().collect();
        assert_eq!(variants.len(), 14);
    }

    #[test]
    fn fleet_record_type_wire_names_are_screaming_snake_case() {
        for variant in FleetRecordType::iter() {
            let wire = variant.as_wire_str();
            assert!(
                wire.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "wire name {wire} must be SCREAMING_SNAKE_CASE"
            );
        }
    }

    #[test]
    fn serde_roundtrip_all_14_record_types() {
        for variant in FleetRecordType::iter() {
            let json = serde_json::to_string(&variant).expect("ser");
            let expected = format!("\"{}\"", variant.as_wire_str());
            assert_eq!(json, expected);
            let parsed: FleetRecordType = serde_json::from_str(&json).expect("de");
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn serde_payload_roundtrips() {
        let p = FleetHostEnrolledPayload {
            host_id: "h1".into(), cluster_id: "c1".into(),
            membership_id: "m1".into(), authorized_by: "op1".into(),
        };
        let json = serde_json::to_string(&p).expect("ser");
        let back: FleetHostEnrolledPayload = serde_json::from_str(&json).expect("de");
        assert_eq!(p, back);
    }

    #[test]
    fn serde_dag_fork_payload_roundtrip() {
        let p = EvidenceDagForkDetectedPayload {
            cluster_id: "c1".into(),
            involved_hosts: vec!["h1".into(), "h2".into()],
            fork_point: "fp".into(),
            divergent_ancestors: vec!["a1".into(), "a2".into()],
        };
        let json = serde_json::to_string(&p).expect("ser");
        let back: EvidenceDagForkDetectedPayload = serde_json::from_str(&json).expect("de");
        assert_eq!(p, back);
    }

    #[test]
    fn serde_host_policy_override_denied_roundtrip() {
        let p = HostPolicyOverrideDeniedPayload {
            host_id: "h1".into(), cluster_id: "c1".into(),
            denied_action: "SUSPEND".into(), reason: "INV-026".into(),
        };
        let json = serde_json::to_string(&p).expect("ser");
        let back: HostPolicyOverrideDeniedPayload = serde_json::from_str(&json).expect("de");
        assert_eq!(p, back);
    }
}
