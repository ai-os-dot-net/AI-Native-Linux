//! `aios-fleet` — typed core skeleton for S25 Fleet, Cluster, and Remote Execution.
//!
//! Provides the type surface for cluster trust roots, fleet membership state machines,
//! federated identity across realms, cross-org trust delegation, remote workload
//! routing decisions, cross-host sandbox floor enforcement, cluster overlay
//! network control, and distributed evidence Merkle-DAG (SPEC S25).

#![forbid(unsafe_code)]

pub mod cluster_overlay;
pub mod cluster_root;
pub mod distributed_evidence;
pub mod distribution_rollout;
pub mod enums;
pub mod error;
pub mod evidence;
pub mod federated_identity;
pub mod fleet_policy;
pub mod fleet_recovery;
pub mod identity_resolver;
pub mod membership;
pub mod membership_driver;
pub mod quorum;
pub mod remote_execution;
pub mod remote_routing;
pub mod remote_sandbox;
pub mod trust_delegation;
pub mod zero_trust;

pub use cluster_overlay::{
    ClusterOverlayError, ClusterOverlayNetwork, CoordinatorElection, MeshConnection,
    OverlayEvidenceEmitter, OverlayPeer, OverlayRole, OverlayTopologySummary, PeerState,
    WireGuardKey,
};
pub use cluster_root::ClusterTrustRoot;
pub use distributed_evidence::{
    ClusterCheckpoint, ConsistencyState, DagError, DagNode, DistributedEvidenceLog, HostChainHead,
    ProofScheme,
};
pub use distribution_rollout::{
    DistributionSource, FleetDistributionRollout, FleetRolloutRecordType, HostInstallStatus,
    PackageRef, PhaseState, RolloutError, RolloutHostState, RolloutPhase, RolloutStatus,
    RolloutStrategy, RolloutSummary,
};
pub use enums::{
    ClusterOverlayMode, ClusterRole, ClusterTrustScope, FleetMembershipState, RemoteRoutingClass,
    RemoteRoutingReason, TrustDelegationDirection,
};
pub use error::MembershipError;
pub use evidence::FleetRecordType;
pub use federated_identity::{FederatedIdentityBundle, FederatedSubjectId};
pub use fleet_policy::{
    ClusterAction, FleetHardDenyRule, FleetPolicyDenial, FleetPolicyError, FleetPolicyGate,
    SecurityProfile,
};
pub use fleet_recovery::{
    CoordinatorHeartbeat, FleetHealthReport, FleetHealthStatus, FleetRecoveryCoordinator,
    FleetRecoveryError,
};
pub use identity_resolver::{
    FederatedIdentityResolver, RealmDescriptor, RealmStatus, ResolvedSubject,
};
pub use membership::FleetMembership;
pub use membership_driver::FleetMembershipDriver as MembershipDriver;
pub use quorum::QuorumManager;
pub use remote_execution::{
    FleetEvidenceEmitter, InMemoryFleetEvidenceLog, NoopFleetEvidenceEmitter, PolicyDecision,
    RemoteExecutionError, RemoteExecutionJob, RemoteJobState, RemoteWorkloadRouter, WorkloadRef,
    AIOS_FLEET_SUBJECT,
};
pub use remote_routing::RemoteWorkloadRouting;
pub use remote_sandbox::{
    CrossHostSandboxError, CrossHostSandboxFloor, SecurityProfileLevel, StricterOf,
};
pub use trust_delegation::CrossOrgTrustDelegation;
pub use zero_trust::{
    PostureDrift, TrustLevel, ZeroTrustCheck, ZeroTrustCheckResult, ZeroTrustEngine,
    ZeroTrustEvidence, ZeroTrustEvidenceKind, ZeroTrustPolicy, ZeroTrustPosture,
};
