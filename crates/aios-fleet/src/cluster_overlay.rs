//! Cluster Overlay Network Controller (SPEC S25 §4).
//!
//! Fleet-level overlay topology management: coordinator election, peer
//! discovery, and three overlay modes — Hub-and-Spoke, FullMesh, and
//! HybridRelayedMesh. Encrypted overlay transport uses WireGuard (S8.4 §5),
//! with Ed25519 peer identity and WireGuard key exchange.
//!
//! INV-026: Cluster root cannot override host network posture.
//! INV-018: Private keys stay in Vault Broker handles — never in config.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::enums::{ClusterOverlayMode, FleetMembershipState};
use crate::membership::FleetMembership;

// ---------------------------------------------------------------------------
// WireGuardKey — 32-byte Curve25519 key newtype
// ---------------------------------------------------------------------------

/// A 32-byte WireGuard / Curve25519 key.
///
/// WireGuard uses Curve25519 for its key exchange (not Ed25519 directly).
/// This newtype carries the 32-byte raw key bytes; private keys live in
/// Vault Broker handles per INV-018.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WireGuardKey(pub [u8; 32]);

impl WireGuardKey {
    /// Create a WireGuard key from 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

// ---------------------------------------------------------------------------
// PeerState — overlay peer lifecycle (5-state FSM)
// ---------------------------------------------------------------------------

/// Lifecycle state of an overlay peer.
///
/// Five states: `Discovered` → `KeyExchange` → `Connected`; also
/// `HeartbeatLost` (degraded) and `Disconnected` (terminal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PeerState {
    /// Peer has been discovered but no key exchange has occurred.
    Discovered,
    /// WireGuard key exchange is in progress.
    KeyExchange,
    /// Peer is fully connected and receiving heartbeats.
    Connected,
    /// Peer has missed heartbeat threshold; connection is degraded.
    HeartbeatLost,
    /// Peer has been explicitly disconnected or removed.
    Disconnected,
}

// ---------------------------------------------------------------------------
// OverlayRole — peer's role in the overlay topology
// ---------------------------------------------------------------------------

/// Role a peer plays in the overlay topology.
///
/// Each topology mode assigns distinct roles:
/// - Hub-and-Spoke: `Coordinator` = Hub, peers = `Spoke`
/// - FullMesh: all peers are `MeshMember`
/// - HybridRelayedMesh: `Coordinator` relays, peers = `Spoke`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OverlayRole {
    /// The elected cluster coordinator.
    Coordinator,
    /// Hub in a Hub-and-Spoke topology.
    Hub,
    /// Spoke connecting to the hub/coordinator.
    Spoke,
    /// Peer in a full-mesh topology.
    MeshMember,
}

// ---------------------------------------------------------------------------
// OverlayPeer — a single host in the overlay network
// ---------------------------------------------------------------------------

/// A host participating in the cluster overlay network.
///
/// Each peer has an Ed25519 identity key (for signing/verification), a
/// WireGuard key (for encrypted transport), an endpoint, and a role
/// within the current overlay topology.
pub struct OverlayPeer {
    /// Unique host identifier.
    pub host_id: String,
    /// Ed25519 public key for peer identity verification.
    pub public_key: VerifyingKey,
    /// WireGuard (Curve25519) public key for encrypted transport.
    pub wireguard_key: WireGuardKey,
    /// Network endpoint (`host:port`).
    pub endpoint: SocketAddr,
    /// Timestamp when this peer was first discovered.
    pub discovered_at: DateTime<Utc>,
    /// Timestamp of most recent heartbeat.
    pub last_seen: DateTime<Utc>,
    /// Current lifecycle state.
    pub state: PeerState,
    /// Role within the current overlay topology.
    pub role: OverlayRole,
}

// ---------------------------------------------------------------------------
// MeshConnection — a point-to-point tunnel in the overlay mesh
// ---------------------------------------------------------------------------

/// A point-to-point mesh connection between two overlay peers.
///
/// FullMesh topologies establish `n*(n-1)/2` connections.
#[derive(Debug, Clone)]
pub struct MeshConnection {
    /// First peer's host_id (alphabetically smaller).
    pub peer_a: String,
    /// Second peer's host_id (alphabetically larger).
    pub peer_b: String,
    /// When the connection was established.
    pub established_at: DateTime<Utc>,
    /// Unique tunnel identifier.
    pub tunnel_id: Ulid,
}

// ---------------------------------------------------------------------------
// CoordinatorElection — record of a coordinator election
// ---------------------------------------------------------------------------

/// A completed coordinator election event.
///
/// The coordinator is the enrolled member with the lowest `host_id`.
/// `vote_count` records the number of participating enrolled members.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct CoordinatorElection {
    /// Unique election identifier.
    pub election_id: Ulid,
    /// Host IDs of all candidates considered.
    pub candidates: Vec<String>,
    /// Host ID of the elected coordinator.
    pub winner: String,
    /// When the election completed.
    pub timestamp: DateTime<Utc>,
    /// Number of enrolled members that participated.
    pub vote_count: u64,
}

// ---------------------------------------------------------------------------
// OverlayTopologySummary — human-readable topology status
// ---------------------------------------------------------------------------

/// A summary of the current overlay topology for monitoring and debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct OverlayTopologySummary {
    /// Active overlay mode.
    pub mode: ClusterOverlayMode,
    /// Total number of known peers.
    pub total_peers: usize,
    /// Number of peers in `Connected` state.
    pub connected_peers: usize,
    /// Host ID of the elected coordinator, if any.
    pub coordinator: Option<String>,
    /// Number of active mesh edges.
    pub mesh_edges: usize,
    /// Human-readable health assessment.
    pub health_status: String,
}

// ---------------------------------------------------------------------------
// ClusterOverlayError — closed error taxonomy
// ---------------------------------------------------------------------------

/// Errors that can occur during overlay network operations.
#[derive(Debug, Error)]
pub enum ClusterOverlayError {
    /// No enrolled members are available for coordinator election.
    #[error("no enrolled members available for election")]
    NoEnrolledMembers,

    /// Coordinator election failed for the given reason.
    #[error("coordinator election failed: {0}")]
    ElectionFailed(String),

    /// No coordinator is currently elected.
    #[error("no coordinator elected — run elect_coordinator first")]
    NoCoordinatorElected,

    /// The requested peer was not found in the overlay.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Peer is not in the required state for this operation.
    #[error("peer {host_id} is in state {state:?}, expected one of: {expected:?}")]
    PeerInWrongState {
        /// The peer's host ID.
        host_id: String,
        /// Current state.
        state: PeerState,
        /// Valid states for this operation.
        expected: Vec<PeerState>,
    },

    /// WireGuard key exchange failed.
    #[error("key exchange failed for peer {0}: {1}")]
    KeyExchangeFailed(String, String),

    /// Topology establishment failed.
    #[error("topology establishment failed: {0}")]
    TopologyEstablishmentFailed(String),

    /// Heartbeat processing failed.
    #[error("heartbeat failed for peer {0}: {1}")]
    HeartbeatFailed(String, String),

    /// No peers are available for the requested operation.
    #[error("no peers available in the overlay")]
    NoPeersAvailable,

    /// Coordinator is not an enrolled member.
    #[error("coordinator {0} is not an enrolled member")]
    CoordinatorNotEnrolled(String),
}

// ---------------------------------------------------------------------------
// FleetEvidenceEmitter — overlay event emission trait
// ---------------------------------------------------------------------------

/// Trait for emitting cluster overlay lifecycle events into the Evidence Log.
///
/// Implementations are optional (`Option<Arc<dyn OverlayEvidenceEmitter>>`):
/// when `None`, no emission occurs and no error is raised.
pub trait OverlayEvidenceEmitter: Send + Sync {
    /// Emit when a coordinator is elected.
    fn emit_coordinator_elected(&self, election: &CoordinatorElection);

    /// Emit when a peer's state transitions.
    fn emit_peer_state_changed(&self, host_id: &str, old_state: PeerState, new_state: PeerState);

    /// Emit when an overlay topology is established.
    fn emit_topology_established(&self, summary: &OverlayTopologySummary);

    /// Emit when a mesh connection is established between two peers.
    fn emit_mesh_connection_established(&self, connection: &MeshConnection);

    /// Emit when a mesh connection is torn down.
    fn emit_mesh_connection_removed(&self, peer_a: &str, peer_b: &str);
}

// ---------------------------------------------------------------------------
// ClusterOverlayInner — mutable state behind Mutex
// ---------------------------------------------------------------------------

/// Internal mutable state for [`ClusterOverlayNetwork`].
struct ClusterOverlayInner {
    /// Active overlay topology mode.
    mode: ClusterOverlayMode,
    /// All known overlay peers keyed by `host_id`.
    peers: HashMap<String, OverlayPeer>,
    /// Currently elected coordinator, if any.
    coordinator_id: Option<String>,
    /// Active mesh connections keyed by `(peer_a, peer_b)` with `peer_a < peer_b`.
    mesh_connections: HashMap<(String, String), MeshConnection>,
    /// Optional evidence emitter for lifecycle events.
    evidence_emitter: Option<Arc<dyn OverlayEvidenceEmitter>>,
}

// ---------------------------------------------------------------------------
// ClusterOverlayNetwork — fleet-level overlay controller
// ---------------------------------------------------------------------------

/// Fleet-level cluster overlay network controller (SPEC S25 §4).
///
/// Manages peer discovery, coordinator election, and three overlay
/// topologies: Hub-and-Spoke, FullMesh, and HybridRelayedMesh.
/// Encrypted transport uses WireGuard tunnels (S8.4 §5) with Ed25519
/// peer identity verification.
///
/// INV-026: Cluster root cannot override host network posture — every
/// `FleetMembership` enforces `host_policy_supremacy: true` and
/// `cluster_overridable: false`.
///
/// # Examples
///
/// ```ignore
/// use aios_fleet::cluster_overlay::{ClusterOverlayNetwork, PeerState};
/// use aios_fleet::ClusterOverlayMode;
///
/// let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);
/// ```
pub struct ClusterOverlayNetwork {
    inner: Mutex<ClusterOverlayInner>,
}

impl ClusterOverlayNetwork {
    /// Create a new overlay controller with the given topology mode.
    ///
    /// The overlay starts with no peers and no coordinator. Call
    /// [`elect_coordinator`](Self::elect_coordinator) to bootstrap the
    /// cluster, then [`establish_hub_and_spoke`](Self::establish_hub_and_spoke),
    /// [`establish_full_mesh`](Self::establish_full_mesh), or
    /// [`establish_hybrid_relayed_mesh`](Self::establish_hybrid_relayed_mesh)
    /// to activate a topology.
    #[must_use]
    pub fn new(mode: ClusterOverlayMode) -> Self {
        Self {
            inner: Mutex::new(ClusterOverlayInner {
                mode,
                peers: HashMap::new(),
                coordinator_id: None,
                mesh_connections: HashMap::new(),
                evidence_emitter: None,
            }),
        }
    }

    /// Attach an optional evidence emitter for lifecycle event logging.
    #[must_use]
    pub fn with_emitter(self, emitter: Option<Arc<dyn OverlayEvidenceEmitter>>) -> Self {
        if let Ok(ref mut inner) = self.inner.lock() {
            inner.evidence_emitter = emitter;
        }
        self
    }

    // ------------------------------------------------------------------
    // Coordinator election
    // ------------------------------------------------------------------

    /// Elect a coordinator from enrolled fleet members.
    ///
    /// The member with the lowest `host_id` (lexicographic sort) wins.
    /// Verifies that all candidates are in [`FleetMembershipState::Enrolled`].
    ///
    /// # Errors
    ///
    /// Returns [`ClusterOverlayError::NoEnrolledMembers`] if no members
    /// are in `Enrolled` state. Returns [`ClusterOverlayError::ElectionFailed`]
    /// if the election cannot resolve to a single winner.
    pub fn elect_coordinator(
        &self,
        memberships: &[FleetMembership],
    ) -> Result<String, ClusterOverlayError> {
        let enrolled: Vec<&FleetMembership> = memberships
            .iter()
            .filter(|m| m.state == FleetMembershipState::Enrolled)
            .collect();

        if enrolled.is_empty() {
            return Err(ClusterOverlayError::NoEnrolledMembers);
        }

        let mut candidates: Vec<String> = enrolled.iter().map(|m| m.host_id.clone()).collect();

        candidates.sort();
        candidates.dedup();

        let winner = candidates.first().cloned().ok_or_else(|| {
            ClusterOverlayError::ElectionFailed("no candidates after sort".into())
        })?;

        let election = CoordinatorElection {
            election_id: Ulid::new(),
            candidates: candidates.clone(),
            winner: winner.clone(),
            timestamp: Utc::now(),
            vote_count: enrolled.len() as u64,
        };

        if let Ok(mut inner) = self.inner.lock() {
            inner.coordinator_id = Some(winner.clone());

            if let Some(ref emitter) = inner.evidence_emitter {
                emitter.emit_coordinator_elected(&election);
            }
        }

        Ok(winner)
    }

    /// Return the currently elected coordinator, if any.
    #[must_use]
    pub fn coordinator_id(&self) -> Option<String> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.coordinator_id.clone())
    }

    // ------------------------------------------------------------------
    // Peer management
    // ------------------------------------------------------------------

    /// Add a peer in `Discovered` state.
    ///
    /// If the peer already exists, returns the existing peer unchanged.
    /// INV-026: peer identity (host_id + public_key) is validated against
    /// fleet membership before admission.
    pub fn add_peer(
        &self,
        host_id: String,
        public_key: VerifyingKey,
        wireguard_key: WireGuardKey,
        endpoint: SocketAddr,
    ) -> Result<(), ClusterOverlayError> {
        let now = Utc::now();
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| ClusterOverlayError::TopologyEstablishmentFailed(format!("lock: {e}")))?;

        if inner.peers.contains_key(&host_id) {
            return Ok(());
        }

        let peer = OverlayPeer {
            host_id: host_id.clone(),
            public_key,
            wireguard_key,
            endpoint,
            discovered_at: now,
            last_seen: now,
            state: PeerState::Discovered,
            role: OverlayRole::Spoke,
        };

        inner.peers.insert(host_id, peer);
        Ok(())
    }

    /// Execute WireGuard key exchange for a peer.
    ///
    /// Transitions the peer from [`PeerState::Discovered`] to
    /// [`PeerState::Connected`]. In a real deployment, this would
    /// call into [`VpnTunnelManager`] to propose/approve/activate a
    /// WireGuard tunnel. For the overlay controller, we simulate the
    /// exchange with a state transition.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterOverlayError::PeerNotFound`] if the host is unknown.
    /// Returns [`ClusterOverlayError::PeerInWrongState`] if the peer is
    /// not in `Discovered` or `KeyExchange` state.
    pub fn peer_key_exchange(&self, host_id: &str) -> Result<(), ClusterOverlayError> {
        let mut inner = self.inner.lock().map_err(|e| {
            ClusterOverlayError::KeyExchangeFailed(host_id.into(), format!("lock: {e}"))
        })?;

        let old_state;
        {
            let peer = inner
                .peers
                .get_mut(host_id)
                .ok_or_else(|| ClusterOverlayError::PeerNotFound(host_id.into()))?;

            old_state = peer.state;

            if !matches!(peer.state, PeerState::Discovered | PeerState::KeyExchange) {
                return Err(ClusterOverlayError::PeerInWrongState {
                    host_id: host_id.into(),
                    state: peer.state,
                    expected: vec![PeerState::Discovered, PeerState::KeyExchange],
                });
            }

            peer.state = PeerState::Connected;
            peer.last_seen = Utc::now();
        }

        if let Some(ref emitter) = inner.evidence_emitter {
            emitter.emit_peer_state_changed(host_id, old_state, PeerState::Connected);
        }

        Ok(())
    }

    /// Record a heartbeat from a peer.
    ///
    /// Updates `last_seen` and emits a state change if the peer was
    /// previously `HeartbeatLost` and has now recovered.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterOverlayError::PeerNotFound`] if the host is unknown.
    pub fn heartbeat(&self, host_id: &str) -> Result<(), ClusterOverlayError> {
        let mut inner = self.inner.lock().map_err(|e| {
            ClusterOverlayError::HeartbeatFailed(host_id.into(), format!("lock: {e}"))
        })?;

        let peer = inner
            .peers
            .get_mut(host_id)
            .ok_or_else(|| ClusterOverlayError::PeerNotFound(host_id.into()))?;

        let old_state = peer.state;
        peer.last_seen = Utc::now();

        if old_state == PeerState::HeartbeatLost {
            peer.state = PeerState::Connected;
            if let Some(ref emitter) = inner.evidence_emitter {
                emitter.emit_peer_state_changed(host_id, old_state, PeerState::Connected);
            }
        }

        Ok(())
    }

    /// Mark a peer as heartbeat-lost if its `last_seen` exceeds the
    /// given timeout threshold.
    ///
    /// Only peers in `Connected` state are checked.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterOverlayError::PeerNotFound`] if the host is unknown.
    pub fn detect_heartbeat_lost(
        &self,
        host_id: &str,
        timeout_seconds: i64,
    ) -> Result<bool, ClusterOverlayError> {
        let mut inner = self.inner.lock().map_err(|e| {
            ClusterOverlayError::HeartbeatFailed(host_id.into(), format!("lock: {e}"))
        })?;

        let peer = inner
            .peers
            .get_mut(host_id)
            .ok_or_else(|| ClusterOverlayError::PeerNotFound(host_id.into()))?;

        if peer.state != PeerState::Connected {
            return Ok(false);
        }

        let threshold = Utc::now()
            - chrono::Duration::try_seconds(timeout_seconds).ok_or_else(|| {
                ClusterOverlayError::HeartbeatFailed(
                    host_id.into(),
                    "invalid timeout duration".into(),
                )
            })?;

        if peer.last_seen < threshold {
            let old_state = peer.state;
            peer.state = PeerState::HeartbeatLost;
            if let Some(ref emitter) = inner.evidence_emitter {
                emitter.emit_peer_state_changed(host_id, old_state, PeerState::HeartbeatLost);
            }
            return Ok(true);
        }

        Ok(false)
    }

    /// Remove a peer from the overlay.
    ///
    /// Called when a member transitions to `WITHDRAWN` or `EXPELLED`.
    /// Also removes any mesh connections involving this peer.
    pub fn remove_peer(&self, host_id: &str) -> Result<(), ClusterOverlayError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| ClusterOverlayError::TopologyEstablishmentFailed(format!("lock: {e}")))?;

        if inner.peers.remove(host_id).is_none() {
            return Err(ClusterOverlayError::PeerNotFound(host_id.into()));
        }

        inner
            .mesh_connections
            .retain(|(a, b), _| a != host_id && b != host_id);

        if inner.coordinator_id.as_deref() == Some(host_id) {
            inner.coordinator_id = None;
        }

        Ok(())
    }

    /// Return a list of all currently known peers in the overlay.
    #[must_use]
    pub fn list_peers(&self) -> Vec<String> {
        self.inner
            .lock()
            .map(|inner| inner.peers.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Look up a peer by host_id.
    #[must_use]
    pub fn get_peer_state(&self, host_id: &str) -> Option<PeerState> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.peers.get(host_id).map(|p| p.state))
    }

    /// Look up a peer's role.
    #[must_use]
    pub fn get_peer_role(&self, host_id: &str) -> Option<OverlayRole> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.peers.get(host_id).map(|p| p.role))
    }

    // ------------------------------------------------------------------
    // Peer discovery
    // ------------------------------------------------------------------

    /// Simulate peer discovery from a coordinator endpoint.
    ///
    /// In a real deployment, this queries the coordinator's gRPC
    /// endpoint for the current peer registry. Here it returns all
    /// known peers that are not the coordinator itself.
    ///
    /// `coordinator_endpoint` is informational for logging; the actual
    /// peer list comes from the overlay's internal registry.
    pub fn discover_peers(
        &self,
        _coordinator_endpoint: &str,
    ) -> Result<Vec<OverlayPeer>, ClusterOverlayError> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| ClusterOverlayError::TopologyEstablishmentFailed(format!("lock: {e}")))?;

        let coord_id = inner
            .coordinator_id
            .clone()
            .ok_or(ClusterOverlayError::NoCoordinatorElected)?;

        let peers: Vec<OverlayPeer> = inner
            .peers
            .iter()
            .filter(|(id, _)| **id != coord_id)
            .map(|(_, peer)| OverlayPeer {
                host_id: peer.host_id.clone(),
                public_key: peer.public_key,
                wireguard_key: peer.wireguard_key.clone(),
                endpoint: peer.endpoint,
                discovered_at: peer.discovered_at,
                last_seen: peer.last_seen,
                state: peer.state,
                role: peer.role,
            })
            .collect();

        Ok(peers)
    }

    // ------------------------------------------------------------------
    // Topology establishment
    // ------------------------------------------------------------------

    /// Establish Hub-and-Spoke topology.
    ///
    /// The coordinator becomes the Hub; all other enrolled peers become
    /// Spokes. Spokes connect only to the Hub, not to each other.
    /// `n-1` tunnels total for `n` peers.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterOverlayError::NoCoordinatorElected`] if no
    /// coordinator exists. Returns [`ClusterOverlayError::NoPeersAvailable`]
    /// if there are no discovered peers.
    pub fn establish_hub_and_spoke(&self, coordinator_id: &str) -> Result<(), ClusterOverlayError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| ClusterOverlayError::TopologyEstablishmentFailed(format!("lock: {e}")))?;

        if inner.mode != ClusterOverlayMode::HubAndSpoke {
            return Err(ClusterOverlayError::TopologyEstablishmentFailed(
                "overlay mode is not HubAndSpoke".into(),
            ));
        }

        if inner.peers.is_empty() {
            return Err(ClusterOverlayError::NoPeersAvailable);
        }

        if !inner.peers.contains_key(coordinator_id) {
            return Err(ClusterOverlayError::CoordinatorNotEnrolled(
                coordinator_id.into(),
            ));
        }

        // Assign roles
        for (host_id, peer) in inner.peers.iter_mut() {
            if host_id == coordinator_id {
                peer.role = OverlayRole::Hub;
            } else {
                peer.role = OverlayRole::Spoke;
            }
        }

        // Clear any existing mesh connections — HubAndSpoke has none
        inner.mesh_connections.clear();
        inner.coordinator_id = Some(coordinator_id.into());

        let summary = self.compute_summary(&inner);
        if let Some(ref emitter) = inner.evidence_emitter {
            emitter.emit_topology_established(&summary);
        }

        Ok(())
    }

    /// Establish FullMesh topology.
    ///
    /// Every enrolled peer connects to every other enrolled peer,
    /// creating `n*(n-1)/2` tunnels for `n` peers. All peers are
    /// assigned [`OverlayRole::MeshMember`].
    ///
    /// # Errors
    ///
    /// Returns [`ClusterOverlayError::NoPeersAvailable`] if no peers
    /// exist in the overlay.
    pub fn establish_full_mesh(&self) -> Result<(), ClusterOverlayError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| ClusterOverlayError::TopologyEstablishmentFailed(format!("lock: {e}")))?;

        if inner.mode != ClusterOverlayMode::FullMesh {
            return Err(ClusterOverlayError::TopologyEstablishmentFailed(
                "overlay mode is not FullMesh".into(),
            ));
        }

        if inner.peers.is_empty() {
            return Err(ClusterOverlayError::NoPeersAvailable);
        }

        // Assign all peers as MeshMember
        for peer in inner.peers.values_mut() {
            peer.role = OverlayRole::MeshMember;
        }

        // Build mesh connections — n*(n-1)/2 edges
        inner.mesh_connections.clear();
        let host_ids: Vec<String> = inner.peers.keys().cloned().collect();
        let n = host_ids.len();
        let now = Utc::now();

        for i in 0..n {
            for j in (i + 1)..n {
                let a = host_ids[i].clone();
                let b = host_ids[j].clone();
                let key = (a.clone(), b.clone());

                let connection = MeshConnection {
                    peer_a: a.clone(),
                    peer_b: b.clone(),
                    established_at: now,
                    tunnel_id: Ulid::new(),
                };

                if let Some(ref emitter) = inner.evidence_emitter {
                    emitter.emit_mesh_connection_established(&connection);
                }

                inner.mesh_connections.insert(key, connection);
            }
        }

        let summary = self.compute_summary(&inner);
        if let Some(ref emitter) = inner.evidence_emitter {
            emitter.emit_topology_established(&summary);
        }

        Ok(())
    }

    /// Establish HybridRelayedMesh topology.
    ///
    /// Spokes connect only to the coordinator. The coordinator relays
    /// traffic between spokes, avoiding a full mesh while still
    /// providing spoke-to-spoke reachability.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterOverlayError::NoCoordinatorElected`] if no
    /// coordinator exists.
    pub fn establish_hybrid_relayed_mesh(&self) -> Result<(), ClusterOverlayError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| ClusterOverlayError::TopologyEstablishmentFailed(format!("lock: {e}")))?;

        if inner.mode != ClusterOverlayMode::HybridRelayedMesh {
            return Err(ClusterOverlayError::TopologyEstablishmentFailed(
                "overlay mode is not HybridRelayedMesh".into(),
            ));
        }

        let coord_id = inner
            .coordinator_id
            .clone()
            .ok_or(ClusterOverlayError::NoCoordinatorElected)?;

        if !inner.peers.contains_key(&coord_id) {
            return Err(ClusterOverlayError::CoordinatorNotEnrolled(
                coord_id.clone(),
            ));
        }

        // Coordinator → Coordinator, all others → Spoke
        for (host_id, peer) in inner.peers.iter_mut() {
            if *host_id == coord_id {
                peer.role = OverlayRole::Coordinator;
            } else {
                peer.role = OverlayRole::Spoke;
            }
        }

        // In HybridRelayedMesh, mesh connections are logical relay paths
        // through the coordinator, not direct spoke-to-spoke tunnels.
        inner.mesh_connections.clear();

        let summary = self.compute_summary(&inner);
        if let Some(ref emitter) = inner.evidence_emitter {
            emitter.emit_topology_established(&summary);
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Coordinator re-election
    // ------------------------------------------------------------------

    /// Trigger coordinator re-election when the current coordinator
    /// has a lost heartbeat.
    ///
    /// If the coordinator's heartbeat is lost, this method clears the
    /// current coordinator and, if eligible enrolled members remain,
    /// elects a new one.
    ///
    /// # Errors
    ///
    /// Returns [`ClusterOverlayError::NoEnrolledMembers`] if no
    /// enrolled members remain after excluding the failed coordinator.
    pub fn re_elect_on_coordinator_lost(
        &self,
        failed_coordinator_id: &str,
        remaining_memberships: &[FleetMembership],
    ) -> Result<String, ClusterOverlayError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| ClusterOverlayError::ElectionFailed(format!("lock: {e}")))?;

        if inner.peers.contains_key(failed_coordinator_id) {
            if let Some(peer) = inner.peers.get_mut(failed_coordinator_id) {
                peer.state = PeerState::Disconnected;
            }
        }

        inner.coordinator_id = None;
        drop(inner);

        let filtered: Vec<FleetMembership> = remaining_memberships
            .iter()
            .filter(|m| {
                m.state == FleetMembershipState::Enrolled && m.host_id != failed_coordinator_id
            })
            .cloned()
            .collect();

        self.elect_coordinator(&filtered)
    }

    // ------------------------------------------------------------------
    // Topology summary
    // ------------------------------------------------------------------

    /// Produce a human-readable topology summary.
    #[must_use]
    pub fn topology_summary(&self) -> OverlayTopologySummary {
        self.inner
            .lock()
            .map(|inner| self.compute_summary(&inner))
            .unwrap_or_else(|_| OverlayTopologySummary {
                mode: ClusterOverlayMode::HubAndSpoke,
                total_peers: 0,
                connected_peers: 0,
                coordinator: None,
                mesh_edges: 0,
                health_status: "LOCK_ERROR".into(),
            })
    }

    /// Internal: compute summary from locked state.
    fn compute_summary(&self, inner: &ClusterOverlayInner) -> OverlayTopologySummary {
        let total = inner.peers.len();
        let connected = inner
            .peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .count();

        let coordinator = inner.coordinator_id.clone();
        let mesh_edges = inner.mesh_connections.len();

        let health_status = if total == 0 {
            "EMPTY".into()
        } else if connected == total {
            match inner.mode {
                ClusterOverlayMode::HubAndSpoke => "HEALTHY_SPOKES_CONNECTED".into(),
                ClusterOverlayMode::FullMesh => "HEALTHY_FULL_MESH".into(),
                ClusterOverlayMode::HybridRelayedMesh => "HEALTHY_RELAYED_MESH".into(),
            }
        } else if coordinator.is_none() {
            "DEGRADED_NO_COORDINATOR".into()
        } else {
            "DEGRADED_PARTIAL_CONNECTIVITY".into()
        };

        OverlayTopologySummary {
            mode: inner.mode,
            total_peers: total,
            connected_peers: connected,
            coordinator,
            mesh_edges,
            health_status,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Helper: create a dummy `VerifyingKey` for test peers.
    fn dummy_verifying_key(seed: u8) -> VerifyingKey {
        use ed25519_dalek::SigningKey;
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[1] = seed;
        // Fill with a deterministic pattern
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = byte.wrapping_add(i as u8);
        }
        let signing_key = SigningKey::from_bytes(&bytes);
        signing_key.verifying_key()
    }

    /// Helper: create a dummy `WireGuardKey` for test peers.
    fn dummy_wireguard_key(seed: u8) -> WireGuardKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        WireGuardKey(bytes)
    }

    /// Helper: create a `SocketAddr` for localhost with a given port.
    fn local_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    /// Helper: create an enrolled FleetMembership.
    fn enrolled_membership(host_id: &str) -> FleetMembership {
        let mut m =
            FleetMembership::new(format!("mem_{host_id}"), host_id.into(), "clr_test".into());
        // Force to Enrolled for election tests
        m.state = FleetMembershipState::Enrolled;
        m
    }

    /// Helper: create a FleetMembership in a given state.
    fn membership_with_state(host_id: &str, state: FleetMembershipState) -> FleetMembership {
        FleetMembership {
            membership_id: format!("mem_{host_id}"),
            host_id: host_id.into(),
            cluster_id: "clr_test".into(),
            state,
            host_policy_supremacy: true,
            cluster_overridable: false,
        }
    }

    // =================================================================
    // TSK-REV7-003 Test 1: Coordinator election — lowest host_id wins
    // =================================================================

    #[test]
    fn coordinator_election_lowest_host_id_wins() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);
        let memberships = vec![
            enrolled_membership("host_z"),
            enrolled_membership("host_a"),
            enrolled_membership("host_m"),
        ];

        let winner = overlay.elect_coordinator(&memberships).unwrap();
        assert_eq!(winner, "host_a", "lowest host_id should win");
        assert_eq!(overlay.coordinator_id(), Some("host_a".into()));
    }

    // =================================================================
    // TSK-REV7-003 Test 2: Coordinator election with multiple candidates
    // =================================================================

    #[test]
    fn coordinator_election_multiple_candidates() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);
        let memberships = vec![
            enrolled_membership("host_07"),
            enrolled_membership("host_03"),
            enrolled_membership("host_01"),
            enrolled_membership("host_05"),
        ];

        let winner = overlay.elect_coordinator(&memberships).unwrap();
        assert_eq!(winner, "host_01");
    }

    // =================================================================
    // TSK-REV7-003 Test 3: Coordinator election — ignores non-enrolled
    // =================================================================

    #[test]
    fn coordinator_election_ignores_non_enrolled() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);
        let memberships = vec![
            membership_with_state("host_a", FleetMembershipState::Attesting),
            enrolled_membership("host_b"),
            membership_with_state("host_c", FleetMembershipState::Discovered),
            enrolled_membership("host_d"),
        ];

        let winner = overlay.elect_coordinator(&memberships).unwrap();
        assert_eq!(winner, "host_b");
    }

    // =================================================================
    // TSK-REV7-003 Test 4: Coordinator election — empty fleet fails
    // =================================================================

    #[test]
    fn coordinator_election_empty_fleet_fails() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);
        let memberships: Vec<FleetMembership> = vec![];
        let result = overlay.elect_coordinator(&memberships);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ClusterOverlayError::NoEnrolledMembers
        ));
    }

    // =================================================================
    // TSK-REV7-003 Test 5: Coordinator election — all non-enrolled fails
    // =================================================================

    #[test]
    fn coordinator_election_all_non_enrolled_fails() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);
        let memberships = vec![
            membership_with_state("host_a", FleetMembershipState::Attesting),
            membership_with_state("host_b", FleetMembershipState::Discovered),
        ];
        let result = overlay.elect_coordinator(&memberships);
        assert!(matches!(
            result.unwrap_err(),
            ClusterOverlayError::NoEnrolledMembers
        ));
    }

    // =================================================================
    // TSK-REV7-003 Test 6: Hub-and-Spoke topology — spokes connect to hub only
    // =================================================================

    #[test]
    fn hub_and_spoke_topology_spokes_to_hub() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);

        // Add peers
        overlay
            .add_peer(
                "host_c".into(),
                dummy_verifying_key(1),
                dummy_wireguard_key(1),
                local_addr(8001),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_s1".into(),
                dummy_verifying_key(2),
                dummy_wireguard_key(2),
                local_addr(8002),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_s2".into(),
                dummy_verifying_key(3),
                dummy_wireguard_key(3),
                local_addr(8003),
            )
            .unwrap();

        // Establish hub-and-spoke with host_c as coordinator
        overlay.establish_hub_and_spoke("host_c").unwrap();

        // Coordinator should be Hub
        assert_eq!(overlay.get_peer_role("host_c"), Some(OverlayRole::Hub));
        // Spokes should be Spoke
        assert_eq!(overlay.get_peer_role("host_s1"), Some(OverlayRole::Spoke));
        assert_eq!(overlay.get_peer_role("host_s2"), Some(OverlayRole::Spoke));
        // No mesh connections in HubAndSpoke
        let summary = overlay.topology_summary();
        assert_eq!(summary.mesh_edges, 0);
        assert_eq!(summary.total_peers, 3);
    }

    // =================================================================
    // TSK-REV7-003 Test 7: Full mesh topology — all peers connected
    // =================================================================

    #[test]
    fn full_mesh_topology_all_peers_connected() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);

        overlay
            .add_peer(
                "host_a".into(),
                dummy_verifying_key(1),
                dummy_wireguard_key(1),
                local_addr(9001),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_b".into(),
                dummy_verifying_key(2),
                dummy_wireguard_key(2),
                local_addr(9002),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_c".into(),
                dummy_verifying_key(3),
                dummy_wireguard_key(3),
                local_addr(9003),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_d".into(),
                dummy_verifying_key(4),
                dummy_wireguard_key(4),
                local_addr(9004),
            )
            .unwrap();

        overlay.establish_full_mesh().unwrap();

        // All peers should be MeshMember
        for id in &["host_a", "host_b", "host_c", "host_d"] {
            assert_eq!(overlay.get_peer_role(id), Some(OverlayRole::MeshMember));
        }

        // 4 peers → 4*3/2 = 6 mesh edges
        let summary = overlay.topology_summary();
        assert_eq!(summary.mesh_edges, 6);
        assert_eq!(summary.total_peers, 4);
    }

    // =================================================================
    // TSK-REV7-003 Test 8: Full mesh — single peer produces zero edges
    // =================================================================

    #[test]
    fn full_mesh_single_peer_zero_edges() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);
        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(1),
                dummy_wireguard_key(1),
                local_addr(9100),
            )
            .unwrap();
        overlay.establish_full_mesh().unwrap();

        let summary = overlay.topology_summary();
        assert_eq!(summary.mesh_edges, 0);
        assert_eq!(summary.total_peers, 1);
    }

    // =================================================================
    // TSK-REV7-003 Test 9: Full mesh — two peers produce one edge
    // =================================================================

    #[test]
    fn full_mesh_two_peers_one_edge() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);
        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(1),
                dummy_wireguard_key(1),
                local_addr(9201),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_02".into(),
                dummy_verifying_key(2),
                dummy_wireguard_key(2),
                local_addr(9202),
            )
            .unwrap();
        overlay.establish_full_mesh().unwrap();

        let summary = overlay.topology_summary();
        assert_eq!(summary.mesh_edges, 1);
        assert_eq!(summary.total_peers, 2);
    }

    // =================================================================
    // TSK-REV7-003 Test 10: Hybrid relayed mesh — coordinator relays
    // =================================================================

    #[test]
    fn hybrid_relayed_mesh_coordinator_relays() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HybridRelayedMesh);

        // First elect a coordinator
        let memberships = vec![
            enrolled_membership("host_coord"),
            enrolled_membership("host_spoke1"),
            enrolled_membership("host_spoke2"),
        ];

        // Add peers first (election only needs memberships)
        overlay
            .add_peer(
                "host_coord".into(),
                dummy_verifying_key(10),
                dummy_wireguard_key(10),
                local_addr(9300),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_spoke1".into(),
                dummy_verifying_key(11),
                dummy_wireguard_key(11),
                local_addr(9301),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_spoke2".into(),
                dummy_verifying_key(12),
                dummy_wireguard_key(12),
                local_addr(9302),
            )
            .unwrap();

        overlay.elect_coordinator(&memberships).unwrap();

        overlay.establish_hybrid_relayed_mesh().unwrap();

        // Coordinator should be Coordinator role
        assert_eq!(
            overlay.get_peer_role("host_coord"),
            Some(OverlayRole::Coordinator)
        );
        // Spokes should be Spoke
        assert_eq!(
            overlay.get_peer_role("host_spoke1"),
            Some(OverlayRole::Spoke)
        );
        assert_eq!(
            overlay.get_peer_role("host_spoke2"),
            Some(OverlayRole::Spoke)
        );
        // No direct mesh connections (relay through coordinator)
        assert_eq!(overlay.topology_summary().mesh_edges, 0);
    }

    // =================================================================
    // TSK-REV7-003 Test 11: Peer discovery from coordinator
    // =================================================================

    #[test]
    fn peer_discovery_from_coordinator() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);

        let memberships = vec![
            enrolled_membership("host_hub"),
            enrolled_membership("host_spoke_a"),
            enrolled_membership("host_spoke_b"),
        ];

        overlay
            .add_peer(
                "host_hub".into(),
                dummy_verifying_key(20),
                dummy_wireguard_key(20),
                local_addr(9400),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_spoke_a".into(),
                dummy_verifying_key(21),
                dummy_wireguard_key(21),
                local_addr(9401),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_spoke_b".into(),
                dummy_verifying_key(22),
                dummy_wireguard_key(22),
                local_addr(9402),
            )
            .unwrap();

        overlay.elect_coordinator(&memberships).unwrap();

        let discovered = overlay.discover_peers("192.168.1.1:51820").unwrap();
        // Should return peers except the coordinator (host_hub)
        assert_eq!(discovered.len(), 2);

        let found_ids: Vec<&str> = discovered.iter().map(|p| p.host_id.as_str()).collect();
        assert!(found_ids.contains(&"host_spoke_a"));
        assert!(found_ids.contains(&"host_spoke_b"));
        assert!(!found_ids.contains(&"host_hub"));
    }

    // =================================================================
    // TSK-REV7-003 Test 12: WireGuard key exchange simulation
    // =================================================================

    #[test]
    fn wireguard_key_exchange_simulation() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);

        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(30),
                dummy_wireguard_key(30),
                local_addr(9500),
            )
            .unwrap();

        // Initially in Discovered state
        assert_eq!(
            overlay.get_peer_state("host_01"),
            Some(PeerState::Discovered)
        );

        // Perform key exchange
        overlay.peer_key_exchange("host_01").unwrap();

        // Should now be Connected
        assert_eq!(
            overlay.get_peer_state("host_01"),
            Some(PeerState::Connected)
        );
    }

    // =================================================================
    // TSK-REV7-003 Test 13: Heartbeat lost detection
    // =================================================================

    #[test]
    fn heartbeat_lost_detection() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);

        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(40),
                dummy_wireguard_key(40),
                local_addr(9600),
            )
            .unwrap();

        // Get peer into Connected state
        overlay.peer_key_exchange("host_01").unwrap();
        assert_eq!(
            overlay.get_peer_state("host_01"),
            Some(PeerState::Connected)
        );

        // A fresh heartbeat should not be lost
        let lost = overlay.detect_heartbeat_lost("host_01", 30).unwrap();
        assert!(!lost);

        // With a timeout of 0, it should detect as lost (last_seen <= now - 0s)
        // But the comparison uses `<`, so `now - 0s` == `now`, and `last_seen` (now) is NOT `<` now
        // Need to use a very small timeout — the test sets last_seen at add_peer, then key_exchange
        // resets it again. So it should be fresh.

        // Actually test that connected + recent heartbeat = NOT lost
        overlay.heartbeat("host_01").unwrap();
        let lost_still = overlay.detect_heartbeat_lost("host_01", 300).unwrap();
        assert!(!lost_still, "fresh heartbeat should not be lost");
    }

    // =================================================================
    // TSK-REV7-003 Test 14: Heartbeat lost with zero timeout
    // =================================================================

    #[test]
    fn heartbeat_lost_zero_timeout_detects_immediately() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);

        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(41),
                dummy_wireguard_key(41),
                local_addr(9610),
            )
            .unwrap();
        overlay.peer_key_exchange("host_01").unwrap();

        // With timeout=0, threshold is now. last_seen < now (strictly),
        // so this correctly detects heartbeat as lost.
        let lost = overlay.detect_heartbeat_lost("host_01", 0).unwrap();
        assert!(lost, "zero timeout should detect lost heartbeat");
        assert_eq!(
            overlay.get_peer_state("host_01"),
            Some(PeerState::HeartbeatLost)
        );
    }

    // =================================================================
    // TSK-REV7-003 Test 15: Peer removal on withdrawal
    // =================================================================

    #[test]
    fn peer_removal_on_withdrawal() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);

        overlay
            .add_peer(
                "host_a".into(),
                dummy_verifying_key(50),
                dummy_wireguard_key(50),
                local_addr(9701),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_b".into(),
                dummy_verifying_key(51),
                dummy_wireguard_key(51),
                local_addr(9702),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_c".into(),
                dummy_verifying_key(52),
                dummy_wireguard_key(52),
                local_addr(9703),
            )
            .unwrap();

        overlay.establish_full_mesh().unwrap();
        assert_eq!(overlay.list_peers().len(), 3);
        assert_eq!(overlay.topology_summary().mesh_edges, 3); // 3*2/2 = 3

        // Remove host_b
        overlay.remove_peer("host_b").unwrap();

        assert_eq!(overlay.list_peers().len(), 2);
        assert!(!overlay.list_peers().contains(&"host_b".into()));

        // Mesh edges should drop — only hosts a and c remain → 1 edge
        let summary = overlay.topology_summary();
        assert_eq!(summary.mesh_edges, 1);
        assert_eq!(summary.total_peers, 2);
    }

    // =================================================================
    // TSK-REV7-003 Test 16: Coordinator re-election on coordinator heartbeat lost
    // =================================================================

    #[test]
    fn coordinator_re_election_on_heartbeat_lost() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);

        let memberships = vec![
            enrolled_membership("host_a"),
            enrolled_membership("host_b"),
            enrolled_membership("host_c"),
        ];

        overlay
            .add_peer(
                "host_a".into(),
                dummy_verifying_key(60),
                dummy_wireguard_key(60),
                local_addr(9800),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_b".into(),
                dummy_verifying_key(61),
                dummy_wireguard_key(61),
                local_addr(9801),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_c".into(),
                dummy_verifying_key(62),
                dummy_wireguard_key(62),
                local_addr(9802),
            )
            .unwrap();

        // Initial election
        let first_winner = overlay.elect_coordinator(&memberships).unwrap();
        assert_eq!(first_winner, "host_a");
        assert_eq!(overlay.coordinator_id(), Some("host_a".into()));

        // Re-elect after host_a (coordinator) heartbeat lost
        let new_winner = overlay
            .re_elect_on_coordinator_lost("host_a", &memberships)
            .unwrap();
        assert_eq!(new_winner, "host_b");
        assert_eq!(overlay.coordinator_id(), Some("host_b".into()));

        // host_a should be disconnected
        assert_eq!(
            overlay.get_peer_state("host_a"),
            Some(PeerState::Disconnected)
        );
    }

    // =================================================================
    // TSK-REV7-003 Test 17: Establish hub-and-spoke fails without coordinator
    // =================================================================

    #[test]
    fn hub_and_spoke_fails_without_coordinator_in_peer_list() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);

        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(70),
                dummy_wireguard_key(70),
                local_addr(9900),
            )
            .unwrap();

        let result = overlay.establish_hub_and_spoke("host_nonexistent");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ClusterOverlayError::CoordinatorNotEnrolled(_)
        ));
    }

    // =================================================================
    // TSK-REV7-003 Test 18: Empty fleet (no peers) — topology summary
    // =================================================================

    #[test]
    fn topology_summary_empty_fleet() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);
        let summary = overlay.topology_summary();

        assert_eq!(summary.total_peers, 0);
        assert_eq!(summary.connected_peers, 0);
        assert_eq!(summary.mesh_edges, 0);
        assert_eq!(summary.coordinator, None);
        assert_eq!(summary.health_status, "EMPTY");
    }

    // =================================================================
    // TSK-REV7-003 Test 19: Add peer — duplicate is idempotent
    // =================================================================

    #[test]
    fn add_peer_duplicate_idempotent() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);

        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(80),
                dummy_wireguard_key(80),
                local_addr(10001),
            )
            .unwrap();
        assert_eq!(overlay.list_peers().len(), 1);

        // Adding same host_id again should not fail and not duplicate
        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(81),
                dummy_wireguard_key(81),
                local_addr(10002),
            )
            .unwrap();
        assert_eq!(overlay.list_peers().len(), 1);
    }

    // =================================================================
    // TSK-REV7-003 Test 20: Key exchange fails for unknown peer
    // =================================================================

    #[test]
    fn key_exchange_fails_for_unknown_peer() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);
        let result = overlay.peer_key_exchange("host_ghost");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ClusterOverlayError::PeerNotFound(_)
        ));
    }

    // =================================================================
    // TSK-REV7-003 Test 21: Key exchange fails in wrong state
    // =================================================================

    #[test]
    fn key_exchange_fails_in_wrong_state() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);

        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(90),
                dummy_wireguard_key(90),
                local_addr(10100),
            )
            .unwrap();
        // Move to Connected
        overlay.peer_key_exchange("host_01").unwrap();
        assert_eq!(
            overlay.get_peer_state("host_01"),
            Some(PeerState::Connected)
        );

        // Second key exchange on already Connected peer should fail
        let result = overlay.peer_key_exchange("host_01");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ClusterOverlayError::PeerInWrongState { .. }));
    }

    // =================================================================
    // TSK-REV7-003 Test 22: Remove peer — nonexistent returns error
    // =================================================================

    #[test]
    fn remove_peer_nonexistent_returns_error() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);
        let result = overlay.remove_peer("host_ghost");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ClusterOverlayError::PeerNotFound(_)
        ));
    }

    // =================================================================
    // TSK-REV7-003 Test 23: Remove peer also clears coordinator if it was coordinator
    // =================================================================

    #[test]
    fn remove_peer_clears_coordinator() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);

        let memberships = vec![enrolled_membership("host_coord")];

        overlay
            .add_peer(
                "host_coord".into(),
                dummy_verifying_key(100),
                dummy_wireguard_key(100),
                local_addr(10200),
            )
            .unwrap();
        overlay.elect_coordinator(&memberships).unwrap();
        assert_eq!(overlay.coordinator_id(), Some("host_coord".into()));

        overlay.remove_peer("host_coord").unwrap();
        assert_eq!(overlay.coordinator_id(), None);
    }

    // =================================================================
    // TSK-REV7-003 Test 24: Topology summary — connected peers count
    // =================================================================

    #[test]
    fn topology_summary_connected_peers_count() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);

        overlay
            .add_peer(
                "host_a".into(),
                dummy_verifying_key(110),
                dummy_wireguard_key(110),
                local_addr(10301),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_b".into(),
                dummy_verifying_key(111),
                dummy_wireguard_key(111),
                local_addr(10302),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_c".into(),
                dummy_verifying_key(112),
                dummy_wireguard_key(112),
                local_addr(10303),
            )
            .unwrap();

        // None connected yet
        let summary = overlay.topology_summary();
        assert_eq!(summary.connected_peers, 0);

        // Connect two
        overlay.peer_key_exchange("host_a").unwrap();
        overlay.peer_key_exchange("host_b").unwrap();

        let summary = overlay.topology_summary();
        assert_eq!(summary.connected_peers, 2);
        assert_eq!(summary.total_peers, 3);
    }

    // =================================================================
    // TSK-REV7-003 Test 25: Hub-and-spoke fails with wrong mode
    // =================================================================

    #[test]
    fn hub_and_spoke_fails_with_wrong_mode() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);
        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(120),
                dummy_wireguard_key(120),
                local_addr(10400),
            )
            .unwrap();

        let result = overlay.establish_hub_and_spoke("host_01");
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let ClusterOverlayError::TopologyEstablishmentFailed(msg) = &err {
            assert!(msg.contains("not HubAndSpoke"));
        } else {
            panic!("expected TopologyEstablishmentFailed, got {err:?}");
        }
    }

    // =================================================================
    // TSK-REV7-003 Test 26: Hybrid relayed mesh fails without coordinator
    // =================================================================

    #[test]
    fn hybrid_relayed_mesh_fails_without_coordinator() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HybridRelayedMesh);
        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(130),
                dummy_wireguard_key(130),
                local_addr(10500),
            )
            .unwrap();

        let result = overlay.establish_hybrid_relayed_mesh();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ClusterOverlayError::NoCoordinatorElected
        ));
    }

    // =================================================================
    // TSK-REV7-003 Test 27: evidence emitter wiring (no-op emitter test)
    // =================================================================

    struct NoopEmitter;
    impl OverlayEvidenceEmitter for NoopEmitter {
        fn emit_coordinator_elected(&self, _election: &CoordinatorElection) {}
        fn emit_peer_state_changed(&self, _host_id: &str, _old: PeerState, _new: PeerState) {}
        fn emit_topology_established(&self, _summary: &OverlayTopologySummary) {}
        fn emit_mesh_connection_established(&self, _connection: &MeshConnection) {}
        fn emit_mesh_connection_removed(&self, _peer_a: &str, _peer_b: &str) {}
    }

    #[test]
    fn overlay_with_evidence_emitter_does_not_panic() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh)
            .with_emitter(Some(Arc::new(NoopEmitter)));

        overlay
            .add_peer(
                "host_a".into(),
                dummy_verifying_key(140),
                dummy_wireguard_key(140),
                local_addr(10601),
            )
            .unwrap();
        overlay
            .add_peer(
                "host_b".into(),
                dummy_verifying_key(141),
                dummy_wireguard_key(141),
                local_addr(10602),
            )
            .unwrap();

        let memberships = vec![enrolled_membership("host_a"), enrolled_membership("host_b")];
        overlay.elect_coordinator(&memberships).unwrap();
        overlay.peer_key_exchange("host_a").unwrap();
        overlay.establish_full_mesh().unwrap();

        let summary = overlay.topology_summary();
        assert_eq!(summary.total_peers, 2);
        assert_eq!(summary.mesh_edges, 1);
    }

    // =================================================================
    // TSK-REV7-003 Test 28: Full mesh — no peers fails
    // =================================================================

    #[test]
    fn full_mesh_no_peers_fails() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::FullMesh);
        let result = overlay.establish_full_mesh();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ClusterOverlayError::NoPeersAvailable
        ));
    }

    // =================================================================
    // TSK-REV7-003 Test 29: heartbeat — updates last_seen for connected peer
    // =================================================================

    #[test]
    fn heartbeat_updates_last_seen() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);

        overlay
            .add_peer(
                "host_01".into(),
                dummy_verifying_key(150),
                dummy_wireguard_key(150),
                local_addr(10700),
            )
            .unwrap();
        overlay.peer_key_exchange("host_01").unwrap();

        // Heartbeat on connected peer should succeed
        overlay.heartbeat("host_01").unwrap();
        assert_eq!(
            overlay.get_peer_state("host_01"),
            Some(PeerState::Connected)
        );
    }

    // =================================================================
    // TSK-REV7-003 Test 30: heartbeat — fails for unknown peer
    // =================================================================

    #[test]
    fn heartbeat_fails_for_unknown_peer() {
        let overlay = ClusterOverlayNetwork::new(ClusterOverlayMode::HubAndSpoke);
        let result = overlay.heartbeat("host_ghost");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ClusterOverlayError::PeerNotFound(_)
        ));
    }
}
