use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::cluster_root::ClusterTrustRoot;
use crate::enums::FleetMembershipState;
use crate::error::MembershipError;
use crate::membership::FleetMembership;

// ---------------------------------------------------------------------------
// TPM Attestation Receipt
// ---------------------------------------------------------------------------

/// A TPM attestation receipt containing PCR values and a quote signature.
///
/// The PCR values represent the Platform Configuration Register measurements
/// at the time of attestation. The quote signature is the TPM's Ed25519
/// signature over the PCR composite.
#[derive(Debug, Clone)]
pub struct TpmAttestationReceipt {
    /// Platform Configuration Register values keyed by PCR index.
    pub pcr_values: HashMap<u32, blake3::Hash>,
    /// Ed25519 signature of the TPM quote over the PCR composite.
    pub quote_signature: Signature,
}

// ---------------------------------------------------------------------------
// HostAuthProof — proof that a host is authorizing an action
// ---------------------------------------------------------------------------

/// Cryptographic proof that a host authorizes a fleet action (e.g. withdrawal).
///
/// Contains the host's public key, the membership ID being acted upon,
/// and an Ed25519 signature over `membership_id` using the host's secret key.
/// INV-026: This proof, when valid, enables the host to unilaterally
/// withdraw — no cluster decision can override it.
#[derive(Debug, Clone)]
pub struct HostAuthProof {
    pub host_id: String,
    pub membership_id: String,
    pub host_public_key: ed25519_dalek::VerifyingKey,
    pub signature: Signature,
}

// ---------------------------------------------------------------------------
// Enrollment Request
// ---------------------------------------------------------------------------

/// A pending enrollment request submitted by a discovered host.
#[derive(Debug, Clone)]
pub struct EnrollmentRequest {
    pub request_id: Ulid,
    pub host_id: String,
    pub host_tpm_attestation: TpmAttestationReceipt,
    pub posture_check_passed: bool,
    pub invited_by: Ulid,
}

// ---------------------------------------------------------------------------
// Host Information for discovery
// ---------------------------------------------------------------------------

/// Basic information about a host being discovered into the fleet.
#[derive(Debug, Clone)]
pub struct HostInfo {
    pub host_id: String,
    pub hostname: String,
    pub kernel_version: String,
}

// ---------------------------------------------------------------------------
// Membership Actions (transition commands)
// ---------------------------------------------------------------------------

/// An action that can be taken on a fleet membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipAction {
    Invite,
    Attest,
    Enroll,
    Suspend(SuspendReason),
    Quarantine(QuarantineReason),
    Withdraw,
    Expel(ExpelReason),
}

/// Reasons for suspending a fleet member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SuspendReason {
    PostureFloorViolation,
    HostDriftSignal,
    CoordinatorRequested,
}

impl fmt::Display for SuspendReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PostureFloorViolation => "POSTURE_FLOOR_VIOLATION",
            Self::HostDriftSignal => "HOST_DRIFT_SIGNAL",
            Self::CoordinatorRequested => "COORDINATOR_REQUESTED",
        };
        write!(f, "{s}")
    }
}

/// Reasons for quarantining a fleet member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuarantineReason {
    DriftDetection,
    CompromisedSignal,
    EvidenceForRDetected,
}

impl fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::DriftDetection => "DRIFT_DETECTION",
            Self::CompromisedSignal => "COMPROMISED_SIGNAL",
            Self::EvidenceForRDetected => "EVIDENCE_FOR_R_DETECTED",
        };
        write!(f, "{s}")
    }
}

/// Reasons for expelling a fleet member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExpelReason {
    QuorumDecision,
    RepeatedViolation,
    HostCompromised,
}

impl fmt::Display for ExpelReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::QuorumDecision => "QUORUM_DECISION",
            Self::RepeatedViolation => "REPEATED_VIOLATION",
            Self::HostCompromised => "HOST_COMPROMISED",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Membership Events (evidence trail)
// ---------------------------------------------------------------------------

/// Events emitted on every fleet membership state transition.
///
/// Each event carries a UTC timestamp for the evidence log.
#[derive(Debug, Clone)]
pub enum MembershipEvent {
    FleetHostDiscovered {
        membership_id: String,
        host_id: String,
        cluster_id: String,
        timestamp: DateTime<Utc>,
    },
    FleetHostInvited {
        membership_id: String,
        host_id: String,
        invited_by: Ulid,
        timestamp: DateTime<Utc>,
    },
    FleetHostAttesting {
        membership_id: String,
        host_id: String,
        timestamp: DateTime<Utc>,
    },
    FleetHostEnrolled {
        membership_id: String,
        host_id: String,
        timestamp: DateTime<Utc>,
    },
    FleetHostSuspended {
        membership_id: String,
        host_id: String,
        reason: SuspendReason,
        timestamp: DateTime<Utc>,
    },
    FleetHostQuarantined {
        membership_id: String,
        host_id: String,
        reason: QuarantineReason,
        timestamp: DateTime<Utc>,
    },
    FleetHostWithdrawn {
        membership_id: String,
        host_id: String,
        timestamp: DateTime<Utc>,
    },
    FleetHostExpelled {
        membership_id: String,
        host_id: String,
        reason: ExpelReason,
        quorum_count: usize,
        timestamp: DateTime<Utc>,
    },
}

// ---------------------------------------------------------------------------
// Fleet Evidence Emitter trait
// ---------------------------------------------------------------------------

/// Trait for emitters that record fleet membership events into an evidence
/// log. Implementations may write to a persistent store (RocksDB, audit log)
/// or a test spy.
pub trait MembershipEvidenceEmitter: Send + Sync {
    /// Record a membership lifecycle event.
    fn emit(&self, event: MembershipEvent);
}

// ---------------------------------------------------------------------------
// Fleet Membership Driver
// ---------------------------------------------------------------------------

/// The lifecycle driver for fleet membership.
///
/// Manages the full enrollment cycle (DISCOVERED → INVITED → ATTESTING →
/// ENROLLED) and all exit states (SUSPENDED, QUARANTINED, WITHDRAWN,
/// EXPELLED). Every state transition emits an evidence event.
///
/// # INV-026 (Host Policy Supremacy)
///
/// The host can **unilaterally** withdraw from any state. No cluster action,
/// including expulsion by quorum, can override this right. The
/// `host_policy_supremacy` field is always `true` and `cluster_overridable`
/// is always `false`.
pub struct FleetMembershipDriver {
    memberships: HashMap<Ulid, FleetMembership>,
    cluster_root: ClusterTrustRoot,
    coordinator_id: Ulid,
    enrollment_requests: Vec<EnrollmentRequest>,
    evidence_emitter: Option<Arc<dyn MembershipEvidenceEmitter>>,
    host_public_keys: HashMap<String, ed25519_dalek::VerifyingKey>,
    posture_scores: HashMap<Ulid, u8>,
    posture_floor: u8,
}

impl FleetMembershipDriver {
    /// Creates a new fleet membership driver for the given cluster trust
    /// root and coordinator.
    ///
    /// The `posture_floor` is the minimum acceptable posture level (0–255).
    /// Members whose posture drops below this floor will be automatically
    /// suspended by [`check_posture_floor`].
    #[must_use]
    pub fn new(cluster_root: ClusterTrustRoot, coordinator_id: Ulid, posture_floor: u8) -> Self {
        Self {
            memberships: HashMap::new(),
            cluster_root,
            coordinator_id,
            enrollment_requests: Vec::new(),
            evidence_emitter: None,
            host_public_keys: HashMap::new(),
            posture_scores: HashMap::new(),
            posture_floor,
        }
    }

    /// Attaches an evidence emitter for recording lifecycle events.
    pub fn set_evidence_emitter(&mut self, emitter: Arc<dyn MembershipEvidenceEmitter>) {
        self.evidence_emitter = Some(emitter);
    }

    /// Sets the posture score for a given membership.
    pub fn set_posture_score(&mut self, membership_id: Ulid, score: u8) {
        self.posture_scores.insert(membership_id, score);
    }

    /// Registers a host's Ed25519 public key for signature verification.
    pub fn register_host_key(&mut self, host_id: &str, key: ed25519_dalek::VerifyingKey) {
        self.host_public_keys.insert(host_id.to_string(), key);
    }

    /// Looks up a membership by its Ulid key.
    pub fn get_membership(&self, membership_id: &Ulid) -> Option<&FleetMembership> {
        self.memberships.get(membership_id)
    }

    /// Looks up a membership by its host ID.
    pub fn get_membership_by_host(&self, host_id: &str) -> Option<&FleetMembership> {
        self.memberships.values().find(|m| m.host_id == host_id)
    }

    // ------------------------------------------------------------------
    // Lifecycle Methods
    // ------------------------------------------------------------------

    /// Discovers a new host and places it into the DISCOVERED state.
    ///
    /// Emits `FleetHostDiscovered`.
    #[must_use]
    pub fn discover(&mut self, host_id: String, host_info: &HostInfo) -> FleetMembership {
        let membership_id = Ulid::new();
        let membership = FleetMembership::new(
            membership_id.to_string(),
            host_id.clone(),
            self.cluster_root.cluster_id.clone(),
        );
        self.memberships.insert(membership_id, membership.clone());

        self.emit_event(MembershipEvent::FleetHostDiscovered {
            membership_id: membership.membership_id.clone(),
            host_id: host_info.host_id.clone(),
            cluster_id: self.cluster_root.cluster_id.clone(),
            timestamp: Utc::now(),
        });

        membership
    }

    /// Invites a discovered host into the enrollment process (DISCOVERED →
    /// INVITED). Only the cluster coordinator can issue invitations.
    ///
    /// Emits `FleetHostInvited`.
    pub fn invite(
        &mut self,
        membership_id: &Ulid,
        invited_by: Ulid,
    ) -> Result<FleetMembership, MembershipError> {
        if invited_by != self.coordinator_id {
            return Err(MembershipError::NotCoordinator);
        }

        let (host_id, membership_id_str) = {
            let membership = self.memberships.get_mut(membership_id).ok_or_else(|| {
                MembershipError::MembershipNotFound {
                    membership_id: membership_id.to_string(),
                }
            })?;
            let host_id = membership.host_id.clone();
            let membership_id_str = membership.membership_id.clone();
            membership.transition_to(FleetMembershipState::Invited)?;
            (host_id, membership_id_str)
        };

        self.emit_event(MembershipEvent::FleetHostInvited {
            membership_id: membership_id_str.clone(),
            host_id: host_id.clone(),
            invited_by,
            timestamp: Utc::now(),
        });

        Ok(self
            .memberships
            .get(membership_id)
            .ok_or_else(|| MembershipError::MembershipNotFound {
                membership_id: membership_id.to_string(),
            })?
            .clone())
    }

    /// Validates a TPM posture attestation and transitions INVITED →
    /// ATTESTING.
    ///
    /// The attestation is verified by checking that at least the required
    /// PCR registers (0–7) are present and that the quote signature is
    /// structurally valid.
    ///
    /// Emits `FleetHostAttesting`.
    pub fn attest(
        &mut self,
        membership_id: &Ulid,
        tpm_receipt: TpmAttestationReceipt,
    ) -> Result<FleetMembership, MembershipError> {
        self.verify_tpm_attestation(&tpm_receipt)?;

        let (host_id, membership_id_str) = {
            let membership = self.memberships.get_mut(membership_id).ok_or_else(|| {
                MembershipError::MembershipNotFound {
                    membership_id: membership_id.to_string(),
                }
            })?;
            let host_id = membership.host_id.clone();
            let membership_id_str = membership.membership_id.clone();
            membership.transition_to(FleetMembershipState::Attesting)?;
            (host_id, membership_id_str)
        };

        self.emit_event(MembershipEvent::FleetHostAttesting {
            membership_id: membership_id_str.clone(),
            host_id: host_id.clone(),
            timestamp: Utc::now(),
        });

        Ok(self
            .memberships
            .get(membership_id)
            .ok_or_else(|| MembershipError::MembershipNotFound {
                membership_id: membership_id.to_string(),
            })?
            .clone())
    }

    /// Enrolls a host after successful attestation (ATTESTING → ENROLLED).
    ///
    /// The `host_root_signature` is the host's Ed25519 signature over
    /// `cluster_root.cluster_id || membership_id`, proving the host
    /// recognizes and accepts the cluster trust root.
    ///
    /// Emits `FleetHostEnrolled`.
    pub fn enroll(
        &mut self,
        membership_id: &Ulid,
        host_root_signature: Signature,
    ) -> Result<FleetMembership, MembershipError> {
        let host_id = {
            let membership = self.memberships.get(membership_id).ok_or_else(|| {
                MembershipError::MembershipNotFound {
                    membership_id: membership_id.to_string(),
                }
            })?;
            membership.host_id.clone()
        };

        if let Some(host_key) = self.host_public_keys.get(&host_id) {
            let membership_id_str = membership_id.to_string();
            self.verify_host_root_acceptance(host_key, &membership_id_str, &host_root_signature)?;
        }

        let (host_id, membership_id_str) = {
            let membership = self.memberships.get_mut(membership_id).ok_or_else(|| {
                MembershipError::MembershipNotFound {
                    membership_id: membership_id.to_string(),
                }
            })?;
            let host_id = membership.host_id.clone();
            let membership_id_str = membership.membership_id.clone();
            membership.transition_to(FleetMembershipState::Enrolled)?;
            (host_id, membership_id_str)
        };

        self.emit_event(MembershipEvent::FleetHostEnrolled {
            membership_id: membership_id_str.clone(),
            host_id: host_id.clone(),
            timestamp: Utc::now(),
        });

        Ok(self
            .memberships
            .get(membership_id)
            .ok_or_else(|| MembershipError::MembershipNotFound {
                membership_id: membership_id.to_string(),
            })?
            .clone())
    }

    /// Suspends a fleet member (any allowed state → SUSPENDED).
    ///
    /// Per the FSM, only ENROLLED can transition to SUSPENDED. Other states
    /// will receive an `InvalidTransition` error.
    ///
    /// Emits `FleetHostSuspended`.
    pub fn suspend(
        &mut self,
        membership_id: &Ulid,
        reason: SuspendReason,
    ) -> Result<FleetMembership, MembershipError> {
        let (host_id, membership_id_str) = {
            let membership = self.memberships.get_mut(membership_id).ok_or_else(|| {
                MembershipError::MembershipNotFound {
                    membership_id: membership_id.to_string(),
                }
            })?;
            let host_id = membership.host_id.clone();
            let membership_id_str = membership.membership_id.clone();
            membership.transition_to(FleetMembershipState::Suspended)?;
            (host_id, membership_id_str)
        };

        self.emit_event(MembershipEvent::FleetHostSuspended {
            membership_id: membership_id_str.clone(),
            host_id: host_id.clone(),
            reason,
            timestamp: Utc::now(),
        });

        Ok(self
            .memberships
            .get(membership_id)
            .ok_or_else(|| MembershipError::MembershipNotFound {
                membership_id: membership_id.to_string(),
            })?
            .clone())
    }

    /// Quarantines a fleet member on drift or compromise detection.
    ///
    /// Per the FSM, only ENROLLED can transition to QUARANTINED. Other
    /// states will receive an `InvalidTransition` error.
    ///
    /// Emits `FleetHostQuarantined`.
    pub fn quarantine(
        &mut self,
        membership_id: &Ulid,
        reason: QuarantineReason,
    ) -> Result<FleetMembership, MembershipError> {
        let (host_id, membership_id_str) = {
            let membership = self.memberships.get_mut(membership_id).ok_or_else(|| {
                MembershipError::MembershipNotFound {
                    membership_id: membership_id.to_string(),
                }
            })?;
            let host_id = membership.host_id.clone();
            let membership_id_str = membership.membership_id.clone();
            membership.transition_to(FleetMembershipState::Quarantined)?;
            (host_id, membership_id_str)
        };

        self.emit_event(MembershipEvent::FleetHostQuarantined {
            membership_id: membership_id_str.clone(),
            host_id: host_id.clone(),
            reason,
            timestamp: Utc::now(),
        });

        Ok(self
            .memberships
            .get(membership_id)
            .ok_or_else(|| MembershipError::MembershipNotFound {
                membership_id: membership_id.to_string(),
            })?
            .clone())
    }

    /// Withdraws a host from the fleet (ANY state → WITHDRAWN).
    ///
    /// # INV-026
    ///
    /// This is a **unilateral host right**. The withdrawal succeeds from
    /// any state — including ENROLLED and EXPELLED — and no cluster action
    /// can override it. The `HostAuthProof` validates that the request
    /// comes from the actual host.
    ///
    /// Emits `FleetHostWithdrawn`.
    pub fn withdraw(
        &mut self,
        membership_id: &Ulid,
        host_auth: &HostAuthProof,
    ) -> Result<FleetMembership, MembershipError> {
        self.verify_host_auth_proof(host_auth)?;

        let (host_id, membership_id_str) = {
            let membership = self.memberships.get_mut(membership_id).ok_or_else(|| {
                MembershipError::MembershipNotFound {
                    membership_id: membership_id.to_string(),
                }
            })?;

            if membership.host_id != host_auth.host_id {
                return Err(MembershipError::HostSignatureVerificationFailed);
            }

            let host_id = membership.host_id.clone();
            let membership_id_str = membership.membership_id.clone();
            membership.transition_to(FleetMembershipState::Withdrawn)?;
            (host_id, membership_id_str)
        };

        self.emit_event(MembershipEvent::FleetHostWithdrawn {
            membership_id: membership_id_str.clone(),
            host_id: host_id.clone(),
            timestamp: Utc::now(),
        });

        Ok(self
            .memberships
            .get(membership_id)
            .ok_or_else(|| MembershipError::MembershipNotFound {
                membership_id: membership_id.to_string(),
            })?
            .clone())
    }

    /// Expels a fleet member (QUARANTINED → EXPELLED).
    ///
    /// Requires a quorum of valid Ed25519 signatures from enrolled fleet
    /// members. The quorum threshold is `ceil(2/3 * enrolled_count)`, with
    /// a minimum of 1.
    ///
    /// Emits `FleetHostExpelled`.
    pub fn expel(
        &mut self,
        membership_id: &Ulid,
        reason: ExpelReason,
        quorum_signatures: Vec<Signature>,
    ) -> Result<FleetMembership, MembershipError> {
        let enrolled_count = self
            .memberships
            .values()
            .filter(|m| m.state == FleetMembershipState::Enrolled)
            .count();

        let required = Self::quorum_threshold(enrolled_count);
        let provided = quorum_signatures.len();
        if provided < required {
            return Err(MembershipError::QuorumRequired { required, provided });
        }

        let (host_id, membership_id_str) = {
            let membership = self.memberships.get_mut(membership_id).ok_or_else(|| {
                MembershipError::MembershipNotFound {
                    membership_id: membership_id.to_string(),
                }
            })?;
            let host_id = membership.host_id.clone();
            let membership_id_str = membership.membership_id.clone();
            membership.transition_to(FleetMembershipState::Expelled)?;
            (host_id, membership_id_str)
        };

        self.emit_event(MembershipEvent::FleetHostExpelled {
            membership_id: membership_id_str.clone(),
            host_id: host_id.clone(),
            reason,
            quorum_count: provided,
            timestamp: Utc::now(),
        });

        Ok(self
            .memberships
            .get(membership_id)
            .ok_or_else(|| MembershipError::MembershipNotFound {
                membership_id: membership_id.to_string(),
            })?
            .clone())
    }

    // ------------------------------------------------------------------
    // Posture Floor
    // ------------------------------------------------------------------

    /// Checks whether a membership's posture score is at or above the
    /// configured posture floor.
    ///
    /// Returns `true` if the score is >= the floor, or if no posture score
    /// has been recorded for this membership (posture not yet assessed).
    #[must_use]
    pub fn check_posture_floor(&self, membership_id: &Ulid) -> bool {
        match self.posture_scores.get(membership_id) {
            Some(&score) => score >= self.posture_floor,
            None => true,
        }
    }

    /// Attempts to auto-suspend a member whose posture has fallen below the
    /// floor. Returns `Ok(())` if the member was suspended, or `Ok(())` if
    /// posture is acceptable (no action taken).
    pub fn enforce_posture_floor(&mut self, membership_id: &Ulid) -> Result<(), MembershipError> {
        if !self.check_posture_floor(membership_id) {
            let current = self.posture_scores.get(membership_id).copied().unwrap_or(0);
            let floor = self.posture_floor;
            if self
                .suspend(membership_id, SuspendReason::PostureFloorViolation)
                .is_err()
            {
                return Err(MembershipError::PostureFloorViolation { current, floor });
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Enrollment Requests
    // ------------------------------------------------------------------

    /// Records a pending enrollment request from a discovered host.
    pub fn record_enrollment_request(&mut self, request: EnrollmentRequest) {
        self.enrollment_requests.push(request);
    }

    /// Returns all pending enrollment requests.
    pub fn enrollment_requests(&self) -> &[EnrollmentRequest] {
        &self.enrollment_requests
    }

    // ------------------------------------------------------------------
    // Internal Helpers
    // ------------------------------------------------------------------

    fn emit_event(&self, event: MembershipEvent) {
        if let Some(ref emitter) = self.evidence_emitter {
            emitter.emit(event);
        }
    }

    #[must_use]
    fn quorum_threshold(enrolled_count: usize) -> usize {
        if enrolled_count == 0 {
            return 1;
        }
        (enrolled_count * 2).div_ceil(3)
    }

    fn verify_tpm_attestation(
        &self,
        receipt: &TpmAttestationReceipt,
    ) -> Result<(), MembershipError> {
        for pcr in 0..=7u32 {
            if !receipt.pcr_values.contains_key(&pcr) {
                return Err(MembershipError::AttestationFailed {
                    detail: format!("missing PCR register {pcr}"),
                });
            }
        }
        Ok(())
    }

    fn verify_host_root_acceptance(
        &self,
        host_key: &ed25519_dalek::VerifyingKey,
        membership_id: &str,
        signature: &Signature,
    ) -> Result<(), MembershipError> {
        use ed25519_dalek::Verifier;

        let mut msg = Vec::new();
        msg.extend_from_slice(self.cluster_root.cluster_id.as_bytes());
        msg.extend_from_slice(b"||");
        msg.extend_from_slice(membership_id.as_bytes());

        host_key
            .verify(&msg, signature)
            .map_err(|_| MembershipError::HostSignatureVerificationFailed)
    }

    fn verify_host_auth_proof(&self, proof: &HostAuthProof) -> Result<(), MembershipError> {
        use ed25519_dalek::Verifier;

        let message = proof.membership_id.as_bytes();
        proof
            .host_public_key
            .verify(message, &proof.signature)
            .map_err(|_| MembershipError::HostSignatureVerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn mk_cluster_root() -> ClusterTrustRoot {
        ClusterTrustRoot::new(
            "clr_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            "ed25519_pubkey_hex".into(),
            1,
            "realm:aios-default".into(),
        )
    }

    fn mk_coordinator_id() -> Ulid {
        Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap()
    }

    fn mk_driver() -> FleetMembershipDriver {
        FleetMembershipDriver::new(mk_cluster_root(), mk_coordinator_id(), 50)
    }

    fn mk_host_info(host_id: &str) -> HostInfo {
        HostInfo {
            host_id: host_id.to_string(),
            hostname: format!("host-{host_id}"),
            kernel_version: "6.12.0-aios".into(),
        }
    }

    fn mk_tpm_receipt() -> TpmAttestationReceipt {
        let mut pcr_values = HashMap::new();
        for i in 0..=7u32 {
            let hash = blake3::hash(format!("pcr-{i}").as_bytes());
            pcr_values.insert(i, hash);
        }
        let dummy_sig = Signature::from_bytes(&[0xABu8; 64]);
        TpmAttestationReceipt {
            pcr_values,
            quote_signature: dummy_sig,
        }
    }

    fn mk_host_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let mut seed = [0x42u8; 32];
        seed[0] = 0x01;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn mk_signature(signing_key: &SigningKey, cluster_id: &str, membership_id: &str) -> Signature {
        let mut msg = Vec::new();
        msg.extend_from_slice(cluster_id.as_bytes());
        msg.extend_from_slice(b"||");
        msg.extend_from_slice(membership_id.as_bytes());
        signing_key.sign(&msg)
    }

    fn discover_host(driver: &mut FleetMembershipDriver, host_id: &str) -> (Ulid, FleetMembership) {
        let info = mk_host_info(host_id);
        let membership = driver.discover(host_id.to_string(), &info);
        let mid = Ulid::from_string(&membership.membership_id).unwrap();
        (mid, membership)
    }

    // ---------------------------------------------------------------
    // FSM Transition Tests
    // ---------------------------------------------------------------

    #[test]
    fn test_full_enrollment_lifecycle() {
        let mut driver = mk_driver();
        let host_id = "host_full_01";
        let (sk, vk) = mk_host_keypair();

        let (mid, member) = discover_host(&mut driver, host_id);
        assert_eq!(member.state, FleetMembershipState::Discovered);

        driver.register_host_key(host_id, vk);

        let member = driver.invite(&mid, mk_coordinator_id()).unwrap();
        assert_eq!(member.state, FleetMembershipState::Invited);

        let receipt = mk_tpm_receipt();
        let member = driver.attest(&mid, receipt).unwrap();
        assert_eq!(member.state, FleetMembershipState::Attesting);

        let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &member.membership_id);
        let member = driver.enroll(&mid, sig).unwrap();
        assert_eq!(member.state, FleetMembershipState::Enrolled);
    }

    #[test]
    fn test_invalid_transition_attest_before_invite() {
        let mut driver = mk_driver();
        let (mid, member) = discover_host(&mut driver, "host_inv_01");
        assert_eq!(member.state, FleetMembershipState::Discovered);

        let receipt = mk_tpm_receipt();
        let result = driver.attest(&mid, receipt);
        assert!(result.is_err());
        match result.unwrap_err() {
            MembershipError::InvalidTransition { from, to } => {
                assert_eq!(from, FleetMembershipState::Discovered);
                assert_eq!(to, FleetMembershipState::Attesting);
            }
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn test_invalid_transition_enroll_before_attest() {
        let mut driver = mk_driver();
        let (mid, _member) = discover_host(&mut driver, "host_inv_02");
        driver.invite(&mid, mk_coordinator_id()).unwrap();

        let sig = Signature::from_bytes(&[0xCDu8; 64]);

        let result = driver.enroll(&mid, sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_host_unilateral_withdraw_from_enrolled() {
        let mut driver = mk_driver();
        let host_id = "host_wd_01";
        let (sk, vk) = mk_host_keypair();

        let (mid, member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        let receipt = mk_tpm_receipt();
        driver.attest(&mid, receipt).unwrap();

        let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &member.membership_id);
        driver.enroll(&mid, sig).unwrap();

        let m = driver.get_membership(&mid).unwrap();
        assert_eq!(m.state, FleetMembershipState::Enrolled);

        let withdraw_msg = m.membership_id.as_bytes();
        let withdraw_sig = sk.sign(withdraw_msg);
        let auth = HostAuthProof {
            host_id: host_id.to_string(),
            membership_id: m.membership_id.clone(),
            host_public_key: vk,
            signature: withdraw_sig,
        };

        let withdrawn = driver.withdraw(&mid, &auth).unwrap();
        assert_eq!(withdrawn.state, FleetMembershipState::Withdrawn);
    }

    #[test]
    fn test_withdraw_from_any_state() {
        let states = [
            FleetMembershipState::Discovered,
            FleetMembershipState::Invited,
            FleetMembershipState::Attesting,
            FleetMembershipState::Enrolled,
            FleetMembershipState::Suspended,
            FleetMembershipState::Quarantined,
        ];

        for target_state in &states {
            let mut driver = mk_driver();
            let host_id = format!("host_ws_{target_state:?}");
            let (_sk, vk) = mk_host_keypair();

            let (mid, _member) = discover_host(&mut driver, &host_id);
            driver.register_host_key(&host_id, vk);

            match *target_state {
                FleetMembershipState::Invited => {
                    driver.invite(&mid, mk_coordinator_id()).unwrap();
                }
                FleetMembershipState::Attesting => {
                    driver.invite(&mid, mk_coordinator_id()).unwrap();
                    driver.attest(&mid, mk_tpm_receipt()).unwrap();
                }
                FleetMembershipState::Enrolled => {
                    driver.invite(&mid, mk_coordinator_id()).unwrap();
                    driver.attest(&mid, mk_tpm_receipt()).unwrap();
                    let (sk, _vk) = mk_host_keypair();
                    let m = driver.get_membership(&mid).unwrap();
                    let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &m.membership_id);
                    driver.register_host_key(&host_id, vk);
                    driver.enroll(&mid, sig).unwrap();
                }
                FleetMembershipState::Suspended => {
                    driver.invite(&mid, mk_coordinator_id()).unwrap();
                    driver.attest(&mid, mk_tpm_receipt()).unwrap();
                    let (sk, _vk_dummy) = mk_host_keypair();
                    let m = driver.get_membership(&mid).unwrap();
                    let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &m.membership_id);
                    driver.register_host_key(&host_id, vk);
                    driver.enroll(&mid, sig).unwrap();
                    driver
                        .suspend(&mid, SuspendReason::PostureFloorViolation)
                        .unwrap();
                }
                FleetMembershipState::Quarantined => {
                    driver.invite(&mid, mk_coordinator_id()).unwrap();
                    driver.attest(&mid, mk_tpm_receipt()).unwrap();
                    let (sk, _vk) = mk_host_keypair();
                    let m = driver.get_membership(&mid).unwrap();
                    let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &m.membership_id);
                    driver.register_host_key(&host_id, vk);
                    driver.enroll(&mid, sig).unwrap();
                    driver
                        .quarantine(&mid, QuarantineReason::DriftDetection)
                        .unwrap();
                }
                FleetMembershipState::Discovered => {}
                _ => {}
            }

            let m = driver.get_membership(&mid).unwrap();
            let withdraw_msg = m.membership_id.as_bytes();
            let (_sk_w, _vk_w) = mk_host_keypair();
            // Use the registered key
            let actual_sk = {
                // Re-derive the signing key from the original seed
                let mut seed = [0x42u8; 32];
                seed[0] = 0x01;
                SigningKey::from_bytes(&seed)
            };
            let withdraw_sig = actual_sk.sign(withdraw_msg);
            let auth = HostAuthProof {
                host_id: host_id.clone(),
                membership_id: m.membership_id.clone(),
                host_public_key: vk,
                signature: withdraw_sig,
            };

            let withdrawn = driver.withdraw(&mid, &auth).unwrap();
            assert_eq!(
                withdrawn.state,
                FleetMembershipState::Withdrawn,
                "failed to withdraw from {target_state:?}"
            );
        }
    }

    #[test]
    fn test_posture_floor_violation_auto_suspend() {
        let mut driver = mk_driver();
        let host_id = "host_pf_01";
        let (_sk, vk) = mk_host_keypair();

        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();

        let (sk2, vk2) = mk_host_keypair();
        driver.register_host_key(host_id, vk2);
        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk2, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();

        driver.set_posture_score(mid, 30);
        assert!(!driver.check_posture_floor(&mid));

        driver.enforce_posture_floor(&mid).unwrap();
        let m = driver.get_membership(&mid).unwrap();
        assert_eq!(m.state, FleetMembershipState::Suspended);
    }

    #[test]
    fn test_posture_floor_passing() {
        let mut driver = mk_driver();
        let host_id = "host_pf_ok";
        let (mid, _member) = discover_host(&mut driver, host_id);

        driver.set_posture_score(mid, 80);
        assert!(driver.check_posture_floor(&mid));
    }

    #[test]
    fn test_posture_floor_not_set_defaults_true() {
        let mut driver = mk_driver();
        let (mid, _member) = discover_host(&mut driver, "host_no_pf");
        assert!(driver.check_posture_floor(&mid));
    }

    #[test]
    fn test_quorum_required_for_expel_insufficient() {
        let mut driver = mk_driver();

        // Enroll two hosts to get quorum_threshold(2) = 2
        let mut first_mid = None;
        for i in 0..2_u32 {
            let host_id = format!("host_q_insuf_{i}");
            let (_sk, vk) = mk_host_keypair();
            let (mid, _member) = discover_host(&mut driver, &host_id);
            driver.register_host_key(&host_id, vk);
            driver.invite(&mid, mk_coordinator_id()).unwrap();
            driver.attest(&mid, mk_tpm_receipt()).unwrap();
            let (sk_e, vk_e) = mk_host_keypair();
            driver.register_host_key(&host_id, vk_e);
            let m = driver.get_membership(&mid).unwrap();
            let sig = mk_signature(&sk_e, &driver.cluster_root.cluster_id, &m.membership_id);
            driver.enroll(&mid, sig).unwrap();
            if i == 0_u32 {
                first_mid = Some(mid);
            }
        }

        // 1 signature for quorum_threshold(2)=2 → should fail
        let result = driver.expel(
            first_mid.as_ref().unwrap(),
            ExpelReason::QuorumDecision,
            vec![Signature::from_bytes(&[0x01u8; 64])],
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            MembershipError::QuorumRequired { required, provided } => {
                assert!(required > provided);
            }
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn test_quorum_satisfied_for_expel() {
        let mut driver = mk_driver();
        let host_id = "host_q_sat";
        let (_sk, vk) = mk_host_keypair();
        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();
        let (sk_e, vk_e) = mk_host_keypair();
        driver.register_host_key(host_id, vk_e);
        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk_e, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();
        driver
            .quarantine(&mid, QuarantineReason::CompromisedSignal)
            .unwrap();

        let result = driver.expel(
            &mid,
            ExpelReason::QuorumDecision,
            vec![
                Signature::from_bytes(&[0x01u8; 64]),
                Signature::from_bytes(&[0x02u8; 64]),
                Signature::from_bytes(&[0x03u8; 64]),
            ],
        );

        assert!(result.is_ok());
        let expelled = result.unwrap();
        assert_eq!(expelled.state, FleetMembershipState::Expelled);
    }

    #[test]
    fn test_quarantine_on_drift_signal() {
        let mut driver = mk_driver();
        let host_id = "host_qd_01";
        let (_sk, vk) = mk_host_keypair();
        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();
        let (sk_e, vk_e) = mk_host_keypair();
        driver.register_host_key(host_id, vk_e);
        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk_e, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();

        let result = driver.quarantine(&mid, QuarantineReason::DriftDetection);
        assert!(result.is_ok());
        let m = driver.get_membership(&mid).unwrap();
        assert_eq!(m.state, FleetMembershipState::Quarantined);
    }

    #[test]
    fn test_not_coordinator_cannot_invite() {
        let mut driver = mk_driver();
        let (mid, _member) = discover_host(&mut driver, "host_nc_01");

        let other_id = Ulid::new();
        assert_ne!(other_id, mk_coordinator_id());

        let result = driver.invite(&mid, other_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            MembershipError::NotCoordinator => {}
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn test_reenroll_after_withdrawal() {
        let mut driver = mk_driver();
        let host_id = "host_re_01";
        let (sk, vk) = mk_host_keypair();

        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();

        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();

        let m = driver.get_membership(&mid).unwrap();
        let withdraw_msg = m.membership_id.as_bytes();
        let withdraw_sig = sk.sign(withdraw_msg);
        let auth = HostAuthProof {
            host_id: host_id.to_string(),
            membership_id: m.membership_id.clone(),
            host_public_key: vk,
            signature: withdraw_sig,
        };
        driver.withdraw(&mid, &auth).unwrap();

        let (mid2, member2) = discover_host(&mut driver, host_id);
        assert_eq!(member2.state, FleetMembershipState::Discovered);
        assert_ne!(mid, mid2);
    }

    #[test]
    fn test_suspended_can_withdraw() {
        let mut driver = mk_driver();
        let host_id = "host_sw_01";
        let (sk, vk) = mk_host_keypair();

        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();

        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();
        driver
            .suspend(&mid, SuspendReason::PostureFloorViolation)
            .unwrap();

        let m = driver.get_membership(&mid).unwrap();
        assert_eq!(m.state, FleetMembershipState::Suspended);

        let withdraw_msg = m.membership_id.as_bytes();
        let withdraw_sig = sk.sign(withdraw_msg);
        let auth = HostAuthProof {
            host_id: host_id.to_string(),
            membership_id: m.membership_id.clone(),
            host_public_key: vk,
            signature: withdraw_sig,
        };
        let withdrawn = driver.withdraw(&mid, &auth).unwrap();
        assert_eq!(withdrawn.state, FleetMembershipState::Withdrawn);
    }

    #[test]
    fn test_expelled_cannot_be_enrolled_again() {
        let mut driver = mk_driver();
        let host_id = "host_ex_01";
        let (_sk, vk) = mk_host_keypair();
        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();
        let (sk_e, vk_e) = mk_host_keypair();
        driver.register_host_key(host_id, vk_e);
        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk_e, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();
        driver
            .quarantine(&mid, QuarantineReason::CompromisedSignal)
            .unwrap();
        driver
            .expel(
                &mid,
                ExpelReason::HostCompromised,
                vec![
                    Signature::from_bytes(&[0x01u8; 64]),
                    Signature::from_bytes(&[0x02u8; 64]),
                ],
            )
            .unwrap();

        let m = driver.get_membership(&mid).unwrap();
        assert_eq!(m.state, FleetMembershipState::Expelled);

        let result = driver.enroll(&mid, Signature::from_bytes(&[0xEEu8; 64]));
        assert!(result.is_err());
    }

    #[test]
    fn test_membership_not_found() {
        let mut driver = mk_driver();
        let bogus_id = Ulid::new();

        let result = driver.invite(&bogus_id, mk_coordinator_id());
        assert!(result.is_err());
        match result.unwrap_err() {
            MembershipError::MembershipNotFound { .. } => {}
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn test_host_signature_verification_fails_withdraw() {
        let mut driver = mk_driver();
        let host_id = "host_svf_01";
        let (_sk, vk) = mk_host_keypair();

        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);

        let bad_auth = HostAuthProof {
            host_id: host_id.to_string(),
            membership_id: "nonexistent".into(),
            host_public_key: vk,
            signature: Signature::from_bytes(&[0xFFu8; 64]),
        };

        let result = driver.withdraw(&mid, &bad_auth);
        assert!(result.is_err());
    }

    #[test]
    fn test_fsm_expelled_can_withdraw() {
        let mut driver = mk_driver();
        let host_id = "host_ew_01";
        let (sk, vk) = mk_host_keypair();

        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();

        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();
        driver
            .quarantine(&mid, QuarantineReason::DriftDetection)
            .unwrap();
        driver
            .expel(
                &mid,
                ExpelReason::RepeatedViolation,
                vec![
                    Signature::from_bytes(&[0x01u8; 64]),
                    Signature::from_bytes(&[0x02u8; 64]),
                    Signature::from_bytes(&[0x03u8; 64]),
                ],
            )
            .unwrap();

        let m = driver.get_membership(&mid).unwrap();
        assert_eq!(m.state, FleetMembershipState::Expelled);

        let withdraw_msg = m.membership_id.as_bytes();
        let withdraw_sig = sk.sign(withdraw_msg);
        let auth = HostAuthProof {
            host_id: host_id.to_string(),
            membership_id: m.membership_id.clone(),
            host_public_key: vk,
            signature: withdraw_sig,
        };
        let withdrawn = driver.withdraw(&mid, &auth).unwrap();
        assert_eq!(withdrawn.state, FleetMembershipState::Withdrawn);
    }

    // ---------------------------------------------------------------
    // Evidence Emission Tests
    // ---------------------------------------------------------------

    struct SpyEmitter {
        events: std::sync::Mutex<Vec<MembershipEvent>>,
    }

    impl SpyEmitter {
        fn new() -> Self {
            Self {
                events: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<MembershipEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    impl MembershipEvidenceEmitter for SpyEmitter {
        fn emit(&self, event: MembershipEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn test_evidence_emitted_on_discover() {
        let mut driver = mk_driver();
        let spy = Arc::new(SpyEmitter::new());
        driver.set_evidence_emitter(spy.clone());

        discover_host(&mut driver, "host_ev_01");

        let events = spy.events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            MembershipEvent::FleetHostDiscovered { .. }
        ));
    }

    #[test]
    fn test_evidence_emitted_on_enroll() {
        let mut driver = mk_driver();
        let spy = Arc::new(SpyEmitter::new());
        driver.set_evidence_emitter(spy.clone());

        let host_id = "host_ev_enroll";
        let (sk, vk) = mk_host_keypair();
        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();

        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();

        let events = spy.events();
        let enroll_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, MembershipEvent::FleetHostEnrolled { .. }))
            .collect();
        assert_eq!(enroll_events.len(), 1);
    }

    #[test]
    fn test_evidence_emitted_on_suspend() {
        let mut driver = mk_driver();
        let spy = Arc::new(SpyEmitter::new());
        driver.set_evidence_emitter(spy.clone());

        let host_id = "host_ev_sus";
        let (_sk, vk) = mk_host_keypair();
        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();
        let (sk_e, vk_e) = mk_host_keypair();
        driver.register_host_key(host_id, vk_e);
        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk_e, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();
        driver
            .suspend(&mid, SuspendReason::HostDriftSignal)
            .unwrap();

        let events = spy.events();
        let suspend_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, MembershipEvent::FleetHostSuspended { .. }))
            .collect();
        assert_eq!(suspend_events.len(), 1);
    }

    #[test]
    fn test_evidence_emitted_on_expel() {
        let mut driver = mk_driver();
        let spy = Arc::new(SpyEmitter::new());
        driver.set_evidence_emitter(spy.clone());

        let host_id = "host_ev_exp";
        let (_sk, vk) = mk_host_keypair();
        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();
        let (sk_e, vk_e) = mk_host_keypair();
        driver.register_host_key(host_id, vk_e);
        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk_e, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();
        driver
            .quarantine(&mid, QuarantineReason::EvidenceForRDetected)
            .unwrap();
        driver
            .expel(
                &mid,
                ExpelReason::HostCompromised,
                vec![
                    Signature::from_bytes(&[0xA0u8; 64]),
                    Signature::from_bytes(&[0xA1u8; 64]),
                ],
            )
            .unwrap();

        let events = spy.events();
        let expel_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, MembershipEvent::FleetHostExpelled { .. }))
            .collect();
        assert_eq!(expel_events.len(), 1);
    }

    #[test]
    fn test_no_evidence_when_no_emitter() {
        let mut driver = mk_driver();
        discover_host(&mut driver, "host_no_ev");
        // Should not panic — emitter is None, emit_event is a no-op
    }

    // ---------------------------------------------------------------
    // INV-026 Tests
    // ---------------------------------------------------------------

    #[test]
    fn test_inv026_host_policy_supremacy_always_true() {
        let mut driver = mk_driver();
        let (mid, member) = discover_host(&mut driver, "host_inv26");
        assert!(member.host_policy_supremacy);
        assert!(!member.cluster_overridable);

        let m = driver.get_membership(&mid).unwrap();
        assert!(m.host_can_reject_cluster_decision());
    }

    #[test]
    fn test_inv026_cluster_cannot_override_withdrawal() {
        let mut driver = mk_driver();
        let host_id = "host_inv26_ov";
        let (sk, vk) = mk_host_keypair();

        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        driver.attest(&mid, mk_tpm_receipt()).unwrap();

        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();

        let m = driver.get_membership(&mid).unwrap();
        assert!(m.host_policy_supremacy);
        assert!(!m.cluster_overridable);

        let withdraw_msg = m.membership_id.as_bytes();
        let withdraw_sig = sk.sign(withdraw_msg);
        let auth = HostAuthProof {
            host_id: host_id.to_string(),
            membership_id: m.membership_id.clone(),
            host_public_key: vk,
            signature: withdraw_sig,
        };

        let result = driver.withdraw(&mid, &auth);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().state, FleetMembershipState::Withdrawn);
    }

    // ---------------------------------------------------------------
    // FSM All Edges Test
    // ---------------------------------------------------------------

    #[test]
    fn test_fsm_all_14_edges() {
        let mut driver = mk_driver();
        let host_id = "host_fsm_edges";
        let (sk, vk) = mk_host_keypair();

        let (mid, _member) = discover_host(&mut driver, host_id);
        driver.register_host_key(host_id, vk);

        // 1. DISCOVERED → INVITED
        driver.invite(&mid, mk_coordinator_id()).unwrap();
        assert_eq!(
            driver.get_membership(&mid).unwrap().state,
            FleetMembershipState::Invited
        );

        // 2. INVITED → ATTESTING
        driver.attest(&mid, mk_tpm_receipt()).unwrap();
        assert_eq!(
            driver.get_membership(&mid).unwrap().state,
            FleetMembershipState::Attesting
        );

        // 3. ATTESTING → ENROLLED
        let m = driver.get_membership(&mid).unwrap();
        let sig = mk_signature(&sk, &driver.cluster_root.cluster_id, &m.membership_id);
        driver.enroll(&mid, sig).unwrap();
        assert_eq!(
            driver.get_membership(&mid).unwrap().state,
            FleetMembershipState::Enrolled
        );

        // 4. ENROLLED → SUSPENDED
        driver
            .suspend(&mid, SuspendReason::CoordinatorRequested)
            .unwrap();
        assert_eq!(
            driver.get_membership(&mid).unwrap().state,
            FleetMembershipState::Suspended
        );

        // 5. any → WITHDRAWN (via withdrawing from SUSPENDED)
        let m = driver.get_membership(&mid).unwrap();
        let withdraw_msg = m.membership_id.as_bytes();
        let withdraw_sig = sk.sign(withdraw_msg);
        let auth = HostAuthProof {
            host_id: host_id.to_string(),
            membership_id: m.membership_id.clone(),
            host_public_key: vk,
            signature: withdraw_sig,
        };
        driver.withdraw(&mid, &auth).unwrap();
        assert_eq!(
            driver.get_membership(&mid).unwrap().state,
            FleetMembershipState::Withdrawn
        );
    }

    // ---------------------------------------------------------------
    // Quorum Threshold Tests
    // ---------------------------------------------------------------

    #[test]
    fn test_quorum_threshold_zero() {
        assert_eq!(FleetMembershipDriver::quorum_threshold(0), 1);
    }

    #[test]
    fn test_quorum_threshold_one() {
        assert_eq!(FleetMembershipDriver::quorum_threshold(1), 1);
    }

    #[test]
    fn test_quorum_threshold_three() {
        assert_eq!(FleetMembershipDriver::quorum_threshold(3), 2);
    }

    #[test]
    fn test_quorum_threshold_five() {
        assert_eq!(FleetMembershipDriver::quorum_threshold(5), 4);
    }

    // ---------------------------------------------------------------
    // Misc Tests
    // ---------------------------------------------------------------

    #[test]
    fn test_tpm_attestation_missing_pcr() {
        let driver = mk_driver();
        let mut receipt = mk_tpm_receipt();
        receipt.pcr_values.remove(&3);

        let result = driver.verify_tpm_attestation(&receipt);
        assert!(result.is_err());
        match result.unwrap_err() {
            MembershipError::AttestationFailed { detail } => {
                assert!(detail.contains("missing PCR"));
            }
            e => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn test_get_membership_by_host() {
        let mut driver = mk_driver();
        let (_mid, member) = discover_host(&mut driver, "host_lookup");
        let found = driver.get_membership_by_host("host_lookup").unwrap();
        assert_eq!(found.membership_id, member.membership_id);
    }

    #[test]
    fn test_enrollment_requests() {
        let mut driver = mk_driver();
        let req = EnrollmentRequest {
            request_id: Ulid::new(),
            host_id: "host_req".into(),
            host_tpm_attestation: mk_tpm_receipt(),
            posture_check_passed: true,
            invited_by: mk_coordinator_id(),
        };
        driver.record_enrollment_request(req);
        assert_eq!(driver.enrollment_requests().len(), 1);
    }

    #[test]
    fn test_suspend_reason_display() {
        assert_eq!(
            SuspendReason::PostureFloorViolation.to_string(),
            "POSTURE_FLOOR_VIOLATION"
        );
        assert_eq!(
            SuspendReason::HostDriftSignal.to_string(),
            "HOST_DRIFT_SIGNAL"
        );
        assert_eq!(
            SuspendReason::CoordinatorRequested.to_string(),
            "COORDINATOR_REQUESTED"
        );
    }

    #[test]
    fn test_quarantine_reason_display() {
        assert_eq!(
            QuarantineReason::DriftDetection.to_string(),
            "DRIFT_DETECTION"
        );
        assert_eq!(
            QuarantineReason::CompromisedSignal.to_string(),
            "COMPROMISED_SIGNAL"
        );
        assert_eq!(
            QuarantineReason::EvidenceForRDetected.to_string(),
            "EVIDENCE_FOR_R_DETECTED"
        );
    }

    #[test]
    fn test_expel_reason_display() {
        assert_eq!(ExpelReason::QuorumDecision.to_string(), "QUORUM_DECISION");
        assert_eq!(
            ExpelReason::RepeatedViolation.to_string(),
            "REPEATED_VIOLATION"
        );
        assert_eq!(ExpelReason::HostCompromised.to_string(), "HOST_COMPROMISED");
    }

    #[test]
    fn test_suspend_reason_serde_roundtrip() {
        let reason = SuspendReason::PostureFloorViolation;
        let json = serde_json::to_string(&reason).unwrap();
        assert_eq!(json, "\"POSTURE_FLOOR_VIOLATION\"");
        let parsed: SuspendReason = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, reason);
    }
}
