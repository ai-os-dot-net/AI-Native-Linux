use crate::enums::FleetMembershipState;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    #[error("invalid state transition from {from} to {to}")]
    InvalidTransition {
        from: FleetMembershipState,
        to: FleetMembershipState,
    },

    #[error("only the cluster coordinator can perform this action")]
    NotCoordinator,

    #[error("TPM attestation failed: {detail}")]
    AttestationFailed { detail: String },

    #[error("quorum required: need {required} signatures, got {provided}")]
    QuorumRequired { required: usize, provided: usize },

    #[error("host is already enrolled in another membership")]
    HostAlreadyEnrolled,

    #[error("host has withdrawn from the fleet")]
    HostWithdrawn,

    #[error("host posture level {current} is below the minimum floor {floor}")]
    PostureFloorViolation { current: u8, floor: u8 },

    #[error("membership not found: {membership_id}")]
    MembershipNotFound { membership_id: String },

    #[error("host signature verification failed")]
    HostSignatureVerificationFailed,

    #[error("coordinator invitation not found for membership {membership_id}")]
    NoCoordinatorInvitation { membership_id: String },
}
