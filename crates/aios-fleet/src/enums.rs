use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClusterOverlayMode {
    HubAndSpoke,
    FullMesh,
    HybridRelayedMesh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClusterRole {
    ClusterCoordinator,
    FleetMember,
    FleetObserver,
    RecoveryWitness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClusterTrustScope {
    FleetTrustOnly,
    FleetTrustAndRepo,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
    strum_macros::Display,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum FleetMembershipState {
    Discovered,
    Invited,
    Attesting,
    Enrolled,
    Suspended,
    Quarantined,
    Withdrawn,
    Expelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustDelegationDirection {
    InboundAccept,
    OutboundVouch,
    Bidirectional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemoteRoutingReason {
    HardwareAffinity,
    CapacityOffload,
    IsolationRequired,
    KernelPersonalityMatch,
    RecoveryFailover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemoteRoutingClass {
    SandboxedCapsule,
    MicroVmJob,
    DriverLabJob,
    KernelBuildJob,
    BlockedRoute,
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn cluster_overlay_mode_count() {
        let variants: Vec<_> = ClusterOverlayMode::iter().collect();
        assert_eq!(variants.len(), 3);
    }

    #[test]
    fn cluster_role_count() {
        let variants: Vec<_> = ClusterRole::iter().collect();
        assert_eq!(variants.len(), 4);
    }

    #[test]
    fn fleet_membership_state_count() {
        let variants: Vec<_> = FleetMembershipState::iter().collect();
        assert_eq!(variants.len(), 8);
    }

    #[test]
    fn remote_routing_count() {
        let reason_variants: Vec<_> = RemoteRoutingReason::iter().collect();
        assert_eq!(reason_variants.len(), 5);
        let class_variants: Vec<_> = RemoteRoutingClass::iter().collect();
        assert_eq!(class_variants.len(), 5);
    }

    #[test]
    fn serde_roundtrip_screaming_snake() {
        let json = serde_json::to_string(&FleetMembershipState::Attesting).unwrap();
        assert_eq!(json, "\"ATTESTING\"");
        let parsed: FleetMembershipState = serde_json::from_str("\"ATTESTING\"").unwrap();
        assert_eq!(parsed, FleetMembershipState::Attesting);
    }

    #[test]
    fn blocked_route_present() {
        assert!(RemoteRoutingClass::iter().any(|c| c == RemoteRoutingClass::BlockedRoute));
    }
}
