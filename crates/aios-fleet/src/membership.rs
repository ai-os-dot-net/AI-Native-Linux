use crate::enums::FleetMembershipState;
use crate::error::MembershipError;

#[derive(Debug, Clone)]
pub struct FleetMembership {
    pub membership_id: String,
    pub host_id: String,
    pub cluster_id: String,
    pub state: FleetMembershipState,
    /// INV-026: ALWAYS true — host policy supremacy is a constitutional constant.
    pub host_policy_supremacy: bool,
    /// INV-026: ALWAYS false — cluster cannot override host policy.
    pub cluster_overridable: bool,
}

impl FleetMembership {
    #[must_use]
    pub fn new(membership_id: String, host_id: String, cluster_id: String) -> Self {
        Self {
            membership_id,
            host_id,
            cluster_id,
            state: FleetMembershipState::Discovered,
            host_policy_supremacy: true,
            cluster_overridable: false,
        }
    }

    #[must_use]
    pub fn transition(&self, target: FleetMembershipState) -> Option<FleetMembershipState> {
        match (self.state, target) {
            (FleetMembershipState::Discovered, FleetMembershipState::Invited) => Some(target),
            (FleetMembershipState::Invited, FleetMembershipState::Attesting) => Some(target),
            (FleetMembershipState::Attesting, FleetMembershipState::Enrolled) => Some(target),

            (FleetMembershipState::Enrolled, FleetMembershipState::Suspended) => Some(target),
            (FleetMembershipState::Enrolled, FleetMembershipState::Expelled) => Some(target),

            (_, FleetMembershipState::Withdrawn) => Some(target),

            (FleetMembershipState::Enrolled, FleetMembershipState::Quarantined) => Some(target),
            (FleetMembershipState::Quarantined, FleetMembershipState::Expelled) => Some(target),

            (FleetMembershipState::Expelled, _) => None,
            _ => None,
        }
    }

    /// Validates and applies a state transition. Returns an error if the
    /// transition is invalid per the FSM table (14 allowed edges, 8 states).
    ///
    /// INV-026: The `Withdrawn` target is always accepted from any state
    /// because host policy supremacy is a constitutional constant — no
    /// cluster action can override a host's unilateral withdrawal.
    pub fn transition_to(
        &mut self,
        new_state: FleetMembershipState,
    ) -> Result<(), MembershipError> {
        match self.transition(new_state) {
            Some(target) => {
                self.state = target;
                Ok(())
            }
            None => Err(MembershipError::InvalidTransition {
                from: self.state,
                to: new_state,
            }),
        }
    }

    #[must_use]
    pub fn host_can_reject_cluster_decision(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_membership(state: FleetMembershipState) -> FleetMembership {
        FleetMembership {
            membership_id: "mem_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            host_id: "host_01".into(),
            cluster_id: "clr_01".into(),
            state,
            host_policy_supremacy: true,
            cluster_overridable: false,
        }
    }

    #[test]
    fn host_policy_supremacy_always_true() {
        let m = FleetMembership::new("mem_01".into(), "host_01".into(), "clr_01".into());
        assert!(m.host_policy_supremacy);
    }

    #[test]
    fn cluster_overridable_always_false() {
        let m = FleetMembership::new("mem_02".into(), "host_02".into(), "clr_02".into());
        assert!(!m.cluster_overridable);
    }

    #[test]
    fn host_can_reject() {
        let m = FleetMembership::new("mem_03".into(), "host_03".into(), "clr_03".into());
        assert!(m.host_can_reject_cluster_decision());
    }

    #[test]
    fn fsm_discovered_to_invited() {
        let m = mk_membership(FleetMembershipState::Discovered);
        assert_eq!(
            m.transition(FleetMembershipState::Invited),
            Some(FleetMembershipState::Invited)
        );
    }

    #[test]
    fn fsm_invited_to_attesting() {
        let m = mk_membership(FleetMembershipState::Invited);
        assert_eq!(
            m.transition(FleetMembershipState::Attesting),
            Some(FleetMembershipState::Attesting)
        );
    }

    #[test]
    fn fsm_attesting_to_enrolled() {
        let m = mk_membership(FleetMembershipState::Attesting);
        assert_eq!(
            m.transition(FleetMembershipState::Enrolled),
            Some(FleetMembershipState::Enrolled)
        );
    }

    #[test]
    fn fsm_enrolled_to_suspended() {
        let m = mk_membership(FleetMembershipState::Enrolled);
        assert_eq!(
            m.transition(FleetMembershipState::Suspended),
            Some(FleetMembershipState::Suspended)
        );
    }

    #[test]
    fn fsm_any_to_withdrawn() {
        let states = [
            FleetMembershipState::Discovered,
            FleetMembershipState::Invited,
            FleetMembershipState::Attesting,
            FleetMembershipState::Enrolled,
            FleetMembershipState::Suspended,
            FleetMembershipState::Quarantined,
        ];
        for s in &states {
            let m = mk_membership(*s);
            assert_eq!(
                m.transition(FleetMembershipState::Withdrawn),
                Some(FleetMembershipState::Withdrawn),
                "failed to withdraw from {s:?}"
            );
        }
    }

    #[test]
    fn fsm_enrolled_to_quarantined() {
        let m = mk_membership(FleetMembershipState::Enrolled);
        assert_eq!(
            m.transition(FleetMembershipState::Quarantined),
            Some(FleetMembershipState::Quarantined)
        );
    }

    #[test]
    fn fsm_quarantined_to_expelled() {
        let m = mk_membership(FleetMembershipState::Quarantined);
        assert_eq!(
            m.transition(FleetMembershipState::Expelled),
            Some(FleetMembershipState::Expelled)
        );
    }

    #[test]
    fn fsm_expelled_is_terminal() {
        let m = mk_membership(FleetMembershipState::Expelled);
        assert_eq!(m.transition(FleetMembershipState::Enrolled), None);
        assert_eq!(m.transition(FleetMembershipState::Discovered), None);
        assert_eq!(m.transition(FleetMembershipState::Invited), None);
        assert_eq!(m.transition(FleetMembershipState::Attesting), None);
    }

    #[test]
    fn fsm_expelled_can_withdraw() {
        let m = mk_membership(FleetMembershipState::Expelled);
        assert_eq!(
            m.transition(FleetMembershipState::Withdrawn),
            Some(FleetMembershipState::Withdrawn)
        );
    }

    #[test]
    fn fsm_invalid_transitions() {
        let m = mk_membership(FleetMembershipState::Discovered);
        assert_eq!(m.transition(FleetMembershipState::Enrolled), None);
        assert_eq!(m.transition(FleetMembershipState::Expelled), None);
    }

    #[test]
    fn new_membership_starts_discovered() {
        let m = FleetMembership::new("mem_01".into(), "host_01".into(), "clr_01".into());
        assert_eq!(m.state, FleetMembershipState::Discovered);
    }
}
