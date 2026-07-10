use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::enums::BackupSetState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSet {
    pub set_id: String,
    pub contract_id: String,
    pub host_id: String,
    pub state: BackupSetState,
    pub parent_set_id: Option<String>,
}

impl BackupSet {
    pub fn new(contract_id: String, host_id: String, parent_set_id: Option<String>) -> Self {
        let set_id = format!("bset_{}", Ulid::new());
        Self {
            set_id,
            contract_id,
            host_id,
            state: BackupSetState::Planned,
            parent_set_id,
        }
    }

    pub fn transition_to_snapshotting(&mut self) -> Result<(), String> {
        if self.state != BackupSetState::Planned {
            return Err(format!(
                "invalid transition: {:?} -> Snapshotting",
                self.state
            ));
        }
        self.state = BackupSetState::Snapshotting;
        Ok(())
    }

    pub fn transition_to_encrypting(&mut self) -> Result<(), String> {
        if self.state != BackupSetState::Snapshotting {
            return Err(format!(
                "invalid transition: {:?} -> Encrypting",
                self.state
            ));
        }
        self.state = BackupSetState::Encrypting;
        Ok(())
    }

    pub fn transition_to_writing(&mut self) -> Result<(), String> {
        if self.state != BackupSetState::Encrypting {
            return Err(format!("invalid transition: {:?} -> Writing", self.state));
        }
        self.state = BackupSetState::Writing;
        Ok(())
    }

    pub fn transition_to_verifying(&mut self) -> Result<(), String> {
        if self.state != BackupSetState::Writing {
            return Err(format!("invalid transition: {:?} -> Verifying", self.state));
        }
        self.state = BackupSetState::Verifying;
        Ok(())
    }

    pub fn transition_to_sealed(&mut self) -> Result<(), String> {
        if self.state != BackupSetState::Verifying {
            return Err(format!("invalid transition: {:?} -> Sealed", self.state));
        }
        self.state = BackupSetState::Sealed;
        Ok(())
    }

    pub fn transition_to_failed(&mut self) -> Result<(), String> {
        if self.is_terminal() {
            return Err(format!(
                "invalid transition: {:?} -> Failed (already terminal)",
                self.state
            ));
        }
        self.state = BackupSetState::Failed;
        Ok(())
    }

    pub fn transition_to_shredded(&mut self) -> Result<(), String> {
        if self.state != BackupSetState::Sealed {
            return Err(format!(
                "invalid transition: {:?} -> Shredded (only Sealed may be shredded)",
                self.state
            ));
        }
        self.state = BackupSetState::Shredded;
        Ok(())
    }

    pub fn is_restorable(&self) -> bool {
        self.state == BackupSetState::Sealed
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            BackupSetState::Failed | BackupSetState::Expired | BackupSetState::Shredded
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_fsm_transitions() {
        let mut set = BackupSet::new("cbc_01".into(), "host-1".into(), None);
        assert_eq!(set.state, BackupSetState::Planned);

        set.transition_to_snapshotting()
            .expect("Planned -> Snapshotting");
        assert_eq!(set.state, BackupSetState::Snapshotting);

        set.transition_to_encrypting()
            .expect("Snapshotting -> Encrypting");
        assert_eq!(set.state, BackupSetState::Encrypting);

        set.transition_to_writing().expect("Encrypting -> Writing");
        assert_eq!(set.state, BackupSetState::Writing);

        set.transition_to_verifying().expect("Writing -> Verifying");
        assert_eq!(set.state, BackupSetState::Verifying);

        set.transition_to_sealed().expect("Verifying -> Sealed");
        assert_eq!(set.state, BackupSetState::Sealed);
    }

    #[test]
    fn any_state_can_fail() {
        let states = [
            BackupSetState::Planned,
            BackupSetState::Snapshotting,
            BackupSetState::Encrypting,
            BackupSetState::Writing,
            BackupSetState::Verifying,
        ];
        for state in &states {
            let mut set = BackupSet::new("cbc_01".into(), "host-1".into(), None);
            set.state = *state;
            set.transition_to_failed()
                .expect("should transition to Failed");
            assert_eq!(set.state, BackupSetState::Failed);
        }
    }

    #[test]
    fn failed_cannot_fail_again() {
        let mut set = BackupSet::new("cbc_01".into(), "host-1".into(), None);
        set.state = BackupSetState::Failed;
        assert!(set.transition_to_failed().is_err());
    }

    #[test]
    fn only_sealed_is_restorable() {
        let mut set = BackupSet::new("cbc_01".into(), "host-1".into(), None);
        assert!(!set.is_restorable());

        // Walk to Sealed
        set.state = BackupSetState::Sealed;
        assert!(set.is_restorable());

        set.state = BackupSetState::Failed;
        assert!(!set.is_restorable());

        set.state = BackupSetState::Shredded;
        assert!(!set.is_restorable());

        set.state = BackupSetState::Expired;
        assert!(!set.is_restorable());
    }

    #[test]
    fn terminal_states_are_terminal() {
        for state in &[
            BackupSetState::Failed,
            BackupSetState::Expired,
            BackupSetState::Shredded,
        ] {
            let mut set = BackupSet::new("cbc_01".into(), "host-1".into(), None);
            set.state = *state;
            assert!(set.is_terminal());
        }
    }

    #[test]
    fn non_terminal_states_are_not_terminal() {
        for state in &[
            BackupSetState::Planned,
            BackupSetState::Snapshotting,
            BackupSetState::Encrypting,
            BackupSetState::Writing,
            BackupSetState::Verifying,
            BackupSetState::Sealed,
        ] {
            let mut set = BackupSet::new("cbc_01".into(), "host-1".into(), None);
            set.state = *state;
            assert!(!set.is_terminal());
        }
    }

    #[test]
    fn invalid_transition_to_snapshotting_rejected() {
        let mut set = BackupSet::new("cbc_01".into(), "host-1".into(), None);
        set.state = BackupSetState::Sealed;
        assert!(set.transition_to_snapshotting().is_err());
    }

    #[test]
    fn sealed_to_shredded_valid() {
        let mut set = BackupSet::new("cbc_01".into(), "host-1".into(), None);
        set.state = BackupSetState::Sealed;
        set.transition_to_shredded().expect("Sealed -> Shredded");
        assert_eq!(set.state, BackupSetState::Shredded);
    }

    #[test]
    fn shred_from_non_sealed_rejected() {
        let mut set = BackupSet::new("cbc_01".into(), "host-1".into(), None);
        assert!(set.transition_to_shredded().is_err());

        set.state = BackupSetState::Failed;
        assert!(set.transition_to_shredded().is_err());

        set.state = BackupSetState::Planned;
        assert!(set.transition_to_shredded().is_err());
    }

    #[test]
    fn incremental_chain_preserves_parent() {
        let parent = BackupSet::new("cbc_01".into(), "host-1".into(), None);
        let child = BackupSet::new(
            "cbc_01".into(),
            "host-1".into(),
            Some(parent.set_id.clone()),
        );
        assert_eq!(child.parent_set_id, Some(parent.set_id));
    }
}
