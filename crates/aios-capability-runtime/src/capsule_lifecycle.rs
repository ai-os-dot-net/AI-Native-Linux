//! Capsule lifecycle manager — orchestrates OS-RESEARCH modules.
#![allow(clippy::doc_markdown, clippy::missing_const_for_fn)]

use super::capsule_namespace::CapsuleId;
use super::managed_isolate::{IsolationMechanism, IsolationRegistry, ManagedIsolate};
use super::recursive_sandbox::SandboxHierarchy;
use super::sel4_cap_model::CapRights;
use super::snapshot::{CapsuleSnapshot, SnapshotPayload, SnapshotStore};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapsuleLifecycle {
    Created,
    Configured,
    Launching,
    Running,
    Paused,
    Snapshotting,
    Stopping,
    Destroyed,
}

impl CapsuleLifecycle {
    pub fn valid_transitions() -> Vec<(Self, Self)> {
        use CapsuleLifecycle::*;
        vec![
            (Created, Configured),
            (Configured, Launching),
            (Configured, Destroyed),
            (Launching, Running),
            (Launching, Destroyed),
            (Running, Paused),
            (Running, Snapshotting),
            (Running, Stopping),
            (Paused, Running),
            (Paused, Stopping),
            (Paused, Destroyed),
            (Snapshotting, Running),
            (Stopping, Destroyed),
        ]
    }

    pub fn can_transition_to(&self, target: Self) -> bool {
        Self::valid_transitions()
            .iter()
            .any(|(f, t)| *f == *self && *t == target)
    }
}

#[derive(Debug, Clone)]
pub struct CapsuleLifecycleState {
    pub capsule_id: CapsuleId,
    pub state: CapsuleLifecycle,
    pub mechanism: IsolationMechanism,
    pub parent_id: Option<CapsuleId>,
    pub created_at: u64,
    pub last_transition: u64,
}

#[derive(Debug)]
pub struct CapsuleLifecycleManager {
    capsules: HashMap<CapsuleId, CapsuleLifecycleState>,
    pub sandbox_hierarchy: SandboxHierarchy,
    pub isolation_registry: IsolationRegistry,
    pub snapshot_store: SnapshotStore,
}

impl CapsuleLifecycleManager {
    pub fn new() -> Self {
        let mut h = SandboxHierarchy::new();
        h.create_root(CapsuleId(0));
        Self {
            capsules: HashMap::new(),
            sandbox_hierarchy: h,
            isolation_registry: IsolationRegistry::new(),
            snapshot_store: SnapshotStore::new(),
        }
    }

    pub fn create_capsule(
        &mut self,
        id: CapsuleId,
        mechanism: IsolationMechanism,
        parent_id: Option<CapsuleId>,
    ) -> Result<(), String> {
        if self.capsules.contains_key(&id) {
            return Err("capsule already exists".into());
        }
        let parent = parent_id.unwrap_or(CapsuleId(0));
        self.sandbox_hierarchy
            .create_child(id, parent)
            .ok_or("failed to create sandbox child")?;
        let isolate = ManagedIsolate::new(id.0, mechanism, vec![]);
        self.isolation_registry.register(isolate);
        let state = CapsuleLifecycleState {
            capsule_id: id,
            state: CapsuleLifecycle::Created,
            mechanism,
            parent_id,
            created_at: 0,
            last_transition: 0,
        };
        self.capsules.insert(id, state);
        Ok(())
    }

    pub fn configure_capsule(
        &mut self,
        id: CapsuleId,
        _caps: Vec<CapRights>,
        _bindings: Vec<String>,
    ) -> Result<(), String> {
        let state = self.capsules.get_mut(&id).ok_or("capsule not found")?;
        if !state.state.can_transition_to(CapsuleLifecycle::Configured) {
            return Err("invalid transition".into());
        }
        state.state = CapsuleLifecycle::Configured;
        Ok(())
    }

    pub fn launch_capsule(&mut self, id: CapsuleId) -> Result<(), String> {
        let state = self.capsules.get_mut(&id).ok_or("capsule not found")?;
        if !state.state.can_transition_to(CapsuleLifecycle::Launching) {
            return Err("invalid transition".into());
        }
        state.state = CapsuleLifecycle::Launching;
        state.state = CapsuleLifecycle::Running;
        Ok(())
    }

    pub fn snapshot_capsule(
        &mut self,
        id: CapsuleId,
        label: String,
    ) -> Result<CapsuleSnapshot, String> {
        let state = self.capsules.get_mut(&id).ok_or("capsule not found")?;
        if !state
            .state
            .can_transition_to(CapsuleLifecycle::Snapshotting)
        {
            return Err("invalid transition".into());
        }
        state.state = CapsuleLifecycle::Snapshotting;
        let snap = self.snapshot_store.freeze(
            id,
            label,
            0,
            SnapshotPayload::CapsuleState {
                data: vec![],
                mime: "".into(),
            },
        );
        state.state = CapsuleLifecycle::Running;
        Ok(snap)
    }

    pub fn stop_capsule(&mut self, id: CapsuleId) -> Result<(), String> {
        let state = self.capsules.get_mut(&id).ok_or("capsule not found")?;
        if !state.state.can_transition_to(CapsuleLifecycle::Stopping) {
            return Err("invalid transition".into());
        }
        state.state = CapsuleLifecycle::Stopping;
        Ok(())
    }

    pub fn destroy_capsule(&mut self, id: CapsuleId) -> Result<(), String> {
        let state = self.capsules.get_mut(&id).ok_or("capsule not found")?;
        if !state.state.can_transition_to(CapsuleLifecycle::Destroyed) {
            return Err("invalid transition".into());
        }
        state.state = CapsuleLifecycle::Destroyed;
        self.sandbox_hierarchy.destroy_cascade(id);
        self.snapshot_store.delete_all_for_capsule(id);
        Ok(())
    }

    pub fn lifecycle_state(&self, id: CapsuleId) -> Option<CapsuleLifecycle> {
        self.capsules.get(&id).map(|s| s.state)
    }

    pub fn capsule_count(&self) -> usize {
        self.capsules.len()
    }
}

impl Default for CapsuleLifecycleManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> CapsuleLifecycleManager {
        CapsuleLifecycleManager::new()
    }

    #[test]
    fn create_initializes_subsystems() {
        let mut m = setup();
        assert!(m
            .create_capsule(CapsuleId(1), IsolationMechanism::TypeSafe, None)
            .is_ok());
        assert_eq!(m.capsule_count(), 1);
        assert_eq!(
            m.lifecycle_state(CapsuleId(1)),
            Some(CapsuleLifecycle::Created)
        );
    }

    #[test]
    fn full_lifecycle() {
        let mut m = setup();
        let id = CapsuleId(1);
        m.create_capsule(id, IsolationMechanism::TypeSafe, None)
            .unwrap();
        m.configure_capsule(id, vec![], vec![]).unwrap();
        m.launch_capsule(id).unwrap();
        assert_eq!(m.lifecycle_state(id), Some(CapsuleLifecycle::Running));
        let snap = m.snapshot_capsule(id, "test".into()).unwrap();
        assert_eq!(snap.capsule_id, id);
        m.stop_capsule(id).unwrap();
        m.destroy_capsule(id).unwrap();
        assert_eq!(m.lifecycle_state(id), Some(CapsuleLifecycle::Destroyed));
    }

    #[test]
    fn cannot_launch_without_configure() {
        let mut m = setup();
        m.create_capsule(CapsuleId(1), IsolationMechanism::TypeSafe, None)
            .unwrap();
        assert!(m.launch_capsule(CapsuleId(1)).is_err());
    }

    #[test]
    fn cannot_configure_destroyed() {
        let mut m = setup();
        m.create_capsule(CapsuleId(1), IsolationMechanism::TypeSafe, None)
            .unwrap();
        m.configure_capsule(CapsuleId(1), vec![], vec![]).unwrap();
        m.launch_capsule(CapsuleId(1)).unwrap();
        m.stop_capsule(CapsuleId(1)).unwrap();
        m.destroy_capsule(CapsuleId(1)).unwrap();
        assert!(m.configure_capsule(CapsuleId(1), vec![], vec![]).is_err());
    }

    #[test]
    fn transition_table_coverage() {
        let transitions = CapsuleLifecycle::valid_transitions();
        assert!(transitions.len() > 5);
        assert!(CapsuleLifecycle::Created.can_transition_to(CapsuleLifecycle::Configured));
        assert!(!CapsuleLifecycle::Destroyed.can_transition_to(CapsuleLifecycle::Running));
    }

    #[test]
    fn snapshot_integration() {
        let mut m = setup();
        let id = CapsuleId(1);
        m.create_capsule(id, IsolationMechanism::TypeSafe, None)
            .unwrap();
        m.configure_capsule(id, vec![], vec![]).unwrap();
        m.launch_capsule(id).unwrap();
        let s1 = m.snapshot_capsule(id, "s1".into()).unwrap();
        let s2 = m.snapshot_capsule(id, "s2".into()).unwrap();
        assert_eq!(m.snapshot_store.list(id).len(), 2);
        assert_ne!(s1.id, s2.id);
    }
}
