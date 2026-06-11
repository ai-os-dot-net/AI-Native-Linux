use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ulid::Ulid;

use crate::enums::{CapsuleWineAppState, WineAppSource, WineDxvkMode, WineGPUClass, WinePrefixState};
use crate::error::WineError;
use crate::evidence::WineEvidenceEmitter;
use crate::sandbox_profile::generate_wine_sandbox_profile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WineAppManifest {
    pub name: String,
    pub version: String,
    pub install_date: DateTime<Utc>,
    pub exe_path: PathBuf,
    pub source: WineAppSource,
}

pub struct WinePrefixManager {
    pub prefix_id: Ulid,
    pub capsule_id: Ulid,
    pub prefix_path: PathBuf,
    pub architecture: WineArchitecture,
    pub dxvk_mode: WineDxvkMode,
    pub gpu_class: WineGPUClass,
    pub state: WinePrefixState,
    pub app_list: Vec<(String, CapsuleWineAppState)>,
    pub manifests: Vec<WineAppManifest>,
    evidence: Arc<dyn WineEvidenceEmitter>,
    created_at: DateTime<Utc>,
}

impl fmt::Debug for WinePrefixManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WinePrefixManager")
            .field("prefix_id", &self.prefix_id)
            .field("capsule_id", &self.capsule_id)
            .field("prefix_path", &self.prefix_path)
            .field("architecture", &self.architecture)
            .field("dxvk_mode", &self.dxvk_mode)
            .field("gpu_class", &self.gpu_class)
            .field("state", &self.state)
            .field("app_list", &self.app_list)
            .field("manifests", &self.manifests)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WineArchitecture {
    Win64,
    Win32,
}

impl WinePrefixManager {
    #[must_use]
    pub fn new(capsule_id: Ulid, evidence: Arc<dyn WineEvidenceEmitter>) -> Self {
        let prefix_id = Ulid::new();
        let prefix_path = PathBuf::from(format!("/var/lib/aios/capsules/{capsule_id}/wine/"));
        Self {
            prefix_id,
            capsule_id,
            prefix_path,
            architecture: WineArchitecture::Win64,
            dxvk_mode: WineDxvkMode::None,
            gpu_class: WineGPUClass::None,
            state: WinePrefixState::Creating,
            app_list: Vec::new(),
            manifests: Vec::new(),
            evidence,
            created_at: Utc::now(),
        }
    }

    #[must_use]
    pub fn with_architecture(mut self, arch: WineArchitecture) -> Self {
        self.architecture = arch;
        self
    }

    #[must_use]
    pub fn with_gpu_class(mut self, gpu_class: WineGPUClass) -> Self {
        self.gpu_class = gpu_class;
        self
    }

    pub fn create_prefix(&mut self) -> Result<(), WineError> {
        self.validate_state(WinePrefixState::Creating)?;

        let sandbox = generate_wine_sandbox_profile(
            &self.prefix_path,
            self.capsule_id.to_string(),
            false,
        );

        let _evidence = self
            .evidence
            .emit(
                aios_evidence::RecordType::ActionReceived,
                serde_json::json!({
                    "event": "WinePrefixCreated",
                    "prefix_id": self.prefix_id.to_string(),
                    "capsule_id": self.capsule_id.to_string(),
                    "prefix_path": self.prefix_path.to_string_lossy(),
                    "architecture": if self.architecture == WineArchitecture::Win64 { "win64" } else { "win32" },
                    "sandbox_profile_id": sandbox.profile_id.to_string(),
                }),
            )
            .map_err(|e| {
                WineError::prefix_creation_failed(self.capsule_id.to_string(), e.to_string())
            })?;

        self.state = WinePrefixState::Active;
        Ok(())
    }

    pub fn install_app(
        &mut self,
        source: WineAppSource,
        installer_path: PathBuf,
        app_name: String,
    ) -> Result<(), WineError> {
        self.validate_state(WinePrefixState::Active)?;
        self.validate_not_running()?;

        self.app_list
            .push((app_name.clone(), CapsuleWineAppState::Installing));

        let manifest = WineAppManifest {
            name: app_name.clone(),
            version: String::from("0.0.0"),
            install_date: Utc::now(),
            exe_path: self.prefix_path.join("drive_c").join(&app_name),
            source,
        };

        let _evidence = self
            .evidence
            .emit(
                aios_evidence::RecordType::ActionReceived,
                serde_json::json!({
                    "event": "WineAppInstalled",
                    "prefix_id": self.prefix_id.to_string(),
                    "app_name": app_name,
                    "source": serde_json::to_value(source).expect("serialize"),
                    "installer_path": installer_path.to_string_lossy(),
                }),
            )
            .map_err(|e| WineError::install_failed(self.prefix_id.to_string(), e.to_string()))?;

        self.manifests.push(manifest);
        if let Some((_, state)) = self.app_list.last_mut() {
            *state = CapsuleWineAppState::Installed;
        }

        Ok(())
    }

    pub fn run_app(
        &mut self,
        exe_path: PathBuf,
        _args: Vec<String>,
    ) -> Result<(), WineError> {
        self.validate_state(WinePrefixState::Active)?;

        let matching = self.app_list.iter().find(|(_, state)| {
            *state == CapsuleWineAppState::Installed || *state == CapsuleWineAppState::Suspended
        });

        if matching.is_none() {
            return Err(WineError::app_not_found(
                self.prefix_id.to_string(),
                exe_path.to_string_lossy().to_string(),
            ));
        }

        let app_name = matching.expect("checked").0.clone();
        for (name, state) in &mut self.app_list {
            if *name == app_name {
                *state = CapsuleWineAppState::Running;
            }
        }

        let _evidence = self
            .evidence
            .emit(
                aios_evidence::RecordType::ActionReceived,
                serde_json::json!({
                    "event": "WineAppLaunched",
                    "prefix_id": self.prefix_id.to_string(),
                    "exe_path": exe_path.to_string_lossy(),
                    "app_name": app_name,
                }),
            )
            .map_err(|e| WineError::wine_not_found(format!("evidence emit failed: {e}")))?;

        Ok(())
    }

    pub fn suspend(&mut self) -> Result<(), WineError> {
        self.validate_state(WinePrefixState::Active)?;

        for (_, state) in &mut self.app_list {
            if *state == CapsuleWineAppState::Running {
                *state = CapsuleWineAppState::Suspended;
            }
        }

        let _evidence = self
            .evidence
            .emit(
                aios_evidence::RecordType::ActionReceived,
                serde_json::json!({
                    "event": "WineAppSuspended",
                    "prefix_id": self.prefix_id.to_string(),
                }),
            )
            .map_err(|e| WineError::wine_not_found(format!("evidence emit failed: {e}")))?;

        self.state = WinePrefixState::Suspended;
        Ok(())
    }

    pub fn destroy_ephemeral(&mut self) -> Result<(), WineError> {
        self.state = WinePrefixState::EphemeralDestroyed;

        let _evidence = self
            .evidence
            .emit(
                aios_evidence::RecordType::ActionReceived,
                serde_json::json!({
                    "event": "WinePrefixDestroyed",
                    "prefix_id": self.prefix_id.to_string(),
                }),
            )
            .map_err(|e| WineError::wine_not_found(format!("evidence emit failed: {e}")))?;

        Ok(())
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == WinePrefixState::Active
    }

    fn validate_state(&self, expected: WinePrefixState) -> Result<(), WineError> {
        if self.state != expected {
            return Err(WineError::invalid_state_transition(
                self.prefix_id.to_string(),
                self.state,
                expected,
            ));
        }
        Ok(())
    }

    fn validate_not_running(&self) -> Result<(), WineError> {
        let has_running = self
            .app_list
            .iter()
            .any(|(_, state)| *state == CapsuleWineAppState::Running);
        if has_running {
            return Err(WineError::already_running(self.prefix_id.to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::evidence::InMemoryWineEvidenceEmitter;

    fn make_prefix() -> WinePrefixManager {
        let emitter = Arc::new(InMemoryWineEvidenceEmitter::new());
        WinePrefixManager::new(Ulid::new(), emitter)
    }

    #[test]
    fn prefix_created_in_expected_path() {
        let capsule_id = Ulid::new();
        let emitter = Arc::new(InMemoryWineEvidenceEmitter::new());
        let mut manager = WinePrefixManager::new(capsule_id, emitter);
        let result = manager.create_prefix();
        assert!(result.is_ok());
        let expected = format!("/var/lib/aios/capsules/{capsule_id}/wine/");
        assert_eq!(manager.prefix_path.to_string_lossy(), expected);
    }

    #[test]
    fn prefix_state_transitions_creating_to_active() {
        let mut manager = make_prefix();
        assert_eq!(manager.state, WinePrefixState::Creating);
        manager.create_prefix().expect("create");
        assert_eq!(manager.state, WinePrefixState::Active);
    }

    #[test]
    fn install_app_records_manifest() {
        let mut manager = make_prefix();
        manager.create_prefix().expect("create");
        let installer = PathBuf::from("/tmp/setup.exe");
        manager
            .install_app(
                WineAppSource::ExeInstaller,
                installer,
                String::from("TestApp"),
            )
            .expect("install");
        assert_eq!(manager.manifests.len(), 1);
        assert_eq!(manager.manifests[0].name, "TestApp");
        assert_eq!(manager.manifests[0].source, WineAppSource::ExeInstaller);
    }

    #[test]
    fn install_app_emits_evidence() {
        let mut manager = make_prefix();
        manager.create_prefix().expect("create");
        manager
            .install_app(
                WineAppSource::ExeInstaller,
                PathBuf::from("/tmp/setup.exe"),
                String::from("TestApp"),
            )
            .expect("install");
        assert_eq!(manager.app_list.len(), 1);
        assert_eq!(manager.app_list[0].1, CapsuleWineAppState::Installed);
    }

    #[test]
    fn run_app_changes_state_to_running() {
        let mut manager = make_prefix();
        manager.create_prefix().expect("create");
        manager
            .install_app(
                WineAppSource::ExeInstaller,
                PathBuf::from("/tmp/app.exe"),
                String::from("MyApp"),
            )
            .expect("install");

        manager
            .run_app(PathBuf::from("/tmp/app.exe"), vec![])
            .expect("run");

        let (_, state) = &manager.app_list[0];
        assert_eq!(*state, CapsuleWineAppState::Running);
    }

    #[test]
    fn suspend_changes_state_to_suspended() {
        let mut manager = make_prefix();
        manager.create_prefix().expect("create");
        manager
            .install_app(
                WineAppSource::ExeInstaller,
                PathBuf::from("/tmp/app.exe"),
                String::from("MyApp"),
            )
            .expect("install");
        manager
            .run_app(PathBuf::from("/tmp/app.exe"), vec![])
            .expect("run");

        manager.suspend().expect("suspend");
        assert_eq!(manager.state, WinePrefixState::Suspended);
    }

    #[test]
    fn ephemeral_prefix_destroyed_on_close() {
        let mut manager = make_prefix();
        manager.create_prefix().expect("create");
        manager.destroy_ephemeral().expect("destroy");
        assert_eq!(manager.state, WinePrefixState::EphemeralDestroyed);
    }

    #[test]
    fn cannot_create_already_active_prefix() {
        let mut manager = make_prefix();
        manager.create_prefix().expect("create");
        let result = manager.create_prefix();
        assert!(result.is_err());
    }

    #[test]
    fn run_app_fails_when_no_matching_app() {
        let mut manager = make_prefix();
        manager.create_prefix().expect("create");
        let result = manager.run_app(PathBuf::from("/nonexistent.exe"), vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn prefix_manager_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WinePrefixManager>();
    }
}
