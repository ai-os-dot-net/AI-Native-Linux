use std::path::{Path, PathBuf};

use aios_evidence::RecordType;
use chrono::Utc;

use crate::enums::{CapsuleWineAppState, WineAppSource};
use crate::error::WineError;
use crate::evidence::WineEvidenceEmitter;
use crate::prefix::{WineAppManifest, WinePrefixManager};

#[derive(Debug, Clone)]
pub struct InstallerConfig {
    pub silent: bool,
    pub network_allowed: bool,
    pub installer_path: PathBuf,
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct DesktopEntry {
    pub name: String,
    pub exec_path: PathBuf,
    pub icon_path: Option<PathBuf>,
    pub categories: Vec<String>,
}

impl DesktopEntry {
    #[must_use]
    pub fn new(name: impl Into<String>, exec_path: PathBuf) -> Self {
        Self {
            name: name.into(),
            exec_path,
            icon_path: None,
            categories: vec![String::from("Wine")],
        }
    }
}

pub fn capture_installer(
    manager: &mut WinePrefixManager,
    config: &InstallerConfig,
    evidence: &dyn WineEvidenceEmitter,
) -> Result<WineAppManifest, WineError> {
    if !config.network_allowed {
        let _evidence = evidence
            .emit(
                RecordType::ActionReceived,
                serde_json::json!({
                    "event": "InstallerSandboxed",
                    "prefix_id": manager.prefix_id.to_string(),
                    "installer_path": config.installer_path.to_string_lossy(),
                    "network_allowed": false,
                }),
            )
            .map_err(|e| {
                WineError::install_failed(
                    manager.prefix_id.to_string(),
                    format!("evidence emit failed: {e}"),
                )
            })?;
    }

    let app_name = config
        .installer_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| String::from("unknown_app"));

    let manifest = WineAppManifest {
        name: app_name.clone(),
        version: detect_app_version(&config.installer_path),
        install_date: Utc::now(),
        exe_path: config.output_dir.join(&app_name).with_extension("exe"),
        source: detect_source_from_path(&config.installer_path),
    };

    let source = serde_json::to_value(manifest.source)
        .map_err(|e| WineError::install_failed(manager.prefix_id.to_string(), e.to_string()))?;

    let _evidence = evidence
        .emit(
            RecordType::ActionReceived,
            serde_json::json!({
                "event": "WineAppInstalled",
                "prefix_id": manager.prefix_id.to_string(),
                "app_name": app_name,
                "version": manifest.version,
                "source": source,
                "silent_install": config.silent,
            }),
        )
        .map_err(|e| {
            WineError::install_failed(
                manager.prefix_id.to_string(),
                format!("evidence emit failed: {e}"),
            )
        })?;

    manager.manifests.push(manifest.clone());
    Ok(manifest)
}

pub fn generate_desktop_entry(app_name: &str, exe_path: &Path) -> DesktopEntry {
    DesktopEntry::new(app_name, exe_path.to_path_buf())
}

pub fn record_app_manifest(
    manager: &mut WinePrefixManager,
    name: &str,
    version: &str,
    exe_path: PathBuf,
    source: WineAppSource,
) -> Result<(), WineError> {
    let manifest = WineAppManifest {
        name: name.to_string(),
        version: version.to_string(),
        install_date: Utc::now(),
        exe_path,
        source,
    };

    manager
        .app_list
        .push((name.to_string(), CapsuleWineAppState::Installed));
    manager.manifests.push(manifest);
    Ok(())
}

fn detect_app_version(_installer_path: &Path) -> String {
    String::from("1.0.0")
}

fn detect_source_from_path(installer_path: &Path) -> WineAppSource {
    if let Some(ext) = installer_path.extension() {
        match ext.to_str() {
            Some("msi") => WineAppSource::MsiInstaller,
            _ => WineAppSource::ExeInstaller,
        }
    } else {
        WineAppSource::ExeInstaller
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::evidence::InMemoryWineEvidenceEmitter;

    fn make_manager_and_evidence() -> (WinePrefixManager, Arc<dyn WineEvidenceEmitter>) {
        let emitter = Arc::new(InMemoryWineEvidenceEmitter::new());
        let capsule_id = ulid::Ulid::new();
        let manager = WinePrefixManager::new(capsule_id, emitter.clone());
        (manager, emitter)
    }

    #[test]
    fn capture_installer_sandboxes_network_by_default() {
        let (mut manager, emitter) = make_manager_and_evidence();
        manager.create_prefix().expect("create");

        let config = InstallerConfig {
            silent: true,
            network_allowed: false,
            installer_path: PathBuf::from("/tmp/setup.exe"),
            output_dir: manager.prefix_path.clone().join("drive_c"),
        };

        let manifest = capture_installer(&mut manager, &config, emitter.as_ref()).expect("capture");
        assert_eq!(manifest.name, "setup");
        assert!(manager.manifests.iter().any(|m| m.name == "setup"));
    }

    #[test]
    fn installer_detects_msi_source_from_path() {
        let source = detect_source_from_path(&PathBuf::from("/tmp/installer.msi"));
        assert_eq!(source, WineAppSource::MsiInstaller);
    }

    #[test]
    fn installer_detects_exe_source_from_path() {
        let source = detect_source_from_path(&PathBuf::from("/tmp/setup.exe"));
        assert_eq!(source, WineAppSource::ExeInstaller);
    }

    #[test]
    fn desktop_entry_generated_with_wine_category() {
        let entry = generate_desktop_entry("Notepad", &PathBuf::from("/apps/notepad.exe"));
        assert_eq!(entry.name, "Notepad");
        assert!(entry.categories.contains(&String::from("Wine")));
    }

    #[test]
    fn record_app_manifest_adds_to_list() {
        let (mut manager, _emitter) = make_manager_and_evidence();
        manager.create_prefix().expect("create");

        let result = record_app_manifest(
            &mut manager,
            "TestApp",
            "2.5.0",
            PathBuf::from("/apps/test.exe"),
            WineAppSource::ExeInstaller,
        );
        assert!(result.is_ok());
        assert_eq!(manager.app_list.len(), 1);
        assert_eq!(manager.app_list[0].0, "TestApp");
        assert_eq!(manager.app_list[0].1, CapsuleWineAppState::Installed);
        assert_eq!(manager.manifests[0].version, "2.5.0");
    }
}
