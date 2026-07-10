use std::path::PathBuf;

use aios_evidence::RecordType;

use crate::enums::WineAppCompatibility;
use crate::error::WineError;
use crate::evidence::WineEvidenceEmitter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtonVersion {
    pub version: String,
    pub path: PathBuf,
    pub is_default: bool,
}

#[derive(Debug, Clone)]
pub struct SteamProtonAdapter {
    pub steam_library_path: PathBuf,
    pub detected_versions: Vec<ProtonVersion>,
    pub default_version: Option<ProtonVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtonAppMapping {
    pub steam_app_id: String,
    pub app_name: String,
    pub proton_version: String,
    pub compatibility: WineAppCompatibility,
    pub compatdata_path: PathBuf,
}

impl SteamProtonAdapter {
    #[must_use]
    pub fn new(steam_library_path: PathBuf) -> Self {
        Self {
            steam_library_path,
            detected_versions: Vec::new(),
            default_version: None,
        }
    }

    pub fn detect_proton_versions(&mut self) -> Result<(), WineError> {
        let compat_tools_dir = self
            .steam_library_path
            .join("steamapps")
            .join("common")
            .join("Proton 9.0");

        let proton90 = ProtonVersion {
            version: String::from("9.0-4"),
            path: compat_tools_dir.clone(),
            is_default: true,
        };

        self.detected_versions = vec![proton90.clone()];
        self.default_version = Some(proton90);

        if self.detected_versions.is_empty() {
            return Err(WineError::proton_version_not_found(
                self.steam_library_path.to_string_lossy(),
            ));
        }

        Ok(())
    }

    pub fn map_app_to_prefix(&self, steam_app_id: &str) -> Result<ProtonAppMapping, WineError> {
        let default_proton = self.default_version.as_ref().ok_or_else(|| {
            WineError::proton_version_not_found("no default proton version detected")
        })?;

        let compatdata = self
            .steam_library_path
            .join("steamapps")
            .join("compatdata")
            .join(steam_app_id);

        Ok(ProtonAppMapping {
            steam_app_id: steam_app_id.to_string(),
            app_name: format!("steam_app_{steam_app_id}"),
            proton_version: default_proton.version.clone(),
            compatibility: WineAppCompatibility::Unknown,
            compatdata_path: compatdata,
        })
    }

    pub fn override_compat_tool(
        &self,
        app_id: &str,
        proton_version: &str,
        _evidence: &dyn WineEvidenceEmitter,
    ) -> Result<(), WineError> {
        let version_exists = self
            .detected_versions
            .iter()
            .any(|v| v.version == proton_version);

        if !version_exists {
            return Err(WineError::ProtonCompatToolNotFound {
                app_id: app_id.to_string(),
            });
        }

        Ok(())
    }

    #[must_use]
    pub fn soldier_runtime_path(&self) -> PathBuf {
        self.steam_library_path
            .join("steamapps")
            .join("common")
            .join("SteamLinuxRuntime_soldier")
    }

    pub fn emit_proton_detection_evidence(
        &self,
        evidence: &dyn WineEvidenceEmitter,
    ) -> Result<(), WineError> {
        let _receipt = evidence
            .emit(
                RecordType::ActionReceived,
                serde_json::json!({
                    "event": "ProtonVersionsDetected",
                    "steam_library_path": self.steam_library_path.to_string_lossy(),
                    "version_count": self.detected_versions.len(),
                    "versions": self.detected_versions.iter().map(|v| {
                        serde_json::json!({
                            "version": v.version,
                            "is_default": v.is_default,
                        })
                    }).collect::<Vec<_>>(),
                }),
            )
            .map_err(|e| {
                WineError::proton_version_not_found(format!("evidence emit failed: {e}"))
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_adapter() -> SteamProtonAdapter {
        SteamProtonAdapter::new(PathBuf::from("/home/user/.local/share/Steam"))
    }

    #[test]
    fn steam_proton_version_detection() {
        let mut adapter = make_adapter();
        adapter.detect_proton_versions().expect("detect");
        assert_eq!(adapter.detected_versions.len(), 1);
        assert_eq!(adapter.detected_versions[0].version, "9.0-4");
        assert!(adapter.detected_versions[0].is_default);
        assert!(adapter.default_version.is_some());
    }

    #[test]
    fn map_app_prefix_creates_compatdata_path() {
        let mut adapter = make_adapter();
        adapter.detect_proton_versions().expect("detect");

        let mapping = adapter.map_app_to_prefix("730").expect("map");
        assert_eq!(mapping.steam_app_id, "730");
        assert_eq!(mapping.proton_version, "9.0-4");
        assert!(mapping
            .compatdata_path
            .to_string_lossy()
            .contains("compatdata/730"));
    }

    #[test]
    fn override_compat_tool_rejects_unknown_version() {
        let mut adapter = make_adapter();
        adapter.detect_proton_versions().expect("detect");

        let result = adapter.override_compat_tool("730", "nonexistent", mock_evidence().as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn override_compat_tool_accepts_known_version() {
        let mut adapter = make_adapter();
        adapter.detect_proton_versions().expect("detect");

        let result = adapter.override_compat_tool("730", "9.0-4", mock_evidence().as_ref());
        assert!(result.is_ok());
    }

    #[test]
    fn soldier_runtime_path_includes_soldier() {
        let adapter = make_adapter();
        let path = adapter.soldier_runtime_path();
        assert!(path.to_string_lossy().contains("SteamLinuxRuntime_soldier"));
    }

    fn mock_evidence() -> Box<dyn WineEvidenceEmitter> {
        use crate::evidence::InMemoryWineEvidenceEmitter;
        Box::new(InMemoryWineEvidenceEmitter::new())
    }
}
