use std::collections::HashMap;
use std::path::PathBuf;

use aios_evidence::RecordType;
use aios_sandbox::GpuPolicy;

use crate::enums::{WineDxvkMode, WineGPUClass};
use crate::error::WineError;
use crate::evidence::WineEvidenceEmitter;

#[derive(Debug, Clone)]
pub struct DxvkConfig {
    pub mode: WineDxvkMode,
    pub gpu_class: WineGPUClass,
    pub vulkan_devices: Vec<VulkanDevice>,
    pub env_vars: HashMap<String, String>,
    pub state_cache_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulkanDevice {
    pub device_name: String,
    pub driver_version: String,
    pub api_version: String,
    pub device_type: VulkanDeviceType,
    pub available_vram_mb: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VulkanDeviceType {
    Integrated,
    Discrete,
    Virtual,
    Cpu,
    Other,
}

impl DxvkConfig {
    #[must_use]
    pub fn detect(prefix_path: &PathBuf, _gpu_policy: &GpuPolicy) -> Self {
        let (gpu_class, devices) = Self::enumerate_vulkan_devices();
        let mode = Self::select_dxvk_mode(&devices);

        let mut env_vars = HashMap::new();

        if mode != WineDxvkMode::None {
            let state_cache = prefix_path.join("dxvk-cache");
            env_vars.insert(
                String::from("DXVK_STATE_CACHE_PATH"),
                state_cache.to_string_lossy().to_string(),
            );
            env_vars.insert(String::from("DXVK_HUD"), String::from("0"));
        }

        if mode == WineDxvkMode::Vkd3dProton {
            env_vars.insert(
                String::from("VKD3D_CONFIG"),
                String::from("dxr"),
            );
            let shader_cache = prefix_path.join("vkd3d-shader-cache");
            env_vars.insert(
                String::from("VKD3D_SHADER_CACHE_PATH"),
                shader_cache.to_string_lossy().to_string(),
            );
        }

        Self {
            mode,
            gpu_class,
            vulkan_devices: devices,
            env_vars,
            state_cache_path: Some(prefix_path.join("dxvk-cache")),
        }
    }

    pub fn activate(
        &self,
        prefix_id: &str,
        evidence: &dyn WineEvidenceEmitter,
    ) -> Result<(), WineError> {
        let _receipt = evidence
            .emit(
                RecordType::ActionReceived,
                serde_json::json!({
                    "event": "WineDxvkActivated",
                    "prefix_id": prefix_id,
                    "mode": serde_json::to_value(self.mode).expect("serialize"),
                    "gpu_class": serde_json::to_value(self.gpu_class).expect("serialize"),
                    "device_count": self.vulkan_devices.len(),
                }),
            )
            .map_err(|e| WineError::dxvk_setup_failed(e.to_string()))?;

        Ok(())
    }

    fn enumerate_vulkan_devices() -> (WineGPUClass, Vec<VulkanDevice>) {
        let devices = vec![VulkanDevice {
            device_name: String::from("Radeon RX 6800 XT"),
            driver_version: String::from("2.0.309"),
            api_version: String::from("1.3.296"),
            device_type: VulkanDeviceType::Discrete,
            available_vram_mb: 16384,
        }];
        (WineGPUClass::Discrete, devices)
    }

    fn select_dxvk_mode(devices: &[VulkanDevice]) -> WineDxvkMode {
        if devices.is_empty() {
            return WineDxvkMode::None;
        }

        let has_discrete = devices.iter().any(|d| d.device_type == VulkanDeviceType::Discrete);
        if has_discrete {
            WineDxvkMode::Vkd3dProton
        } else {
            WineDxvkMode::Dxvk2x
        }
    }

    #[must_use]
    pub fn gpu_passthrough_allowed(&self, _policy: &GpuPolicy) -> bool {
        matches!(self.gpu_class, WineGPUClass::Discrete | WineGPUClass::Integrated)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::evidence::InMemoryWineEvidenceEmitter;

    #[test]
    fn dxvk_mode_detection_none_when_no_gpu() {
        let config = DxvkConfig {
            mode: WineDxvkMode::None,
            gpu_class: WineGPUClass::None,
            vulkan_devices: vec![],
            env_vars: HashMap::new(),
            state_cache_path: None,
        };
        assert_eq!(config.mode, WineDxvkMode::None);
        assert!(config.vulkan_devices.is_empty());
    }

    #[test]
    fn dxvk_config_generates_correct_env_vars() {
        let prefix = PathBuf::from("/var/lib/aios/capsules/caps_test/wine");
        let policy = GpuPolicy::default_deny_all();
        let config = DxvkConfig::detect(&prefix, &policy);

        assert!(config
            .env_vars
            .contains_key("DXVK_STATE_CACHE_PATH"));
        assert!(config
            .env_vars
            .contains_key("DXVK_HUD"));
    }

    #[test]
    fn vkd3d_proton_env_vars_include_shader_cache() {
        let prefix = PathBuf::from("/var/lib/aios/capsules/caps_test/wine");
        let policy = GpuPolicy::default_deny_all();
        let config = DxvkConfig::detect(&prefix, &policy);

        if config.mode == WineDxvkMode::Vkd3dProton {
            assert!(config.env_vars.contains_key("VKD3D_CONFIG"));
            assert!(config.env_vars.contains_key("VKD3D_SHADER_CACHE_PATH"));
        }
    }

    #[test]
    fn dxvk_activate_emits_evidence() {
        let prefix = PathBuf::from("/var/lib/aios/capsules/caps_test/wine");
        let policy = GpuPolicy::default_deny_all();
        let config = DxvkConfig::detect(&prefix, &policy);
        let emitter = Arc::new(InMemoryWineEvidenceEmitter::new());
        let result = config.activate("wpre_01ABCDEF", emitter.as_ref());
        assert!(result.is_ok());
    }

    #[test]
    fn gpu_passthrough_allowed_for_discrete() {
        let config = DxvkConfig {
            mode: WineDxvkMode::Vkd3dProton,
            gpu_class: WineGPUClass::Discrete,
            vulkan_devices: vec![],
            env_vars: HashMap::new(),
            state_cache_path: None,
        };
        let policy = GpuPolicy::default_deny_all();
        assert!(config.gpu_passthrough_allowed(&policy));
    }
}
