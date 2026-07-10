use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::WaydroidError;
use crate::AndroidGPUClass;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaydroidGpuConfig {
    pub gpu_class: AndroidGPUClass,
    pub dri_device: Option<String>,
    pub vulkan_device: Option<String>,
    pub software_rendering: bool,
    pub env_overrides: HashMap<String, String>,
}

impl WaydroidGpuConfig {
    #[must_use]
    pub fn software_rendering() -> Self {
        Self {
            gpu_class: AndroidGPUClass::Software,
            dri_device: None,
            vulkan_device: None,
            software_rendering: true,
            env_overrides: {
                let mut env = HashMap::new();
                env.insert(String::from("LIBGL_ALWAYS_SOFTWARE"), String::from("1"));
                env.insert(String::from("GALLIUM_DRIVER"), String::from("llvmpipe"));
                env
            },
        }
    }

    #[must_use]
    pub fn host_gpu_passthrough(
        dri_device: impl Into<String>,
        vulkan_device: impl Into<String>,
    ) -> Self {
        Self {
            gpu_class: AndroidGPUClass::HostGpuPassthrough,
            dri_device: Some(dri_device.into()),
            vulkan_device: Some(vulkan_device.into()),
            software_rendering: false,
            env_overrides: HashMap::new(),
        }
    }

    #[must_use]
    pub fn vulkan_wsi() -> Self {
        Self {
            gpu_class: AndroidGPUClass::VulkanWsi,
            dri_device: None,
            vulkan_device: None,
            software_rendering: false,
            env_overrides: {
                let mut env = HashMap::new();
                env.insert(String::from("WAYLAND_DISPLAY"), String::from("wayland-0"));
                env
            },
        }
    }
}

pub fn resolve_dri_device() -> Option<String> {
    let candidates = [
        "/dev/dri/renderD128",
        "/dev/dri/renderD129",
        "/dev/dri/card0",
    ];

    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(path.to_string());
        }
    }

    None
}

pub fn resolve_vulkan_device() -> Option<String> {
    let candidates = ["/dev/dri/renderD128", "/dev/dri/renderD129"];

    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(path.to_string());
        }
    }

    None
}

pub fn build_gpu_config(gpu_class: AndroidGPUClass) -> Result<WaydroidGpuConfig, WaydroidError> {
    match gpu_class {
        AndroidGPUClass::Software => Ok(WaydroidGpuConfig::software_rendering()),
        AndroidGPUClass::HostGpuPassthrough => {
            let dri = resolve_dri_device().ok_or_else(|| {
                WaydroidError::gpu_config_failed("no DRI device found for host passthrough")
            })?;
            let vulkan = resolve_vulkan_device().ok_or_else(|| {
                WaydroidError::gpu_config_failed("no Vulkan device found for host passthrough")
            })?;
            Ok(WaydroidGpuConfig::host_gpu_passthrough(dri, vulkan))
        }
        AndroidGPUClass::VulkanWsi => Ok(WaydroidGpuConfig::vulkan_wsi()),
    }
}

pub fn gpu_class_to_waydroid_mode(gpu_class: AndroidGPUClass) -> &'static str {
    match gpu_class {
        AndroidGPUClass::Software => "software",
        AndroidGPUClass::HostGpuPassthrough => "host",
        AndroidGPUClass::VulkanWsi => "vulkan",
    }
}

pub fn waydroid_gpu_env_vars(config: &WaydroidGpuConfig) -> HashMap<String, String> {
    config.env_overrides.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_software_rendering_config() {
        let config = WaydroidGpuConfig::software_rendering();
        assert_eq!(config.gpu_class, AndroidGPUClass::Software);
        assert!(config.software_rendering);
        assert_eq!(
            config.env_overrides.get("LIBGL_ALWAYS_SOFTWARE"),
            Some(&String::from("1"))
        );
        assert_eq!(
            config.env_overrides.get("GALLIUM_DRIVER"),
            Some(&String::from("llvmpipe"))
        );
        assert!(config.dri_device.is_none());
        assert!(config.vulkan_device.is_none());
    }

    #[test]
    fn gpu_host_passthrough_config() {
        let config =
            WaydroidGpuConfig::host_gpu_passthrough("/dev/dri/renderD128", "/dev/dri/renderD128");
        assert_eq!(config.gpu_class, AndroidGPUClass::HostGpuPassthrough);
        assert!(!config.software_rendering);
        assert_eq!(config.dri_device, Some(String::from("/dev/dri/renderD128")));
        assert_eq!(
            config.vulkan_device,
            Some(String::from("/dev/dri/renderD128"))
        );
        assert!(config.env_overrides.is_empty());
    }

    #[test]
    fn gpu_vulkan_wsi_config() {
        let config = WaydroidGpuConfig::vulkan_wsi();
        assert_eq!(config.gpu_class, AndroidGPUClass::VulkanWsi);
        assert!(!config.software_rendering);
        assert_eq!(
            config.env_overrides.get("WAYLAND_DISPLAY"),
            Some(&String::from("wayland-0"))
        );
    }

    #[test]
    fn build_gpu_config_software_returns_software_config() {
        let result = build_gpu_config(AndroidGPUClass::Software);
        assert!(result.is_ok());
        let config = result.expect("build should succeed");
        assert_eq!(config.gpu_class, AndroidGPUClass::Software);
        assert!(config.software_rendering);
    }

    #[test]
    fn build_gpu_config_vulkan_wsi_returns_vulkan_config() {
        let result = build_gpu_config(AndroidGPUClass::VulkanWsi);
        assert!(result.is_ok());
        let config = result.expect("build should succeed");
        assert_eq!(config.gpu_class, AndroidGPUClass::VulkanWsi);
    }

    #[test]
    fn gpu_class_to_waydroid_mode_maps_correctly() {
        assert_eq!(
            gpu_class_to_waydroid_mode(AndroidGPUClass::Software),
            "software"
        );
        assert_eq!(
            gpu_class_to_waydroid_mode(AndroidGPUClass::HostGpuPassthrough),
            "host"
        );
        assert_eq!(
            gpu_class_to_waydroid_mode(AndroidGPUClass::VulkanWsi),
            "vulkan"
        );
    }

    #[test]
    fn waydroid_gpu_env_vars_returns_clone() {
        let config = WaydroidGpuConfig::software_rendering();
        let env = waydroid_gpu_env_vars(&config);
        assert_eq!(env.len(), 2);
        assert_eq!(env.get("LIBGL_ALWAYS_SOFTWARE"), Some(&String::from("1")));
        assert_eq!(env.get("GALLIUM_DRIVER"), Some(&String::from("llvmpipe")));
    }
}
