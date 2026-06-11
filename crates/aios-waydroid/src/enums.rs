use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WaydroidContainerState {
    Stopped,
    Starting,
    Running,
    Suspended,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AndroidAppState {
    Installing,
    Installed,
    Running,
    Suspended,
    Uninstalled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AndroidAppSource {
    ApkFile,
    FdroidRepo,
    AuroraStore,
    PlayStoreOffline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AndroidGPUClass {
    Software,
    HostGpuPassthrough,
    VulkanWsi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WaydroidImageChannel {
    LineageOs,
    AospVanilla,
    BlissOs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waydroid_container_state_serializes_as_screaming_snake_case() {
        let v = serde_json::to_string(&WaydroidContainerState::Running).expect("serialize");
        assert_eq!(v, r#""RUNNING""#);
    }

    #[test]
    fn waydroid_container_state_all_variants_round_trip() {
        for variant in &[
            WaydroidContainerState::Stopped,
            WaydroidContainerState::Starting,
            WaydroidContainerState::Running,
            WaydroidContainerState::Suspended,
            WaydroidContainerState::Failed,
        ] {
            let s = serde_json::to_string(variant).expect("serialize");
            let back: WaydroidContainerState = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn android_app_state_serializes_as_screaming_snake_case() {
        let v = serde_json::to_string(&AndroidAppState::Installed).expect("serialize");
        assert_eq!(v, r#""INSTALLED""#);
    }

    #[test]
    fn android_app_state_all_variants_round_trip() {
        for variant in &[
            AndroidAppState::Installing,
            AndroidAppState::Installed,
            AndroidAppState::Running,
            AndroidAppState::Suspended,
            AndroidAppState::Uninstalled,
            AndroidAppState::Failed,
        ] {
            let s = serde_json::to_string(variant).expect("serialize");
            let back: AndroidAppState = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn android_app_source_all_variants_round_trip() {
        for variant in &[
            AndroidAppSource::ApkFile,
            AndroidAppSource::FdroidRepo,
            AndroidAppSource::AuroraStore,
            AndroidAppSource::PlayStoreOffline,
        ] {
            let s = serde_json::to_string(variant).expect("serialize");
            let back: AndroidAppSource = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn android_gpu_class_all_variants_round_trip() {
        for variant in &[
            AndroidGPUClass::Software,
            AndroidGPUClass::HostGpuPassthrough,
            AndroidGPUClass::VulkanWsi,
        ] {
            let s = serde_json::to_string(variant).expect("serialize");
            let back: AndroidGPUClass = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn waydroid_image_channel_all_variants_round_trip() {
        for variant in &[
            WaydroidImageChannel::LineageOs,
            WaydroidImageChannel::AospVanilla,
            WaydroidImageChannel::BlissOs,
        ] {
            let s = serde_json::to_string(variant).expect("serialize");
            let back: WaydroidImageChannel = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn software_gpu_class_serializes_correctly() {
        let v = serde_json::to_string(&AndroidGPUClass::Software).expect("serialize");
        assert_eq!(v, r#""SOFTWARE""#);
    }

    #[test]
    fn host_gpu_passthrough_serializes_correctly() {
        let v = serde_json::to_string(&AndroidGPUClass::HostGpuPassthrough).expect("serialize");
        assert_eq!(v, r#""HOST_GPU_PASSTHROUGH""#);
    }
}
