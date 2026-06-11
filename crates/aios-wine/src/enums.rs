use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WinePrefixState {
    Creating,
    Active,
    Suspended,
    Corrupted,
    EphemeralDestroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WineDxvkMode {
    None,
    Dxvk2x,
    Vkd3dProton,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WineAppSource {
    ExeInstaller,
    MsiInstaller,
    SteamProton,
    LutrisScript,
    GogOffline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WineAppCompatibility {
    Gold,
    Silver,
    Bronze,
    Garbage,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WineGPUClass {
    Integrated,
    Discrete,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapsuleWineAppState {
    Installing,
    Installed,
    Running,
    Suspended,
    Uninstalled,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wine_prefix_state_serializes_as_screaming_snake_case() {
        let v = serde_json::to_string(&WinePrefixState::Active).expect("serialize");
        assert_eq!(v, r#""ACTIVE""#);
    }

    #[test]
    fn wine_dxvk_mode_serializes_as_screaming_snake_case() {
        let v = serde_json::to_string(&WineDxvkMode::Vkd3dProton).expect("serialize");
        assert_eq!(v, r#""VKD3D_PROTON""#);
    }

    #[test]
    fn wine_app_source_round_trips() {
        for variant in &[
            WineAppSource::ExeInstaller,
            WineAppSource::MsiInstaller,
            WineAppSource::SteamProton,
            WineAppSource::LutrisScript,
            WineAppSource::GogOffline,
        ] {
            let s = serde_json::to_string(variant).expect("serialize");
            let back: WineAppSource = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn wine_app_compatibility_round_trips() {
        for variant in &[
            WineAppCompatibility::Gold,
            WineAppCompatibility::Silver,
            WineAppCompatibility::Bronze,
            WineAppCompatibility::Garbage,
            WineAppCompatibility::Unknown,
        ] {
            let s = serde_json::to_string(variant).expect("serialize");
            let back: WineAppCompatibility = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn capsule_wine_app_state_transitions() {
        let states = [
            CapsuleWineAppState::Installing,
            CapsuleWineAppState::Installed,
            CapsuleWineAppState::Running,
            CapsuleWineAppState::Suspended,
            CapsuleWineAppState::Uninstalled,
            CapsuleWineAppState::Failed,
        ];
        for &state in &states {
            let s = serde_json::to_string(&state).expect("serialize");
            let back: CapsuleWineAppState = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(state, back);
        }
    }

    #[test]
    fn gpu_class_none_serializes_correctly() {
        let v = serde_json::to_string(&WineGPUClass::None).expect("serialize");
        assert_eq!(v, r#""NONE""#);
    }
}
