//! `aios-wine` — Wine/Proton Windows App Capsule Driver (Rev.6).
//!
//! Implements governed Wine/Proton capsules for running Windows applications
//! under AI-OS.NET sandbox profiles. Covers:
//!
//! - Wine prefix lifecycle management (create, install, run, suspend, destroy)
//! - DXVK / VKD3D-Proton GPU passthrough with Vulkan device enumeration
//! - Steam Proton capsule adapter with version auto-detection
//! - EXE/MSI installer capture in isolated prefixes
//! - Wine-specific sandbox profile generation with AppArmor integration
//! - Evidence emission for all state transitions
//!
//! Constitutional invariants:
//! - No `unsafe` code
//! - No `unwrap`/`expect`/`panic` outside test blocks
//! - All state transitions emit sealed evidence receipts

#![forbid(unsafe_code)]
#![allow(missing_docs)]

pub mod dxvk;
pub mod enums;
pub mod error;
pub mod evidence;
pub mod installer;
pub mod prefix;
pub mod sandbox_profile;
pub mod steam_proton;

pub use dxvk::{DxvkConfig, VulkanDevice, VulkanDeviceType};
pub use enums::{
    CapsuleWineAppState, WineAppCompatibility, WineAppSource, WineDxvkMode, WineGPUClass,
    WinePrefixState,
};
pub use error::WineError;
pub use evidence::{InMemoryWineEvidenceEmitter, WineEvidenceEmitter};
pub use installer::{
    capture_installer, generate_desktop_entry, record_app_manifest, DesktopEntry, InstallerConfig,
};
pub use prefix::{WineAppManifest, WineArchitecture, WinePrefixManager};
pub use sandbox_profile::{
    allow_wine_system_paths, deny_proc_sys, generate_wine_sandbox_profile, validate_prefix_path,
};
pub use steam_proton::{ProtonAppMapping, ProtonVersion, SteamProtonAdapter};
