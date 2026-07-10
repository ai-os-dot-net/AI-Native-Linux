//! `aios-waydroid` — Waydroid Android App Capsule Adapter (Rev.6).
//!
//! Implements governed Waydroid-based Android application containers under
//! AI-OS.NET sandbox profiles. Covers:
//!
//! - Waydroid container lifecycle management (init, start, stop, suspend)
//! - Android APK installation, launch, and uninstall with state tracking
//! - GPU passthrough configuration (software, host DRI/Vulkan, Vulkan WSI)
//! - Android-specific sandbox profile generation with Binder access
//! - Waydroid desktop entry generation for XDG integration
//! - Evidence emission for all container and app lifecycle transitions
//!
//! Constitutional invariants:
//! - No `unsafe` code
//! - No `unwrap`/`expect`/`panic` outside test blocks
//! - All state transitions emit sealed evidence receipts

#![forbid(unsafe_code)]
#![allow(missing_docs)]

pub mod app_lifecycle;
pub mod container;
pub mod enums;
pub mod error;
pub mod evidence;
pub mod gpu;
pub mod sandbox_profile;

pub use app_lifecycle::{
    generate_desktop_entry, get_app_state, install_apk, launch_app, list_apps, resolve_human_name,
    suspend_app, uninstall_app,
};
pub use container::WaydroidContainer;
pub use enums::{
    AndroidAppSource, AndroidAppState, AndroidGPUClass, WaydroidContainerState,
    WaydroidImageChannel,
};
pub use error::WaydroidError;
pub use evidence::{InMemoryWaydroidEvidenceEmitter, WaydroidEvidenceEmitter};
pub use gpu::{
    build_gpu_config, gpu_class_to_waydroid_mode, resolve_dri_device, resolve_vulkan_device,
    waydroid_gpu_env_vars, WaydroidGpuConfig,
};
pub use sandbox_profile::{
    allow_binder_socket, allow_waydroid_network, allow_waydroid_system_paths, deny_proc_sys_access,
    deny_waydroid_network, generate_waydroid_sandbox_profile, validate_data_path,
};
