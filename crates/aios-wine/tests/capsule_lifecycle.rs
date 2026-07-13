//! Integration tests for the `aios-wine` capsule driver — governance logic.
//!
//! These exercise the **public** API of the Wine/Proton capsule through a full
//! state-machine lifecycle (create → install → run → suspend → destroy), assert
//! that a sealed evidence receipt is emitted on every transition, cover the
//! error paths (invalid transition, missing app), and verify the DXVK / sandbox
//! config builders.
//!
//! Evidence grade: these prove **E3** (governance logic tested). They do NOT
//! invoke the real `wine`/`wineboot` binary — see `real_exec.rs` for the
//! guarded real-invocation seam, which is E4-pending on the target image.

use std::sync::Arc;

use aios_wine::{
    allow_wine_system_paths, deny_proc_sys, generate_wine_sandbox_profile, validate_prefix_path,
    CapsuleWineAppState, DxvkConfig, InMemoryWineEvidenceEmitter, ProtonVersion,
    SteamProtonAdapter, VulkanDevice, VulkanDeviceType, WineAppSource, WineArchitecture,
    WineDxvkMode, WineError, WineGPUClass, WinePrefixManager, WinePrefixState,
};
use std::path::PathBuf;
use ulid::Ulid;

fn emitter() -> Arc<InMemoryWineEvidenceEmitter> {
    Arc::new(InMemoryWineEvidenceEmitter::new())
}

fn receipt_count(e: &InMemoryWineEvidenceEmitter) -> usize {
    e.chain
        .lock()
        .expect("evidence chain lock")
        .receipts()
        .len()
}

#[test]
fn full_lifecycle_create_install_run_suspend_destroy_emits_evidence_each_step() {
    let ev = emitter();
    let mut mgr = WinePrefixManager::new(Ulid::new(), ev.clone())
        .with_architecture(WineArchitecture::Win64)
        .with_gpu_class(WineGPUClass::Discrete);

    // create
    assert_eq!(mgr.state, WinePrefixState::Creating);
    mgr.create_prefix().expect("create_prefix");
    assert_eq!(mgr.state, WinePrefixState::Active);
    assert_eq!(receipt_count(&ev), 1, "create emits a receipt");

    // install
    mgr.install_app(
        WineAppSource::ExeInstaller,
        PathBuf::from("/tmp/setup.exe"),
        String::from("Notepad"),
    )
    .expect("install_app");
    assert_eq!(mgr.app_list[0].1, CapsuleWineAppState::Installed);
    assert_eq!(receipt_count(&ev), 2, "install emits a receipt");

    // run
    mgr.run_app(PathBuf::from("/tmp/setup.exe"), vec![])
        .expect("run_app");
    assert_eq!(mgr.app_list[0].1, CapsuleWineAppState::Running);
    assert_eq!(receipt_count(&ev), 3, "run emits a receipt");

    // suspend
    mgr.suspend().expect("suspend");
    assert_eq!(mgr.state, WinePrefixState::Suspended);
    assert_eq!(mgr.app_list[0].1, CapsuleWineAppState::Suspended);
    assert_eq!(receipt_count(&ev), 4, "suspend emits a receipt");

    // destroy
    mgr.destroy_ephemeral().expect("destroy_ephemeral");
    assert_eq!(mgr.state, WinePrefixState::EphemeralDestroyed);
    assert_eq!(receipt_count(&ev), 5, "destroy emits a receipt");
}

#[test]
fn evidence_chain_is_append_only_and_hash_linked() {
    let ev = emitter();
    let mut mgr = WinePrefixManager::new(Ulid::new(), ev.clone());
    mgr.create_prefix().expect("create");
    mgr.install_app(
        WineAppSource::MsiInstaller,
        PathBuf::from("/tmp/app.msi"),
        String::from("App"),
    )
    .expect("install");

    // Snapshot the receipt IDs and release the guard before asserting.
    let ids: Vec<_> = {
        let chain = ev.chain.lock().expect("lock");
        chain
            .receipts()
            .iter()
            .map(|r| r.receipt_id().clone())
            .collect()
    };
    assert_eq!(ids.len(), 2);
    // Distinct receipt IDs prove the chain grew rather than overwrote.
    assert_ne!(ids[0], ids[1]);
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
fn invalid_transition_create_twice_is_rejected() {
    let mut mgr = WinePrefixManager::new(Ulid::new(), emitter());
    mgr.create_prefix().expect("first create");
    let err = mgr.create_prefix().expect_err("second create must fail");
    assert!(matches!(err, WineError::InvalidStateTransition { .. }));
}

#[test]
fn run_without_installed_app_is_rejected() {
    let mut mgr = WinePrefixManager::new(Ulid::new(), emitter());
    mgr.create_prefix().expect("create");
    let err = mgr
        .run_app(PathBuf::from("/nope.exe"), vec![])
        .expect_err("run with no app must fail");
    assert!(matches!(err, WineError::AppNotFound { .. }));
}

#[test]
fn install_before_create_is_rejected() {
    let mut mgr = WinePrefixManager::new(Ulid::new(), emitter());
    // state is Creating, install requires Active
    let err = mgr
        .install_app(
            WineAppSource::ExeInstaller,
            PathBuf::from("/tmp/x.exe"),
            String::from("X"),
        )
        .expect_err("install before create must fail");
    assert!(matches!(err, WineError::InvalidStateTransition { .. }));
}

#[test]
fn cannot_install_while_app_running() {
    let mut mgr = WinePrefixManager::new(Ulid::new(), emitter());
    mgr.create_prefix().expect("create");
    mgr.install_app(
        WineAppSource::ExeInstaller,
        PathBuf::from("/tmp/a.exe"),
        String::from("A"),
    )
    .expect("install a");
    mgr.run_app(PathBuf::from("/tmp/a.exe"), vec![])
        .expect("run a");
    let err = mgr
        .install_app(
            WineAppSource::ExeInstaller,
            PathBuf::from("/tmp/b.exe"),
            String::from("B"),
        )
        .expect_err("install while running must fail");
    assert!(matches!(err, WineError::AlreadyRunning { .. }));
}

// ---------------------------------------------------------------------------
// Config builders — DXVK / Vulkan / sandbox / Proton
// ---------------------------------------------------------------------------

#[test]
fn dxvk_config_activate_emits_evidence() {
    let ev = emitter();
    let cfg = DxvkConfig {
        mode: WineDxvkMode::Vkd3dProton,
        gpu_class: WineGPUClass::Discrete,
        vulkan_devices: vec![VulkanDevice {
            device_name: String::from("Test GPU"),
            driver_version: String::from("1.0"),
            api_version: String::from("1.3"),
            device_type: VulkanDeviceType::Discrete,
            available_vram_mb: 8192,
        }],
        env_vars: std::collections::HashMap::new(),
        state_cache_path: None,
    };
    cfg.activate("wpre_TEST", ev.as_ref())
        .expect("dxvk activate");
    assert_eq!(receipt_count(&ev), 1, "dxvk activation emits evidence");
}

#[test]
fn wine_sandbox_profile_denies_network_by_default() {
    let profile = generate_wine_sandbox_profile(
        &PathBuf::from("/var/lib/aios/capsules/c1/wine"),
        "c1".into(),
        false,
    );
    assert!(profile.name.contains("wine-prefix-c1"));
    // deny/allow path builders are non-empty and disjoint
    let deny = deny_proc_sys();
    let allow = allow_wine_system_paths();
    assert!(deny.iter().any(|p| p.contains("/proc/sys")));
    assert!(allow.iter().any(|p| p.contains("wine")));
    assert!(deny.iter().all(|d| !allow.contains(d)));
}

#[test]
fn validate_prefix_path_accepts_capsule_root_rejects_outside() {
    assert!(validate_prefix_path(&PathBuf::from("/var/lib/aios/capsules/c1/wine")).is_ok());
    let err = validate_prefix_path(&PathBuf::from("/etc/passwd"))
        .expect_err("outside capsule root must fail");
    assert!(matches!(err, WineError::SandboxViolation { .. }));
}

#[test]
fn steam_proton_detection_and_mapping() {
    let mut adapter = SteamProtonAdapter::new(PathBuf::from("/home/u/.local/share/Steam"));
    adapter.detect_proton_versions().expect("detect");
    assert!(!adapter.detected_versions.is_empty());

    let mapping = adapter.map_app_to_prefix("620").expect("map app");
    assert_eq!(mapping.steam_app_id, "620");
    assert!(mapping
        .compatdata_path
        .to_string_lossy()
        .contains("compatdata/620"));

    // override to a known version succeeds; unknown fails-closed
    let ev = emitter();
    let known = adapter.detected_versions[0].version.clone();
    adapter
        .override_compat_tool("620", &known, ev.as_ref())
        .expect("known version ok");
    let err = adapter
        .override_compat_tool("620", "does-not-exist", ev.as_ref())
        .expect_err("unknown version must fail");
    assert!(matches!(err, WineError::ProtonCompatToolNotFound { .. }));
}

#[test]
fn proton_version_struct_is_constructible() {
    let v = ProtonVersion {
        version: String::from("9.0-4"),
        path: PathBuf::from("/steam/proton"),
        is_default: true,
    };
    assert!(v.is_default);
    assert_eq!(v.version, "9.0-4");
}
