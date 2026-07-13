//! Integration tests for the `aios-waydroid` capsule adapter — governance.
//!
//! These exercise the **public** API of the Waydroid Android capsule through a
//! full state-machine lifecycle (start → install-apk → launch → suspend-app →
//! stop), assert that a sealed evidence receipt is emitted on container
//! transitions, cover error paths (invalid transition, missing app, double
//! install), and verify the GPU passthrough config builders.
//!
//! Evidence grade: these prove **E3** (governance logic tested). They do NOT
//! invoke the real `waydroid` binary — see `real_exec.rs` for the guarded
//! real-invocation seam, which is E4-pending on the target image.

use std::path::PathBuf;
use std::sync::Arc;

use aios_waydroid::{
    build_gpu_config, get_app_state, gpu_class_to_waydroid_mode, install_apk, launch_app,
    list_apps, suspend_app, uninstall_app, waydroid_gpu_env_vars, AndroidAppState, AndroidGPUClass,
    InMemoryWaydroidEvidenceEmitter, WaydroidContainer, WaydroidContainerState, WaydroidError,
    WaydroidGpuConfig,
};
use ulid::Ulid;

fn running_container_with_emitter() -> (WaydroidContainer, Arc<InMemoryWaydroidEvidenceEmitter>) {
    let capsule_id = Ulid::new();
    let ev = Arc::new(InMemoryWaydroidEvidenceEmitter::new());
    let mut c = WaydroidContainer::new_with_emitter(capsule_id, ev.clone()).expect("new container");
    // Keep the modeled data path out of the real filesystem's way.
    c.data_path = PathBuf::from(format!("/var/lib/aios/waydroid/{capsule_id}/"));
    (c, ev)
}

fn receipts(ev: &InMemoryWaydroidEvidenceEmitter) -> usize {
    ev.chain
        .lock()
        .expect("evidence chain lock")
        .receipts()
        .len()
}

#[test]
fn full_lifecycle_start_install_launch_suspend_stop() {
    let (mut c, ev) = running_container_with_emitter();

    // start (Stopped -> Running), emits evidence
    assert_eq!(c.container_state, WaydroidContainerState::Stopped);
    c.start().expect("start");
    assert_eq!(c.container_state, WaydroidContainerState::Running);
    assert_eq!(receipts(&ev), 1, "start emits a receipt");

    // install apk
    install_apk(&mut c, &PathBuf::from("/tmp/app.apk"), "com.example.app").expect("install");
    assert_eq!(
        get_app_state(&c, "com.example.app"),
        Some(AndroidAppState::Installed)
    );

    // launch (Installed -> Running)
    launch_app(&mut c, "com.example.app").expect("launch");
    assert_eq!(
        get_app_state(&c, "com.example.app"),
        Some(AndroidAppState::Running)
    );

    // suspend app (Running -> Suspended)
    suspend_app(&mut c, "com.example.app").expect("suspend");
    assert_eq!(
        get_app_state(&c, "com.example.app"),
        Some(AndroidAppState::Suspended)
    );

    // uninstall
    uninstall_app(&mut c, "com.example.app").expect("uninstall");
    assert_eq!(
        get_app_state(&c, "com.example.app"),
        Some(AndroidAppState::Uninstalled)
    );

    // stop (Running -> Stopped), emits evidence
    c.stop().expect("stop");
    assert_eq!(c.container_state, WaydroidContainerState::Stopped);
    assert_eq!(receipts(&ev), 2, "stop emits a receipt");
}

#[test]
fn container_suspend_resume_cycle_emits_start_evidence() {
    let (mut c, ev) = running_container_with_emitter();
    c.start().expect("start");
    c.suspend().expect("suspend");
    assert_eq!(c.container_state, WaydroidContainerState::Suspended);
    c.start().expect("resume from suspended");
    assert_eq!(c.container_state, WaydroidContainerState::Running);
    // start emitted twice (initial + resume); suspend does not emit.
    assert_eq!(receipts(&ev), 2);
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
fn stop_from_stopped_is_rejected() {
    let (mut c, _ev) = running_container_with_emitter();
    let err = c.stop().expect_err("stop while stopped must fail");
    assert!(matches!(err, WaydroidError::InvalidStateTransition { .. }));
}

#[test]
fn start_twice_is_rejected() {
    let (mut c, _ev) = running_container_with_emitter();
    c.start().expect("start");
    let err = c.start().expect_err("start while running must fail");
    assert!(matches!(err, WaydroidError::AlreadyRunning { .. }));
}

#[test]
fn install_apk_when_not_running_is_rejected() {
    let (mut c, _ev) = running_container_with_emitter();
    // still Stopped
    let err = install_apk(&mut c, &PathBuf::from("/tmp/x.apk"), "com.x")
        .expect_err("install while stopped must fail");
    assert!(matches!(err, WaydroidError::ContainerInitFailed { .. }));
}

#[test]
fn double_install_is_rejected() {
    let (mut c, _ev) = running_container_with_emitter();
    c.start().expect("start");
    install_apk(&mut c, &PathBuf::from("/tmp/x.apk"), "com.x").expect("install once");
    let err = install_apk(&mut c, &PathBuf::from("/tmp/x.apk"), "com.x")
        .expect_err("double install must fail");
    assert!(matches!(err, WaydroidError::ApkInstallFailed { .. }));
}

#[test]
fn launch_missing_app_is_rejected() {
    let (mut c, _ev) = running_container_with_emitter();
    c.start().expect("start");
    let err = launch_app(&mut c, "com.missing").expect_err("launch missing must fail");
    assert!(matches!(err, WaydroidError::AppNotFound { .. }));
}

#[test]
fn uninstall_missing_app_is_rejected() {
    let (mut c, _ev) = running_container_with_emitter();
    c.start().expect("start");
    let err = uninstall_app(&mut c, "com.missing").expect_err("uninstall missing must fail");
    assert!(matches!(err, WaydroidError::AppNotFound { .. }));
}

// ---------------------------------------------------------------------------
// GPU / passthrough config builders
// ---------------------------------------------------------------------------

#[test]
fn gpu_software_config_is_deterministic() {
    let cfg = build_gpu_config(AndroidGPUClass::Software).expect("software config");
    assert_eq!(cfg.gpu_class, AndroidGPUClass::Software);
    assert!(cfg.software_rendering);
    let env = waydroid_gpu_env_vars(&cfg);
    assert_eq!(env.get("LIBGL_ALWAYS_SOFTWARE"), Some(&String::from("1")));
    assert_eq!(
        gpu_class_to_waydroid_mode(AndroidGPUClass::Software),
        "software"
    );
}

#[test]
fn gpu_vulkan_wsi_config_builds() {
    let cfg = build_gpu_config(AndroidGPUClass::VulkanWsi).expect("vulkan config");
    assert_eq!(cfg.gpu_class, AndroidGPUClass::VulkanWsi);
    assert!(!cfg.software_rendering);
    assert_eq!(
        gpu_class_to_waydroid_mode(AndroidGPUClass::VulkanWsi),
        "vulkan"
    );
}

#[test]
fn gpu_host_passthrough_direct_construction() {
    // build_gpu_config(HostGpuPassthrough) depends on real /dev/dri devices,
    // so exercise the direct builder to keep the test host-independent.
    let cfg = WaydroidGpuConfig::host_gpu_passthrough("/dev/dri/renderD128", "/dev/dri/renderD128");
    assert_eq!(cfg.gpu_class, AndroidGPUClass::HostGpuPassthrough);
    assert_eq!(cfg.dri_device.as_deref(), Some("/dev/dri/renderD128"));
    assert_eq!(
        gpu_class_to_waydroid_mode(AndroidGPUClass::HostGpuPassthrough),
        "host"
    );
}

#[test]
fn list_apps_reflects_installed_set() {
    let (mut c, _ev) = running_container_with_emitter();
    c.start().expect("start");
    install_apk(&mut c, &PathBuf::from("/tmp/a.apk"), "com.a").expect("install a");
    install_apk(&mut c, &PathBuf::from("/tmp/b.apk"), "com.b").expect("install b");
    let apps = list_apps(&c);
    assert_eq!(apps.len(), 2);
    assert!(apps
        .iter()
        .any(|(n, s)| n == "com.a" && *s == AndroidAppState::Installed));
}
