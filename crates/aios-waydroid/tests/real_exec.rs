//! Integration test for the **guarded real-binary** Waydroid seam.
//!
//! [`WaydroidContainer::init_container_real`] invokes the real `waydroid
//! status` + `waydroid session start` host binary **only when it is detected on
//! `$PATH`**. This test handles both realities honestly:
//!
//! - Binary **absent** (the usual CI / dev host): the method must NOT fake
//!   success — it returns `WaydroidError::WaydroidNotFound`, leaves the
//!   container `Stopped`, and still emits an evidence receipt describing the
//!   unavailability. This proves the **E3** governance behavior of the seam.
//! - Binary **present** (a QEMU image that ships Waydroid + binder): the method
//!   actually brings the session up and transitions the container to `Running`.
//!   That is the **E4** path; it is exercised here only when detected.

use std::sync::Arc;

use aios_waydroid::{
    InMemoryWaydroidEvidenceEmitter, WaydroidContainer, WaydroidContainerState, WaydroidError,
};
use ulid::Ulid;

/// Detect whether the `waydroid` binary is present, using the same `which`
/// probe the driver uses internally.
async fn waydroid_present() -> bool {
    tokio::process::Command::new("which")
        .arg("waydroid")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn init_container_real_is_honest_about_binary_presence() {
    let ev = Arc::new(InMemoryWaydroidEvidenceEmitter::new());
    let mut c =
        WaydroidContainer::new_with_emitter(Ulid::new(), ev.clone()).expect("new container");

    let result = c.init_container_real().await;

    if waydroid_present().await {
        // E4 path: real waydroid ran. Success => Running; failure => a typed
        // CommandFailed error (e.g. no binder module). Never a panic, never a
        // fake success.
        match result {
            Ok(()) => assert_eq!(
                c.container_state,
                WaydroidContainerState::Running,
                "real init success must transition to Running"
            ),
            Err(WaydroidError::CommandFailed(_)) => {
                eprintln!("waydroid present but session start failed (typed error) — acceptable");
            }
            Err(other) => panic!("unexpected error variant from real init: {other}"),
        }
    } else {
        // E3 path (host without Waydroid): honest not-available state, no fake
        // success, no state mutation, but evidence still emitted.
        let err = result.expect_err("no waydroid on PATH must yield an error, not fake success");
        assert!(
            matches!(err, WaydroidError::WaydroidNotFound(_)),
            "absent binary must map to WaydroidNotFound, got {err}"
        );
        assert_eq!(
            c.container_state,
            WaydroidContainerState::Stopped,
            "no state change when binary absent"
        );
        let receipts = ev.chain.lock().expect("lock").receipts().len();
        assert_eq!(
            receipts, 1,
            "unavailability path still emits exactly one evidence receipt"
        );
    }
}
