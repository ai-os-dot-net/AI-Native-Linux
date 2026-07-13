//! Integration test for the **guarded real-binary** Wine seam.
//!
//! [`WinePrefixManager::create_prefix_real`] invokes the real
//! `wineboot --init` (or `wine wineboot --init`) host binary **only when it is
//! detected on `$PATH`**. This test handles both realities honestly:
//!
//! - Binary **absent** (the usual CI / dev host): the method must NOT fake
//!   success — it returns `WineError::WineNotFound`, leaves the prefix in
//!   `Creating`, and still emits an evidence receipt describing the
//!   unavailability. This proves the **E3** governance behavior of the seam.
//! - Binary **present** (a QEMU image that ships Wine): the method actually
//!   boots the prefix and transitions it to `Active`. That is the **E4** path;
//!   it is exercised here only when the binary is detected.

use std::sync::Arc;

use aios_wine::{InMemoryWineEvidenceEmitter, WineError, WinePrefixManager, WinePrefixState};
use ulid::Ulid;

/// Detect whether a Wine binary is present, using the same `which`-probe the
/// driver uses internally. Keeps the test's expectation aligned with the code.
async fn wine_present() -> bool {
    for bin in ["wineboot", "wine"] {
        let ok = tokio::process::Command::new("which")
            .arg(bin)
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return true;
        }
    }
    false
}

#[tokio::test]
async fn create_prefix_real_is_honest_about_binary_presence() {
    let ev = Arc::new(InMemoryWineEvidenceEmitter::new());
    let mut mgr = WinePrefixManager::new(Ulid::new(), ev.clone());

    let result = mgr.create_prefix_real().await;

    if wine_present().await {
        // E4 path: real wineboot ran. It should either succeed (prefix Active)
        // or fail with a typed prefix-creation error — never panic, never a
        // fake success while leaving state inconsistent.
        match result {
            Ok(()) => assert_eq!(
                mgr.state,
                WinePrefixState::Active,
                "real init success must transition to Active"
            ),
            Err(WineError::PrefixCreationFailed { .. }) => {
                eprintln!("wine present but wineboot --init failed (typed error) — acceptable");
            }
            Err(other) => panic!("unexpected error variant from real init: {other}"),
        }
    } else {
        // E3 path (host without Wine): honest not-available state, no fake
        // success, no state mutation, but evidence still emitted.
        let err = result.expect_err("no wine on PATH must yield an error, not fake success");
        assert!(
            matches!(err, WineError::WineNotFound(_)),
            "absent binary must map to WineNotFound, got {err}"
        );
        assert_eq!(
            mgr.state,
            WinePrefixState::Creating,
            "no state change when binary absent"
        );
        let receipts = ev.chain.lock().expect("lock").receipts().len();
        assert_eq!(
            receipts, 1,
            "unavailability path still emits exactly one evidence receipt"
        );
    }
}

#[tokio::test]
async fn create_prefix_real_rejects_non_creating_state() {
    // Drive the prefix to Active via the modeled (non-real) path first, then
    // assert the real seam refuses to re-init an already-active prefix.
    let ev = Arc::new(InMemoryWineEvidenceEmitter::new());
    let mut mgr = WinePrefixManager::new(Ulid::new(), ev);
    mgr.create_prefix().expect("modeled create");
    assert_eq!(mgr.state, WinePrefixState::Active);

    let err = mgr
        .create_prefix_real()
        .await
        .expect_err("real init on Active prefix must fail");
    assert!(matches!(err, WineError::InvalidStateTransition { .. }));
}
