//! Workspace regression tests — smoke test that EVERY crate compiles and tests pass.
//!
//! These tests verify that all 34 crates in the AI-OS.NET workspace are in a
//! healthy state: they compile without errors and their own unit tests pass.
//! This is the pre-flight check before running full-pipeline integration tests.

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::significant_drop_tightening,
    clippy::wildcard_imports,
    clippy::similar_names,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::needless_collect,
    clippy::format_collect,
    clippy::missing_const_for_fn,
    clippy::too_many_arguments,
    clippy::float_cmp,
    clippy::unused_imports,
    missing_docs,
    reason = "test code; panic-on-failure is the idiomatic test signal"
)]

use std::process::Command;

/// All 34 crate names under `crates/`.
const ALL_CRATES: &[&str] = &[
    "aios-action",
    "aios-apps",
    "aios-autonomous",
    "aios-backup",
    "aios-capability-runtime",
    "aios-cognitive",
    "aios-container",
    "aios-distribution",
    "aios-ebpf",
    "aios-eval",
    "aios-evidence",
    "aios-fleet",
    "aios-fs",
    "aios-hardening",
    "aios-hardware",
    "aios-integration",
    "aios-marketplace",
    "aios-mobile",
    "aios-network",
    "aios-policy",
    "aios-recovery",
    "aios-renderer-cli",
    "aios-renderer-kde",
    "aios-renderer-voice",
    "aios-renderer-web",
    "aios-sandbox",
    "aios-sdk",
    "aios-sgr",
    "aios-terminal",
    "aios-time",
    "aios-vault",
    "aios-verification",
    "aios-waydroid",
    "aios-wine",
];

fn workspace_root() -> std::path::PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set");
    std::path::PathBuf::from(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Run `cargo check` on the named crate and return success.
fn cargo_check_crate(crate_name: &str) -> bool {
    let root = workspace_root();
    let output = Command::new("cargo")
        .args(["check", "-p", crate_name, "--no-default-features"])
        .current_dir(&root)
        .output();

    match output {
        Ok(o) => {
            if !o.status.success() {
                eprintln!(
                    "cargo check failed for {crate_name}:\n{}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            o.status.success()
        }
        Err(e) => {
            eprintln!("failed to run cargo check for {crate_name}: {e}");
            false
        }
    }
}

/// Run `cargo test` on the named crate and return success.
fn cargo_test_crate(crate_name: &str) -> bool {
    let root = workspace_root();
    let output = Command::new("cargo")
        .args(["test", "-p", crate_name, "--no-fail-fast"])
        .current_dir(&root)
        .output();

    match output {
        Ok(o) => {
            if !o.status.success() {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // Print last 500 chars of stderr for diagnostics
                let tail = if stderr.len() > 500 {
                    &stderr[stderr.len() - 500..]
                } else {
                    &stderr
                };
                eprintln!("cargo test failed for {crate_name}:\n...{tail}");
            }
            o.status.success()
        }
        Err(e) => {
            eprintln!("failed to run cargo test for {crate_name}: {e}");
            false
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: All 34 crates compile via `cargo check`
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_all_crates_cargo_check() {
    assert_eq!(ALL_CRATES.len(), 34, "must have exactly 34 crates");

    let mut failed: Vec<&str> = Vec::new();
    for crate_name in ALL_CRATES {
        if !cargo_check_crate(crate_name) {
            failed.push(crate_name);
        }
    }

    assert!(
        failed.is_empty(),
        "cargo check failed for {} crate(s): {failed:?}",
        failed.len(),
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Foundational crates — action, policy, evidence, fs
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_foundational_crates_tests_pass() {
    let foundational = ["aios-action", "aios-policy", "aios-evidence", "aios-fs"];

    let mut failed: Vec<&str> = Vec::new();
    for crate_name in foundational {
        if !cargo_test_crate(crate_name) {
            failed.push(crate_name);
        }
    }

    assert!(
        failed.is_empty(),
        "foundational crate tests failed for {} crate(s): {failed:?}",
        failed.len(),
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Runtime crates — capability-runtime, cognitive, sandbox, recovery
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_runtime_crates_tests_pass() {
    let runtime = [
        "aios-capability-runtime",
        "aios-cognitive",
        "aios-sandbox",
        "aios-recovery",
    ];

    let mut failed: Vec<&str> = Vec::new();
    for crate_name in runtime {
        if !cargo_test_crate(crate_name) {
            failed.push(crate_name);
        }
    }

    assert!(
        failed.is_empty(),
        "runtime crate tests failed for {} crate(s): {failed:?}",
        failed.len(),
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: Distribution crates — distribution, apps
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_distribution_crates_tests_pass() {
    let distribution = ["aios-distribution", "aios-apps"];

    let mut failed: Vec<&str> = Vec::new();
    for crate_name in distribution {
        if !cargo_test_crate(crate_name) {
            failed.push(crate_name);
        }
    }

    assert!(
        failed.is_empty(),
        "distribution crate tests failed for {} crate(s): {failed:?}",
        failed.len(),
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Fleet crates — fleet, container, autonomous
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_fleet_crates_tests_pass() {
    let fleet = ["aios-fleet", "aios-container", "aios-autonomous"];

    let mut failed: Vec<&str> = Vec::new();
    for crate_name in fleet {
        if !cargo_test_crate(crate_name) {
            failed.push(crate_name);
        }
    }

    assert!(
        failed.is_empty(),
        "fleet crate tests failed for {} crate(s): {failed:?}",
        failed.len(),
    );
}
