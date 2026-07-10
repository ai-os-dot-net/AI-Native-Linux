#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    missing_docs,
    reason = "test code"
)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

const BIN_NAME: &str = "aios-system";

fn binary() -> Command {
    Command::cargo_bin(BIN_NAME).unwrap()
}

fn unique_state_dir() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("aios-system-test-{nonce}"))
}

#[test]
fn aios_system_help_succeeds() {
    binary()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("AIOS system orchestrator"));
}

#[test]
fn aios_system_boot_prints_aios_action_first() {
    binary()
        .arg("boot")
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "[0] aios-action (crate=aios-action, endpoint=unix:/run/aios/aios-action.sock)\n",
        ));
}

#[test]
fn aios_system_boot_prints_17_lines() {
    let output = binary().arg("boot").assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let boot_lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        boot_lines.len(),
        17,
        "expected 17 boot lines, got {}:\n{stdout}",
        boot_lines.len()
    );
}

#[test]
fn aios_system_topo_emits_topological_order() {
    binary()
        .arg("topo")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("aios-action\n"));
}

#[test]
fn aios_system_services_lists_17_entries() {
    let output = binary().arg("services").assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    // Lines after the header line (which starts with "17 services")
    let svc_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("crate=") && l.contains("endpoint="))
        .collect();
    assert_eq!(
        svc_lines.len(),
        17,
        "expected 17 service lines, got {}:\n{stdout}",
        svc_lines.len()
    );
}

#[test]
fn aios_system_health_check_prints_scaffold_ready_for_each() {
    let output = binary().arg("health-check").assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let scaffold_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.ends_with(": scaffold-ready"))
        .collect();
    assert_eq!(
        scaffold_lines.len(),
        17,
        "expected 17 scaffold-ready lines, got {}:\n{stdout}",
        scaffold_lines.len()
    );
}

#[test]
fn aios_system_run_service_once_writes_state_for_alias() {
    let state_dir = unique_state_dir();

    binary()
        .args([
            "run-service",
            "aios-policy-kernel",
            "--config",
            "/tmp/aios-test-config.toml",
            "--state-dir",
        ])
        .arg(&state_dir)
        .arg("--once")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "requested=aios-policy-kernel canonical=aios-policy",
        ));

    let state_path = state_dir.join("aios-policy-kernel.json");
    let state = std::fs::read_to_string(&state_path).unwrap();
    assert!(state.contains("\"canonical_service_id\": \"aios-policy\""));

    std::fs::remove_dir_all(&state_dir).unwrap();
}
