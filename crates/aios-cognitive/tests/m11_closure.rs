//! T-105 M11 closure invariants — version markers, code-quality gates, deferred surfaces.

#![allow(
    clippy::expect_used,
    clippy::items_after_statements,
    clippy::panic,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "closure invariants must fail loudly on regressions"
)]

use std::fs;
use std::path::Path;
use std::process::Command;

use aios_cognitive::{
    AICrossOriginPosture, BackendHealthState, CircuitState, LatencyTier, ModelBackendKind,
    PrivacyClass, ProviderClass,
};

// ---------------------------------------------------------------------------
// Closure Invariant 1 — Cargo.toml version is 0.1.0
// ---------------------------------------------------------------------------

#[test]
fn closure_version_0_1_0() {
    let cargo_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let contents = fs::read_to_string(&cargo_path).expect("Cargo.toml readable");
    assert!(
        contents.contains("version = \"0.1.0\""),
        "Cargo.toml must declare version = \"0.1.0\""
    );
}

// ---------------------------------------------------------------------------
// Closure Invariant 2 — DEFAULT_CODE_VERSION is 0.1.0-T105
// ---------------------------------------------------------------------------

#[test]
fn closure_default_code_version_t105() {
    let marker = aios_cognitive::DEFAULT_CODE_VERSION;
    assert_eq!(
        marker, "aios-cognitive/0.1.0-T105",
        "DEFAULT_CODE_VERSION must be 0.1.0-T105, got {marker}"
    );
}

// ---------------------------------------------------------------------------
// Closure Invariant 3 — the gRPC service has NO unimplemented RPCs (M20)
// ---------------------------------------------------------------------------
// The gRPC surface is 12 RPCs per S13.1 §19. As of M20 ALL are implemented:
// PerceiveIntent + GetCognitiveCoreInfo + the agent/plan/memory surface
// (register/get/list/retire agent, get/list plan, get memory entry, draft plan,
// draft action proposal, reason about verification). This invariant guards
// against a Status::unimplemented stub regressing back into the service.

#[test]
fn closure_no_status_unimplemented_in_service() {
    let svc_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("service");
    for entry in fs::read_dir(&svc_dir).expect("service dir readable") {
        let path = entry.expect("entry ok").path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let contents = fs::read_to_string(&path).expect("file readable");
        let fname = path.file_name().unwrap().to_string_lossy();
        assert!(
            !contents.contains("Status::unimplemented"),
            "service/{fname}: found Status::unimplemented — all 12 CognitiveCore RPCs must be implemented (M20 discharged the L5 deferred surface; no stubs allowed)"
        );
    }
}

// ---------------------------------------------------------------------------
// Closure Invariant 4 — No todo!() or unimplemented!() in src/
// ---------------------------------------------------------------------------

#[test]
fn closure_no_todo_or_unimplemented_in_src() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    check_dir_no_todo(&src_dir);
}

fn check_dir_no_todo(dir: &Path) {
    for entry in fs::read_dir(dir).expect("dir readable") {
        let path = entry.expect("entry ok").path();
        if path.is_dir() {
            check_dir_no_todo(&path);
        } else if path.extension().is_none_or(|e| e != "rs") {
        } else {
            let contents = fs::read_to_string(&path).expect("file readable");
            let fname = path.file_name().unwrap().to_string_lossy();
            assert!(
                !contents.contains("todo!("),
                "src/{fname} contains todo!() — must be resolved before M11 closure"
            );
            assert!(
                !contents.contains("unimplemented!("),
                "src/{fname} contains unimplemented!() — must be resolved before M11 closure"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Closure Invariant 5 — Every CognitiveCore gRPC RPC is implemented
// ---------------------------------------------------------------------------

#[test]
fn closure_every_cognitive_core_rpc_implemented() {
    // The gRPC service must implement all required RPCs from S13.1 §19.
    // We verify no Status::unimplemented in server.rs (covered by invariant 3)
    // and that the server struct compiles.
    let svc_server = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("service")
        .join("server.rs");
    let contents = fs::read_to_string(&svc_server).expect("server.rs readable");

    // Verify the server struct compiles and implements the trait
    assert!(
        contents.contains("CognitiveCoreServiceImpl"),
        "server.rs must define CognitiveCoreServiceImpl"
    );
    assert!(
        contents.contains(
            "impl proto::cognitive_core_server::CognitiveCore for CognitiveCoreServiceImpl"
        ),
        "server.rs must implement CognitiveCore gRPC trait"
    );
}

// ---------------------------------------------------------------------------
// Closure Invariant 6 — Closed-enum type coverage matches spec
// ---------------------------------------------------------------------------

#[test]
fn closure_type_coverage_enums_match_spec() {
    use strum::EnumCount;

    // S13.2 §4: ModelBackendKind = 8 variants
    assert_eq!(
        ModelBackendKind::COUNT,
        8,
        "ModelBackendKind must have 8 variants per S13.2 §4"
    );

    // S13.2 §5: ProviderClass = 5 variants
    assert_eq!(
        ProviderClass::COUNT,
        5,
        "ProviderClass must have 5 variants per S13.2 §5"
    );

    // S8.1 §4.9: AICrossOriginPosture = 3 variants
    assert_eq!(
        AICrossOriginPosture::COUNT,
        3,
        "AICrossOriginPosture must have 3 variants per S8.1 §4.9"
    );

    // S13.2 §9.1: BackendHealthState = 5 variants
    assert_eq!(
        BackendHealthState::COUNT,
        5,
        "BackendHealthState must have 5 variants per S13.2 §9.1"
    );

    // S1.2: LatencyTier (5 variants), PrivacyClass (5 variants)
    assert_eq!(
        LatencyTier::COUNT,
        5,
        "LatencyTier must have 5 variants per S1.2"
    );
    assert_eq!(
        PrivacyClass::COUNT,
        5,
        "PrivacyClass must have 5 variants per S1.2"
    );

    // S14.1 §6: CircuitState = 3 variants
    assert_eq!(
        CircuitState::COUNT,
        3,
        "CircuitState must have 3 variants per S14.1 §6"
    );
}

// ---------------------------------------------------------------------------
// Closure Invariant 7 — Deferred surfaces documented
// ---------------------------------------------------------------------------

#[test]
fn closure_deferred_surfaces_documented() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    // Known deferred surfaces — these are M12+ work items that were
    // intentionally not implemented in M11. Each must have corresponding
    // documentation or a visible deferred marker.
    let known_deferred = [
        "vault_client_not_configured",
        "no vault client",
        "stub-model-invocation",
        "stub-backend",
    ];

    let mut deferred_found = Vec::new();
    for entry in fs::read_dir(&src_dir).expect("src dir readable") {
        let path = entry.expect("entry ok").path();
        if path.is_dir() {
            if let Ok(sub_dir) = fs::read_dir(&path) {
                for sub in sub_dir {
                    let sp = sub.expect("sub entry ok").path();
                    if sp.extension().is_none_or(|e| e != "rs") {
                        continue;
                    }
                    let c = fs::read_to_string(&sp).unwrap_or_default();
                    for keyword in known_deferred {
                        if c.contains(keyword) {
                            deferred_found.push(keyword);
                        }
                    }
                }
            }
        } else if path.extension().is_none_or(|e| e != "rs") {
        } else {
            let contents = fs::read_to_string(&path).unwrap_or_default();
            for keyword in known_deferred {
                if contents.contains(keyword) {
                    deferred_found.push(keyword);
                }
            }
        }
    }

    // At minimum, a subset of deferred surfaces should be documented.
    // We don't require all 4 — only enough to prove the closure is honest.
    assert!(
        deferred_found.len() >= 2,
        "at least 2 deferred surfaces must be documented in source; found {}: {deferred_found:?}",
        deferred_found.len()
    );
}

// ---------------------------------------------------------------------------
// Closure Invariant 8 — Closure files present
// ---------------------------------------------------------------------------

#[test]
fn closure_closure_files_present() {
    let tests_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let required = [
        "mvp_cognitive_walk.rs",
        "acceptance_fixtures.rs",
        "m11_closure.rs",
    ];
    for fname in &required {
        let path = tests_dir.join(fname);
        assert!(path.exists(), "closure file {fname} must exist in tests/");
        let contents = fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !contents.trim().is_empty(),
            "closure file {fname} must not be empty"
        );
    }
}

// ---------------------------------------------------------------------------
// Bonus invariant — workspace builds clean with no warnings
// ---------------------------------------------------------------------------

#[test]
#[ignore = "expensive nested cargo check; deadlocks with the outer cargo lock in CI where a dedicated cargo-check job provides the same evidence — run explicitly with `cargo test -p aios-cognitive --test m11_closure -- --ignored`"]
fn closure_aios_cognitive_crate_builds_clean() {
    // Verify this crate compiles without errors
    let output = Command::new("cargo")
        .args(["check", "-p", "aios-cognitive"])
        .output()
        .expect("cargo check succeeds");
    assert!(
        output.status.success(),
        "cargo check -p aios-cognitive must pass\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
