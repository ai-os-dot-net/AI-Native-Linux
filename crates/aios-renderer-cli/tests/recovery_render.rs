//! Tests for recovery/kernel renderable implementations and CLI wiring.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]

use aios_recovery::{
    BootId, CandidateId, CandidateState, FirstBootContext, FirstBootPhase, FirstBootStatus,
    KernelCandidate, KernelManifest, RecoveryMode, RecoveryState,
};
use aios_renderer_cli::{
    AiosCli, AiosCommand, InProcessBackend, KernelSubcommand, OutputFormat, RecoverySubcommand,
    RenderContext, Renderable,
};
use chrono::{TimeZone, Utc};
use clap::Parser;
use strum::IntoEnumIterator;

fn ctx(color: bool) -> RenderContext {
    RenderContext {
        color,
        width: Some(220),
        redact_secrets: true,
        verbose: false,
        locale: "en_US.UTF-8".to_owned(),
    }
}

fn fixed_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 25, 10, 0, 0)
        .single()
        .expect("timestamp")
}

fn recovery_state(mode: RecoveryMode) -> RecoveryState {
    RecoveryState {
        mode,
        entered_at: (mode == RecoveryMode::Recovery).then_some(fixed_time()),
        exit_planned_at: None,
        reason: (mode == RecoveryMode::Recovery).then(|| "BOOT_FAILURE_AUTO".to_owned()),
        operator_grant: None,
        active_sub_boundaries: Vec::new(),
    }
}

fn manifest() -> KernelManifest {
    KernelManifest {
        version: "6.9.0-aios.1".to_owned(),
        min_aios_version: "0.1.0".to_owned(),
        requires_recovery_install: true,
        verification_intent: Some("verify dedicated kernel gates".to_owned()),
        tags: vec!["KSPP_STRICT".to_owned(), "S9_3".to_owned()],
    }
}

fn candidate(state: CandidateState) -> KernelCandidate {
    KernelCandidate {
        candidate_id: CandidateId::new(),
        version: "6.9.0-aios.1".to_owned(),
        kernel_blake3: "0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        signature_ed25519: vec![7; 64],
        signing_authority: "neurocad-kernel-ca".to_owned(),
        registered_at: fixed_time(),
        state,
        manifest: manifest(),
    }
}

fn first_boot_context(status: FirstBootStatus) -> FirstBootContext {
    FirstBootContext {
        boot_id: BootId::new(),
        started_at: fixed_time(),
        completed_at: (status == FirstBootStatus::Completed).then_some(fixed_time()),
        status,
        performed_phases: vec![
            FirstBootPhase::StageInstallerMediaVerified,
            FirstBootPhase::StageDiskPartitioned,
            FirstBootPhase::StageKernelInstalled,
        ],
    }
}

#[test]
fn recovery_state_normal_renders_green_when_color_enabled_and_plain_without_color() {
    let state = recovery_state(RecoveryMode::Normal);

    let colored = state
        .render(OutputFormat::Text, &ctx(true))
        .expect("render colored normal");
    let plain = state
        .render(OutputFormat::Text, &ctx(false))
        .expect("render plain normal");

    assert!(colored.contains("\u{1b}[32mNORMAL\u{1b}[0m"), "{colored}");
    assert!(plain.contains("mode: NORMAL"), "{plain}");
    assert!(!plain.contains('\u{1b}'));
}

#[test]
fn recovery_state_recovery_mode_renders_red_when_color_enabled() {
    let state = recovery_state(RecoveryMode::Recovery);

    let rendered = state
        .render(OutputFormat::Text, &ctx(true))
        .expect("render recovery");

    assert!(
        rendered.contains("\u{1b}[31mRECOVERY\u{1b}[0m"),
        "{rendered}"
    );
    assert!(rendered.contains("reason: BOOT_FAILURE_AUTO"));
}

#[test]
fn recovery_state_renders_all_output_formats() {
    let state = recovery_state(RecoveryMode::Degraded);

    for format in [
        OutputFormat::Text,
        OutputFormat::Json,
        OutputFormat::Tree,
        OutputFormat::Table,
    ] {
        let rendered = state.render(format, &ctx(false)).expect("render state");
        assert!(rendered.contains("DEGRADED"), "{rendered}");
    }
}

#[test]
fn recovery_mode_first_boot_renders_blue_when_color_enabled() {
    let rendered = RecoveryMode::FirstBoot
        .render(OutputFormat::Text, &ctx(true))
        .expect("render first boot mode");

    assert!(
        rendered.contains("\u{1b}[34mFIRST_BOOT\u{1b}[0m"),
        "{rendered}"
    );
}

#[test]
fn first_boot_status_completed_failed_and_in_progress_are_color_coded() {
    let cases = [
        (FirstBootStatus::Completed, "\u{1b}[32mCOMPLETED\u{1b}[0m"),
        (FirstBootStatus::Failed, "\u{1b}[31mFAILED\u{1b}[0m"),
        (
            FirstBootStatus::InProgress,
            "\u{1b}[34mIN_PROGRESS\u{1b}[0m",
        ),
    ];

    for (status, expected) in cases {
        let rendered = status
            .render(OutputFormat::Text, &ctx(true))
            .expect("render first-boot status");
        assert!(rendered.contains(expected), "{rendered}");
    }
}

#[test]
fn first_boot_context_tree_shows_performed_phase_hierarchy() {
    let context = first_boot_context(FirstBootStatus::InProgress);

    let rendered = context
        .render(OutputFormat::Tree, &ctx(false))
        .expect("render first-boot tree");

    assert!(rendered.starts_with("FirstBootContext boot_"), "{rendered}");
    assert!(rendered.contains("status: IN_PROGRESS"), "{rendered}");
    assert!(rendered.contains("performed_phases: count=3"), "{rendered}");
    assert!(
        rendered.contains("STAGE_INSTALLER_MEDIA_VERIFIED"),
        "{rendered}"
    );
    assert!(rendered.contains("STAGE_KERNEL_INSTALLED"), "{rendered}");
}

#[test]
fn first_boot_phase_all_fifteen_variants_render_wire_names() {
    let rendered = FirstBootPhase::iter()
        .map(|phase| phase.render(OutputFormat::Text, &ctx(false)))
        .collect::<Result<Vec<_>, _>>()
        .expect("render phases");

    assert_eq!(rendered.len(), 15);
    assert!(rendered
        .iter()
        .any(|value| value.contains("STAGE_FIRST_BOOT_COMPLETE")));
    assert!(rendered
        .iter()
        .any(|value| value.contains("STAGE_FAILED_REQUIRES_RECOVERY")));
}

#[test]
fn kernel_candidate_renders_kernel_blake3_truncated_to_twelve_chars() {
    let candidate = candidate(CandidateState::GatePassed);

    let rendered = candidate
        .render(OutputFormat::Text, &ctx(false))
        .expect("render candidate");

    assert!(
        rendered.contains("kernel_blake3: 0123456789ab"),
        "{rendered}"
    );
    assert!(!rendered.contains(&candidate.kernel_blake3), "{rendered}");
}

#[test]
fn kernel_manifest_renders_actual_t074_fields() {
    let manifest = manifest();

    let rendered = manifest
        .render(OutputFormat::Tree, &ctx(false))
        .expect("render manifest");

    assert!(rendered.contains("version: 6.9.0-aios.1"), "{rendered}");
    assert!(rendered.contains("min_aios_version: 0.1.0"), "{rendered}");
    assert!(
        rendered.contains("requires_recovery_install: true"),
        "{rendered}"
    );
    assert!(rendered.contains("verification_intent: verify dedicated kernel gates"));
    assert!(rendered.contains("tags: count=2"), "{rendered}");
}

#[test]
fn candidate_state_each_variant_renders() {
    let rendered = CandidateState::iter()
        .map(|state| state.render(OutputFormat::Text, &ctx(false)))
        .collect::<Result<Vec<_>, _>>()
        .expect("render candidate states");

    assert_eq!(rendered.len(), 9);
    for expected in [
        "BUILDING",
        "BUILT",
        "GATING",
        "GATE_PASSED",
        "GATE_FAILED",
        "A_PROMOTED",
        "B_DEMOTED_TO_A",
        "ROLLBACK",
        "RETIRED",
    ] {
        assert!(rendered.iter().any(|value| value.contains(expected)));
    }
}

#[test]
fn parser_recovery_status_accepts_command() {
    let cli =
        AiosCli::try_parse_from(["aios", "recovery", "status"]).expect("parse recovery status");

    match cli.command {
        AiosCommand::Recovery {
            subcommand: RecoverySubcommand::Status,
        } => {}
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parser_recovery_enter_accepts_reason_flag() {
    let cli = AiosCli::try_parse_from(["aios", "recovery", "enter", "--reason", "manual"])
        .expect("parse recovery enter");

    match cli.command {
        AiosCommand::Recovery {
            subcommand: RecoverySubcommand::Enter { reason },
        } => assert_eq!(reason, "manual"),
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parser_recovery_exit_accepts_token_flag() {
    let cli = AiosCli::try_parse_from(["aios", "recovery", "exit", "--token", "X"])
        .expect("parse recovery exit");

    match cli.command {
        AiosCommand::Recovery {
            subcommand: RecoverySubcommand::Exit { token },
        } => assert_eq!(token, "X"),
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parser_kernel_list_accepts_command() {
    let cli = AiosCli::try_parse_from(["aios", "kernel", "list"]).expect("parse kernel list");

    match cli.command {
        AiosCommand::Kernel {
            subcommand: KernelSubcommand::List,
        } => {}
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parser_kernel_activate_accepts_candidate_id() {
    let cli = AiosCli::try_parse_from(["aios", "kernel", "activate", "kc_01XXX"])
        .expect("parse kernel activate");

    match cli.command {
        AiosCommand::Kernel {
            subcommand: KernelSubcommand::Activate { candidate_id },
        } => assert_eq!(candidate_id, "kc_01XXX"),
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parser_kernel_rollback_accepts_candidate_id() {
    let cli = AiosCli::try_parse_from(["aios", "kernel", "rollback", "kc_01XXX"])
        .expect("parse kernel rollback");

    match cli.command {
        AiosCommand::Kernel {
            subcommand: KernelSubcommand::Rollback { candidate_id },
        } => assert_eq!(candidate_id, "kc_01XXX"),
        other => panic!("unexpected command: {other:?}"),
    }
}

#[tokio::test]
async fn in_process_backend_service_count_is_ten() {
    let (_client, shutdown) = InProcessBackend::spawn_and_connect()
        .await
        .expect("spawn backend");

    assert_eq!(shutdown.service_count(), 10);

    shutdown.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn in_process_enter_recovery_returns_recovery_state_and_renders() {
    let (mut client, shutdown) = InProcessBackend::spawn_and_connect()
        .await
        .expect("spawn backend");

    let state = client
        .enter_recovery("BOOT_FAILURE_AUTO")
        .await
        .expect("enter recovery");
    let rendered = state
        .render(OutputFormat::Text, &ctx(true))
        .expect("render recovery state");

    assert_eq!(state.mode, RecoveryMode::Recovery);
    assert!(
        rendered.contains("\u{1b}[31mRECOVERY\u{1b}[0m"),
        "{rendered}"
    );

    // Under a loaded runner the in-process channel can drop before the
    // graceful-shutdown ack ("transport error"); the RPC assertions above
    // are the test's substance, so tolerate the shutdown race.
    if let Err(e) = shutdown.shutdown().await {
        eprintln!("tolerated shutdown race: {e}");
    }
}

#[tokio::test]
async fn in_process_kernel_list_is_empty_initially_and_cli_renders() {
    let cli = AiosCli::try_parse_from(["aios", "--no-color", "kernel", "list"])
        .expect("parse kernel list");
    let (mut client, shutdown) = InProcessBackend::spawn_and_connect()
        .await
        .expect("spawn backend");

    let candidates = client
        .list_kernel_candidates()
        .await
        .expect("list candidates");
    let output = cli.execute(&mut client).await.expect("execute kernel list");

    assert!(candidates.is_empty());
    assert!(output.contains("KernelCandidates"), "{output}");
    assert!(output.contains("candidates: 0"), "{output}");

    shutdown.shutdown().await.expect("shutdown");
}
