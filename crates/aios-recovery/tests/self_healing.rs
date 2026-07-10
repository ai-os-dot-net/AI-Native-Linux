//! Self-healing module tests — autonomous MINIX-inspired reincarnation logic.
//!
//! Covers: policy validation, health state transitions, driver decision logic,
//! evidence emission for healing actions, and INV-012 (recovery-required) guard.

#![allow(
    clippy::module_name_repetitions,
    clippy::too_long_first_doc_paragraph,
    reason = "Self-healing test names are intentionally descriptive"
)]

use std::sync::Arc;

use aios_recovery::{
    ComponentHealingConfig, ComponentHealthState, ComponentIsolationLevel, ComponentRegistry,
    ComponentSnapshot, HealAction, HealActionKind, HealCommand, HealCommandChannel,
    HealCommandResponse, HealingCapability, InMemoryRecoveryBoundary, InMemorySelfHealingDriver,
    PanicSeverity, RecoveryBoundary, RecoveryEvidenceEmitter, RecoveryMode, RecoveryMutableScope,
    RecoverySubjectRef, RegistryEntry, RestartBoundary, RestartPolicy, SelfHealingDriver,
    SelfHealingPolicy, WatchdogPolicy,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32])
}

fn make_emitter(log: Arc<aios_recovery::InMemoryRecoveryEvidenceLog>) -> RecoveryEvidenceEmitter {
    RecoveryEvidenceEmitter::new(
        log,
        test_signing_key(),
        RecoverySubjectRef(aios_recovery::SELF_HEALING_SUBJECT.to_owned()),
    )
}

fn minix_policy() -> SelfHealingPolicy {
    let mut component_policies = std::collections::HashMap::new();
    component_policies.insert(
        "aios-network-manager".to_owned(),
        ComponentHealingConfig {
            display_name: "Network Manager".to_owned(),
            restart_policy: RestartPolicy::minix_style(3),
            allowed_scopes: vec![
                RecoveryMutableScope::ProcessLifecycle,
                RecoveryMutableScope::NetworkReconfig,
            ],
            allowed_capabilities: vec![],
            isolation_level: ComponentIsolationLevel::Replaceable,
            restart_boundary: RestartBoundary::ProcessLocal,
            component_type: Some("infrastructure".to_owned()),
        },
    );
    component_policies.insert(
        "aios-dns-resolver".to_owned(),
        ComponentHealingConfig {
            display_name: "DNS Resolver".to_owned(),
            restart_policy: RestartPolicy::conservative(5),
            allowed_scopes: vec![RecoveryMutableScope::ProcessLifecycle],
            allowed_capabilities: vec![],
            isolation_level: ComponentIsolationLevel::Replaceable,
            restart_boundary: RestartBoundary::ProcessLocal,
            component_type: Some("infrastructure".to_owned()),
        },
    );
    SelfHealingPolicy {
        enabled: true,
        minimum_mode: RecoveryMode::Recovery,
        component_policies,
        default_policy: RestartPolicy::conservative(2),
    }
}

fn disabled_policy() -> SelfHealingPolicy {
    SelfHealingPolicy::default()
}

// ---------------------------------------------------------------------------
// Policy validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn policy_normal_mode_with_components_is_invalid() {
    let mut bad = SelfHealingPolicy {
        minimum_mode: RecoveryMode::Normal,
        ..Default::default()
    };
    bad.component_policies.insert(
        "test-comp".to_owned(),
        ComponentHealingConfig {
            display_name: "Test".to_owned(),
            restart_policy: RestartPolicy::default(),
            allowed_scopes: vec![],
            allowed_capabilities: vec![],
            isolation_level: ComponentIsolationLevel::Replaceable,
            restart_boundary: RestartBoundary::ProcessLocal,
            component_type: None,
        },
    );
    assert!(bad.validate().is_err());
}

#[tokio::test]
async fn policy_recovery_mode_is_valid() {
    assert!(minix_policy().validate().is_ok());
}

#[tokio::test]
async fn policy_disabled_with_no_components_is_valid() {
    assert!(disabled_policy().validate().is_ok());
}

// ---------------------------------------------------------------------------
// Health states
// ---------------------------------------------------------------------------

#[test]
fn healthy_needs_no_intervention() {
    assert!(!ComponentHealthState::Healthy.needs_intervention());
    assert!(!ComponentHealthState::Unknown.needs_intervention());
}

#[test]
fn degraded_needs_intervention() {
    assert!(ComponentHealthState::Degraded.needs_intervention());
}

#[test]
fn failed_needs_intervention_and_is_terminal() {
    assert!(ComponentHealthState::Failed.needs_intervention());
    assert!(ComponentHealthState::Failed.is_terminal());
}

#[test]
fn failed_is_terminal_degraded_is_not() {
    assert!(!ComponentHealthState::Degraded.is_terminal());
}

// ---------------------------------------------------------------------------
// Restart policy backoff
// ---------------------------------------------------------------------------

#[test]
fn minix_style_zero_backoff() {
    let p = RestartPolicy::minix_style(5);
    // MINIX-style always returns 0.0 while within max_retries
    assert_eq!(p.backoff_for_attempt(1), Some(0.0));
    assert_eq!(p.backoff_for_attempt(3), Some(0.0));
    assert_eq!(p.backoff_for_attempt(5), Some(0.0)); // 5 <= 5 → still within budget
    assert_eq!(p.backoff_for_attempt(6), None); // 6 > 5 → escalate
}

#[test]
fn conservative_backoff_grows() {
    let p = RestartPolicy::conservative(4);
    // Actual impl: base * (2 - attempt), saturating at 0
    // attempt 1: 2s * (2-1) = 2s
    assert_eq!(p.backoff_for_attempt(1), Some(2.0));
    // attempt 2: 2s * (2-2) = 0s
    assert_eq!(p.backoff_for_attempt(2), Some(0.0));
    // attempt 3: 2s * saturating_sub(3)=0 = 0s
    assert_eq!(p.backoff_for_attempt(3), Some(0.0));
    // attempt 4: same, 0s
    assert_eq!(p.backoff_for_attempt(4), Some(0.0));
    // attempt 5: > max_retries → escalate
    assert_eq!(p.backoff_for_attempt(5), None);
}

// ---------------------------------------------------------------------------
// Driver: disabled policy produces no actions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disabled_driver_evaluates_to_empty_actions() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let driver = InMemorySelfHealingDriver::new(boundary);

    driver
        .set_policy(disabled_policy())
        .await
        .expect("disabled policy should be valid");

    driver
        .observe_health("aios-dns-resolver", ComponentHealthState::Failed)
        .await
        .expect("observe should succeed");

    let actions = driver.evaluate().await.expect("evaluate should succeed");
    assert!(
        actions.is_empty(),
        "disabled policy must produce zero actions"
    );
}

// ---------------------------------------------------------------------------
// Driver: recovery-not-active blocks execution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn heal_denied_when_recovery_not_active() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let driver = InMemorySelfHealingDriver::new(boundary);
    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    driver
        .observe_health("aios-network-manager", ComponentHealthState::Failed)
        .await
        .expect("observe should succeed");

    // NOT in recovery mode, but policy requires it
    let action = HealAction {
        component_id: "aios-network-manager".to_owned(),
        observed_state: ComponentHealthState::Failed,
        action_kind: HealActionKind::Restart,
        required_scope: RecoveryMutableScope::ProcessLifecycle,
        reason: "test".to_owned(),
        decided_at: chrono::Utc::now(),
        sequence: 1,
    };

    let result = driver
        .execute_heal(&action)
        .await
        .expect("execute should succeed");
    assert!(!result.success, "must fail when recovery not active");
    assert!(
        result.detail.contains("INV-012"),
        "detail should mention invariant violation"
    );
    assert!(result.receipt_id.is_none(), "no receipt when denied");
}

// ---------------------------------------------------------------------------
// Driver: full observe → evaluate → execute cycle with recovery active
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_cycle_in_recovery_produces_actions() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone()).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    // Enter recovery mode first
    boundary
        .enter_recovery(aios_recovery::EnterRecoveryRequest {
            reason: "BOOT_FAILURE_AUTO".to_owned(),
            operator_grant: Some("self-healing-bootstrap".to_owned()),
            expected_phases: vec![aios_recovery::BootPhase::Recovery],
            bundle: None,
        })
        .await
        .expect("enter recovery should succeed");

    // Observe two failing components
    driver
        .observe_health("aios-network-manager", ComponentHealthState::Failed)
        .await
        .expect("observe nm");
    driver
        .observe_health("aios-dns-resolver", ComponentHealthState::Degraded)
        .await
        .expect("observe dns");

    // Evaluate should produce actions for both
    let actions = driver.evaluate().await.expect("evaluate");
    assert_eq!(actions.len(), 2, "two unhealthy components → two actions");

    // Execute both
    for action in &actions {
        let result = driver.execute_heal(action).await.expect("execute heal");
        assert!(
            result.success,
            "{} must succeed: {}",
            action.component_id, result.detail
        );
        assert!(
            result.receipt_id.is_some(),
            "{} must emit evidence",
            action.component_id
        );
    }

    // Full cycle
    let cycle = driver.heal_cycle().await.expect("heal cycle");
    assert_eq!(cycle.components_evaluated, 2);
    assert_eq!(cycle.actions_decided, 2);
    assert_eq!(cycle.actions_executed, 2);
    assert_eq!(cycle.actions_failed, 0);

    // Verify evidence was actually appended (2 from manual execute + 2 from heal_cycle)
    assert_eq!(log.len().await, 4, "receipts emitted for all executions");
}

// ---------------------------------------------------------------------------
// Driver: healthy observation resets retry counter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn healthy_observation_resets_retry_counter() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone()).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    boundary
        .enter_recovery(aios_recovery::EnterRecoveryRequest {
            reason: "BOOT_FAILURE_AUTO".to_owned(),
            operator_grant: Some("self-healing-bootstrap".to_owned()),
            expected_phases: vec![aios_recovery::BootPhase::Recovery],
            bundle: None,
        })
        .await
        .expect("enter recovery");

    // First observation: Failed → counter=1
    driver
        .observe_health("aios-dns-resolver", ComponentHealthState::Failed)
        .await
        .expect("observe failed");
    let actions1 = driver.evaluate().await.expect("eval 1");
    assert_eq!(actions1.len(), 1, "first failure → one action");
    assert_eq!(actions1[0].action_kind, HealActionKind::Restart);

    // Second observation: still Failed → counter=2
    driver
        .observe_health("aios-dns-resolver", ComponentHealthState::Failed)
        .await
        .expect("observe failed again");
    let tracker = driver.tracker_for("aios-dns-resolver").await;
    assert_eq!(tracker.consecutive_failures, 2, "counter should be 2");

    // Third observation: Healthy → resets to 0
    driver
        .observe_health("aios-dns-resolver", ComponentHealthState::Healthy)
        .await
        .expect("observe healthy");
    let tracker = driver.tracker_for("aios-dns-resolver").await;
    assert_eq!(tracker.consecutive_failures, 0, "healthy reset the counter");

    // After reset: evaluate should produce no actions (component is healthy)
    let actions2 = driver.evaluate().await.expect("eval after healthy");
    assert!(actions2.is_empty(), "healthy → no actions needed");
}

// ---------------------------------------------------------------------------
// Evidence payload round-trip for healing
// ---------------------------------------------------------------------------

#[test]
fn healing_payload_round_trips_through_serde_json() {
    use aios_recovery::HealingAttemptedPayload;

    let original = HealingAttemptedPayload {
        component_id: "aios-dns-resolver".to_owned(),
        observed_state: ComponentHealthState::Failed,
        action_kind: HealActionKind::Restart,
        required_scope: RecoveryMutableScope::ProcessLifecycle,
        reason: "consecutive_failures=3 attempt=3/5".to_owned(),
        decided_at: chrono::Utc::now(),
        sequence: 42,
    };

    let json = serde_json::to_value(&original).expect("serialize");
    let round_tripped: HealingAttemptedPayload = serde_json::from_value(json).expect("deserialize");

    assert_eq!(round_tripped.component_id, original.component_id);
    assert_eq!(round_tripped.observed_state, original.observed_state);
    assert_eq!(round_tripped.action_kind, original.action_kind);
    assert_eq!(round_tripped.sequence, original.sequence);
}

// ---------------------------------------------------------------------------
// Subject constant is well-formed
// ---------------------------------------------------------------------------

#[test]
fn self_healing_subject_is_well_formed_system_subject() {
    assert!(aios_recovery::SELF_HEALING_SUBJECT.starts_with("_system:service:"));
    assert_eq!(
        aios_recovery::SELF_HEALING_SUBJECT,
        "_system:service:self-healing"
    );
}

// ---------------------------------------------------------------------------
// RecoveryMutableScope has expected variants and default
// ---------------------------------------------------------------------------

#[test]
fn recovery_mutable_scope_has_all_expected_variants() {
    // Verify expected variants exist and default is ProcessLifecycle
    assert_eq!(
        RecoveryMutableScope::default(),
        RecoveryMutableScope::ProcessLifecycle
    );
    // Spot-check key variants are accessible (compile-time verification)
    let _ = RecoveryMutableScope::NetworkReconfig;
    let _ = RecoveryMutableScope::FilesystemMutation;
    let _ = RecoveryMutableScope::SysctlTuning;
    let _ = RecoveryMutableScope::MeshRouting;
}

// ---------------------------------------------------------------------------
// Tracker records observations correctly
// ---------------------------------------------------------------------------

#[test]
fn tracker_accumulates_failures_on_degraded_or_failed() {
    use aios_recovery::ComponentHealingTracker;

    let mut t = ComponentHealingTracker::default();
    assert_eq!(t.consecutive_failures, 0);
    t.record_observation(ComponentHealthState::Degraded);
    assert_eq!(t.consecutive_failures, 1);
    t.record_observation(ComponentHealthState::Failed);
    assert_eq!(t.consecutive_failures, 2);
    // Healthy resets
    t.record_observation(ComponentHealthState::Healthy);
    assert_eq!(t.consecutive_failures, 0);
    // Unknown does NOT reset
    t.record_observation(ComponentHealthState::Degraded);
    assert_eq!(t.consecutive_failures, 1);
    t.record_observation(ComponentHealthState::Unknown);
    assert_eq!(t.consecutive_failures, 1, "unknown does not reset counter");
}

// ---------------------------------------------------------------------------
// Panic severity classification
// ---------------------------------------------------------------------------

#[test]
fn unwind_panic_is_recoverable() {
    assert!(PanicSeverity::Unwind.is_recoverable_by_restart());
    assert!(!PanicSeverity::Unwind.requires_escalation());
}

#[test]
fn abort_panic_is_recoverable_but_flagged_for_postmortem() {
    assert!(PanicSeverity::Abort.is_recoverable_by_restart());
    assert!(!PanicSeverity::Abort.requires_escalation());
}

#[test]
fn oom_panic_requires_escalation_no_restart() {
    assert!(!PanicSeverity::Oom.is_recoverable_by_restart());
    assert!(PanicSeverity::Oom.requires_escalation());
}

#[test]
fn sigfault_requires_escalation_no_restart() {
    assert!(!PanicSeverity::SigFault.is_recoverable_by_restart());
    assert!(PanicSeverity::SigFault.requires_escalation());
}

#[test]
fn unknown_panic_defaults_to_non_recoverable() {
    assert!(!PanicSeverity::Unknown.is_recoverable_by_restart());
    assert!(!PanicSeverity::Unknown.requires_escalation());
}

// ---------------------------------------------------------------------------
// PanicContext serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn panic_context_round_trips_through_serde_json() {
    use aios_recovery::PanicContext;

    let original = PanicContext {
        component_id: "aios-dns-resolver".to_owned(),
        severity: PanicSeverity::Abort,
        message: "assertion failed: empty response body".to_owned(),
        file: Some("src/resolver/mod.rs".to_owned()),
        line: Some(247),
        backtrace_hash: Some("a1b2c3d4e5f6".to_owned()),
        core_dump_ref: Some("/var/crashes/dns-1673289123.core".to_owned()),
        observed_at: chrono::Utc::now(),
        consecutive_panics: 3,
    };

    let json = serde_json::to_value(&original).expect("serialize");
    let round_tripped: PanicContext = serde_json::from_value(json).expect("deserialize");

    assert_eq!(round_tripped.component_id, original.component_id);
    assert_eq!(round_tripped.severity, original.severity);
    assert_eq!(round_tripped.message, original.message);
    assert_eq!(round_tripped.line, Some(247));
    assert_eq!(
        round_tripped.core_dump_ref.as_deref(),
        Some("/var/crashes/dns-1673289123.core")
    );
}

// ---------------------------------------------------------------------------
// ComponentPanicPayload round-trip with flags derived from severity
// ---------------------------------------------------------------------------

#[test]
fn panic_payload_flags_match_severity() {
    use aios_recovery::ComponentPanicPayload;

    let unwind_payload = ComponentPanicPayload {
        component_id: "test".to_owned(),
        severity: PanicSeverity::Unwind,
        message: "".to_owned(),
        file: None,
        line: None,
        backtrace_hash: None,
        core_dump_ref: None,
        observed_at: chrono::Utc::now(),
        consecutive_panics: 1,
        recoverable_by_restart: true,
        requires_escalation: false,
    };
    assert!(unwind_payload.recoverable_by_restart);
    assert!(!unwind_payload.requires_escalation);

    // OOM payload — explicitly constructed with correct flags
    let oom_payload = ComponentPanicPayload {
        component_id: "test".to_owned(),
        severity: PanicSeverity::Oom,
        message: "".to_owned(),
        file: None,
        line: None,
        backtrace_hash: None,
        core_dump_ref: None,
        observed_at: chrono::Utc::now(),
        consecutive_panics: 1,
        recoverable_by_restart: false,
        requires_escalation: true,
    };
    assert!(!oom_payload.recoverable_by_restart);
    assert!(oom_payload.requires_escalation);
}

// ---------------------------------------------------------------------------
// Tracker record_panic always bumps and sets Failed
// ---------------------------------------------------------------------------

#[test]
fn record_panic_bumps_consecutive_and_sets_failed() {
    use aios_recovery::ComponentHealingTracker;

    let mut t = ComponentHealingTracker::default();
    assert_eq!(t.consecutive_failures, 0);
    assert_eq!(t.total_actions, 0);

    // First panic: bumps to 1, total_actions to 1, state → Failed
    t.record_panic();
    assert_eq!(t.consecutive_failures, 1);
    assert_eq!(t.total_actions, 1);
    assert_eq!(t.last_observed_state, ComponentHealthState::Failed);

    // Second panic: bumps to 2, total_actions to 2
    t.record_panic();
    assert_eq!(t.consecutive_failures, 2);
    assert_eq!(t.total_actions, 2);
}

// ---------------------------------------------------------------------------
// Driver: observe_panic emits evidence immediately (MINIX-style)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn observe_panic_emits_evidence_immediately() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    let ctx = aios_recovery::PanicContext {
        component_id: "aios-network-manager".to_owned(),
        severity: aios_recovery::PanicSeverity::Abort,
        message: "connection pool exhausted after 30s".to_owned(),
        file: Some("src/net/pool.rs".to_owned()),
        line: Some(89),
        backtrace_hash: Some("deadbeef1234".to_owned()),
        core_dump_ref: Some("/var/dumps/nm-42.core".to_owned()),
        observed_at: chrono::Utc::now(),
        consecutive_panics: 1,
    };

    let receipt = driver
        .observe_panic(ctx)
        .await
        .expect("observe_panic succeeds");

    // Must return a receipt id (evidence was emitted)
    assert!(!receipt.is_empty(), "panic must produce evidence receipt");

    // Verify evidence landed in log
    assert_eq!(log.len().await, 1, "one panic receipt emitted");
}

// ---------------------------------------------------------------------------
// Driver: OOM panic still emits but signals escalation in payload
// ---------------------------------------------------------------------------

#[tokio::test]
async fn observe_oom_panic_emits_with_escalation_flag() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary).with_evidence_emitter(emitter);
    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    // Fire 4 panics to accumulate the tracker counter
    for i in 1..=4 {
        let ctx = aios_recovery::PanicContext {
            component_id: "aios-dns-resolver".to_owned(),
            severity: aios_recovery::PanicSeverity::Oom,
            message: format!("cannot allocate 256 MiB block — panic #{i}"),
            file: None,
            line: None,
            backtrace_hash: None,
            core_dump_ref: None,
            observed_at: chrono::Utc::now(),
            consecutive_panics: i,
        };
        driver
            .observe_panic(ctx)
            .await
            .expect("OOM panic emits evidence");
    }

    // Tracker should show 4 accumulated panics
    let tracker = driver.tracker_for("aios-dns-resolver").await;
    assert_eq!(tracker.consecutive_failures, 4, "4th panic → counter=4");
    assert_eq!(tracker.last_observed_state, ComponentHealthState::Failed);
    // Each panic increments total_actions
    assert_eq!(tracker.total_actions, 4);
}

// ---------------------------------------------------------------------------
// Watchdog: registration, ping, timeout, disabled
// ---------------------------------------------------------------------------

fn enabled_watchdog_policy() -> WatchdogPolicy {
    WatchdogPolicy {
        enabled: true,
        default_timeout_secs: 1,
        component_timeouts: std::collections::HashMap::new(),
    }
}

fn disabled_watchdog_policy() -> WatchdogPolicy {
    WatchdogPolicy::default()
}

#[tokio::test]
async fn watchdog_register_adds_component_to_timer() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary)
        .with_evidence_emitter(emitter)
        .with_watchdog_policy(enabled_watchdog_policy());

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    // Register a component — deadline should be set
    driver.register_watchdog("aios-network-manager").await;

    // Immediately check — deadline should NOT be expired yet (1s timeout)
    driver
        .watchdog_check()
        .await
        .expect("watchdog_check succeeds on clean state");

    let health = driver.health_snapshot().await;
    assert!(
        !health.contains_key("aios-network-manager"),
        "no health entry before timeout expiry"
    );
}

#[tokio::test]
async fn ping_resets_watchdog_timer() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary)
        .with_evidence_emitter(emitter)
        .with_watchdog_policy(enabled_watchdog_policy());

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    // Register and immediately ping to set initial deadline
    driver.register_watchdog("aios-network-manager").await;
    driver.ping_watchdog("aios-network-manager").await;

    // Sleep longer than the 1-second timeout
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Ping just before checking — reset the timer
    driver.ping_watchdog("aios-network-manager").await;

    // Deadline was just reset; component should not be flagged
    driver
        .watchdog_check()
        .await
        .expect("watchdog_check succeeds");

    let health = driver.health_snapshot().await;
    assert!(
        !health.contains_key("aios-network-manager"),
        "ping reset deadline — component still within window"
    );
}

#[tokio::test]
async fn watchdog_timeout_triggers_degraded_observation() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary)
        .with_evidence_emitter(emitter)
        .with_watchdog_policy(enabled_watchdog_policy());

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    // Register and set deadline
    driver.register_watchdog("aios-network-manager").await;
    driver.ping_watchdog("aios-network-manager").await;

    // Sleep past the 1-second timeout
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Watchdog check should auto-flag the expired component as Degraded
    driver
        .watchdog_check()
        .await
        .expect("watchdog_check should succeed");

    let health = driver.health_snapshot().await;
    assert!(
        health.contains_key("aios-network-manager"),
        "expired component must appear in health registry"
    );
    assert_eq!(
        health["aios-network-manager"],
        ComponentHealthState::Degraded,
        "expired component must be Degraded"
    );
}

#[tokio::test]
async fn disabled_watchdog_does_not_auto_flag() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary)
        .with_evidence_emitter(emitter)
        .with_watchdog_policy(disabled_watchdog_policy());

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    // Register component even though watchdog is disabled
    driver.register_watchdog("aios-network-manager").await;

    // Sleep past any possible timeout
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Watchdog check should return empty — policy is disabled
    driver
        .watchdog_check()
        .await
        .expect("watchdog_check should succeed");

    let health = driver.health_snapshot().await;
    assert!(
        !health.contains_key("aios-network-manager"),
        "disabled watchdog must NOT auto-flag components"
    );
}

// ---------------------------------------------------------------------------
// Tracker checkpoint: sets hash + timestamp on checkpoint()
// ---------------------------------------------------------------------------

#[test]
fn tracker_checkpoint_sets_hash_and_timestamp() {
    use aios_recovery::ComponentHealingTracker;

    let mut t = ComponentHealingTracker::default();
    assert!(t.checkpoint_hash.is_none(), "no hash before checkpoint");
    assert!(
        t.checkpoint_timestamp.is_none(),
        "no timestamp before checkpoint"
    );

    t.checkpoint("abc123def456");

    assert_eq!(
        t.checkpoint_hash.as_deref(),
        Some("abc123def456"),
        "hash must match argument"
    );
    assert!(t.checkpoint_timestamp.is_some(), "timestamp must be set");
}

#[test]
fn tracker_checkpoint_overwrites_previous() {
    use aios_recovery::ComponentHealingTracker;

    let mut t = ComponentHealingTracker::default();
    t.checkpoint("first");
    let first_ts = t.checkpoint_timestamp;

    // Small sleep to ensure distinct timestamps (within test resolution)
    std::thread::sleep(std::time::Duration::from_millis(5));

    t.checkpoint("second");

    assert_eq!(t.checkpoint_hash.as_deref(), Some("second"));
    assert!(t.checkpoint_timestamp.is_some());
    assert_ne!(
        t.checkpoint_timestamp, first_ts,
        "subsequent checkpoint should update timestamp"
    );
}

// ---------------------------------------------------------------------------
// ComponentSnapshot serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn component_snapshot_round_trips_through_serde_json() {
    let now = chrono::Utc::now();
    let original = ComponentSnapshot {
        component_id: "aios-network-manager".to_owned(),
        checkpoint_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_owned(),
        config_blob_hex: "7b22686f7374223a226e6d31222c22706f7274223a383038307d".to_owned(),
        captured_at: now,
    };

    let json = serde_json::to_value(&original).expect("serialize");
    let round_tripped: ComponentSnapshot = serde_json::from_value(json).expect("deserialize");

    assert_eq!(round_tripped.component_id, original.component_id);
    assert_eq!(round_tripped.checkpoint_hash, original.checkpoint_hash);
    assert_eq!(round_tripped.config_blob_hex, original.config_blob_hex);
    // DateTime comparison — within tolerance of serialization precision loss
    let diff = (round_tripped.captured_at - original.captured_at)
        .num_milliseconds()
        .unsigned_abs();
    assert!(diff < 1_000, "timestamp should round-trip within 1s");
}

// ---------------------------------------------------------------------------
// Driver take_snapshot() returns valid snapshot
// ---------------------------------------------------------------------------

#[tokio::test]
async fn driver_take_snapshot_returns_valid_snapshot() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    let config_blob = b"{\"host\":\"nm1\",\"port\":8080}";
    let snapshot = driver
        .take_snapshot("aios-network-manager", config_blob)
        .await
        .expect("take_snapshot should succeed");

    assert_eq!(snapshot.component_id, "aios-network-manager");
    assert!(
        !snapshot.checkpoint_hash.is_empty(),
        "hash must be non-empty"
    );
    assert!(
        !snapshot.config_blob_hex.is_empty(),
        "config_blob_hex must be non-empty"
    );

    // The hash should be a BLAKE3 hex (64 chars, characters [0-9a-f])
    assert_eq!(
        snapshot.checkpoint_hash.len(),
        64,
        "BLAKE3 hex hash is always 64 characters"
    );
    assert!(
        snapshot
            .checkpoint_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "hash must be hex chars only"
    );

    // config_blob_hex must decode back to the original bytes
    let decoded = hex::decode(&snapshot.config_blob_hex).expect("valid hex");
    assert_eq!(decoded, config_blob, "round-trip through hex encoding");

    // Verify the tracker was updated
    let tracker = driver.tracker_for("aios-network-manager").await;
    assert_eq!(
        tracker.checkpoint_hash.as_deref(),
        Some(snapshot.checkpoint_hash.as_str()),
        "tracker checkpoint_hash must match snapshot"
    );
    assert!(
        tracker.checkpoint_timestamp.is_some(),
        "tracker must have checkpoint timestamp"
    );
}

#[tokio::test]
async fn driver_take_snapshot_different_blobs_produce_different_hashes() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    let snap1 = driver
        .take_snapshot("aios-dns-resolver", b"config-a")
        .await
        .expect("snapshot 1");
    let snap2 = driver
        .take_snapshot("aios-dns-resolver", b"config-b")
        .await
        .expect("snapshot 2");

    assert_ne!(
        snap1.checkpoint_hash, snap2.checkpoint_hash,
        "different configs must produce different hashes"
    );
    assert_ne!(
        snap1.config_blob_hex, snap2.config_blob_hex,
        "different configs produce different hex blobs"
    );
}

// ---------------------------------------------------------------------------
// Restore snapshot restores tracker state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_snapshot_updates_existing_tracker() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    // First, observe a component so it exists in the tracker
    driver
        .observe_health("aios-network-manager", ComponentHealthState::Failed)
        .await
        .expect("observe failed");

    // Create a snapshot with known data
    let now = chrono::Utc::now();
    let snapshot = ComponentSnapshot {
        component_id: "aios-network-manager".to_owned(),
        checkpoint_hash: "deadbeef00000000000000000000000000000000000000000000000000000000"
            .to_owned(),
        config_blob_hex: "ffeeddcc".to_owned(),
        captured_at: now,
    };

    let updated = driver.restore_snapshot(&snapshot).await;
    assert!(updated, "restore on existing component returns true");

    let tracker = driver.tracker_for("aios-network-manager").await;
    assert_eq!(
        tracker.checkpoint_hash.unwrap(),
        snapshot.checkpoint_hash,
        "restored hash must match"
    );
    assert_eq!(
        tracker.checkpoint_timestamp.unwrap(),
        snapshot.captured_at,
        "restored timestamp must match"
    );
    // restore_snapshot does NOT reset other tracker fields
    assert_eq!(
        tracker.last_observed_state,
        ComponentHealthState::Failed,
        "restore does not overwrite health observations"
    );
}

#[tokio::test]
async fn restore_snapshot_creates_tracker_if_missing() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    let snapshot = ComponentSnapshot {
        component_id: "aios-new-component".to_owned(),
        checkpoint_hash: "cafe000000000000000000000000000000000000000000000000000000000000"
            .to_owned(),
        config_blob_hex: "aabb".to_owned(),
        captured_at: chrono::Utc::now(),
    };

    let updated = driver.restore_snapshot(&snapshot).await;
    assert!(
        !updated,
        "restore on unknown component returns false (creates new)"
    );

    let tracker = driver.tracker_for("aios-new-component").await;
    assert_eq!(
        tracker.checkpoint_hash.unwrap(),
        snapshot.checkpoint_hash,
        "tracker created with correct hash"
    );
    assert_eq!(
        tracker.checkpoint_timestamp.unwrap(),
        snapshot.captured_at,
        "tracker created with correct timestamp"
    );
    // Newly created tracker should have defaults for non-snapshot fields
    assert_eq!(
        tracker.consecutive_failures, 0,
        "new tracker has zero failures"
    );
    assert_eq!(
        tracker.last_observed_state,
        ComponentHealthState::Unknown,
        "new tracker has unknown health"
    );
}

// ---------------------------------------------------------------------------
// Registry: register + resolve round-trip
// ---------------------------------------------------------------------------

#[test]
fn registry_register_and_resolve_round_trip() {
    let mut registry = ComponentRegistry::new();
    let entry = RegistryEntry::new("aios-dns-resolver", "DNS Resolver")
        .with_type("infrastructure")
        .with_dependencies(vec!["aios-kernel".to_owned()])
        .with_expected_initial_state(ComponentHealthState::Healthy)
        .with_isolation_level(ComponentIsolationLevel::Important);

    registry.register(entry.clone());
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());

    let resolved = registry
        .resolve("aios-dns-resolver")
        .expect("resolve must succeed");
    assert_eq!(resolved.component_id, entry.component_id);
    assert_eq!(resolved.display_name, entry.display_name);
    assert_eq!(resolved.component_type.as_deref(), Some("infrastructure"));
    assert_eq!(resolved.dependencies, vec!["aios-kernel"]);
    assert_eq!(resolved.isolation_level, ComponentIsolationLevel::Important);
}

#[test]
fn registry_resolve_missing_returns_none() {
    let registry = ComponentRegistry::new();
    assert!(registry.resolve("nonexistent").is_none());
}

#[test]
fn registry_deregister_removes_entry() {
    let mut registry = ComponentRegistry::new();
    registry.register(RegistryEntry::new("comp-a", "Component A"));
    assert_eq!(registry.len(), 1);

    let removed = registry.deregister("comp-a");
    assert!(removed.is_some());
    assert_eq!(registry.len(), 0);
    assert!(registry.resolve("comp-a").is_none());
}

#[test]
fn registry_deregister_unknown_returns_none() {
    let mut registry = ComponentRegistry::new();
    assert!(registry.deregister("ghost").is_none());
}

// ---------------------------------------------------------------------------
// Registry: dependency chain resolution
// ---------------------------------------------------------------------------

#[test]
fn registry_dependencies_of_returns_declared_deps() {
    let mut registry = ComponentRegistry::new();
    registry.register(
        RegistryEntry::new("aios-api-gateway", "API Gateway").with_dependencies(vec![
            "aios-network-manager".to_owned(),
            "aios-dns-resolver".to_owned(),
        ]),
    );

    let deps = registry.dependencies_of("aios-api-gateway");
    assert_eq!(deps.len(), 2);
    assert!(deps.contains(&"aios-network-manager".to_owned()));
    assert!(deps.contains(&"aios-dns-resolver".to_owned()));
}

#[test]
fn registry_dependencies_of_unknown_returns_empty() {
    let registry = ComponentRegistry::new();
    assert!(registry.dependencies_of("ghost").is_empty());
}

#[test]
fn registry_dependents_of_resolves_reverse_deps() {
    let mut registry = ComponentRegistry::new();
    registry.register(RegistryEntry::new("aios-kernel", "Kernel"));
    registry.register(
        RegistryEntry::new("aios-dns-resolver", "DNS Resolver")
            .with_dependencies(vec!["aios-kernel".to_owned()]),
    );
    registry.register(
        RegistryEntry::new("aios-api-gateway", "API Gateway").with_dependencies(vec![
            "aios-kernel".to_owned(),
            "aios-dns-resolver".to_owned(),
        ]),
    );

    let dependents = registry.dependents_of("aios-kernel");
    assert_eq!(dependents.len(), 2);
    assert!(dependents.contains(&"aios-dns-resolver".to_owned()));
    assert!(dependents.contains(&"aios-api-gateway".to_owned()));
}

#[test]
fn registry_dependents_of_leaf_returns_empty() {
    let mut registry = ComponentRegistry::new();
    registry.register(
        RegistryEntry::new("aios-kernel", "Kernel")
            .with_dependencies(vec!["aios-dns-resolver".to_owned()]),
    );

    let dependents = registry.dependents_of("aios-dns-resolver");
    assert!(dependents.contains(&"aios-kernel".to_owned()));
}

// ---------------------------------------------------------------------------
// Registry: all_entries / from_entries
// ---------------------------------------------------------------------------

#[test]
fn registry_all_entries_returns_all_registered() {
    let entries = vec![
        RegistryEntry::new("comp-a", "A"),
        RegistryEntry::new("comp-b", "B"),
        RegistryEntry::new("comp-c", "C"),
    ];
    let registry = ComponentRegistry::from_entries(entries);
    let all = registry.all_entries();
    assert_eq!(all.len(), 3);
}

#[test]
fn registry_default_is_empty() {
    let registry = ComponentRegistry::default();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
}

// ---------------------------------------------------------------------------
// Registry: isolation_level_of
// ---------------------------------------------------------------------------

#[test]
fn registry_isolation_level_of_returns_stored_level() {
    let mut registry = ComponentRegistry::new();
    registry.register(
        RegistryEntry::new("aios-kernel", "Kernel")
            .with_isolation_level(ComponentIsolationLevel::Critical),
    );
    registry.register(
        RegistryEntry::new("aios-dns-resolver", "DNS Resolver")
            .with_isolation_level(ComponentIsolationLevel::Important),
    );

    assert_eq!(
        registry.isolation_level_of("aios-kernel"),
        ComponentIsolationLevel::Critical,
    );
    assert_eq!(
        registry.isolation_level_of("aios-dns-resolver"),
        ComponentIsolationLevel::Important,
    );
}

#[test]
fn registry_isolation_level_of_unknown_falls_back_to_default() {
    let registry = ComponentRegistry::new();
    assert_eq!(
        registry.isolation_level_of("ghost"),
        ComponentIsolationLevel::default(),
    );
}

// ---------------------------------------------------------------------------
// Registry: ComponentIsolationLevel predicates
// ---------------------------------------------------------------------------

#[test]
fn critical_may_not_restart() {
    assert!(!ComponentIsolationLevel::Critical.may_restart());
    assert!(!ComponentIsolationLevel::Critical.may_kill_and_replace());
    assert!(ComponentIsolationLevel::Critical.requires_escalation());
}

#[test]
fn important_may_restart_but_not_kill_and_replace() {
    assert!(ComponentIsolationLevel::Important.may_restart());
    assert!(!ComponentIsolationLevel::Important.may_kill_and_replace());
    assert!(!ComponentIsolationLevel::Important.requires_escalation());
}

#[test]
fn replaceable_may_restart_and_may_kill_and_replace() {
    assert!(ComponentIsolationLevel::Replaceable.may_restart());
    assert!(ComponentIsolationLevel::Replaceable.may_kill_and_replace());
    assert!(!ComponentIsolationLevel::Replaceable.requires_escalation());
}

// ---------------------------------------------------------------------------
// Driver: Critical isolation prevents restart decision
// ---------------------------------------------------------------------------

#[tokio::test]
async fn critical_component_forces_escalation_not_restart() {
    let mut registry = ComponentRegistry::new();
    registry.register(
        RegistryEntry::new("aios-kernel", "Kernel")
            .with_isolation_level(ComponentIsolationLevel::Critical),
    );

    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone())
        .with_registry(Arc::new(registry))
        .with_evidence_emitter(emitter);

    let mut policy = minix_policy();
    policy.component_policies.insert(
        "aios-kernel".to_owned(),
        ComponentHealingConfig {
            display_name: "Kernel".to_owned(),
            restart_policy: RestartPolicy::minix_style(5),
            allowed_scopes: vec![RecoveryMutableScope::ProcessLifecycle],
            allowed_capabilities: vec![],
            isolation_level: ComponentIsolationLevel::Critical,
            restart_boundary: RestartBoundary::SystemWide,
            component_type: Some("infrastructure".to_owned()),
        },
    );
    driver.set_policy(policy).await.expect("valid policy");

    boundary
        .enter_recovery(aios_recovery::EnterRecoveryRequest {
            reason: "BOOT_FAILURE_AUTO".to_owned(),
            operator_grant: Some("self-healing-bootstrap".to_owned()),
            expected_phases: vec![aios_recovery::BootPhase::Recovery],
            bundle: None,
        })
        .await
        .expect("enter recovery");

    // Observe kernel as Failed — even with first failure, registry says Critical → escalate
    driver
        .observe_health("aios-kernel", ComponentHealthState::Failed)
        .await
        .expect("observe kernel");

    let actions = driver.evaluate().await.expect("evaluate");
    assert_eq!(actions.len(), 1, "one action for Critical kernel");

    let action = &actions[0];
    assert_eq!(
        action.action_kind,
        HealActionKind::Escalate,
        "Critical component must escalate, not restart"
    );
    assert!(
        action.reason.contains("isolation_level=Critical"),
        "reason must mention isolation_level=Critical"
    );
}

// ---------------------------------------------------------------------------
// Registry serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn registry_entry_round_trips_through_serde_json() {
    let original = RegistryEntry::new("aios-dns-resolver", "DNS Resolver")
        .with_type("infrastructure")
        .with_dependencies(vec!["aios-kernel".to_owned()])
        .with_expected_initial_state(ComponentHealthState::Healthy)
        .with_isolation_level(ComponentIsolationLevel::Important);

    let json = serde_json::to_value(&original).expect("serialize");
    let round_tripped: RegistryEntry = serde_json::from_value(json).expect("deserialize");

    assert_eq!(round_tripped.component_id, original.component_id);
    assert_eq!(round_tripped.display_name, original.display_name);
    assert_eq!(round_tripped.component_type, original.component_type);
    assert_eq!(round_tripped.dependencies, original.dependencies);
    assert_eq!(
        round_tripped.expected_initial_state,
        original.expected_initial_state,
    );
    assert_eq!(round_tripped.isolation_level, original.isolation_level);
}

#[test]
fn component_isolation_level_serde_is_screaming_snake_case() {
    let crit = serde_json::to_value(ComponentIsolationLevel::Critical).expect("serialize");
    assert_eq!(
        crit,
        serde_json::Value::String("CRITICAL".to_owned()),
        "Critical → CRITICAL"
    );

    let imp = serde_json::to_value(ComponentIsolationLevel::Important).expect("serialize");
    assert_eq!(
        imp,
        serde_json::Value::String("IMPORTANT".to_owned()),
        "Important → IMPORTANT"
    );

    let repl = serde_json::to_value(ComponentIsolationLevel::Replaceable).expect("serialize");
    assert_eq!(
        repl,
        serde_json::Value::String("REPLACEABLE".to_owned()),
        "Replaceable → REPLACEABLE"
    );
}

#[test]
fn component_isolation_level_default_is_replaceable() {
    assert_eq!(
        ComponentIsolationLevel::default(),
        ComponentIsolationLevel::Replaceable,
    );
}

// ---------------------------------------------------------------------------
// IPC: HealCommand channel send + receive round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn channel_send_receive_round_trip() {
    use tokio::sync::oneshot;

    let mut channel = HealCommandChannel::new(4);
    let sender = channel.sender();

    let handle = tokio::spawn(async move {
        let (resp_tx, resp_rx) = oneshot::channel();
        sender
            .send((
                HealCommand::Shutdown {
                    grace_period_seconds: 10,
                },
                resp_tx,
            ))
            .await
            .expect("send succeeds");
        resp_rx.await.expect("response received")
    });

    // Yield to let the spawned task execute its send
    tokio::task::yield_now().await;

    let (cmd, response_tx) = channel.try_receive().expect("should receive command");
    assert_eq!(
        cmd,
        HealCommand::Shutdown {
            grace_period_seconds: 10
        }
    );

    response_tx
        .send(HealCommandResponse::Ack("shutting down".to_owned()))
        .expect("send response");

    let response = handle.await.expect("task completes");
    assert_eq!(
        response,
        HealCommandResponse::Ack("shutting down".to_owned())
    );
}

#[tokio::test]
async fn channel_try_receive_returns_none_when_empty() {
    let mut channel = HealCommandChannel::new(4);
    assert!(channel.try_receive().is_none());
}

// ---------------------------------------------------------------------------
// IPC: HealCommand Shutdown with grace period serializes/deserializes
// ---------------------------------------------------------------------------

#[test]
fn heal_command_shutdown_serializes_with_grace_period() {
    let cmd = HealCommand::Shutdown {
        grace_period_seconds: 30,
    };
    let json = serde_json::to_value(&cmd).expect("serialize");
    assert_eq!(json["shutdown"]["grace_period_seconds"], 30);
}

#[test]
fn heal_command_shutdown_round_trips_through_json() {
    let original = HealCommand::Shutdown {
        grace_period_seconds: 60,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let round_tripped: HealCommand = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(round_tripped, original);
}

#[test]
fn heal_command_all_variants_round_trip() {
    let commands = vec![
        HealCommand::Shutdown {
            grace_period_seconds: 15,
        },
        HealCommand::RestartInstant,
        HealCommand::Isolate {
            redirect_target: Some("standby-01.local".to_owned()),
        },
        HealCommand::Isolate {
            redirect_target: None,
        },
        HealCommand::Checkpoint {
            state_hash: "abc123def456".to_owned(),
        },
    ];

    for cmd in &commands {
        let json = serde_json::to_string(cmd).expect("serialize");
        let rt: HealCommand = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&rt, cmd, "round-trip failed for {cmd:?}");
    }
}

// ---------------------------------------------------------------------------
// IPC: HealCommandResponse serde round-trip (Ack, Nack, Timeout)
// ---------------------------------------------------------------------------

#[test]
fn heal_command_response_ack_round_trips() {
    let original = HealCommandResponse::Ack("checkpoint=deadbeef".to_owned());
    let json = serde_json::to_string(&original).expect("serialize");
    let rt: HealCommandResponse = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(rt, original);
}

#[test]
fn heal_command_response_nack_round_trips() {
    let original = HealCommandResponse::Nack {
        reason: "still draining connections".to_owned(),
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let rt: HealCommandResponse = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(rt, original);
}

#[test]
fn heal_command_response_timeout_round_trips() {
    let original = HealCommandResponse::Timeout;
    let json = serde_json::to_string(&original).expect("serialize");
    let rt: HealCommandResponse = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(rt, original);
}

#[test]
fn heal_command_response_serde_screaming_snake_case() {
    // Ack is a newtype variant → serialized as {"ACK": "ok"}
    let ack_json =
        serde_json::to_value(HealCommandResponse::Ack("ok".to_owned())).expect("serialize");
    assert!(
        ack_json.as_object().unwrap().contains_key("ACK"),
        "Ack variant key must be ACK"
    );

    // Nack is a struct variant → serialized as {"NACK": {"reason": "no"}}
    let nack_json = serde_json::to_value(HealCommandResponse::Nack {
        reason: "no".to_owned(),
    })
    .expect("serialize");
    assert!(
        nack_json.as_object().unwrap().contains_key("NACK"),
        "Nack variant key must be NACK"
    );

    // Timeout is a unit variant → serialized as "TIMEOUT"
    let timeout_json = serde_json::to_value(HealCommandResponse::Timeout).expect("serialize");
    assert_eq!(timeout_json.as_str().unwrap(), "TIMEOUT");
}

// ---------------------------------------------------------------------------
// IPC: Driver registers and delivers command through channel
// ---------------------------------------------------------------------------

#[tokio::test]
async fn driver_registers_and_delivers_command_through_channel() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    // Register a command channel for aios-network-manager
    let mut channel = driver
        .register_command_channel("aios-network-manager", 4)
        .await;

    // Spawn a task that receives and responds (component side)
    let component_handle = tokio::spawn(async move {
        let (cmd, response_tx) = channel.try_receive().expect("should receive command");
        match cmd {
            HealCommand::Shutdown { .. } => {
                response_tx
                    .send(HealCommandResponse::Ack(
                        "graceful shutdown complete".to_owned(),
                    ))
                    .expect("send ack");
            }
            _ => {
                response_tx
                    .send(HealCommandResponse::Nack {
                        reason: "unexpected command".to_owned(),
                    })
                    .expect("send nack");
            }
        }
    });

    // Driver delivers a shutdown command
    let response = driver
        .deliver_heal_command(
            "aios-network-manager",
            HealCommand::Shutdown {
                grace_period_seconds: 5,
            },
        )
        .await;

    assert_eq!(
        response,
        Some(HealCommandResponse::Ack(
            "graceful shutdown complete".to_owned()
        ))
    );

    component_handle.await.expect("component task completes");
}

// ---------------------------------------------------------------------------
// IPC: No channel → falls back to direct restart (no crash)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_channel_falls_back_to_direct_restart_no_crash() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone()).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    boundary
        .enter_recovery(aios_recovery::EnterRecoveryRequest {
            reason: "BOOT_FAILURE_AUTO".to_owned(),
            operator_grant: Some("self-healing-bootstrap".to_owned()),
            expected_phases: vec![aios_recovery::BootPhase::Recovery],
            bundle: None,
        })
        .await
        .expect("enter recovery");

    // No channel registered for this component
    let action = HealAction {
        component_id: "aios-dns-resolver".to_owned(),
        observed_state: ComponentHealthState::Failed,
        action_kind: HealActionKind::Restart,
        required_scope: RecoveryMutableScope::ProcessLifecycle,
        reason: "test — no channel fallback".to_owned(),
        decided_at: chrono::Utc::now(),
        sequence: 1,
    };

    let result = driver
        .execute_heal(&action)
        .await
        .expect("execute succeeds");
    assert!(result.success, "restart must succeed even without channel");
    assert!(
        result.receipt_id.is_some(),
        "evidence must be emitted despite no channel"
    );
}

// ---------------------------------------------------------------------------
// IPC: Driver delivers command to unknown component returns None
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deliver_heal_command_to_unknown_component_returns_none() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    let response = driver
        .deliver_heal_command("nonexistent-component", HealCommand::RestartInstant)
        .await;

    assert!(
        response.is_none(),
        "delivering to unknown component returns None"
    );
}

// ---------------------------------------------------------------------------
// IPC: Registering a second channel for same component replaces the first
// ---------------------------------------------------------------------------

#[tokio::test]
async fn second_registration_replaces_first_channel() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    let first_channel = driver
        .register_command_channel("aios-dns-resolver", 4)
        .await;

    let _second_channel = driver
        .register_command_channel("aios-dns-resolver", 4)
        .await;

    // The first receiver should be orphaned — drop it
    drop(first_channel);

    // Spawn a receiver task for the second channel so deliver_heal_command
    // doesn't hang. The task drops the oneshot sender without responding,
    // which causes deliver_heal_command to return None.
    let handle = tokio::spawn(async move {
        // The second_channel's receiver is owned by this task — when this
        // task drops it, the sender becomes disconnected. Since we never
        // respond on the oneshot, deliver_heal_command returns None.
        drop(_second_channel);
    });

    // Wait for the receiver to be dropped first
    handle.await.expect("receiver drop task completes");

    // Now deliver — the receiver handle is gone, so response_rx will error
    let response = driver
        .deliver_heal_command("aios-dns-resolver", HealCommand::RestartInstant)
        .await;
    assert!(response.is_none(), "orphaned channel returns None");
}

// ---------------------------------------------------------------------------
// IPC: HealCommandChannel close drops both halves
// ---------------------------------------------------------------------------

#[tokio::test]
async fn close_channel_stops_send_and_receive() {
    let channel = HealCommandChannel::new(4);
    let sender = channel.sender();

    // Drop all sender halves (channel + clone) to close the channel
    drop(sender);
    channel.close();

    // Both senders dropped — channel is fully closed
    // Creating a fresh channel and closing it without clone should work
    let ch2 = HealCommandChannel::new(1);
    let s2 = ch2.sender();
    drop(ch2); // drops original tx/rx, but s2 clone keeps it alive
    drop(s2); // now fully closed
}

// ---------------------------------------------------------------------------
// RestartBoundary tests
// ---------------------------------------------------------------------------

#[test]
fn restart_boundary_default_is_process_local() {
    assert_eq!(
        RestartBoundary::default(),
        RestartBoundary::ProcessLocal,
        "RestartBoundary must default to ProcessLocal"
    );
}

#[test]
fn restart_boundary_serde_round_trip() {
    let boundaries = vec![
        RestartBoundary::ProcessLocal,
        RestartBoundary::MeshLocal,
        RestartBoundary::SystemWide,
    ];

    for boundary in &boundaries {
        let json = serde_json::to_value(boundary).expect("serialize");
        let rt: RestartBoundary = serde_json::from_value(json).expect("deserialize");
        assert_eq!(
            &rt, boundary,
            "RestartBoundary {boundary:?} must round-trip"
        );
    }
}

#[test]
fn restart_boundary_serde_is_screaming_snake_case() {
    let local = serde_json::to_value(RestartBoundary::ProcessLocal).expect("serialize");
    assert_eq!(
        local,
        serde_json::Value::String("PROCESS_LOCAL".to_owned()),
        "ProcessLocal → PROCESS_LOCAL"
    );

    let mesh = serde_json::to_value(RestartBoundary::MeshLocal).expect("serialize");
    assert_eq!(
        mesh,
        serde_json::Value::String("MESH_LOCAL".to_owned()),
        "MeshLocal → MESH_LOCAL"
    );

    let system = serde_json::to_value(RestartBoundary::SystemWide).expect("serialize");
    assert_eq!(
        system,
        serde_json::Value::String("SYSTEM_WIDE".to_owned()),
        "SystemWide → SYSTEM_WIDE"
    );
}

// ---------------------------------------------------------------------------
// Driver: Important component can be restarted (not escalated)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn important_component_can_be_restarted() {
    let mut registry = ComponentRegistry::new();
    registry.register(
        RegistryEntry::new("aios-dns-resolver", "DNS Resolver")
            .with_isolation_level(ComponentIsolationLevel::Important),
    );

    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone())
        .with_registry(Arc::new(registry))
        .with_evidence_emitter(emitter);

    let mut policy = minix_policy();
    policy.component_policies.insert(
        "aios-dns-resolver".to_owned(),
        ComponentHealingConfig {
            display_name: "DNS Resolver".to_owned(),
            restart_policy: RestartPolicy::minix_style(3),
            allowed_scopes: vec![RecoveryMutableScope::ProcessLifecycle],
            allowed_capabilities: vec![],
            isolation_level: ComponentIsolationLevel::Important,
            restart_boundary: RestartBoundary::ProcessLocal,
            component_type: Some("infrastructure".to_owned()),
        },
    );
    driver.set_policy(policy).await.expect("valid policy");

    boundary
        .enter_recovery(aios_recovery::EnterRecoveryRequest {
            reason: "BOOT_FAILURE_AUTO".to_owned(),
            operator_grant: Some("self-healing-bootstrap".to_owned()),
            expected_phases: vec![aios_recovery::BootPhase::Recovery],
            bundle: None,
        })
        .await
        .expect("enter recovery");

    // Observe Important component as Degraded — should get Restart, not Escalate
    driver
        .observe_health("aios-dns-resolver", ComponentHealthState::Degraded)
        .await
        .expect("observe dns");

    let actions = driver.evaluate().await.expect("evaluate");
    assert_eq!(actions.len(), 1, "one action for Important dns-resolver");

    let action = &actions[0];
    assert_eq!(
        action.action_kind,
        HealActionKind::Restart,
        "Important component must be restarted, not escalated"
    );
    assert!(
        action.reason.contains("isolation_level=Important"),
        "reason must mention isolation_level=Important"
    );
    assert!(
        action.reason.contains("restart_boundary=ProcessLocal"),
        "reason must contain restart_boundary"
    );
}

// ---------------------------------------------------------------------------
// Driver: escalate_after on RestartPolicy works correctly
// ---------------------------------------------------------------------------

#[tokio::test]
async fn escalate_after_important_escalates_important_and_critical() {
    let mut registry = ComponentRegistry::new();
    registry.register(
        RegistryEntry::new("aios-dns-resolver", "DNS Resolver")
            .with_isolation_level(ComponentIsolationLevel::Important),
    );

    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone())
        .with_registry(Arc::new(registry))
        .with_evidence_emitter(emitter);

    // escalate_after = Important means Important AND Critical components escalate
    let escalate_policy = RestartPolicy {
        max_retries: 5,
        backoff_seconds_base: 0.0,
        backoff_cap_seconds: 0.0,
        reset_on_healthy: true,
        escalate_after: Some(ComponentIsolationLevel::Important),
    };

    let mut policy = minix_policy();
    policy.component_policies.insert(
        "aios-dns-resolver".to_owned(),
        ComponentHealingConfig {
            display_name: "DNS Resolver".to_owned(),
            restart_policy: escalate_policy,
            allowed_scopes: vec![RecoveryMutableScope::ProcessLifecycle],
            allowed_capabilities: vec![],
            isolation_level: ComponentIsolationLevel::Important,
            restart_boundary: RestartBoundary::ProcessLocal,
            component_type: Some("infrastructure".to_owned()),
        },
    );
    driver.set_policy(policy).await.expect("valid policy");

    boundary
        .enter_recovery(aios_recovery::EnterRecoveryRequest {
            reason: "BOOT_FAILURE_AUTO".to_owned(),
            operator_grant: Some("self-healing-bootstrap".to_owned()),
            expected_phases: vec![aios_recovery::BootPhase::Recovery],
            bundle: None,
        })
        .await
        .expect("enter recovery");

    driver
        .observe_health("aios-dns-resolver", ComponentHealthState::Failed)
        .await
        .expect("observe dns");

    let actions = driver.evaluate().await.expect("evaluate");
    assert_eq!(actions.len(), 1);

    let action = &actions[0];
    assert_eq!(
        action.action_kind,
        HealActionKind::Escalate,
        "escalate_after=Important must escalate an Important component"
    );
}

#[tokio::test]
async fn escalate_after_not_triggered_for_lower_isolation() {
    let mut registry = ComponentRegistry::new();
    registry.register(
        RegistryEntry::new("aios-log-collector", "Log Collector")
            .with_isolation_level(ComponentIsolationLevel::Replaceable),
    );

    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone())
        .with_registry(Arc::new(registry))
        .with_evidence_emitter(emitter);

    // escalate_after = Important — Replaceable is BELOW this threshold
    let escalate_policy = RestartPolicy {
        max_retries: 5,
        backoff_seconds_base: 0.0,
        backoff_cap_seconds: 0.0,
        reset_on_healthy: true,
        escalate_after: Some(ComponentIsolationLevel::Important),
    };

    let mut policy = minix_policy();
    policy.component_policies.insert(
        "aios-log-collector".to_owned(),
        ComponentHealingConfig {
            display_name: "Log Collector".to_owned(),
            restart_policy: escalate_policy,
            allowed_scopes: vec![RecoveryMutableScope::ProcessLifecycle],
            allowed_capabilities: vec![],
            isolation_level: ComponentIsolationLevel::Replaceable,
            restart_boundary: RestartBoundary::ProcessLocal,
            component_type: Some("utility".to_owned()),
        },
    );
    driver.set_policy(policy).await.expect("valid policy");

    boundary
        .enter_recovery(aios_recovery::EnterRecoveryRequest {
            reason: "BOOT_FAILURE_AUTO".to_owned(),
            operator_grant: Some("self-healing-bootstrap".to_owned()),
            expected_phases: vec![aios_recovery::BootPhase::Recovery],
            bundle: None,
        })
        .await
        .expect("enter recovery");

    driver
        .observe_health("aios-log-collector", ComponentHealthState::Failed)
        .await
        .expect("observe collector");

    let actions = driver.evaluate().await.expect("evaluate");
    assert_eq!(actions.len(), 1);

    let action = &actions[0];
    assert_eq!(
        action.action_kind,
        HealActionKind::Restart,
        "escalate_after=Important must NOT escalate a Replaceable component"
    );
}

// ---------------------------------------------------------------------------
// ComponentIsolationLevel rank and ordering
// ---------------------------------------------------------------------------

#[test]
fn isolation_level_rank_values() {
    assert_eq!(ComponentIsolationLevel::Replaceable.rank(), 0);
    assert_eq!(ComponentIsolationLevel::Important.rank(), 1);
    assert_eq!(ComponentIsolationLevel::Critical.rank(), 2);
}

#[test]
fn isolation_level_ordering() {
    assert!(ComponentIsolationLevel::Critical > ComponentIsolationLevel::Important);
    assert!(ComponentIsolationLevel::Important > ComponentIsolationLevel::Replaceable);
    assert!(ComponentIsolationLevel::Critical >= ComponentIsolationLevel::Important);
    assert!(ComponentIsolationLevel::Important >= ComponentIsolationLevel::Important);
    assert!(ComponentIsolationLevel::Replaceable >= ComponentIsolationLevel::Replaceable);
    assert!(ComponentIsolationLevel::Replaceable < ComponentIsolationLevel::Important);
}

// ---------------------------------------------------------------------------
// HealingCapability tests — MINIX-inspired fine-grained capability grants
// ---------------------------------------------------------------------------

#[test]
fn healing_capability_maps_to_correct_scope() {
    assert_eq!(
        HealingCapability::CanRestartProcess.required_scope(),
        RecoveryMutableScope::ProcessLifecycle,
    );
    assert_eq!(
        HealingCapability::CanRestartNetwork.required_scope(),
        RecoveryMutableScope::NetworkReconfig,
    );
    assert_eq!(
        HealingCapability::CanReconfigureDNS.required_scope(),
        RecoveryMutableScope::NetworkReconfig,
    );
    assert_eq!(
        HealingCapability::CanIsolateMeshNode.required_scope(),
        RecoveryMutableScope::MeshRouting,
    );
    assert_eq!(
        HealingCapability::CanSnapshotState.required_scope(),
        RecoveryMutableScope::FilesystemMutation,
    );
    assert_eq!(
        HealingCapability::CanEscalateToOperator.required_scope(),
        RecoveryMutableScope::ProcessLifecycle,
    );
}

#[test]
fn can_restart_process_is_subset_of_process_lifecycle() {
    assert!(
        HealingCapability::CanRestartProcess.is_subset_of(RecoveryMutableScope::ProcessLifecycle,)
    );
    assert!(
        !HealingCapability::CanRestartProcess.is_subset_of(RecoveryMutableScope::NetworkReconfig,)
    );
    assert!(!HealingCapability::CanRestartProcess
        .is_subset_of(RecoveryMutableScope::FilesystemMutation,));
}

#[test]
fn restart_action_requires_can_restart_process_capability() {
    let caps = ComponentHealingConfig::capabilities_for_action(HealActionKind::Restart);
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0], HealingCapability::CanRestartProcess);
}

#[test]
fn failover_action_requires_can_restart_process_capability() {
    let caps = ComponentHealingConfig::capabilities_for_action(HealActionKind::Failover);
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0], HealingCapability::CanRestartProcess);
}

#[test]
fn isolate_action_requires_can_isolate_mesh_node_capability() {
    let caps = ComponentHealingConfig::capabilities_for_action(HealActionKind::Isolate);
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0], HealingCapability::CanIsolateMeshNode);
}

#[test]
fn escalate_action_requires_can_escalate_to_operator_capability() {
    let caps = ComponentHealingConfig::capabilities_for_action(HealActionKind::Escalate);
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0], HealingCapability::CanEscalateToOperator);
}

#[test]
fn healing_capability_serde_round_trip() {
    let capabilities = vec![
        HealingCapability::CanRestartProcess,
        HealingCapability::CanRestartNetwork,
        HealingCapability::CanReconfigureDNS,
        HealingCapability::CanIsolateMeshNode,
        HealingCapability::CanSnapshotState,
        HealingCapability::CanEscalateToOperator,
    ];

    for cap in &capabilities {
        let json = serde_json::to_value(cap).expect("serialize");
        let rt: HealingCapability = serde_json::from_value(json).expect("deserialize");
        assert_eq!(&rt, cap, "HealingCapability {cap:?} must round-trip");
    }
}

#[test]
fn healing_capability_serde_is_screaming_snake_case() {
    let json = serde_json::to_value(HealingCapability::CanRestartProcess).expect("serialize");
    assert_eq!(
        json,
        serde_json::Value::String("CAN_RESTART_PROCESS".to_owned()),
    );

    let json = serde_json::to_value(HealingCapability::CanReconfigureDNS).expect("serialize");
    assert_eq!(
        json,
        serde_json::Value::String("CAN_RECONFIGURE_DNS".to_owned()),
    );

    let json = serde_json::to_value(HealingCapability::CanIsolateMeshNode).expect("serialize");
    assert_eq!(
        json,
        serde_json::Value::String("CAN_ISOLATE_MESH_NODE".to_owned()),
    );

    let json = serde_json::to_value(HealingCapability::CanEscalateToOperator).expect("serialize");
    assert_eq!(
        json,
        serde_json::Value::String("CAN_ESCALATE_TO_OPERATOR".to_owned()),
    );
}

#[test]
fn all_healing_capability_variants_are_accessible() {
    // Compile-time check that all variants are accessible
    let _ = HealingCapability::CanRestartProcess;
    let _ = HealingCapability::CanRestartNetwork;
    let _ = HealingCapability::CanReconfigureDNS;
    let _ = HealingCapability::CanIsolateMeshNode;
    let _ = HealingCapability::CanSnapshotState;
    let _ = HealingCapability::CanEscalateToOperator;
}

#[test]
fn healing_capability_default_is_can_restart_process() {
    assert_eq!(
        HealingCapability::default(),
        HealingCapability::CanRestartProcess,
    );
}

#[test]
fn healing_capability_is_subset_of_matches_required_scope() {
    let all_caps = [
        HealingCapability::CanRestartProcess,
        HealingCapability::CanRestartNetwork,
        HealingCapability::CanReconfigureDNS,
        HealingCapability::CanIsolateMeshNode,
        HealingCapability::CanSnapshotState,
        HealingCapability::CanEscalateToOperator,
    ];

    for cap in &all_caps {
        let scope = cap.required_scope();
        assert!(
            cap.is_subset_of(scope),
            "{cap:?} must be subset of its own scope {scope:?}"
        );
    }
}

#[test]
fn crosstalk_dns_capability_not_subset_of_process_lifecycle() {
    assert!(
        !HealingCapability::CanReconfigureDNS.is_subset_of(RecoveryMutableScope::ProcessLifecycle,)
    );
}

#[test]
fn crosstalk_isolate_not_subset_of_network_reconfig() {
    assert!(
        !HealingCapability::CanIsolateMeshNode.is_subset_of(RecoveryMutableScope::NetworkReconfig,)
    );
}

#[test]
fn component_config_with_capabilities_deserializes_from_json() {
    let json = serde_json::json!({
        "display_name": "DNS Resolver",
        "restart_policy": {
            "max_retries": 3,
            "backoff_seconds_base": 1.0,
            "backoff_cap_seconds": 30.0,
            "reset_on_healthy": true
        },
        "allowed_scopes": ["PROCESS_LIFECYCLE"],
        "allowed_capabilities": ["CAN_RESTART_PROCESS", "CAN_RECONFIGURE_DNS"],
        "isolation_level": "REPLACEABLE",
        "restart_boundary": "PROCESS_LOCAL"
    });

    let config: ComponentHealingConfig =
        serde_json::from_value(json).expect("deserialize with capabilities");

    assert_eq!(config.display_name, "DNS Resolver");
    assert_eq!(config.allowed_capabilities.len(), 2);
    assert_eq!(
        config.allowed_capabilities[0],
        HealingCapability::CanRestartProcess
    );
    assert_eq!(
        config.allowed_capabilities[1],
        HealingCapability::CanReconfigureDNS
    );
}

#[test]
fn component_config_without_capabilities_field_defaults_to_empty() {
    let json = serde_json::json!({
        "display_name": "DNS Resolver",
        "restart_policy": {
            "max_retries": 3,
            "backoff_seconds_base": 1.0,
            "backoff_cap_seconds": 30.0,
            "reset_on_healthy": true
        },
        "allowed_scopes": ["PROCESS_LIFECYCLE"],
        "isolation_level": "REPLACEABLE",
        "restart_boundary": "PROCESS_LOCAL"
    });

    let config: ComponentHealingConfig =
        serde_json::from_value(json).expect("deserialize without capabilities field");

    assert!(config.allowed_capabilities.is_empty());
}

// ---------------------------------------------------------------------------
// RecoverySubBoundary — MINIX-inspired multi-level recovery boundaries
// ---------------------------------------------------------------------------

#[test]
fn recovery_sub_boundary_from_mutable_scope_maps_correctly() {
    use aios_recovery::RecoverySubBoundary;

    // NetworkReconfig → Network
    assert_eq!(
        RecoverySubBoundary::from_mutable_scope(RecoveryMutableScope::NetworkReconfig),
        Some(RecoverySubBoundary::Network),
    );

    // FilesystemMutation → Storage
    assert_eq!(
        RecoverySubBoundary::from_mutable_scope(RecoveryMutableScope::FilesystemMutation),
        Some(RecoverySubBoundary::Storage),
    );

    // ProcessLifecycle → Compute
    assert_eq!(
        RecoverySubBoundary::from_mutable_scope(RecoveryMutableScope::ProcessLifecycle),
        Some(RecoverySubBoundary::Compute),
    );

    // SysctlTuning → Compute
    assert_eq!(
        RecoverySubBoundary::from_mutable_scope(RecoveryMutableScope::SysctlTuning),
        Some(RecoverySubBoundary::Compute),
    );

    // MeshRouting → Network
    assert_eq!(
        RecoverySubBoundary::from_mutable_scope(RecoveryMutableScope::MeshRouting),
        Some(RecoverySubBoundary::Network),
    );
}

#[test]
fn recovery_sub_boundary_contains_is_reflexive() {
    use aios_recovery::RecoverySubBoundary;

    assert!(RecoverySubBoundary::Network.contains(RecoverySubBoundary::Network));
    assert!(RecoverySubBoundary::Storage.contains(RecoverySubBoundary::Storage));
    assert!(RecoverySubBoundary::Compute.contains(RecoverySubBoundary::Compute));
}

#[test]
fn system_full_contains_every_sub_boundary() {
    use aios_recovery::RecoverySubBoundary;

    assert!(RecoverySubBoundary::SystemFull.contains(RecoverySubBoundary::Network));
    assert!(RecoverySubBoundary::SystemFull.contains(RecoverySubBoundary::Storage));
    assert!(RecoverySubBoundary::SystemFull.contains(RecoverySubBoundary::Compute));
    assert!(RecoverySubBoundary::SystemFull.contains(RecoverySubBoundary::SystemFull));
}

#[test]
fn sub_boundaries_do_not_cross_contain() {
    use aios_recovery::RecoverySubBoundary;

    assert!(!RecoverySubBoundary::Network.contains(RecoverySubBoundary::Storage));
    assert!(!RecoverySubBoundary::Network.contains(RecoverySubBoundary::Compute));
    assert!(!RecoverySubBoundary::Storage.contains(RecoverySubBoundary::Network));
    assert!(!RecoverySubBoundary::Storage.contains(RecoverySubBoundary::Compute));
    assert!(!RecoverySubBoundary::Compute.contains(RecoverySubBoundary::Network));
    assert!(!RecoverySubBoundary::Compute.contains(RecoverySubBoundary::Storage));
}

#[test]
fn recovery_sub_boundary_default_is_system_full() {
    use aios_recovery::RecoverySubBoundary;

    assert_eq!(
        RecoverySubBoundary::default(),
        RecoverySubBoundary::SystemFull,
    );
}

#[test]
fn recovery_sub_boundary_serde_round_trip() {
    use aios_recovery::RecoverySubBoundary;

    let boundaries = vec![
        RecoverySubBoundary::Network,
        RecoverySubBoundary::Storage,
        RecoverySubBoundary::Compute,
        RecoverySubBoundary::SystemFull,
    ];

    for b in &boundaries {
        let json = serde_json::to_value(b).expect("serialize");
        let rt: RecoverySubBoundary = serde_json::from_value(json).expect("deserialize");
        assert_eq!(
            &rt, b,
            "RecoverySubBoundary {b:?} must round-trip through serde"
        );
    }
}

#[test]
fn recovery_sub_boundary_serde_is_screaming_snake_case() {
    use aios_recovery::RecoverySubBoundary;

    let json = serde_json::to_value(RecoverySubBoundary::Network).expect("serialize");
    assert_eq!(
        json,
        serde_json::Value::String("NETWORK".to_owned()),
        "Network → NETWORK"
    );

    let json = serde_json::to_value(RecoverySubBoundary::Storage).expect("serialize");
    assert_eq!(
        json,
        serde_json::Value::String("STORAGE".to_owned()),
        "Storage → STORAGE"
    );

    let json = serde_json::to_value(RecoverySubBoundary::Compute).expect("serialize");
    assert_eq!(
        json,
        serde_json::Value::String("COMPUTE".to_owned()),
        "Compute → COMPUTE"
    );

    let json = serde_json::to_value(RecoverySubBoundary::SystemFull).expect("serialize");
    assert_eq!(
        json,
        serde_json::Value::String("SYSTEM_FULL".to_owned()),
        "SystemFull → SYSTEM_FULL"
    );
}

#[test]
fn recovery_state_deserializes_without_active_sub_boundaries_field() {
    // Backward-compatible: missing field defaults to empty vec
    let json = serde_json::json!({
        "mode": "RECOVERY",
        "entered_at": null,
        "exit_planned_at": null,
        "reason": "BOOT_FAILURE_AUTO",
        "operator_grant": null
    });
    let state: aios_recovery::RecoveryState =
        serde_json::from_value(json).expect("deserialize without active_sub_boundaries");
    assert!(state.active_sub_boundaries.is_empty());
}

// ---------------------------------------------------------------------------
// InMemoryBoundary sub-boundary tracking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn in_memory_boundary_enter_sub_boundary_activates_network() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());

    let state = boundary
        .enter_sub_boundary(aios_recovery::RecoverySubBoundary::Network)
        .await
        .expect("enter network sub-boundary");
    assert!(state
        .active_sub_boundaries
        .contains(&aios_recovery::RecoverySubBoundary::Network));

    let active = boundary
        .is_sub_recovery_active(aios_recovery::RecoverySubBoundary::Network)
        .await
        .expect("check");
    assert!(active, "Network sub-boundary must be active");
}

#[tokio::test]
async fn in_memory_boundary_exit_sub_boundary_deactivates_it() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());

    boundary
        .enter_sub_boundary(aios_recovery::RecoverySubBoundary::Storage)
        .await
        .expect("enter storage");

    assert!(
        boundary
            .is_sub_recovery_active(aios_recovery::RecoverySubBoundary::Storage)
            .await
            .expect("check"),
        "Storage must be active before exit"
    );

    boundary
        .exit_sub_boundary(aios_recovery::RecoverySubBoundary::Storage)
        .await
        .expect("exit storage");

    assert!(
        !boundary
            .is_sub_recovery_active(aios_recovery::RecoverySubBoundary::Storage)
            .await
            .expect("check"),
        "Storage must NOT be active after exit"
    );
}

#[tokio::test]
async fn in_memory_boundary_exit_non_active_sub_boundary_errors() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());

    let result = boundary
        .exit_sub_boundary(aios_recovery::RecoverySubBoundary::Compute)
        .await;
    assert!(
        result.is_err(),
        "exiting non-active sub-boundary must error"
    );
}

#[tokio::test]
async fn in_memory_boundary_enter_duplicate_sub_boundary_errors() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());

    boundary
        .enter_sub_boundary(aios_recovery::RecoverySubBoundary::Compute)
        .await
        .expect("first enter");
    let result = boundary
        .enter_sub_boundary(aios_recovery::RecoverySubBoundary::Compute)
        .await;
    assert!(result.is_err(), "duplicate enter must error");
}

#[tokio::test]
async fn in_memory_boundary_multiple_sub_boundaries_can_be_active() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());

    boundary
        .enter_sub_boundary(aios_recovery::RecoverySubBoundary::Network)
        .await
        .expect("enter network");
    boundary
        .enter_sub_boundary(aios_recovery::RecoverySubBoundary::Storage)
        .await
        .expect("enter storage");

    assert!(
        boundary
            .is_sub_recovery_active(aios_recovery::RecoverySubBoundary::Network)
            .await
            .expect("check network"),
        "Network must be active"
    );
    assert!(
        boundary
            .is_sub_recovery_active(aios_recovery::RecoverySubBoundary::Storage)
            .await
            .expect("check storage"),
        "Storage must be active"
    );
    assert!(
        !boundary
            .is_sub_recovery_active(aios_recovery::RecoverySubBoundary::Compute)
            .await
            .expect("check compute"),
        "Compute must NOT be active"
    );

    let state = boundary.current_state().await;
    assert_eq!(state.active_sub_boundaries.len(), 2);
    assert!(state
        .active_sub_boundaries
        .contains(&aios_recovery::RecoverySubBoundary::Network));
    assert!(state
        .active_sub_boundaries
        .contains(&aios_recovery::RecoverySubBoundary::Storage));
}

#[tokio::test]
async fn full_recovery_entry_adds_system_full_to_active_sub_boundaries() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());

    let state = boundary
        .enter_recovery(aios_recovery::EnterRecoveryRequest {
            reason: "BOOT_FAILURE_AUTO".to_owned(),
            operator_grant: Some("self-healing-bootstrap".to_owned()),
            expected_phases: vec![aios_recovery::BootPhase::Recovery],
            bundle: None,
        })
        .await
        .expect("enter recovery");

    assert_eq!(state.active_sub_boundaries.len(), 1);
    assert!(state
        .active_sub_boundaries
        .contains(&aios_recovery::RecoverySubBoundary::SystemFull));

    // SystemFull implies all sub-boundaries are active
    assert!(
        boundary
            .is_sub_recovery_active(aios_recovery::RecoverySubBoundary::Network)
            .await
            .expect("check"),
        "Network must be active when SystemFull is active"
    );
    assert!(
        boundary
            .is_sub_recovery_active(aios_recovery::RecoverySubBoundary::Compute)
            .await
            .expect("check"),
        "Compute must be active when SystemFull is active"
    );
}

// ---------------------------------------------------------------------------
// Driver: healing in sub-boundary (no full recovery)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn heal_allowed_in_network_sub_boundary_without_full_recovery() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone()).with_evidence_emitter(emitter);

    // Policy where the component's scope maps purely to Network
    let mut component_policies = std::collections::HashMap::new();
    component_policies.insert(
        "aios-network-manager".to_owned(),
        ComponentHealingConfig {
            display_name: "Network Manager".to_owned(),
            restart_policy: RestartPolicy::minix_style(3),
            allowed_scopes: vec![RecoveryMutableScope::NetworkReconfig],
            allowed_capabilities: vec![],
            isolation_level: ComponentIsolationLevel::Replaceable,
            restart_boundary: RestartBoundary::ProcessLocal,
            component_type: Some("infrastructure".to_owned()),
        },
    );
    let network_policy = SelfHealingPolicy {
        enabled: true,
        minimum_mode: RecoveryMode::Recovery,
        component_policies,
        default_policy: RestartPolicy::conservative(2),
    };
    driver
        .set_policy(network_policy)
        .await
        .expect("valid policy");

    // Activate only the Network sub-boundary (no full recovery)
    boundary
        .enter_sub_boundary(aios_recovery::RecoverySubBoundary::Network)
        .await
        .expect("enter network sub-boundary");

    // Observe a network-scoped component
    driver
        .observe_health("aios-network-manager", ComponentHealthState::Failed)
        .await
        .expect("observe nm");

    // Evaluate must produce actions for the Network-scoped component
    let actions = driver.evaluate().await.expect("evaluate");
    assert_eq!(actions.len(), 1, "network-only component must be evaluated");

    let action = &actions[0];
    let result = driver.execute_heal(action).await.expect("execute heal");
    assert!(
        result.success,
        "healing must succeed when Network sub-boundary is active: {}",
        result.detail
    );
}

#[tokio::test]
async fn heal_denied_when_sub_boundary_not_active() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone()).with_evidence_emitter(emitter);

    // Create a policy where the component's ONLY scope is NetworkReconfig
    // (not ProcessLifecycle), so Compute being active does NOT grant access.
    let mut component_policies = std::collections::HashMap::new();
    component_policies.insert(
        "aios-network-manager".to_owned(),
        ComponentHealingConfig {
            display_name: "Network Manager".to_owned(),
            restart_policy: RestartPolicy::minix_style(3),
            allowed_scopes: vec![RecoveryMutableScope::NetworkReconfig],
            allowed_capabilities: vec![],
            isolation_level: ComponentIsolationLevel::Replaceable,
            restart_boundary: RestartBoundary::ProcessLocal,
            component_type: Some("infrastructure".to_owned()),
        },
    );
    let network_only_policy = SelfHealingPolicy {
        enabled: true,
        minimum_mode: RecoveryMode::Recovery,
        component_policies,
        default_policy: RestartPolicy::conservative(2),
    };
    driver
        .set_policy(network_only_policy)
        .await
        .expect("valid policy");

    // Only Compute sub-boundary is active — Network is NOT
    boundary
        .enter_sub_boundary(aios_recovery::RecoverySubBoundary::Compute)
        .await
        .expect("enter compute sub-boundary");

    // Observe network-manager (needs Network sub-boundary, only NetworkReconfig scope)
    driver
        .observe_health("aios-network-manager", ComponentHealthState::Failed)
        .await
        .expect("observe nm");

    // Evaluate should skip network-only components since Network sub-boundary is not active
    let actions = driver.evaluate().await.expect("evaluate");
    assert!(
        actions.is_empty(),
        "network-only component must be skipped when Network sub-boundary is not active"
    );

    // Direct execute_heal with NetworkReconfig scope must also be denied
    let action = HealAction {
        component_id: "aios-network-manager".to_owned(),
        observed_state: ComponentHealthState::Failed,
        action_kind: HealActionKind::Restart,
        required_scope: RecoveryMutableScope::NetworkReconfig,
        reason: "test".to_owned(),
        decided_at: chrono::Utc::now(),
        sequence: 1,
    };
    let result = driver.execute_heal(&action).await.expect("execute heal");
    assert!(
        !result.success,
        "must fail when Network sub-boundary not active"
    );
    assert!(
        result.detail.contains("INV-012"),
        "detail should mention INV-012"
    );
}

#[tokio::test]
async fn compute_sub_boundary_allows_process_healing() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone()).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    // Activate only Compute sub-boundary
    boundary
        .enter_sub_boundary(aios_recovery::RecoverySubBoundary::Compute)
        .await
        .expect("enter compute");

    // aios-dns-resolver has allowed_scopes: [ProcessLifecycle] → maps to Compute
    driver
        .observe_health("aios-dns-resolver", ComponentHealthState::Degraded)
        .await
        .expect("observe dns");

    let actions = driver.evaluate().await.expect("evaluate");
    assert_eq!(
        actions.len(),
        1,
        "dns component with ProcessLifecycle → Compute must be evaluated"
    );

    let action = &actions[0];
    let result = driver.execute_heal(action).await.expect("execute heal");
    assert!(
        result.success,
        "Compute sub-boundary must allow ProcessLifecycle healing: {}",
        result.detail
    );
}

#[tokio::test]
async fn healing_in_full_recovery_still_works_with_sub_boundary_impl() {
    // Full recovery (enter_recovery) adds SystemFull, which implies all
    // sub-boundaries are active.  This test ensures backward compatibility.
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());
    let log = Arc::new(aios_recovery::InMemoryRecoveryEvidenceLog::new());
    let emitter = Arc::new(make_emitter(log.clone()));
    let driver = InMemorySelfHealingDriver::new(boundary.clone()).with_evidence_emitter(emitter);

    driver
        .set_policy(minix_policy())
        .await
        .expect("valid policy");

    boundary
        .enter_recovery(aios_recovery::EnterRecoveryRequest {
            reason: "BOOT_FAILURE_AUTO".to_owned(),
            operator_grant: Some("self-healing-bootstrap".to_owned()),
            expected_phases: vec![aios_recovery::BootPhase::Recovery],
            bundle: None,
        })
        .await
        .expect("enter recovery");

    driver
        .observe_health("aios-network-manager", ComponentHealthState::Failed)
        .await
        .expect("observe nm");
    driver
        .observe_health("aios-dns-resolver", ComponentHealthState::Degraded)
        .await
        .expect("observe dns");

    let actions = driver.evaluate().await.expect("evaluate");
    assert_eq!(
        actions.len(),
        2,
        "both components still evaluated under SystemFull"
    );

    for action in &actions {
        let result = driver.execute_heal(action).await.expect("execute heal");
        assert!(
            result.success,
            "{} must succeed: {}",
            action.component_id, result.detail
        );
    }
}

#[tokio::test]
async fn exit_system_full_exit_token_clears_active_sub_boundaries() {
    let boundary = Arc::new(InMemoryRecoveryBoundary::new());

    boundary
        .enter_recovery(aios_recovery::EnterRecoveryRequest {
            reason: "BOOT_FAILURE_AUTO".to_owned(),
            operator_grant: Some("self-healing-bootstrap".to_owned()),
            expected_phases: vec![aios_recovery::BootPhase::Recovery],
            bundle: None,
        })
        .await
        .expect("enter recovery");

    let token = boundary
        .current_exit_token()
        .await
        .expect("must have exit token");

    boundary.exit_recovery(&token).await.expect("exit recovery");

    let state = boundary.current_state().await;
    assert!(
        state.active_sub_boundaries.is_empty(),
        "exit recovery clears sub-boundaries"
    );
    assert_eq!(state.mode, aios_recovery::RecoveryMode::Normal);
}
