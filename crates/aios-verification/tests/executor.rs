//! Executor coverage for S2.4 verification composition semantics.

#![allow(
    clippy::expect_used,
    clippy::missing_const_for_fn,
    reason = "Integration tests use poisoned-lock failures as hard assertion failures and small AST helpers stay readable"
)]

use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aios_action::ActionId;
use aios_verification::{
    InMemoryVerificationEngine, LocalProbe, PrimitiveInvocation, PrimitiveResult, StdStateProbe,
    VerificationContext, VerificationDuration, VerificationDurationUnit, VerificationExecutor,
    VerificationGrammar, VerificationPrimitive, VerificationStatus,
};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn context(timeout_seconds: u32) -> VerificationContext {
    VerificationContext {
        subject: "operator:goriko".to_owned(),
        action_id: ActionId::new(),
        started_at: Utc::now(),
        timeout_seconds,
        dry_run: true,
    }
}

fn executor(probe: Arc<dyn LocalProbe>, default_timeout_ms: u64) -> VerificationExecutor {
    VerificationExecutor::new(
        Arc::new(InMemoryVerificationEngine::new()),
        probe,
        Arc::new(StdStateProbe),
        default_timeout_ms,
    )
}

fn primitive(kind: VerificationPrimitive, args: Value) -> VerificationGrammar {
    VerificationGrammar::Primitive(PrimitiveInvocation { kind, args })
}

fn file_exists(path: &str) -> VerificationGrammar {
    primitive(
        VerificationPrimitive::FileExists,
        json!({"object_or_path": path}),
    )
}

fn service_active(service: &str) -> VerificationGrammar {
    primitive(
        VerificationPrimitive::ServiceActive,
        json!({"service": service}),
    )
}

fn http_ok() -> VerificationGrammar {
    primitive(
        VerificationPrimitive::HttpOk,
        json!({"url": "http://127.0.0.1/"}),
    )
}

fn eventually(term: VerificationGrammar, max_ms: u64, interval_ms: u64) -> VerificationGrammar {
    VerificationGrammar::Eventually {
        term: Box::new(term),
        max_duration: VerificationDuration {
            value: max_ms,
            unit: VerificationDurationUnit::Milliseconds,
        },
        interval: VerificationDuration {
            value: interval_ms,
            unit: VerificationDurationUnit::Milliseconds,
        },
    }
}

#[derive(Debug, Default)]
struct ScriptedProbe {
    files: HashMap<String, bool>,
    services: HashMap<String, bool>,
    file_calls: Mutex<Vec<String>>,
    service_calls: Mutex<Vec<String>>,
}

impl ScriptedProbe {
    fn with_file(mut self, path: &str, exists: bool) -> Self {
        self.files.insert(path.to_owned(), exists);
        self
    }

    fn with_service(mut self, service: &str, running: bool) -> Self {
        self.services.insert(service.to_owned(), running);
        self
    }

    fn service_call_count(&self, service: &str) -> usize {
        self.service_calls
            .lock()
            .expect("service call lock poisoned")
            .iter()
            .filter(|called| called.as_str() == service)
            .count()
    }
}

#[async_trait]
impl LocalProbe for ScriptedProbe {
    async fn file_exists(&self, path: &str) -> bool {
        self.file_calls
            .lock()
            .expect("file call lock poisoned")
            .push(path.to_owned());
        self.files.get(path).copied().unwrap_or(false)
    }

    async fn file_blake3(&self, _path: &str) -> Option<String> {
        None
    }

    async fn process_running(&self, name: &str) -> bool {
        self.service_calls
            .lock()
            .expect("service call lock poisoned")
            .push(name.to_owned());
        self.services.get(name).copied().unwrap_or(false)
    }

    async fn port_listening(&self, _port: u16) -> bool {
        false
    }

    async fn env_var(&self, _name: &str) -> Option<String> {
        None
    }

    async fn command_exit_code(&self, _cmd: &str, _args: &[String]) -> Option<i32> {
        None
    }
}

#[derive(Debug)]
struct FlakyProbe {
    attempts: AtomicUsize,
    pass_on_attempt: usize,
}

#[async_trait]
impl LocalProbe for FlakyProbe {
    async fn file_exists(&self, _path: &str) -> bool {
        self.attempts.fetch_add(1, Ordering::SeqCst) + 1 >= self.pass_on_attempt
    }

    async fn file_blake3(&self, _path: &str) -> Option<String> {
        None
    }

    async fn process_running(&self, _name: &str) -> bool {
        false
    }

    async fn port_listening(&self, _port: u16) -> bool {
        false
    }

    async fn env_var(&self, _name: &str) -> Option<String> {
        None
    }

    async fn command_exit_code(&self, _cmd: &str, _args: &[String]) -> Option<i32> {
        None
    }
}

#[derive(Debug)]
struct SlowProbe {
    sleep_ms: u64,
}

#[async_trait]
impl LocalProbe for SlowProbe {
    async fn file_exists(&self, _path: &str) -> bool {
        tokio::time::sleep(Duration::from_millis(self.sleep_ms)).await;
        true
    }

    async fn file_blake3(&self, _path: &str) -> Option<String> {
        None
    }

    async fn process_running(&self, _name: &str) -> bool {
        false
    }

    async fn port_listening(&self, _port: u16) -> bool {
        false
    }

    async fn env_var(&self, _name: &str) -> Option<String> {
        None
    }

    async fn command_exit_code(&self, _cmd: &str, _args: &[String]) -> Option<i32> {
        None
    }
}

#[tokio::test]
async fn all_file_exists_and_service_active_both_passes() -> TestResult {
    let probe = Arc::new(
        ScriptedProbe::default()
            .with_file("/tmp/aios-ok", true)
            .with_service("nginx", true),
    );
    let grammar =
        VerificationGrammar::All(vec![file_exists("/tmp/aios-ok"), service_active("nginx")]);

    let result = executor(probe, 1_000).execute(&grammar, &context(2)).await;

    assert_eq!(result.status, VerificationStatus::Passed);
    assert_eq!(result.per_primitive.len(), 2);
    assert!(result
        .per_primitive
        .iter()
        .all(|primitive| primitive.passed));
    Ok(())
}

#[tokio::test]
async fn all_fails_and_short_circuits_remaining_terms() -> TestResult {
    let probe = Arc::new(
        ScriptedProbe::default()
            .with_file("/tmp/missing", false)
            .with_service("nginx", true),
    );
    let grammar =
        VerificationGrammar::All(vec![file_exists("/tmp/missing"), service_active("nginx")]);

    let result = executor(probe.clone(), 1_000)
        .execute(&grammar, &context(2))
        .await;

    assert_eq!(result.status, VerificationStatus::Failed);
    assert_eq!(result.per_primitive.len(), 2);
    assert_eq!(result.per_primitive[1].elapsed_ms, 0);
    assert_eq!(probe.service_call_count("nginx"), 0);
    Ok(())
}

#[tokio::test]
async fn any_first_passes_and_short_circuits_remaining_terms() -> TestResult {
    let probe = Arc::new(
        ScriptedProbe::default()
            .with_file("/tmp/aios-ok", true)
            .with_service("nginx", false),
    );
    let grammar =
        VerificationGrammar::Any(vec![file_exists("/tmp/aios-ok"), service_active("nginx")]);

    let result = executor(probe.clone(), 1_000)
        .execute(&grammar, &context(2))
        .await;

    assert_eq!(result.status, VerificationStatus::Passed);
    assert_eq!(result.per_primitive.len(), 2);
    assert_eq!(result.per_primitive[1].elapsed_ms, 0);
    assert_eq!(probe.service_call_count("nginx"), 0);
    Ok(())
}

#[tokio::test]
async fn any_all_fail_returns_failed() -> TestResult {
    let probe = Arc::new(
        ScriptedProbe::default()
            .with_file("/tmp/missing", false)
            .with_service("nginx", false),
    );
    let grammar =
        VerificationGrammar::Any(vec![file_exists("/tmp/missing"), service_active("nginx")]);

    let result = executor(probe, 1_000).execute(&grammar, &context(2)).await;

    assert_eq!(result.status, VerificationStatus::Failed);
    assert_eq!(result.per_primitive.len(), 2);
    Ok(())
}

#[tokio::test]
async fn not_file_exists_passes_when_inner_fails() -> TestResult {
    let probe = Arc::new(ScriptedProbe::default().with_file("/tmp/missing", false));
    let grammar = VerificationGrammar::Not(Box::new(file_exists("/tmp/missing")));

    let result = executor(probe, 1_000).execute(&grammar, &context(2)).await;

    assert_eq!(result.status, VerificationStatus::Passed);
    Ok(())
}

#[tokio::test]
async fn not_file_exists_fails_when_inner_passes() -> TestResult {
    let probe = Arc::new(ScriptedProbe::default().with_file("/tmp/aios-ok", true));
    let grammar = VerificationGrammar::Not(Box::new(file_exists("/tmp/aios-ok")));

    let result = executor(probe, 1_000).execute(&grammar, &context(2)).await;

    assert_eq!(result.status, VerificationStatus::Failed);
    Ok(())
}

#[tokio::test]
async fn eventually_tier3_probe_error_retries_until_window_then_probe_error() -> TestResult {
    let grammar = eventually(http_ok(), 1_000, 100);

    let result = executor(Arc::new(ScriptedProbe::default()), 100)
        .execute(&grammar, &context(2))
        .await;

    assert_eq!(result.status, VerificationStatus::ProbeError);
    assert_eq!(result.per_primitive.len(), 1);
    assert!(result.per_primitive[0]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("retry_count=")));
    Ok(())
}

#[tokio::test]
async fn eventually_retries_until_mock_probe_passes() -> TestResult {
    let probe = Arc::new(FlakyProbe {
        attempts: AtomicUsize::new(0),
        pass_on_attempt: 3,
    });
    let grammar = eventually(file_exists("/tmp/eventual"), 1_000, 150);

    let result = executor(probe.clone(), 100)
        .execute(&grammar, &context(2))
        .await;

    assert_eq!(result.status, VerificationStatus::Passed);
    assert_eq!(probe.attempts.load(Ordering::SeqCst), 3);
    assert!(result.per_primitive[0]
        .actual
        .get("retry_count")
        .and_then(Value::as_u64)
        .is_some_and(|count| count >= 2));
    Ok(())
}

#[tokio::test]
async fn nested_combinators_evaluate_correctly() -> TestResult {
    let probe = Arc::new(
        ScriptedProbe::default()
            .with_file("/tmp/p1", false)
            .with_file("/tmp/p2", true)
            .with_file("/tmp/p3", false),
    );
    let grammar = VerificationGrammar::All(vec![
        VerificationGrammar::Any(vec![file_exists("/tmp/p1"), file_exists("/tmp/p2")]),
        VerificationGrammar::Not(Box::new(file_exists("/tmp/p3"))),
    ]);

    let result = executor(probe, 1_000).execute(&grammar, &context(2)).await;

    assert_eq!(result.status, VerificationStatus::Passed);
    assert_eq!(result.per_primitive.len(), 3);
    Ok(())
}

#[tokio::test]
async fn primitive_timeout_is_enforced() -> TestResult {
    let grammar = file_exists("/tmp/slow");

    let result = executor(Arc::new(SlowProbe { sleep_ms: 80 }), 20)
        .execute(&grammar, &context(1))
        .await;

    assert_eq!(result.status, VerificationStatus::Timeout);
    assert!(result.per_primitive[0]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("TIMEOUT after 20ms")));
    Ok(())
}

#[tokio::test]
async fn verification_result_records_total_elapsed_ms() -> TestResult {
    let grammar = file_exists("/tmp/slow");

    let result = executor(Arc::new(SlowProbe { sleep_ms: 25 }), 100)
        .execute(&grammar, &context(1))
        .await;

    assert_eq!(result.status, VerificationStatus::Passed);
    assert!(result.duration_ms >= 20);
    assert!(result.completed_at >= result.started_at);
    Ok(())
}

#[tokio::test]
async fn probe_error_under_not_does_not_propagate_to_top_level() -> TestResult {
    let grammar = VerificationGrammar::All(vec![
        VerificationGrammar::Not(Box::new(http_ok())),
        file_exists("/tmp/aios-ok"),
    ]);

    let result = executor(Arc::new(ScriptedProbe::default()), 100)
        .execute(&grammar, &context(1))
        .await;

    assert_eq!(result.status, VerificationStatus::Failed);
    assert_ne!(result.status, VerificationStatus::ProbeError);
    Ok(())
}

#[tokio::test]
async fn load_bearing_tier3_probe_error_sets_top_level_probe_error() -> TestResult {
    let probe = Arc::new(ScriptedProbe::default().with_file("/tmp/aios-ok", true));
    let grammar = VerificationGrammar::All(vec![file_exists("/tmp/aios-ok"), http_ok()]);

    let result = executor(probe, 100).execute(&grammar, &context(1)).await;

    assert_eq!(result.status, VerificationStatus::ProbeError);
    Ok(())
}

#[tokio::test]
async fn same_grammar_context_and_probe_are_deterministic_except_generated_metadata() -> TestResult
{
    let probe = Arc::new(ScriptedProbe::default().with_file("/tmp/aios-ok", true));
    let grammar = file_exists("/tmp/aios-ok");
    let context = context(1);
    let executor = executor(probe, 1_000);

    let first = executor.execute(&grammar, &context).await;
    let second = executor.execute(&grammar, &context).await;

    assert_eq!(first.status, second.status);
    // elapsed_ms is generated metadata (wall clock) — normalize before comparing
    fn strip_elapsed(results: &[PrimitiveResult]) -> Vec<PrimitiveResult> {
        results
            .iter()
            .cloned()
            .map(|mut result| {
                result.elapsed_ms = 0;
                result
            })
            .collect()
    }
    assert_eq!(
        strip_elapsed(&first.per_primitive),
        strip_elapsed(&second.per_primitive)
    );
    assert_eq!(first.intent_id, second.intent_id);
    assert_eq!(first.action_id, second.action_id);
    Ok(())
}
