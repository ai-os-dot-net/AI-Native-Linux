//! Live backend health monitoring — periodic health-check loop that pings
//! Ollama/vLLM adapters, measures latency, updates RouterState and
//! CircuitBreakerRegistry, emits evidence on state transitions.
//!
//! # State machine
//!
//! ```text
//!   (start) → Healthy (first success)
//!   Healthy → DegradedLatency (latency > degraded_threshold_ms)
//!   DegradedLatency → Unhealthy (consecutive_failures > down_consecutive_failures)
//!   Unhealthy → DegradedLatency (first success after being down)
//!   DegradedLatency → Healthy (latency ≤ degraded_threshold_ms)
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;

use crate::adapter::ollama::OllamaAdapter;
use crate::adapter::vllm::VllmAdapter;
use crate::breaker_registry::CircuitBreakerRegistry;
use crate::evidence_emit::CognitiveEvidenceEmitter;
use crate::router_state::RouterState;
use crate::routing::{BackendHealthState, ModelBackendKind, ProviderClass};

/// Configuration for the health monitor loop.
#[derive(Debug, Clone)]
pub struct HealthMonitorConfig {
    /// Interval between full health-check sweeps.
    pub check_interval: std::time::Duration,
    /// Per-check request timeout.
    pub timeout: std::time::Duration,
    /// Latency threshold in ms — above this the backend is considered degraded.
    pub degraded_threshold_ms: u64,
    /// Consecutive failures that trigger an unhealthy transition.
    pub down_consecutive_failures: u32,
}

impl Default for HealthMonitorConfig {
    fn default() -> Self {
        Self {
            check_interval: std::time::Duration::from_secs(30),
            timeout: std::time::Duration::from_secs(5),
            degraded_threshold_ms: 500,
            down_consecutive_failures: 3,
        }
    }
}

/// Per-backend health snapshot produced after each check sweep.
#[derive(Debug, Clone)]
pub struct BackendHealthSnapshot {
    /// Provider class of this backend.
    pub provider_class: ProviderClass,
    /// Observed health state.
    pub state: BackendHealthState,
    /// Latency of the last successful check in milliseconds.
    pub last_latency_ms: u64,
    /// Number of consecutive failures since last success.
    pub consecutive_failures: u32,
    /// When the last check completed.
    pub last_checked: DateTime<Utc>,
    /// Error message from the last failed check, if any.
    pub last_error: Option<String>,
}

impl BackendHealthSnapshot {
    #[must_use]
    pub fn new(provider_class: ProviderClass) -> Self {
        Self {
            provider_class,
            state: BackendHealthState::Healthy,
            last_latency_ms: 0,
            consecutive_failures: 0,
            last_checked: Utc::now(),
            last_error: None,
        }
    }
}

/// Aggregate health report from a single check sweep.
#[derive(Debug, Clone)]
pub struct HealthReport {
    /// Unique report identifier (`hrpt_<ULID>`).
    pub report_id: String,
    /// When the report was generated.
    pub timestamp: DateTime<Utc>,
    /// Per-backend health snapshots.
    pub backends: HashMap<ProviderClass, BackendHealthSnapshot>,
    /// `true` when all tracked backends are Healthy.
    pub overall_healthy: bool,
}

impl HealthReport {
    #[must_use]
    pub fn new(backends: HashMap<ProviderClass, BackendHealthSnapshot>) -> Self {
        let overall_healthy = backends
            .values()
            .all(|s| s.state == BackendHealthState::Healthy);
        Self {
            report_id: format!("hrpt_{}", ulid::Ulid::new()),
            timestamp: Utc::now(),
            backends,
            overall_healthy,
        }
    }
}

/// Tracks per-backend state between health-check sweeps.
#[derive(Debug, Clone)]
struct BackendTracker {
    provider_class: ProviderClass,
    backend_kind: ModelBackendKind,
    current_state: BackendHealthState,
    consecutive_failures: u32,
    last_latency_ms: u64,
    last_error: Option<String>,
    last_checked: DateTime<Utc>,
}

impl BackendTracker {
    fn new(provider_class: ProviderClass, backend_kind: ModelBackendKind) -> Self {
        Self {
            provider_class,
            backend_kind,
            current_state: BackendHealthState::Healthy,
            consecutive_failures: 0,
            last_latency_ms: 0,
            last_error: None,
            last_checked: Utc::now(),
        }
    }
}

/// Live backend health monitor with periodic health-check loop.
///
/// Spawns a background `tokio` task that pings each configured backend adapter
/// on a configurable interval, measures latency, updates the `RouterState` and
/// `CircuitBreakerRegistry`, and emits evidence on state transitions.
pub struct HealthMonitor {
    config: HealthMonitorConfig,
    ollama_adapter: Option<Arc<OllamaAdapter>>,
    vllm_adapter: Option<Arc<VllmAdapter>>,
    shutdown: Arc<Notify>,
    breaker_registry: Arc<CircuitBreakerRegistry>,
    router_state: Arc<RouterState>,
    evidence_emitter: Option<Arc<CognitiveEvidenceEmitter>>,
    handle: RwLock<Option<JoinHandle<()>>>,
}

impl HealthMonitor {
    /// Create a new `HealthMonitor` with the given configuration.
    #[must_use]
    pub fn new(
        config: HealthMonitorConfig,
        breaker_registry: Arc<CircuitBreakerRegistry>,
        router_state: Arc<RouterState>,
    ) -> Self {
        Self {
            config,
            ollama_adapter: None,
            vllm_adapter: None,
            shutdown: Arc::new(Notify::new()),
            breaker_registry,
            router_state,
            evidence_emitter: None,
            handle: RwLock::new(None),
        }
    }

    /// Attach an Ollama adapter for health checks.
    #[must_use]
    pub fn with_ollama(mut self, adapter: Arc<OllamaAdapter>) -> Self {
        self.ollama_adapter = Some(adapter);
        self
    }

    /// Attach a vLLM adapter for health checks.
    #[must_use]
    pub fn with_vllm(mut self, adapter: Arc<VllmAdapter>) -> Self {
        self.vllm_adapter = Some(adapter);
        self
    }

    /// Attach an evidence emitter for state transition evidence.
    #[must_use]
    pub fn with_evidence_emitter(mut self, emitter: Arc<CognitiveEvidenceEmitter>) -> Self {
        self.evidence_emitter = Some(emitter);
        self
    }

    /// Start the background monitoring loop.
    ///
    /// Spawns a `tokio` task that loops every `check_interval`, pinging each
    /// configured adapter and recording outcomes. Does nothing if the loop is
    /// already running.
    pub async fn start_monitoring(&self) {
        let mut guard = self.handle.write().await;
        if guard.is_some() {
            return;
        }

        let config = self.config.clone();
        let ollama = self.ollama_adapter.clone();
        let vllm = self.vllm_adapter.clone();
        let shutdown = Arc::clone(&self.shutdown);
        let breaker_registry = Arc::clone(&self.breaker_registry);
        let router_state = Arc::clone(&self.router_state);
        let evidence_emitter = self.evidence_emitter.clone();

        let handle = tokio::spawn(async move {
            run_monitoring_loop(
                config,
                ollama,
                vllm,
                shutdown,
                breaker_registry,
                router_state,
                evidence_emitter,
            )
            .await;
        });

        *guard = Some(handle);
    }

    /// Trigger graceful shutdown of the monitoring loop.
    ///
    /// Awaiting this completes after the loop task has exited.
    ///
    /// # Errors
    ///
    /// Returns `JoinError` if the spawned task panicked.
    pub async fn stop(&self) -> Result<(), tokio::task::JoinError> {
        self.shutdown.notify_one();

        let handle = {
            let mut guard = self.handle.write().await;
            guard.take()
        };

        if let Some(h) = handle {
            h.await
        } else {
            Ok(())
        }
    }
}

impl std::fmt::Debug for HealthMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthMonitor")
            .field("config", &self.config)
            .field("ollama_adapter", &self.ollama_adapter.is_some())
            .field("vllm_adapter", &self.vllm_adapter.is_some())
            .field("evidence_emitter", &self.evidence_emitter.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Monitoring loop internals
// ---------------------------------------------------------------------------

async fn run_monitoring_loop(
    config: HealthMonitorConfig,
    ollama_adapter: Option<Arc<OllamaAdapter>>,
    vllm_adapter: Option<Arc<VllmAdapter>>,
    shutdown: Arc<Notify>,
    breaker_registry: Arc<CircuitBreakerRegistry>,
    router_state: Arc<RouterState>,
    evidence_emitter: Option<Arc<CognitiveEvidenceEmitter>>,
) {
    let mut trackers: Vec<BackendTracker> = Vec::new();

    if ollama_adapter.is_some() {
        trackers.push(BackendTracker::new(
            ProviderClass::Ollama,
            ModelBackendKind::LocalGpu,
        ));
    }
    if vllm_adapter.is_some() {
        trackers.push(BackendTracker::new(
            ProviderClass::Vllm,
            ModelBackendKind::LocalGpu,
        ));
    }

    loop {
        tokio::select! {
            () = shutdown.notified() => {
                tracing::info!(
                    target: "aios_cognitive.health_monitor",
                    "health monitor loop shutting down"
                );
                break;
            }
            () = tokio::time::sleep(config.check_interval) => {
                run_single_sweep(
                    &config,
                    ollama_adapter.as_deref(),
                    vllm_adapter.as_deref(),
                    &mut trackers,
                    &breaker_registry,
                    &router_state,
                    evidence_emitter.as_deref(),
                )
                .await;
            }
        }
    }
}

/// Run a single health-check sweep across all configured backends.
async fn run_single_sweep(
    config: &HealthMonitorConfig,
    ollama: Option<&OllamaAdapter>,
    vllm: Option<&VllmAdapter>,
    trackers: &mut [BackendTracker],
    breaker_registry: &CircuitBreakerRegistry,
    router_state: &RouterState,
    evidence_emitter: Option<&CognitiveEvidenceEmitter>,
) {
    for tracker in trackers.iter_mut() {
        let (healthy, latency_ms, error_msg) = match tracker.provider_class {
            ProviderClass::Ollama => {
                if let Some(adapter) = ollama {
                    check_ollama(adapter, config.timeout).await
                } else {
                    continue;
                }
            }
            ProviderClass::Vllm => {
                if let Some(adapter) = vllm {
                    check_vllm(adapter, config.timeout).await
                } else {
                    continue;
                }
            }
            _ => continue,
        };

        let new_state =
            compute_new_state(tracker.current_state, healthy, latency_ms, tracker, config);

        tracker.last_latency_ms = latency_ms;
        tracker.last_checked = Utc::now();

        if healthy {
            tracker.consecutive_failures = 0;
            tracker.last_error = None;
        } else {
            tracker.consecutive_failures += 1;
            tracker.last_error = error_msg;
        }

        // Report to circuit breaker.
        let _ = breaker_registry
            .observe_and_update(tracker.backend_kind, healthy, latency_ms)
            .await;

        // Update RouterState.
        router_state
            .observe_invocation(tracker.backend_kind, healthy)
            .await;

        // Emit evidence on state transition.
        if new_state != tracker.current_state {
            if let Some(emitter) = evidence_emitter {
                let _ = emitter
                    .emit_backend_health_changed(
                        tracker.backend_kind,
                        tracker.provider_class,
                        tracker.current_state,
                        new_state,
                        tracker.last_latency_ms,
                        tracker.consecutive_failures,
                        tracker.last_error.as_deref(),
                    )
                    .await;
            }
        }

        tracker.current_state = new_state;
    }
}

/// Ping the Ollama adapter's health endpoint and measure latency.
async fn check_ollama(
    adapter: &OllamaAdapter,
    timeout: std::time::Duration,
) -> (bool, u64, Option<String>) {
    let start = Instant::now();
    let result = tokio::time::timeout(timeout, adapter.health_check()).await;
    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(true)) => (true, latency_ms, None),
        Ok(Ok(false)) => (
            false,
            latency_ms,
            Some("ollama health check returned false".into()),
        ),
        Ok(Err(e)) => (
            false,
            latency_ms,
            Some(format!("ollama health check error: {e}")),
        ),
        Err(_elapsed) => (
            false,
            latency_ms,
            Some("ollama health check timed out".into()),
        ),
    }
}

/// Ping the vLLM adapter's health endpoint and measure latency.
async fn check_vllm(
    adapter: &VllmAdapter,
    timeout: std::time::Duration,
) -> (bool, u64, Option<String>) {
    let start = Instant::now();
    let result = tokio::time::timeout(timeout, adapter.health_check()).await;
    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(true)) => (true, latency_ms, None),
        Ok(Ok(false)) => (
            false,
            latency_ms,
            Some("vllm health check returned false".into()),
        ),
        Ok(Err(e)) => (
            false,
            latency_ms,
            Some(format!("vllm health check error: {e}")),
        ),
        Err(_elapsed) => (
            false,
            latency_ms,
            Some("vllm health check timed out".into()),
        ),
    }
}

/// Compute the next health state based on the check outcome, current state, and config.
#[must_use]
fn compute_new_state(
    current_state: BackendHealthState,
    healthy: bool,
    latency_ms: u64,
    tracker: &BackendTracker,
    config: &HealthMonitorConfig,
) -> BackendHealthState {
    let _ = tracker; // keep for future extension fields

    if healthy {
        let high_latency = latency_ms > config.degraded_threshold_ms;
        match current_state {
            BackendHealthState::Unhealthy | BackendHealthState::Suspended => {
                BackendHealthState::DegradedLatency
            }
            BackendHealthState::DegradedLatency | BackendHealthState::DegradedAvailability => {
                if high_latency {
                    BackendHealthState::DegradedLatency
                } else {
                    BackendHealthState::Healthy
                }
            }
            BackendHealthState::Healthy => {
                if high_latency {
                    BackendHealthState::DegradedLatency
                } else {
                    BackendHealthState::Healthy
                }
            }
        }
    } else {
        let new_failures = tracker.consecutive_failures + 1;
        if new_failures >= config.down_consecutive_failures {
            BackendHealthState::Unhealthy
        } else if current_state == BackendHealthState::Healthy {
            BackendHealthState::DegradedLatency
        } else {
            current_state
        }
    }
}

/// Run a full sweep and return a `HealthReport` for tests.
#[cfg(test)]
#[must_use]
fn build_report(trackers: &[BackendTracker]) -> HealthReport {
    let mut backends = HashMap::new();
    for t in trackers {
        backends.insert(
            t.provider_class,
            BackendHealthSnapshot {
                provider_class: t.provider_class,
                state: t.current_state,
                last_latency_ms: t.last_latency_ms,
                consecutive_failures: t.consecutive_failures,
                last_checked: t.last_checked,
                last_error: t.last_error.clone(),
            },
        );
    }
    HealthReport::new(backends)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        clippy::unwrap_in_result,
        reason = "panic-on-failure is the idiomatic test signal"
    )]

    use super::*;

    // -----------------------------------------------------------------------
    // BackendHealthSnapshot defaults
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_defaults_to_healthy_zero_failures() {
        let snap = BackendHealthSnapshot::new(ProviderClass::Ollama);
        assert_eq!(snap.state, BackendHealthState::Healthy);
        assert_eq!(snap.consecutive_failures, 0);
        assert_eq!(snap.last_latency_ms, 0);
        assert!(snap.last_error.is_none());
    }

    // -----------------------------------------------------------------------
    // HealthReport generation
    // -----------------------------------------------------------------------

    #[test]
    fn health_report_from_snapshots() {
        let mut backends = HashMap::new();
        backends.insert(
            ProviderClass::Ollama,
            BackendHealthSnapshot::new(ProviderClass::Ollama),
        );
        backends.insert(
            ProviderClass::Vllm,
            BackendHealthSnapshot::new(ProviderClass::Vllm),
        );

        let report = HealthReport::new(backends);
        assert!(report.report_id.starts_with("hrpt_"));
        assert!(report.overall_healthy);
        assert_eq!(report.backends.len(), 2);
    }

    #[test]
    fn health_report_detects_unhealthy_backend() {
        let mut backends = HashMap::new();
        let mut snap = BackendHealthSnapshot::new(ProviderClass::Ollama);
        snap.state = BackendHealthState::Unhealthy;
        backends.insert(ProviderClass::Ollama, snap);
        backends.insert(
            ProviderClass::Vllm,
            BackendHealthSnapshot::new(ProviderClass::Vllm),
        );

        let report = HealthReport::new(backends);
        assert!(!report.overall_healthy);
    }

    // -----------------------------------------------------------------------
    // State transitions: Healthy → DegradedLatency on high latency
    // -----------------------------------------------------------------------

    #[test]
    fn healthy_to_degraded_on_high_latency() {
        let config = HealthMonitorConfig {
            degraded_threshold_ms: 100,
            ..Default::default()
        };
        let tracker = BackendTracker::new(ProviderClass::Ollama, ModelBackendKind::LocalGpu);
        let new_state = compute_new_state(
            BackendHealthState::Healthy,
            true, // healthy
            250,  // latency above threshold
            &tracker,
            &config,
        );
        assert_eq!(new_state, BackendHealthState::DegradedLatency);
    }

    // -----------------------------------------------------------------------
    // State transitions: DegradedLatency → Unhealthy on consecutive failures
    // -----------------------------------------------------------------------

    #[test]
    fn degraded_to_down_on_consecutive_failures() {
        let config = HealthMonitorConfig {
            down_consecutive_failures: 3,
            ..Default::default()
        };
        let mut tracker = BackendTracker::new(ProviderClass::Ollama, ModelBackendKind::LocalGpu);
        tracker.current_state = BackendHealthState::DegradedLatency;
        tracker.consecutive_failures = 2; // 2 prior failures

        let new_state = compute_new_state(
            BackendHealthState::DegradedLatency,
            false, // unhealthy
            0,
            &tracker,
            &config,
        );
        // 2 prior + 1 = 3 → Unhealthy
        assert_eq!(new_state, BackendHealthState::Unhealthy);
    }

    // -----------------------------------------------------------------------
    // State transitions: Unhealthy → DegradedLatency on first recovery
    // -----------------------------------------------------------------------

    #[test]
    fn down_to_degraded_on_first_success() {
        let config = HealthMonitorConfig::default();
        let tracker = BackendTracker::new(ProviderClass::Ollama, ModelBackendKind::LocalGpu);

        let new_state = compute_new_state(
            BackendHealthState::Unhealthy,
            true, // first success
            100,
            &tracker,
            &config,
        );
        assert_eq!(new_state, BackendHealthState::DegradedLatency);
    }

    // -----------------------------------------------------------------------
    // State transitions: DegradedLatency → Healthy on latency recovery
    // -----------------------------------------------------------------------

    #[test]
    fn degraded_to_healthy_on_latency_recovery() {
        let config = HealthMonitorConfig {
            degraded_threshold_ms: 500,
            ..Default::default()
        };
        let tracker = BackendTracker::new(ProviderClass::Ollama, ModelBackendKind::LocalGpu);

        let new_state = compute_new_state(
            BackendHealthState::DegradedLatency,
            true, // healthy
            100,  // latency below threshold
            &tracker,
            &config,
        );
        assert_eq!(new_state, BackendHealthState::Healthy);
    }

    // -----------------------------------------------------------------------
    // State transitions: Healthy stays Healthy on normal latency
    // -----------------------------------------------------------------------

    #[test]
    fn healthy_stays_healthy_on_normal_latency() {
        let config = HealthMonitorConfig {
            degraded_threshold_ms: 500,
            ..Default::default()
        };
        let tracker = BackendTracker::new(ProviderClass::Ollama, ModelBackendKind::LocalGpu);

        let new_state = compute_new_state(
            BackendHealthState::Healthy,
            true, // healthy
            50,   // latency below threshold
            &tracker,
            &config,
        );
        assert_eq!(new_state, BackendHealthState::Healthy);
    }

    // -----------------------------------------------------------------------
    // HealthMonitor construction
    // -----------------------------------------------------------------------

    #[test]
    fn health_monitor_constructs_with_config() {
        let config = HealthMonitorConfig {
            check_interval: std::time::Duration::from_secs(10),
            timeout: std::time::Duration::from_secs(2),
            degraded_threshold_ms: 300,
            down_consecutive_failures: 5,
        };
        let monitor = HealthMonitor::new(
            config,
            Arc::new(CircuitBreakerRegistry::new_with_defaults()),
            Arc::new(RouterState::new()),
        );
        assert_eq!(
            monitor.config.check_interval,
            std::time::Duration::from_secs(10)
        );
        assert_eq!(monitor.config.timeout, std::time::Duration::from_secs(2));
    }

    // -----------------------------------------------------------------------
    // stop() without start (no-op)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn stop_without_start_is_noop() {
        let monitor = HealthMonitor::new(
            HealthMonitorConfig::default(),
            Arc::new(CircuitBreakerRegistry::new_with_defaults()),
            Arc::new(RouterState::new()),
        );
        let result = monitor.stop().await;
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // start + stop integration
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn start_and_stop_monitor() {
        let config = HealthMonitorConfig {
            check_interval: std::time::Duration::from_millis(100),
            ..Default::default()
        };
        let monitor = HealthMonitor::new(
            config,
            Arc::new(CircuitBreakerRegistry::new_with_defaults()),
            Arc::new(RouterState::new()),
        );
        monitor.start_monitoring().await;
        // Let it run briefly.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let result = monitor.stop().await;
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // HealthReport::new
    // -----------------------------------------------------------------------

    #[test]
    fn health_report_new_generates_unique_id() {
        let backends = HashMap::new();
        let r1 = HealthReport::new(backends.clone());
        let r2 = HealthReport::new(backends);
        assert_ne!(r1.report_id, r2.report_id);
    }

    // -----------------------------------------------------------------------
    // State transitions: Degraded stays Degraded on continued high latency
    // -----------------------------------------------------------------------

    #[test]
    fn degraded_stays_degraded_on_continued_high_latency() {
        let config = HealthMonitorConfig {
            degraded_threshold_ms: 100,
            ..Default::default()
        };
        let tracker = BackendTracker::new(ProviderClass::Ollama, ModelBackendKind::LocalGpu);

        let new_state = compute_new_state(
            BackendHealthState::DegradedLatency,
            true, // healthy
            250,  // still above threshold
            &tracker,
            &config,
        );
        assert_eq!(new_state, BackendHealthState::DegradedLatency);
    }

    // -----------------------------------------------------------------------
    // build_report produces correct report
    // -----------------------------------------------------------------------

    #[test]
    fn build_report_maps_all_trackers() {
        let trackers = vec![
            BackendTracker::new(ProviderClass::Ollama, ModelBackendKind::LocalGpu),
            BackendTracker::new(ProviderClass::Vllm, ModelBackendKind::LocalGpu),
        ];
        let report = build_report(&trackers);
        assert_eq!(report.backends.len(), 2);
        assert!(report.backends.contains_key(&ProviderClass::Ollama));
        assert!(report.backends.contains_key(&ProviderClass::Vllm));
    }
}
