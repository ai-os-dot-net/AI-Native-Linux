//! Cross‑machine healing coordination for AIOS Rev.10.
//!
//! This module implements the fleet‑wide healing logic: when a component on a
//! remote host becomes unhealthy, the cross‑machine healing engine decides the
//! correct autonomous action — restart, failover, isolate, or escalate — and
//! coordinates across the registered remote host registry.
//!
//! ## Architecture
//!
//! ```text
//! CrossMachineHealing              ← top-level coordinator
//!   ├── RemoteHost                  ← per-host health registry entry
//!   │     └── RemoteComponentHealth ← per-component observed state
//!   └── HealingScope               ← constrains which hosts are eligible
//!
//! HealDecision                     ← what the coordinator decided
//! HealthState                      ← Healthy / Degraded / Failed / Unknown
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::AutonomousError;

// ── Healing scope ──────────────────────────────────────────────────────────

/// Governs which hosts the cross‑machine healing coordinator is allowed to act on.
///
/// * [`HealingScope::LocalOnly`] — only the local host (no remote healing).
/// * [`HealingScope::SameCluster`] — all hosts sharing the same cluster id.
/// * [`HealingScope::FullFleet`] — every registered host regardless of cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealingScope {
    /// Restrict healing to the local machine only.
    LocalOnly,
    /// Allow healing across hosts that share a cluster id.
    SameCluster,
    /// Allow healing across the entire registered fleet.
    FullFleet,
}

// ── Health state vocabulary ────────────────────────────────────────────────

/// Observed health of a single remote component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthState {
    /// Component is operating normally.
    Healthy,
    /// Component is operational but exhibiting degraded performance.
    Degraded,
    /// Component has failed and is non‑responsive.
    Failed,
    /// Component health cannot be determined (e.g. network partition).
    Unknown,
}

// ── Remote component health snapshot ───────────────────────────────────────

/// A point‑in‑time health observation of a single component on a remote host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteComponentHealth {
    /// Logical component identifier (e.g. `"kernel-monitor"`, `"grpc-gateway"`).
    pub component_id: String,
    /// Host id this component runs on.
    pub host_id: String,
    /// Current health state.
    pub state: HealthState,
    /// Timestamp of the most recent observation.
    pub last_seen: DateTime<Utc>,
    /// Consecutive failure observations since the last healthy signal.
    pub failure_count: u64,
    /// Number of restart attempts already performed for this component.
    pub restart_attempts: u64,
}

impl RemoteComponentHealth {
    /// Create a new health snapshot for a component.
    #[must_use]
    pub fn new(
        component_id: impl Into<String>,
        host_id: impl Into<String>,
        state: HealthState,
    ) -> Self {
        Self {
            component_id: component_id.into(),
            host_id: host_id.into(),
            state,
            last_seen: Utc::now(),
            failure_count: 0,
            restart_attempts: 0,
        }
    }

    /// Record a failed observation — increment the failure counter.
    pub fn record_failure(&mut self) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_seen = Utc::now();
    }

    /// Record a restart attempt — increment the restart counter.
    pub fn record_restart(&mut self) {
        self.restart_attempts = self.restart_attempts.saturating_add(1);
    }
}

// ── Remote host ────────────────────────────────────────────────────────────

/// A remote host registered in the cross‑machine healing fleet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteHost {
    /// Unique host identifier within the fleet.
    pub host_id: String,
    /// Cluster identifier for scoped healing.
    pub cluster_id: String,
    /// Whether the host was reachable at the last heartbeat.
    pub is_reachable: bool,
    /// Timestamp of the most recent heartbeat.
    pub last_heartbeat: DateTime<Utc>,
    /// Per‑component health registry keyed by `component_id`.
    pub component_health: HashMap<String, RemoteComponentHealth>,
}

impl RemoteHost {
    /// Create a new remote host entry.
    #[must_use]
    pub fn new(host_id: impl Into<String>, cluster_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            cluster_id: cluster_id.into(),
            is_reachable: true,
            last_heartbeat: Utc::now(),
            component_health: HashMap::new(),
        }
    }
}

// ── Heal decision ──────────────────────────────────────────────────────────

/// Autonomous healing action decided by the cross‑machine coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HealDecision {
    /// Restart the component on its current host.
    RestartLocally,
    /// Fail the component over to the named target host.
    FailoverTo(String),
    /// Quarantine the host — remove it from the active fleet.
    Isolate,
    /// Escalate to the fleet operator for manual intervention.
    Escalate,
}

// ── Cross‑machine healing coordinator ──────────────────────────────────────

/// Top‑level cross‑machine healing coordinator.
///
/// Maintains a registry of remote hosts, receives per‑component health
/// observations, decides autonomous healing actions, and executes them
/// within the configured [`HealingScope`].
pub struct CrossMachineHealing {
    /// Whether a local self‑healing driver is present (stub).
    pub has_local_healing: bool,
    /// Registered remote hosts in the fleet.
    pub remote_hosts: Vec<RemoteHost>,
    /// Current healing scope.
    pub healing_scope: HealingScope,
}

impl CrossMachineHealing {
    /// Create a new cross‑machine healing coordinator with default
    /// [`HealingScope::LocalOnly`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            has_local_healing: false,
            remote_hosts: Vec::new(),
            healing_scope: HealingScope::LocalOnly,
        }
    }

    /// Return a high‑level fleet health status string for the orchestrator.
    #[must_use]
    pub fn fleet_health(&self) -> String {
        if self.remote_hosts.is_empty() {
            return "Unknown".into();
        }

        let total = self.remote_hosts.len();
        let reachable = self.remote_hosts.iter().filter(|h| h.is_reachable).count();

        let has_failed = self.remote_hosts.iter().any(|h| {
            h.component_health
                .values()
                .any(|c| c.state == HealthState::Failed)
        });

        let has_degraded = self.remote_hosts.iter().any(|h| {
            h.component_health
                .values()
                .any(|c| c.state == HealthState::Degraded)
        });

        if reachable == 0 {
            "QuorumLost".into()
        } else if has_failed {
            "Critical".into()
        } else if has_degraded {
            "Degraded".into()
        } else if reachable == total {
            "Healthy".into()
        } else {
            "Degraded".into()
        }
    }

    /// Register a new remote host in the fleet registry.
    ///
    /// If a host with the same `host_id` already exists, this is a no‑op.
    pub fn register_host(&mut self, host_id: &str) {
        if self.remote_hosts.iter().any(|h| h.host_id == host_id) {
            return;
        }
        self.remote_hosts.push(RemoteHost::new(host_id, "default"));
    }

    /// Remove a host from the fleet registry by id.
    pub fn remove_host(&mut self, host_id: &str) {
        self.remote_hosts.retain(|h| h.host_id != host_id);
    }

    /// Find a host by id, returning a reference.
    fn find_host(&self, host_id: &str) -> Option<&RemoteHost> {
        self.remote_hosts.iter().find(|h| h.host_id == host_id)
    }

    /// Find a host by id, returning a mutable reference.
    fn find_host_mut(&mut self, host_id: &str) -> Option<&mut RemoteHost> {
        self.remote_hosts.iter_mut().find(|h| h.host_id == host_id)
    }

    /// Receive and record a health observation for a component on a remote host.
    ///
    /// # Errors
    ///
    /// Returns [`AutonomousError`] if the target host is not registered.
    pub fn observe_remote_health(
        &mut self,
        host_id: &str,
        health: RemoteComponentHealth,
    ) -> Result<(), AutonomousError> {
        let host = self
            .find_host_mut(host_id)
            .ok_or(AutonomousError::HostNotFound {
                host_id: host_id.to_owned(),
            })?;

        host.last_heartbeat = Utc::now();
        host.is_reachable = true;

        let entry = host
            .component_health
            .entry(health.component_id.clone())
            .or_insert_with(|| health.clone());

        entry.state = health.state;
        entry.last_seen = health.last_seen;

        match health.state {
            HealthState::Failed | HealthState::Degraded => {
                entry.record_failure();
            }
            HealthState::Unknown => {
                entry.failure_count = health.failure_count;
            }
            HealthState::Healthy => {
                entry.failure_count = 0;
            }
        }

        Ok(())
    }

    /// Decide whether and how to heal a component on a given host.
    ///
    /// Returns `None` if the component is healthy (no action needed).
    #[must_use]
    pub fn decide_heal(&self, host_id: &str, component_id: &str) -> Option<HealDecision> {
        let host = self.find_host(host_id)?;
        let component = host.component_health.get(component_id)?;

        // Scope gate — LocalOnly prevents remote actions for non‑local hosts.
        if self.healing_scope == HealingScope::LocalOnly {
            return None;
        }

        match component.state {
            HealthState::Healthy => None,

            HealthState::Degraded => {
                if component.restart_attempts < 3 && component.failure_count < 5 {
                    Some(HealDecision::RestartLocally)
                } else {
                    Some(HealDecision::Escalate)
                }
            }

            HealthState::Failed => {
                // Try to find a failover target: another healthy host in the same cluster.
                let failover_target = self
                    .remote_hosts
                    .iter()
                    .find(|h| {
                        h.host_id != host_id && h.is_reachable && h.cluster_id == host.cluster_id
                    })
                    .map(|h| h.host_id.clone());

                match failover_target {
                    Some(target) => Some(HealDecision::FailoverTo(target)),
                    None => {
                        if component.failure_count >= 3 {
                            Some(HealDecision::Isolate)
                        } else {
                            Some(HealDecision::RestartLocally)
                        }
                    }
                }
            }

            HealthState::Unknown => {
                if component.failure_count > 0 {
                    Some(HealDecision::Escalate)
                } else {
                    None
                }
            }
        }
    }

    /// Detect whether multiple hosts are degrading simultaneously
    /// (cascading failure). Returns the host ids that should be isolated.
    #[must_use]
    pub fn cascading_failure_check(&self) -> Vec<String> {
        const CASCADE_THRESHOLD: usize = 2;

        let degraded_hosts: Vec<&RemoteHost> = self
            .remote_hosts
            .iter()
            .filter(|h| {
                h.component_health
                    .values()
                    .any(|c| c.state == HealthState::Failed || c.state == HealthState::Degraded)
            })
            .collect();

        if degraded_hosts.len() >= CASCADE_THRESHOLD {
            degraded_hosts.iter().map(|h| h.host_id.clone()).collect()
        } else {
            Vec::new()
        }
    }

    /// Execute a cross‑machine healing decision.
    ///
    /// # Errors
    ///
    /// Returns an error if the action is not permitted under the current
    /// [`HealingScope`].
    pub fn execute_cross_machine_heal(
        &self,
        decision: HealDecision,
    ) -> Result<(), AutonomousError> {
        match &decision {
            HealDecision::RestartLocally => {
                // RestartLocally is always permitted (it is local).
                Ok(())
            }
            HealDecision::FailoverTo(_target) => {
                if self.healing_scope == HealingScope::LocalOnly {
                    return Err(AutonomousError::ScopeDenied {
                        action: "failover".to_owned(),
                        scope: format!("{self:?}", self = self.healing_scope),
                    });
                }
                Ok(())
            }
            HealDecision::Isolate => {
                if self.healing_scope == HealingScope::LocalOnly {
                    return Err(AutonomousError::ScopeDenied {
                        action: "isolate".to_owned(),
                        scope: format!("{self:?}", self = self.healing_scope),
                    });
                }
                Ok(())
            }
            HealDecision::Escalate => {
                // Escalation is always allowed regardless of scope.
                Ok(())
            }
        }
    }
}

impl Default for CrossMachineHealing {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_health(
        component_id: &str,
        host_id: &str,
        state: HealthState,
        failures: u64,
        restarts: u64,
    ) -> RemoteComponentHealth {
        RemoteComponentHealth {
            component_id: component_id.to_owned(),
            host_id: host_id.to_owned(),
            state,
            last_seen: Utc::now(),
            failure_count: failures,
            restart_attempts: restarts,
        }
    }

    // ── RemoteComponentHealth helpers ──────────────────────────────────

    #[test]
    fn record_failure_increments_counter() {
        let mut health = make_health("kernel", "h1", HealthState::Degraded, 0, 0);
        health.record_failure();
        assert_eq!(health.failure_count, 1);
    }

    #[test]
    fn record_restart_increments_counter() {
        let mut health = make_health("kernel", "h1", HealthState::Degraded, 0, 0);
        health.record_restart();
        assert_eq!(health.restart_attempts, 1);
    }

    #[test]
    fn failure_count_saturates() {
        let mut health = make_health("kernel", "h1", HealthState::Degraded, u64::MAX, 0);
        health.record_failure();
        assert_eq!(health.failure_count, u64::MAX);
    }

    // ── Host registration / removal ───────────────────────────────────

    #[test]
    fn register_host_adds_to_registry() {
        let mut ch = CrossMachineHealing::new();
        ch.register_host("host-a");
        assert_eq!(ch.remote_hosts.len(), 1);
        assert_eq!(ch.remote_hosts[0].host_id, "host-a");
    }

    #[test]
    fn register_duplicate_host_is_noop() {
        let mut ch = CrossMachineHealing::new();
        ch.register_host("host-a");
        ch.register_host("host-a");
        assert_eq!(ch.remote_hosts.len(), 1);
    }

    #[test]
    fn remove_host_removes_from_registry() {
        let mut ch = CrossMachineHealing::new();
        ch.register_host("host-a");
        ch.register_host("host-b");
        ch.remove_host("host-a");
        assert_eq!(ch.remote_hosts.len(), 1);
        assert_eq!(ch.remote_hosts[0].host_id, "host-b");
    }

    #[test]
    fn remove_nonexistent_host_is_noop() {
        let mut ch = CrossMachineHealing::new();
        ch.register_host("host-a");
        ch.remove_host("nonexistent");
        assert_eq!(ch.remote_hosts.len(), 1);
    }

    // ── Health observation ────────────────────────────────────────────

    #[test]
    fn observe_health_for_unknown_host_returns_error() {
        let mut ch = CrossMachineHealing::new();
        let health = make_health("kernel", "ghost", HealthState::Failed, 0, 0);
        let result = ch.observe_remote_health("ghost", health);
        assert!(result.is_err());
    }

    #[test]
    fn observe_health_updates_component_state() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");

        let health = make_health("kernel", "h1", HealthState::Failed, 1, 0);
        ch.observe_remote_health("h1", health).unwrap();

        let host = ch.find_host("h1").unwrap();
        let comp = host.component_health.get("kernel").unwrap();
        assert_eq!(comp.state, HealthState::Failed);
        assert_eq!(comp.failure_count, 2); // was 1, + recorded
    }

    // ── Decide heal ───────────────────────────────────────────────────

    #[test]
    fn healthy_component_returns_none() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");
        let health = make_health("kernel", "h1", HealthState::Healthy, 0, 0);
        ch.observe_remote_health("h1", health).unwrap();

        let decision = ch.decide_heal("h1", "kernel");
        assert!(decision.is_none());
    }

    #[test]
    fn degraded_component_triggers_restart_locally() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");
        let health = make_health("kernel", "h1", HealthState::Degraded, 1, 0);
        ch.observe_remote_health("h1", health).unwrap();

        let decision = ch.decide_heal("h1", "kernel");
        assert_eq!(decision, Some(HealDecision::RestartLocally));
    }

    #[test]
    fn exhausted_restarts_escalate() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");
        let health = make_health("kernel", "h1", HealthState::Degraded, 1, 3); // 3 restarts already
        ch.observe_remote_health("h1", health).unwrap();

        let decision = ch.decide_heal("h1", "kernel");
        assert_eq!(decision, Some(HealDecision::Escalate));
    }

    #[test]
    fn failed_component_failover_to_healthy_host() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");
        ch.register_host("h2");

        // h2 is healthy and reachable
        let h2 = ch.find_host_mut("h2").unwrap();
        h2.component_health.insert(
            "kernel".to_owned(),
            make_health("kernel", "h2", HealthState::Healthy, 0, 0),
        );

        let health = make_health("kernel", "h1", HealthState::Failed, 0, 0);
        ch.observe_remote_health("h1", health).unwrap();

        let decision = ch.decide_heal("h1", "kernel");
        assert_eq!(decision, Some(HealDecision::FailoverTo("h2".to_owned())));
    }

    #[test]
    fn failed_component_no_failover_target_isolation() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");
        let health = make_health("kernel", "h1", HealthState::Failed, 3, 2);
        ch.observe_remote_health("h1", health).unwrap();

        let decision = ch.decide_heal("h1", "kernel");
        // No other hosts → with failure_count >= 3 → Isolate
        assert_eq!(decision, Some(HealDecision::Isolate));
    }

    #[test]
    fn unknown_component_without_history_returns_none() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");
        let health = make_health("kernel", "h1", HealthState::Unknown, 0, 0);
        ch.observe_remote_health("h1", health).unwrap();

        let decision = ch.decide_heal("h1", "kernel");
        assert!(decision.is_none());
    }

    #[test]
    fn unknown_component_with_failures_escalates() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");
        let health = make_health("kernel", "h1", HealthState::Unknown, 1, 0);
        ch.observe_remote_health("h1", health).unwrap();

        let decision = ch.decide_heal("h1", "kernel");
        assert_eq!(decision, Some(HealDecision::Escalate));
    }

    // ── Scope gating ──────────────────────────────────────────────────

    #[test]
    fn local_only_scope_blocks_remote_decisions() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::LocalOnly;
        ch.register_host("h1");
        let health = make_health("kernel", "h1", HealthState::Failed, 3, 2);
        ch.observe_remote_health("h1", health).unwrap();

        let decision = ch.decide_heal("h1", "kernel");
        assert!(decision.is_none());
    }

    #[test]
    fn local_only_scope_blocks_failover_execution() {
        let ch = CrossMachineHealing::new();
        let result = ch.execute_cross_machine_heal(HealDecision::FailoverTo("h2".to_owned()));
        assert!(result.is_err());
    }

    #[test]
    fn local_only_scope_blocks_isolate_execution() {
        let ch = CrossMachineHealing::new();
        let result = ch.execute_cross_machine_heal(HealDecision::Isolate);
        assert!(result.is_err());
    }

    #[test]
    fn escalate_is_always_permitted() {
        let ch = CrossMachineHealing::new();
        let result = ch.execute_cross_machine_heal(HealDecision::Escalate);
        assert!(result.is_ok());
    }

    #[test]
    fn restart_locally_is_always_permitted() {
        let ch = CrossMachineHealing::new();
        let result = ch.execute_cross_machine_heal(HealDecision::RestartLocally);
        assert!(result.is_ok());
    }

    // ── Cascading failure detection ───────────────────────────────────

    #[test]
    fn cascading_failure_detects_multiple_degraded_hosts() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::FullFleet;

        ch.register_host("h1");
        ch.register_host("h2");
        ch.register_host("h3");

        // h1 has a failed component
        ch.observe_remote_health("h1", make_health("kernel", "h1", HealthState::Failed, 1, 0))
            .unwrap();
        // h2 has a degraded component
        ch.observe_remote_health(
            "h2",
            make_health("gateway", "h2", HealthState::Degraded, 2, 1),
        )
        .unwrap();
        // h3 is healthy
        ch.observe_remote_health(
            "h3",
            make_health("kernel", "h3", HealthState::Healthy, 0, 0),
        )
        .unwrap();

        let isolated = ch.cascading_failure_check();
        assert_eq!(isolated.len(), 2);
        assert!(isolated.contains(&"h1".to_owned()));
        assert!(isolated.contains(&"h2".to_owned()));
    }

    #[test]
    fn no_cascade_when_only_one_host_degraded() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::FullFleet;

        ch.register_host("h1");
        ch.register_host("h2");

        ch.observe_remote_health(
            "h1",
            make_health("kernel", "h1", HealthState::Degraded, 1, 0),
        )
        .unwrap();
        ch.observe_remote_health(
            "h2",
            make_health("kernel", "h2", HealthState::Healthy, 0, 0),
        )
        .unwrap();

        let isolated = ch.cascading_failure_check();
        assert!(isolated.is_empty());
    }

    #[test]
    fn all_hosts_healthy_returns_empty_cascade() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::FullFleet;

        ch.register_host("h1");
        ch.register_host("h2");
        ch.register_host("h3");

        ch.observe_remote_health(
            "h1",
            make_health("kernel", "h1", HealthState::Healthy, 0, 0),
        )
        .unwrap();
        ch.observe_remote_health(
            "h2",
            make_health("kernel", "h2", HealthState::Healthy, 0, 0),
        )
        .unwrap();
        ch.observe_remote_health(
            "h3",
            make_health("kernel", "h3", HealthState::Healthy, 0, 0),
        )
        .unwrap();

        let isolated = ch.cascading_failure_check();
        assert!(isolated.is_empty());
    }

    // ── Healing decision execution under valid scope ──────────────────

    #[test]
    fn failover_executes_when_scope_permits() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::FullFleet;
        let result = ch.execute_cross_machine_heal(HealDecision::FailoverTo("h2".to_owned()));
        assert!(result.is_ok());
    }

    #[test]
    fn isolate_executes_when_scope_permits() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::FullFleet;
        let result = ch.execute_cross_machine_heal(HealDecision::Isolate);
        assert!(result.is_ok());
    }

    // ── Health update aggregation ─────────────────────────────────────

    #[test]
    fn healthy_observation_resets_failure_count() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");

        // First observe as failed with failures
        ch.observe_remote_health("h1", make_health("kernel", "h1", HealthState::Failed, 3, 2))
            .unwrap();

        // Then observe as healthy
        ch.observe_remote_health(
            "h1",
            make_health("kernel", "h1", HealthState::Healthy, 0, 0),
        )
        .unwrap();

        let comp = ch
            .find_host("h1")
            .and_then(|h| h.component_health.get("kernel"))
            .unwrap();
        assert_eq!(comp.state, HealthState::Healthy);
        assert_eq!(comp.failure_count, 0);
    }

    #[test]
    fn high_failure_count_with_degraded_escalates() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");
        let health = make_health("kernel", "h1", HealthState::Degraded, 5, 0); // ≥5 failures
        ch.observe_remote_health("h1", health).unwrap();

        let decision = ch.decide_heal("h1", "kernel");
        assert_eq!(decision, Some(HealDecision::Escalate));
    }

    #[test]
    fn find_host_returns_none_for_unknown_id() {
        let ch = CrossMachineHealing::new();
        assert!(ch.find_host("ghost").is_none());
    }

    #[test]
    fn decide_heal_returns_none_for_unknown_host() {
        let ch = CrossMachineHealing::new();
        assert!(ch.decide_heal("ghost", "kernel").is_none());
    }

    #[test]
    fn decide_heal_returns_none_for_unknown_component() {
        let mut ch = CrossMachineHealing::new();
        ch.healing_scope = HealingScope::SameCluster;
        ch.register_host("h1");
        assert!(ch.decide_heal("h1", "nonexistent").is_none());
    }
}
