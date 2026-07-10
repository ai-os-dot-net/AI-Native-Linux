//! AIOS Rev.10 — Distributed Cognitive Routing & Cross-Agent Coordination
//!
//! Multi-host cognitive routing with GPU VRAM-aware model dispatch, INV-016
//! agent separation enforcement, and cross-agent coordination for fleet-scale
//! LLM inference pipelines.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// AgentRole — the three roles in a cross-agent coordination pipeline
// ---------------------------------------------------------------------------

/// Agent role per INV-016 coordination topology.
///
/// Every cross-agent task must have a Planner, an Executor, and a Reviewer.
/// INV-016 requires: planner ≠ executor, reviewer ≠ executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentRole {
    /// Plans the work — produces a plan for the executor.
    Planner = 1,
    /// Executes the plan — carries out the actual work.
    Executor = 2,
    /// Reviews the execution — validates and approves/rejects the result.
    Reviewer = 3,
}

// ---------------------------------------------------------------------------
// CrossAgentVerdict — the outcome of a cross-agent coordination round
// ---------------------------------------------------------------------------

/// Verdict produced by cross-agent coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrossAgentVerdict {
    /// The coordination round completed successfully.
    Accepted,
    /// The coordination round was rejected (separation violation, missing agents, etc.).
    Rejected,
    /// The result needs rework — send back to a specific phase.
    NeedsRework,
}

// ---------------------------------------------------------------------------
// HostCognitionProfile — what a host can contribute
// ---------------------------------------------------------------------------

/// Profile describing the cognitive capacity of a fleet host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCognitionProfile {
    /// Unique host identifier (e.g. `hst_<ULID>`).
    pub host_id: String,
    /// Model identifiers this host can serve.
    pub available_models: Vec<String>,
    /// GPU VRAM available on this host in MiB.
    pub gpu_vram_mb: u64,
    /// Rolling-average inference latency in milliseconds.
    pub avg_latency_ms: u64,
    /// Number of CPU cores available.
    pub cpu_cores: u32,
}

// ---------------------------------------------------------------------------
// AgentBinding — ties a subject agent to a host
// ---------------------------------------------------------------------------

/// Binds a subject (agent) to a specific host and role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBinding {
    /// Subject identifier (e.g. `sub_<ULID>`).
    pub subject_id: String,
    /// Host where this agent runs.
    pub host_id: String,
    /// Role this agent plays.
    pub role: AgentRole,
    /// Model identifier this agent uses for inference.
    pub model_id: String,
}

// ---------------------------------------------------------------------------
// InferenceRequest — what the router needs to decide
// ---------------------------------------------------------------------------

/// An inference request submitted to the distributed cognitive router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceRequest {
    /// Requested model identifier.
    pub model_id: String,
    /// Estimated prompt length in tokens.
    pub prompt_length: u32,
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// Minimum VRAM required in MiB.
    pub required_vram_mb: u64,
}

// ---------------------------------------------------------------------------
// InferenceRouting — the router's decision
// ---------------------------------------------------------------------------

/// The result of distributed inference routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceRouting {
    /// The selected best host, or empty string if no host qualifies.
    pub selected_host_id: String,
    /// Estimated latency on the selected host in milliseconds.
    pub estimated_latency_ms: u64,
    /// Fallback host if the primary fails, or empty string.
    pub fallback_host_id: String,
}

// ---------------------------------------------------------------------------
// CrossAgentTask — a single coordination unit
// ---------------------------------------------------------------------------

/// A cross-agent coordination task spanning Planner, Executor, and Reviewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossAgentTask {
    /// Unique task identifier (e.g. `tsk_<ULID>`).
    pub task_id: String,
    /// Subject identifier for the Planner role.
    pub planner_subject: String,
    /// Subject identifier for the Executor role.
    pub executor_subject: String,
    /// Subject identifier for the Reviewer role.
    pub reviewer_subject: String,
}

// ---------------------------------------------------------------------------
// CrossAgentResult — the outcome of coordination
// ---------------------------------------------------------------------------

/// Result of a cross-agent coordination round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossAgentResult {
    /// The task identifier.
    pub task_id: String,
    /// The verdict: Accepted, Rejected, or NeedsRework.
    pub verdict: CrossAgentVerdict,
    /// Human-readable reasoning for the verdict.
    pub reasoning: String,
}

// ---------------------------------------------------------------------------
// DistributedCognitiveRouter — fleet-scale cognitive routing
// ---------------------------------------------------------------------------

/// Multi-host cognitive router for fleet-scale LLM inference.
///
/// Maintains registries of host capabilities and agent bindings, selects the
/// best host for each inference request, enforces INV-016 agent separation,
/// and coordinates multi-agent task pipelines.
#[derive(Debug, Clone, Default)]
pub struct DistributedCognitiveRouter {
    /// Hosts indexed by host identifier.
    pub host_registry: HashMap<String, HostCognitionProfile>,
    /// Agent bindings indexed by subject identifier.
    pub agent_registry: HashMap<String, AgentBinding>,
}

impl DistributedCognitiveRouter {
    /// Create an empty distributed cognitive router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            host_registry: HashMap::new(),
            agent_registry: HashMap::new(),
        }
    }

    /// Register a host and its cognitive profile.
    ///
    /// If the host already exists, its profile is replaced.
    pub fn register_host(&mut self, profile: HostCognitionProfile) {
        self.host_registry.insert(profile.host_id.clone(), profile);
    }

    /// Remove a host from the registry.
    ///
    /// Returns `true` if the host was present.
    pub fn remove_host(&mut self, host_id: &str) -> bool {
        self.host_registry.remove(host_id).is_some()
    }

    /// Route an inference request to the best available host.
    ///
    /// Selection criteria (in priority order):
    /// 1. Host must have the requested model in `available_models`.
    /// 2. Host must have at least `required_vram_mb` of GPU VRAM.
    /// 3. Among qualified hosts, the one with the lowest `avg_latency_ms` wins.
    ///
    /// The runner-up becomes the fallback. If no host qualifies, both
    /// `selected_host_id` and `fallback_host_id` are empty strings.
    pub fn route_inference(&self, request: &InferenceRequest) -> InferenceRouting {
        let mut candidates: Vec<&HostCognitionProfile> = self
            .host_registry
            .values()
            .filter(|h| {
                h.available_models.contains(&request.model_id)
                    && h.gpu_vram_mb >= request.required_vram_mb
            })
            .collect();

        candidates.sort_by_key(|h| h.avg_latency_ms);

        match candidates.len() {
            0 => InferenceRouting {
                selected_host_id: String::new(),
                estimated_latency_ms: 0,
                fallback_host_id: String::new(),
            },
            1 => InferenceRouting {
                selected_host_id: candidates[0].host_id.clone(),
                estimated_latency_ms: candidates[0].avg_latency_ms,
                fallback_host_id: String::new(),
            },
            _ => InferenceRouting {
                selected_host_id: candidates[0].host_id.clone(),
                estimated_latency_ms: candidates[0].avg_latency_ms,
                fallback_host_id: candidates[1].host_id.clone(),
            },
        }
    }

    /// Dispatch an agent role to a host for a given task.
    ///
    /// Looks up the agent registry for an agent binding matching the requested
    /// role and returns the host identifier. Returns `None` if no agent with
    /// the requested role is registered.
    pub fn dispatch_agent_role(&self, role: AgentRole, _task_id: &str) -> Option<String> {
        self.agent_registry
            .values()
            .find(|binding| binding.role == role)
            .map(|binding| binding.host_id.clone())
    }

    /// Validate agent separation per INV-016.
    ///
    /// INV-016 mandates:
    /// - planner_host MUST NOT equal executor_host (planning and execution
    ///   must be on separate hosts).
    /// - reviewer_host MUST NOT equal executor_host (review and execution
    ///   must be on separate hosts).
    /// - reviewer_host MAY equal planner_host (same host is allowed, but
    ///   must be different agent instances).
    ///
    /// Returns `true` if the separation constraints are satisfied.
    #[must_use]
    pub fn validate_separation(
        &self,
        planner_host: &str,
        executor_host: &str,
        reviewer_host: &str,
    ) -> bool {
        if planner_host == executor_host {
            return false;
        }
        if reviewer_host == executor_host {
            return false;
        }
        true
    }

    /// Coordinate a cross-agent task across Planner, Executor, and Reviewer.
    ///
    /// Validates INV-016 separation by resolving each subject's host from the
    /// agent registry. If separation is violated or any agent is missing, the
    /// verdict is Rejected. Otherwise, the verdict is Accepted.
    pub fn multi_agent_coordination(&self, task: &CrossAgentTask) -> CrossAgentResult {
        let Some(planner_binding) = self.agent_registry.get(&task.planner_subject) else {
            return CrossAgentResult {
                task_id: task.task_id.clone(),
                verdict: CrossAgentVerdict::Rejected,
                reasoning: format!(
                    "Planner subject '{}' not found in agent registry",
                    task.planner_subject
                ),
            };
        };
        let Some(executor_binding) = self.agent_registry.get(&task.executor_subject) else {
            return CrossAgentResult {
                task_id: task.task_id.clone(),
                verdict: CrossAgentVerdict::Rejected,
                reasoning: format!(
                    "Executor subject '{}' not found in agent registry",
                    task.executor_subject
                ),
            };
        };
        let Some(reviewer_binding) = self.agent_registry.get(&task.reviewer_subject) else {
            return CrossAgentResult {
                task_id: task.task_id.clone(),
                verdict: CrossAgentVerdict::Rejected,
                reasoning: format!(
                    "Reviewer subject '{}' not found in agent registry",
                    task.reviewer_subject
                ),
            };
        };

        let planner_host = &planner_binding.host_id;
        let executor_host = &executor_binding.host_id;
        let reviewer_host = &reviewer_binding.host_id;

        if !self.validate_separation(planner_host, executor_host, reviewer_host) {
            return CrossAgentResult {
                task_id: task.task_id.clone(),
                verdict: CrossAgentVerdict::Rejected,
                reasoning: format!(
                    "INV-016 separation violated: planner={p}, executor={e}, reviewer={r}",
                    p = planner_host,
                    e = executor_host,
                    r = reviewer_host
                ),
            };
        }

        CrossAgentResult {
            task_id: task.task_id.clone(),
            verdict: CrossAgentVerdict::Accepted,
            reasoning: format!(
                "Cross-agent coordination accepted: planner={p} on {ph}, executor={e} on {eh}, reviewer={r} on {rh}",
                p = task.planner_subject,
                ph = planner_host,
                e = task.executor_subject,
                eh = executor_host,
                r = task.reviewer_subject,
                rh = reviewer_host
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_host(
        id: &str,
        models: &[&str],
        vram: u64,
        latency: u64,
        cores: u32,
    ) -> HostCognitionProfile {
        HostCognitionProfile {
            host_id: id.to_string(),
            available_models: models.iter().map(|s| s.to_string()).collect(),
            gpu_vram_mb: vram,
            avg_latency_ms: latency,
            cpu_cores: cores,
        }
    }

    fn make_binding(subject: &str, host: &str, role: AgentRole, model: &str) -> AgentBinding {
        AgentBinding {
            subject_id: subject.to_string(),
            host_id: host.to_string(),
            role,
            model_id: model.to_string(),
        }
    }

    fn make_router_with_two_hosts() -> DistributedCognitiveRouter {
        let mut router = DistributedCognitiveRouter::new();
        router.register_host(make_host("hst_A", &["llama3"], 16_384, 50, 8));
        router.register_host(make_host("hst_B", &["llama3", "mistral"], 24_576, 30, 16));
        router
    }

    #[test]
    fn route_inference_picks_lowest_latency_host() {
        let router = make_router_with_two_hosts();
        let request = InferenceRequest {
            model_id: "llama3".into(),
            prompt_length: 1024,
            max_tokens: 512,
            required_vram_mb: 8_192,
        };
        let routing = router.route_inference(&request);
        assert_eq!(routing.selected_host_id, "hst_B");
        assert_eq!(routing.estimated_latency_ms, 30);
        assert_eq!(routing.fallback_host_id, "hst_A");
    }

    #[test]
    fn route_inference_filters_by_vram() {
        let mut router = DistributedCognitiveRouter::new();
        router.register_host(make_host("hst_small", &["llama3"], 4_096, 20, 4));
        router.register_host(make_host("hst_big", &["llama3"], 32_768, 80, 16));
        let request = InferenceRequest {
            model_id: "llama3".into(),
            prompt_length: 1024,
            max_tokens: 512,
            required_vram_mb: 16_384,
        };
        let routing = router.route_inference(&request);
        assert_eq!(routing.selected_host_id, "hst_big");
        assert!(routing.fallback_host_id.is_empty());
    }

    #[test]
    fn validate_separation_allows_reviewer_same_as_planner() {
        let router = DistributedCognitiveRouter::new();
        assert!(router.validate_separation("hst_A", "hst_B", "hst_A"));
    }

    #[test]
    fn validate_separation_allows_all_different_hosts() {
        let router = DistributedCognitiveRouter::new();
        assert!(router.validate_separation("hst_A", "hst_B", "hst_C"));
    }

    #[test]
    fn validate_separation_rejects_planner_equals_executor() {
        let router = DistributedCognitiveRouter::new();
        assert!(!router.validate_separation("hst_A", "hst_A", "hst_C"));
    }

    #[test]
    fn validate_separation_rejects_reviewer_equals_executor() {
        let router = DistributedCognitiveRouter::new();
        assert!(!router.validate_separation("hst_A", "hst_B", "hst_B"));
    }

    #[test]
    fn dispatch_agent_role_returns_host_for_registered_role() {
        let mut router = DistributedCognitiveRouter::new();
        router.agent_registry.insert(
            "sub_001".into(),
            make_binding("sub_001", "hst_A", AgentRole::Planner, "llama3"),
        );
        let host = router.dispatch_agent_role(AgentRole::Planner, "tsk_001");
        assert_eq!(host, Some("hst_A".into()));
    }

    #[test]
    fn dispatch_agent_role_returns_none_for_unregistered_role() {
        let router = DistributedCognitiveRouter::new();
        let host = router.dispatch_agent_role(AgentRole::Executor, "tsk_001");
        assert_eq!(host, None);
    }

    #[test]
    fn dispatch_finds_correct_role_among_many() {
        let mut router = DistributedCognitiveRouter::new();
        router.agent_registry.insert(
            "sub_p".into(),
            make_binding("sub_p", "hst_A", AgentRole::Planner, "llama3"),
        );
        router.agent_registry.insert(
            "sub_e".into(),
            make_binding("sub_e", "hst_B", AgentRole::Executor, "mistral"),
        );
        router.agent_registry.insert(
            "sub_r".into(),
            make_binding("sub_r", "hst_C", AgentRole::Reviewer, "llama3"),
        );
        assert_eq!(
            router.dispatch_agent_role(AgentRole::Planner, "tsk_x"),
            Some("hst_A".into())
        );
        assert_eq!(
            router.dispatch_agent_role(AgentRole::Executor, "tsk_x"),
            Some("hst_B".into())
        );
        assert_eq!(
            router.dispatch_agent_role(AgentRole::Reviewer, "tsk_x"),
            Some("hst_C".into())
        );
    }

    #[test]
    fn multi_agent_coordination_accepted_with_valid_separation() {
        let mut router = DistributedCognitiveRouter::new();
        router.agent_registry.insert(
            "sub_p".into(),
            make_binding("sub_p", "hst_A", AgentRole::Planner, "llama3"),
        );
        router.agent_registry.insert(
            "sub_e".into(),
            make_binding("sub_e", "hst_B", AgentRole::Executor, "mistral"),
        );
        router.agent_registry.insert(
            "sub_r".into(),
            make_binding("sub_r", "hst_A", AgentRole::Reviewer, "llama3"),
        );
        let task = CrossAgentTask {
            task_id: "tsk_001".into(),
            planner_subject: "sub_p".into(),
            executor_subject: "sub_e".into(),
            reviewer_subject: "sub_r".into(),
        };
        let result = router.multi_agent_coordination(&task);
        assert_eq!(result.verdict, CrossAgentVerdict::Accepted);
        assert!(result.reasoning.contains("accepted"));
    }

    #[test]
    fn multi_agent_coordination_rejected_by_separation_violation() {
        let mut router = DistributedCognitiveRouter::new();
        router.agent_registry.insert(
            "sub_p".into(),
            make_binding("sub_p", "hst_A", AgentRole::Planner, "llama3"),
        );
        router.agent_registry.insert(
            "sub_e".into(),
            make_binding("sub_e", "hst_A", AgentRole::Executor, "mistral"),
        );
        router.agent_registry.insert(
            "sub_r".into(),
            make_binding("sub_r", "hst_B", AgentRole::Reviewer, "llama3"),
        );
        let task = CrossAgentTask {
            task_id: "tsk_002".into(),
            planner_subject: "sub_p".into(),
            executor_subject: "sub_e".into(),
            reviewer_subject: "sub_r".into(),
        };
        let result = router.multi_agent_coordination(&task);
        assert_eq!(result.verdict, CrossAgentVerdict::Rejected);
        assert!(result.reasoning.contains("INV-016"));
    }

    #[test]
    fn multi_agent_coordination_rejected_missing_executor() {
        let mut router = DistributedCognitiveRouter::new();
        router.agent_registry.insert(
            "sub_p".into(),
            make_binding("sub_p", "hst_A", AgentRole::Planner, "llama3"),
        );
        router.agent_registry.insert(
            "sub_r".into(),
            make_binding("sub_r", "hst_B", AgentRole::Reviewer, "llama3"),
        );
        let task = CrossAgentTask {
            task_id: "tsk_003".into(),
            planner_subject: "sub_p".into(),
            executor_subject: "sub_e".into(),
            reviewer_subject: "sub_r".into(),
        };
        let result = router.multi_agent_coordination(&task);
        assert_eq!(result.verdict, CrossAgentVerdict::Rejected);
        assert!(result.reasoning.contains("Executor"));
    }

    #[test]
    fn register_host_adds_profile() {
        let mut router = DistributedCognitiveRouter::new();
        let profile = make_host("hst_X", &["phi3"], 8_192, 42, 6);
        router.register_host(profile);
        assert_eq!(router.host_registry.len(), 1);
        assert!(router.host_registry.contains_key("hst_X"));
    }

    #[test]
    fn remove_host_deletes_and_returns_true() {
        let mut router = DistributedCognitiveRouter::new();
        router.register_host(make_host("hst_X", &["phi3"], 8_192, 42, 6));
        assert!(router.remove_host("hst_X"));
        assert!(router.host_registry.is_empty());
        assert!(!router.remove_host("hst_X"));
    }

    #[test]
    fn route_inference_returns_empty_on_empty_registry() {
        let router = DistributedCognitiveRouter::new();
        let request = InferenceRequest {
            model_id: "llama3".into(),
            prompt_length: 1024,
            max_tokens: 512,
            required_vram_mb: 8_192,
        };
        let routing = router.route_inference(&request);
        assert_eq!(routing.selected_host_id, "");
        assert_eq!(routing.estimated_latency_ms, 0);
        assert_eq!(routing.fallback_host_id, "");
    }

    #[test]
    fn route_inference_rejects_when_model_not_available() {
        let router = make_router_with_two_hosts();
        let request = InferenceRequest {
            model_id: "gemini-pro".into(),
            prompt_length: 512,
            max_tokens: 256,
            required_vram_mb: 0,
        };
        let routing = router.route_inference(&request);
        assert!(routing.selected_host_id.is_empty());
    }

    #[test]
    fn route_inference_rejects_when_no_host_has_enough_vram() {
        let router = make_router_with_two_hosts();
        let request = InferenceRequest {
            model_id: "llama3".into(),
            prompt_length: 1024,
            max_tokens: 512,
            required_vram_mb: 48_000,
        };
        let routing = router.route_inference(&request);
        assert!(routing.selected_host_id.is_empty());
    }
}
