use crate::enums::EvaluationHarnessState;
use ulid::Ulid;

/// An evaluation harness orchestrates a single benchmark run against a model
/// under test.
///
/// # Invariants
///
/// - The evaluator subject MUST be `SYSTEM_SERVICE` (never an AI agent).
/// - The benchmark digest MUST be frozen before execution.
/// - All harness runs occur off the active execution path.
#[derive(Debug, Clone)]
pub struct AIEvaluationHarness {
    /// Unique harness identifier (prefix `"evalh_"` + ULID).
    pub harness_id: String,
    /// Harness specification version (e.g. `"2026.05.rev3"`).
    pub harness_version: String,
    /// Whether the evaluator subject is an AI agent.  MUST be `false` for any
    /// valid harness — the evaluator is always `SYSTEM_SERVICE`.
    pub evaluator_subject_is_ai: bool,
    /// ID of the model under test.
    pub model_under_test_id: String,
    /// Blake3 digest of the frozen benchmark content.
    pub benchmark_digest: String,
    /// Whether the benchmark content is frozen (digest‑locked).  MUST be
    /// `true`.
    pub benchmark_frozen: bool,
    /// Whether the harness runs off the active execution path.  MUST be `true`.
    pub off_active_path: bool,
    /// Current harness lifecycle state.
    pub state: EvaluationHarnessState,
}

impl AIEvaluationHarness {
    /// Creates a new harness in the `Staged` state with a fresh ULID.
    ///
    /// Callers MUST call [`validate`](Self::validate) after construction to
    /// enforce the harness safety invariants.
    #[must_use]
    pub fn new(
        model_under_test_id: impl Into<String>,
        benchmark_digest: impl Into<String>,
    ) -> Self {
        Self {
            harness_id: format!("evalh_{}", Ulid::new()),
            harness_version: "2026.05.rev3".into(),
            evaluator_subject_is_ai: false,
            model_under_test_id: model_under_test_id.into(),
            benchmark_digest: benchmark_digest.into(),
            benchmark_frozen: true,
            off_active_path: true,
            state: EvaluationHarnessState::Staged,
        }
    }

    /// Validates the harness safety invariants.
    ///
    /// # Errors
    ///
    /// Returns a string describing the first violated invariant if any of the
    /// following conditions are true:
    ///
    /// - `evaluator_subject_is_ai` is `true`
    /// - `benchmark_frozen` is `false`
    /// - `off_active_path` is `false`
    pub fn validate(&self) -> Result<(), String> {
        if self.evaluator_subject_is_ai {
            return Err(
                "evaluator_subject_is_ai must be false — evaluator is always SYSTEM_SERVICE".into(),
            );
        }
        if !self.benchmark_frozen {
            return Err(
                "benchmark_frozen must be true — unfrozen benchmarks are not admissible".into(),
            );
        }
        if !self.off_active_path {
            return Err(
                "off_active_path must be true — harness must run off the active execution path"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn new_harness_starts_in_staged_state() {
        let harness = AIEvaluationHarness::new("model-001", "abc123");
        assert_eq!(harness.state, EvaluationHarnessState::Staged);
    }

    #[test]
    fn new_harness_has_reasonable_defaults() {
        let harness = AIEvaluationHarness::new("model-001", "abc123");
        assert!(!harness.evaluator_subject_is_ai);
        assert!(harness.benchmark_frozen);
        assert!(harness.off_active_path);
        assert!(harness.harness_id.starts_with("evalh_"));
        assert_eq!(harness.harness_version, "2026.05.rev3");
    }

    #[test]
    fn validate_passes_on_default_harness() {
        let harness = AIEvaluationHarness::new("model-001", "abc123");
        assert!(harness.validate().is_ok());
    }

    #[test]
    fn validate_rejects_ai_evaluator() {
        let mut harness = AIEvaluationHarness::new("model-001", "abc123");
        harness.evaluator_subject_is_ai = true;
        let result = harness.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("evaluator_subject_is_ai"));
    }

    #[test]
    fn validate_rejects_unfrozen_benchmark() {
        let mut harness = AIEvaluationHarness::new("model-001", "abc123");
        harness.benchmark_frozen = false;
        let result = harness.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("benchmark_frozen"));
    }

    #[test]
    fn validate_rejects_on_path_execution() {
        let mut harness = AIEvaluationHarness::new("model-001", "abc123");
        harness.off_active_path = false;
        let result = harness.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("off_active_path"));
    }
}
