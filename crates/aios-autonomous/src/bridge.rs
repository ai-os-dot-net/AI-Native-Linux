use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

use crate::AutonomousError;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStateSummary {
    pub host_count: usize,
    pub healthy: usize,
    pub degraded: usize,
    pub critical: usize,
    pub recent_failovers: Vec<String>,
    pub pending_decisions: Vec<String>,
    pub last_autonomous_cycle: Option<String>,
}

impl FleetStateSummary {
    pub fn new(
        host_count: usize,
        healthy: usize,
        degraded: usize,
        critical: usize,
        recent_failovers: Vec<String>,
        pending_decisions: Vec<String>,
        last_autonomous_cycle: Option<String>,
    ) -> Self {
        Self {
            host_count,
            healthy,
            degraded,
            critical,
            recent_failovers,
            pending_decisions,
            last_autonomous_cycle,
        }
    }

    pub fn empty() -> Self {
        Self {
            host_count: 0,
            healthy: 0,
            degraded: 0,
            critical: 0,
            recent_failovers: Vec::new(),
            pending_decisions: Vec::new(),
            last_autonomous_cycle: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.host_count == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SuggestedAction {
    pub action: String,
    pub confidence: f64,
    pub reasoning: String,
    pub risk_level: RiskLevel,
}

impl SuggestedAction {
    pub fn new(action: String, confidence: f64, reasoning: String, risk_level: RiskLevel) -> Self {
        Self {
            action,
            confidence,
            reasoning,
            risk_level,
        }
    }
}

pub struct FleetCognitionBridge;

impl FleetCognitionBridge {
    pub fn new() -> Self {
        Self
    }

    pub fn translate_fleet_state_to_prompt(&self, state: &FleetStateSummary) -> String {
        if state.is_empty() {
            return String::from(
                "FLEET STATUS: No hosts registered. The fleet is empty.\n\
                 No actions are pending.\n\n\
                 Please provide your analysis and any recommended actions.",
            );
        }

        let mut prompt = String::new();
        prompt.push_str("--- FLEET STATUS ---\n");
        prompt.push_str(&format!("Total hosts: {}\n", state.host_count));
        prompt.push_str(&format!("Healthy: {}\n", state.healthy));
        prompt.push_str(&format!("Degraded: {}\n", state.degraded));
        prompt.push_str(&format!("Critical: {}\n", state.critical));

        if let Some(ref cycle) = state.last_autonomous_cycle {
            prompt.push_str(&format!("Last autonomous cycle: {}\n", cycle));
        } else {
            prompt.push_str("Last autonomous cycle: never\n");
        }

        if !state.recent_failovers.is_empty() {
            prompt.push_str("\nRecent failovers:\n");
            for failover in &state.recent_failovers {
                prompt.push_str(&format!("  - {}\n", failover));
            }
        }

        if !state.pending_decisions.is_empty() {
            prompt.push_str("\nPending decisions:\n");
            for decision in &state.pending_decisions {
                prompt.push_str(&format!("  - {}\n", decision));
            }
        } else {
            prompt.push_str("\nNo pending decisions.\n");
        }

        let health_pct = if state.host_count > 0 {
            (state.healthy as f64 / state.host_count as f64) * 100.0
        } else {
            0.0
        };
        prompt.push_str(&format!(
            "\nFleet health: {:.1}% healthy\n",
            health_pct
        ));

        prompt.push_str(
            "\nBased on this fleet state, provide a JSON array of suggested actions. \
             Each action must have: \"action\" (string), \"confidence\" (0.0-1.0), \
             \"reasoning\" (string), \"risk_level\" (\"LOW\"/\"MEDIUM\"/\"HIGH\"/\"CRITICAL\").",
        );

        prompt
    }

    pub fn interpret_ai_response(
        &self,
        response: &str,
    ) -> Result<Vec<SuggestedAction>, AutonomousError> {
        let trimmed = response.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }

        let json_start = trimmed.find('[');
        let json_end = trimmed.rfind(']');

        let json_str = match (json_start, json_end) {
            (Some(start), Some(end)) if end > start => &trimmed[start..=end],
            _ => {
                return Err(AutonomousError::InvalidAiResponse {
                    detail: "response does not contain a JSON array".into(),
                });
            }
        };

        let parsed: Vec<serde_json::Value> = serde_json::from_str(json_str).map_err(|e| {
            AutonomousError::InvalidAiResponse {
                detail: format!("JSON parse error: {}", e),
            }
        })?;

        let mut actions = Vec::with_capacity(parsed.len());
        for (idx, entry) in parsed.iter().enumerate() {
            let action = entry
                .get("action")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| AutonomousError::InvalidAiResponse {
                    detail: format!("action[{}]: missing or invalid 'action' field", idx),
                })?;

            let confidence = entry
                .get("confidence")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| AutonomousError::InvalidAiResponse {
                    detail: format!("action[{}]: missing or invalid 'confidence' field", idx),
                })?;

            if confidence < 0.0 || confidence > 1.0 {
                return Err(AutonomousError::InvalidAiResponse {
                    detail: format!(
                        "action[{}]: confidence {} out of range [0.0, 1.0]",
                        idx, confidence
                    ),
                });
            }

            let reasoning = entry
                .get("reasoning")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| AutonomousError::InvalidAiResponse {
                    detail: format!("action[{}]: missing or invalid 'reasoning' field", idx),
                })?;

            let risk_str = entry
                .get("risk_level")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AutonomousError::InvalidAiResponse {
                    detail: format!("action[{}]: missing or invalid 'risk_level' field", idx),
                })?;

            let risk_level = RiskLevel::from_str(risk_str).ok_or_else(|| {
                AutonomousError::InvalidAiResponse {
                    detail: format!(
                        "action[{}]: unknown risk_level '{}' (expected LOW/MEDIUM/HIGH/CRITICAL)",
                        idx, risk_str
                    ),
                }
            })?;

            actions.push(SuggestedAction {
                action,
                confidence,
                reasoning,
                risk_level,
            });
        }

        Ok(actions)
    }

    pub fn validate_actions(&self, actions: &[SuggestedAction]) -> Vec<SuggestedAction> {
        let valid_risk_levels = [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ];

        actions
            .iter()
            .filter(|a| {
                if a.action.trim().is_empty() {
                    return false;
                }
                if a.reasoning.trim().is_empty() {
                    return false;
                }
                if a.confidence < 0.0 || a.confidence > 1.0 {
                    return false;
                }
                if !valid_risk_levels.contains(&a.risk_level) {
                    return false;
                }
                true
            })
            .cloned()
            .collect()
    }

    pub fn generate_status_report(&self, state: &FleetStateSummary) -> String {
        if state.is_empty() {
            return String::from(
                "=== FLEET STATUS REPORT ===\n\
                 Fleet State: EMPTY\n\
                 No hosts registered.\n\
                 No autonomous actions available.",
            );
        }

        let health_pct = if state.host_count > 0 {
            (state.healthy as f64 / state.host_count as f64) * 100.0
        } else {
            0.0
        };

        let overall = if health_pct >= 90.0 {
            "HEALTHY"
        } else if health_pct >= 70.0 {
            "DEGRADED"
        } else if health_pct > 0.0 {
            "CRITICAL"
        } else {
            "DOWN"
        };

        let mut report = String::new();
        report.push_str("=== FLEET STATUS REPORT ===\n");
        report.push_str(&format!("Fleet State: {}\n", overall));
        report.push_str(&format!(
            "Hosts: {} total | {} healthy | {} degraded | {} critical\n",
            state.host_count, state.healthy, state.degraded, state.critical
        ));
        report.push_str(&format!("Fleet Health: {:.1}%\n", health_pct));

        if let Some(ref cycle) = state.last_autonomous_cycle {
            report.push_str(&format!("Last Cycle: {}\n", cycle));
        } else {
            report.push_str("Last Cycle: never\n");
        }

        report.push_str(&format!(
            "Recent Failovers: {}\n",
            state.recent_failovers.len()
        ));
        for f in &state.recent_failovers {
            report.push_str(&format!("  - {}\n", f));
        }

        report.push_str(&format!(
            "Pending Decisions: {}\n",
            state.pending_decisions.len()
        ));
        for d in &state.pending_decisions {
            report.push_str(&format!("  - {}\n", d));
        }

        report
    }
}

impl Default for FleetCognitionBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> FleetStateSummary {
        FleetStateSummary::new(
            5,
            3,
            1,
            1,
            vec!["node-03 -> node-07 (2026-06-10)".into()],
            vec!["Rebalance shard-east after failover".into()],
            Some("2026-06-11T10:30:00Z".into()),
        )
    }

    fn sample_all_healthy_state() -> FleetStateSummary {
        FleetStateSummary::new(
            4,
            4,
            0,
            0,
            vec![],
            vec![],
            Some("2026-06-11T10:30:00Z".into()),
        )
    }

    #[test]
    fn prompt_contains_host_counts() {
        let bridge = FleetCognitionBridge::new();
        let state = sample_state();
        let prompt = bridge.translate_fleet_state_to_prompt(&state);
        assert!(prompt.contains("Total hosts: 5"));
        assert!(prompt.contains("Healthy: 3"));
        assert!(prompt.contains("Degraded: 1"));
        assert!(prompt.contains("Critical: 1"));
    }

    #[test]
    fn prompt_contains_failover_info() {
        let bridge = FleetCognitionBridge::new();
        let state = sample_state();
        let prompt = bridge.translate_fleet_state_to_prompt(&state);
        assert!(prompt.contains("node-03 -> node-07"));
    }

    #[test]
    fn prompt_contains_pending_decisions() {
        let bridge = FleetCognitionBridge::new();
        let state = sample_state();
        let prompt = bridge.translate_fleet_state_to_prompt(&state);
        assert!(prompt.contains("Rebalance shard-east after failover"));
    }

    #[test]
    fn prompt_contains_last_cycle() {
        let bridge = FleetCognitionBridge::new();
        let state = sample_state();
        let prompt = bridge.translate_fleet_state_to_prompt(&state);
        assert!(prompt.contains("2026-06-11T10:30:00Z"));
    }

    #[test]
    fn prompt_handles_empty_fleet() {
        let bridge = FleetCognitionBridge::new();
        let state = FleetStateSummary::empty();
        let prompt = bridge.translate_fleet_state_to_prompt(&state);
        assert!(prompt.contains("No hosts registered"));
        assert!(prompt.contains("empty"));
    }

    #[test]
    fn prompt_all_healthy_fleet() {
        let bridge = FleetCognitionBridge::new();
        let state = sample_all_healthy_state();
        let prompt = bridge.translate_fleet_state_to_prompt(&state);
        assert!(prompt.contains("Healthy: 4"));
        assert!(prompt.contains("Critical: 0"));
        assert!(prompt.contains("No pending decisions"));
    }

    #[test]
    fn parse_valid_ai_response() {
        let bridge = FleetCognitionBridge::new();
        let response = r#"Some preamble text [{"action": "restart node-05", "confidence": 0.92, "reasoning": "Node has been degraded for 10min", "risk_level": "LOW"}] trailing"#;
        let actions = bridge.interpret_ai_response(response).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action, "restart node-05");
        assert!((actions[0].confidence - 0.92).abs() < f64::EPSILON);
        assert_eq!(actions[0].risk_level, RiskLevel::Low);
    }

    #[test]
    fn parse_multiple_actions() {
        let bridge = FleetCognitionBridge::new();
        let response = r#"[
            {"action": "restart node-01", "confidence": 0.85, "reasoning": "Unresponsive", "risk_level": "LOW"},
            {"action": "failover node-02", "confidence": 0.95, "reasoning": "Critical failure", "risk_level": "HIGH"}
        ]"#;
        let actions = bridge.interpret_ai_response(response).unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].action, "restart node-01");
        assert_eq!(actions[1].action, "failover node-02");
        assert_eq!(actions[1].risk_level, RiskLevel::High);
    }

    #[test]
    fn parse_empty_response() {
        let bridge = FleetCognitionBridge::new();
        let actions = bridge.interpret_ai_response("").unwrap();
        assert!(actions.is_empty());
    }

    #[test]
    fn parse_rejects_missing_json_array() {
        let bridge = FleetCognitionBridge::new();
        let result = bridge.interpret_ai_response("Just some text, no JSON here.");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("does not contain a JSON array"));
    }

    #[test]
    fn parse_rejects_invalid_confidence_range() {
        let bridge = FleetCognitionBridge::new();
        let response = r#"[{"action": "reboot", "confidence": 1.5, "reasoning": "Test", "risk_level": "LOW"}]"#;
        let result = bridge.interpret_ai_response(response);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn parse_rejects_unknown_risk_level() {
        let bridge = FleetCognitionBridge::new();
        let response =
            r#"[{"action": "reboot", "confidence": 0.5, "reasoning": "Test", "risk_level": "NUCLEAR"}]"#;
        let result = bridge.interpret_ai_response(response);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unknown risk_level"));
    }

    #[test]
    fn parse_rejects_missing_action_field() {
        let bridge = FleetCognitionBridge::new();
        let response = r#"[{"confidence": 0.5, "reasoning": "Test", "risk_level": "LOW"}]"#;
        let result = bridge.interpret_ai_response(response);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("missing or invalid 'action' field"));
    }

    #[test]
    fn parse_all_risk_levels_accepted() {
        let bridge = FleetCognitionBridge::new();
        let response = r#"[
            {"action": "a1", "confidence": 0.9, "reasoning": "r1", "risk_level": "LOW"},
            {"action": "a2", "confidence": 0.8, "reasoning": "r2", "risk_level": "MEDIUM"},
            {"action": "a3", "confidence": 0.7, "reasoning": "r3", "risk_level": "HIGH"},
            {"action": "a4", "confidence": 0.6, "reasoning": "r4", "risk_level": "CRITICAL"}
        ]"#;
        let actions = bridge.interpret_ai_response(response).unwrap();
        assert_eq!(actions.len(), 4);
        assert_eq!(actions[0].risk_level, RiskLevel::Low);
        assert_eq!(actions[1].risk_level, RiskLevel::Medium);
        assert_eq!(actions[2].risk_level, RiskLevel::High);
        assert_eq!(actions[3].risk_level, RiskLevel::Critical);
    }

    #[test]
    fn validate_filters_empty_action_name() {
        let bridge = FleetCognitionBridge::new();
        let actions = vec![
            SuggestedAction::new(String::new(), 0.9, "valid reasoning".into(), RiskLevel::Low),
            SuggestedAction::new(
                "valid-action".into(),
                0.8,
                "valid reasoning".into(),
                RiskLevel::Medium,
            ),
        ];
        let validated = bridge.validate_actions(&actions);
        assert_eq!(validated.len(), 1);
        assert_eq!(validated[0].action, "valid-action");
    }

    #[test]
    fn validate_filters_empty_reasoning() {
        let bridge = FleetCognitionBridge::new();
        let actions = vec![
            SuggestedAction::new("act".into(), 0.9, String::new(), RiskLevel::Low),
            SuggestedAction::new("act2".into(), 0.8, "good".into(), RiskLevel::Low),
        ];
        let validated = bridge.validate_actions(&actions);
        assert_eq!(validated.len(), 1);
    }

    #[test]
    fn validate_filters_invalid_confidence() {
        let bridge = FleetCognitionBridge::new();
        let actions = vec![
            SuggestedAction::new("act".into(), -0.5, "r".into(), RiskLevel::Low),
            SuggestedAction::new("act2".into(), 2.0, "r".into(), RiskLevel::Low),
            SuggestedAction::new("act3".into(), 0.5, "r".into(), RiskLevel::Low),
        ];
        let validated = bridge.validate_actions(&actions);
        assert_eq!(validated.len(), 1);
    }

    #[test]
    fn validate_returns_empty_on_all_invalid() {
        let bridge = FleetCognitionBridge::new();
        let actions = vec![SuggestedAction::new(String::new(), 0.9, String::new(), RiskLevel::Low)];
        let validated = bridge.validate_actions(&actions);
        assert!(validated.is_empty());
    }

    #[test]
    fn status_report_contains_overall_health() {
        let bridge = FleetCognitionBridge::new();
        let state = sample_state();
        let report = bridge.generate_status_report(&state);
        assert!(report.contains("Fleet State:"));
        assert!(report.contains("Fleet Health: 60.0%"));
    }

    #[test]
    fn status_report_all_healthy_shows_healthy() {
        let bridge = FleetCognitionBridge::new();
        let state = sample_all_healthy_state();
        let report = bridge.generate_status_report(&state);
        assert!(report.contains("Fleet State: HEALTHY"));
        assert!(report.contains("Fleet Health: 100.0%"));
    }

    #[test]
    fn status_report_empty_fleet() {
        let bridge = FleetCognitionBridge::new();
        let state = FleetStateSummary::empty();
        let report = bridge.generate_status_report(&state);
        assert!(report.contains("Fleet State: EMPTY"));
        assert!(report.contains("No hosts registered"));
    }

    #[test]
    fn status_report_never_cycle_when_none() {
        let bridge = FleetCognitionBridge::new();
        let state = FleetStateSummary::new(1, 1, 0, 0, vec![], vec![], None);
        let report = bridge.generate_status_report(&state);
        assert!(report.contains("Last Cycle: never"));
    }

    #[test]
    fn risk_level_from_str_valid() {
        assert_eq!(RiskLevel::from_str("LOW"), Some(RiskLevel::Low));
        assert_eq!(RiskLevel::from_str("medium"), Some(RiskLevel::Medium));
        assert_eq!(RiskLevel::from_str("HIGH"), Some(RiskLevel::High));
        assert_eq!(RiskLevel::from_str("Critical"), Some(RiskLevel::Critical));
    }

    #[test]
    fn risk_level_from_str_invalid() {
        assert_eq!(RiskLevel::from_str("UNKNOWN"), None);
        assert_eq!(RiskLevel::from_str(""), None);
    }

    #[test]
    fn risk_level_as_str() {
        assert_eq!(RiskLevel::Low.as_str(), "LOW");
        assert_eq!(RiskLevel::Medium.as_str(), "MEDIUM");
        assert_eq!(RiskLevel::High.as_str(), "HIGH");
        assert_eq!(RiskLevel::Critical.as_str(), "CRITICAL");
    }

    #[test]
    fn fleet_state_empty_detection() {
        let empty = FleetStateSummary::empty();
        assert!(empty.is_empty());
        let non_empty = FleetStateSummary::new(1, 1, 0, 0, vec![], vec![], None);
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn fleet_state_summary_new_fields_preserved() {
        let state = FleetStateSummary::new(
            10,
            7,
            2,
            1,
            vec!["f1".into(), "f2".into()],
            vec!["d1".into()],
            Some("2026-06-11".into()),
        );
        assert_eq!(state.host_count, 10);
        assert_eq!(state.healthy, 7);
        assert_eq!(state.degraded, 2);
        assert_eq!(state.critical, 1);
        assert_eq!(state.recent_failovers.len(), 2);
        assert_eq!(state.pending_decisions.len(), 1);
        assert_eq!(state.last_autonomous_cycle.as_deref(), Some("2026-06-11"));
    }
}
