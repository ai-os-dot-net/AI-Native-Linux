use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum AutonomousError {
    #[error("host not found: {host_id}")]
    HostNotFound { host_id: String },

    #[error("action '{action}' denied under scope {scope}")]
    ScopeDenied { action: String, scope: String },

    #[error("quorum lost: {detail}")]
    QuorumLost { detail: String },

    #[error("insufficient evidence")]
    InsufficientEvidence,

    #[error("action denied by policy: {policy_ref}")]
    PolicyDenied { policy_ref: String },

    #[error("risk threshold exceeded: score {score} exceeds limit {limit}")]
    RiskThresholdExceeded { score: u8, limit: u8 },

    #[error("governance rejected: {reason}")]
    GovernanceRejected { reason: String },

    #[error("failover not allowed for {component_id}: {reason}")]
    FailoverNotAllowed {
        component_id: String,
        reason: String,
    },

    #[error("remote host unreachable: {host_id}")]
    RemoteHostUnreachable { host_id: String },

    #[error("invalid state transition {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("autonomy level {current} insufficient; required {required}")]
    AutonomyLevelInsufficient { current: String, required: String },

    #[error("coordination conflict: {detail}")]
    CoordinationConflict { detail: String },

    #[error("invalid AI response: {detail}")]
    InvalidAiResponse { detail: String },

    #[error("evidence sync failed for '{host_id}': {reason}")]
    EvidenceSyncFailed { host_id: String, reason: String },

    #[error("invalid failover state: {0}")]
    InvalidFailoverState(String),

    #[error("failover limit exceeded: max {max}, current {current}")]
    FailoverLimitExceeded { max: u32, current: usize },

    #[error("coordinator promotion failed: {0}")]
    CoordinatorPromotionFailed(String),

    #[error("failover not found: {0}")]
    FailoverNotFound(String),

    #[error("autonomy forbidden at level {level}")]
    AutonomyForbidden { level: String },

    #[error("governance vetoed action '{action}'")]
    GovernanceVeto { action: String },

    #[error("constitutional clause not found: {clause_id}")]
    ClauseNotFound { clause_id: String },

    #[error("amendment quorum not met: {present}/{required}")]
    QuorumNotMet { present: usize, required: usize },

    #[error("insufficient valid signatures: {valid}/{required}")]
    InsufficientSignatures { valid: usize, required: usize },

    #[error("clause is immutable: {clause_id}")]
    ImmutableClause { clause_id: String },

    #[error("constitutional violation: {clause_title} — {detail}")]
    ConstitutionalViolation {
        clause_title: String,
        detail: String,
    },

    #[error("invalid governance vote: {reason}")]
    InvalidVote { reason: String },

    #[error("federation policy push failed: hosts {hosts:?} did not acknowledge")]
    FederationPushFailed { hosts: Vec<String> },

    #[error("{0}")]
    InvalidArgument(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_not_found_display() {
        let err = AutonomousError::HostNotFound {
            host_id: "node-12".into(),
        };
        assert_eq!(err.to_string(), "host not found: node-12");
    }

    #[test]
    fn scope_denied_display() {
        let err = AutonomousError::ScopeDenied {
            action: "failover".into(),
            scope: "LocalOnly".into(),
        };
        assert_eq!(
            err.to_string(),
            "action 'failover' denied under scope LocalOnly"
        );
    }

    #[test]
    fn quorum_lost_display() {
        let err = AutonomousError::QuorumLost {
            detail: "only 2 of 5 responded".into(),
        };
        assert_eq!(err.to_string(), "quorum lost: only 2 of 5 responded");
    }

    #[test]
    fn insufficient_evidence_display() {
        let err = AutonomousError::InsufficientEvidence;
        assert_eq!(err.to_string(), "insufficient evidence");
    }

    #[test]
    fn policy_denied_display() {
        let err = AutonomousError::PolicyDenied {
            policy_ref: "POL-042".into(),
        };
        assert_eq!(err.to_string(), "action denied by policy: POL-042");
    }

    #[test]
    fn risk_threshold_exceeded_display() {
        let err = AutonomousError::RiskThresholdExceeded {
            score: 85,
            limit: 70,
        };
        assert_eq!(
            err.to_string(),
            "risk threshold exceeded: score 85 exceeds limit 70"
        );
    }

    #[test]
    fn governance_rejected_display() {
        let err = AutonomousError::GovernanceRejected {
            reason: "2 of 3 voted reject".into(),
        };
        assert_eq!(err.to_string(), "governance rejected: 2 of 3 voted reject");
    }

    #[test]
    fn failover_not_allowed_display() {
        let err = AutonomousError::FailoverNotAllowed {
            component_id: "comp-7a".into(),
            reason: "not yet healthy".into(),
        };
        assert_eq!(
            err.to_string(),
            "failover not allowed for comp-7a: not yet healthy"
        );
    }

    #[test]
    fn remote_host_unreachable_display() {
        let err = AutonomousError::RemoteHostUnreachable {
            host_id: "node-12".into(),
        };
        assert_eq!(err.to_string(), "remote host unreachable: node-12");
    }

    #[test]
    fn invalid_state_transition_display() {
        let err = AutonomousError::InvalidStateTransition {
            from: "MONITORING".into(),
            to: "COMPLETED".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid state transition MONITORING -> COMPLETED"
        );
    }

    #[test]
    fn autonomy_level_insufficient_display() {
        let err = AutonomousError::AutonomyLevelInsufficient {
            current: "Advisory".into(),
            required: "AutonomousRecovery".into(),
        };
        assert_eq!(
            err.to_string(),
            "autonomy level Advisory insufficient; required AutonomousRecovery"
        );
    }

    #[test]
    fn coordination_conflict_display() {
        let err = AutonomousError::CoordinationConflict {
            detail: "two coordinators for cluster east".into(),
        };
        assert_eq!(
            err.to_string(),
            "coordination conflict: two coordinators for cluster east"
        );
    }

    #[test]
    fn invalid_ai_response_display() {
        let err = AutonomousError::InvalidAiResponse {
            detail: "bad JSON".into(),
        };
        assert_eq!(err.to_string(), "invalid AI response: bad JSON");
    }

    #[test]
    fn evidence_sync_failed_display() {
        let err = AutonomousError::EvidenceSyncFailed {
            host_id: "h1".into(),
            reason: "timeout".into(),
        };
        assert_eq!(err.to_string(), "evidence sync failed for 'h1': timeout");
    }

    #[test]
    fn failover_limit_exceeded_display() {
        let err = AutonomousError::FailoverLimitExceeded { max: 3, current: 3 };
        assert_eq!(err.to_string(), "failover limit exceeded: max 3, current 3");
    }

    #[test]
    fn failover_not_found_display() {
        let err = AutonomousError::FailoverNotFound("abc123".into());
        assert_eq!(err.to_string(), "failover not found: abc123");
    }

    #[test]
    fn invalid_failover_state_display() {
        let err = AutonomousError::InvalidFailoverState("bad phase".into());
        assert_eq!(err.to_string(), "invalid failover state: bad phase");
    }

    #[test]
    fn coordinator_promotion_failed_display() {
        let err = AutonomousError::CoordinatorPromotionFailed("no quorum".into());
        assert_eq!(err.to_string(), "coordinator promotion failed: no quorum");
    }

    #[test]
    fn autonomy_forbidden_display() {
        let err = AutonomousError::AutonomyForbidden {
            level: "Advisory".into(),
        };
        assert_eq!(err.to_string(), "autonomy forbidden at level Advisory");
    }

    #[test]
    fn governance_veto_display() {
        let err = AutonomousError::GovernanceVeto {
            action: "rebuild_quorum".into(),
        };
        assert_eq!(err.to_string(), "governance vetoed action 'rebuild_quorum'");
    }

    #[test]
    fn clause_not_found_display() {
        let err = AutonomousError::ClauseNotFound {
            clause_id: "CL-007".into(),
        };
        assert_eq!(err.to_string(), "constitutional clause not found: CL-007");
    }

    #[test]
    fn quorum_not_met_display() {
        let err = AutonomousError::QuorumNotMet {
            present: 2,
            required: 5,
        };
        assert_eq!(err.to_string(), "amendment quorum not met: 2/5");
    }

    #[test]
    fn insufficient_signatures_display() {
        let err = AutonomousError::InsufficientSignatures {
            valid: 1,
            required: 3,
        };
        assert_eq!(err.to_string(), "insufficient valid signatures: 1/3");
    }

    #[test]
    fn immutable_clause_display() {
        let err = AutonomousError::ImmutableClause {
            clause_id: "CL-PREAMBLE".into(),
        };
        assert_eq!(err.to_string(), "clause is immutable: CL-PREAMBLE");
    }

    #[test]
    fn constitutional_violation_display() {
        let err = AutonomousError::ConstitutionalViolation {
            clause_title: "Max Blast Radius".into(),
            detail: "3 active failovers, limit is 2".into(),
        };
        assert_eq!(
            err.to_string(),
            "constitutional violation: Max Blast Radius — 3 active failovers, limit is 2"
        );
    }

    #[test]
    fn invalid_vote_display() {
        let err = AutonomousError::InvalidVote {
            reason: "signature mismatch".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid governance vote: signature mismatch"
        );
    }

    #[test]
    fn federation_push_failed_display() {
        let err = AutonomousError::FederationPushFailed {
            hosts: vec!["h1".into(), "h3".into()],
        };
        assert_eq!(
            err.to_string(),
            r#"federation policy push failed: hosts ["h1", "h3"] did not acknowledge"#
        );
    }

    #[test]
    fn invalid_argument_display() {
        let err = AutonomousError::InvalidArgument("fleet_id must not be nil".into());
        assert_eq!(err.to_string(), "fleet_id must not be nil");
    }

    #[test]
    fn variant_count() {
        let variants: &[AutonomousError] = &[
            AutonomousError::HostNotFound {
                host_id: String::new(),
            },
            AutonomousError::ScopeDenied {
                action: String::new(),
                scope: String::new(),
            },
            AutonomousError::QuorumLost {
                detail: String::new(),
            },
            AutonomousError::InsufficientEvidence,
            AutonomousError::PolicyDenied {
                policy_ref: String::new(),
            },
            AutonomousError::RiskThresholdExceeded { score: 0, limit: 0 },
            AutonomousError::GovernanceRejected {
                reason: String::new(),
            },
            AutonomousError::FailoverNotAllowed {
                component_id: String::new(),
                reason: String::new(),
            },
            AutonomousError::RemoteHostUnreachable {
                host_id: String::new(),
            },
            AutonomousError::InvalidStateTransition {
                from: String::new(),
                to: String::new(),
            },
            AutonomousError::AutonomyLevelInsufficient {
                current: String::new(),
                required: String::new(),
            },
            AutonomousError::CoordinationConflict {
                detail: String::new(),
            },
            AutonomousError::InvalidAiResponse {
                detail: String::new(),
            },
            AutonomousError::EvidenceSyncFailed {
                host_id: String::new(),
                reason: String::new(),
            },
            AutonomousError::InvalidFailoverState(String::new()),
            AutonomousError::FailoverLimitExceeded { max: 0, current: 0 },
            AutonomousError::CoordinatorPromotionFailed(String::new()),
            AutonomousError::FailoverNotFound(String::new()),
            AutonomousError::AutonomyForbidden {
                level: String::new(),
            },
            AutonomousError::GovernanceVeto {
                action: String::new(),
            },
            AutonomousError::ClauseNotFound {
                clause_id: String::new(),
            },
            AutonomousError::QuorumNotMet {
                present: 0,
                required: 0,
            },
            AutonomousError::InsufficientSignatures {
                valid: 0,
                required: 0,
            },
            AutonomousError::ImmutableClause {
                clause_id: String::new(),
            },
            AutonomousError::ConstitutionalViolation {
                clause_title: String::new(),
                detail: String::new(),
            },
            AutonomousError::InvalidVote {
                reason: String::new(),
            },
            AutonomousError::FederationPushFailed { hosts: Vec::new() },
            AutonomousError::InvalidArgument(String::new()),
        ];
        assert_eq!(variants.len(), 28);
    }

    #[test]
    fn errors_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AutonomousError>();
    }
}
