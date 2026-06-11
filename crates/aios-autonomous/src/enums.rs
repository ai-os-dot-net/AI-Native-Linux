use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutonomyLevel {
    Advisory,
    Assisted,
    AutonomousRecovery,
    FullyAutonomous,
}

impl AutonomyLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Advisory => "ADVISORY",
            Self::Assisted => "ASSISTED",
            Self::AutonomousRecovery => "AUTONOMOUS_RECOVERY",
            Self::FullyAutonomous => "FULLY_AUTONOMOUS",
        }
    }

    #[must_use]
    pub fn permits_self_action(&self) -> bool {
        matches!(self, Self::AutonomousRecovery | Self::FullyAutonomous)
    }

    #[must_use]
    pub fn permits_amendments(&self) -> bool {
        matches!(self, Self::FullyAutonomous)
    }
}

impl std::fmt::Display for AutonomyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutonomousAction {
    RebuildQuorum,
    PromoteCoordinator,
    RestartRemote,
    MigrateWorkload,
    SuggestRebuildQuorum,
    SuggestPromoteCoordinator,
    SuggestRestartRemote,
    SuggestMigrateWorkload,
    FailoverComponent,
    IsolateHost,
    AdjustPolicy,
}

impl AutonomousAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PromoteCoordinator => "PROMOTE_COORDINATOR",
            Self::FailoverComponent => "FAILOVER_COMPONENT",
            Self::RestartRemote => "RESTART_REMOTE",
            Self::MigrateWorkload => "MIGRATE_WORKLOAD",
            Self::RebuildQuorum => "REBUILD_QUORUM",
            Self::IsolateHost => "ISOLATE_HOST",
            Self::AdjustPolicy => "ADJUST_POLICY",
            Self::SuggestRebuildQuorum => "SUGGEST_REBUILD_QUORUM",
            Self::SuggestPromoteCoordinator => "SUGGEST_PROMOTE_COORDINATOR",
            Self::SuggestRestartRemote => "SUGGEST_RESTART_REMOTE",
            Self::SuggestMigrateWorkload => "SUGGEST_MIGRATE_WORKLOAD",
        }
    }

    #[must_use]
    pub fn is_suggestion(&self) -> bool {
        matches!(
            self,
            Self::SuggestRebuildQuorum
                | Self::SuggestPromoteCoordinator
                | Self::SuggestRestartRemote
                | Self::SuggestMigrateWorkload
        )
    }
}

impl std::fmt::Display for AutonomousAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::RebuildQuorum => "RebuildQuorum",
            Self::PromoteCoordinator => "PromoteCoordinator",
            Self::RestartRemote => "RestartRemote",
            Self::MigrateWorkload => "MigrateWorkload",
            Self::SuggestRebuildQuorum => "SuggestRebuildQuorum",
            Self::SuggestPromoteCoordinator => "SuggestPromoteCoordinator",
            Self::SuggestRestartRemote => "SuggestRestartRemote",
            Self::SuggestMigrateWorkload => "SuggestMigrateWorkload",
            Self::FailoverComponent => "FailoverComponent",
            Self::IsolateHost => "IsolateHost",
            Self::AdjustPolicy => "AdjustPolicy",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FleetHealthAggregate {
    Healthy { resource_imbalance: bool },
    Degraded,
    Critical,
    QuorumLost,
}

impl FleetHealthAggregate {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy { .. } => "HEALTHY",
            Self::Degraded => "DEGRADED",
            Self::Critical => "CRITICAL",
            Self::QuorumLost => "QUORUM_LOST",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrchestratorMode {
    Disabled,
    MonitorOnly,
    Suggest,
    ExecuteRecovery,
    FullAutonomy,
}

impl OrchestratorMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "DISABLED",
            Self::MonitorOnly => "MONITOR_ONLY",
            Self::Suggest => "SUGGEST",
            Self::ExecuteRecovery => "EXECUTE_RECOVERY",
            Self::FullAutonomy => "FULL_AUTONOMY",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AutonomousDecisionVerdict {
    Approved,
    DeniedRisk,
    DeniedPolicy,
    DeniedInsufficientEvidence,
    DeniedAutonomy,
    DeniedGovernance,
}

impl AutonomousDecisionVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approved => "APPROVED",
            Self::DeniedRisk => "DENIED_RISK",
            Self::DeniedPolicy => "DENIED_POLICY",
            Self::DeniedInsufficientEvidence => "DENIED_INSUFFICIENT_EVIDENCE",
            Self::DeniedAutonomy => "DENIED_AUTONOMY",
            Self::DeniedGovernance => "DENIED_GOVERNANCE",
        }
    }
}

impl std::fmt::Display for AutonomousDecisionVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthTrend {
    Improving,
    Stable,
    Degrading,
    Critical,
}

impl HealthTrend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Improving => "IMPROVING",
            Self::Stable => "STABLE",
            Self::Degrading => "DEGRADING",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailoverPhase {
    Monitoring,
    WarmStandby,
    ActiveFailover,
    Completed,
    RolledBack,
}

impl FailoverPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Monitoring => "MONITORING",
            Self::WarmStandby => "WARM_STANDBY",
            Self::ActiveFailover => "ACTIVE_FAILOVER",
            Self::Completed => "COMPLETED",
            Self::RolledBack => "ROLLED_BACK",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceVote {
    Approve,
    Reject,
    Abstain,
    Delegate,
}
