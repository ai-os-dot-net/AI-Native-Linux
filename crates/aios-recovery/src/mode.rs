//! S9.1 recovery mode and active-state vocabulary.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// MINIX-inspired recovery sub-boundary classification.
///
/// Each variant represents an independently-managed recovery zone (network,
/// storage, compute).  A component in one sub-boundary can be healed without
/// entering full system recovery.  [`RecoverySubBoundary::SystemFull`] is the
/// default and implies full recovery authority over all sub-boundaries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount, Default,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoverySubBoundary {
    /// Network-layer recovery (DNS, routes, interfaces, mesh routing).
    Network,
    /// Storage-layer recovery (filesystem mounts, snapshot state).
    Storage,
    /// Compute-layer recovery (process lifecycle, sysctl tuning).
    Compute,
    /// Full system recovery — all sub-boundaries are implicitly active.
    #[default]
    SystemFull,
}

impl RecoverySubBoundary {
    /// Map a [`RecoveryMutableScope`] to the narrowest sub-boundary that
    /// covers it.  Returns `None` when no direct mapping exists (should not
    /// happen for any valid scope variant).
    #[must_use]
    pub const fn from_mutable_scope(scope: RecoveryMutableScope) -> Option<Self> {
        match scope {
            RecoveryMutableScope::ProcessLifecycle | RecoveryMutableScope::SysctlTuning => {
                Some(Self::Compute)
            }
            RecoveryMutableScope::NetworkReconfig | RecoveryMutableScope::MeshRouting => {
                Some(Self::Network)
            }
            RecoveryMutableScope::FilesystemMutation => Some(Self::Storage),
        }
    }

    /// Returns `true` when `self` subsumes `other`.
    ///
    /// [`RecoverySubBoundary::SystemFull`] contains every other sub-boundary.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::SystemFull, _)
                | (Self::Network, Self::Network)
                | (Self::Storage, Self::Storage)
                | (Self::Compute, Self::Compute)
        )
    }
}

/// Closed S9.1 boot-time mode classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryMode {
    /// `NORMAL` - full AIOS stack running.
    Normal,
    /// `RECOVERY` - recovery boot path active with degraded L4 only.
    Recovery,
    /// `DEGRADED` - abnormal normal-mode, not recovery privileges.
    Degraded,
    /// `FIRST_BOOT` - first-boot installer active.
    FirstBoot,
}

/// Scoped mutation grants available only inside an active recovery session.
///
/// Each variant represents a class of state mutation that requires explicit
/// recovery-mode authority.  The self-healing subject holds pre-authorised
/// grants for a subset of these scopes; the runtime adapter enforces scope
/// boundaries at execution time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryMutableScope {
    /// Restart / stop / start of L1–L4 infrastructure processes.
    #[default]
    ProcessLifecycle,
    /// Reconfiguration of networking (DNS, routes, interfaces).
    NetworkReconfig,
    /// Mount / unmount / remount of filesystem paths (non-L5).
    FilesystemMutation,
    /// Kernel parameter tuning via `/proc/sys`.
    SysctlTuning,
    /// Service-mesh routing rule updates.
    MeshRouting,
}

/// MINIX-inspired fine-grained capability grants for the self-healing subject.
///
/// Each capability maps to a [`RecoveryMutableScope`] and represents a specific
/// healing action the subject is authorized to perform. Unlike the coarse
/// [`RecoveryMutableScope`] model, capabilities grant exactly what each action
/// needs — nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealingCapability {
    /// Restart a component process (start / stop / restart lifecycle).
    #[default]
    CanRestartProcess,
    /// Restart network interfaces or services wholesale.
    CanRestartNetwork,
    /// Reconfigure DNS resolution settings.
    #[serde(rename = "CAN_RECONFIGURE_DNS")]
    CanReconfigureDNS,
    /// Isolate a node from the service mesh (drain traffic, remove routes).
    CanIsolateMeshNode,
    /// Capture and persist component state snapshots.
    CanSnapshotState,
    /// Escalate an incident to the operator (no autonomous action possible).
    CanEscalateToOperator,
}

impl HealingCapability {
    /// Returns the [`RecoveryMutableScope`] required by this capability.
    #[must_use]
    pub const fn required_scope(self) -> RecoveryMutableScope {
        match self {
            Self::CanRestartProcess | Self::CanEscalateToOperator => {
                RecoveryMutableScope::ProcessLifecycle
            }
            Self::CanRestartNetwork | Self::CanReconfigureDNS => {
                RecoveryMutableScope::NetworkReconfig
            }
            Self::CanIsolateMeshNode => RecoveryMutableScope::MeshRouting,
            Self::CanSnapshotState => RecoveryMutableScope::FilesystemMutation,
        }
    }

    /// Returns `true` when this capability is a subset of the given scope.
    ///
    /// A capability is a subset of a scope when the scope covers at least
    /// the operations required by the capability.
    #[must_use]
    pub const fn is_subset_of(self, scope: RecoveryMutableScope) -> bool {
        matches!(
            (self, scope),
            (
                Self::CanRestartProcess | Self::CanEscalateToOperator,
                RecoveryMutableScope::ProcessLifecycle,
            ) | (
                Self::CanRestartNetwork | Self::CanReconfigureDNS,
                RecoveryMutableScope::NetworkReconfig,
            ) | (Self::CanIsolateMeshNode, RecoveryMutableScope::MeshRouting)
                | (
                    Self::CanSnapshotState,
                    RecoveryMutableScope::FilesystemMutation
                )
        )
    }
}

/// Current recovery-related state observed by the boot/recovery layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryState {
    /// S9.1 closed mode for the host.
    pub mode: RecoveryMode,
    /// UTC timestamp when recovery mode was entered, if active.
    pub entered_at: Option<DateTime<Utc>>,
    /// UTC timestamp at which an exit/reboot is planned.
    pub exit_planned_at: Option<DateTime<Utc>>,
    /// Human-readable entry reason or diagnostic detail.
    pub reason: Option<String>,
    /// Optional S5.4 override binding id authorising this recovery context.
    pub operator_grant: Option<String>,
    /// Individually-active recovery sub-boundaries (MINIX-inspired).
    ///
    /// When empty or containing only [`RecoverySubBoundary::SystemFull`],
    /// the system is in full recovery mode.  Individual sub-boundaries can be
    /// activated independently to heal components within a specific recovery
    /// zone (network, storage, compute) without entering full system recovery.
    #[serde(default)]
    pub active_sub_boundaries: Vec<RecoverySubBoundary>,
}
