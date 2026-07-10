//! `aios-recovery` — typed core skeleton for S9.1, S9.2, and S9.3.
//!
//! T-074 intentionally stops at the type surface: recovery mode state,
//! first-boot context, dedicated-kernel candidate metadata, the degraded
//! recovery bundle, and the recovery error taxonomy.

#![forbid(unsafe_code)]

pub mod boot;
pub mod boundary;
pub mod bundle;
pub mod error;
pub mod evidence_emit;
pub mod evidence_payloads;
pub mod first_boot;
pub mod in_memory_boundary;
pub mod ipc;
pub mod kernel;
pub mod kernel_pipeline;
pub mod mode;
pub mod policy_adapter;
pub mod recovery_guard;
pub mod registry;
pub mod runtime_adapter;
pub mod self_healing;
pub mod self_healing_driver;
pub mod service;
pub mod watchdog;

pub use boot::{BootId, BootPhase, FirstBootContext, FirstBootPhase, FirstBootStatus};
pub use boundary::{EnterRecoveryRequest, RecoveryBoundary};
pub use bundle::RecoveryBundle;
pub use error::RecoveryError;
pub use evidence_emit::{
    InMemoryRecoveryEvidenceLog, RecoveryEvidenceEmitter, RecoveryEvidenceLog, RecoverySubjectRef,
    AIOS_RECOVERY_SUBJECT,
};
pub use evidence_payloads::{
    ComponentPanicPayload, FirstBootCompletedPayload, FirstBootPhaseCompletedPayload,
    FirstBootStartedPayload, HealingAttemptedPayload, KernelActivatedPayload,
    KernelCandidateRegisteredPayload, KernelGateResultPayload, KernelRolledBackPayload,
    RecoveryEnteredPayload, RecoveryExitedPayload,
};
pub use first_boot::FirstBootDriver;
pub use in_memory_boundary::InMemoryRecoveryBoundary;
pub use ipc::{HealCommand, HealCommandChannel, HealCommandResponse};
pub use kernel::{CandidateId, CandidateState, KernelCandidate, KernelManifest};
pub use kernel_pipeline::KernelPipelineDriver;
pub use mode::{
    HealingCapability, RecoveryMode, RecoveryMutableScope, RecoveryState, RecoverySubBoundary,
};
pub use policy_adapter::RecoveryPolicyHydratorEnhancer;
pub use recovery_guard::RecoveryGuard;
pub use registry::{ComponentIsolationLevel, ComponentRegistry, RegistryEntry};
pub use runtime_adapter::RecoveryRuntimeAdapter;
pub use self_healing::{
    ComponentHealingConfig, ComponentHealingTracker, ComponentHealthState, ComponentSnapshot,
    HealAction, HealActionKind, PanicContext, PanicSeverity, RestartBoundary, RestartPolicy,
    SelfHealingPolicy, SELF_HEALING_SUBJECT,
};
pub use self_healing_driver::{
    HealCycleResult, HealExecutionResult, InMemorySelfHealingDriver, SelfHealingDriver,
};
pub use service::{RecoveryServiceClient, RecoveryServiceGrpcServer, RecoveryServiceImpl};
pub use watchdog::{WatchdogPolicy, WatchdogTimer};

/// Default code version reported by future recovery service metadata surfaces.
pub const DEFAULT_CODE_VERSION: &str = "0.1.0-T083";
