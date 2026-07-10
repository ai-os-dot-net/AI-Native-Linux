//! Typed recovery evidence payloads for S9.x -> S3.1 emission.

#![allow(
    clippy::module_name_repetitions,
    reason = "Public names mirror the S9.x evidence vocabulary"
)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::self_healing::{ComponentHealthState, HealActionKind, PanicSeverity};
use crate::{BootId, CandidateId, FirstBootPhase, RecoveryMode, RecoveryMutableScope};

/// Payload for recovery entry evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RecoveryEnteredPayload {
    /// Mode observed before recovery entry.
    pub from_mode: RecoveryMode,
    /// Mode observed after recovery entry.
    pub to_mode: RecoveryMode,
    /// UTC timestamp when recovery was entered.
    pub entered_at: DateTime<Utc>,
    /// S9.1 recovery-entry reason token.
    pub reason: Option<String>,
    /// Optional operator grant id authorising the recovery session.
    pub operator_grant: Option<String>,
}

/// Payload for recovery exit evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RecoveryExitedPayload {
    /// Mode observed before recovery exit.
    pub from_mode: RecoveryMode,
    /// Mode observed after recovery exit.
    pub to_mode: RecoveryMode,
    /// UTC timestamp when recovery was exited.
    pub exited_at: DateTime<Utc>,
    /// BLAKE3 hash of the opaque exit token; never the raw token.
    ///
    /// Serialized as `exit_hash` because S3.1 default redaction strips any
    /// JSON key containing `token`.
    #[serde(rename = "exit_hash", alias = "exit_token")]
    pub exit_token: String,
}

/// Payload for first-boot start evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FirstBootStartedPayload {
    /// First-boot session id.
    pub boot_id: BootId,
    /// UTC timestamp when first-boot started.
    pub started_at: DateTime<Utc>,
    /// Expected happy-path phase sequence.
    pub expected_phases: Vec<FirstBootPhase>,
}

/// Payload for first-boot phase-completion evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FirstBootPhaseCompletedPayload {
    /// First-boot session id.
    pub boot_id: BootId,
    /// Completed phase.
    pub phase: FirstBootPhase,
    /// UTC timestamp when the phase completed.
    pub completed_at: DateTime<Utc>,
}

/// Payload for first-boot terminal completion evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FirstBootCompletedPayload {
    /// First-boot session id.
    pub boot_id: BootId,
    /// UTC timestamp when first-boot completed.
    pub completed_at: DateTime<Utc>,
    /// Total phases recorded for the session.
    pub total_phases: u64,
    /// Phases intentionally skipped by the coordinator.
    pub skipped_phases: Vec<FirstBootPhase>,
}

/// Payload for kernel-candidate registration evidence.
///
/// This payload intentionally carries no raw `Ed25519` signature bytes. The
/// authority and content hash are enough for S3.1 linkage; raw signature
/// material remains on the candidate record, not in evidence payload JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct KernelCandidateRegisteredPayload {
    /// Registered candidate id.
    pub candidate_id: CandidateId,
    /// Candidate version string.
    pub version: String,
    /// Full lower-hex BLAKE3 hash of the signed manifest binding.
    pub kernel_blake3: String,
    /// Manifest signing authority name.
    pub signing_authority: String,
    /// UTC timestamp when the candidate was registered.
    pub registered_at: DateTime<Utc>,
}

/// Payload for kernel-candidate activation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct KernelActivatedPayload {
    /// Activated candidate id.
    pub candidate_id: CandidateId,
    /// Candidate version string.
    pub version: String,
    /// Full lower-hex BLAKE3 hash of the signed manifest binding.
    pub kernel_blake3: String,
    /// UTC timestamp when the candidate was promoted.
    pub activated_at: DateTime<Utc>,
    /// Whether the manifest required recovery mode for activation.
    pub required_recovery: bool,
}

/// Payload for kernel rollback evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct KernelRolledBackPayload {
    /// Candidate rolled back from slot A.
    pub candidate_id: CandidateId,
    /// Previous active candidate restored by rollback.
    pub previous_candidate_id: CandidateId,
    /// Non-secret rollback reason.
    pub reason: String,
    /// UTC timestamp when rollback completed.
    pub rolled_back_at: DateTime<Utc>,
}

/// Payload for the shallow T-080 gate-pass witness emitted by `verify_candidate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct KernelGateResultPayload {
    /// Candidate whose gate result was recorded.
    pub candidate_id: CandidateId,
    /// Candidate version string.
    pub version: String,
    /// Full lower-hex BLAKE3 hash of the signed manifest binding.
    pub kernel_blake3: String,
    /// Closed result token for the current shallow gate stub.
    pub result: String,
    /// UTC timestamp when the gate result completed.
    pub completed_at: DateTime<Utc>,
}

/// Payload for an autonomous self-healing action attempt.
///
/// Emitted by the self-healing driver every time it decides and executes a
/// healing operation on a component.  Retention class: **Forever**
/// (autonomous system actions are never purged).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HealingAttemptedPayload {
    /// Target component id.
    pub component_id: String,
    /// Observed health state that triggered this action.
    pub observed_state: ComponentHealthState,
    /// Healing action kind decided by the driver.
    pub action_kind: HealActionKind,
    /// Recovery-mutable scope used for authorisation.
    pub required_scope: RecoveryMutableScope,
    /// Human-readable decision rationale.
    pub reason: String,
    /// UTC timestamp when the driver produced this decision.
    pub decided_at: DateTime<Utc>,
    /// Monotonic sequence number within the current boot session.
    pub sequence: u64,
}

/// Payload for a structured component panic event (MINIX-inspired post-mortem).
///
/// Unlike [`HealingAttemptedPayload`] which captures *healing decisions*,
/// this payload captures the *crash itself* — what happened, where, how severe,
/// and where to find the artefacts for post-mortem analysis.
///
/// Emitted by the self-healing driver whenever `observe_panic()` is called.
/// Retention class: **Forever** (panic evidence is never purged).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ComponentPanicPayload {
    /// Component id that panicked.
    pub component_id: String,
    /// Classified severity of the panic.
    pub severity: PanicSeverity,
    /// Human-readable panic message or assertion string.
    pub message: String,
    /// Source file where the panic originated.
    pub file: Option<String>,
    /// Line number inside the source file.
    pub line: Option<u32>,
    /// BLAKE3 hash of the symbolised backtrace (for deduplication).
    pub backtrace_hash: Option<String>,
    /// Reference path to a core dump file.
    pub core_dump_ref: Option<String>,
    /// UTC timestamp when the panic was observed.
    pub observed_at: DateTime<Utc>,
    /// Consecutive panic count including this one.
    pub consecutive_panics: u32,
    /// Whether the panic was classified as auto-recoverable by restart.
    pub recoverable_by_restart: bool,
    /// Whether escalation was required instead of restart.
    pub requires_escalation: bool,
}
