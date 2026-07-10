//! Rust-to-proto translations for the gRPC `RecoveryService` surface (T-079).

#![allow(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::result_large_err,
    reason = "conversion function names are intentionally literal and covered by tests"
)]

use aios_action::ActionId;
use chrono::{DateTime, TimeZone, Utc};
use prost_types::Timestamp;
use serde::de::DeserializeOwned;
use tonic::Status;

use crate::service::proto;
use crate::{
    BootId, BootPhase, CandidateId, CandidateState, EnterRecoveryRequest, FirstBootContext,
    FirstBootPhase, FirstBootStatus, KernelCandidate, KernelManifest, RecoveryBundle,
    RecoveryError, RecoveryMode, RecoveryState,
};

pub const ACTION_ID_FORMAT_UNSPECIFIED: u32 = 0;
pub const ACTION_ID_FORMAT_UTF8: u32 = 1;

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

pub fn datetime_to_proto(dt: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: i32::try_from(dt.timestamp_subsec_nanos()).unwrap_or(0),
    }
}

pub fn datetime_from_proto(ts: Timestamp) -> DateTime<Utc> {
    Utc.timestamp_opt(ts.seconds, u32::try_from(ts.nanos).unwrap_or(0))
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap_or_default())
}

fn required_datetime_from_proto(
    ts: Option<Timestamp>,
    field: &'static str,
) -> Result<DateTime<Utc>, Status> {
    ts.map(datetime_from_proto)
        .ok_or_else(|| Status::invalid_argument(format!("{field} is required")))
}

// ---------------------------------------------------------------------------
// Error -> tonic::Status
// ---------------------------------------------------------------------------

pub fn recovery_error_to_status(err: &RecoveryError) -> Status {
    match err {
        RecoveryError::RecoveryNotActive
        | RecoveryError::AlreadyInRecovery
        | RecoveryError::InvalidPhaseTransition { .. }
        | RecoveryError::InvalidCandidateTransition { .. } => {
            Status::failed_precondition(err.to_string())
        }
        RecoveryError::BundleSignatureInvalid
        | RecoveryError::KernelSignatureInvalid
        | RecoveryError::RecoveryOnlyPathMutationDenied { .. }
        | RecoveryError::AiPathMutationDenied { .. }
        | RecoveryError::RecoveryAuthorizationInvalid(_) => {
            Status::permission_denied(err.to_string())
        }
        RecoveryError::BundleUnknownAuthority(_) | RecoveryError::KernelUnknownAuthority(_) => {
            Status::unauthenticated(err.to_string())
        }
        RecoveryError::CandidateNotFound(_) => Status::not_found(err.to_string()),
        RecoveryError::FirstBootAlreadyCompleted => Status::already_exists(err.to_string()),
        RecoveryError::EvidenceEmitFailed(_)
        | RecoveryError::Internal(_)
        | RecoveryError::SelfHealingPolicyInvalid(_)
        | RecoveryError::SelfHealingRecoveryNotActive(_)
        | RecoveryError::SelfHealingComponentUnknown(_) => Status::internal(err.to_string()),
        RecoveryError::SelfHealingEscalationRequired { .. } => Status::unavailable(err.to_string()),
    }
}

// ---------------------------------------------------------------------------
// ID helpers
// ---------------------------------------------------------------------------

pub fn action_id_to_proto(action_id: &ActionId) -> Vec<u8> {
    action_id.as_str().as_bytes().to_vec()
}

pub fn action_id_from_proto(bytes: &[u8]) -> Result<ActionId, Status> {
    if bytes.is_empty() {
        return Err(Status::invalid_argument("action_id_proto is required"));
    }
    let raw = std::str::from_utf8(bytes)
        .map_err(|err| Status::invalid_argument(format!("action_id_proto is not UTF-8: {err}")))?;
    ActionId::parse(raw)
        .map_err(|err| Status::invalid_argument(format!("invalid action id `{raw}`: {err}")))
}

fn transparent_newtype_from_string<T: DeserializeOwned>(
    value: String,
    field: &'static str,
) -> Result<T, Status> {
    serde_json::from_value(serde_json::Value::String(value))
        .map_err(|err| Status::invalid_argument(format!("invalid {field}: {err}")))
}

pub fn boot_id_from_string(value: String) -> Result<BootId, Status> {
    if !value.starts_with(BootId::PREFIX) {
        return Err(Status::invalid_argument(format!(
            "boot_id must start with `{}`",
            BootId::PREFIX
        )));
    }
    transparent_newtype_from_string(value, "boot_id")
}

pub fn candidate_id_from_string(value: String) -> Result<CandidateId, Status> {
    if !value.starts_with(CandidateId::PREFIX) {
        return Err(Status::invalid_argument(format!(
            "candidate_id must start with `{}`",
            CandidateId::PREFIX
        )));
    }
    transparent_newtype_from_string(value, "candidate_id")
}

// ---------------------------------------------------------------------------
// Enum conversions
// ---------------------------------------------------------------------------

pub const fn recovery_mode_to_proto(mode: RecoveryMode) -> proto::RecoveryModeProto {
    match mode {
        RecoveryMode::Normal => proto::RecoveryModeProto::RecoveryModeNormal,
        RecoveryMode::Recovery => proto::RecoveryModeProto::RecoveryModeRecovery,
        RecoveryMode::Degraded => proto::RecoveryModeProto::RecoveryModeDegraded,
        RecoveryMode::FirstBoot => proto::RecoveryModeProto::RecoveryModeFirstBoot,
    }
}

pub fn recovery_mode_from_proto(mode: proto::RecoveryModeProto) -> Result<RecoveryMode, Status> {
    match mode {
        proto::RecoveryModeProto::RecoveryModeNormal => Ok(RecoveryMode::Normal),
        proto::RecoveryModeProto::RecoveryModeRecovery => Ok(RecoveryMode::Recovery),
        proto::RecoveryModeProto::RecoveryModeDegraded => Ok(RecoveryMode::Degraded),
        proto::RecoveryModeProto::RecoveryModeFirstBoot => Ok(RecoveryMode::FirstBoot),
        proto::RecoveryModeProto::RecoveryModeUnspecified => {
            Err(Status::invalid_argument("recovery mode is unspecified"))
        }
    }
}

pub const fn boot_phase_to_proto(phase: BootPhase) -> proto::BootPhaseProto {
    match phase {
        BootPhase::Cold => proto::BootPhaseProto::BootPhaseCold,
        BootPhase::Bootstrap => proto::BootPhaseProto::BootPhaseBootstrap,
        BootPhase::FirstBoot => proto::BootPhaseProto::BootPhaseFirstBoot,
        BootPhase::Normal => proto::BootPhaseProto::BootPhaseNormal,
        BootPhase::Recovery => proto::BootPhaseProto::BootPhaseRecovery,
    }
}

pub fn boot_phase_from_proto(phase: proto::BootPhaseProto) -> Result<BootPhase, Status> {
    match phase {
        proto::BootPhaseProto::BootPhaseCold => Ok(BootPhase::Cold),
        proto::BootPhaseProto::BootPhaseBootstrap => Ok(BootPhase::Bootstrap),
        proto::BootPhaseProto::BootPhaseFirstBoot => Ok(BootPhase::FirstBoot),
        proto::BootPhaseProto::BootPhaseNormal => Ok(BootPhase::Normal),
        proto::BootPhaseProto::BootPhaseRecovery => Ok(BootPhase::Recovery),
        proto::BootPhaseProto::BootPhaseUnspecified => {
            Err(Status::invalid_argument("boot phase is unspecified"))
        }
    }
}

pub const fn first_boot_phase_to_proto(phase: FirstBootPhase) -> proto::FirstBootPhaseProto {
    match phase {
        FirstBootPhase::StageInstallerMediaVerified => {
            proto::FirstBootPhaseProto::FirstBootPhaseInstallerMediaVerified
        }
        FirstBootPhase::StageDiskPartitioned => {
            proto::FirstBootPhaseProto::FirstBootPhaseDiskPartitioned
        }
        FirstBootPhase::StageKernelInstalled => {
            proto::FirstBootPhaseProto::FirstBootPhaseKernelInstalled
        }
        FirstBootPhase::StageAiosFsInitialized => {
            proto::FirstBootPhaseProto::FirstBootPhaseAiosFsInitialized
        }
        FirstBootPhase::StageVaultRootGenerated => {
            proto::FirstBootPhaseProto::FirstBootPhaseVaultRootGenerated
        }
        FirstBootPhase::StageInvariantBundleLoaded => {
            proto::FirstBootPhaseProto::FirstBootPhaseInvariantBundleLoaded
        }
        FirstBootPhase::StagePolicyBundleLoaded => {
            proto::FirstBootPhaseProto::FirstBootPhasePolicyBundleLoaded
        }
        FirstBootPhase::StageIdentityBundleLoaded => {
            proto::FirstBootPhaseProto::FirstBootPhaseIdentityBundleLoaded
        }
        FirstBootPhase::StageRecoveryOperatorRegistration => {
            proto::FirstBootPhaseProto::FirstBootPhaseRecoveryOperatorRegistration
        }
        FirstBootPhase::StageAiProviderConfiguration => {
            proto::FirstBootPhaseProto::FirstBootPhaseAiProviderConfiguration
        }
        FirstBootPhase::StageFirstGroupRegistration => {
            proto::FirstBootPhaseProto::FirstBootPhaseFirstGroupRegistration
        }
        FirstBootPhase::StageFirstUserRegistration => {
            proto::FirstBootPhaseProto::FirstBootPhaseFirstUserRegistration
        }
        FirstBootPhase::StageRuntimeServicesStarted => {
            proto::FirstBootPhaseProto::FirstBootPhaseRuntimeServicesStarted
        }
        FirstBootPhase::StageFirstBootComplete => {
            proto::FirstBootPhaseProto::FirstBootPhaseFirstBootComplete
        }
        FirstBootPhase::StageFailedRequiresRecovery => {
            proto::FirstBootPhaseProto::FirstBootPhaseFailedRequiresRecovery
        }
    }
}

pub fn first_boot_phase_from_proto(
    phase: proto::FirstBootPhaseProto,
) -> Result<FirstBootPhase, Status> {
    match phase {
        proto::FirstBootPhaseProto::FirstBootPhaseInstallerMediaVerified => {
            Ok(FirstBootPhase::StageInstallerMediaVerified)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseDiskPartitioned => {
            Ok(FirstBootPhase::StageDiskPartitioned)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseKernelInstalled => {
            Ok(FirstBootPhase::StageKernelInstalled)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseAiosFsInitialized => {
            Ok(FirstBootPhase::StageAiosFsInitialized)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseVaultRootGenerated => {
            Ok(FirstBootPhase::StageVaultRootGenerated)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseInvariantBundleLoaded => {
            Ok(FirstBootPhase::StageInvariantBundleLoaded)
        }
        proto::FirstBootPhaseProto::FirstBootPhasePolicyBundleLoaded => {
            Ok(FirstBootPhase::StagePolicyBundleLoaded)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseIdentityBundleLoaded => {
            Ok(FirstBootPhase::StageIdentityBundleLoaded)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseRecoveryOperatorRegistration => {
            Ok(FirstBootPhase::StageRecoveryOperatorRegistration)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseAiProviderConfiguration => {
            Ok(FirstBootPhase::StageAiProviderConfiguration)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseFirstGroupRegistration => {
            Ok(FirstBootPhase::StageFirstGroupRegistration)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseFirstUserRegistration => {
            Ok(FirstBootPhase::StageFirstUserRegistration)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseRuntimeServicesStarted => {
            Ok(FirstBootPhase::StageRuntimeServicesStarted)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseFirstBootComplete => {
            Ok(FirstBootPhase::StageFirstBootComplete)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseFailedRequiresRecovery => {
            Ok(FirstBootPhase::StageFailedRequiresRecovery)
        }
        proto::FirstBootPhaseProto::FirstBootPhaseUnspecified => {
            Err(Status::invalid_argument("first-boot phase is unspecified"))
        }
    }
}

pub const fn first_boot_status_to_proto(status: FirstBootStatus) -> proto::FirstBootStatusProto {
    match status {
        FirstBootStatus::NotStarted => proto::FirstBootStatusProto::FirstBootStatusNotStarted,
        FirstBootStatus::InProgress => proto::FirstBootStatusProto::FirstBootStatusInProgress,
        FirstBootStatus::Completed => proto::FirstBootStatusProto::FirstBootStatusCompleted,
        FirstBootStatus::Failed => proto::FirstBootStatusProto::FirstBootStatusFailed,
        FirstBootStatus::Skipped => proto::FirstBootStatusProto::FirstBootStatusSkipped,
    }
}

pub fn first_boot_status_from_proto(
    status: proto::FirstBootStatusProto,
) -> Result<FirstBootStatus, Status> {
    match status {
        proto::FirstBootStatusProto::FirstBootStatusNotStarted => Ok(FirstBootStatus::NotStarted),
        proto::FirstBootStatusProto::FirstBootStatusInProgress => Ok(FirstBootStatus::InProgress),
        proto::FirstBootStatusProto::FirstBootStatusCompleted => Ok(FirstBootStatus::Completed),
        proto::FirstBootStatusProto::FirstBootStatusFailed => Ok(FirstBootStatus::Failed),
        proto::FirstBootStatusProto::FirstBootStatusSkipped => Ok(FirstBootStatus::Skipped),
        proto::FirstBootStatusProto::FirstBootStatusUnspecified => {
            Err(Status::invalid_argument("first-boot status is unspecified"))
        }
    }
}

pub const fn candidate_state_to_proto(state: CandidateState) -> proto::CandidateStateProto {
    match state {
        CandidateState::Building => proto::CandidateStateProto::CandidateBuilding,
        CandidateState::Built => proto::CandidateStateProto::CandidateRegistered,
        CandidateState::Gating => proto::CandidateStateProto::CandidateGating,
        CandidateState::GatePassed => proto::CandidateStateProto::CandidateVerified,
        CandidateState::GateFailed => proto::CandidateStateProto::CandidateGateFailed,
        CandidateState::APromoted => proto::CandidateStateProto::CandidateActive,
        CandidateState::BDemotedToA => proto::CandidateStateProto::CandidateBDemotedToA,
        CandidateState::Rollback => proto::CandidateStateProto::CandidateRollback,
        CandidateState::Retired => proto::CandidateStateProto::CandidateRetired,
    }
}

pub fn candidate_state_from_proto(
    state: proto::CandidateStateProto,
) -> Result<CandidateState, Status> {
    match state {
        proto::CandidateStateProto::CandidateBuilding => Ok(CandidateState::Building),
        proto::CandidateStateProto::CandidateRegistered => Ok(CandidateState::Built),
        proto::CandidateStateProto::CandidateGating => Ok(CandidateState::Gating),
        proto::CandidateStateProto::CandidateVerified => Ok(CandidateState::GatePassed),
        proto::CandidateStateProto::CandidateGateFailed => Ok(CandidateState::GateFailed),
        proto::CandidateStateProto::CandidateActive => Ok(CandidateState::APromoted),
        proto::CandidateStateProto::CandidateBDemotedToA => Ok(CandidateState::BDemotedToA),
        proto::CandidateStateProto::CandidateRollback => Ok(CandidateState::Rollback),
        proto::CandidateStateProto::CandidateRetired => Ok(CandidateState::Retired),
        proto::CandidateStateProto::CandidateStateUnspecified => {
            Err(Status::invalid_argument("candidate state is unspecified"))
        }
    }
}

// ---------------------------------------------------------------------------
// Struct conversions
// ---------------------------------------------------------------------------

pub fn recovery_state_to_proto(state: &RecoveryState) -> proto::RecoveryStateProto {
    proto::RecoveryStateProto {
        mode: i32::from(recovery_mode_to_proto(state.mode)),
        entered_at: state.entered_at.map(datetime_to_proto),
        exit_planned_at: state.exit_planned_at.map(datetime_to_proto),
        reason: state.reason.clone(),
        operator_grant: state.operator_grant.clone(),
    }
}

pub fn recovery_state_from_proto(
    proto: proto::RecoveryStateProto,
) -> Result<RecoveryState, Status> {
    Ok(RecoveryState {
        mode: recovery_mode_from_proto(proto::RecoveryModeProto::try_from(proto.mode).map_err(
            |_| Status::invalid_argument(format!("unknown recovery mode {}", proto.mode)),
        )?)?,
        entered_at: proto.entered_at.map(datetime_from_proto),
        exit_planned_at: proto.exit_planned_at.map(datetime_from_proto),
        reason: proto.reason,
        operator_grant: proto.operator_grant,
        active_sub_boundaries: Vec::new(),
    })
}

pub fn recovery_bundle_to_proto(bundle: &RecoveryBundle) -> proto::RecoveryBundleProto {
    proto::RecoveryBundleProto {
        bundle_id: bundle.bundle_id.clone(),
        loaded_at: Some(datetime_to_proto(bundle.loaded_at)),
        hard_deny_signatures: bundle.hard_deny_signatures.clone(),
        override_signatures: bundle.override_signatures.clone(),
        signing_authority: bundle.signing_authority.clone(),
    }
}

pub fn recovery_bundle_from_proto(
    proto: proto::RecoveryBundleProto,
) -> Result<RecoveryBundle, Status> {
    Ok(RecoveryBundle {
        bundle_id: proto.bundle_id,
        loaded_at: required_datetime_from_proto(proto.loaded_at, "loaded_at")?,
        hard_deny_signatures: proto.hard_deny_signatures,
        override_signatures: proto.override_signatures,
        signing_authority: proto.signing_authority,
    })
}

pub fn enter_recovery_request_from_proto(
    proto: proto::EnterRecoveryRequestProto,
) -> Result<EnterRecoveryRequest, Status> {
    Ok(EnterRecoveryRequest {
        reason: proto.reason,
        operator_grant: proto.operator_grant,
        expected_phases: proto
            .expected_phases
            .into_iter()
            .map(|phase| {
                proto::BootPhaseProto::try_from(phase)
                    .map_err(|_| Status::invalid_argument(format!("unknown boot phase {phase}")))
                    .and_then(boot_phase_from_proto)
            })
            .collect::<Result<Vec<_>, _>>()?,
        bundle: proto.bundle.map(recovery_bundle_from_proto).transpose()?,
    })
}

pub fn first_boot_context_to_proto(context: &FirstBootContext) -> proto::FirstBootContextProto {
    proto::FirstBootContextProto {
        boot_id: context.boot_id.as_str().to_owned(),
        started_at: Some(datetime_to_proto(context.started_at)),
        completed_at: context.completed_at.map(datetime_to_proto),
        status: i32::from(first_boot_status_to_proto(context.status)),
        performed_phases: context
            .performed_phases
            .iter()
            .copied()
            .map(first_boot_phase_to_proto)
            .map(i32::from)
            .collect(),
    }
}

pub fn first_boot_context_from_proto(
    proto: proto::FirstBootContextProto,
) -> Result<FirstBootContext, Status> {
    Ok(FirstBootContext {
        boot_id: boot_id_from_string(proto.boot_id)?,
        started_at: required_datetime_from_proto(proto.started_at, "started_at")?,
        completed_at: proto.completed_at.map(datetime_from_proto),
        status: first_boot_status_from_proto(
            proto::FirstBootStatusProto::try_from(proto.status).map_err(|_| {
                Status::invalid_argument(format!("unknown first-boot status {}", proto.status))
            })?,
        )?,
        performed_phases: proto
            .performed_phases
            .into_iter()
            .map(|phase| {
                proto::FirstBootPhaseProto::try_from(phase)
                    .map_err(|_| {
                        Status::invalid_argument(format!("unknown first-boot phase {phase}"))
                    })
                    .and_then(first_boot_phase_from_proto)
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub fn kernel_manifest_to_proto(manifest: &KernelManifest) -> proto::KernelManifestProto {
    proto::KernelManifestProto {
        version: manifest.version.clone(),
        min_aios_version: manifest.min_aios_version.clone(),
        requires_recovery_install: manifest.requires_recovery_install,
        verification_intent: manifest.verification_intent.clone(),
        tags: manifest.tags.clone(),
    }
}

pub fn kernel_manifest_from_proto(
    proto: proto::KernelManifestProto,
) -> Result<KernelManifest, Status> {
    if proto.version.trim().is_empty() {
        return Err(Status::invalid_argument("manifest.version is required"));
    }
    Ok(KernelManifest {
        version: proto.version,
        min_aios_version: proto.min_aios_version,
        requires_recovery_install: proto.requires_recovery_install,
        verification_intent: proto.verification_intent,
        tags: proto.tags,
    })
}

pub fn kernel_candidate_to_proto(candidate: &KernelCandidate) -> proto::KernelCandidateProto {
    proto::KernelCandidateProto {
        candidate_id: candidate.candidate_id.as_str().to_owned(),
        version: candidate.version.clone(),
        kernel_blake3: candidate.kernel_blake3.clone(),
        signature_ed25519: candidate.signature_ed25519.clone(),
        signing_authority: candidate.signing_authority.clone(),
        registered_at: Some(datetime_to_proto(candidate.registered_at)),
        state: i32::from(candidate_state_to_proto(candidate.state)),
        manifest: Some(kernel_manifest_to_proto(&candidate.manifest)),
    }
}

pub fn kernel_candidate_from_proto(
    proto: proto::KernelCandidateProto,
) -> Result<KernelCandidate, Status> {
    Ok(KernelCandidate {
        candidate_id: candidate_id_from_string(proto.candidate_id)?,
        version: proto.version,
        kernel_blake3: proto.kernel_blake3,
        signature_ed25519: proto.signature_ed25519,
        signing_authority: proto.signing_authority,
        registered_at: required_datetime_from_proto(proto.registered_at, "registered_at")?,
        state: candidate_state_from_proto(
            proto::CandidateStateProto::try_from(proto.state).map_err(|_| {
                Status::invalid_argument(format!("unknown candidate state {}", proto.state))
            })?,
        )?,
        manifest: kernel_manifest_from_proto(
            proto
                .manifest
                .ok_or_else(|| Status::invalid_argument("manifest is required"))?,
        )?,
    })
}
