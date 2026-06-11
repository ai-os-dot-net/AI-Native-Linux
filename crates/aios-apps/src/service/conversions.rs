//! Rust ↔ proto translations for the gRPC `AppsService` surface (T-122).
//!
//! This module owns the bidirectional translation between the crate's Rust
//! value types and the tonic-generated proto message types. The service
//! module's `server.rs` calls into these functions; tests exercise them
//! directly for round-trip correctness.

#![allow(clippy::result_large_err, missing_docs)]

use chrono::{DateTime, TimeZone, Utc};
use prost_types::Timestamp;

use crate::app_profile::{AppProfile, CompatibilityRating, EvidenceLevel, RatingDimension};
use crate::ecosystem::{EcosystemHonestyClass, EcosystemRuntime, RecipeTrustClass};
use crate::error::AppsError;
use crate::package::PackageId;
use crate::package_store::AppPackage;
use crate::service::proto;
use crate::session_driver::{
    Principal, SessionDescriptor, SessionExitReason, SessionFilter, SessionState,
    SessionTerminationReceipt,
};
use crate::update_driver::{
    FailureClass, RollbackExitState, RollbackReason, RollbackReceipt, UpdateOutcome, UpdatePlan,
    UpdatePlanId, UpdateState, UpdateVerification,
};

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

#[must_use]
pub fn datetime_to_proto(dt: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: i32::try_from(dt.timestamp_subsec_nanos()).unwrap_or(0),
    }
}

#[must_use]
pub fn datetime_from_proto(ts: Timestamp) -> DateTime<Utc> {
    Utc.timestamp_opt(ts.seconds, u32::try_from(ts.nanos).unwrap_or(0))
        .single()
        .unwrap_or_else(unix_epoch)
}

#[must_use]
fn unix_epoch() -> DateTime<Utc> {
    Utc.timestamp_opt(0, 0).single().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// EcosystemRuntime <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn ecosystem_runtime_to_proto(e: EcosystemRuntime) -> proto::EcosystemRuntimeProto {
    match e {
        EcosystemRuntime::RuntimeLinuxNative => proto::EcosystemRuntimeProto::RuntimeLinuxNative,
        EcosystemRuntime::RuntimeFlatpak => proto::EcosystemRuntimeProto::RuntimeFlatpak,
        EcosystemRuntime::RuntimeAppimage => proto::EcosystemRuntimeProto::RuntimeAppimage,
        EcosystemRuntime::RuntimeSnap => proto::EcosystemRuntimeProto::RuntimeSnap,
        EcosystemRuntime::RuntimeDistrobox => proto::EcosystemRuntimeProto::RuntimeDistrobox,
        EcosystemRuntime::RuntimeWindowsProton => {
            proto::EcosystemRuntimeProto::RuntimeWindowsProton
        }
        EcosystemRuntime::RuntimeWindowsVm => proto::EcosystemRuntimeProto::RuntimeWindowsVm,
        EcosystemRuntime::RuntimeAndroidWaydroid => {
            proto::EcosystemRuntimeProto::RuntimeAndroidWaydroid
        }
        EcosystemRuntime::RuntimeAndroidVmWithGms => {
            proto::EcosystemRuntimeProto::RuntimeAndroidVmWithGms
        }
        EcosystemRuntime::RuntimeMacosDarling => proto::EcosystemRuntimeProto::RuntimeMacosDarling,
        EcosystemRuntime::RuntimeMacosVm => proto::EcosystemRuntimeProto::RuntimeMacosVm,
        EcosystemRuntime::RuntimeRemoteAppleBridge => {
            proto::EcosystemRuntimeProto::RuntimeRemoteAppleBridge
        }
    }
}

#[must_use]
pub const fn ecosystem_runtime_from_proto(
    p: proto::EcosystemRuntimeProto,
) -> Option<EcosystemRuntime> {
    match p {
        proto::EcosystemRuntimeProto::RuntimeUnspecified => None,
        proto::EcosystemRuntimeProto::RuntimeLinuxNative => {
            Some(EcosystemRuntime::RuntimeLinuxNative)
        }
        proto::EcosystemRuntimeProto::RuntimeFlatpak => Some(EcosystemRuntime::RuntimeFlatpak),
        proto::EcosystemRuntimeProto::RuntimeAppimage => Some(EcosystemRuntime::RuntimeAppimage),
        proto::EcosystemRuntimeProto::RuntimeSnap => Some(EcosystemRuntime::RuntimeSnap),
        proto::EcosystemRuntimeProto::RuntimeDistrobox => Some(EcosystemRuntime::RuntimeDistrobox),
        proto::EcosystemRuntimeProto::RuntimeWindowsProton => {
            Some(EcosystemRuntime::RuntimeWindowsProton)
        }
        proto::EcosystemRuntimeProto::RuntimeWindowsVm => Some(EcosystemRuntime::RuntimeWindowsVm),
        proto::EcosystemRuntimeProto::RuntimeAndroidWaydroid => {
            Some(EcosystemRuntime::RuntimeAndroidWaydroid)
        }
        proto::EcosystemRuntimeProto::RuntimeAndroidVmWithGms => {
            Some(EcosystemRuntime::RuntimeAndroidVmWithGms)
        }
        proto::EcosystemRuntimeProto::RuntimeMacosDarling => {
            Some(EcosystemRuntime::RuntimeMacosDarling)
        }
        proto::EcosystemRuntimeProto::RuntimeMacosVm => Some(EcosystemRuntime::RuntimeMacosVm),
        proto::EcosystemRuntimeProto::RuntimeRemoteAppleBridge => {
            Some(EcosystemRuntime::RuntimeRemoteAppleBridge)
        }
    }
}

// ---------------------------------------------------------------------------
// CompatibilityRating <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn compatibility_rating_to_proto(
    r: CompatibilityRating,
) -> proto::CompatibilityRatingProto {
    match r {
        CompatibilityRating::Borked => proto::CompatibilityRatingProto::Borked,
        CompatibilityRating::Bronze => proto::CompatibilityRatingProto::Bronze,
        CompatibilityRating::Silver => proto::CompatibilityRatingProto::Silver,
        CompatibilityRating::Gold => proto::CompatibilityRatingProto::Gold,
        CompatibilityRating::Platinum => proto::CompatibilityRatingProto::Platinum,
    }
}

#[must_use]
pub const fn compatibility_rating_from_proto(
    p: proto::CompatibilityRatingProto,
) -> Option<CompatibilityRating> {
    match p {
        proto::CompatibilityRatingProto::RatingUnspecified => None,
        proto::CompatibilityRatingProto::Borked => Some(CompatibilityRating::Borked),
        proto::CompatibilityRatingProto::Bronze => Some(CompatibilityRating::Bronze),
        proto::CompatibilityRatingProto::Silver => Some(CompatibilityRating::Silver),
        proto::CompatibilityRatingProto::Gold => Some(CompatibilityRating::Gold),
        proto::CompatibilityRatingProto::Platinum => Some(CompatibilityRating::Platinum),
    }
}

// ---------------------------------------------------------------------------
// RatingDimension <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn rating_dimension_to_proto(d: RatingDimension) -> proto::RatingDimensionProto {
    match d {
        RatingDimension::LaunchReliability => proto::RatingDimensionProto::LaunchReliability,
        RatingDimension::GameplayStability => proto::RatingDimensionProto::GameplayStability,
        RatingDimension::VisualQuality => proto::RatingDimensionProto::VisualQuality,
        RatingDimension::AudioFunctionality => proto::RatingDimensionProto::AudioFunctionality,
        RatingDimension::InputHandling => proto::RatingDimensionProto::InputHandling,
        RatingDimension::NetworkBehavior => proto::RatingDimensionProto::NetworkBehavior,
        RatingDimension::SaveStateCorrectness => proto::RatingDimensionProto::SaveStateCorrectness,
        RatingDimension::DrmBehavior => proto::RatingDimensionProto::DrmBehavior,
    }
}

#[must_use]
pub const fn rating_dimension_from_proto(
    p: proto::RatingDimensionProto,
) -> Option<RatingDimension> {
    match p {
        proto::RatingDimensionProto::DimensionUnspecified => None,
        proto::RatingDimensionProto::LaunchReliability => Some(RatingDimension::LaunchReliability),
        proto::RatingDimensionProto::GameplayStability => Some(RatingDimension::GameplayStability),
        proto::RatingDimensionProto::VisualQuality => Some(RatingDimension::VisualQuality),
        proto::RatingDimensionProto::AudioFunctionality => {
            Some(RatingDimension::AudioFunctionality)
        }
        proto::RatingDimensionProto::InputHandling => Some(RatingDimension::InputHandling),
        proto::RatingDimensionProto::NetworkBehavior => Some(RatingDimension::NetworkBehavior),
        proto::RatingDimensionProto::SaveStateCorrectness => {
            Some(RatingDimension::SaveStateCorrectness)
        }
        proto::RatingDimensionProto::DrmBehavior => Some(RatingDimension::DrmBehavior),
    }
}

// ---------------------------------------------------------------------------
// EvidenceLevel <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn evidence_level_to_proto(e: EvidenceLevel) -> proto::EvidenceLevelProto {
    match e {
        EvidenceLevel::SelfReported => proto::EvidenceLevelProto::SelfReported,
        EvidenceLevel::SingleOperatorObserved => proto::EvidenceLevelProto::SingleOperatorObserved,
        EvidenceLevel::MultiOperatorCorroborated => {
            proto::EvidenceLevelProto::MultiOperatorCorroborated
        }
        EvidenceLevel::VerifiedPublisher => proto::EvidenceLevelProto::VerifiedPublisher,
    }
}

#[must_use]
pub const fn evidence_level_from_proto(p: proto::EvidenceLevelProto) -> Option<EvidenceLevel> {
    match p {
        proto::EvidenceLevelProto::EvidenceUnspecified => None,
        proto::EvidenceLevelProto::SelfReported => Some(EvidenceLevel::SelfReported),
        proto::EvidenceLevelProto::SingleOperatorObserved => {
            Some(EvidenceLevel::SingleOperatorObserved)
        }
        proto::EvidenceLevelProto::MultiOperatorCorroborated => {
            Some(EvidenceLevel::MultiOperatorCorroborated)
        }
        proto::EvidenceLevelProto::VerifiedPublisher => Some(EvidenceLevel::VerifiedPublisher),
    }
}

// ---------------------------------------------------------------------------
// EcosystemHonestyClass <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn ecosystem_honesty_class_to_proto(
    h: EcosystemHonestyClass,
) -> proto::EcosystemHonestyClassProto {
    match h {
        EcosystemHonestyClass::FullySupported => proto::EcosystemHonestyClassProto::FullySupported,
        EcosystemHonestyClass::PartiallySupported => {
            proto::EcosystemHonestyClassProto::PartiallySupported
        }
        EcosystemHonestyClass::RequiresVm => proto::EcosystemHonestyClassProto::RequiresVm,
        EcosystemHonestyClass::NotRunnableOnNonNative => {
            proto::EcosystemHonestyClassProto::NotRunnableOnNonNative
        }
    }
}

#[must_use]
pub const fn ecosystem_honesty_class_from_proto(
    p: proto::EcosystemHonestyClassProto,
) -> Option<EcosystemHonestyClass> {
    match p {
        proto::EcosystemHonestyClassProto::HonestyUnspecified => None,
        proto::EcosystemHonestyClassProto::FullySupported => {
            Some(EcosystemHonestyClass::FullySupported)
        }
        proto::EcosystemHonestyClassProto::PartiallySupported => {
            Some(EcosystemHonestyClass::PartiallySupported)
        }
        proto::EcosystemHonestyClassProto::RequiresVm => Some(EcosystemHonestyClass::RequiresVm),
        proto::EcosystemHonestyClassProto::NotRunnableOnNonNative => {
            Some(EcosystemHonestyClass::NotRunnableOnNonNative)
        }
    }
}

// ---------------------------------------------------------------------------
// RecipeTrustClass <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn recipe_trust_class_to_proto(r: RecipeTrustClass) -> proto::RecipeTrustClassProto {
    match r {
        RecipeTrustClass::RecipeAiosCurated => proto::RecipeTrustClassProto::RecipeAiosCurated,
        RecipeTrustClass::RecipeCommunity => proto::RecipeTrustClassProto::RecipeCommunity,
        RecipeTrustClass::RecipeImported => proto::RecipeTrustClassProto::RecipeImported,
        RecipeTrustClass::RecipeQuarantined => proto::RecipeTrustClassProto::RecipeQuarantined,
    }
}

#[must_use]
pub const fn recipe_trust_class_from_proto(
    p: proto::RecipeTrustClassProto,
) -> Option<RecipeTrustClass> {
    match p {
        proto::RecipeTrustClassProto::RecipeTrustUnspecified => None,
        proto::RecipeTrustClassProto::RecipeAiosCurated => {
            Some(RecipeTrustClass::RecipeAiosCurated)
        }
        proto::RecipeTrustClassProto::RecipeCommunity => Some(RecipeTrustClass::RecipeCommunity),
        proto::RecipeTrustClassProto::RecipeImported => Some(RecipeTrustClass::RecipeImported),
        proto::RecipeTrustClassProto::RecipeQuarantined => {
            Some(RecipeTrustClass::RecipeQuarantined)
        }
    }
}

// ---------------------------------------------------------------------------
// SessionState <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn session_state_to_proto(s: SessionState) -> proto::SessionStateProto {
    match s {
        SessionState::Allocating => proto::SessionStateProto::Allocating,
        SessionState::Active => proto::SessionStateProto::SessionActive,
        SessionState::Suspended => proto::SessionStateProto::Suspended,
        SessionState::Terminating => proto::SessionStateProto::Terminating,
        SessionState::Terminated => proto::SessionStateProto::Terminated,
    }
}

#[must_use]
pub const fn session_state_from_proto(p: proto::SessionStateProto) -> Option<SessionState> {
    match p {
        proto::SessionStateProto::SessionStateUnspecified => None,
        proto::SessionStateProto::Allocating => Some(SessionState::Allocating),
        proto::SessionStateProto::SessionActive => Some(SessionState::Active),
        proto::SessionStateProto::Suspended => Some(SessionState::Suspended),
        proto::SessionStateProto::Terminating => Some(SessionState::Terminating),
        proto::SessionStateProto::Terminated => Some(SessionState::Terminated),
    }
}

// ---------------------------------------------------------------------------
// SessionExitReason <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn session_exit_reason_to_proto(r: SessionExitReason) -> proto::SessionExitReasonProto {
    match r {
        SessionExitReason::ClosedByOwner => proto::SessionExitReasonProto::ClosedByOwner,
        SessionExitReason::TimedOut => proto::SessionExitReasonProto::TimedOut,
        SessionExitReason::PolicyRevoked => proto::SessionExitReasonProto::SessionPolicyRevoked,
        SessionExitReason::AdapterFailure => proto::SessionExitReasonProto::AdapterFailure,
        SessionExitReason::RecoveryReclaim => proto::SessionExitReasonProto::RecoveryReclaim,
        SessionExitReason::Crashed => proto::SessionExitReasonProto::Crashed,
    }
}

#[must_use]
pub const fn session_exit_reason_from_proto(
    p: proto::SessionExitReasonProto,
) -> Option<SessionExitReason> {
    match p {
        proto::SessionExitReasonProto::ExitReasonUnspecified => None,
        proto::SessionExitReasonProto::ClosedByOwner => Some(SessionExitReason::ClosedByOwner),
        proto::SessionExitReasonProto::TimedOut => Some(SessionExitReason::TimedOut),
        proto::SessionExitReasonProto::SessionPolicyRevoked => {
            Some(SessionExitReason::PolicyRevoked)
        }
        proto::SessionExitReasonProto::AdapterFailure => Some(SessionExitReason::AdapterFailure),
        proto::SessionExitReasonProto::RecoveryReclaim => Some(SessionExitReason::RecoveryReclaim),
        proto::SessionExitReasonProto::Crashed => Some(SessionExitReason::Crashed),
    }
}

// ---------------------------------------------------------------------------
// UpdateState <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn update_state_to_proto(s: UpdateState) -> proto::UpdateStateProto {
    match s {
        UpdateState::Planned => proto::UpdateStateProto::Planned,
        UpdateState::Executing => proto::UpdateStateProto::Executing,
        UpdateState::Executed => proto::UpdateStateProto::Executed,
        UpdateState::Verifying => proto::UpdateStateProto::Verifying,
        UpdateState::Verified => proto::UpdateStateProto::Verified,
        UpdateState::Activating => proto::UpdateStateProto::Activating,
        UpdateState::Active => proto::UpdateStateProto::Active,
        UpdateState::Failed => proto::UpdateStateProto::Failed,
        UpdateState::RollingBack => proto::UpdateStateProto::RollingBack,
        UpdateState::RolledBack => proto::UpdateStateProto::RolledBack,
        UpdateState::RollbackFailed => proto::UpdateStateProto::RollbackFailed,
    }
}

#[must_use]
pub const fn update_state_from_proto(p: proto::UpdateStateProto) -> Option<UpdateState> {
    match p {
        proto::UpdateStateProto::UpdateStateUnspecified => None,
        proto::UpdateStateProto::Planned => Some(UpdateState::Planned),
        proto::UpdateStateProto::Executing => Some(UpdateState::Executing),
        proto::UpdateStateProto::Executed => Some(UpdateState::Executed),
        proto::UpdateStateProto::Verifying => Some(UpdateState::Verifying),
        proto::UpdateStateProto::Verified => Some(UpdateState::Verified),
        proto::UpdateStateProto::Activating => Some(UpdateState::Activating),
        proto::UpdateStateProto::Active => Some(UpdateState::Active),
        proto::UpdateStateProto::Failed => Some(UpdateState::Failed),
        proto::UpdateStateProto::RollingBack => Some(UpdateState::RollingBack),
        proto::UpdateStateProto::RolledBack => Some(UpdateState::RolledBack),
        proto::UpdateStateProto::RollbackFailed => Some(UpdateState::RollbackFailed),
    }
}

// ---------------------------------------------------------------------------
// FailureClass <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn failure_class_to_proto(f: FailureClass) -> proto::FailureClassProto {
    match f {
        FailureClass::ExecuteError => proto::FailureClassProto::ExecuteError,
        FailureClass::VerifyMismatch => proto::FailureClassProto::VerifyMismatch,
        FailureClass::ActivateError => proto::FailureClassProto::ActivateError,
        FailureClass::PolicyDenied => proto::FailureClassProto::PolicyDenied,
    }
}

#[must_use]
pub const fn failure_class_from_proto(p: proto::FailureClassProto) -> Option<FailureClass> {
    match p {
        proto::FailureClassProto::FailureClassUnspecified => None,
        proto::FailureClassProto::ExecuteError => Some(FailureClass::ExecuteError),
        proto::FailureClassProto::VerifyMismatch => Some(FailureClass::VerifyMismatch),
        proto::FailureClassProto::ActivateError => Some(FailureClass::ActivateError),
        proto::FailureClassProto::PolicyDenied => Some(FailureClass::PolicyDenied),
    }
}

// ---------------------------------------------------------------------------
// RollbackReason <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn rollback_reason_to_proto(r: RollbackReason) -> proto::RollbackReasonProto {
    match r {
        RollbackReason::VerifyFailed => proto::RollbackReasonProto::VerifyFailed,
        RollbackReason::PolicyRevoked => proto::RollbackReasonProto::PolicyRevoked,
        RollbackReason::UserRequested => proto::RollbackReasonProto::UserRequested,
        RollbackReason::RegressionDetected => proto::RollbackReasonProto::RegressionDetected,
    }
}

#[must_use]
pub const fn rollback_reason_from_proto(p: proto::RollbackReasonProto) -> Option<RollbackReason> {
    match p {
        proto::RollbackReasonProto::RollbackReasonUnspecified => None,
        proto::RollbackReasonProto::VerifyFailed => Some(RollbackReason::VerifyFailed),
        proto::RollbackReasonProto::PolicyRevoked => Some(RollbackReason::PolicyRevoked),
        proto::RollbackReasonProto::UserRequested => Some(RollbackReason::UserRequested),
        proto::RollbackReasonProto::RegressionDetected => Some(RollbackReason::RegressionDetected),
    }
}

// ---------------------------------------------------------------------------
// RollbackExitState <-> proto
// ---------------------------------------------------------------------------

#[must_use]
pub const fn rollback_exit_state_to_proto(e: RollbackExitState) -> proto::RollbackExitStateProto {
    match e {
        RollbackExitState::Reverted => proto::RollbackExitStateProto::Reverted,
        RollbackExitState::PartialRevert => proto::RollbackExitStateProto::PartialRevert,
        RollbackExitState::RollbackFailed => proto::RollbackExitStateProto::RollbackFailedExit,
    }
}

#[must_use]
pub const fn rollback_exit_state_from_proto(
    p: proto::RollbackExitStateProto,
) -> Option<RollbackExitState> {
    match p {
        proto::RollbackExitStateProto::RollbackExitUnspecified => None,
        proto::RollbackExitStateProto::Reverted => Some(RollbackExitState::Reverted),
        proto::RollbackExitStateProto::PartialRevert => Some(RollbackExitState::PartialRevert),
        proto::RollbackExitStateProto::RollbackFailedExit => {
            Some(RollbackExitState::RollbackFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// AppPackage <-> PackageEnvelopeProto
// ---------------------------------------------------------------------------

#[must_use]
pub fn app_package_to_proto(pkg: &AppPackage) -> proto::PackageEnvelopeProto {
    proto::PackageEnvelopeProto {
        package_id: pkg.package_id.0.clone(),
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        manifest_bytes: pkg.manifest_bytes.clone(),
        content_hash_blake3: pkg.content_hash_blake3.clone(),
        ed25519_signature: pkg.ed25519_signature.clone(),
        signer_public_key: pkg.signer_public_key.clone(),
        registered_at: Some(datetime_to_proto(pkg.registered_at)),
    }
}

pub fn app_package_from_proto(p: &proto::PackageEnvelopeProto) -> AppPackage {
    AppPackage {
        package_id: PackageId(p.package_id.clone()),
        name: p.name.clone(),
        version: p.version.clone(),
        manifest_bytes: p.manifest_bytes.clone(),
        content_hash_blake3: p.content_hash_blake3.clone(),
        ed25519_signature: p.ed25519_signature.clone(),
        signer_public_key: p.signer_public_key.clone(),
        registered_at: p.registered_at.map_or_else(unix_epoch, datetime_from_proto),
    }
}

// ---------------------------------------------------------------------------
// SessionDescriptor <-> SessionDescriptorProto
// ---------------------------------------------------------------------------

#[must_use]
pub fn session_descriptor_to_proto(d: &SessionDescriptor) -> proto::SessionDescriptorProto {
    proto::SessionDescriptorProto {
        session_id: d.session_id.0.clone(),
        package_id: d.package_id.0.clone(),
        ecosystem: ecosystem_runtime_to_proto(d.ecosystem) as i32,
        state: session_state_to_proto(d.state) as i32,
        requester: Some(proto::PrincipalProto {
            canonical_id: d.requester.canonical_id.clone(),
        }),
        created_at: Some(datetime_to_proto(d.created_at)),
        last_heartbeat: Some(datetime_to_proto(d.last_heartbeat)),
        timeout_seconds: d.timeout_seconds,
    }
}

/// # Errors
///
/// Returns `AppsError::ValidationFailed` when an enum field carries UNSPECIFIED.
pub fn session_descriptor_from_proto(
    p: &proto::SessionDescriptorProto,
) -> Result<SessionDescriptor, AppsError> {
    let ecosystem =
        ecosystem_runtime_from_proto(proto::EcosystemRuntimeProto::try_from(p.ecosystem).map_err(
            |_| AppsError::ValidationFailed(format!("invalid ecosystem_runtime: {}", p.ecosystem)),
        )?)
        .ok_or_else(|| AppsError::ValidationFailed("ecosystem_runtime=UNSPECIFIED".into()))?;
    let state = session_state_from_proto(
        proto::SessionStateProto::try_from(p.state)
            .map_err(|_| AppsError::ValidationFailed(format!("invalid state: {}", p.state)))?,
    )
    .ok_or_else(|| AppsError::ValidationFailed("state=UNSPECIFIED".into()))?;
    let requester = p.requester.as_ref().map_or_else(
        || Principal {
            canonical_id: String::new(),
        },
        |r| Principal {
            canonical_id: r.canonical_id.clone(),
        },
    );
    Ok(SessionDescriptor {
        session_id: crate::session::SessionId(p.session_id.clone()),
        package_id: PackageId(p.package_id.clone()),
        ecosystem,
        state,
        requester,
        created_at: p.created_at.map_or_else(unix_epoch, datetime_from_proto),
        last_heartbeat: p
            .last_heartbeat
            .map_or_else(unix_epoch, datetime_from_proto),
        timeout_seconds: p.timeout_seconds,
    })
}

// ---------------------------------------------------------------------------
// SessionTerminationReceipt <-> SessionTerminationReceiptProto
// ---------------------------------------------------------------------------

#[must_use]
pub fn session_termination_receipt_to_proto(
    r: &SessionTerminationReceipt,
) -> proto::SessionTerminationReceiptProto {
    proto::SessionTerminationReceiptProto {
        session_id: r.session_id.0.clone(),
        ended_at: Some(datetime_to_proto(r.ended_at)),
        exit_reason: session_exit_reason_to_proto(r.exit_reason) as i32,
        final_metrics: Some(proto::SessionMetricsProto {
            total_uptime_seconds: r.final_metrics.total_uptime_seconds,
            heartbeat_count: r.final_metrics.heartbeat_count,
        }),
    }
}

// ---------------------------------------------------------------------------
// UpdatePlan <-> UpdatePlanProto
// ---------------------------------------------------------------------------

#[must_use]
pub fn update_plan_to_proto(p: &UpdatePlan) -> proto::UpdatePlanProto {
    let (failure_class, has_failure_class) = p
        .failure_class
        .map_or((0, false), |fc| (failure_class_to_proto(fc) as i32, true));
    proto::UpdatePlanProto {
        plan_id: p.id.0.clone(),
        package_id: p.package_id.0.clone(),
        from_version: p.from_version.clone(),
        to_version: p.to_version.clone(),
        state: update_state_to_proto(p.state) as i32,
        failure_class,
        has_failure_class,
        created_at: Some(datetime_to_proto(p.created_at)),
        state_changed_at: Some(datetime_to_proto(p.state_changed_at)),
    }
}

/// # Errors
///
/// Returns `AppsError::ValidationFailed` when an enum field carries UNSPECIFIED.
pub fn update_plan_from_proto(p: &proto::UpdatePlanProto) -> Result<UpdatePlan, AppsError> {
    let state = update_state_from_proto(
        proto::UpdateStateProto::try_from(p.state)
            .map_err(|_| AppsError::ValidationFailed(format!("invalid state: {}", p.state)))?,
    )
    .ok_or_else(|| AppsError::ValidationFailed("state=UNSPECIFIED".into()))?;
    let failure_class = if p.has_failure_class {
        failure_class_from_proto(proto::FailureClassProto::try_from(p.failure_class).map_err(
            |_| AppsError::ValidationFailed(format!("invalid failure_class: {}", p.failure_class)),
        )?)
    } else {
        None
    };
    Ok(UpdatePlan {
        id: UpdatePlanId(p.plan_id.clone()),
        package_id: PackageId(p.package_id.clone()),
        from_version: p.from_version.clone(),
        to_version: p.to_version.clone(),
        state,
        failure_class,
        created_at: p.created_at.map_or_else(unix_epoch, datetime_from_proto),
        state_changed_at: p
            .state_changed_at
            .map_or_else(unix_epoch, datetime_from_proto),
    })
}

// ---------------------------------------------------------------------------
// UpdateOutcome <-> UpdateOutcomeProto
// ---------------------------------------------------------------------------

#[must_use]
pub fn update_outcome_to_proto(o: &UpdateOutcome) -> proto::UpdateOutcomeProto {
    proto::UpdateOutcomeProto {
        execution_metrics_json: o.execution_metrics.to_string(),
        artifacts_swapped: o.artifacts_swapped,
    }
}

// ---------------------------------------------------------------------------
// UpdateVerification <-> UpdateVerificationProto
// ---------------------------------------------------------------------------

#[must_use]
pub fn update_verification_to_proto(v: &UpdateVerification) -> proto::UpdateVerificationProto {
    proto::UpdateVerificationProto {
        hash_match: v.hash_match,
        capability_drift: v.capability_drift.clone(),
        profile_compat: u32::from(v.profile_compat),
    }
}

// ---------------------------------------------------------------------------
// RollbackReceipt <-> RollbackReceiptProto
// ---------------------------------------------------------------------------

#[must_use]
pub fn rollback_receipt_to_proto(r: &RollbackReceipt) -> proto::RollbackReceiptProto {
    proto::RollbackReceiptProto {
        plan_id: r.plan_id.0.clone(),
        reverted_to: r.reverted_to.clone(),
        completed_at: Some(datetime_to_proto(r.completed_at)),
        exit_state: rollback_exit_state_to_proto(r.exit_state) as i32,
    }
}

// ---------------------------------------------------------------------------
// AppProfile <-> AppProfileProto
// ---------------------------------------------------------------------------

#[must_use]
pub fn app_profile_to_proto(p: &AppProfile) -> proto::AppProfileProto {
    proto::AppProfileProto {
        app_id: p.app_id.clone(),
        ecosystem_runtime: ecosystem_runtime_to_proto(p.ecosystem_runtime) as i32,
        current_recipe_trust_class: recipe_trust_class_to_proto(p.current_recipe_trust_class)
            as i32,
        headline_rating: compatibility_rating_to_proto(p.headline_rating) as i32,
        headline_evidence_level: evidence_level_to_proto(p.headline_evidence_level) as i32,
        worst_dimension: rating_dimension_to_proto(p.worst_dimension) as i32,
        ecosystem_honesty_class: ecosystem_honesty_class_to_proto(p.ecosystem_honesty_class) as i32,
    }
}

/// # Errors
///
/// Returns `AppsError::ValidationFailed` when any enum field is UNSPECIFIED.
pub fn app_profile_from_proto(p: &proto::AppProfileProto) -> Result<AppProfile, AppsError> {
    let ecosystem_runtime = ecosystem_runtime_from_proto(
        proto::EcosystemRuntimeProto::try_from(p.ecosystem_runtime).map_err(|_| {
            AppsError::ValidationFailed(format!(
                "invalid ecosystem_runtime: {}",
                p.ecosystem_runtime
            ))
        })?,
    )
    .ok_or_else(|| AppsError::ValidationFailed("ecosystem_runtime=UNSPECIFIED".into()))?;
    let current_recipe_trust_class = recipe_trust_class_from_proto(
        proto::RecipeTrustClassProto::try_from(p.current_recipe_trust_class).map_err(|_| {
            AppsError::ValidationFailed(format!(
                "invalid recipe_trust_class: {}",
                p.current_recipe_trust_class
            ))
        })?,
    )
    .ok_or_else(|| AppsError::ValidationFailed("recipe_trust_class=UNSPECIFIED".into()))?;
    let headline_rating = compatibility_rating_from_proto(
        proto::CompatibilityRatingProto::try_from(p.headline_rating).map_err(|_| {
            AppsError::ValidationFailed(format!("invalid headline_rating: {}", p.headline_rating))
        })?,
    )
    .ok_or_else(|| AppsError::ValidationFailed("headline_rating=UNSPECIFIED".into()))?;
    let headline_evidence_level = evidence_level_from_proto(
        proto::EvidenceLevelProto::try_from(p.headline_evidence_level).map_err(|_| {
            AppsError::ValidationFailed(format!(
                "invalid headline_evidence_level: {}",
                p.headline_evidence_level
            ))
        })?,
    )
    .ok_or_else(|| AppsError::ValidationFailed("headline_evidence_level=UNSPECIFIED".into()))?;
    let worst_dimension = rating_dimension_from_proto(
        proto::RatingDimensionProto::try_from(p.worst_dimension).map_err(|_| {
            AppsError::ValidationFailed(format!("invalid worst_dimension: {}", p.worst_dimension))
        })?,
    )
    .ok_or_else(|| AppsError::ValidationFailed("worst_dimension=UNSPECIFIED".into()))?;
    let ecosystem_honesty_class = ecosystem_honesty_class_from_proto(
        proto::EcosystemHonestyClassProto::try_from(p.ecosystem_honesty_class).map_err(|_| {
            AppsError::ValidationFailed(format!(
                "invalid ecosystem_honesty_class: {}",
                p.ecosystem_honesty_class
            ))
        })?,
    )
    .ok_or_else(|| AppsError::ValidationFailed("ecosystem_honesty_class=UNSPECIFIED".into()))?;
    Ok(AppProfile {
        app_id: p.app_id.clone(),
        ecosystem_runtime,
        current_recipe_trust_class,
        headline_rating,
        headline_evidence_level,
        worst_dimension,
        ecosystem_honesty_class,
    })
}

// ---------------------------------------------------------------------------
// SessionFilter conversion
// ---------------------------------------------------------------------------

#[must_use]
pub fn session_filter_from_proto(p: &proto::SessionFilterProto) -> SessionFilter {
    if !p.filter_by_package.is_empty() {
        SessionFilter::ByPackage(PackageId(p.filter_by_package.clone()))
    } else if !p.filter_by_principal.is_empty() {
        SessionFilter::ByPrincipal(Principal {
            canonical_id: p.filter_by_principal.clone(),
        })
    } else if let Some(state) = session_state_from_proto(
        proto::SessionStateProto::try_from(p.filter_by_state).unwrap_or_default(),
    ) {
        SessionFilter::ByState(state)
    } else {
        SessionFilter::All
    }
}

// ---------------------------------------------------------------------------
// AppsError -> tonic::Status
// ---------------------------------------------------------------------------

#[must_use]
pub fn apps_error_to_status(e: &AppsError) -> tonic::Status {
    match e {
        AppsError::PackageNotFound(id) => {
            tonic::Status::not_found(format!("package not found: {id}"))
        }
        AppsError::IllegalStateTransition { from, to } => {
            tonic::Status::failed_precondition(format!("illegal state transition: {from} → {to}"))
        }
        AppsError::PackageObjectLayoutCorruption(msg) => {
            tonic::Status::internal(format!("package object layout corruption: {msg}"))
        }
        AppsError::ManifestMaterializationDrift {
            package_id,
            expected,
            actual,
        } => tonic::Status::internal(format!(
            "manifest materialization drift for {package_id}: expected {expected}, got {actual}"
        )),
        AppsError::RollbackForbidden(msg) => {
            tonic::Status::failed_precondition(format!("rollback forbidden: {msg}"))
        }
        AppsError::RollbackBlocklisted { version, reason } => tonic::Status::failed_precondition(
            format!("rollback blocked: version {version} is on the blocklist: {reason}"),
        ),
        AppsError::EcosystemRuntimeMismatch {
            manifest_runtime,
            adapter_runtime,
        } => tonic::Status::failed_precondition(format!(
            "ecosystem runtime mismatch: manifest={manifest_runtime}, adapter={adapter_runtime}"
        )),
        AppsError::HonestyClassViolation { claimed } => tonic::Status::failed_precondition(
            format!("honesty class violation: claimed {claimed}, observed behaviour contradicts"),
        ),
        AppsError::ProfileNotFound { app_id, runtime } => tonic::Status::not_found(format!(
            "compatibility profile not found for {app_id} under {runtime}"
        )),
        AppsError::SessionNotFound(id) => {
            tonic::Status::not_found(format!("session container not found: {id}"))
        }
        AppsError::SessionQuotaExceeded {
            group_id,
            active,
            quota,
        } => tonic::Status::resource_exhausted(format!(
            "session quota exceeded for group {group_id}: {active} active, quota {quota}"
        )),
        AppsError::AiSessionAuthorshipBlocked => {
            tonic::Status::permission_denied("AI session container authorship blocked (INV-013)")
        }
        AppsError::StreamedSurfaceInChromeBlocked => {
            tonic::Status::permission_denied("streamed surface in chrome blocked (INV-023)")
        }
        AppsError::StagedUpdateAlreadyExists(id) => {
            tonic::Status::already_exists(format!("staged update already exists for {id}"))
        }
        AppsError::ObservationRejected {
            observation_id,
            reason,
        } => tonic::Status::invalid_argument(format!(
            "observation {observation_id} rejected: {reason}"
        )),
        AppsError::InvalidStateTransition { from, to } => {
            tonic::Status::failed_precondition(format!("invalid state transition: {from} → {to}"))
        }
        AppsError::UpdatePlanNotFound(id) => {
            tonic::Status::not_found(format!("update plan not found: {id}"))
        }
        AppsError::ValidationFailed(msg) => {
            tonic::Status::invalid_argument(format!("validation failed: {msg}"))
        }
        AppsError::EvidenceEmitFailed(msg) => {
            tonic::Status::internal(format!("evidence emit failed: {msg}"))
        }
        AppsError::RuntimeReject(msg) => {
            tonic::Status::internal(format!("runtime rejected: {msg}"))
        }
        AppsError::InvalidRuntimeClass(msg) => {
            tonic::Status::invalid_argument(format!("invalid runtime class: {msg}"))
        }
        AppsError::NotFound(msg) => tonic::Status::not_found(format!("not found: {msg}")),
        AppsError::SessionContainerError(msg) => {
            tonic::Status::internal(format!("session container error: {msg}"))
        }
    }
}

#[must_use]
pub const fn apps_error_to_code(e: &AppsError) -> u32 {
    match e {
        AppsError::PackageNotFound(_) => 1,
        AppsError::IllegalStateTransition { .. } => 2,
        AppsError::PackageObjectLayoutCorruption(_) => 3,
        AppsError::ManifestMaterializationDrift { .. } => 4,
        AppsError::RollbackForbidden(_) => 5,
        AppsError::RollbackBlocklisted { .. } => 6,
        AppsError::EcosystemRuntimeMismatch { .. } => 7,
        AppsError::HonestyClassViolation { .. } => 8,
        AppsError::ProfileNotFound { .. } => 9,
        AppsError::SessionNotFound(_) => 10,
        AppsError::SessionQuotaExceeded { .. } => 11,
        AppsError::AiSessionAuthorshipBlocked => 12,
        AppsError::StreamedSurfaceInChromeBlocked => 13,
        AppsError::StagedUpdateAlreadyExists(_) => 14,
        AppsError::ObservationRejected { .. } => 15,
        AppsError::InvalidStateTransition { .. } => 16,
        AppsError::UpdatePlanNotFound(_) => 17,
        AppsError::ValidationFailed(_) => 18,
        AppsError::EvidenceEmitFailed(_) => 19,
        AppsError::RuntimeReject(_) => 20,
        AppsError::InvalidRuntimeClass(_) => 21,
        AppsError::NotFound(_) => 22,
        AppsError::SessionContainerError(_) => 23,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code; panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn datetime_round_trip() {
        let now = Utc::now();
        let proto = datetime_to_proto(now);
        let back = datetime_from_proto(proto);
        assert_eq!(now.timestamp(), back.timestamp());
    }

    #[test]
    fn ecosystem_runtime_round_trip_all() {
        use strum::IntoEnumIterator;
        for e in EcosystemRuntime::iter() {
            let p = ecosystem_runtime_to_proto(e);
            let back = ecosystem_runtime_from_proto(p).expect("non-UNSPECIFIED");
            assert_eq!(e, back);
        }
    }

    #[test]
    fn compatibility_rating_round_trip_all() {
        use strum::IntoEnumIterator;
        for r in CompatibilityRating::iter() {
            let p = compatibility_rating_to_proto(r);
            let back = compatibility_rating_from_proto(p).expect("non-UNSPECIFIED");
            assert_eq!(r, back);
        }
    }

    #[test]
    fn session_state_round_trip_all() {
        use strum::IntoEnumIterator;
        for s in SessionState::iter() {
            let p = session_state_to_proto(s);
            let back = session_state_from_proto(p).expect("non-UNSPECIFIED");
            assert_eq!(s, back);
        }
    }

    #[test]
    fn session_exit_reason_round_trip_all() {
        use strum::IntoEnumIterator;
        for r in SessionExitReason::iter() {
            let p = session_exit_reason_to_proto(r);
            let back = session_exit_reason_from_proto(p).expect("non-UNSPECIFIED");
            assert_eq!(r, back);
        }
    }

    #[test]
    fn update_state_round_trip_all() {
        use strum::IntoEnumIterator;
        for s in UpdateState::iter() {
            let p = update_state_to_proto(s);
            let back = update_state_from_proto(p).expect("non-UNSPECIFIED");
            assert_eq!(s, back);
        }
    }

    #[test]
    fn failure_class_round_trip_all() {
        use strum::IntoEnumIterator;
        for f in FailureClass::iter() {
            let p = failure_class_to_proto(f);
            let back = failure_class_from_proto(p).expect("non-UNSPECIFIED");
            assert_eq!(f, back);
        }
    }

    #[test]
    fn rollback_reason_round_trip_all() {
        use strum::IntoEnumIterator;
        for r in RollbackReason::iter() {
            let p = rollback_reason_to_proto(r);
            let back = rollback_reason_from_proto(p).expect("non-UNSPECIFIED");
            assert_eq!(r, back);
        }
    }

    #[test]
    fn rollback_exit_state_round_trip_all() {
        use strum::IntoEnumIterator;
        for e in RollbackExitState::iter() {
            let p = rollback_exit_state_to_proto(e);
            let back = rollback_exit_state_from_proto(p).expect("non-UNSPECIFIED");
            assert_eq!(e, back);
        }
    }

    #[test]
    fn status_mapping_package_not_found_is_not_found() {
        let s = apps_error_to_status(&AppsError::PackageNotFound("pkg_x".into()));
        assert_eq!(s.code(), tonic::Code::NotFound);
    }

    #[test]
    fn status_mapping_invalid_transition_is_failed_precondition() {
        let s = apps_error_to_status(&AppsError::InvalidStateTransition {
            from: "Planned".into(),
            to: "Active".into(),
        });
        assert_eq!(s.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn status_mapping_session_not_found_is_not_found() {
        let s = apps_error_to_status(&AppsError::SessionNotFound("sess_x".into()));
        assert_eq!(s.code(), tonic::Code::NotFound);
    }

    #[test]
    fn status_mapping_validation_failed_is_invalid_argument() {
        let s = apps_error_to_status(&AppsError::ValidationFailed("bad input".into()));
        assert_eq!(s.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn status_mapping_ai_session_blocked_is_permission_denied() {
        let s = apps_error_to_status(&AppsError::AiSessionAuthorshipBlocked);
        assert_eq!(s.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn error_code_projection_table() {
        assert_eq!(
            apps_error_to_code(&AppsError::PackageNotFound("x".into())),
            1
        );
        assert_eq!(
            apps_error_to_code(&AppsError::InvalidStateTransition {
                from: "a".into(),
                to: "b".into()
            }),
            16
        );
        assert_eq!(
            apps_error_to_code(&AppsError::UpdatePlanNotFound("x".into())),
            17
        );
    }
}
