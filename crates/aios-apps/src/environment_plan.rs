//! AI-assisted application-environment provisioning seam (L6 ↔ L4).
//!
//! This module is the missing link between a **package analysis** (produced by
//! the [`RosettaSolver`](crate::rosetta_solver::RosettaSolver)) and a
//! **governed, typed environment plan** that can be routed to the Policy Kernel
//! for a decision.
//!
//! ## The constitutional law encoded here
//!
//! > **AI proposes, never executes.** The [`EnvironmentProvisioningPlan`] is a
//! > *typed proposal*. Turning it into effect is owned **downstream** by the
//! > Capability Runtime, and only after a real Policy Kernel decision. This
//! > module NEVER executes the plan, NEVER shells out, NEVER mutates the host,
//! > and NEVER fabricates a policy approval.
//!
//! The plan's terminal state *before* an external decision is
//! [`ProvisioningPlanState::AwaitingPolicyDecision`]. There is deliberately **no**
//! `Provisioned` / `Executed` state: no code path in this module can mark an
//! environment as set up. That transition happens elsewhere, keyed on a policy
//! decision id, and is evidenced by the Capability Runtime.
//!
//! ## Inputs → output
//!
//! ```text
//! PackagePassport  ┐
//! RosettaTranslation ┼─► EnvironmentProvisioningPlan ─► route_for_decision()
//! CompatibilityScore ┘        (typed proposal)            ─► aios.policy.PolicyKernel
//! ```
//!
//! The plan chooses an [`EcosystemRuntime`], a [`SandboxProfileSpec`] to compose
//! (referencing the `aios-sandbox` public types), a **closed** set of
//! [`GrantedCapability`] baseline grants, a GPU/passthrough requirement, and a
//! list of typed [`RemediationStep`] **proposals** for anything beyond the safe
//! baseline.
//!
//! ## Honest taxonomy
//!
//! * The deterministic plan-builder, the closed capability/remediation
//!   vocabularies, the governance routing to `aios.policy.PolicyKernel`, and the
//!   sealed evidence receipts are `REAL` at `E3` (unit-tested in this file).
//! * The **live** `PolicyKernel.EvaluatePolicy` channel and the downstream
//!   Capability-Runtime execution are a `CONTRACT` boundary — marked
//!   `// CONTRACT:` at [`EnvironmentProvisioningPlan::route_for_decision`]. No
//!   execution is faked.
//! * The **L5 cognitive proposal** hook is now wired `REAL` at `E3` in
//!   [`crate::cognitive_bridge`]: a real [`aios_cognitive::CognitiveIntent`] is
//!   mapped to a typed environment intent, the deterministic planner produces
//!   the plan, and it terminates at `AwaitingPolicyDecision`. What remains
//!   `CONTRACT` is only the *live* gRPC `CognitiveCore/ProposePlan` RPC that
//!   would mint the intent from a running model — see
//!   [`COGNITIVE_PROPOSER_CONTRACT`].

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use aios_evidence::{ReceiptBuilder, ReceiptChain, RecordType, RetentionClass};
use aios_sandbox::{GpuCapabilityClass, IsolationKind, NetworkPosture};

use crate::ecosystem::EcosystemRuntime;
use crate::error::AppsError;
use crate::rosetta_solver::{
    CompatibilityScore, ComplexityBand, PackagePassport, RosettaTranslation,
};

/// The fully-qualified Policy Kernel service every mutating provisioning
/// proposal is routed to. The operator/AI *proposes*; the kernel *decides*.
pub const POLICY_KERNEL_SERVICE: &str = "aios.policy.PolicyKernel";

/// The gRPC method on [`POLICY_KERNEL_SERVICE`] that evaluates a typed proposed
/// action and returns a `PolicyDecision`.
pub const POLICY_EVALUATE_METHOD: &str = "EvaluatePolicy";

/// The L5 Cognitive Core planning RPC that mints a typed intent.
///
/// The in-process proposal seam is now **REAL** — see
/// [`crate::cognitive_bridge`]: it consumes a real
/// [`aios_cognitive::CognitiveIntent`], maps it to a typed environment intent,
/// and drives the deterministic planner to a `AwaitingPolicyDecision` plan with
/// sealed evidence. The L6→L5 dependency is legal (a layer may depend on
/// lower-numbered layers) and acyclic (`aios-cognitive` has no dependency on
/// `aios-apps`).
///
/// What this constant still marks as `CONTRACT` is the **live gRPC channel**:
/// delivering a `ProposePlan` call to a running `aios.cognitive.CognitiveCore`
/// backend so a model *mints* the [`aios_cognitive::CognitiveIntent`]. The bridge
/// accepts an already-minted intent; no model is called and none is fabricated.
/// The Cognitive Core still only *proposes*; this module still only *proposes*;
/// nothing here executes.
pub const COGNITIVE_PROPOSER_CONTRACT: &str = "aios.cognitive.CognitiveCore/ProposePlan";

// ---------------------------------------------------------------------------
// FilesystemAccess — closed filesystem capability vocabulary
// ---------------------------------------------------------------------------

/// Closed set of filesystem access scopes a provisioning plan may reference.
///
/// The safe baseline is [`FilesystemAccess::AppPrivate`]; anything broader is
/// an elevated capability surfaced as a [`RemediationStep`] proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilesystemAccess {
    /// App-private scope only (the S3.2 floor). No host paths.
    AppPrivate,
    /// Read-only access to explicitly shared host paths.
    ReadOnlyShared,
    /// Read-write access to the operator home (elevated).
    HomeReadWrite,
}

// ---------------------------------------------------------------------------
// GrantedCapability — closed, typed capability set
// ---------------------------------------------------------------------------

/// A single typed capability referenced by an [`EnvironmentProvisioningPlan`].
///
/// This is a **closed** set — never a free-form string. Where a typed value
/// already exists in `aios-sandbox` it is reused ([`NetworkPosture`],
/// [`GpuCapabilityClass`]) rather than re-invented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "cap", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrantedCapability {
    /// Filesystem access scope (reuses [`FilesystemAccess`]).
    Filesystem(FilesystemAccess),
    /// Network posture (reuses the sandbox [`NetworkPosture`]).
    Network(NetworkPosture),
    /// GPU capability class (reuses the sandbox [`GpuCapabilityClass`]).
    Gpu(GpuCapabilityClass),
    /// Wayland display surface access (GUI apps).
    Display,
    /// Audio device access.
    Audio,
    /// Android `binder` IPC access (Waydroid / Android-VM runtimes).
    Binder,
}

// ---------------------------------------------------------------------------
// RemediationStep — closed, typed proposals (NOT actions)
// ---------------------------------------------------------------------------

/// A typed remediation **proposal** for a missing dependency or capability.
///
/// Every remediation is a *proposal*, not an executed action. The plan lists
/// what would be required beyond the safe baseline; granting any of it requires
/// a downstream Policy Kernel decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemediationStep {
    /// An elevated capability is required beyond the auto-granted baseline.
    /// Proposal only — approval is a downstream policy decision.
    RequiresCapability(GrantedCapability),
    /// A runtime component (Wine/Proton, Waydroid image, VM guest, …) must be
    /// present before the environment can be composed. Proposal only.
    MissingRuntimeComponent {
        /// Stable component identifier (e.g. `wine-proton`, `waydroid-lxc-image`).
        component: String,
    },
    /// GPU device passthrough is required (VM runtimes or GPU-heavy hints).
    /// Proposal only — passthrough is a policy-gated capability.
    RequiresGpuPassthrough,
    /// A compatibility blocking issue must be resolved before provisioning is
    /// even proposable. Proposal / advisory only.
    ResolveBlockingIssue {
        /// The blocking issue text carried from the [`CompatibilityScore`].
        issue: String,
    },
}

// ---------------------------------------------------------------------------
// SandboxProfileSpec — reference/spec the composer will materialize
// ---------------------------------------------------------------------------

/// A *reference spec* the sandbox composer will materialize into a real
/// `aios_sandbox::SandboxProfile`.
///
/// This deliberately carries only the typed knobs (reusing the sandbox public
/// enums) — it is **not** a signed profile. The plan references the profile to
/// compose; it does not compose it (that is a downstream effect).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProfileSpec {
    /// Human-readable label for the profile to compose.
    pub name: String,
    /// Kernel-level isolation boundary (reuses [`IsolationKind`]).
    pub isolation_kind: IsolationKind,
    /// Baseline network posture (reuses [`NetworkPosture`]).
    pub network_posture: NetworkPosture,
    /// Baseline GPU capability class (reuses [`GpuCapabilityClass`]).
    pub gpu_capability_class: GpuCapabilityClass,
}

// ---------------------------------------------------------------------------
// ProvisioningPlanState — terminal-before-decision state machine
// ---------------------------------------------------------------------------

/// Lifecycle state of an [`EnvironmentProvisioningPlan`].
///
/// There is deliberately **no** `Provisioned` / `Executed` variant. The most
/// advanced state this module can reach is [`AwaitingPolicyDecision`](Self::AwaitingPolicyDecision).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProvisioningPlanState {
    /// The plan has been produced but not yet routed for a decision.
    Drafted,
    /// The plan's typed proposal has been routed to the Policy Kernel and is
    /// awaiting a decision id. This is the terminal state of this module.
    AwaitingPolicyDecision,
    /// The underlying compatibility analysis is blocked; the plan cannot be
    /// proposed for provisioning until the blocking issues are resolved.
    Blocked,
}

// ---------------------------------------------------------------------------
// RoutedProvisioningRequest / ProvisioningOutcome — the governance seam
// ---------------------------------------------------------------------------

/// A typed request derived from an [`EnvironmentProvisioningPlan`], addressed to
/// the Policy Kernel. This is a *proposal envelope*, never a shell command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutedProvisioningRequest {
    /// Fully-qualified target service — always [`POLICY_KERNEL_SERVICE`].
    pub service_fqn: String,
    /// gRPC method — always [`POLICY_EVALUATE_METHOD`].
    pub method: String,
    /// Canonical JSON payload bytes of the typed proposed action.
    pub payload: Vec<u8>,
    /// Always `true`: provisioning mutates system state, so it must pass the
    /// Policy Kernel before any effect.
    pub mutating: bool,
}

/// The outcome of routing a plan for a decision.
///
/// There is deliberately **no** `Provisioned` / `Executed` variant: routing
/// terminates at [`ProvisioningOutcome::PolicyPending`] until an external
/// decision arrives. This module never proceeds on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvisioningOutcome {
    /// The typed proposal was routed to the Policy Kernel and awaits a decision.
    PolicyPending {
        /// The routed proposal envelope.
        routed: RoutedProvisioningRequest,
    },
}

// ---------------------------------------------------------------------------
// EnvironmentProvisioningPlan
// ---------------------------------------------------------------------------

/// The typed environment plan — the deliverable of this seam.
///
/// Built deterministically from a [`PackagePassport`], a [`RosettaTranslation`],
/// and a [`CompatibilityScore`] via [`EnvironmentProvisioningPlan::from_analysis`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentProvisioningPlan {
    /// Deterministic plan id (BLAKE3 of the canonical input identity).
    pub plan_id: String,
    /// The application identity from the passport.
    pub app_id: String,
    /// The source package identifier from the translation.
    pub source_package: String,
    /// The chosen ecosystem runtime (consumed from the translation/passport).
    pub chosen_runtime: EcosystemRuntime,
    /// The sandbox profile spec the composer will materialize.
    pub sandbox_profile: SandboxProfileSpec,
    /// The **closed** set of baseline capabilities granted without elevation.
    pub granted_capabilities: Vec<GrantedCapability>,
    /// Whether GPU passthrough is required for this environment.
    pub gpu_passthrough_required: bool,
    /// Typed remediation **proposals** for anything beyond the safe baseline.
    pub remediation_steps: Vec<RemediationStep>,
    /// The compatibility score (0–100) carried from the analysis.
    pub compatibility_score: u8,
    /// The estimated conversion complexity carried from the translation.
    pub complexity: ComplexityBand,
    /// Current lifecycle state (never reaches a "provisioned" state here).
    pub state: ProvisioningPlanState,
}

impl EnvironmentProvisioningPlan {
    /// Build a deterministic plan from an existing package analysis.
    ///
    /// This consumes the three already-derived inputs — it does **not**
    /// re-derive them. The result is a pure function of the inputs: the same
    /// inputs always produce byte-identical plans (including [`plan_id`]).
    ///
    /// [`plan_id`]: EnvironmentProvisioningPlan::plan_id
    #[must_use]
    pub fn from_analysis(
        passport: &PackagePassport,
        translation: &RosettaTranslation,
        score: &CompatibilityScore,
    ) -> Self {
        let chosen_runtime = passport.target_runtime;
        let isolation_kind = isolation_for_runtime(chosen_runtime);

        let gpu_passthrough_required =
            runtime_needs_vm(chosen_runtime) || translation_mentions_gpu(translation);

        let gpu_baseline = if gpu_passthrough_required {
            GpuCapabilityClass::GpuComputeHeavy
        } else {
            GpuCapabilityClass::GpuPassiveDisplay
        };

        let sandbox_profile = SandboxProfileSpec {
            name: format!("env-{}", passport.app_id),
            isolation_kind,
            // Baseline is loopback-only; broader network is an elevated
            // remediation proposal, never auto-granted.
            network_posture: NetworkPosture::LoopbackOnly,
            gpu_capability_class: gpu_baseline,
        };

        // Safe baseline grants — minimal, non-elevated.
        let granted_capabilities = vec![
            GrantedCapability::Filesystem(FilesystemAccess::AppPrivate),
            GrantedCapability::Network(NetworkPosture::LoopbackOnly),
            GrantedCapability::Display,
        ];

        let remediation_steps = build_remediations(chosen_runtime, gpu_passthrough_required, score);

        let state = if score.is_blocked() {
            ProvisioningPlanState::Blocked
        } else {
            ProvisioningPlanState::Drafted
        };

        let plan_id = deterministic_plan_id(passport, translation, score);

        Self {
            plan_id,
            app_id: passport.app_id.clone(),
            source_package: translation.source_package.clone(),
            chosen_runtime,
            sandbox_profile,
            granted_capabilities,
            gpu_passthrough_required,
            remediation_steps,
            compatibility_score: score.score,
            complexity: translation.estimated_complexity,
            state,
        }
    }

    /// Returns `true` when the plan cannot be proposed for provisioning because
    /// the underlying compatibility analysis is blocked.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        matches!(self.state, ProvisioningPlanState::Blocked)
    }

    /// The governance seam: convert this plan into the typed action(s) that must
    /// go to the Policy Kernel, and move the plan to
    /// [`ProvisioningPlanState::AwaitingPolicyDecision`].
    ///
    /// This is the **only** forward transition available, and it terminates at
    /// "awaiting decision" — there is no path here that marks the environment as
    /// provisioned. The returned [`ProvisioningOutcome::PolicyPending`] carries
    /// the typed proposal envelope addressed to [`POLICY_KERNEL_SERVICE`].
    ///
    /// # Errors
    ///
    /// * [`AppsError::ValidationFailed`] if the plan is blocked (its
    ///   compatibility analysis has blocking issues) — a blocked conversion is
    ///   not proposable for provisioning.
    /// * [`AppsError::ValidationFailed`] if the typed proposal payload cannot be
    ///   encoded.
    pub fn route_for_decision(&mut self) -> Result<ProvisioningOutcome, AppsError> {
        if self.is_blocked() {
            return Err(AppsError::ValidationFailed(format!(
                "environment plan {} is blocked; resolve blocking issues before proposing provisioning",
                self.plan_id
            )));
        }

        // A typed proposed-action envelope — NOT a shell command, NOT an effect.
        let payload = serde_json::json!({
            "proposed_action": {
                "verb": "app.environment.provision",
                "plan_id": self.plan_id,
                "app_id": self.app_id,
                "source_package": self.source_package,
                "runtime": self.chosen_runtime.to_string(),
                "sandbox_profile": self.sandbox_profile,
                "granted_capabilities": self.granted_capabilities,
                "gpu_passthrough_required": self.gpu_passthrough_required,
                "remediation_steps": self.remediation_steps,
                "compatibility_score": self.compatibility_score,
            }
        });

        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| AppsError::ValidationFailed(format!("proposal encode: {e}")))?;

        // CONTRACT: this envelope must be delivered to the live
        // `aios.policy.PolicyKernel` `EvaluatePolicy` method over a tonic
        // `Channel`. The returned `PolicyDecision` (Allow / RequireApproval /
        // Deny) gates the downstream effect, which the Capability Runtime — NOT
        // this module — executes and evidences. No backend call is made here and
        // no decision is fabricated; the plan simply stops at AwaitingPolicyDecision.
        let routed = RoutedProvisioningRequest {
            service_fqn: POLICY_KERNEL_SERVICE.to_string(),
            method: POLICY_EVALUATE_METHOD.to_string(),
            payload: bytes,
            mutating: true,
        };

        self.state = ProvisioningPlanState::AwaitingPolicyDecision;
        Ok(ProvisioningOutcome::PolicyPending { routed })
    }
}

// ---------------------------------------------------------------------------
// Deterministic helpers (pure)
// ---------------------------------------------------------------------------

/// Map a runtime to its kernel isolation boundary.
const fn isolation_for_runtime(runtime: EcosystemRuntime) -> IsolationKind {
    match runtime {
        EcosystemRuntime::RuntimeLinuxNative
        | EcosystemRuntime::RuntimeFlatpak
        | EcosystemRuntime::RuntimeAppimage
        | EcosystemRuntime::RuntimeSnap
        | EcosystemRuntime::RuntimeWindowsProton
        | EcosystemRuntime::RuntimeMacosDarling
        | EcosystemRuntime::RuntimeRemoteAppleBridge => IsolationKind::NamespaceLocal,
        EcosystemRuntime::RuntimeDistrobox | EcosystemRuntime::RuntimeAndroidWaydroid => {
            IsolationKind::ProcessContainer
        }
        EcosystemRuntime::RuntimeWindowsVm
        | EcosystemRuntime::RuntimeAndroidVmWithGms
        | EcosystemRuntime::RuntimeMacosVm => IsolationKind::VmGuest,
    }
}

/// Whether a runtime is a full-VM runtime (implies GPU passthrough).
const fn runtime_needs_vm(runtime: EcosystemRuntime) -> bool {
    matches!(
        runtime,
        EcosystemRuntime::RuntimeWindowsVm
            | EcosystemRuntime::RuntimeAndroidVmWithGms
            | EcosystemRuntime::RuntimeMacosVm
    )
}

/// Whether a runtime is an Android runtime (implies `binder` IPC).
const fn runtime_needs_binder(runtime: EcosystemRuntime) -> bool {
    matches!(
        runtime,
        EcosystemRuntime::RuntimeAndroidWaydroid | EcosystemRuntime::RuntimeAndroidVmWithGms
    )
}

/// The runtime component that must be present for a non-native runtime, if any.
const fn missing_runtime_component(runtime: EcosystemRuntime) -> Option<&'static str> {
    match runtime {
        EcosystemRuntime::RuntimeLinuxNative
        | EcosystemRuntime::RuntimeFlatpak
        | EcosystemRuntime::RuntimeAppimage
        | EcosystemRuntime::RuntimeSnap
        | EcosystemRuntime::RuntimeRemoteAppleBridge => None,
        EcosystemRuntime::RuntimeDistrobox => Some("distrobox"),
        EcosystemRuntime::RuntimeWindowsProton => Some("wine-proton"),
        EcosystemRuntime::RuntimeWindowsVm => Some("windows-guest-image"),
        EcosystemRuntime::RuntimeAndroidWaydroid => Some("waydroid-lxc-image"),
        EcosystemRuntime::RuntimeAndroidVmWithGms => Some("android-gms-vm-image"),
        EcosystemRuntime::RuntimeMacosDarling => Some("darling-runtime"),
        EcosystemRuntime::RuntimeMacosVm => Some("macos-guest-image"),
    }
}

/// Whether the translation hints/warnings mention GPU or passthrough needs.
fn translation_mentions_gpu(translation: &RosettaTranslation) -> bool {
    let needle = |s: &String| {
        let lower = s.to_lowercase();
        lower.contains("gpu") || lower.contains("passthrough")
    };
    translation.declarer_hints.iter().any(needle)
        || translation.compatibility_warnings.iter().any(needle)
}

/// Build the closed set of remediation proposals for the plan.
fn build_remediations(
    runtime: EcosystemRuntime,
    gpu_passthrough_required: bool,
    score: &CompatibilityScore,
) -> Vec<RemediationStep> {
    let mut steps = Vec::new();

    // Missing runtime component (proposal to install/enable it).
    if let Some(component) = missing_runtime_component(runtime) {
        steps.push(RemediationStep::MissingRuntimeComponent {
            component: component.to_string(),
        });
    }

    // Elevated GPU capability beyond the passive-display baseline.
    if gpu_passthrough_required {
        steps.push(RemediationStep::RequiresCapability(GrantedCapability::Gpu(
            GpuCapabilityClass::GpuComputeHeavy,
        )));
        steps.push(RemediationStep::RequiresGpuPassthrough);
    }

    // Android runtimes need the binder IPC capability (elevated, not baseline).
    if runtime_needs_binder(runtime) {
        steps.push(RemediationStep::RequiresCapability(
            GrantedCapability::Binder,
        ));
    }

    // Every blocking issue becomes an advisory remediation proposal.
    for issue in &score.blocking_issues {
        steps.push(RemediationStep::ResolveBlockingIssue {
            issue: issue.clone(),
        });
    }

    steps
}

/// Compute a deterministic plan id from the canonical input identity.
fn deterministic_plan_id(
    passport: &PackagePassport,
    translation: &RosettaTranslation,
    score: &CompatibilityScore,
) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}",
        passport.app_id,
        passport.target_runtime,
        translation.source_package,
        translation.estimated_complexity,
        score.score,
    );
    let digest = blake3::hash(canonical.as_bytes());
    format!("envplan_{}", &digest.to_hex()[..24])
}

// ---------------------------------------------------------------------------
// EnvironmentPlanner — evidence-emitting wrapper
// ---------------------------------------------------------------------------

/// Simplified evidence receipt returned to callers of the planner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningEvidenceReceipt {
    /// Evidence receipt id (`evr_<ULID>`).
    pub record_id: String,
    /// BLAKE3-256 content hash (64 lowercase hex chars).
    pub hash: String,
    /// 0-based sequence position in the emitter's chain.
    pub sequence: u64,
}

/// The environment planner — produces plans and seals evidence receipts.
///
/// Wraps the pure [`EnvironmentProvisioningPlan::from_analysis`] builder with an
/// append-only evidence chain (same pattern as
/// [`crate::evidence::InMemoryAppsEvidenceEmitter`]). A sealed receipt is emitted
/// when a plan is **produced** ([`RecordType::TranslationCreated`]) and when it
/// is **routed for a decision** ([`RecordType::RoutingDecision`]).
pub struct EnvironmentPlanner {
    chain: Mutex<ReceiptChain>,
    subject: String,
}

impl EnvironmentPlanner {
    /// Create a planner that stamps receipts with the given subject id
    /// (e.g. `"service:aios-apps"`).
    #[must_use]
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            chain: Mutex::new(ReceiptChain::new()),
            subject: subject.into(),
        }
    }

    /// Number of evidence receipts sealed so far (test/inspection seam).
    ///
    /// # Errors
    ///
    /// [`AppsError::EvidenceEmitFailed`] if the internal lock is poisoned.
    pub fn receipt_count(&self) -> Result<usize, AppsError> {
        let chain = self
            .chain
            .lock()
            .map_err(|_| AppsError::EvidenceEmitFailed("evidence lock poisoned".to_string()))?;
        Ok(chain.len())
    }

    /// Verify the full hash-chain integrity (test seam).
    ///
    /// # Errors
    ///
    /// [`AppsError::EvidenceEmitFailed`] if the lock is poisoned or the chain
    /// integrity check fails.
    pub fn verify_chain(&self) -> Result<(), AppsError> {
        let chain = self
            .chain
            .lock()
            .map_err(|_| AppsError::EvidenceEmitFailed("evidence lock poisoned".to_string()))?;
        chain
            .verify_integrity()
            .map_err(|e| AppsError::EvidenceEmitFailed(format!("chain integrity: {e}")))
    }

    /// Produce a plan from an existing analysis and seal a `TRANSLATION_CREATED`
    /// evidence receipt describing it.
    ///
    /// # Errors
    ///
    /// [`AppsError::EvidenceEmitFailed`] if the receipt cannot be sealed or
    /// appended.
    pub fn produce_plan(
        &self,
        passport: &PackagePassport,
        translation: &RosettaTranslation,
        score: &CompatibilityScore,
    ) -> Result<(EnvironmentProvisioningPlan, ProvisioningEvidenceReceipt), AppsError> {
        let plan = EnvironmentProvisioningPlan::from_analysis(passport, translation, score);

        let payload = serde_json::json!({
            "event": "ENVIRONMENT_PLAN_PRODUCED",
            "plan_id": plan.plan_id,
            "app_id": plan.app_id,
            "runtime": plan.chosen_runtime.to_string(),
            "compatibility_score": plan.compatibility_score,
            "gpu_passthrough_required": plan.gpu_passthrough_required,
            "remediation_count": plan.remediation_steps.len(),
            "state": plan.state,
        });

        let receipt = self.seal(RecordType::TranslationCreated, payload)?;
        Ok((plan, receipt))
    }

    /// Route a plan for a Policy Kernel decision and seal a `ROUTING_DECISION`
    /// evidence receipt.
    ///
    /// The plan is advanced to [`ProvisioningPlanState::AwaitingPolicyDecision`]
    /// and the typed proposal is returned. No execution occurs; no decision is
    /// fabricated.
    ///
    /// # Errors
    ///
    /// * Propagates [`EnvironmentProvisioningPlan::route_for_decision`] errors.
    /// * [`AppsError::EvidenceEmitFailed`] if the receipt cannot be sealed.
    pub fn route_plan(
        &self,
        plan: &mut EnvironmentProvisioningPlan,
    ) -> Result<(ProvisioningOutcome, ProvisioningEvidenceReceipt), AppsError> {
        let outcome = plan.route_for_decision()?;

        let payload = serde_json::json!({
            "event": "ENVIRONMENT_PLAN_ROUTED",
            "plan_id": plan.plan_id,
            "target_service": POLICY_KERNEL_SERVICE,
            "method": POLICY_EVALUATE_METHOD,
            "state": plan.state,
        });

        let receipt = self.seal(RecordType::RoutingDecision, payload)?;
        Ok((outcome, receipt))
    }

    /// Shared seal-and-append helper.
    fn seal(
        &self,
        record_type: RecordType,
        payload: serde_json::Value,
    ) -> Result<ProvisioningEvidenceReceipt, AppsError> {
        let mut chain = self
            .chain
            .lock()
            .map_err(|_| AppsError::EvidenceEmitFailed("evidence lock poisoned".to_string()))?;
        let seq = chain.len() as u64;
        let prev = chain.receipts().last();

        let receipt = ReceiptBuilder::new(record_type, RetentionClass::Standard24M, &self.subject)
            .with_payload(payload)
            .seal(prev)
            .map_err(|e| AppsError::EvidenceEmitFailed(format!("seal: {e}")))?;

        let out = ProvisioningEvidenceReceipt {
            record_id: receipt.receipt_id().as_str().to_owned(),
            hash: receipt.content_hash().to_owned(),
            sequence: seq,
        };

        chain
            .append(receipt)
            .map_err(|e| AppsError::EvidenceEmitFailed(format!("append: {e}")))?;
        drop(chain);

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;
    use crate::rosetta_solver::{PackageFormat, RosettaSolver};

    fn native_inputs() -> (PackagePassport, RosettaTranslation, CompatibilityScore) {
        let solver = RosettaSolver::new();
        let translation = solver.propose_translation("nginx", PackageFormat::Deb);
        let score =
            solver.validate_compatibility(PackageFormat::Deb, EcosystemRuntime::RuntimeLinuxNative);
        let passport = PackagePassport::new(
            "pkgpass_native".into(),
            "app:debian:nginx".into(),
            PackageFormat::Deb,
            translation.target_runtime,
            translation.translation_strategy,
        );
        (passport, translation, score)
    }

    fn windows_inputs() -> (PackagePassport, RosettaTranslation, CompatibilityScore) {
        let solver = RosettaSolver::new();
        let translation = solver.propose_translation("game.exe", PackageFormat::Exe);
        let score = solver
            .validate_compatibility(PackageFormat::Exe, EcosystemRuntime::RuntimeWindowsProton);
        let passport = PackagePassport::new(
            "pkgpass_win".into(),
            "app:acme:game".into(),
            PackageFormat::Exe,
            translation.target_runtime,
            translation.translation_strategy,
        );
        (passport, translation, score)
    }

    #[test]
    fn plan_is_deterministic_for_given_inputs() {
        let (passport, translation, score) = native_inputs();
        let a = EnvironmentProvisioningPlan::from_analysis(&passport, &translation, &score);
        let b = EnvironmentProvisioningPlan::from_analysis(&passport, &translation, &score);
        assert_eq!(a, b, "same inputs must produce byte-identical plans");
        assert!(a.plan_id.starts_with("envplan_"));
    }

    #[test]
    fn native_plan_grants_safe_baseline_only() {
        let (passport, translation, score) = native_inputs();
        let plan = EnvironmentProvisioningPlan::from_analysis(&passport, &translation, &score);
        assert_eq!(plan.chosen_runtime, EcosystemRuntime::RuntimeLinuxNative);
        assert_eq!(
            plan.sandbox_profile.isolation_kind,
            IsolationKind::NamespaceLocal
        );
        assert!(plan
            .granted_capabilities
            .contains(&GrantedCapability::Filesystem(FilesystemAccess::AppPrivate)));
        assert!(plan
            .granted_capabilities
            .contains(&GrantedCapability::Network(NetworkPosture::LoopbackOnly)));
        assert!(!plan.gpu_passthrough_required);
        // Native runtime: no missing component, no elevated remediation.
        assert!(plan.remediation_steps.is_empty());
        assert_eq!(plan.state, ProvisioningPlanState::Drafted);
    }

    #[test]
    fn windows_plan_proposes_missing_runtime_component() {
        let (passport, translation, score) = windows_inputs();
        let plan = EnvironmentProvisioningPlan::from_analysis(&passport, &translation, &score);
        assert_eq!(plan.chosen_runtime, EcosystemRuntime::RuntimeWindowsProton);
        assert!(plan.remediation_steps.iter().any(|s| matches!(
            s,
            RemediationStep::MissingRuntimeComponent { component } if component == "wine-proton"
        )));
    }

    #[test]
    fn missing_capability_produces_requires_capability_remediation() {
        // A GPU-heavy hint drives an elevated capability proposal.
        let mut translation = RosettaTranslation::new(
            "cad.exe".into(),
            PackageFormat::Exe,
            EcosystemRuntime::RuntimeWindowsProton,
            crate::rosetta_solver::ConversionStrategy::Emulate,
            ComplexityBand::High,
        );
        translation.add_hint("needs GPU passthrough for rendering".into());
        let score = CompatibilityScore::new(60);
        let passport = PackagePassport::new(
            "pkgpass_cad".into(),
            "app:acme:cad".into(),
            PackageFormat::Exe,
            EcosystemRuntime::RuntimeWindowsProton,
            crate::rosetta_solver::ConversionStrategy::Emulate,
        );
        let plan = EnvironmentProvisioningPlan::from_analysis(&passport, &translation, &score);
        assert!(plan.gpu_passthrough_required);
        assert!(plan.remediation_steps.iter().any(|s| matches!(
            s,
            RemediationStep::RequiresCapability(GrantedCapability::Gpu(
                GpuCapabilityClass::GpuComputeHeavy
            ))
        )));
        assert!(plan
            .remediation_steps
            .contains(&RemediationStep::RequiresGpuPassthrough));
    }

    #[test]
    fn android_runtime_requires_binder_capability() {
        let translation = RosettaTranslation::new(
            "app.apk".into(),
            PackageFormat::Oci, // format irrelevant here; runtime drives binder
            EcosystemRuntime::RuntimeAndroidWaydroid,
            crate::rosetta_solver::ConversionStrategy::ContainerBridge,
            ComplexityBand::Medium,
        );
        let score = CompatibilityScore::new(80);
        let passport = PackagePassport::new(
            "pkgpass_apk".into(),
            "app:acme:mobile".into(),
            PackageFormat::Oci,
            EcosystemRuntime::RuntimeAndroidWaydroid,
            crate::rosetta_solver::ConversionStrategy::ContainerBridge,
        );
        let plan = EnvironmentProvisioningPlan::from_analysis(&passport, &translation, &score);
        assert_eq!(
            plan.sandbox_profile.isolation_kind,
            IsolationKind::ProcessContainer
        );
        assert!(plan
            .remediation_steps
            .contains(&RemediationStep::RequiresCapability(
                GrantedCapability::Binder
            )));
    }

    #[test]
    fn mutating_plan_terminates_at_awaiting_decision_no_auto_provision() {
        let (passport, translation, score) = native_inputs();
        let mut plan = EnvironmentProvisioningPlan::from_analysis(&passport, &translation, &score);
        assert_eq!(plan.state, ProvisioningPlanState::Drafted);

        let outcome = plan.route_for_decision().expect("route");
        // The proposal targets the Policy Kernel, never a domain executor.
        let ProvisioningOutcome::PolicyPending { routed } = outcome;
        assert_eq!(routed.service_fqn, POLICY_KERNEL_SERVICE);
        assert_eq!(routed.method, POLICY_EVALUATE_METHOD);
        assert!(routed.mutating);

        // The most advanced reachable state is AwaitingPolicyDecision — there is
        // no "provisioned"/"executed" state in the type at all.
        assert_eq!(plan.state, ProvisioningPlanState::AwaitingPolicyDecision);
    }

    #[test]
    fn blocked_plan_cannot_be_routed_for_decision() {
        let mut score = CompatibilityScore::new(20);
        score.add_blocking_issue("kernel module required but not available".into());
        let solver = RosettaSolver::new();
        let translation = solver.propose_translation("driver.exe", PackageFormat::Exe);
        let passport = PackagePassport::new(
            "pkgpass_blocked".into(),
            "app:acme:driver".into(),
            PackageFormat::Exe,
            translation.target_runtime,
            translation.translation_strategy,
        );
        let mut plan = EnvironmentProvisioningPlan::from_analysis(&passport, &translation, &score);
        assert_eq!(plan.state, ProvisioningPlanState::Blocked);
        assert!(plan.is_blocked());
        // Blocking issues must surface as remediation proposals.
        assert!(plan
            .remediation_steps
            .iter()
            .any(|s| matches!(s, RemediationStep::ResolveBlockingIssue { .. })));
        // Routing a blocked plan is refused — it never advances.
        assert!(matches!(
            plan.route_for_decision(),
            Err(AppsError::ValidationFailed(_))
        ));
        assert_eq!(plan.state, ProvisioningPlanState::Blocked);
    }

    #[test]
    fn planner_emits_evidence_on_produce_and_route() {
        let (passport, translation, score) = native_inputs();
        let planner = EnvironmentPlanner::new("service:aios-apps");
        assert_eq!(planner.receipt_count().expect("count"), 0);

        let (mut plan, produced) = planner
            .produce_plan(&passport, &translation, &score)
            .expect("produce");
        assert_eq!(produced.sequence, 0);
        assert!(produced.record_id.starts_with("evr_"));
        assert_eq!(produced.hash.len(), 64);
        assert_eq!(planner.receipt_count().expect("count"), 1);

        let (outcome, routed_receipt) = planner.route_plan(&mut plan).expect("route");
        assert!(matches!(outcome, ProvisioningOutcome::PolicyPending { .. }));
        assert_eq!(routed_receipt.sequence, 1);
        assert_eq!(planner.receipt_count().expect("count"), 2);

        // The append-only chain must verify end-to-end.
        planner.verify_chain().expect("chain integrity");
    }

    #[test]
    fn capability_and_remediation_types_serde_round_trip() {
        let cap = GrantedCapability::Gpu(GpuCapabilityClass::GpuComputeHeavy);
        let json = serde_json::to_string(&cap).expect("ser");
        let back: GrantedCapability = serde_json::from_str(&json).expect("de");
        assert_eq!(cap, back);

        let step = RemediationStep::MissingRuntimeComponent {
            component: "wine-proton".into(),
        };
        let json = serde_json::to_string(&step).expect("ser");
        let back: RemediationStep = serde_json::from_str(&json).expect("de");
        assert_eq!(step, back);
    }
}
