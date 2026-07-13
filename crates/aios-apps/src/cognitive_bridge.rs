//! L5→L6 cognitive proposal bridge for the environment-provisioning seam.
//!
//! This module discharges the `COGNITIVE_PROPOSER_CONTRACT` seam left open in
//! [`crate::environment_plan`]. It wires the **L5 Cognitive Core** to the
//! deterministic L6 environment planner while preserving the constitutional
//! law verbatim:
//!
//! > **AI proposes, never executes.** The Cognitive Core only *proposes* a
//! > typed app-provisioning **intent**. The deterministic
//! > [`RosettaSolver`](crate::rosetta_solver::RosettaSolver) turns that intent
//! > into the three typed inputs, and
//! > [`EnvironmentProvisioningPlan::from_analysis`] builds the governed plan.
//! > The plan still terminates at
//! > [`ProvisioningPlanState::AwaitingPolicyDecision`] — there is **no** path
//! > here that marks an environment provisioned. Authority stays with the
//! > deterministic planner and, downstream, the Policy Kernel.
//!
//! ## Layer direction
//!
//! `aios-apps` is **L6**; `aios-cognitive` is **L5**. A layer may depend on
//! lower-numbered layers, so **L6 → L5 is legal**. The forbidden direction —
//! L5 requiring L6 — is *not* taken: `aios-cognitive` has no dependency on
//! `aios-apps`, so importing [`aios_cognitive::CognitiveIntent`] here introduces
//! no dependency cycle. The bridge therefore lives entirely on the L6 side.
//!
//! ## What is REAL vs CONTRACT
//!
//! * **REAL (E3):** consuming a real [`aios_cognitive::CognitiveIntent`],
//!   mapping it to a typed [`EnvironmentIntent`], deterministically deriving the
//!   three plan inputs, building the plan, emitting evidence via
//!   [`EnvironmentPlanner`], and terminating at `AwaitingPolicyDecision`.
//! * **CONTRACT:** the *live* gRPC `aios.cognitive.CognitiveCore/ProposePlan`
//!   RPC that would *mint* a [`aios_cognitive::CognitiveIntent`] from a running
//!   local model. This bridge accepts an already-minted intent; it never calls
//!   a model and never fabricates one.

use aios_cognitive::CognitiveIntent;
use serde::{Deserialize, Serialize};

use crate::environment_plan::{
    EnvironmentPlanner, EnvironmentProvisioningPlan, ProvisioningEvidenceReceipt,
    ProvisioningOutcome,
};
use crate::error::AppsError;
use crate::rosetta_solver::{
    CompatibilityScore, PackageFormat, PackagePassport, RosettaSolver, RosettaTranslation,
};

/// A typed app-provisioning **request** — the dependency-light form of an intent
/// that a proposer turns into plan inputs.
///
/// This is the boundary type between "what the operator/AI wants" and the
/// deterministic planner. It carries only typed, closed-vocabulary fields — no
/// free-form shell command, no host mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentIntent {
    /// Human-readable application identifier (e.g. `app:publisher:name`).
    pub app_id: String,
    /// The source package name (e.g. `nginx`, `game.exe`).
    pub source_package: String,
    /// The declared source package format (closed vocabulary).
    pub source_format: PackageFormat,
}

impl EnvironmentIntent {
    /// Construct a typed environment intent directly.
    #[must_use]
    pub fn new(
        app_id: impl Into<String>,
        source_package: impl Into<String>,
        source_format: PackageFormat,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            source_package: source_package.into(),
            source_format,
        }
    }

    /// The **REAL** L5→L6 bridge: derive a typed [`EnvironmentIntent`] from a
    /// Cognitive Core [`CognitiveIntent`].
    ///
    /// The cognitive intent carries only a natural-language goal plus a
    /// canonical subject. This mapping is deterministic and **fail-closed**: it
    /// scans the utterance for a token bearing a recognized package-format
    /// extension and refuses (rather than guessing) when none is present. It
    /// never fabricates a format and never mutates anything.
    ///
    /// # Errors
    ///
    /// [`AppsError::ValidationFailed`] if the utterance contains no token whose
    /// suffix maps to a known [`PackageFormat`]. Fail-closed: no format is
    /// invented.
    pub fn from_cognitive_intent(intent: &CognitiveIntent) -> Result<Self, AppsError> {
        let utterance = &intent.natural_language;

        let (token, format) = utterance
            .split_whitespace()
            .find_map(|raw| {
                let cleaned = raw.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
                detect_format(cleaned).map(|fmt| (cleaned.to_string(), fmt))
            })
            .ok_or_else(|| {
                AppsError::ValidationFailed(format!(
                    "cognitive intent {} carries no recognizable package format token; \
                     refusing to fabricate one",
                    intent.intent_id.0
                ))
            })?;

        let stem = package_stem(&token);
        let subject = sanitize(&intent.subject.0);
        let app_id = format!("app:{subject}:{stem}");

        Ok(Self::new(app_id, token, format))
    }
}

/// Map a token's suffix to a [`PackageFormat`], if recognized.
///
/// Closed mapping — an unrecognized suffix yields `None` (fail-closed at the
/// caller). Case-insensitive on the extension.
fn detect_format(token: &str) -> Option<PackageFormat> {
    let lower = token.to_ascii_lowercase();
    let ext = lower.rsplit('.').next()?;
    // A bare token with no `.` has `rsplit` yield the whole token; require a dot.
    if !lower.contains('.') {
        return None;
    }
    match ext {
        "deb" => Some(PackageFormat::Deb),
        "rpm" => Some(PackageFormat::Rpm),
        "flatpak" => Some(PackageFormat::Flatpak),
        "snap" => Some(PackageFormat::Snap),
        "appimage" => Some(PackageFormat::Appimage),
        "nix" => Some(PackageFormat::Nix),
        "oci" => Some(PackageFormat::Oci),
        "exe" => Some(PackageFormat::Exe),
        "msi" => Some(PackageFormat::Msi),
        _ => None,
    }
}

/// The package name stem (drop a single trailing extension).
fn package_stem(token: &str) -> String {
    token
        .rsplit_once('.')
        .map_or(token, |(stem, _ext)| stem)
        .to_string()
}

/// Sanitize a subject/id fragment to `[a-z0-9_-]`.
fn sanitize(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

/// The three typed inputs a proposer derives from an [`EnvironmentIntent`].
///
/// These feed [`EnvironmentProvisioningPlan::from_analysis`] unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedPlanInputs {
    /// The package passport.
    pub passport: PackagePassport,
    /// The Rosetta translation.
    pub translation: RosettaTranslation,
    /// The compatibility score.
    pub score: CompatibilityScore,
}

impl ProposedPlanInputs {
    /// Build the deterministic environment plan from these inputs.
    ///
    /// This is a pure delegation to
    /// [`EnvironmentProvisioningPlan::from_analysis`]; no execution, no effect.
    #[must_use]
    pub fn into_plan(&self) -> EnvironmentProvisioningPlan {
        EnvironmentProvisioningPlan::from_analysis(&self.passport, &self.translation, &self.score)
    }
}

/// A proposer that turns a typed [`EnvironmentIntent`] into the three plan
/// inputs. Object-safe: usable as `&dyn EnvironmentPlanProposer`.
///
/// Implementations MUST be *proposal-only*: they may derive typed inputs but
/// must never execute the plan, mutate the host, or fabricate a policy decision.
pub trait EnvironmentPlanProposer {
    /// Derive the typed plan inputs for an intent.
    ///
    /// # Errors
    ///
    /// [`AppsError`] if the inputs cannot be derived (e.g. an invalid intent).
    fn propose_inputs(&self, intent: &EnvironmentIntent) -> Result<ProposedPlanInputs, AppsError>;
}

/// The default, fully-deterministic proposer (REAL, no model in the loop).
///
/// Uses the [`RosettaSolver`] to derive the translation, compatibility score,
/// and passport from the intent. Same intent ⇒ same inputs.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeterministicEnvironmentProposer;

impl DeterministicEnvironmentProposer {
    /// Create a deterministic proposer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl EnvironmentPlanProposer for DeterministicEnvironmentProposer {
    fn propose_inputs(&self, intent: &EnvironmentIntent) -> Result<ProposedPlanInputs, AppsError> {
        if intent.source_package.trim().is_empty() {
            return Err(AppsError::ValidationFailed(
                "environment intent has an empty source_package".to_string(),
            ));
        }

        let solver = RosettaSolver::new();
        let translation = solver.propose_translation(&intent.source_package, intent.source_format);
        let score = solver.validate_compatibility(intent.source_format, translation.target_runtime);

        let passport_id = deterministic_passport_id(intent);
        let passport = PackagePassport::new(
            passport_id,
            intent.app_id.clone(),
            intent.source_format,
            translation.target_runtime,
            translation.translation_strategy,
        );

        Ok(ProposedPlanInputs {
            passport,
            translation,
            score,
        })
    }
}

/// Deterministic passport id from the intent identity.
fn deterministic_passport_id(intent: &EnvironmentIntent) -> String {
    let canonical = format!(
        "{}|{}|{}",
        intent.app_id, intent.source_package, intent.source_format
    );
    let digest = blake3::hash(canonical.as_bytes());
    format!("pkgpass_{}", &digest.to_hex()[..24])
}

/// The receipt bundle for a routed proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalTicket {
    /// The typed plan (never in a "provisioned" state).
    pub plan: EnvironmentProvisioningPlan,
    /// Evidence receipt sealed when the plan was produced.
    pub produced_receipt: ProvisioningEvidenceReceipt,
    /// The routing outcome + receipt, present only when the plan was routed
    /// (i.e. it was not blocked). A blocked plan is produced-and-evidenced but
    /// never routed.
    pub routed: Option<(ProvisioningOutcome, ProvisioningEvidenceReceipt)>,
}

/// Ties a proposer to the evidence-emitting [`EnvironmentPlanner`], running the
/// full seam: intent → typed inputs → plan → (produce evidence) → route →
/// `AwaitingPolicyDecision`.
///
/// This is the single entry point the L5 cognitive hook drives. It is the only
/// place that turns a proposal into a *routed, evidenced* proposal — and it
/// still terminates at the Policy Kernel boundary. Nothing here executes.
pub struct EnvironmentProposalPipeline<'a> {
    proposer: &'a dyn EnvironmentPlanProposer,
    planner: &'a EnvironmentPlanner,
}

impl<'a> EnvironmentProposalPipeline<'a> {
    /// Create a pipeline over a proposer and a planner.
    #[must_use]
    pub fn new(proposer: &'a dyn EnvironmentPlanProposer, planner: &'a EnvironmentPlanner) -> Self {
        Self { proposer, planner }
    }

    /// Run the seam for a typed [`EnvironmentIntent`].
    ///
    /// Produces the plan (sealing a `TRANSLATION_CREATED` receipt) and, unless
    /// the plan is blocked, routes it for a Policy Kernel decision (sealing a
    /// `ROUTING_DECISION` receipt and advancing to
    /// [`crate::environment_plan::ProvisioningPlanState::AwaitingPolicyDecision`]).
    ///
    /// # Errors
    ///
    /// * Propagates proposer errors (invalid intent).
    /// * Propagates [`EnvironmentPlanner`] evidence-sealing errors.
    pub fn propose(&self, intent: &EnvironmentIntent) -> Result<ProposalTicket, AppsError> {
        let inputs = self.proposer.propose_inputs(intent)?;
        let (mut plan, produced_receipt) =
            self.planner
                .produce_plan(&inputs.passport, &inputs.translation, &inputs.score)?;

        let routed = if plan.is_blocked() {
            None
        } else {
            Some(self.planner.route_plan(&mut plan)?)
        };

        Ok(ProposalTicket {
            plan,
            produced_receipt,
            routed,
        })
    }

    /// The **REAL** cognitive entry point: run the seam directly from a
    /// Cognitive Core [`CognitiveIntent`].
    ///
    /// Maps the intent via [`EnvironmentIntent::from_cognitive_intent`] then runs
    /// [`propose`](Self::propose). The Cognitive Core only *proposed* the intent;
    /// the deterministic planner and Policy Kernel remain the authority.
    ///
    /// # Errors
    ///
    /// * [`AppsError::ValidationFailed`] if the cognitive intent carries no
    ///   recognizable package format (fail-closed).
    /// * Propagates [`propose`](Self::propose) errors.
    pub fn propose_from_cognitive_intent(
        &self,
        intent: &CognitiveIntent,
    ) -> Result<ProposalTicket, AppsError> {
        let env_intent = EnvironmentIntent::from_cognitive_intent(intent)?;
        self.propose(&env_intent)
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
    use crate::environment_plan::ProvisioningPlanState;
    use aios_cognitive::intent::{IntentId, SubjectRef};
    use aios_cognitive::{LatencyTier, PrivacyClass};
    use chrono::Utc;

    fn cognitive_intent(utterance: &str) -> CognitiveIntent {
        CognitiveIntent {
            intent_id: IntentId::new(),
            subject: SubjectRef("operator:root".to_string()),
            natural_language: utterance.to_string(),
            context_hash: "0".repeat(64),
            created_at: Utc::now(),
            latency_class: LatencyTier::T3LocalCognitive,
            privacy_class: PrivacyClass::Internal,
        }
    }

    #[test]
    fn deterministic_proposer_is_object_safe_and_deterministic() {
        // Object-safe: usable behind a trait object.
        let proposer: &dyn EnvironmentPlanProposer = &DeterministicEnvironmentProposer::new();
        let intent = EnvironmentIntent::new("app:debian:nginx", "nginx", PackageFormat::Deb);

        let a = proposer.propose_inputs(&intent).expect("inputs a");
        let b = proposer.propose_inputs(&intent).expect("inputs b");
        assert_eq!(a, b, "same intent must yield identical inputs");
    }

    #[test]
    fn cognitive_intent_maps_to_typed_intent() {
        let ci = cognitive_intent("please install game.exe for me");
        let env = EnvironmentIntent::from_cognitive_intent(&ci).expect("map");
        assert_eq!(env.source_format, PackageFormat::Exe);
        assert_eq!(env.source_package, "game.exe");
        assert!(env.app_id.starts_with("app:operator_root:"));
    }

    #[test]
    fn cognitive_intent_without_format_is_refused_fail_closed() {
        let ci = cognitive_intent("make my computer faster somehow");
        let err = EnvironmentIntent::from_cognitive_intent(&ci)
            .expect_err("must refuse: no format token");
        assert!(matches!(err, AppsError::ValidationFailed(_)));
    }

    #[test]
    fn full_seam_flows_intent_to_policy_pending_never_provisioned() {
        let proposer = DeterministicEnvironmentProposer::new();
        let planner = EnvironmentPlanner::new("service:aios-apps");
        let pipeline = EnvironmentProposalPipeline::new(&proposer, &planner);

        let ci = cognitive_intent("install nginx.deb please");
        let ticket = pipeline
            .propose_from_cognitive_intent(&ci)
            .expect("full seam");

        // Evidence: produce receipt at seq 0, route receipt at seq 1.
        assert_eq!(ticket.produced_receipt.sequence, 0);
        assert!(ticket.produced_receipt.record_id.starts_with("evr_"));
        let (outcome, routed_receipt) = ticket.routed.expect("routed");
        assert!(matches!(outcome, ProvisioningOutcome::PolicyPending { .. }));
        assert_eq!(routed_receipt.sequence, 1);
        assert_eq!(planner.receipt_count().expect("count"), 2);
        planner.verify_chain().expect("chain integrity");

        // Terminal state is AwaitingPolicyDecision — never provisioned.
        assert_eq!(
            ticket.plan.state,
            ProvisioningPlanState::AwaitingPolicyDecision
        );
    }

    #[test]
    fn policy_pending_targets_policy_kernel() {
        use crate::environment_plan::{POLICY_EVALUATE_METHOD, POLICY_KERNEL_SERVICE};

        let proposer = DeterministicEnvironmentProposer::new();
        let planner = EnvironmentPlanner::new("service:aios-apps");
        let pipeline = EnvironmentProposalPipeline::new(&proposer, &planner);

        let intent = EnvironmentIntent::new("app:acme:game", "game.exe", PackageFormat::Exe);
        let ticket = pipeline.propose(&intent).expect("propose");

        let (ProvisioningOutcome::PolicyPending { routed }, _) = ticket.routed.expect("routed")
        else {
            unreachable!()
        };
        assert_eq!(routed.service_fqn, POLICY_KERNEL_SERVICE);
        assert_eq!(routed.method, POLICY_EVALUATE_METHOD);
        assert!(routed.mutating);
        // A Windows binary must surface a missing-runtime remediation proposal.
        assert!(!ticket.plan.remediation_steps.is_empty());
    }

    #[test]
    fn empty_source_package_is_rejected() {
        let proposer = DeterministicEnvironmentProposer::new();
        let intent = EnvironmentIntent::new("app:x:y", "   ", PackageFormat::Deb);
        assert!(matches!(
            proposer.propose_inputs(&intent),
            Err(AppsError::ValidationFailed(_))
        ));
    }
}
