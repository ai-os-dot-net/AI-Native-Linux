//! Zero-Trust Fleet Posture — NIST 800-207 continuous verification module.
//!
//! Implements the zero-trust posture rules for cross-host fleet authorization:
//! no implicit trust from network location, every access decision is per-request
//! per-session with continuous verification. Hosts never trust because a peer
//! is "on the same network"; they trust for one specific request, for a bounded
//! time, because the peer's signed posture earned it.
//!
//! NIST 800-207 alignment: per-request authorization, continuous diagnostics,
//! dynamic policy from multiple posture signals. No "trust once, access forever."

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::remote_sandbox::SecurityProfileLevel;

// ---------------------------------------------------------------------------
// ZeroTrustCheck — closed enum of posture signal kinds
// ---------------------------------------------------------------------------

/// A zero-trust posture check that contributes to overall trust scoring.
///
/// Each variant represents a distinct security signal. The `ZeroTrustPolicy`
/// declares which checks are mandatory per profile. This enum is **closed**:
/// unknown check kinds MUST be rejected by posture validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ZeroTrustCheck {
    /// TPM remote attestation quote verified; bound to S16.4 measured boot.
    TpmAttestation,
    /// SELinux is in enforcing mode (not permissive or disabled).
    SelinuxEnforcing,
    /// IMA (Integrity Measurement Architecture) appraisal is active.
    ImaAppraisal,
    /// dm-verity block integrity chain is intact.
    DmVerityIntegrity,
    /// Host service hardening score meets the profile floor.
    ServiceHardeningScore,
    /// The fleet membership record is valid (S25 membership facts).
    FleetMembershipValid,
    /// The local evidence log hash chain is consistent (S3.1).
    EvidenceChainConsistent,
    /// Network transport posture satisfies the profile requirements.
    NetworkPostureValid,
    /// The cryptographic boundary (TPM, key hierarchy) is intact.
    CryptoBoundaryIntact,
    /// Data residency constraints are satisfied.
    DataResidencyCompliant,
}

impl ZeroTrustCheck {
    /// Human-readable label for this check kind.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TpmAttestation => "TPM_ATTESTATION",
            Self::SelinuxEnforcing => "SELINUX_ENFORCING",
            Self::ImaAppraisal => "IMA_APPRAISAL",
            Self::DmVerityIntegrity => "DM_VERITY_INTEGRITY",
            Self::ServiceHardeningScore => "SERVICE_HARDENING_SCORE",
            Self::FleetMembershipValid => "FLEET_MEMBERSHIP_VALID",
            Self::EvidenceChainConsistent => "EVIDENCE_CHAIN_CONSISTENT",
            Self::NetworkPostureValid => "NETWORK_POSTURE_VALID",
            Self::CryptoBoundaryIntact => "CRYPTO_BOUNDARY_INTACT",
            Self::DataResidencyCompliant => "DATA_RESIDENCY_COMPLIANT",
        }
    }
}

impl fmt::Display for ZeroTrustCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// TrustLevel — closed enum for overall trust standing
// ---------------------------------------------------------------------------

/// The computed trust standing of a fleet participant.
///
/// Variants are declared **least to most trusted** so that derived `Ord`
/// yields `Quarantined < Untrusted < ConditionalTrust < Trusted`.
///
/// NIST 800-207: tiers are continuously re-evaluated; no standing trust.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustLevel {
    /// FAIL signal or posture expired; deny all but recovery.
    Quarantined,
    /// No valid posture yet; treated as deny-all-except-recovery.
    Untrusted,
    /// WARN signals present; read-only or low-risk actions only.
    ConditionalTrust,
    /// All required signals PASS/FRESH; profile floor met; full access.
    Trusted,
}

impl TrustLevel {
    /// Returns `true` if this level permits any non-recovery access.
    #[must_use]
    pub const fn allows_access(self) -> bool {
        matches!(self, Self::Trusted | Self::ConditionalTrust)
    }

    /// Returns `true` if this level denies all non-recovery access.
    #[must_use]
    pub const fn is_denied(self) -> bool {
        matches!(self, Self::Untrusted | Self::Quarantined)
    }

    /// Returns the canonical SCREAMING_SNAKE_CASE label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::ConditionalTrust => "CONDITIONAL_TRUST",
            Self::Untrusted => "UNTRUSTED",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// ZeroTrustCheckResult
// ---------------------------------------------------------------------------

/// The outcome of a single `ZeroTrustCheck` evaluation against a host posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustCheckResult {
    /// Which check was evaluated.
    pub check: ZeroTrustCheck,
    /// Whether the check passed its per-profile threshold.
    pub passed: bool,
    /// Numeric score 0–100 representing the check quality.
    pub score: u8,
    /// Human-readable detail about the evaluation.
    pub details: String,
    /// Timestamp when this check was last run.
    pub last_run: DateTime<Utc>,
    /// Whether evidence was emitted for this check result.
    pub evidence_emitted: bool,
}

impl ZeroTrustCheckResult {
    /// Create a passed check result with a perfect score.
    #[must_use]
    pub fn passed(check: ZeroTrustCheck, details: String) -> Self {
        Self {
            check,
            passed: true,
            score: 100,
            details,
            last_run: Utc::now(),
            evidence_emitted: false,
        }
    }

    /// Create a failed check result with the given score and reason.
    ///
    /// The score is clamped to `0..=99` since a failed result cannot have
    /// a perfect score.
    #[must_use]
    pub fn failed(check: ZeroTrustCheck, score: u8, details: String) -> Self {
        Self {
            check,
            passed: false,
            score: score.min(99),
            details,
            last_run: Utc::now(),
            evidence_emitted: false,
        }
    }

    /// Mark this result as having emitted an evidence record.
    pub fn mark_evidence_emitted(&mut self) {
        self.evidence_emitted = true;
    }
}

// ---------------------------------------------------------------------------
// ZeroTrustPosture
// ---------------------------------------------------------------------------

/// The signed snapshot of a host's current standing as a fleet participant.
///
/// This is the unit a peer reads before granting any access. It is
/// content-addressed and recorded so a verdict can be replayed from evidence.
///
/// NIST 800-207: posture is continuously re-evaluated, never trusted once
/// and forgotten.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustPosture {
    /// The host this posture describes.
    pub host_id: String,
    /// Whether continuous background re-evaluation is active.
    pub continuous_check_enabled: bool,
    /// Timestamp of the last complete posture evaluation.
    pub last_full_recheck: Option<DateTime<Utc>>,
    /// Seconds between scheduled re-evaluations.
    pub check_interval_seconds: u64,
    /// Results for each check that was executed.
    pub per_check_results: Vec<ZeroTrustCheckResult>,
    /// The overall trust level computed from all check results.
    pub overall_trust_level: TrustLevel,
}

impl ZeroTrustPosture {
    /// Create a new posture record for a host with no check results yet.
    #[must_use]
    pub fn new(host_id: String, check_interval_seconds: u64) -> Self {
        Self {
            host_id,
            continuous_check_enabled: true,
            last_full_recheck: None,
            check_interval_seconds,
            per_check_results: Vec::new(),
            overall_trust_level: TrustLevel::Untrusted,
        }
    }

    /// Compute the aggregate score across all check results.
    ///
    /// Returns `None` when there are no check results to score.
    #[must_use]
    pub fn aggregate_score(&self) -> Option<u8> {
        if self.per_check_results.is_empty() {
            return None;
        }
        let total: u16 = self
            .per_check_results
            .iter()
            .map(|r| u16::from(r.score))
            .sum();
        let count = self.per_check_results.len() as u16;
        let avg = total / count;
        // Clamp safely: avg is at most 100 (all scores ≤100, division by ≥1)
        if avg > 255 {
            None
        } else {
            Some(avg as u8)
        }
    }

    /// Returns `true` if all mandatory checks (from the given list) have
    /// passed with score ≥ 100.
    #[must_use]
    pub fn all_mandatory_passed(&self, mandatory: &[ZeroTrustCheck]) -> bool {
        mandatory.iter().all(|required| {
            self.per_check_results
                .iter()
                .any(|r| r.check == *required && r.passed)
        })
    }
}

// ---------------------------------------------------------------------------
// PostureDrift — detects posture degradation between checks
// ---------------------------------------------------------------------------

/// Captures a degradation between two posture evaluations.
///
/// Posture drift is detected when the aggregate score drops or any check
/// transitions from passed to failed between consecutive evaluations.
/// Drift always triggers a `POSTURE_DRIFT_DETECTED` evidence record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureDrift {
    /// The previous posture snapshot.
    pub previous: ZeroTrustPosture,
    /// The current posture snapshot showing degradation.
    pub current: ZeroTrustPosture,
    /// When the drift was detected.
    pub detected_at: DateTime<Utc>,
    /// The effective trust level after accounting for the drift.
    pub resulting_level: TrustLevel,
}

impl PostureDrift {
    /// Detect drift between a previous and current posture.
    ///
    /// Returns `Some(PostureDrift)` when any of these conditions hold:
    /// - The aggregate score has decreased.
    /// - Any previously-passed check is now failed.
    /// - The overall trust level has degraded.
    ///
    /// Returns `None` when the posture is stable or has improved.
    #[must_use]
    pub fn detect(
        previous: &ZeroTrustPosture,
        current: &ZeroTrustPosture,
    ) -> Option<Self> {
        let prev_score = previous.aggregate_score();
        let curr_score = current.aggregate_score();

        let score_degraded = match (prev_score, curr_score) {
            (Some(p), Some(c)) => c < p,
            _ => false,
        };

        let checks_degraded = previous.per_check_results.iter().any(|prev| {
            prev.passed
                && current
                    .per_check_results
                    .iter()
                    .any(|curr| curr.check == prev.check && !curr.passed)
        });

        let tier_degraded = current.overall_trust_level < previous.overall_trust_level;

        if score_degraded || checks_degraded || tier_degraded {
            Some(Self {
                previous: previous.clone(),
                current: current.clone(),
                detected_at: Utc::now(),
                resulting_level: current.overall_trust_level,
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ZeroTrustPolicy — per-profile continuous re-evaluation rules
// ---------------------------------------------------------------------------

/// Defines the zero-trust re-evaluation cadence and thresholds per security
/// profile. Each profile mandates specific checks and sets score boundaries
/// for trust tier transitions.
///
/// NIST 800-207: policy must support per-request, per-session decisions with
/// continuous diagnostics — not trust-once-access-forever.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustPolicy {
    /// The security profile this policy belongs to.
    pub profile: SecurityProfileLevel,
    /// Seconds between scheduled posture re-evaluations.
    pub check_interval_seconds: u64,
    /// Checks that must be present and passing for a host to be considered
    /// in good standing for this profile.
    pub mandatory_checks: Vec<ZeroTrustCheck>,
    /// Aggregate score below which the host is quarantined.
    pub quarantine_threshold: u8,
    /// Aggregate score below which the host is conditionally trusted.
    pub conditional_trust_threshold: u8,
}

impl ZeroTrustPolicy {
    /// Create a policy enforcing the tightest posture: all checks mandatory,
    /// 5-minute re-check interval, quarantine below 50, conditional below 75.
    #[must_use]
    pub fn airgap_high() -> Self {
        Self {
            profile: SecurityProfileLevel::AirgapHigh,
            check_interval_seconds: 300,
            mandatory_checks: all_checks(),
            quarantine_threshold: 50,
            conditional_trust_threshold: 75,
        }
    }

    /// Create a policy for STIG-aligned deployments: 15-minute re-check,
    /// all checks mandatory, same thresholds as AirgapHigh.
    #[must_use]
    pub fn stig_aligned() -> Self {
        Self {
            profile: SecurityProfileLevel::StigAligned,
            check_interval_seconds: 900,
            mandatory_checks: all_checks(),
            quarantine_threshold: 50,
            conditional_trust_threshold: 75,
        }
    }

    /// Create a policy for secure-default production: 1-hour re-check,
    /// core checks mandatory, same thresholds.
    #[must_use]
    pub fn secure_default() -> Self {
        Self {
            profile: SecurityProfileLevel::SecureDefault,
            check_interval_seconds: 3600,
            mandatory_checks: mandatory_for_secure(),
            quarantine_threshold: 50,
            conditional_trust_threshold: 75,
        }
    }

    /// Create a policy for developer-relaxed environments: 4-hour re-check,
    /// minimal checks mandatory, lower thresholds.
    #[must_use]
    pub fn dev_relaxed() -> Self {
        Self {
            profile: SecurityProfileLevel::DevRelaxed,
            check_interval_seconds: 14400,
            mandatory_checks: mandatory_for_dev(),
            quarantine_threshold: 40,
            conditional_trust_threshold: 60,
        }
    }

    /// Build the default policy for the given security profile level.
    #[must_use]
    pub fn for_profile(profile: SecurityProfileLevel) -> Self {
        match profile {
            SecurityProfileLevel::AirgapHigh => Self::airgap_high(),
            SecurityProfileLevel::StigAligned => Self::stig_aligned(),
            SecurityProfileLevel::SecureDefault => Self::secure_default(),
            SecurityProfileLevel::DevRelaxed => Self::dev_relaxed(),
        }
    }

    /// Compute the trust level from a set of check results.
    ///
    /// Rules:
    /// - `None` (no results) → `Untrusted`
    /// - aggregate score < quarantine_threshold → `Quarantined`
    /// - aggregate score < conditional_trust_threshold → `ConditionalTrust`
    /// - all mandatory passed with score 100 → `Trusted`
    /// - otherwise → `ConditionalTrust`
    #[must_use]
    pub fn compute_trust_level(&self, results: &[ZeroTrustCheckResult]) -> TrustLevel {
        if results.is_empty() {
            return TrustLevel::Untrusted;
        }

        let total: u16 = results.iter().map(|r| u16::from(r.score)).sum();
        let count = results.len() as u16;
        let avg: u8 = if count == 0 {
            0
        } else {
            let a = total / count;
            if a > 255 { 0 } else { a as u8 }
        };

        if avg < self.quarantine_threshold {
            TrustLevel::Quarantined
        } else if avg < self.conditional_trust_threshold {
            TrustLevel::ConditionalTrust
        } else if self.all_mandatory_passed(results) {
            TrustLevel::Trusted
        } else {
            TrustLevel::ConditionalTrust
        }
    }

    /// Returns `true` when all mandatory checks for this policy are present
    /// and passed in the given results.
    #[must_use]
    pub fn all_mandatory_passed(&self, results: &[ZeroTrustCheckResult]) -> bool {
        self.mandatory_checks.iter().all(|required| {
            results
                .iter()
                .any(|r| r.check == *required && r.passed)
        })
    }
}

// ---------------------------------------------------------------------------
// ZeroTrustEvidenceKind — closed enum of evidence event types
// ---------------------------------------------------------------------------

/// Evidence record types emitted by the zero-trust posture subsystem.
///
/// Every posture evaluation, drift detection, quarantine, and trust
/// restoration produces exactly one evidence record of the appropriate kind.
/// These are appended to the local S3.1 Evidence Log and replicated via S25.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ZeroTrustEvidenceKind {
    /// A full posture evaluation completed.
    ZeroTrustPostureEvaluated,
    /// Posture drift was detected between consecutive evaluations.
    PostureDriftDetected,
    /// A host was quarantined (score fell below quarantine threshold).
    HostQuarantined,
    /// A previously quarantined/untrusted host regained trust.
    HostTrustRestored,
}

// ---------------------------------------------------------------------------
// ZeroTrustEvidence
// ---------------------------------------------------------------------------

/// A structured evidence record emitted by the zero-trust engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustEvidence {
    /// The event kind.
    pub kind: ZeroTrustEvidenceKind,
    /// The host this evidence concerns.
    pub host_id: String,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Human-readable detail for auditability.
    pub details: String,
    /// The previous trust level before this event.
    pub previous_level: Option<TrustLevel>,
    /// The new trust level after this event.
    pub new_level: TrustLevel,
    /// Aggregated posture score at the time of this event.
    pub aggregate_score: Option<u8>,
}

impl ZeroTrustEvidence {
    /// Create an evidence record for a posture evaluation.
    #[must_use]
    pub fn posture_evaluated(
        host_id: &str,
        previous_level: TrustLevel,
        new_level: TrustLevel,
        score: Option<u8>,
        details: String,
    ) -> Self {
        Self {
            kind: ZeroTrustEvidenceKind::ZeroTrustPostureEvaluated,
            host_id: host_id.to_string(),
            timestamp: Utc::now(),
            details,
            previous_level: Some(previous_level),
            new_level,
            aggregate_score: score,
        }
    }

    /// Create an evidence record for drift detection.
    #[must_use]
    pub fn drift_detected(
        host_id: &str,
        previous_level: TrustLevel,
        new_level: TrustLevel,
        score: Option<u8>,
        details: String,
    ) -> Self {
        Self {
            kind: ZeroTrustEvidenceKind::PostureDriftDetected,
            host_id: host_id.to_string(),
            timestamp: Utc::now(),
            details,
            previous_level: Some(previous_level),
            new_level,
            aggregate_score: score,
        }
    }

    /// Create an evidence record for host quarantine.
    #[must_use]
    pub fn host_quarantined(
        host_id: &str,
        previous_level: TrustLevel,
        score: Option<u8>,
        details: String,
    ) -> Self {
        Self {
            kind: ZeroTrustEvidenceKind::HostQuarantined,
            host_id: host_id.to_string(),
            timestamp: Utc::now(),
            details,
            previous_level: Some(previous_level),
            new_level: TrustLevel::Quarantined,
            aggregate_score: score,
        }
    }

    /// Create an evidence record for trust restoration.
    #[must_use]
    pub fn trust_restored(
        host_id: &str,
        previous_level: TrustLevel,
        new_level: TrustLevel,
        score: Option<u8>,
        details: String,
    ) -> Self {
        Self {
            kind: ZeroTrustEvidenceKind::HostTrustRestored,
            host_id: host_id.to_string(),
            timestamp: Utc::now(),
            details,
            previous_level: Some(previous_level),
            new_level,
            aggregate_score: score,
        }
    }
}

// ---------------------------------------------------------------------------
// ZeroTrustEngine
// ---------------------------------------------------------------------------

/// The core zero-trust decision engine.
///
/// Holds the active `ZeroTrustPolicy` and the posture state for every
/// known host. Provides evaluation, drift detection, trust level
/// computation, and continuous re-evaluation scheduling.
///
/// NIST 800-207: every access decision is per-request, per-session with
/// continuous verification. This engine provides the posture verdict that
/// the policy kernel and fleet routing consume.
pub struct ZeroTrustEngine {
    /// The active policy (tied to the host's security profile).
    pub policy: ZeroTrustPolicy,
    /// Posture state keyed by host ID.
    posture_state: HashMap<String, ZeroTrustPosture>,
}

impl ZeroTrustEngine {
    /// Create a new zero-trust engine with the given policy.
    #[must_use]
    pub fn new(policy: ZeroTrustPolicy) -> Self {
        Self {
            policy,
            posture_state: HashMap::new(),
        }
    }

    /// Record or update a host's posture in the engine state.
    pub fn set_posture(&mut self, posture: ZeroTrustPosture) {
        self.posture_state
            .insert(posture.host_id.clone(), posture);
    }

    /// Look up a host's posture.
    #[must_use]
    pub fn get_posture(&self, host_id: &str) -> Option<&ZeroTrustPosture> {
        self.posture_state.get(host_id)
    }

    /// Return all known host IDs.
    #[must_use]
    pub fn known_hosts(&self) -> Vec<&String> {
        self.posture_state.keys().collect()
    }

    /// Evaluate a posture against the engine's policy and produce new
    /// check results.
    ///
    /// This recomputes the `overall_trust_level` from the check results
    /// using the policy's `compute_trust_level` method.
    #[must_use]
    pub fn evaluate_posture(&self, posture: &ZeroTrustPosture) -> ZeroTrustPosture {
        let mut evaluated = posture.clone();
        evaluated.last_full_recheck = Some(Utc::now());

        let trust_level = self
            .policy
            .compute_trust_level(&evaluated.per_check_results);
        evaluated.overall_trust_level = trust_level;

        evaluated
    }

    /// Compute the trust level transition from the current state and a set
    /// of check results.
    ///
    /// This is the NIST 800-207 "continuous diagnostics" scoring function:
    /// it maps raw check results through the active policy to produce a
    /// `TrustLevel` verdict. The result can be compared against the current
    /// level to detect transitions (downgrade or upgrade).
    #[must_use]
    pub fn trust_level_transition(
        &self,
        current: TrustLevel,
        results: &[ZeroTrustCheckResult],
    ) -> TrustLevel {
        if results.is_empty() {
            return current;
        }
        self.policy.compute_trust_level(results)
    }

    /// Apply the quarantine threshold: score < 50 → `Quarantined`,
    /// score < 75 → `ConditionalTrust`, otherwise `Trusted`.
    ///
    /// This is the simplified single-score quarantine gate. For the full
    /// check-by-check evaluation, use `trust_level_transition`.
    #[must_use]
    pub fn quarantine_threshold(score: u8) -> TrustLevel {
        if score < 50 {
            TrustLevel::Quarantined
        } else if score < 75 {
            TrustLevel::ConditionalTrust
        } else {
            TrustLevel::Trusted
        }
    }

    /// Update a host's posture, detect drift, and emit evidence.
    ///
    /// Returns the new trust level and any evidence records generated.
    /// This is the primary entry point for feeding new posture data into
    /// the engine.
    pub fn update_posture(
        &mut self,
        posture: ZeroTrustPosture,
    ) -> (TrustLevel, Vec<ZeroTrustEvidence>) {
        let host_id = posture.host_id.clone();
        let mut evidence_records = Vec::new();

        let previous_level = self
            .posture_state
            .get(&host_id)
            .map(|p| p.overall_trust_level)
            .unwrap_or(TrustLevel::Untrusted);

        let drift = self
            .posture_state
            .get(&host_id)
            .and_then(|prev| PostureDrift::detect(prev, &posture));

        let new_level = self
            .policy
            .compute_trust_level(&posture.per_check_results);
        let score = posture.aggregate_score();

        if let Some(d) = drift {
            evidence_records.push(ZeroTrustEvidence::drift_detected(
                &host_id,
                d.previous.overall_trust_level,
                d.resulting_level,
                d.current.aggregate_score(),
                format!(
                    "drift: {} -> {} (score: {:?} -> {:?})",
                    d.previous.overall_trust_level,
                    d.resulting_level,
                    d.previous.aggregate_score(),
                    d.current.aggregate_score(),
                ),
            ));
        }

        if new_level == TrustLevel::Quarantined && previous_level != TrustLevel::Quarantined {
            evidence_records.push(ZeroTrustEvidence::host_quarantined(
                &host_id,
                previous_level,
                score,
                format!(
                    "host quarantined: score {:?} below quarantine threshold {}",
                    score, self.policy.quarantine_threshold,
                ),
            ));
        }

        if new_level.allows_access() && previous_level.is_denied() {
            evidence_records.push(ZeroTrustEvidence::trust_restored(
                &host_id,
                previous_level,
                new_level,
                score,
                format!(
                    "trust restored: {} -> {} (score: {:?})",
                    previous_level, new_level, score,
                ),
            ));
        }

        evidence_records.push(ZeroTrustEvidence::posture_evaluated(
            &host_id,
            previous_level,
            new_level,
            score,
            format!("posture evaluated: {} -> {}", previous_level, new_level),
        ));

        let mut updated = posture;
        updated.overall_trust_level = new_level;
        updated.last_full_recheck = Some(Utc::now());
        self.set_posture(updated);

        (new_level, evidence_records)
    }

    /// Run the continuous re-evaluation loop.
    ///
    /// Re-evaluates every known host's posture on the policy's interval.
    /// Evidence events are sent on the provided channel. The loop runs
    /// until the receiver half of the channel is dropped.
    ///
    /// NIST 800-207: "continuous diagnostics and mitigation" — not a
    /// one-time handshake.
    pub async fn continuous_reevaluation(
        &mut self,
        tx: tokio::sync::mpsc::Sender<ZeroTrustEvidence>,
    ) {
        let interval_secs = self.policy.check_interval_seconds;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;

            let host_ids: Vec<String> =
                self.posture_state.keys().cloned().collect();

            for host_id in host_ids {
                let posture = match self.posture_state.get(&host_id) {
                    Some(p) => p.clone(),
                    None => continue,
                };

                if !posture.continuous_check_enabled {
                    continue;
                }

                let evaluated = self.evaluate_posture(&posture);
                let score = evaluated.aggregate_score();
                let previous_level = posture.overall_trust_level;
                let new_level = evaluated.overall_trust_level;

                let evidence = ZeroTrustEvidence::posture_evaluated(
                    &host_id,
                    previous_level,
                    new_level,
                    score,
                    format!(
                        "continuous re-evaluation: {} -> {} (score: {:?})",
                        previous_level, new_level, score,
                    ),
                );

                self.set_posture(evaluated);

                if tx.send(evidence).await.is_err() {
                    return;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// All known zero-trust checks — used by AirgapHigh and StigAligned profiles.
#[must_use]
fn all_checks() -> Vec<ZeroTrustCheck> {
    vec![
        ZeroTrustCheck::TpmAttestation,
        ZeroTrustCheck::SelinuxEnforcing,
        ZeroTrustCheck::ImaAppraisal,
        ZeroTrustCheck::DmVerityIntegrity,
        ZeroTrustCheck::ServiceHardeningScore,
        ZeroTrustCheck::FleetMembershipValid,
        ZeroTrustCheck::EvidenceChainConsistent,
        ZeroTrustCheck::NetworkPostureValid,
        ZeroTrustCheck::CryptoBoundaryIntact,
        ZeroTrustCheck::DataResidencyCompliant,
    ]
}

/// Mandatory checks for the SecureDefault profile.
#[must_use]
fn mandatory_for_secure() -> Vec<ZeroTrustCheck> {
    vec![
        ZeroTrustCheck::TpmAttestation,
        ZeroTrustCheck::SelinuxEnforcing,
        ZeroTrustCheck::EvidenceChainConsistent,
        ZeroTrustCheck::NetworkPostureValid,
        ZeroTrustCheck::CryptoBoundaryIntact,
    ]
}

/// Mandatory checks for the DevRelaxed profile.
#[must_use]
fn mandatory_for_dev() -> Vec<ZeroTrustCheck> {
    vec![
        ZeroTrustCheck::SelinuxEnforcing,
        ZeroTrustCheck::FleetMembershipValid,
    ]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn mk_host_id(n: u8) -> String {
        format!("host_zt_{n:02}")
    }

    fn mk_passing_result(check: ZeroTrustCheck) -> ZeroTrustCheckResult {
        ZeroTrustCheckResult::passed(check, format!("{check} passed"))
    }

    fn mk_failing_result(check: ZeroTrustCheck, score: u8) -> ZeroTrustCheckResult {
        ZeroTrustCheckResult::failed(check, score, format!("{check} failed"))
    }

    fn mk_posture(host_id: &str, results: Vec<ZeroTrustCheckResult>) -> ZeroTrustPosture {
        let mut posture = ZeroTrustPosture::new(host_id.to_string(), 3600);
        posture.per_check_results = results;
        posture
    }

    fn mk_engine_from_profile(profile: SecurityProfileLevel) -> ZeroTrustEngine {
        ZeroTrustEngine::new(ZeroTrustPolicy::for_profile(profile))
    }

    // ------------------------------------------------------------------
    // TrustLevel tests
    // ------------------------------------------------------------------

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::Trusted > TrustLevel::ConditionalTrust);
        assert!(TrustLevel::ConditionalTrust > TrustLevel::Untrusted);
        assert!(TrustLevel::Untrusted > TrustLevel::Quarantined);
        assert!(TrustLevel::Quarantined < TrustLevel::Trusted);
    }

    #[test]
    fn trust_level_allows_access() {
        assert!(TrustLevel::Trusted.allows_access());
        assert!(TrustLevel::ConditionalTrust.allows_access());
        assert!(!TrustLevel::Untrusted.allows_access());
        assert!(!TrustLevel::Quarantined.allows_access());
    }

    #[test]
    fn trust_level_is_denied() {
        assert!(TrustLevel::Untrusted.is_denied());
        assert!(TrustLevel::Quarantined.is_denied());
        assert!(!TrustLevel::Trusted.is_denied());
        assert!(!TrustLevel::ConditionalTrust.is_denied());
    }

    #[test]
    fn trust_level_display_matches_label() {
        for level in [
            TrustLevel::Trusted,
            TrustLevel::ConditionalTrust,
            TrustLevel::Untrusted,
            TrustLevel::Quarantined,
        ] {
            assert_eq!(level.to_string(), level.label());
        }
    }

    // ------------------------------------------------------------------
    // ZeroTrustCheck tests
    // ------------------------------------------------------------------

    #[test]
    fn zero_trust_check_label_is_stable() {
        assert_eq!(
            ZeroTrustCheck::TpmAttestation.label(),
            "TPM_ATTESTATION"
        );
        assert_eq!(
            ZeroTrustCheck::SelinuxEnforcing.label(),
            "SELINUX_ENFORCING"
        );
        assert_eq!(
            ZeroTrustCheck::ImaAppraisal.label(),
            "IMA_APPRAISAL"
        );
        assert_eq!(
            ZeroTrustCheck::DmVerityIntegrity.label(),
            "DM_VERITY_INTEGRITY"
        );
        assert_eq!(
            ZeroTrustCheck::CryptoBoundaryIntact.label(),
            "CRYPTO_BOUNDARY_INTACT"
        );
    }

    #[test]
    fn zero_trust_check_display_matches_label() {
        for check in [
            ZeroTrustCheck::TpmAttestation,
            ZeroTrustCheck::SelinuxEnforcing,
            ZeroTrustCheck::ImaAppraisal,
            ZeroTrustCheck::DmVerityIntegrity,
            ZeroTrustCheck::ServiceHardeningScore,
            ZeroTrustCheck::FleetMembershipValid,
            ZeroTrustCheck::EvidenceChainConsistent,
            ZeroTrustCheck::NetworkPostureValid,
            ZeroTrustCheck::CryptoBoundaryIntact,
            ZeroTrustCheck::DataResidencyCompliant,
        ] {
            assert_eq!(check.to_string(), check.label());
        }
    }

    // ------------------------------------------------------------------
    // ZeroTrustCheckResult tests
    // ------------------------------------------------------------------

    #[test]
    fn check_result_passed_has_score_100() {
        let result = ZeroTrustCheckResult::passed(
            ZeroTrustCheck::TpmAttestation,
            "all PCRs match".into(),
        );
        assert!(result.passed);
        assert_eq!(result.score, 100);
    }

    #[test]
    fn check_result_failed_clamps_score() {
        let result = ZeroTrustCheckResult::failed(
            ZeroTrustCheck::SelinuxEnforcing,
            100,
            "should clamp".into(),
        );
        assert!(!result.passed);
        assert_eq!(result.score, 99);
    }

    #[test]
    fn check_result_evidence_emitted_flag() {
        let mut result = ZeroTrustCheckResult::passed(
            ZeroTrustCheck::DmVerityIntegrity,
            "ok".into(),
        );
        assert!(!result.evidence_emitted);
        result.mark_evidence_emitted();
        assert!(result.evidence_emitted);
    }

    // ------------------------------------------------------------------
    // ZeroTrustPosture tests
    // ------------------------------------------------------------------

    #[test]
    fn posture_new_starts_untrusted() {
        let posture = ZeroTrustPosture::new(mk_host_id(1), 3600);
        assert_eq!(posture.overall_trust_level, TrustLevel::Untrusted);
        assert!(posture.continuous_check_enabled);
        assert!(posture.last_full_recheck.is_none());
        assert!(posture.per_check_results.is_empty());
    }

    #[test]
    fn posture_aggregate_score_empty_returns_none() {
        let posture = ZeroTrustPosture::new(mk_host_id(1), 3600);
        assert_eq!(posture.aggregate_score(), None);
    }

    #[test]
    fn posture_aggregate_score_all_100() {
        let results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_passing_result(ZeroTrustCheck::SelinuxEnforcing),
            mk_passing_result(ZeroTrustCheck::CryptoBoundaryIntact),
        ];
        let posture = mk_posture(&mk_host_id(1), results);
        assert_eq!(posture.aggregate_score(), Some(100));
    }

    #[test]
    fn posture_aggregate_score_mixed() {
        let results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_failing_result(ZeroTrustCheck::SelinuxEnforcing, 40),
            mk_passing_result(ZeroTrustCheck::CryptoBoundaryIntact),
        ];
        let posture = mk_posture(&mk_host_id(1), results);
        let score = posture.aggregate_score();
        assert!(score.is_some());
        // (100 + 40 + 100) / 3 = 80
        assert_eq!(score, Some(80));
    }

    #[test]
    fn posture_all_mandatory_passed_true() {
        let results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_passing_result(ZeroTrustCheck::SelinuxEnforcing),
        ];
        let posture = mk_posture(&mk_host_id(1), results);
        assert!(posture.all_mandatory_passed(&[
            ZeroTrustCheck::TpmAttestation,
            ZeroTrustCheck::SelinuxEnforcing,
        ]));
    }

    #[test]
    fn posture_all_mandatory_passed_false_when_missing() {
        let results = vec![mk_passing_result(ZeroTrustCheck::TpmAttestation)];
        let posture = mk_posture(&mk_host_id(1), results);
        assert!(!posture.all_mandatory_passed(&[
            ZeroTrustCheck::TpmAttestation,
            ZeroTrustCheck::CryptoBoundaryIntact,
        ]));
    }

    // ------------------------------------------------------------------
    // PostureDrift tests
    // ------------------------------------------------------------------

    #[test]
    fn posture_drift_detected_on_score_degradation() {
        let prev_results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_passing_result(ZeroTrustCheck::SelinuxEnforcing),
        ];
        let prev = mk_posture(&mk_host_id(1), prev_results);

        let curr_results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_failing_result(ZeroTrustCheck::SelinuxEnforcing, 40),
        ];
        let curr = mk_posture(&mk_host_id(1), curr_results);

        let drift = PostureDrift::detect(&prev, &curr);
        assert!(drift.is_some());
    }

    #[test]
    fn posture_drift_not_detected_when_stable() {
        let results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_passing_result(ZeroTrustCheck::SelinuxEnforcing),
        ];
        let prev = mk_posture(&mk_host_id(1), results.clone());
        let curr = mk_posture(&mk_host_id(1), results);

        let drift = PostureDrift::detect(&prev, &curr);
        assert!(drift.is_none());
    }

    #[test]
    fn posture_drift_not_detected_when_improved() {
        let prev_results = vec![
            mk_failing_result(ZeroTrustCheck::TpmAttestation, 50),
        ];
        let prev = mk_posture(&mk_host_id(1), prev_results);

        let curr_results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
        ];
        let curr = mk_posture(&mk_host_id(1), curr_results);

        let drift = PostureDrift::detect(&prev, &curr);
        assert!(drift.is_none());
    }

    // ------------------------------------------------------------------
    // ZeroTrustPolicy tests
    // ------------------------------------------------------------------

    #[test]
    fn policy_for_each_profile() {
        for profile in [
            SecurityProfileLevel::DevRelaxed,
            SecurityProfileLevel::SecureDefault,
            SecurityProfileLevel::StigAligned,
            SecurityProfileLevel::AirgapHigh,
        ] {
            let policy = ZeroTrustPolicy::for_profile(profile);
            assert_eq!(policy.profile, profile);
            assert!(policy.check_interval_seconds > 0);
            assert!(!policy.mandatory_checks.is_empty());
            assert!(policy.quarantine_threshold > 0);
            assert!(policy.conditional_trust_threshold > policy.quarantine_threshold);
        }
    }

    #[test]
    fn policy_compute_trust_level_empty_results() {
        let policy = ZeroTrustPolicy::secure_default();
        assert_eq!(
            policy.compute_trust_level(&[]),
            TrustLevel::Untrusted
        );
    }

    #[test]
    fn policy_compute_trust_level_quarantined() {
        let policy = ZeroTrustPolicy::secure_default();
        let results = vec![mk_failing_result(ZeroTrustCheck::TpmAttestation, 30)];
        assert_eq!(
            policy.compute_trust_level(&results),
            TrustLevel::Quarantined
        );
    }

    #[test]
    fn policy_compute_trust_level_conditional() {
        let policy = ZeroTrustPolicy::secure_default();
        let results = vec![
            mk_failing_result(ZeroTrustCheck::TpmAttestation, 60),
            mk_failing_result(ZeroTrustCheck::SelinuxEnforcing, 60),
        ];
        assert_eq!(
            policy.compute_trust_level(&results),
            TrustLevel::ConditionalTrust
        );
    }

    #[test]
    fn policy_compute_trust_level_trusted() {
        let policy = ZeroTrustPolicy::secure_default();
        let results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_passing_result(ZeroTrustCheck::SelinuxEnforcing),
            mk_passing_result(ZeroTrustCheck::EvidenceChainConsistent),
            mk_passing_result(ZeroTrustCheck::NetworkPostureValid),
            mk_passing_result(ZeroTrustCheck::CryptoBoundaryIntact),
        ];
        assert_eq!(
            policy.compute_trust_level(&results),
            TrustLevel::Trusted
        );
    }

    #[test]
    fn policy_dev_relaxed_lower_thresholds() {
        let policy = ZeroTrustPolicy::dev_relaxed();
        assert_eq!(policy.quarantine_threshold, 40);
        assert_eq!(policy.conditional_trust_threshold, 60);
        // Score 50 should be ConditionalTrust (>= 40, < 60)
        let results = vec![mk_failing_result(ZeroTrustCheck::SelinuxEnforcing, 50)];
        assert_eq!(
            policy.compute_trust_level(&results),
            TrustLevel::ConditionalTrust
        );
    }

    // ------------------------------------------------------------------
    // ZeroTrustEvidence tests
    // ------------------------------------------------------------------

    #[test]
    fn evidence_posture_evaluated() {
        let ev = ZeroTrustEvidence::posture_evaluated(
            &mk_host_id(1),
            TrustLevel::Untrusted,
            TrustLevel::Trusted,
            Some(100),
            "evaluated ok".into(),
        );
        assert_eq!(ev.kind, ZeroTrustEvidenceKind::ZeroTrustPostureEvaluated);
        assert_eq!(ev.previous_level, Some(TrustLevel::Untrusted));
        assert_eq!(ev.new_level, TrustLevel::Trusted);
        assert_eq!(ev.aggregate_score, Some(100));
    }

    #[test]
    fn evidence_host_quarantined() {
        let ev = ZeroTrustEvidence::host_quarantined(
            &mk_host_id(1),
            TrustLevel::Trusted,
            Some(30),
            "score too low".into(),
        );
        assert_eq!(ev.kind, ZeroTrustEvidenceKind::HostQuarantined);
        assert_eq!(ev.new_level, TrustLevel::Quarantined);
        assert_eq!(ev.previous_level, Some(TrustLevel::Trusted));
    }

    #[test]
    fn evidence_trust_restored() {
        let ev = ZeroTrustEvidence::trust_restored(
            &mk_host_id(1),
            TrustLevel::Quarantined,
            TrustLevel::Trusted,
            Some(90),
            "trust restored".into(),
        );
        assert_eq!(ev.kind, ZeroTrustEvidenceKind::HostTrustRestored);
        assert_eq!(ev.new_level, TrustLevel::Trusted);
    }

    #[test]
    fn evidence_drift_detected() {
        let ev = ZeroTrustEvidence::drift_detected(
            &mk_host_id(1),
            TrustLevel::Trusted,
            TrustLevel::ConditionalTrust,
            Some(65),
            "drift".into(),
        );
        assert_eq!(ev.kind, ZeroTrustEvidenceKind::PostureDriftDetected);
        assert_eq!(ev.previous_level, Some(TrustLevel::Trusted));
        assert_eq!(ev.new_level, TrustLevel::ConditionalTrust);
    }

    // ------------------------------------------------------------------
    // ZeroTrustEngine tests
    // ------------------------------------------------------------------

    #[test]
    fn engine_evaluate_posture_updates_recheck_timestamp() {
        let engine = mk_engine_from_profile(SecurityProfileLevel::SecureDefault);
        let posture = ZeroTrustPosture::new(mk_host_id(1), 3600);
        assert!(posture.last_full_recheck.is_none());

        let evaluated = engine.evaluate_posture(&posture);
        assert!(evaluated.last_full_recheck.is_some());
    }

    #[test]
    fn engine_trust_level_transition_from_empty() {
        let engine = mk_engine_from_profile(SecurityProfileLevel::SecureDefault);
        let result = engine.trust_level_transition(TrustLevel::Untrusted, &[]);
        // Empty results keep the current level
        assert_eq!(result, TrustLevel::Untrusted);
    }

    #[test]
    fn engine_trust_level_transition_to_trusted() {
        let engine = mk_engine_from_profile(SecurityProfileLevel::SecureDefault);
        let results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_passing_result(ZeroTrustCheck::SelinuxEnforcing),
            mk_passing_result(ZeroTrustCheck::EvidenceChainConsistent),
            mk_passing_result(ZeroTrustCheck::NetworkPostureValid),
            mk_passing_result(ZeroTrustCheck::CryptoBoundaryIntact),
        ];
        let result = engine.trust_level_transition(TrustLevel::Untrusted, &results);
        assert_eq!(result, TrustLevel::Trusted);
    }

    #[test]
    fn engine_quarantine_threshold_below_50() {
        assert_eq!(
            ZeroTrustEngine::quarantine_threshold(30),
            TrustLevel::Quarantined
        );
    }

    #[test]
    fn engine_quarantine_threshold_between_50_and_74() {
        assert_eq!(
            ZeroTrustEngine::quarantine_threshold(60),
            TrustLevel::ConditionalTrust
        );
    }

    #[test]
    fn engine_quarantine_threshold_75_and_above() {
        assert_eq!(
            ZeroTrustEngine::quarantine_threshold(80),
            TrustLevel::Trusted
        );
    }

    #[test]
    fn engine_update_posture_produces_evidence() {
        let mut engine = mk_engine_from_profile(SecurityProfileLevel::SecureDefault);
        let results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_passing_result(ZeroTrustCheck::SelinuxEnforcing),
            mk_passing_result(ZeroTrustCheck::EvidenceChainConsistent),
            mk_passing_result(ZeroTrustCheck::NetworkPostureValid),
            mk_passing_result(ZeroTrustCheck::CryptoBoundaryIntact),
        ];
        let posture = mk_posture(&mk_host_id(1), results);
        let (level, evidence) = engine.update_posture(posture);

        assert_eq!(level, TrustLevel::Trusted);
        assert!(!evidence.is_empty());
        assert!(evidence.iter().any(
            |e| e.kind == ZeroTrustEvidenceKind::ZeroTrustPostureEvaluated
        ));
        // From Untrusted to Trusted should trigger trust_restored
        assert!(evidence.iter().any(
            |e| e.kind == ZeroTrustEvidenceKind::HostTrustRestored
        ));
    }

    #[test]
    fn engine_update_posture_quarantine_evidence() {
        let mut engine = mk_engine_from_profile(SecurityProfileLevel::SecureDefault);

        // First: establish a trusted posture
        let good_results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_passing_result(ZeroTrustCheck::SelinuxEnforcing),
            mk_passing_result(ZeroTrustCheck::EvidenceChainConsistent),
            mk_passing_result(ZeroTrustCheck::NetworkPostureValid),
            mk_passing_result(ZeroTrustCheck::CryptoBoundaryIntact),
        ];
        let posture = mk_posture(&mk_host_id(1), good_results);
        engine.update_posture(posture);

        // Then: update with failing results to trigger quarantine
        let bad_results = vec![
            mk_failing_result(ZeroTrustCheck::TpmAttestation, 20),
            mk_failing_result(ZeroTrustCheck::SelinuxEnforcing, 30),
        ];
        let posture = mk_posture(&mk_host_id(1), bad_results);
        let (_level, evidence) = engine.update_posture(posture);

        assert!(evidence.iter().any(
            |e| e.kind == ZeroTrustEvidenceKind::HostQuarantined
        ));
        assert!(evidence.iter().any(
            |e| e.kind == ZeroTrustEvidenceKind::PostureDriftDetected
        ));
    }

    #[test]
    fn engine_get_posture_after_update() {
        let mut engine = mk_engine_from_profile(SecurityProfileLevel::SecureDefault);
        let results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_passing_result(ZeroTrustCheck::SelinuxEnforcing),
            mk_passing_result(ZeroTrustCheck::EvidenceChainConsistent),
            mk_passing_result(ZeroTrustCheck::NetworkPostureValid),
            mk_passing_result(ZeroTrustCheck::CryptoBoundaryIntact),
        ];
        let posture = mk_posture(&mk_host_id(1), results);
        engine.update_posture(posture);

        let stored = engine.get_posture(&mk_host_id(1));
        assert!(stored.is_some());
        assert_eq!(
            stored.unwrap().overall_trust_level,
            TrustLevel::Trusted
        );
    }

    #[test]
    fn engine_known_hosts() {
        let mut engine = mk_engine_from_profile(SecurityProfileLevel::SecureDefault);
        engine.set_posture(ZeroTrustPosture::new(mk_host_id(1), 3600));
        engine.set_posture(ZeroTrustPosture::new(mk_host_id(2), 3600));

        let hosts = engine.known_hosts();
        assert_eq!(hosts.len(), 2);
    }

    // ------------------------------------------------------------------
    // Serde round-trip tests
    // ------------------------------------------------------------------

    #[test]
    fn zero_trust_check_serde_round_trip() {
        for check in [
            ZeroTrustCheck::TpmAttestation,
            ZeroTrustCheck::SelinuxEnforcing,
            ZeroTrustCheck::CryptoBoundaryIntact,
        ] {
            let json = serde_json::to_string(&check).unwrap();
            let back: ZeroTrustCheck = serde_json::from_str(&json).unwrap();
            assert_eq!(check, back);
        }
    }

    #[test]
    fn trust_level_serde_round_trip() {
        for level in [
            TrustLevel::Trusted,
            TrustLevel::ConditionalTrust,
            TrustLevel::Untrusted,
            TrustLevel::Quarantined,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: TrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    #[test]
    fn evidence_kind_serde_screaming_snake() {
        let json = serde_json::to_string(&ZeroTrustEvidenceKind::HostQuarantined).unwrap();
        assert_eq!(json, "\"HOST_QUARANTINED\"");
    }

    #[test]
    fn zero_trust_posture_serde_round_trip() {
        let results = vec![
            mk_passing_result(ZeroTrustCheck::TpmAttestation),
            mk_passing_result(ZeroTrustCheck::SelinuxEnforcing),
        ];
        let mut posture = mk_posture(&mk_host_id(1), results);
        posture.overall_trust_level = TrustLevel::Trusted;
        posture.last_full_recheck = Some(Utc::now());

        let json = serde_json::to_string(&posture).unwrap();
        let back: ZeroTrustPosture = serde_json::from_str(&json).unwrap();
        assert_eq!(back.host_id, posture.host_id);
        assert_eq!(back.overall_trust_level, TrustLevel::Trusted);
        assert_eq!(back.per_check_results.len(), 2);
    }
}
