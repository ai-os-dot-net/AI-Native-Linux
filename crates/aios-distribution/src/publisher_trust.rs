//! Publisher trust chain: reputation scoring, audit trails, key rotation,
//! and per-tier trust policies per S11.1 §4.
//!
//! # Architecture
//!
//! - [`TrustTier`] — closed five-tier enum computed from reputation score,
//!   never self-assignable.  The [`Compromised`](TrustTier::Compromised)
//!   variant is set via [`ReputationEvent::SecurityIncidentReported`] and
//!   locks the publisher until a [`ReputationEvent::ManualOverride`] restores it.
//! - [`ReputationEvent`] — events that feed into [`ReputationEngine`].
//! - [`PublisherReputation`] — computed snapshot of a publisher's standing.
//! - [`ReputationEngine`] — event-driven scoring with audit trails.
//! - [`PublisherAuditTrail`] — tamper-evident event log per publisher.
//! - [`SigningKeyRotation`] — publisher signing key rotation record.
//! - [`PublisherTrustPolicy`] — per-tier capability matrix.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

use crate::ids::{PackageSigningKeyId, PublisherId, PublisherRootId};

// ---------------------------------------------------------------------------
// TrustTier — closed five-tier enum, computed from reputation score
// ---------------------------------------------------------------------------

/// Publisher trust tier computed from reputation score.
///
/// # Ordering
///
/// The `PartialOrd` derive produces the order:
/// `Compromised < Unvetted < CommunityTrusted < AiosVerified < AiosCore`.
///
/// # Assignment
///
/// | Score range | Tier               |
/// |-------------|--------------------|
/// | 0–30        | `Unvetted`         |
/// | 31–60       | `CommunityTrusted`  |
/// | 61–85       | `AiosVerified`      |
/// | 86–100      | `AiosCore`          |
///
/// `Compromised` is NOT score-derived — it is set only via
/// [`ReputationEvent::SecurityIncidentReported`] and cleared via
/// [`ReputationEvent::ManualOverride`].
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustTier {
    Compromised,
    Unvetted,
    CommunityTrusted,
    AiosVerified,
    AiosCore,
}

impl TrustTier {
    /// Maps a reputation score (0–100) to a [`TrustTier`].
    ///
    /// Scores outside 0–100 are clamped.  Returns `Unvetted` for
    /// the range 0–30 inclusive, `CommunityTrusted` for 31–60,
    /// `AiosVerified` for 61–85, and `AiosCore` for 86–100.
    #[must_use]
    pub fn from_reputation_score(score: u8) -> Self {
        match score {
            0..=30 => Self::Unvetted,
            31..=60 => Self::CommunityTrusted,
            61..=85 => Self::AiosVerified,
            86..=100 | 101..=u8::MAX => Self::AiosCore,
        }
    }

    /// Returns the minimum score required for this tier.
    #[must_use]
    pub const fn min_score(self) -> u8 {
        match self {
            Self::Compromised => 0,
            Self::Unvetted => 0,
            Self::CommunityTrusted => 31,
            Self::AiosVerified => 61,
            Self::AiosCore => 86,
        }
    }

    /// Returns `true` if publishers at this tier may publish new packages.
    #[must_use]
    pub const fn can_publish(self) -> bool {
        matches!(
            self,
            Self::Unvetted | Self::CommunityTrusted | Self::AiosVerified | Self::AiosCore
        )
    }

    /// Returns `true` if packages from publishers at this tier require
    /// mandatory review before release.
    #[must_use]
    pub const fn requires_review(self) -> bool {
        matches!(self, Self::Unvetted | Self::CommunityTrusted)
    }
}

// ---------------------------------------------------------------------------
// ReputationEvent — events that modify a publisher's reputation
// ---------------------------------------------------------------------------

/// A reputation-modifying event that feeds into the [`ReputationEngine`].
///
/// Each variant carries a numeric score delta returned by
/// [`score_delta`](Self::score_delta).  `ManualOverride` and `TierChanged`
/// return a delta of 0 but have side effects handled by the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReputationEvent {
    /// A new package was published by the publisher.  +2 score.
    PackagePublished {
        package_id: String,
        occurred_at: Option<DateTime<Utc>>,
    },
    /// A published package was flagged for review.  -10 score.
    PackageFlagged {
        package_id: String,
        reason: String,
        occurred_at: Option<DateTime<Utc>>,
    },
    /// A package was formally revoked.  -20 score.
    PackageRevoked {
        package_id: String,
        reason: String,
        occurred_at: Option<DateTime<Utc>>,
    },
    /// A security incident was reported against this publisher.  -30 score,
    /// and the publisher's tier may be set to `Compromised`.
    SecurityIncidentReported {
        incident_id: String,
        severity: String,
        description: String,
        occurred_at: Option<DateTime<Utc>>,
    },
    /// A community or AIOS review was received.  Score delta depends on the
    /// numeric score (1–5): `(score - 3) * 5`, ranging -10 to +10.
    ReviewReceived {
        review_id: String,
        score: u8,
        occurred_at: Option<DateTime<Utc>>,
    },
    /// An AIOS administrator manually overrode a publisher's score.
    /// Delta is 0; the engine sets the score directly.
    ManualOverride {
        new_score: u8,
        override_reason: String,
        override_by: String,
        occurred_at: Option<DateTime<Utc>>,
    },
    /// A tier change was recorded (informational — does not affect score).
    TierChanged {
        from: TrustTier,
        to: TrustTier,
        reason: String,
        occurred_at: Option<DateTime<Utc>>,
    },
}

impl ReputationEvent {
    /// Returns the score delta for this event.
    ///
    /// - `PackagePublished` → +2
    /// - `PackageFlagged` → -10
    /// - `PackageRevoked` → -20
    /// - `SecurityIncidentReported` → -30
    /// - `ReviewReceived` → `(score - 3) * 5` (range -10 to +10)
    /// - `ManualOverride` → 0 (score is set directly by the engine)
    /// - `TierChanged` → 0 (informational)
    #[must_use]
    pub fn score_delta(&self) -> i16 {
        match self {
            Self::PackagePublished { .. } => 2,
            Self::PackageFlagged { .. } => -10,
            Self::PackageRevoked { .. } => -20,
            Self::SecurityIncidentReported { .. } => -30,
            Self::ReviewReceived { score, .. } => (*score as i16 - 3) * 5,
            Self::ManualOverride { .. } => 0,
            Self::TierChanged { .. } => 0,
        }
    }

    /// Returns the timestamp carried by this event, if any.
    #[must_use]
    pub fn occurred_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::PackagePublished { occurred_at, .. }
            | Self::PackageFlagged { occurred_at, .. }
            | Self::PackageRevoked { occurred_at, .. }
            | Self::SecurityIncidentReported { occurred_at, .. }
            | Self::ReviewReceived { occurred_at, .. }
            | Self::ManualOverride { occurred_at, .. }
            | Self::TierChanged { occurred_at, .. } => *occurred_at,
        }
    }
}

// ---------------------------------------------------------------------------
// PublisherReputation
// ---------------------------------------------------------------------------

/// A computed snapshot of a publisher's reputation standing.
///
/// This struct is the output of the [`ReputationEngine`]; it is updated
/// after every event recorded via [`ReputationEngine::record_event`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherReputation {
    /// The publisher identifier.
    pub publisher_id: PublisherId,
    /// Current reputation score (0–100).
    pub reputation_score: u8,
    /// Total number of packages ever published.
    pub total_published: u64,
    /// Number of packages currently active (not flagged/revoked).
    pub total_active: u64,
    /// Number of packages flagged for review.
    pub flagged_count: u64,
    /// Number of packages formally revoked.
    pub revoked_count: u64,
    /// Total reviews received (count).
    pub reviews_received: u64,
    /// Rolling average review score (0.0–5.0).
    pub avg_review_score: f64,
    /// Timestamp of the last security incident, if any.
    pub last_security_incident: Option<DateTime<Utc>>,
    /// Current trust tier, computed from `reputation_score`.
    pub trust_tier: TrustTier,
}

impl PublisherReputation {
    /// Creates a fresh reputation record for the given publisher.
    ///
    /// The initial score is 50 (`CommunityTrusted` tier), representing
    /// a neutral starting point before any events are recorded.
    #[must_use]
    pub fn new(publisher_id: PublisherId) -> Self {
        Self {
            publisher_id,
            reputation_score: 50,
            total_published: 0,
            total_active: 0,
            flagged_count: 0,
            revoked_count: 0,
            reviews_received: 0,
            avg_review_score: 0.0,
            last_security_incident: None,
            trust_tier: TrustTier::from_reputation_score(50),
        }
    }

    /// Recomputes `trust_tier` from the current `reputation_score`.
    fn recompute_tier(&mut self) {
        self.trust_tier = TrustTier::from_reputation_score(self.reputation_score);
    }
}

// ---------------------------------------------------------------------------
// PublisherAuditTrail
// ---------------------------------------------------------------------------

/// A single entry in a publisher's audit trail, recording the event,
/// timestamp, and score transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// The event that was recorded.
    pub event: ReputationEvent,
    /// When the event was recorded (uses `event.occurred_at` or record time).
    pub timestamp: DateTime<Utc>,
    /// The publisher's score immediately before this event.
    pub score_before: u8,
    /// The publisher's score immediately after this event.
    pub score_after: u8,
}

/// A tamper-evident audit trail for a single publisher.
///
/// Every [`ReputationEvent`] recorded via [`ReputationEngine::record_event`]
/// appends an [`AuditEntry`] here.  External verifiers can replay the trail
/// to recompute the publisher's current score independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherAuditTrail {
    /// The publisher this trail belongs to.
    pub publisher_id: PublisherId,
    /// Ordered list of events with their score transitions.
    pub events: Vec<AuditEntry>,
    /// Optional evidence hashes (BLAKE3) linked to each event.
    pub evidence_hashes: Vec<String>,
}

impl PublisherAuditTrail {
    /// Creates an empty audit trail for the given publisher.
    #[must_use]
    pub fn new(publisher_id: PublisherId) -> Self {
        Self {
            publisher_id,
            events: Vec::new(),
            evidence_hashes: Vec::new(),
        }
    }

    /// Appends an event to the audit trail.
    pub fn record(&mut self, event: ReputationEvent, score_before: u8, score_after: u8) {
        let timestamp = match event.occurred_at() {
            Some(ts) => ts,
            None => Utc::now(),
        };
        self.events.push(AuditEntry {
            event,
            timestamp,
            score_before,
            score_after,
        });
    }

    /// Returns the total number of events in the trail.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if the trail has no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SigningKeyRotation
// ---------------------------------------------------------------------------

/// A publisher signing key rotation record per S11.1 §11.
///
/// Records the handover from an old signing key to a new one, with the
/// old key signing the rotation event for chain continuity.  The
/// `rotation_index` is a monotonically-increasing counter so that
/// verifiers can detect gaps or replays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKeyRotation {
    /// The publisher performing the rotation.
    pub publisher_id: PublisherId,
    /// The publisher root whose key is being rotated.
    pub publisher_root_id: PublisherRootId,
    /// Reference to the old signing key being rotated out.
    pub old_key_ref: PackageSigningKeyId,
    /// Reference to the new signing key being rotated in.
    pub new_key_ref: PackageSigningKeyId,
    /// Ed25519 signature by the old key over the canonical rotation bytes
    /// (chain continuity proof).
    pub rotation_signed_by_old_key: Vec<u8>,
    /// Monotonically-increasing rotation counter.
    pub rotation_index: u64,
    /// When the rotation becomes effective.
    pub effective_at: DateTime<Utc>,
    /// Optional pointer to evidence backing the rotation.
    pub evidence: Option<String>,
}

// ---------------------------------------------------------------------------
// PublisherTrustPolicy — per-tier capability matrix
// ---------------------------------------------------------------------------

/// Per-tier capability policy defining what each [`TrustTier`] may do.
///
/// These policies are consulted before admitting a new package, upgrading
/// a publisher's tier, or triggering an auto-revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherTrustPolicy {
    /// The trust tier this policy applies to.
    pub tier: TrustTier,
    /// Maximum number of concurrently active packages.
    pub max_packages_active: u64,
    /// Minimum number of positive reviews required before tier upgrade
    /// is permitted.
    pub min_review_count_before_upgrade: u64,
    /// Number of revocations within a rolling window that trigger
    /// an automatic tier downgrade.
    pub revocation_threshold: u64,
    /// Whether this tier can publish to the community repository.
    pub can_publish_to_community_repo: bool,
    /// Whether this tier can publish to the verified repository.
    pub can_publish_to_verified_repo: bool,
}

impl PublisherTrustPolicy {
    /// Returns the canonical policy for the given tier.
    ///
    /// | Tier               | Max active | Min reviews | Revoke threshold | Community | Verified |
    /// |--------------------|------------|-------------|-------------------|-----------|----------|
    /// | `Unvetted`         | 10         | 3           | 3                 | false     | false    |
    /// | `CommunityTrusted` | 100        | 10          | 5                 | true      | false    |
    /// | `AiosVerified`     | 1 000      | 50          | 10                | true      | true     |
    /// | `AiosCore`         | unlimited  | 0           | n/a               | true      | true     |
    /// | `Compromised`      | 0          | n/a         | 0                 | false     | false    |
    #[must_use]
    pub fn for_tier(tier: TrustTier) -> Self {
        match tier {
            TrustTier::Unvetted => Self {
                tier,
                max_packages_active: 10,
                min_review_count_before_upgrade: 3,
                revocation_threshold: 3,
                can_publish_to_community_repo: false,
                can_publish_to_verified_repo: false,
            },
            TrustTier::CommunityTrusted => Self {
                tier,
                max_packages_active: 100,
                min_review_count_before_upgrade: 10,
                revocation_threshold: 5,
                can_publish_to_community_repo: true,
                can_publish_to_verified_repo: false,
            },
            TrustTier::AiosVerified => Self {
                tier,
                max_packages_active: 1_000,
                min_review_count_before_upgrade: 50,
                revocation_threshold: 10,
                can_publish_to_community_repo: true,
                can_publish_to_verified_repo: true,
            },
            TrustTier::AiosCore => Self {
                tier,
                max_packages_active: u64::MAX,
                min_review_count_before_upgrade: 0,
                revocation_threshold: u64::MAX,
                can_publish_to_community_repo: true,
                can_publish_to_verified_repo: true,
            },
            TrustTier::Compromised => Self {
                tier,
                max_packages_active: 0,
                min_review_count_before_upgrade: u64::MAX,
                revocation_threshold: 0,
                can_publish_to_community_repo: false,
                can_publish_to_verified_repo: false,
            },
        }
    }

    /// Returns `true` if the publisher has exceeded their active package cap.
    #[must_use]
    pub fn exceeds_active_cap(&self, current_active: u64) -> bool {
        current_active > self.max_packages_active
    }

    /// Returns `true` if the publisher has enough reviews to be considered
    /// for tier upgrade.
    #[must_use]
    pub fn has_enough_reviews_for_upgrade(&self, review_count: u64) -> bool {
        review_count >= self.min_review_count_before_upgrade
    }

    /// Returns `true` if the revocation count within the rolling window
    /// exceeds the threshold, triggering an auto-downgrade.
    #[must_use]
    pub fn exceeds_revocation_threshold(&self, recent_revocations: u64) -> bool {
        self.revocation_threshold > 0 && recent_revocations >= self.revocation_threshold
    }
}

// ---------------------------------------------------------------------------
// ReputationEngine
// ---------------------------------------------------------------------------

/// An event-driven reputation engine that tracks and scores publishers.
///
/// # Usage
///
/// ```ignore
/// let mut engine = ReputationEngine::new();
/// engine.record_event(&publisher_id, ReputationEvent::PackagePublished {
///     package_id: "pkg:a:b".into(),
///     occurred_at: None,
/// })?;
/// let score = engine.calculate_score(&publisher_id);
/// ```
pub struct ReputationEngine {
    reputations: HashMap<PublisherId, PublisherReputation>,
    audit_trails: HashMap<PublisherId, PublisherAuditTrail>,
}

impl ReputationEngine {
    /// Creates a new, empty reputation engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reputations: HashMap::new(),
            audit_trails: HashMap::new(),
        }
    }

    /// Records a reputation event for the given publisher, updating their
    /// score, counters, and audit trail.
    ///
    /// If the publisher does not yet have a reputation record, one is
    /// created automatically with a starting score of 50.
    ///
    /// # Side effects
    ///
    /// - `PackagePublished` increments `total_published` and `total_active`.
    /// - `PackageFlagged` decrements `total_active`, increments `flagged_count`.
    /// - `PackageRevoked` decrements `total_active`, increments `revoked_count`.
    /// - `SecurityIncidentReported` sets `last_security_incident` and may set
    ///   the tier to `Compromised`.
    /// - `ReviewReceived` updates the rolling average review score.
    /// - `ManualOverride` sets the score directly, bypassing deltas.
    /// - `TierChanged` is recorded in the audit trail but does not affect the
    ///   score or counters.
    pub fn record_event(&mut self, publisher_id: &PublisherId, event: ReputationEvent) {
        let reputation = self
            .reputations
            .entry(publisher_id.clone())
            .or_insert_with(|| PublisherReputation::new(publisher_id.clone()));

        let score_before = reputation.reputation_score;

        // Apply counter side effects
        match &event {
            ReputationEvent::PackagePublished { .. } => {
                reputation.total_published = reputation.total_published.saturating_add(1);
                reputation.total_active = reputation.total_active.saturating_add(1);
            }
            ReputationEvent::PackageFlagged { .. } => {
                reputation.flagged_count = reputation.flagged_count.saturating_add(1);
                reputation.total_active = reputation.total_active.saturating_sub(1);
            }
            ReputationEvent::PackageRevoked { .. } => {
                reputation.revoked_count = reputation.revoked_count.saturating_add(1);
                reputation.total_active = reputation.total_active.saturating_sub(1);
            }
            ReputationEvent::SecurityIncidentReported { occurred_at, .. } => {
                reputation.last_security_incident = match occurred_at {
                    Some(ts) => Some(*ts),
                    None => Some(Utc::now()),
                };
                reputation.trust_tier = TrustTier::Compromised;
            }
            ReputationEvent::ReviewReceived { score, .. } => {
                let score_f = f64::from(*score);
                if reputation.reviews_received == 0 {
                    reputation.avg_review_score = score_f;
                } else {
                    reputation.avg_review_score = (reputation.avg_review_score
                        * reputation.reviews_received as f64
                        + score_f)
                        / (reputation.reviews_received + 1) as f64;
                }
                reputation.reviews_received = reputation.reviews_received.saturating_add(1);
            }
            ReputationEvent::ManualOverride { new_score, .. } => {
                reputation.reputation_score = *new_score;
                reputation.recompute_tier();

                let score_after = *new_score;
                let audit = self
                    .audit_trails
                    .entry(publisher_id.clone())
                    .or_insert_with(|| PublisherAuditTrail::new(publisher_id.clone()));
                audit.record(event, score_before, score_after);
                return;
            }
            ReputationEvent::TierChanged { .. } => {
                // Informational only — no score or counter change
            }
        }

        // Apply score delta
        let delta = event.score_delta();
        let raw = i16::from(reputation.reputation_score).saturating_add(delta);
        reputation.reputation_score = raw.clamp(0, 100) as u8;

        // If the tier was force-set to Compromised by a security incident,
        // skip recompute so the Compromised tier persists.
        if !matches!(event, ReputationEvent::SecurityIncidentReported { .. }) {
            reputation.recompute_tier();
        }

        let score_after = reputation.reputation_score;

        let audit = self
            .audit_trails
            .entry(publisher_id.clone())
            .or_insert_with(|| PublisherAuditTrail::new(publisher_id.clone()));
        audit.record(event, score_before, score_after);
    }

    /// Returns the current reputation score for a publisher, or `None` if
    /// no events have been recorded for them.
    #[must_use]
    pub fn calculate_score(&self, publisher_id: &PublisherId) -> Option<u8> {
        self.reputations
            .get(publisher_id)
            .map(|r| r.reputation_score)
    }

    /// Returns the current trust tier for a publisher, or `None` if
    /// no events have been recorded for them.
    #[must_use]
    pub fn get_trust_tier(&self, publisher_id: &PublisherId) -> Option<TrustTier> {
        self.reputations.get(publisher_id).map(|r| r.trust_tier)
    }

    /// Lists all publishers currently at the given trust tier.
    #[must_use]
    pub fn list_publishers_by_tier(&self, tier: TrustTier) -> Vec<&PublisherReputation> {
        self.reputations
            .values()
            .filter(|r| r.trust_tier == tier)
            .collect()
    }

    /// Returns the full audit trail for a publisher, or `None` if no
    /// events have been recorded.
    #[must_use]
    pub fn get_audit_trail(&self, publisher_id: &PublisherId) -> Option<&PublisherAuditTrail> {
        self.audit_trails.get(publisher_id)
    }

    /// Returns the full reputation record for a publisher, or `None` if
    /// no events have been recorded.
    #[must_use]
    pub fn get_reputation(&self, publisher_id: &PublisherId) -> Option<&PublisherReputation> {
        self.reputations.get(publisher_id)
    }

    /// Returns the total number of publishers being tracked.
    #[must_use]
    pub fn publisher_count(&self) -> usize {
        self.reputations.len()
    }
}

impl Default for ReputationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::needless_collect,
    clippy::format_collect,
    clippy::too_many_arguments,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use strum::EnumCount;
    use strum::IntoEnumIterator;

    fn publisher_a() -> PublisherId {
        PublisherId("pub:test-a".into())
    }

    fn publisher_b() -> PublisherId {
        PublisherId("pub:test-b".into())
    }

    // -----------------------------------------------------------------------
    // TrustTier tests
    // -----------------------------------------------------------------------

    #[test]
    fn tier_from_score_boundaries() {
        assert_eq!(TrustTier::from_reputation_score(0), TrustTier::Unvetted);
        assert_eq!(TrustTier::from_reputation_score(30), TrustTier::Unvetted);
        assert_eq!(
            TrustTier::from_reputation_score(31),
            TrustTier::CommunityTrusted
        );
        assert_eq!(
            TrustTier::from_reputation_score(60),
            TrustTier::CommunityTrusted
        );
        assert_eq!(
            TrustTier::from_reputation_score(61),
            TrustTier::AiosVerified
        );
        assert_eq!(
            TrustTier::from_reputation_score(85),
            TrustTier::AiosVerified
        );
        assert_eq!(TrustTier::from_reputation_score(86), TrustTier::AiosCore);
        assert_eq!(TrustTier::from_reputation_score(100), TrustTier::AiosCore);
    }

    #[test]
    fn tier_min_scores() {
        assert_eq!(TrustTier::Unvetted.min_score(), 0);
        assert_eq!(TrustTier::CommunityTrusted.min_score(), 31);
        assert_eq!(TrustTier::AiosVerified.min_score(), 61);
        assert_eq!(TrustTier::AiosCore.min_score(), 86);
        assert_eq!(TrustTier::Compromised.min_score(), 0);
    }

    #[test]
    fn tier_can_publish() {
        assert!(TrustTier::Unvetted.can_publish());
        assert!(TrustTier::CommunityTrusted.can_publish());
        assert!(TrustTier::AiosVerified.can_publish());
        assert!(TrustTier::AiosCore.can_publish());
        assert!(!TrustTier::Compromised.can_publish());
    }

    #[test]
    fn tier_requires_review() {
        assert!(TrustTier::Unvetted.requires_review());
        assert!(TrustTier::CommunityTrusted.requires_review());
        assert!(!TrustTier::AiosVerified.requires_review());
        assert!(!TrustTier::AiosCore.requires_review());
        assert!(!TrustTier::Compromised.requires_review());
    }

    #[test]
    fn tier_ordering() {
        assert!(TrustTier::AiosCore > TrustTier::AiosVerified);
        assert!(TrustTier::AiosVerified > TrustTier::CommunityTrusted);
        assert!(TrustTier::CommunityTrusted > TrustTier::Unvetted);
        assert!(TrustTier::Unvetted > TrustTier::Compromised);
    }

    #[test]
    fn tier_enum_iter_iterates_all() {
        let tiers: Vec<TrustTier> = <TrustTier as IntoEnumIterator>::iter().collect();
        assert_eq!(tiers.len(), 5);
        assert!(tiers.contains(&TrustTier::Compromised));
        assert!(tiers.contains(&TrustTier::Unvetted));
        assert!(tiers.contains(&TrustTier::CommunityTrusted));
        assert!(tiers.contains(&TrustTier::AiosVerified));
        assert!(tiers.contains(&TrustTier::AiosCore));
    }

    #[test]
    fn tier_enum_count_is_five() {
        assert_eq!(TrustTier::COUNT, 5);
    }

    // -----------------------------------------------------------------------
    // ReputationEvent tests
    // -----------------------------------------------------------------------

    #[test]
    fn event_score_deltas() {
        assert_eq!(
            ReputationEvent::PackagePublished {
                package_id: "pkg:a:test".into(),
                occurred_at: None
            }
            .score_delta(),
            2
        );
        assert_eq!(
            ReputationEvent::PackageFlagged {
                package_id: "pkg:a:test".into(),
                reason: "spam".into(),
                occurred_at: None
            }
            .score_delta(),
            -10
        );
        assert_eq!(
            ReputationEvent::PackageRevoked {
                package_id: "pkg:a:test".into(),
                reason: "malware".into(),
                occurred_at: None
            }
            .score_delta(),
            -20
        );
        assert_eq!(
            ReputationEvent::SecurityIncidentReported {
                incident_id: "inc-1".into(),
                severity: "critical".into(),
                description: "leak".into(),
                occurred_at: None
            }
            .score_delta(),
            -30
        );
        assert_eq!(
            ReputationEvent::ReviewReceived {
                review_id: "r-1".into(),
                score: 5,
                occurred_at: None
            }
            .score_delta(),
            10
        );
        assert_eq!(
            ReputationEvent::ReviewReceived {
                review_id: "r-2".into(),
                score: 1,
                occurred_at: None
            }
            .score_delta(),
            -10
        );
        assert_eq!(
            ReputationEvent::ReviewReceived {
                review_id: "r-3".into(),
                score: 3,
                occurred_at: None
            }
            .score_delta(),
            0
        );
        assert_eq!(
            ReputationEvent::ManualOverride {
                new_score: 90,
                override_reason: "restore".into(),
                override_by: "admin".into(),
                occurred_at: None
            }
            .score_delta(),
            0
        );
        assert_eq!(
            ReputationEvent::TierChanged {
                from: TrustTier::Unvetted,
                to: TrustTier::CommunityTrusted,
                reason: "upgrade".into(),
                occurred_at: None
            }
            .score_delta(),
            0
        );
    }

    // -----------------------------------------------------------------------
    // PublisherReputation tests
    // -----------------------------------------------------------------------

    #[test]
    fn new_reputation_starts_at_50() {
        let rep = PublisherReputation::new(publisher_a());
        assert_eq!(rep.reputation_score, 50);
        assert_eq!(rep.trust_tier, TrustTier::CommunityTrusted);
        assert_eq!(rep.total_published, 0);
        assert_eq!(rep.total_active, 0);
        assert_eq!(rep.flagged_count, 0);
        assert_eq!(rep.revoked_count, 0);
        assert_eq!(rep.reviews_received, 0);
        assert_eq!(rep.avg_review_score, 0.0);
        assert!(rep.last_security_incident.is_none());
    }

    // -----------------------------------------------------------------------
    // ReputationEngine tests
    // -----------------------------------------------------------------------

    #[test]
    fn engine_record_package_published() {
        let mut engine = ReputationEngine::new();
        let pid = publisher_a();
        engine.record_event(
            &pid,
            ReputationEvent::PackagePublished {
                package_id: "pkg:test-a:cli".into(),
                occurred_at: None,
            },
        );
        let score = engine.calculate_score(&pid).unwrap();
        assert_eq!(score, 52);
        let rep = engine.get_reputation(&pid).unwrap();
        assert_eq!(rep.total_published, 1);
        assert_eq!(rep.total_active, 1);
    }

    #[test]
    fn engine_record_multiple_events_stays_in_bounds() {
        let mut engine = ReputationEngine::new();
        let pid = publisher_a();

        // Push score to 0 with flagged events
        for i in 0..6 {
            engine.record_event(
                &pid,
                ReputationEvent::PackageFlagged {
                    package_id: format!("pkg:test-a:p{i}"),
                    reason: "test".into(),
                    occurred_at: None,
                },
            );
        }
        let score = engine.calculate_score(&pid).unwrap();
        assert_eq!(score, 0, "score must be clamped at 0");

        // Push score to 100 with published events
        let pid2 = publisher_b();
        for i in 0..30 {
            engine.record_event(
                &pid2,
                ReputationEvent::PackagePublished {
                    package_id: format!("pkg:test-b:p{i}"),
                    occurred_at: None,
                },
            );
        }
        let score2 = engine.calculate_score(&pid2).unwrap();
        assert_eq!(score2, 100, "score must be clamped at 100");
    }

    #[test]
    fn engine_security_incident_sets_compromised() {
        let mut engine = ReputationEngine::new();
        let pid = publisher_a();
        engine.record_event(
            &pid,
            ReputationEvent::SecurityIncidentReported {
                incident_id: "sec-1".into(),
                severity: "critical".into(),
                description: "key leaked".into(),
                occurred_at: None,
            },
        );
        let tier = engine.get_trust_tier(&pid).unwrap();
        assert_eq!(tier, TrustTier::Compromised);
        let rep = engine.get_reputation(&pid).unwrap();
        assert!(rep.last_security_incident.is_some());
        // Score drops by 30 from 50
        assert_eq!(rep.reputation_score, 20);
        // But tier is Compromised regardless of score
    }

    #[test]
    fn engine_manual_override_sets_score_directly() {
        let mut engine = ReputationEngine::new();
        let pid = publisher_a();
        engine.record_event(
            &pid,
            ReputationEvent::ManualOverride {
                new_score: 92,
                override_reason: "reinstatement".into(),
                override_by: "aios-admin".into(),
                occurred_at: None,
            },
        );
        let score = engine.calculate_score(&pid).unwrap();
        assert_eq!(score, 92);
        let tier = engine.get_trust_tier(&pid).unwrap();
        assert_eq!(tier, TrustTier::AiosCore);
    }

    #[test]
    fn engine_review_received_updates_average() {
        let mut engine = ReputationEngine::new();
        let pid = publisher_a();

        // Score 5 → delta +10
        engine.record_event(
            &pid,
            ReputationEvent::ReviewReceived {
                review_id: "r-1".into(),
                score: 5,
                occurred_at: None,
            },
        );
        // Score 4 → delta +5
        engine.record_event(
            &pid,
            ReputationEvent::ReviewReceived {
                review_id: "r-2".into(),
                score: 4,
                occurred_at: None,
            },
        );

        let rep = engine.get_reputation(&pid).unwrap();
        assert_eq!(rep.reviews_received, 2);
        // avg = (5 + 4) / 2 = 4.5
        assert!((rep.avg_review_score - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn engine_list_publishers_by_tier() {
        let mut engine = ReputationEngine::new();
        let pid_a = publisher_a();
        let pid_b = publisher_b();

        // A stays at CommunityTrusted (score 50)
        engine.record_event(
            &pid_a,
            ReputationEvent::PackagePublished {
                package_id: "pkg:test-a:cli".into(),
                occurred_at: None,
            },
        );

        // B gets many publishes to reach AiosCore
        for i in 0..20 {
            engine.record_event(
                &pid_b,
                ReputationEvent::PackagePublished {
                    package_id: format!("pkg:test-b:p{i}"),
                    occurred_at: None,
                },
            );
        }

        let community = engine.list_publishers_by_tier(TrustTier::CommunityTrusted);
        assert_eq!(community.len(), 1);
        assert_eq!(community[0].publisher_id, pid_a);

        let core = engine.list_publishers_by_tier(TrustTier::AiosCore);
        assert_eq!(core.len(), 1);
        assert_eq!(core[0].publisher_id, pid_b);

        let compromised = engine.list_publishers_by_tier(TrustTier::Compromised);
        assert!(compromised.is_empty());
    }

    #[test]
    fn engine_publisher_count() {
        let mut engine = ReputationEngine::new();
        assert_eq!(engine.publisher_count(), 0);

        engine.record_event(
            &publisher_a(),
            ReputationEvent::PackagePublished {
                package_id: "pkg:test-a:cli".into(),
                occurred_at: None,
            },
        );
        assert_eq!(engine.publisher_count(), 1);

        engine.record_event(
            &publisher_b(),
            ReputationEvent::PackagePublished {
                package_id: "pkg:test-b:cli".into(),
                occurred_at: None,
            },
        );
        assert_eq!(engine.publisher_count(), 2);
    }

    // -----------------------------------------------------------------------
    // PublisherTrustPolicy tests
    // -----------------------------------------------------------------------

    #[test]
    fn unvetted_policy_restrictions() {
        let policy = PublisherTrustPolicy::for_tier(TrustTier::Unvetted);
        assert_eq!(policy.max_packages_active, 10);
        assert_eq!(policy.min_review_count_before_upgrade, 3);
        assert_eq!(policy.revocation_threshold, 3);
        assert!(!policy.can_publish_to_community_repo);
        assert!(!policy.can_publish_to_verified_repo);
        assert!(policy.exceeds_active_cap(11));
        assert!(!policy.exceeds_active_cap(10));
        assert!(policy.has_enough_reviews_for_upgrade(3));
        assert!(!policy.has_enough_reviews_for_upgrade(2));
        assert!(policy.exceeds_revocation_threshold(3));
        assert!(!policy.exceeds_revocation_threshold(2));
    }

    #[test]
    fn aios_core_policy_gives_full_access() {
        let policy = PublisherTrustPolicy::for_tier(TrustTier::AiosCore);
        assert_eq!(policy.max_packages_active, u64::MAX);
        assert!(policy.can_publish_to_community_repo);
        assert!(policy.can_publish_to_verified_repo);
        assert!(!policy.exceeds_active_cap(1_000_000));
    }

    #[test]
    fn compromised_policy_blocks_all() {
        let policy = PublisherTrustPolicy::for_tier(TrustTier::Compromised);
        assert_eq!(policy.max_packages_active, 0);
        assert!(!policy.can_publish_to_community_repo);
        assert!(!policy.can_publish_to_verified_repo);
        assert!(policy.exceeds_active_cap(1));
    }

    // -----------------------------------------------------------------------
    // SigningKeyRotation tests
    // -----------------------------------------------------------------------

    #[test]
    fn signing_key_rotation_instantiation() {
        let rotation = SigningKeyRotation {
            publisher_id: PublisherId("pub:test".into()),
            publisher_root_id: PublisherRootId("pub:test".into()),
            old_key_ref: PackageSigningKeyId("pks:test:old".into()),
            new_key_ref: PackageSigningKeyId("pks:test:new".into()),
            rotation_signed_by_old_key: vec![0xAAu8; 64],
            rotation_index: 1,
            effective_at: Utc::now(),
            evidence: Some("blake3:abc123".into()),
        };
        assert_eq!(rotation.rotation_index, 1);
        assert_eq!(
            rotation.old_key_ref,
            PackageSigningKeyId("pks:test:old".into())
        );
        assert!(rotation.evidence.is_some());
    }

    // -----------------------------------------------------------------------
    // AuditTrail tests
    // -----------------------------------------------------------------------

    #[test]
    fn audit_trail_records_events() {
        let mut trail = PublisherAuditTrail::new(publisher_a());
        assert!(trail.is_empty());
        assert_eq!(trail.len(), 0);

        trail.record(
            ReputationEvent::PackagePublished {
                package_id: "pkg:test-a:cli".into(),
                occurred_at: None,
            },
            50,
            52,
        );
        assert!(!trail.is_empty());
        assert_eq!(trail.len(), 1);
        assert_eq!(trail.events[0].score_before, 50);
        assert_eq!(trail.events[0].score_after, 52);
    }

    // -----------------------------------------------------------------------
    // TrustTier serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn trust_tier_serde_roundtrip() {
        let tier = TrustTier::AiosVerified;
        let json = serde_json::to_string(&tier).unwrap();
        // SCREAMING_SNAKE_CASE
        assert_eq!(json, "\"AIOS_VERIFIED\"");
        let back: TrustTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tier);
    }

    #[test]
    fn trust_tier_compromised_serde() {
        let json = serde_json::to_string(&TrustTier::Compromised).unwrap();
        assert_eq!(json, "\"COMPROMISED\"");
        let back: TrustTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TrustTier::Compromised);
    }
}
