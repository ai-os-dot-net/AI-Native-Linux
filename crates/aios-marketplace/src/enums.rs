use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// Publisher trust tier.
///
/// Tiers escalate in trust. A publisher **cannot** self-assign or self-promote
/// into any tier — promotion is always gated by a reviewer decision recorded in
/// the onboarding FSM (S11.2 §3.2 / §6).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
    strum_macros::Display,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublisherTier {
    /// Default on first registration; no review has passed.
    Unverified,
    /// Passed lightweight identity + peer-signoff review.
    CommunityVerified,
    /// Passed full identity → technical → security review pipeline.
    AiosPartner,
    /// AIOS-root-internal tier; granted only by recovery-mode operation.
    /// Never applicant-selectable (S11.2 §3.2).
    AiosCore,
}

/// Lifecycle state of a marketplace listing (S11.2 §3.1 / §7).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
    strum_macros::Display,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ListingState {
    /// Author has not yet submitted for review.
    Draft,
    /// Submitted and awaiting reviewer attention.
    UnderReview,
    /// Passed review and visible in the appropriate feed.
    Published,
    /// Temporarily hidden; under investigation.
    Suspended,
    /// Permanently removed by authority decision.
    Revoked,
    /// No longer recommended; existing installs continue.
    Deprecated,
}

/// Decision a reviewer assigns to a capability declaration (S11.2 §3.3).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
    strum_macros::Display,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityReviewDecision {
    /// Capability accepted as declared.
    Approved,
    /// Capability denied with written feedback.
    RejectedWithFeedback,
    /// Reviewer requests revisions before re-evaluation.
    NeedsRevision,
}

/// Top-level marketplace category for discoverability.
///
/// Every listing carries at least one category so the operator can browse or
/// filter the curated feed.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
    strum_macros::Display,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MarketplaceCategory {
    Productivity,
    Development,
    SystemTool,
    Media,
    Gaming,
    Security,
    Network,
    Education,
    Science,
    Finance,
    Utilities,
}

/// Feed curation profile.
///
/// Each feed surface exposes a different risk/relevance window.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
    strum_macros::Display,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FeedKind {
    /// Stable, reviewed listings from AiosPartner+ publishers.
    CuratedStable,
    /// Community-tier listings, lighter review.
    CommunityEdge,
    /// Security-critical updates only (vulnerability fixes).
    SecurityCritical,
    /// Early-access and dev-preview listings.
    DeveloperPreview,
    /// Deprecated-only feed for audit and migration.
    DeprecatedOnly,
}
