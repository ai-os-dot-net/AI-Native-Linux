//! `aios-marketplace` — centralized marketplace and app store for AI-OS.NET Rev.9.
//!
//! Implements the S11.2 / S27 marketplace contract: publisher onboarding,
//! capability review, listings, curated feeds, and app passports.
//!
//! # Architecture
//!
//! - **`enums`** — closed vocabulary: tiers, states, decisions, categories, feeds.
//! - **`error`** — unified `MarketplaceError` taxonomy via `thiserror`.
//! - **`publisher`** — `Publisher` struct + `PublisherRegistry` (register, verify, promote, suspend).
//! - **`listing`** — `Listing` struct + `ListingStore` (publish, withdraw, flag, search).
//! - **`review`** — `CapabilityReview` struct + `CapabilityReviewEngine` (start, complete, appeal).
//! - **`feed`** — `CuratedFeed` struct + `FeedGenerator` + `FeedCache` with TTL.
//! - **`passport`** — `AppPassport` for operator-facing trust/provenance display.
//!
//! # Invariants
//!
//! - No publisher may self-promote to `AiosCore` (INV-013).
//! - All enums are closed (`EnumIter` + `EnumCount`); unknown values rejected at parse.
//! - Zero `unwrap`/`expect`/`panic` in production code.
//! - `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

pub mod enums;
pub mod error;
pub mod feed;
pub mod listing;
pub mod passport;
pub mod publisher;
pub mod review;

pub use enums::{
    CapabilityReviewDecision, FeedKind, ListingState, MarketplaceCategory, PublisherTier,
};
pub use error::MarketplaceError;
pub use feed::{CuratedFeed, FeedCache, FeedGenerator};
pub use listing::{Listing, ListingStore};
pub use passport::AppPassport;
pub use publisher::{Publisher, PublisherRegistry};
pub use review::{CapabilityReview, CapabilityReviewEngine};
