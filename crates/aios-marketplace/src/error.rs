use thiserror::Error;

#[derive(Debug, Error)]
pub enum MarketplaceError {
    #[error("publisher already registered: {0}")]
    PublisherAlreadyRegistered(String),

    #[error("publisher not found: {0}")]
    PublisherNotFound(String),

    #[error("listing not found: {0}")]
    ListingNotFound(String),

    #[error("review not found: {0}")]
    ReviewNotFound(String),

    #[error("feed not found: {0}")]
    FeedNotFound(String),

    #[error("passport not found: {0}")]
    PassportNotFound(String),

    #[error("invalid state transition: from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("self-promotion forbidden: publisher {0} attempted to promote to {1}")]
    SelfPromotionForbidden(String, String),

    #[error("insufficient tier for operation: {0}")]
    InsufficientTier(String),

    #[error("listing already published: {0}")]
    ListingAlreadyPublished(String),

    #[error("listing not published, cannot withdraw: {0}")]
    ListingNotPublished(String),

    #[error("review already completed: {0}")]
    ReviewAlreadyCompleted(String),

    #[error("review not in started state: {0}")]
    ReviewNotStarted(String),

    #[error("feed cache expired")]
    FeedCacheExpired,

    #[error("invalid feed kind for operation")]
    InvalidFeedKind,

    #[error("invalid category: {0}")]
    InvalidCategory(String),

    #[error("publisher suspended, operation denied: {publisher_id}")]
    PublisherSuspended { publisher_id: String },

    #[error("listing in non-reviewable state: {listing_id}")]
    ListingNotReviewable { listing_id: String },

    #[error("duplicate review: reviewer {reviewer_id} already reviewed listing {listing_id}")]
    DuplicateReview {
        reviewer_id: String,
        listing_id: String,
    },

    #[error("signature verification failed for {entity}")]
    SignatureVerificationFailed { entity: String },

    #[error("invalid publisher tier for this operation: {0}")]
    InvalidPublisherTier(String),

    #[error("review cycle limit exceeded for listing: {0}")]
    ReviewCycleLimitExceeded(String),
}
