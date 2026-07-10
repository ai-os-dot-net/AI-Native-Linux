use crate::enums::CapabilityReviewDecision;
use crate::error::MarketplaceError;
use chrono::{DateTime, Utc};
use ulid::Ulid;

/// A capability review record (S11.2 §8.1).
#[derive(Debug, Clone)]
pub struct CapabilityReview {
    /// Unique review identifier (`rev_` + ULID).
    pub review_id: String,
    /// The listing under review.
    pub listing_id: String,
    /// Subject ID of the reviewer.
    pub reviewer_id: String,
    /// Reviewer's decision.
    pub decision: Option<CapabilityReviewDecision>,
    /// Written feedback from the reviewer.
    pub feedback: Option<String>,
    /// When the review was recorded.
    pub reviewed_at: DateTime<Utc>,
}

impl CapabilityReview {
    #[must_use]
    pub fn new(listing_id: impl Into<String>, reviewer_id: impl Into<String>) -> Self {
        Self {
            review_id: format!("rev_{}", Ulid::new()),
            listing_id: listing_id.into(),
            reviewer_id: reviewer_id.into(),
            decision: None,
            feedback: None,
            reviewed_at: Utc::now(),
        }
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.decision.is_some()
    }

    #[must_use]
    pub fn was_approved(&self) -> bool {
        matches!(self.decision, Some(CapabilityReviewDecision::Approved))
    }
}

/// Engine that manages the capability review lifecycle (S11.2 §6.3).
#[derive(Debug, Default)]
pub struct CapabilityReviewEngine {
    reviews: Vec<CapabilityReview>,
    appeal_log: Vec<(String, String)>,
}

impl CapabilityReviewEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start_review(
        &mut self,
        listing_id: impl Into<String>,
        reviewer_id: impl Into<String>,
    ) -> Result<&CapabilityReview, MarketplaceError> {
        let lid = listing_id.into();
        let rid = reviewer_id.into();

        if self
            .reviews
            .iter()
            .any(|r| r.listing_id == lid && r.reviewer_id == rid && r.is_complete())
        {
            return Err(MarketplaceError::DuplicateReview {
                reviewer_id: rid,
                listing_id: lid,
            });
        }

        let review = CapabilityReview::new(lid, rid);
        self.reviews.push(review);
        Ok(&self.reviews[self.reviews.len() - 1])
    }

    pub fn complete_review(
        &mut self,
        review_id: &str,
        decision: CapabilityReviewDecision,
        feedback: impl Into<String>,
    ) -> Result<&CapabilityReview, MarketplaceError> {
        let review = self
            .reviews
            .iter_mut()
            .find(|r| r.review_id == review_id)
            .ok_or_else(|| MarketplaceError::ReviewNotFound(review_id.to_string()))?;

        if review.is_complete() {
            return Err(MarketplaceError::ReviewAlreadyCompleted(
                review_id.to_string(),
            ));
        }

        review.decision = Some(decision);
        review.feedback = Some(feedback.into());
        review.reviewed_at = Utc::now();
        Ok(review)
    }

    pub fn appeal_review(
        &mut self,
        review_id: &str,
        appeal_reason: impl Into<String>,
    ) -> Result<(), MarketplaceError> {
        let review = self
            .reviews
            .iter()
            .find(|r| r.review_id == review_id)
            .ok_or_else(|| MarketplaceError::ReviewNotFound(review_id.to_string()))?;

        if !review.is_complete() {
            return Err(MarketplaceError::ReviewNotStarted(review_id.to_string()));
        }

        self.appeal_log
            .push((review_id.to_string(), appeal_reason.into()));
        Ok(())
    }

    pub fn find(&self, review_id: &str) -> Option<&CapabilityReview> {
        self.reviews.iter().find(|r| r.review_id == review_id)
    }

    pub fn find_by_listing(&self, listing_id: &str) -> Vec<&CapabilityReview> {
        self.reviews
            .iter()
            .filter(|r| r.listing_id == listing_id)
            .collect()
    }

    #[must_use]
    pub fn appeal_count_for(&self, review_id: &str) -> usize {
        self.appeal_log
            .iter()
            .filter(|(rid, _)| rid == review_id)
            .count()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.reviews.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reviews.is_empty()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn new_review_starts_incomplete() {
        let r = CapabilityReview::new("lst-1", "reviewer:alice");
        assert!(!r.is_complete());
        assert!(!r.was_approved());
    }

    #[test]
    fn start_review_succeeds() {
        let mut engine = CapabilityReviewEngine::new();
        let result = engine.start_review("lst-1", "reviewer:alice");
        assert!(result.is_ok());
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn complete_review_sets_decision() {
        let mut engine = CapabilityReviewEngine::new();
        let r = engine.start_review("lst-1", "reviewer:alice").unwrap();
        let rid = r.review_id.clone();
        let result = engine.complete_review(&rid, CapabilityReviewDecision::Approved, "looks good");
        assert!(result.is_ok());
        let updated = engine.find(&rid).unwrap();
        assert!(updated.was_approved());
        assert_eq!(updated.feedback.as_deref(), Some("looks good"));
    }

    #[test]
    fn double_complete_review_fails() {
        let mut engine = CapabilityReviewEngine::new();
        let r = engine.start_review("lst-1", "reviewer:alice").unwrap();
        let rid = r.review_id.clone();
        engine
            .complete_review(&rid, CapabilityReviewDecision::Approved, "ok")
            .ok();
        let result = engine.complete_review(&rid, CapabilityReviewDecision::Approved, "again");
        assert!(result.is_err());
    }

    #[test]
    fn appeal_review_records_appeal() {
        let mut engine = CapabilityReviewEngine::new();
        let r = engine.start_review("lst-1", "reviewer:alice").unwrap();
        let rid = r.review_id.clone();
        engine
            .complete_review(
                &rid,
                CapabilityReviewDecision::RejectedWithFeedback,
                "denied",
            )
            .ok();
        let result = engine.appeal_review(&rid, "unfair review");
        assert!(result.is_ok());
        assert_eq!(engine.appeal_count_for(&rid), 1);
    }

    #[test]
    fn appeal_before_completion_fails() {
        let mut engine = CapabilityReviewEngine::new();
        let r = engine.start_review("lst-1", "reviewer:alice").unwrap();
        let rid = r.review_id.clone();
        let result = engine.appeal_review(&rid, "too early");
        assert!(result.is_err());
    }

    #[test]
    fn find_by_listing_returns_all_reviews() {
        let mut engine = CapabilityReviewEngine::new();
        engine.start_review("lst-1", "reviewer:alice").ok();
        engine.start_review("lst-1", "reviewer:bob").ok();
        engine.start_review("lst-2", "reviewer:alice").ok();
        let lst1_reviews = engine.find_by_listing("lst-1");
        assert_eq!(lst1_reviews.len(), 2);
    }

    #[test]
    fn duplicate_review_from_same_reviewer_fails() {
        let mut engine = CapabilityReviewEngine::new();
        let r = engine.start_review("lst-1", "reviewer:alice").unwrap();
        let rid = r.review_id.clone();
        engine
            .complete_review(&rid, CapabilityReviewDecision::Approved, "ok")
            .ok();
        let result = engine.start_review("lst-1", "reviewer:alice");
        assert!(result.is_err());
    }
}
