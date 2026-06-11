use chrono::{DateTime, Utc};
use ulid::Ulid;
use crate::enums::{ListingState, MarketplaceCategory};
use crate::error::MarketplaceError;

/// A marketplace listing (S11.2 §7).
#[derive(Debug, Clone)]
pub struct Listing {
    /// Unique listing identifier (`lst_` + ULID).
    pub listing_id: String,
    /// The capsule (app/package) this listing represents.
    pub capsule_id: String,
    /// Publisher identity.
    pub publisher_id: String,
    /// Operator-facing display name.
    pub name: String,
    /// Short description.
    pub description: String,
    /// Top-level categories for discoverability.
    pub categories: Vec<MarketplaceCategory>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Lifecycle state.
    pub state: ListingState,
    /// Reference to the capability manifest digest.
    pub capability_manifest_ref: Option<String>,
    /// Ordered list of review IDs applied to this listing.
    pub review_history: Vec<String>,
    /// Optional trust badge (e.g. "AIOS_VERIFIED").
    pub trust_badge: Option<String>,
    /// When the listing was published (set on first publish).
    pub published_at: Option<DateTime<Utc>>,
}

impl Listing {
    #[must_use]
    pub fn new(
        capsule_id: impl Into<String>,
        publisher_id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            listing_id: format!("lst_{}", Ulid::new()),
            capsule_id: capsule_id.into(),
            publisher_id: publisher_id.into(),
            name: name.into(),
            description: description.into(),
            categories: Vec::new(),
            tags: Vec::new(),
            state: ListingState::Draft,
            capability_manifest_ref: None,
            review_history: Vec::new(),
            trust_badge: None,
            published_at: None,
        }
    }

    #[must_use]
    pub fn is_published(&self) -> bool {
        self.state == ListingState::Published
    }

    #[must_use]
    pub fn is_reviewable(&self) -> bool {
        matches!(self.state, ListingState::Draft | ListingState::UnderReview)
    }

    pub fn add_category(&mut self, category: MarketplaceCategory) {
        if !self.categories.contains(&category) {
            self.categories.push(category);
        }
    }

    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let t = tag.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
    }

    pub fn record_review(&mut self, review_id: impl Into<String>) {
        self.review_history.push(review_id.into());
    }
}

/// In-memory store of marketplace listings.
#[derive(Debug, Default)]
pub struct ListingStore {
    listings: Vec<Listing>,
}

impl ListingStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&mut self, listing: Listing) -> Result<&Listing, MarketplaceError> {
        if listing.state == ListingState::Published {
            return Err(MarketplaceError::ListingAlreadyPublished(
                listing.listing_id,
            ));
        }
        if self.listings.iter().any(|l| l.listing_id == listing.listing_id) {
            return Err(MarketplaceError::ListingAlreadyPublished(
                listing.listing_id,
            ));
        }
        self.listings.push(listing);
        let published = self.listings.last_mut().unwrap();
        published.state = ListingState::Published;
        published.published_at = Some(Utc::now());
        Ok(published)
    }

    pub fn withdraw(&mut self, listing_id: &str) -> Result<&Listing, MarketplaceError> {
        let listing = self
            .listings
            .iter_mut()
            .find(|l| l.listing_id == listing_id)
            .ok_or_else(|| MarketplaceError::ListingNotFound(listing_id.to_string()))?;

        if listing.state != ListingState::Published {
            return Err(MarketplaceError::ListingNotPublished(listing_id.to_string()));
        }

        listing.state = ListingState::Deprecated;
        Ok(listing)
    }

    pub fn flag_for_review(&mut self, listing_id: &str) -> Result<&Listing, MarketplaceError> {
        let listing = self
            .listings
            .iter_mut()
            .find(|l| l.listing_id == listing_id)
            .ok_or_else(|| MarketplaceError::ListingNotFound(listing_id.to_string()))?;

        if !listing.is_reviewable() && listing.state != ListingState::Published {
            return Err(MarketplaceError::ListingNotReviewable {
                listing_id: listing_id.to_string(),
            });
        }

        listing.state = ListingState::UnderReview;
        Ok(listing)
    }

    pub fn search_by_category(
        &self,
        category: MarketplaceCategory,
    ) -> Vec<&Listing> {
        self.listings
            .iter()
            .filter(|l| l.categories.contains(&category) && l.state == ListingState::Published)
            .collect()
    }

    pub fn find(&self, listing_id: &str) -> Option<&Listing> {
        self.listings.iter().find(|l| l.listing_id == listing_id)
    }

    pub fn suspend(&mut self, listing_id: &str) -> Result<&Listing, MarketplaceError> {
        let listing = self
            .listings
            .iter_mut()
            .find(|l| l.listing_id == listing_id)
            .ok_or_else(|| MarketplaceError::ListingNotFound(listing_id.to_string()))?;
        listing.state = ListingState::Suspended;
        Ok(listing)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.listings.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.listings.is_empty()
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
    fn new_listing_starts_in_draft() {
        let l = Listing::new("capsule-a", "pub-1", "My App", "A nice app");
        assert_eq!(l.state, ListingState::Draft);
        assert!(!l.is_published());
        assert!(l.is_reviewable());
    }

    #[test]
    fn publish_transitions_to_published() {
        let mut store = ListingStore::new();
        let l = Listing::new("capsule-a", "pub-1", "My App", "A nice app");
        let lid = l.listing_id.clone();
        let result = store.publish(l);
        assert!(result.is_ok());
        let published = store.find(&lid).unwrap();
        assert_eq!(published.state, ListingState::Published);
        assert!(published.published_at.is_some());
    }

    #[test]
    fn withdraw_published_listing() {
        let mut store = ListingStore::new();
        let l = Listing::new("capsule-a", "pub-1", "My App", "desc");
        let lid = l.listing_id.clone();
        store.publish(l).ok();
        let result = store.withdraw(&lid);
        assert!(result.is_ok());
        assert_eq!(store.find(&lid).unwrap().state, ListingState::Deprecated);
    }

    #[test]
    fn search_by_category_finds_published_only() {
        let mut store = ListingStore::new();
        let mut l1 = Listing::new("c1", "p1", "App1", "desc");
        l1.add_category(MarketplaceCategory::Productivity);
        let mut l2 = Listing::new("c2", "p2", "App2", "desc");
        l2.add_category(MarketplaceCategory::Security);
        let lid1 = l1.listing_id.clone();
        store.publish(l1).ok();
        let _ = store.publish(l2);
        let results = store.search_by_category(MarketplaceCategory::Productivity);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].listing_id, lid1);
    }

    #[test]
    fn flag_for_review_from_draft() {
        let mut store = ListingStore::new();
        let l = Listing::new("c1", "p1", "App", "desc");
        let lid = l.listing_id.clone();
        store.publish(l).ok();
        let result = store.flag_for_review(&lid);
        assert!(result.is_ok());
        assert_eq!(store.find(&lid).unwrap().state, ListingState::UnderReview);
    }

    #[test]
    fn withdraw_fails_on_non_published() {
        let mut store = ListingStore::new();
        let l = Listing::new("c1", "p1", "App", "desc");
        let lid = l.listing_id.clone();
        let _ = store.publish(l);
        store.withdraw(&lid).ok();
        let result = store.withdraw(&lid);
        assert!(result.is_err());
    }

    #[test]
    fn suspend_published_listing() {
        let mut store = ListingStore::new();
        let l = Listing::new("c1", "p1", "App", "desc");
        let lid = l.listing_id.clone();
        store.publish(l).ok();
        let result = store.suspend(&lid);
        assert!(result.is_ok());
        assert_eq!(store.find(&lid).unwrap().state, ListingState::Suspended);
    }

    #[test]
    fn add_category_deduplicates() {
        let mut l = Listing::new("c1", "p1", "App", "desc");
        l.add_category(MarketplaceCategory::Security);
        l.add_category(MarketplaceCategory::Security);
        assert_eq!(l.categories.len(), 1);
    }
}
