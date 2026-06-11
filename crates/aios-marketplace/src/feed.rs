use chrono::{DateTime, Duration, Utc};
use ulid::Ulid;
use crate::enums::{FeedKind, MarketplaceCategory};
use crate::error::MarketplaceError;

/// A curated feed of marketplace listings (S11.2 §3.4).
#[derive(Debug, Clone)]
pub struct CuratedFeed {
    /// Unique feed identifier (`feed_` + ULID).
    pub feed_id: String,
    /// Curation profile for this feed.
    pub kind: FeedKind,
    /// Ordered list of listing IDs in this feed.
    pub entries: Vec<String>,
    /// When the feed was last refreshed.
    pub last_updated: DateTime<Utc>,
    /// Ed25519 signature over the feed content (canonical bytes).
    pub signature: Option<Vec<u8>>,
}

impl CuratedFeed {
    #[must_use]
    pub fn new(kind: FeedKind) -> Self {
        Self {
            feed_id: format!("feed_{}", Ulid::new()),
            kind,
            entries: Vec::new(),
            last_updated: Utc::now(),
            signature: None,
        }
    }

    pub fn set_entries(&mut self, entries: Vec<String>) {
        self.entries = entries;
        self.last_updated = Utc::now();
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Feed generator that refreshes and filters curated feeds.
#[derive(Debug, Default)]
pub struct FeedGenerator {
    feeds: Vec<CuratedFeed>,
}

impl FeedGenerator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn refresh_feed(
        &mut self,
        kind: FeedKind,
        listing_ids: Vec<String>,
    ) -> Result<&CuratedFeed, MarketplaceError> {
        let existing_idx = self.feeds.iter().position(|f| f.kind == kind);
        if let Some(idx) = existing_idx {
            self.feeds[idx].set_entries(listing_ids);
            Ok(&self.feeds[idx])
        } else {
            let mut feed = CuratedFeed::new(kind);
            feed.set_entries(listing_ids);
            self.feeds.push(feed);
            let last_idx = self.feeds.len() - 1;
            Ok(&self.feeds[last_idx])
        }
    }

    #[must_use]
    pub fn filter_by_category(
        &self,
        feed_kind: FeedKind,
        category: MarketplaceCategory,
        listing_store: &crate::listing::ListingStore,
    ) -> Vec<String> {
        let feed = match self.feeds.iter().find(|f| f.kind == feed_kind) {
            Some(f) => f,
            None => return Vec::new(),
        };

        feed.entries
            .iter()
            .filter(|lid| {
                listing_store
                    .find(lid)
                    .is_some_and(|l| l.categories.contains(&category))
            })
            .cloned()
            .collect()
    }

    pub fn get_feed_entries(
        &self,
        kind: FeedKind,
    ) -> Result<&[String], MarketplaceError> {
        self.feeds
            .iter()
            .find(|f| f.kind == kind)
            .map(|f| f.entries.as_slice())
            .ok_or(MarketplaceError::FeedNotFound(format!("feed_kind_{kind}")))
    }

    pub fn find(&self, feed_id: &str) -> Option<&CuratedFeed> {
        self.feeds.iter().find(|f| f.feed_id == feed_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.feeds.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.feeds.is_empty()
    }
}

/// Time-to-live cache for feed content.
#[derive(Debug, Clone)]
pub struct FeedCache {
    entries: Vec<String>,
    ttl: Duration,
    last_refreshed: DateTime<Utc>,
}

impl FeedCache {
    #[must_use]
    pub fn new(ttl_seconds: i64) -> Self {
        Self {
            entries: Vec::new(),
            ttl: Duration::seconds(ttl_seconds),
            last_refreshed: Utc::now(),
        }
    }

    pub fn set(&mut self, entries: Vec<String>) {
        self.entries = entries;
        self.last_refreshed = Utc::now();
    }

    pub fn get(&self) -> Result<&[String], MarketplaceError> {
        if self.is_expired() {
            return Err(MarketplaceError::FeedCacheExpired);
        }
        Ok(&self.entries)
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() - self.last_refreshed > self.ttl
    }

    #[must_use]
    pub fn age_seconds(&self) -> i64 {
        (Utc::now() - self.last_refreshed).num_seconds()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
    fn new_feed_has_zero_entries() {
        let feed = CuratedFeed::new(FeedKind::CuratedStable);
        assert_eq!(feed.entry_count(), 0);
    }

    #[test]
    fn refresh_feed_creates_or_updates() {
        let mut gen = FeedGenerator::new();
        let result = gen.refresh_feed(FeedKind::CuratedStable, vec!["lst-1".into()]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().entry_count(), 1);

        let result = gen.refresh_feed(FeedKind::CuratedStable, vec!["lst-2".into(), "lst-3".into()]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().entry_count(), 2);
        assert_eq!(gen.len(), 1);
    }

    #[test]
    fn get_feed_entries_returns_correct_entries() {
        let mut gen = FeedGenerator::new();
        gen.refresh_feed(FeedKind::SecurityCritical, vec!["sec-1".into()])
            .ok();
        let result = gen.get_feed_entries(FeedKind::SecurityCritical);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), &["sec-1"]);
    }

    #[test]
    fn get_feed_entries_missing_feed_errors() {
        let gen = FeedGenerator::new();
        let result = gen.get_feed_entries(FeedKind::DeveloperPreview);
        assert!(result.is_err());
    }

    #[test]
    fn refresh_multiple_kinds_keeps_separate() {
        let mut gen = FeedGenerator::new();
        gen.refresh_feed(FeedKind::CuratedStable, vec!["cs-1".into()])
            .ok();
        gen.refresh_feed(FeedKind::CommunityEdge, vec!["ce-1".into()])
            .ok();
        assert_eq!(gen.len(), 2);
        let cs = gen.get_feed_entries(FeedKind::CuratedStable).unwrap();
        assert_eq!(cs, &["cs-1"]);
    }

    #[test]
    fn feed_cache_not_expired_after_set() {
        let mut cache = FeedCache::new(3600);
        cache.set(vec!["a".into()]);
        assert!(!cache.is_expired());
        let entries = cache.get().unwrap();
        assert_eq!(entries, &["a"]);
    }

    #[test]
    fn feed_cache_expires_after_ttl() {
        let cache = FeedCache {
            entries: vec!["old".into()],
            ttl: Duration::seconds(-1),
            last_refreshed: Utc::now() - Duration::seconds(10),
        };
        assert!(cache.is_expired());
        assert!(cache.get().is_err());
    }

    #[test]
    fn feed_cache_len_and_empty() {
        let mut cache = FeedCache::new(60);
        assert!(cache.is_empty());
        cache.set(vec!["a".into(), "b".into()]);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 2);
    }
}
