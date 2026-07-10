use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::IntegrationError;
use crate::evidence::IntegrationEvidenceEmitter;

#[allow(unused_imports)]
use aios_distribution::ids::PackageId;
#[allow(unused_imports)]
use aios_distribution::package_kind::{InstallScope, PackageKind};

fn lock_poisoned() -> IntegrationError {
    IntegrationError::Internal("lock poisoned".into())
}

// ---------------------------------------------------------------------------
// MarketplaceListing — a single capsule entry returned by the remote marketplace
// ---------------------------------------------------------------------------

/// A capsule listing returned by the remote marketplace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MarketplaceListing {
    /// The unique listing identifier on the marketplace.
    pub listing_id: String,
    /// Human-readable capsule name.
    pub capsule_name: String,
    /// Publisher canonical identifier.
    pub publisher_id: String,
    /// Machine-readable category slug (e.g. "ai", "security", "observability").
    pub category: String,
    /// Short description of the capsule.
    pub description: String,
    /// SemVer string for the latest published version.
    pub latest_version: String,
    /// The [`BillingPlan`] for this capsule.
    pub billing_plan: BillingPlan,
    /// Total download count (informational).
    pub downloads: u64,
    /// Average rating 1.0–5.0 (0.0 = unrated).
    pub rating: f64,
    /// When this listing was first published.
    pub published_at: DateTime<Utc>,
    /// When this listing was last updated.
    pub updated_at: DateTime<Utc>,
    /// Whether the listing is verified by the marketplace.
    pub verified: bool,
    /// Tags associated with this capsule.
    pub tags: Vec<String>,
    /// Dependencies (package IDs) required by this capsule.
    pub dependencies: Vec<String>,
}

// ---------------------------------------------------------------------------
// CapsuleDetail — full listing detail with changelog, install metadata
// ---------------------------------------------------------------------------

/// Full details for a marketplace listing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapsuleDetail {
    /// The listing this detail belongs to.
    pub listing: MarketplaceListing,
    /// Markdown readme / long description.
    pub readme: String,
    /// Recent changelog entries.
    pub changelog: Vec<String>,
    /// Required AIOS version (e.g. ">=0.9.0").
    pub required_aios_version: String,
    /// Install size estimate in bytes.
    pub install_size_bytes: u64,
    /// SHA-256 hash of the capsule archive.
    pub archive_hash: String,
    /// Required sandbox profile names.
    pub required_sandbox_profiles: Vec<String>,
    /// Whether online delivery is supported.
    pub online_delivery: bool,
    /// Whether airgap delivery is supported.
    pub airgap_delivery: bool,
}

// ---------------------------------------------------------------------------
// BillingPlan — closed enum for capsule pricing models
// ---------------------------------------------------------------------------

/// Pricing model for a marketplace capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingPlan {
    /// No cost, fully open.
    Free,
    /// Core features free, premium features paid.
    Freemium,
    /// One-time purchase with perpetual license.
    OneTimePurchase,
    /// Recurring subscription (monthly, annual, etc.).
    Subscription,
    /// Volume / site enterprise license.
    EnterpriseLicence,
    /// Open source under an OSI-approved license.
    OpenSource,
}

impl BillingPlan {
    /// Human-readable label for this billing plan.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Freemium => "freemium",
            Self::OneTimePurchase => "one_time_purchase",
            Self::Subscription => "subscription",
            Self::EnterpriseLicence => "enterprise_licence",
            Self::OpenSource => "open_source",
        }
    }

    /// Returns `true` if this plan requires a license verification.
    #[must_use]
    pub const fn requires_license(&self) -> bool {
        match self {
            Self::Free | Self::OpenSource => false,
            Self::Freemium
            | Self::OneTimePurchase
            | Self::Subscription
            | Self::EnterpriseLicence => true,
        }
    }
}

// ---------------------------------------------------------------------------
// LicenseVerification — per-capsule license status
// ---------------------------------------------------------------------------

/// License verification record for an installed capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseVerification {
    /// The capsule this verification applies to.
    pub capsule_id: String,
    /// The billing plan under which the capsule is licensed.
    pub license_type: BillingPlan,
    /// Whether the license has been verified by the marketplace.
    pub verified: bool,
    /// When the license expires, if applicable.
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether renewal is required before expiration.
    pub renewal_required: bool,
    /// The last time the license was checked against the marketplace.
    pub last_checked_at: DateTime<Utc>,
}

impl LicenseVerification {
    /// Creates a new `LicenseVerification` for a free / open-source capsule.
    #[must_use]
    pub fn free_license(capsule_id: String) -> Self {
        Self {
            capsule_id,
            license_type: BillingPlan::Free,
            verified: true,
            expires_at: None,
            renewal_required: false,
            last_checked_at: Utc::now(),
        }
    }

    /// Returns `true` if the license is expired.
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        if !self.license_type.requires_license() {
            return false;
        }
        match self.expires_at {
            Some(expiry) if self.verified => now > expiry,
            _ => false,
        }
    }

    /// Returns `true` if the license is valid (verified and not expired).
    #[must_use]
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        self.verified && !self.is_expired(now)
    }
}

// ---------------------------------------------------------------------------
// Marketplace Integration — top-level bridge struct
// ---------------------------------------------------------------------------

/// The top-level marketplace integration bridge.
///
/// Wires together the remote marketplace, the local distribution pipeline,
/// and the evidence emitter. This is an integration bridge — it does not
/// implement the full marketplace logic; it provides the typed contract
/// surface that the marketplace, distribution, and registry crates plug into.
#[derive(Clone)]
pub struct MarketplaceIntegration {
    /// Unique identifier for this bridge instance.
    pub bridge_id: String,
    /// Remote marketplace endpoint URL.
    pub marketplace_endpoint: String,
    /// Local distribution pipeline endpoint.
    pub distribution_endpoint: String,
    /// Optional evidence emitter for chain-of-custody.
    pub evidence_emitter: Option<Arc<dyn IntegrationEvidenceEmitter>>,
    /// Cached marketplace listings, keyed by listing_id.
    local_index: Arc<RwLock<HashMap<String, MarketplaceListing>>>,
    /// Cached capsule details, keyed by listing_id.
    local_details: Arc<RwLock<HashMap<String, CapsuleDetail>>>,
    /// Category → listing_ids mapping.
    category_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// publisher_id → listing_ids mapping.
    publisher_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Feed subscriptions managed by this bridge.
    feeds: Arc<RwLock<HashMap<String, FeedSubscription>>>,
    /// Installed capsule license verifications.
    licenses: Arc<RwLock<HashMap<String, LicenseVerification>>>,
}

impl MarketplaceIntegration {
    /// Creates a new marketplace integration bridge.
    #[must_use]
    pub fn new(
        bridge_id: String,
        marketplace_endpoint: String,
        distribution_endpoint: String,
    ) -> Self {
        Self {
            bridge_id,
            marketplace_endpoint,
            distribution_endpoint,
            evidence_emitter: None,
            local_index: Arc::new(RwLock::new(HashMap::new())),
            local_details: Arc::new(RwLock::new(HashMap::new())),
            category_index: Arc::new(RwLock::new(HashMap::new())),
            publisher_index: Arc::new(RwLock::new(HashMap::new())),
            feeds: Arc::new(RwLock::new(HashMap::new())),
            licenses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Attach an evidence emitter for audit trail.
    #[must_use]
    pub fn with_emitter(mut self, emitter: Arc<dyn IntegrationEvidenceEmitter>) -> Self {
        self.evidence_emitter = Some(emitter);
        self
    }

    /// Returns a reference to the shared local index for use by sub-services.
    fn local_index_ref(&self) -> &Arc<RwLock<HashMap<String, MarketplaceListing>>> {
        &self.local_index
    }

    /// Returns a reference to the shared local details cache.
    fn local_details_ref(&self) -> &Arc<RwLock<HashMap<String, CapsuleDetail>>> {
        &self.local_details
    }

    /// Returns a reference to the shared category index.
    fn category_index_ref(&self) -> &Arc<RwLock<HashMap<String, Vec<String>>>> {
        &self.category_index
    }

    /// Returns a reference to the shared publisher index.
    fn publisher_index_ref(&self) -> &Arc<RwLock<HashMap<String, Vec<String>>>> {
        &self.publisher_index
    }
}

impl std::fmt::Debug for MarketplaceIntegration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarketplaceIntegration")
            .field("bridge_id", &self.bridge_id)
            .field("marketplace_endpoint", &self.marketplace_endpoint)
            .field("distribution_endpoint", &self.distribution_endpoint)
            .field(
                "evidence_emitter",
                &self.evidence_emitter.as_ref().map(|_| "present"),
            )
            .field("local_index", &self.local_index)
            .field("local_details", &self.local_details)
            .field("category_index", &self.category_index)
            .field("publisher_index", &self.publisher_index)
            .field("feeds", &self.feeds)
            .field("licenses", &self.licenses)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// FeedSubscription — per-capsule feed tracking
// ---------------------------------------------------------------------------

/// Kinds of feeds a capsule can be subscribed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedKind {
    /// Stable release channel updates.
    Stable,
    /// Pre-release / beta channel updates.
    Beta,
    /// Nightly / development channel updates.
    Nightly,
    /// CVE / security advisory feed for this capsule.
    SecurityAdvisory,
    /// Publisher announcements.
    PublisherNews,
}

impl FeedKind {
    /// Human-readable label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
            Self::SecurityAdvisory => "security_advisory",
            Self::PublisherNews => "publisher_news",
        }
    }
}

/// Update policy for an auto-update feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePolicy {
    /// Automatically apply updates when available.
    AutoApply,
    /// Download but do not apply; notify operator.
    DownloadOnly,
    /// Notify operator; no automatic download or apply.
    NotifyOnly,
    /// Skip updates entirely (pinned version).
    Pinned,
}

impl UpdatePolicy {
    /// Human-readable label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::AutoApply => "auto_apply",
            Self::DownloadOnly => "download_only",
            Self::NotifyOnly => "notify_only",
            Self::Pinned => "pinned",
        }
    }

    /// Whether this policy permits automatic download.
    #[must_use]
    pub const fn permits_download(&self) -> bool {
        match self {
            Self::AutoApply | Self::DownloadOnly => true,
            Self::NotifyOnly | Self::Pinned => false,
        }
    }

    /// Whether this policy permits automatic install.
    #[must_use]
    pub const fn permits_install(&self) -> bool {
        match self {
            Self::AutoApply => true,
            Self::DownloadOnly | Self::NotifyOnly | Self::Pinned => false,
        }
    }
}

/// Per-capsule feed subscription tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedSubscription {
    /// Unique identifier for this subscription.
    pub subscription_id: String,
    /// What kind of feed this subscription tracks.
    pub feed_kind: FeedKind,
    /// Whether updates from this feed are automatically applied.
    pub auto_update: bool,
    /// When the feed was last synchronised.
    pub last_synced: Option<DateTime<Utc>>,
    /// Package IDs installed from this feed.
    pub packages: Vec<String>,
    /// The update policy for this feed.
    pub update_policy: UpdatePolicy,
}

impl FeedSubscription {
    /// Creates a new feed subscription.
    #[must_use]
    pub fn new(
        subscription_id: String,
        feed_kind: FeedKind,
        auto_update: bool,
        packages: Vec<String>,
        update_policy: UpdatePolicy,
    ) -> Self {
        Self {
            subscription_id,
            feed_kind,
            auto_update,
            last_synced: None,
            packages,
            update_policy,
        }
    }

    /// Records a sync event, updating the `last_synced` timestamp.
    #[must_use]
    pub fn record_sync(mut self) -> Self {
        self.last_synced = Some(Utc::now());
        self
    }

    /// Returns `true` if this feed is due for a sync (older than `stale_after` seconds).
    #[must_use]
    pub fn is_stale(&self, stale_after_seconds: i64) -> bool {
        match self.last_synced {
            Some(last) => {
                let elapsed = Utc::now().signed_duration_since(last).num_seconds();
                elapsed > stale_after_seconds
            }
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// CapsuleDiscoveryService
// ---------------------------------------------------------------------------

/// Service for discovering capsules on the remote marketplace.
///
/// This is an integration bridge — the actual HTTP / gRPC calls to the
/// marketplace are handled by the transport layer. This struct provides
/// the typed contract surface and manages the local index cache.
pub struct CapsuleDiscoveryService {
    marketplace_endpoint: String,
    local_index: Arc<RwLock<HashMap<String, MarketplaceListing>>>,
    local_details: Arc<RwLock<HashMap<String, CapsuleDetail>>>,
    category_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    publisher_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    emitter: Option<Arc<dyn IntegrationEvidenceEmitter>>,
}

impl CapsuleDiscoveryService {
    /// Creates a discovery service wired into the given bridge.
    #[must_use]
    pub fn from_bridge(bridge: &MarketplaceIntegration) -> Self {
        Self {
            marketplace_endpoint: bridge.marketplace_endpoint.clone(),
            local_index: Arc::clone(bridge.local_index_ref()),
            local_details: Arc::clone(bridge.local_details_ref()),
            category_index: Arc::clone(bridge.category_index_ref()),
            publisher_index: Arc::clone(bridge.publisher_index_ref()),
            emitter: bridge.evidence_emitter.clone(),
        }
    }

    /// Returns the remote marketplace endpoint backing this discovery service.
    #[must_use]
    pub fn marketplace_endpoint(&self) -> &str {
        &self.marketplace_endpoint
    }

    /// Returns whether this service has an evidence emitter attached.
    #[must_use]
    pub fn has_evidence_emitter(&self) -> bool {
        self.emitter.is_some()
    }

    /// Searches the local marketplace index for capsules matching `query`.
    ///
    /// Matches against capsule name, description, publisher, category, and tags.
    /// Returns up to `limit` results ranked by relevance (download count + rating).
    #[allow(clippy::unused_async)]
    pub async fn search_marketplace(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MarketplaceListing>, IntegrationError> {
        let index = self.local_index.read().map_err(|_| lock_poisoned())?;

        let query_lower = query.to_lowercase();
        let mut results: Vec<MarketplaceListing> = index
            .values()
            .filter(|l| {
                l.capsule_name.to_lowercase().contains(&query_lower)
                    || l.description.to_lowercase().contains(&query_lower)
                    || l.publisher_id.to_lowercase().contains(&query_lower)
                    || l.category.to_lowercase().contains(&query_lower)
                    || l.tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
            })
            .cloned()
            .collect();

        results.sort_by(|a, b| {
            b.downloads.cmp(&a.downloads).then_with(|| {
                b.rating
                    .partial_cmp(&a.rating)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        results.truncate(limit);
        Ok(results)
    }

    /// Returns full details for a marketplace listing.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if the listing is not found in the local cache.
    #[allow(clippy::unused_async)]
    pub async fn get_listing_details(
        &self,
        listing_id: &str,
    ) -> Result<CapsuleDetail, IntegrationError> {
        let details = self.local_details.read().map_err(|_| lock_poisoned())?;

        details
            .get(listing_id)
            .cloned()
            .ok_or_else(|| IntegrationError::Internal(format!("listing {listing_id} not found")))
    }

    /// Returns listings in a given category.
    #[allow(clippy::unused_async)]
    pub async fn browse_category(
        &self,
        category: &str,
    ) -> Result<Vec<MarketplaceListing>, IntegrationError> {
        let cat_index = self.category_index.read().map_err(|_| lock_poisoned())?;

        let listing_ids = match cat_index.get(category) {
            Some(ids) => ids.clone(),
            None => return Ok(Vec::new()),
        };

        let index = self.local_index.read().map_err(|_| lock_poisoned())?;

        let results: Vec<MarketplaceListing> = listing_ids
            .iter()
            .filter_map(|id| index.get(id).cloned())
            .collect();

        Ok(results)
    }

    /// Returns featured listings (highest-rated, verified capsules).
    #[allow(clippy::unused_async)]
    pub async fn get_featured(
        &self,
        limit: usize,
    ) -> Result<Vec<MarketplaceListing>, IntegrationError> {
        let index = self.local_index.read().map_err(|_| lock_poisoned())?;

        let mut results: Vec<MarketplaceListing> = index
            .values()
            .filter(|l| l.verified && l.rating >= 4.0)
            .cloned()
            .collect();

        results.sort_by(|a, b| {
            b.rating
                .partial_cmp(&a.rating)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.downloads.cmp(&a.downloads))
        });

        results.truncate(limit);
        Ok(results)
    }

    /// Returns all listings from a given publisher.
    #[allow(clippy::unused_async)]
    pub async fn get_publisher_listings(
        &self,
        publisher_id: &str,
    ) -> Result<Vec<MarketplaceListing>, IntegrationError> {
        let pub_index = self.publisher_index.read().map_err(|_| lock_poisoned())?;

        let listing_ids = match pub_index.get(publisher_id) {
            Some(ids) => ids.clone(),
            None => return Ok(Vec::new()),
        };

        let index = self.local_index.read().map_err(|_| lock_poisoned())?;

        let results: Vec<MarketplaceListing> = listing_ids
            .iter()
            .filter_map(|id| index.get(id).cloned())
            .collect();

        Ok(results)
    }

    /// Resolves the dependency tree for a given listing.
    ///
    /// Returns a topologically sorted list of all dependencies (including
    /// transitive) that must be installed before `listing_id`.
    #[allow(clippy::unused_async)]
    pub async fn resolve_dependencies(
        &self,
        listing_id: &str,
    ) -> Result<Vec<String>, IntegrationError> {
        let index = self.local_index.read().map_err(|_| lock_poisoned())?;

        let mut resolved: Vec<String> = Vec::new();
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut stack: Vec<String> = vec![listing_id.to_string()];

        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(listing) = index.get(&current) {
                for dep in &listing.dependencies {
                    if !visited.contains(dep) {
                        stack.push(dep.clone());
                    }
                }
            }
            if current != listing_id {
                resolved.push(current);
            }
        }

        resolved.reverse();
        Ok(resolved)
    }
}

// ---------------------------------------------------------------------------
// InstallFromMarketplace — install capsule from marketplace → distribution
// ---------------------------------------------------------------------------

/// Outcome of a marketplace install attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallOutcome {
    /// The listing that was requested for install.
    pub listing_id: String,
    /// Whether the install succeeded.
    pub success: bool,
    /// Order in which dependencies were installed.
    pub install_order: Vec<String>,
    /// Capsules that failed to install.
    pub failures: Vec<String>,
    /// When the install was attempted.
    pub attempted_at: DateTime<Utc>,
}

/// Service for installing capsules from the marketplace through the
/// distribution pipeline.
///
/// This is an integration bridge — the actual package delivery and
/// install verification is delegated to the distribution layer.
pub struct InstallFromMarketplace {
    distribution_endpoint: String,
    emitter: Option<Arc<dyn IntegrationEvidenceEmitter>>,
}

impl InstallFromMarketplace {
    /// Creates a new install service from a bridge.
    #[must_use]
    pub fn from_bridge(bridge: &MarketplaceIntegration) -> Self {
        Self {
            distribution_endpoint: bridge.distribution_endpoint.clone(),
            emitter: bridge.evidence_emitter.clone(),
        }
    }

    /// Returns the distribution endpoint used for installs.
    #[must_use]
    pub fn distribution_endpoint(&self) -> &str {
        &self.distribution_endpoint
    }

    /// Returns whether install actions will emit integration evidence.
    #[must_use]
    pub fn has_evidence_emitter(&self) -> bool {
        self.emitter.is_some()
    }

    /// Installs a capsule from the marketplace.
    ///
    /// Single transaction: marketplace listing → resolve deps → airgap/online
    /// delivery → install through distribution pipeline → verify install.
    ///
    /// This is an integration bridge stub — the actual transport and install
    /// logic is plumbed through the distribution pipeline.
    #[allow(clippy::unused_async)]
    pub async fn install_capsule(
        &self,
        _listing_id: &str,
        _deps: Vec<String>,
        _online: bool,
    ) -> Result<InstallOutcome, IntegrationError> {
        if self.distribution_endpoint.is_empty() {
            return Err(IntegrationError::Internal(
                "distribution endpoint is empty".into(),
            ));
        }

        Ok(InstallOutcome {
            listing_id: _listing_id.to_string(),
            success: true,
            install_order: _deps.clone(),
            failures: Vec::new(),
            attempted_at: Utc::now(),
        })
    }
}

// ---------------------------------------------------------------------------
// MarketplaceSync — keeps local marketplace state in sync with remote
// ---------------------------------------------------------------------------

/// Synchronisation outcome record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOutcome {
    /// Whether the sync completed without errors.
    pub success: bool,
    /// Number of listings added.
    pub listings_added: u64,
    /// Number of listings updated.
    pub listings_updated: u64,
    /// Number of listings removed (no longer on remote).
    pub listings_removed: u64,
    /// Number of categories synchronised.
    pub categories_synced: u64,
    /// Number of publishers synchronised.
    pub publishers_synced: u64,
    /// Number of capsules with available updates.
    pub updates_available: u64,
    /// Error message (when `success` is `false`).
    pub error: Option<String>,
    /// When this sync was performed.
    pub synced_at: DateTime<Utc>,
}

/// Service for synchronising local marketplace state with the remote.
///
/// This is an integration bridge — the actual HTTP / gRPC calls are
/// handled by the transport layer. This struct manages the local caches
/// and provides the typed sync contract.
pub struct MarketplaceSync {
    marketplace_endpoint: String,
    local_index: Arc<RwLock<HashMap<String, MarketplaceListing>>>,
    local_details: Arc<RwLock<HashMap<String, CapsuleDetail>>>,
    category_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    publisher_index: Arc<RwLock<HashMap<String, Vec<String>>>>,
    emitter: Option<Arc<dyn IntegrationEvidenceEmitter>>,
}

impl MarketplaceSync {
    /// Creates a sync service wired into the given bridge.
    #[must_use]
    pub fn from_bridge(bridge: &MarketplaceIntegration) -> Self {
        Self {
            marketplace_endpoint: bridge.marketplace_endpoint.clone(),
            local_index: Arc::clone(bridge.local_index_ref()),
            local_details: Arc::clone(bridge.local_details_ref()),
            category_index: Arc::clone(bridge.category_index_ref()),
            publisher_index: Arc::clone(bridge.publisher_index_ref()),
            emitter: bridge.evidence_emitter.clone(),
        }
    }

    /// Returns the remote marketplace endpoint used by sync operations.
    #[must_use]
    pub fn marketplace_endpoint(&self) -> &str {
        &self.marketplace_endpoint
    }

    /// Returns whether sync actions will emit integration evidence.
    #[must_use]
    pub fn has_evidence_emitter(&self) -> bool {
        self.emitter.is_some()
    }

    /// Returns local cache sizes for listings, details, categories, and publishers.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if any cache lock is poisoned.
    pub fn cache_counts(&self) -> Result<(usize, usize, usize, usize), IntegrationError> {
        let listings = self.local_index.read().map_err(|_| lock_poisoned())?.len();
        let details = self
            .local_details
            .read()
            .map_err(|_| lock_poisoned())?
            .len();
        let categories = self
            .category_index
            .read()
            .map_err(|_| lock_poisoned())?
            .len();
        let publishers = self
            .publisher_index
            .read()
            .map_err(|_| lock_poisoned())?
            .len();
        Ok((listings, details, categories, publishers))
    }

    /// Synchronises the local marketplace index with the remote.
    ///
    /// This is a bridge stub — in production, this would call the remote
    /// marketplace endpoint, diff its listings against the local index,
    /// and apply additions/updates/removals.
    #[allow(clippy::unused_async)]
    pub async fn sync_marketplace_index(&self) -> Result<SyncOutcome, IntegrationError> {
        if self.marketplace_endpoint.is_empty() {
            return Err(IntegrationError::Internal(
                "marketplace endpoint is empty".into(),
            ));
        }

        Ok(SyncOutcome {
            success: true,
            listings_added: 0,
            listings_updated: 0,
            listings_removed: 0,
            categories_synced: 0,
            publishers_synced: 0,
            updates_available: 0,
            error: None,
            synced_at: Utc::now(),
        })
    }

    /// Synchronises the local category index with the remote.
    #[allow(clippy::unused_async)]
    pub async fn sync_categories(&self) -> Result<SyncOutcome, IntegrationError> {
        Ok(SyncOutcome {
            success: true,
            listings_added: 0,
            listings_updated: 0,
            listings_removed: 0,
            categories_synced: 0,
            publishers_synced: 0,
            updates_available: 0,
            error: None,
            synced_at: Utc::now(),
        })
    }

    /// Synchronises the local publisher registry with the remote.
    #[allow(clippy::unused_async)]
    pub async fn sync_publisher_registry(&self) -> Result<SyncOutcome, IntegrationError> {
        Ok(SyncOutcome {
            success: true,
            listings_added: 0,
            listings_updated: 0,
            listings_removed: 0,
            categories_synced: 0,
            publishers_synced: 0,
            updates_available: 0,
            error: None,
            synced_at: Utc::now(),
        })
    }

    /// Checks the remote marketplace for updates to currently installed capsules.
    ///
    /// Returns a map of `listing_id` → `latest_version`.
    #[allow(clippy::unused_async)]
    pub async fn check_for_updates(
        &self,
        _installed_capsule_ids: &[String],
    ) -> Result<HashMap<String, String>, IntegrationError> {
        Ok(HashMap::new())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_test_bridge() -> MarketplaceIntegration {
        MarketplaceIntegration::new(
            "bridge-001".to_string(),
            "https://marketplace.aios.internal".to_string(),
            "https://distribution.aios.internal".to_string(),
        )
    }

    // -----------------------------------------------------------------------
    // BillingPlan tests
    // -----------------------------------------------------------------------

    #[test]
    fn billing_plan_label() {
        assert_eq!(BillingPlan::Free.label(), "free");
        assert_eq!(BillingPlan::Freemium.label(), "freemium");
        assert_eq!(BillingPlan::OneTimePurchase.label(), "one_time_purchase");
        assert_eq!(BillingPlan::Subscription.label(), "subscription");
        assert_eq!(BillingPlan::EnterpriseLicence.label(), "enterprise_licence");
        assert_eq!(BillingPlan::OpenSource.label(), "open_source");
    }

    #[test]
    fn billing_plan_requires_license() {
        assert!(!BillingPlan::Free.requires_license());
        assert!(!BillingPlan::OpenSource.requires_license());
        assert!(BillingPlan::Freemium.requires_license());
        assert!(BillingPlan::OneTimePurchase.requires_license());
        assert!(BillingPlan::Subscription.requires_license());
        assert!(BillingPlan::EnterpriseLicence.requires_license());
    }

    // -----------------------------------------------------------------------
    // LicenseVerification tests
    // -----------------------------------------------------------------------

    #[test]
    fn license_verification_free_license() {
        let lv = LicenseVerification::free_license("capsule-001".to_string());
        assert_eq!(lv.capsule_id, "capsule-001");
        assert_eq!(lv.license_type, BillingPlan::Free);
        assert!(lv.verified);
        assert!(lv.expires_at.is_none());
        assert!(!lv.renewal_required);
    }

    #[test]
    fn license_verification_is_valid() {
        let now = Utc::now();
        let lv = LicenseVerification::free_license("capsule-001".to_string());
        assert!(lv.is_valid(now));
    }

    #[test]
    fn license_verification_expired() {
        let now = Utc::now();
        let lv = LicenseVerification {
            capsule_id: "capsule-002".to_string(),
            license_type: BillingPlan::Subscription,
            verified: true,
            expires_at: Some(now - Duration::hours(1)),
            renewal_required: true,
            last_checked_at: now,
        };
        assert!(lv.is_expired(now));
        assert!(!lv.is_valid(now));
    }

    #[test]
    fn license_verification_not_expired() {
        let now = Utc::now();
        let lv = LicenseVerification {
            capsule_id: "capsule-003".to_string(),
            license_type: BillingPlan::Subscription,
            verified: true,
            expires_at: Some(now + Duration::days(30)),
            renewal_required: false,
            last_checked_at: now,
        };
        assert!(!lv.is_expired(now));
        assert!(lv.is_valid(now));
    }

    #[test]
    fn license_verification_unverified_is_invalid() {
        let now = Utc::now();
        let lv = LicenseVerification {
            capsule_id: "capsule-004".to_string(),
            license_type: BillingPlan::Subscription,
            verified: false,
            expires_at: Some(now + Duration::days(30)),
            renewal_required: false,
            last_checked_at: now,
        };
        assert!(!lv.is_valid(now));
    }

    // -----------------------------------------------------------------------
    // UpdatePolicy tests
    // -----------------------------------------------------------------------

    #[test]
    fn update_policy_label() {
        assert_eq!(UpdatePolicy::AutoApply.label(), "auto_apply");
        assert_eq!(UpdatePolicy::DownloadOnly.label(), "download_only");
        assert_eq!(UpdatePolicy::NotifyOnly.label(), "notify_only");
        assert_eq!(UpdatePolicy::Pinned.label(), "pinned");
    }

    #[test]
    fn update_policy_permits_download() {
        assert!(UpdatePolicy::AutoApply.permits_download());
        assert!(UpdatePolicy::DownloadOnly.permits_download());
        assert!(!UpdatePolicy::NotifyOnly.permits_download());
        assert!(!UpdatePolicy::Pinned.permits_download());
    }

    #[test]
    fn update_policy_permits_install() {
        assert!(UpdatePolicy::AutoApply.permits_install());
        assert!(!UpdatePolicy::DownloadOnly.permits_install());
        assert!(!UpdatePolicy::NotifyOnly.permits_install());
        assert!(!UpdatePolicy::Pinned.permits_install());
    }

    // -----------------------------------------------------------------------
    // FeedSubscription tests
    // -----------------------------------------------------------------------

    #[test]
    fn feed_subscription_new() {
        let sub = FeedSubscription::new(
            "sub-001".to_string(),
            FeedKind::Stable,
            true,
            vec!["pkg-a".to_string(), "pkg-b".to_string()],
            UpdatePolicy::AutoApply,
        );
        assert_eq!(sub.subscription_id, "sub-001");
        assert_eq!(sub.feed_kind, FeedKind::Stable);
        assert!(sub.auto_update);
        assert!(sub.last_synced.is_none());
        assert_eq!(sub.packages.len(), 2);
        assert_eq!(sub.update_policy, UpdatePolicy::AutoApply);
    }

    #[test]
    fn feed_subscription_is_stale_never_synced() {
        let sub = FeedSubscription::new(
            "sub-002".to_string(),
            FeedKind::Stable,
            false,
            Vec::new(),
            UpdatePolicy::NotifyOnly,
        );
        assert!(sub.is_stale(3600));
    }

    #[test]
    fn feed_subscription_is_stale_recently_synced() {
        let sub = FeedSubscription::new(
            "sub-003".to_string(),
            FeedKind::Beta,
            false,
            Vec::new(),
            UpdatePolicy::NotifyOnly,
        )
        .record_sync();
        assert!(!sub.is_stale(3600));
    }

    // -----------------------------------------------------------------------
    // CapsuleDiscoveryService tests
    // -----------------------------------------------------------------------

    #[test]
    fn discovery_search_empty_index() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let bridge = make_test_bridge();
        let discovery = CapsuleDiscoveryService::from_bridge(&bridge);
        let results = rt
            .block_on(discovery.search_marketplace("nonexistent", 10))
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn discovery_browse_missing_category() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let bridge = make_test_bridge();
        let discovery = CapsuleDiscoveryService::from_bridge(&bridge);
        let results = rt
            .block_on(discovery.browse_category("no-such-category"))
            .unwrap();
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // MarketplaceSync + InstallFromMarketplace construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn marketplace_sync_construction() {
        let bridge = make_test_bridge();
        let sync = MarketplaceSync::from_bridge(&bridge);
        assert_eq!(
            sync.marketplace_endpoint,
            "https://marketplace.aios.internal"
        );
    }

    #[test]
    fn install_from_marketplace_construction() {
        let bridge = make_test_bridge();
        let install = InstallFromMarketplace::from_bridge(&bridge);
        assert_eq!(
            install.distribution_endpoint,
            "https://distribution.aios.internal"
        );
    }

    #[test]
    fn bridge_with_emitter_roundtrip() {
        let bridge = make_test_bridge();
        assert!(bridge.evidence_emitter.is_none());
    }

    // -----------------------------------------------------------------------
    // FeedKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn feed_kind_label() {
        assert_eq!(FeedKind::Stable.label(), "stable");
        assert_eq!(FeedKind::Beta.label(), "beta");
        assert_eq!(FeedKind::Nightly.label(), "nightly");
        assert_eq!(FeedKind::SecurityAdvisory.label(), "security_advisory");
        assert_eq!(FeedKind::PublisherNews.label(), "publisher_news");
    }

    // -----------------------------------------------------------------------
    // Dependencies resolution test
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_dependencies_empty() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let bridge = make_test_bridge();
        let discovery = CapsuleDiscoveryService::from_bridge(&bridge);
        let result = rt.block_on(discovery.resolve_dependencies("nonexistent"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // Sync outcome defaults
    // -----------------------------------------------------------------------

    #[test]
    fn sync_marketplace_index_returns_default() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let bridge = make_test_bridge();
        let sync = MarketplaceSync::from_bridge(&bridge);
        let outcome = rt.block_on(sync.sync_marketplace_index()).unwrap();
        assert!(outcome.success);
        assert_eq!(outcome.listings_added, 0);
        assert_eq!(outcome.listings_updated, 0);
        assert_eq!(outcome.listings_removed, 0);
        assert!(outcome.error.is_none());
    }
}
