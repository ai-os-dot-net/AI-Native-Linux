use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::IntegrationError;
use crate::evidence::IntegrationEvidenceEmitter;
use crate::ids::ExternalRepoBridgeId;

/// Closed taxonomy of known external repository sources.
///
/// Each variant maps to a canonical upstream ecosystem that AIOS bridges into.
/// Adding a variant is a versioned spec change; parsers MUST reject unknowns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExternalRepoKind {
    /// Flathub Flatpak distribution (flathub.org).
    Flathub,
    /// Snap Store (snapcraft.io).
    SnapStore,
    /// AppImageHub community catalogue.
    AppImageHub,
    /// Docker Hub OCI registry.
    DockerHub,
    /// Quay.io container registry.
    QuayIo,
    /// GitHub Releases (release artifacts).
    GitHubReleases,
    /// GitLab Releases (release artifacts).
    GitLabReleases,
    /// Nix Packages collection (nixpkgs).
    NixPkgs,
    /// Arch Linux AUR (Arch User Repository).
    ArchAur,
    /// Debian APT repositories.
    DebianApt,
    /// Ubuntu PPA (Personal Package Archive).
    UbuntuPpa,
    /// Fedora Copr build service.
    FedoraCopr,
    /// Homebrew Cask (macOS GUI apps).
    BrewCask,
    /// Chocolatey Windows package manager.
    Chocolatey,
    /// Microsoft WinGet package manager.
    Winget,
}

impl ExternalRepoKind {
    /// Canonical label for this repo kind (used for filtering and display).
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Flathub => "Flathub",
            Self::SnapStore => "SnapStore",
            Self::AppImageHub => "AppImageHub",
            Self::DockerHub => "DockerHub",
            Self::QuayIo => "QuayIo",
            Self::GitHubReleases => "GitHubReleases",
            Self::GitLabReleases => "GitLabReleases",
            Self::NixPkgs => "NixPkgs",
            Self::ArchAur => "ArchAur",
            Self::DebianApt => "DebianApt",
            Self::UbuntuPpa => "UbuntuPpa",
            Self::FedoraCopr => "FedoraCopr",
            Self::BrewCask => "BrewCask",
            Self::Chocolatey => "Chocolatey",
            Self::Winget => "Winget",
        }
    }

    /// Returns true if this repo kind requires network access for discovery.
    #[must_use]
    pub const fn requires_network(&self) -> bool {
        matches!(
            self,
            Self::Flathub
                | Self::SnapStore
                | Self::AppImageHub
                | Self::DockerHub
                | Self::QuayIo
                | Self::GitHubReleases
                | Self::GitLabReleases
                | Self::NixPkgs
                | Self::ArchAur
                | Self::DebianApt
                | Self::UbuntuPpa
                | Self::FedoraCopr
                | Self::BrewCask
                | Self::Chocolatey
                | Self::Winget
        )
    }

    /// Returns true if this repo kind is a container registry.
    #[must_use]
    pub const fn is_container_registry(&self) -> bool {
        matches!(self, Self::DockerHub | Self::QuayIo)
    }

    /// Returns true if this repo kind is a distro package manager.
    #[must_use]
    pub const fn is_distro_repo(&self) -> bool {
        matches!(
            self,
            Self::DebianApt | Self::UbuntuPpa | Self::FedoraCopr | Self::ArchAur
        )
    }
}

/// Sync state for an external repository bridge.
///
/// Tracks whether the bridge has successfully synchronised its local index with
/// the external source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RepoSyncState {
    /// Bridge has never been synchronised.
    NotSynced,
    /// A sync operation is currently in progress.
    Syncing,
    /// Most recent sync completed successfully.
    Synced,
    /// Most recent sync failed with an error.
    SyncFailed,
    /// Sync succeeded but with warnings (e.g. partial index, stale metadata).
    Degraded,
    /// Bridge has been administratively disabled; no sync will run.
    Disabled,
}

impl RepoSyncState {
    /// Whether this state indicates the bridge is healthy enough to serve queries.
    #[must_use]
    pub const fn is_queryable(&self) -> bool {
        matches!(self, Self::Synced | Self::Degraded)
    }
}

/// A typed bridge connection to an external package repository.
///
/// Each bridge targets exactly one `ExternalRepoKind` and carries the
/// configuration needed to reach and authenticate against the upstream source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRepoBridge {
    /// Unique bridge identifier.
    pub bridge_id: ExternalRepoBridgeId,
    /// The external repository kind this bridge connects to.
    pub kind: ExternalRepoKind,
    /// Base URL endpoint for the upstream repository API or index.
    pub endpoint: String,
    /// Whether authentication (token, key, OAuth) is required for this bridge.
    pub auth_required: bool,
    /// Human-readable description of rate limits applied to this bridge.
    pub rate_limit_info: String,
    /// UTC timestamp of the most recent successful sync.
    pub last_synced: Option<DateTime<Utc>>,
    /// Desired interval between sync operations.
    pub sync_interval: Duration,
}

/// An upstream package discovered from an external repository, before
/// translation into an AIOS-native capsule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExternalPackage {
    /// Unique package identifier within the source ecosystem.
    pub package_id: String,
    /// The external repository source this package came from.
    pub source_kind: ExternalRepoKind,
    /// URL to the package's upstream listing or artifact.
    pub source_url: String,
    /// Original name as published in the external source.
    pub original_name: String,
    /// Original version string as published in the external source.
    pub original_version: String,
    /// Target format the package was translated into (e.g. "aios-capsule-v1").
    pub translated_format: Option<String>,
    /// Candidate AIOS capsule identifier after translation, if applicable.
    pub capsule_candidate: Option<String>,
    /// Compatibility score: 0–100. Higher means more likely to run correctly.
    pub compatibility_score: u8,
    /// Whether the package requires a sandbox to run.
    pub sandbox_required: bool,
}

impl ExternalPackage {
    /// Creates a new external package with default scoring.
    #[must_use]
    pub fn new(
        package_id: String,
        source_kind: ExternalRepoKind,
        source_url: String,
        original_name: String,
        original_version: String,
        sandbox_required: bool,
    ) -> Self {
        Self {
            package_id,
            source_kind,
            source_url,
            original_name,
            original_version,
            translated_format: None,
            capsule_candidate: None,
            compatibility_score: 0,
            sandbox_required,
        }
    }

    /// Sets the translation metadata in one call.
    #[must_use]
    pub fn with_translation(mut self, format: String, capsule_id: String) -> Self {
        self.translated_format = Some(format);
        self.capsule_candidate = Some(capsule_id);
        self
    }

    /// Sets the compatibility score, clamping to 0–100.
    pub fn set_compatibility(&mut self, score: u8) {
        self.compatibility_score = score.min(100);
    }
}

/// Security profile that gates which external repos are permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Standard profile: all repos permitted subject to trust checks.
    Standard,
    /// STIG-aligned: all external repos disabled per DISA STIG controls.
    StigAligned,
    /// Air-gapped high-security: live internet repos disabled; only airgap
    /// stores and signed local mirrors permitted.
    AirgapHigh,
}

/// Returns the list of `ExternalRepoKind` values permitted under a given profile.
///
/// STIG_ALIGNED disables all external repos.
/// AIRGAP_HIGH disables all live internet repos (only airgap stores and signed
/// local mirrors) — in practice this means no external repos are reachable.
#[must_use]
pub const fn permitted_repo_kinds(profile: SecurityProfile) -> &'static [ExternalRepoKind] {
    match profile {
        SecurityProfile::StigAligned | SecurityProfile::AirgapHigh => &[],
        SecurityProfile::Standard => &[
            ExternalRepoKind::Flathub,
            ExternalRepoKind::SnapStore,
            ExternalRepoKind::AppImageHub,
            ExternalRepoKind::DockerHub,
            ExternalRepoKind::QuayIo,
            ExternalRepoKind::GitHubReleases,
            ExternalRepoKind::GitLabReleases,
            ExternalRepoKind::NixPkgs,
            ExternalRepoKind::ArchAur,
            ExternalRepoKind::DebianApt,
            ExternalRepoKind::UbuntuPpa,
            ExternalRepoKind::FedoraCopr,
            ExternalRepoKind::BrewCask,
            ExternalRepoKind::Chocolatey,
            ExternalRepoKind::Winget,
        ],
    }
}

/// Returns true if the given repo kind is permitted under the profile.
#[must_use]
pub fn repo_kind_permitted(kind: ExternalRepoKind, profile: SecurityProfile) -> bool {
    permitted_repo_kinds(profile).contains(&kind)
}

/// Health-check diagnostics for an external repository bridge.
///
/// Methods on this struct are thin typed wrappers that return results suitable
/// for telemetry and operator-facing dashboards. Real implementations would
/// perform actual HTTP health probes against the configured endpoint.
#[derive(Debug, Clone)]
pub struct RepoHealthCheck {
    /// The bridge whose health is being checked.
    pub bridge_id: ExternalRepoBridgeId,
    /// The endpoint URL to probe.
    pub endpoint: String,
    /// Whether auth is configured and valid.
    pub auth_configured: bool,
}

impl RepoHealthCheck {
    /// Creates a health check from a bridge configuration.
    #[must_use]
    pub fn from_bridge(bridge: &ExternalRepoBridge) -> Self {
        Self {
            bridge_id: bridge.bridge_id.clone(),
            endpoint: bridge.endpoint.clone(),
            auth_configured: !bridge.auth_required,
        }
    }

    /// Checks whether the upstream endpoint is reachable.
    ///
    /// Returns `true` if reachable, `false` otherwise.
    /// Does not fail — unreachable is a normal operational state.
    #[must_use]
    #[allow(clippy::unused_async)]
    pub async fn check_reachability(&self) -> bool {
        // Stub — real impl performs an HTTP HEAD or TCP connect.
        !self.endpoint.is_empty()
    }

    /// Checks rate-limit status against the upstream.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if rate limits are exhausted or the endpoint
    /// returned HTTP 429.
    #[allow(clippy::unused_async)]
    pub async fn check_rate_limits(&self) -> Result<(), IntegrationError> {
        // Stub — real impl checks HTTP 429 / Retry-After headers.
        if self.endpoint.is_empty() {
            return Err(IntegrationError::Internal(
                "endpoint is empty; cannot check rate limits".into(),
            ));
        }
        Ok(())
    }

    /// Checks whether authentication credentials are valid.
    ///
    /// Returns `true` if auth is valid or not required; `false` if auth is
    /// required but missing or expired.
    #[must_use]
    #[allow(clippy::unused_async)]
    pub async fn check_auth_valid(&self) -> bool {
        // Stub — real impl validates tokens against the upstream.
        self.auth_configured
    }

    /// Checks whether the local index is fresh relative to `now`.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if `last_synced` is `None` (never synced).
    #[allow(clippy::unused_async)]
    pub async fn check_index_freshness(
        &self,
        last_synced: Option<DateTime<Utc>>,
        sync_interval: Duration,
        now: DateTime<Utc>,
    ) -> Result<bool, IntegrationError> {
        let last =
            last_synced.ok_or_else(|| IntegrationError::Internal("index never synced".into()))?;
        Ok(now <= last + sync_interval)
    }
}

// ---------------------------------------------------------------------------
// ExternalRepoRegistry
// ---------------------------------------------------------------------------

fn lock_poisoned() -> IntegrationError {
    IntegrationError::Internal("lock poisoned".into())
}

/// Registry of external repository bridges.
///
/// Manages bridge registration, package discovery, package translation via
/// Package Rosetta, update monitoring, and CVE vulnerability watch.
/// All external I/O is stubbed; actual network operations would require
/// protocol-specific fetch implementations.
pub struct ExternalRepoRegistry {
    bridges: RwLock<HashMap<ExternalRepoBridgeId, ExternalRepoBridge>>,
    packages: RwLock<Vec<ExternalPackage>>,
    emitter: Option<Arc<dyn IntegrationEvidenceEmitter>>,
}

impl ExternalRepoRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bridges: RwLock::new(HashMap::new()),
            packages: RwLock::new(Vec::new()),
            emitter: None,
        }
    }

    /// Attach an optional [`IntegrationEvidenceEmitter`] for chain-of-custody
    /// evidence emission when bridges are registered or packages translated.
    #[must_use]
    pub fn with_emitter(mut self, emitter: Arc<dyn IntegrationEvidenceEmitter>) -> Self {
        self.emitter = Some(emitter);
        self
    }

    /// Registers an external repository bridge.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if a bridge with the same [`ExternalRepoBridgeId`]
    /// already exists or a lock is poisoned.
    #[allow(clippy::unused_async)]
    pub async fn register_bridge(
        &self,
        bridge: ExternalRepoBridge,
    ) -> Result<(), IntegrationError> {
        let mut bridges = self.bridges.write().map_err(|_| lock_poisoned())?;
        if bridges.contains_key(&bridge.bridge_id) {
            return Err(IntegrationError::Internal(
                "bridge_id already exists".into(),
            ));
        }
        bridges.insert(bridge.bridge_id.clone(), bridge);
        drop(bridges);
        Ok(())
    }

    /// Removes a bridge from the registry.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if the bridge is unknown or a lock is poisoned.
    #[allow(clippy::unused_async)]
    pub async fn unregister_bridge(
        &self,
        bridge_id: &ExternalRepoBridgeId,
    ) -> Result<(), IntegrationError> {
        let mut bridges = self.bridges.write().map_err(|_| lock_poisoned())?;
        if bridges.remove(bridge_id).is_none() {
            return Err(IntegrationError::Internal("unknown bridge_id".into()));
        }
        drop(bridges);
        Ok(())
    }

    /// Discovers packages from an external repository.
    ///
    /// If `query` is `Some`, filters results to packages whose name or
    /// identifier contains the query string.
    /// Currently returns packages that have been stored in the local registry;
    /// a real implementation would fetch from the upstream API.
    #[must_use]
    #[allow(clippy::unused_async)]
    pub async fn discover_packages(
        &self,
        kind: ExternalRepoKind,
        query: Option<&str>,
    ) -> Vec<ExternalPackage> {
        let packages = self.packages.read().ok();
        packages
            .map(|p| {
                p.iter()
                    .filter(|pkg| pkg.source_kind == kind)
                    .filter(|pkg| {
                        if let Some(q) = query {
                            pkg.original_name.to_lowercase().contains(&q.to_lowercase())
                                || pkg.package_id.to_lowercase().contains(&q.to_lowercase())
                        } else {
                            true
                        }
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Adds a discovered package to the internal catalogue.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if a lock is poisoned.
    #[allow(clippy::unused_async)]
    pub async fn store_package(&self, package: ExternalPackage) -> Result<(), IntegrationError> {
        let mut packages = self.packages.write().map_err(|_| lock_poisoned())?;
        packages.push(package);
        drop(packages);
        Ok(())
    }

    /// Translates an external package into an AIOS capsule via Package Rosetta.
    ///
    /// Sets the `translated_format` to `"aios-capsule-v1"` and derives a
    /// `capsule_candidate` identifier from the source kind and original name.
    /// Returns the translated package without mutating the stored catalogue.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if the package has no `original_name`.
    #[allow(clippy::unused_async)]
    pub async fn translate_package(
        &self,
        package: &ExternalPackage,
    ) -> Result<ExternalPackage, IntegrationError> {
        if package.original_name.is_empty() {
            return Err(IntegrationError::Internal(
                "cannot translate package with empty original_name".into(),
            ));
        }
        let capsule_id = format!(
            "capsule:{}:{}",
            package.source_kind.label().to_lowercase(),
            package.original_name.to_lowercase().replace(' ', "-"),
        );
        Ok(ExternalPackage {
            package_id: package.package_id.clone(),
            source_kind: package.source_kind,
            source_url: package.source_url.clone(),
            original_name: package.original_name.clone(),
            original_version: package.original_version.clone(),
            translated_format: Some("aios-capsule-v1".into()),
            capsule_candidate: Some(capsule_id),
            compatibility_score: package.compatibility_score,
            sandbox_required: package.sandbox_required,
        })
    }

    /// Monitors an external repository for new versions of known packages.
    ///
    /// Returns packages whose `original_version` has changed since last sync.
    /// This is a stub; a real implementation would compare against a cached
    /// version map from the previous sync.
    #[must_use]
    #[allow(clippy::unused_async)]
    pub async fn monitor_updates(&self, kind: ExternalRepoKind) -> Vec<ExternalPackage> {
        let packages = self.packages.read().ok();
        packages
            .map(|p| {
                p.iter()
                    .filter(|pkg| pkg.source_kind == kind)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Checks CVE feeds for packages installed from external sources.
    ///
    /// Returns a list of CVE alert strings (e.g. `"CVE-2024-1234 affects
    /// package <id>"`). This is a stub; a real implementation would query
    /// the configured CVE feed against the list of packages.
    #[must_use]
    #[allow(clippy::unused_async)]
    pub async fn vulnerability_watch(&self) -> Vec<String> {
        let packages = self.packages.read().ok();
        packages
            .map(|p| {
                p.iter()
                    .filter(|pkg| pkg.sandbox_required)
                    .map(|pkg| {
                        format!(
                            "CVE-WATCH: package {} ({}) from {:?} requires sandbox — monitor for advisories",
                            pkg.original_name,
                            pkg.original_version,
                            pkg.source_kind,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns the bridge associated with the given id.
    #[must_use]
    #[allow(clippy::unused_async)]
    pub async fn get_bridge(&self, bridge_id: &ExternalRepoBridgeId) -> Option<ExternalRepoBridge> {
        let bridges = self.bridges.read().ok()?;
        bridges.get(bridge_id).cloned()
    }

    /// Lists all registered bridges.
    #[must_use]
    #[allow(clippy::unused_async)]
    pub async fn list_bridges(&self) -> Vec<ExternalRepoBridge> {
        let bridges = self.bridges.read().ok();
        bridges
            .map(|b| b.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Lists all known external packages, optionally filtered by source kind.
    #[must_use]
    #[allow(clippy::unused_async)]
    pub async fn list_packages(&self, kind: Option<ExternalRepoKind>) -> Vec<ExternalPackage> {
        let packages = self.packages.read().ok();
        packages
            .map(|p| {
                p.iter()
                    .filter(|pkg| kind.is_none_or(|k| pkg.source_kind == k))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for ExternalRepoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_test_bridge(id: &str) -> ExternalRepoBridge {
        ExternalRepoBridge {
            bridge_id: ExternalRepoBridgeId(id.into()),
            kind: ExternalRepoKind::Flathub,
            endpoint: "https://dl.flathub.org/repo/".into(),
            auth_required: false,
            rate_limit_info: "60 fetches/hour".into(),
            last_synced: Some(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()),
            sync_interval: Duration::hours(6),
        }
    }

    fn make_test_package() -> ExternalPackage {
        ExternalPackage::new(
            "org.gimp.GIMP".into(),
            ExternalRepoKind::Flathub,
            "https://flathub.org/apps/org.gimp.GIMP".into(),
            "GIMP".into(),
            "2.10.38".into(),
            true,
        )
    }

    // ------------------------------------------------------------------
    // ExternalRepoKind
    // ------------------------------------------------------------------

    #[test]
    fn repo_kind_label_is_non_empty() {
        for kind in &[
            ExternalRepoKind::Flathub,
            ExternalRepoKind::SnapStore,
            ExternalRepoKind::AppImageHub,
            ExternalRepoKind::DockerHub,
            ExternalRepoKind::QuayIo,
            ExternalRepoKind::GitHubReleases,
            ExternalRepoKind::GitLabReleases,
            ExternalRepoKind::NixPkgs,
            ExternalRepoKind::ArchAur,
            ExternalRepoKind::DebianApt,
            ExternalRepoKind::UbuntuPpa,
            ExternalRepoKind::FedoraCopr,
            ExternalRepoKind::BrewCask,
            ExternalRepoKind::Chocolatey,
            ExternalRepoKind::Winget,
        ] {
            assert!(!kind.label().is_empty(), "{kind:?} label is empty");
        }
    }

    #[test]
    fn repo_kind_all_require_network() {
        for kind in &[
            ExternalRepoKind::Flathub,
            ExternalRepoKind::SnapStore,
            ExternalRepoKind::AppImageHub,
            ExternalRepoKind::DockerHub,
            ExternalRepoKind::QuayIo,
            ExternalRepoKind::GitHubReleases,
            ExternalRepoKind::GitLabReleases,
            ExternalRepoKind::NixPkgs,
            ExternalRepoKind::ArchAur,
            ExternalRepoKind::DebianApt,
            ExternalRepoKind::UbuntuPpa,
            ExternalRepoKind::FedoraCopr,
            ExternalRepoKind::BrewCask,
            ExternalRepoKind::Chocolatey,
            ExternalRepoKind::Winget,
        ] {
            assert!(kind.requires_network(), "{kind:?} should require network");
        }
    }

    #[test]
    fn container_registry_detection() {
        assert!(ExternalRepoKind::DockerHub.is_container_registry());
        assert!(ExternalRepoKind::QuayIo.is_container_registry());
        assert!(!ExternalRepoKind::Flathub.is_container_registry());
        assert!(!ExternalRepoKind::ArchAur.is_container_registry());
    }

    #[test]
    fn distro_repo_detection() {
        assert!(ExternalRepoKind::DebianApt.is_distro_repo());
        assert!(ExternalRepoKind::UbuntuPpa.is_distro_repo());
        assert!(ExternalRepoKind::FedoraCopr.is_distro_repo());
        assert!(ExternalRepoKind::ArchAur.is_distro_repo());
        assert!(!ExternalRepoKind::DockerHub.is_distro_repo());
        assert!(!ExternalRepoKind::Flathub.is_distro_repo());
    }

    // ------------------------------------------------------------------
    // RepoSyncState
    // ------------------------------------------------------------------

    #[test]
    fn sync_state_queryable() {
        assert!(RepoSyncState::Synced.is_queryable());
        assert!(RepoSyncState::Degraded.is_queryable());
        assert!(!RepoSyncState::NotSynced.is_queryable());
        assert!(!RepoSyncState::Syncing.is_queryable());
        assert!(!RepoSyncState::SyncFailed.is_queryable());
        assert!(!RepoSyncState::Disabled.is_queryable());
    }

    // ------------------------------------------------------------------
    // SecurityProfile gates
    // ------------------------------------------------------------------

    #[test]
    fn stig_aligned_disables_all_repos() {
        assert!(permitted_repo_kinds(SecurityProfile::StigAligned).is_empty());
    }

    #[test]
    fn airgap_high_disables_all_repos() {
        assert!(permitted_repo_kinds(SecurityProfile::AirgapHigh).is_empty());
    }

    #[test]
    fn standard_profile_permits_all_repos() {
        let permitted = permitted_repo_kinds(SecurityProfile::Standard);
        assert_eq!(permitted.len(), 15);
        assert!(permitted.contains(&ExternalRepoKind::Flathub));
    }

    #[test]
    fn repo_kind_permitted_under_stig() {
        assert!(!repo_kind_permitted(
            ExternalRepoKind::Flathub,
            SecurityProfile::StigAligned
        ));
        assert!(!repo_kind_permitted(
            ExternalRepoKind::DockerHub,
            SecurityProfile::AirgapHigh
        ));
        assert!(repo_kind_permitted(
            ExternalRepoKind::Winget,
            SecurityProfile::Standard
        ));
    }

    // ------------------------------------------------------------------
    // ExternalRepoRegistry
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn register_and_list_bridges() {
        let reg = ExternalRepoRegistry::new();
        let bridge = make_test_bridge("br-001");
        reg.register_bridge(bridge).await.expect("register");
        let list = reg.list_bridges().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].bridge_id.0, "br-001");
    }

    #[tokio::test]
    async fn register_duplicate_bridge_fails() {
        let reg = ExternalRepoRegistry::new();
        let bridge = make_test_bridge("br-002");
        reg.register_bridge(bridge.clone())
            .await
            .expect("first register");
        let result = reg.register_bridge(bridge).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn unregister_bridge() {
        let reg = ExternalRepoRegistry::new();
        let bridge = make_test_bridge("br-003");
        reg.register_bridge(bridge).await.expect("register");
        let bid = ExternalRepoBridgeId("br-003".into());
        reg.unregister_bridge(&bid).await.expect("unregister");
        assert_eq!(reg.list_bridges().await.len(), 0);
    }

    #[tokio::test]
    async fn unregister_unknown_bridge_fails() {
        let reg = ExternalRepoRegistry::new();
        let bid = ExternalRepoBridgeId("nonexistent".into());
        let result = reg.unregister_bridge(&bid).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn store_and_discover_packages() {
        let reg = ExternalRepoRegistry::new();
        let pkg = make_test_package();
        reg.store_package(pkg).await.expect("store");
        let found = reg
            .discover_packages(ExternalRepoKind::Flathub, Some("gimp"))
            .await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].original_name, "GIMP");
    }

    #[tokio::test]
    async fn discover_packages_with_missing_query_returns_empty() {
        let reg = ExternalRepoRegistry::new();
        let pkg = make_test_package();
        reg.store_package(pkg).await.expect("store");
        let found = reg
            .discover_packages(ExternalRepoKind::Flathub, Some("nonexistent"))
            .await;
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn translate_package_produces_capsule() {
        let reg = ExternalRepoRegistry::new();
        let pkg = make_test_package();
        let translated = reg.translate_package(&pkg).await.expect("translate");
        assert_eq!(
            translated.translated_format.as_deref(),
            Some("aios-capsule-v1")
        );
        assert!(translated
            .capsule_candidate
            .as_deref()
            .is_some_and(|c| c.starts_with("capsule:flathub:gimp")));
    }

    #[tokio::test]
    async fn translate_empty_name_fails() {
        let reg = ExternalRepoRegistry::new();
        let pkg = ExternalPackage::new(
            "bad-1".into(),
            ExternalRepoKind::Flathub,
            "https://example.com".into(),
            String::new(),
            "1.0".into(),
            false,
        );
        let result = reg.translate_package(&pkg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn vulnerability_watch_flags_sandboxed_packages() {
        let reg = ExternalRepoRegistry::new();
        let sandboxed = make_test_package();
        let unsandboxed = ExternalPackage::new(
            "com.example.Safe".into(),
            ExternalRepoKind::Flathub,
            "https://example.com".into(),
            "SafeApp".into(),
            "1.0".into(),
            false,
        );
        reg.store_package(sandboxed).await.expect("store sandboxed");
        reg.store_package(unsandboxed)
            .await
            .expect("store unsandboxed");
        let alerts = reg.vulnerability_watch().await;
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].contains("GIMP"));
    }

    // ------------------------------------------------------------------
    // RepoHealthCheck
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn health_check_reachability_stub() {
        let bridge = make_test_bridge("br-hc");
        let hc = RepoHealthCheck::from_bridge(&bridge);
        assert!(hc.check_reachability().await);
    }

    #[tokio::test]
    async fn health_check_rate_limits_empty_endpoint_fails() {
        let hc = RepoHealthCheck {
            bridge_id: ExternalRepoBridgeId("br-empty".into()),
            endpoint: String::new(),
            auth_configured: false,
        };
        let result = hc.check_rate_limits().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn health_check_auth_stub() {
        let hc = RepoHealthCheck {
            bridge_id: ExternalRepoBridgeId("br-auth".into()),
            endpoint: "https://example.com".into(),
            auth_configured: true,
        };
        assert!(hc.check_auth_valid().await);
    }

    #[tokio::test]
    async fn health_check_index_never_synced_fails() {
        let hc = RepoHealthCheck {
            bridge_id: ExternalRepoBridgeId("br-idx".into()),
            endpoint: "https://example.com".into(),
            auth_configured: true,
        };
        let now = Utc::now();
        let result = hc
            .check_index_freshness(None, Duration::hours(6), now)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn health_check_index_fresh() {
        let hc = RepoHealthCheck {
            bridge_id: ExternalRepoBridgeId("br-fresh".into()),
            endpoint: "https://example.com".into(),
            auth_configured: true,
        };
        let now = Utc::now();
        let last = now - Duration::hours(1);
        let result = hc
            .check_index_freshness(Some(last), Duration::hours(6), now)
            .await;
        assert!(result.is_ok_and(|f| f));
    }

    #[tokio::test]
    async fn health_check_index_stale() {
        let hc = RepoHealthCheck {
            bridge_id: ExternalRepoBridgeId("br-stale".into()),
            endpoint: "https://example.com".into(),
            auth_configured: true,
        };
        let now = Utc::now();
        let last = now - Duration::hours(8);
        let result = hc
            .check_index_freshness(Some(last), Duration::hours(6), now)
            .await;
        assert!(result.is_ok_and(|f| !f));
    }

    // ------------------------------------------------------------------
    // ExternalPackage
    // ------------------------------------------------------------------

    #[test]
    fn package_with_translation() {
        let pkg = make_test_package()
            .with_translation("aios-capsule-v1".into(), "capsule:flathub:gimp".into());
        assert_eq!(pkg.translated_format.as_deref(), Some("aios-capsule-v1"));
        assert_eq!(
            pkg.capsule_candidate.as_deref(),
            Some("capsule:flathub:gimp")
        );
    }

    #[test]
    fn package_compatibility_clamped() {
        let mut pkg = make_test_package();
        pkg.set_compatibility(150);
        assert_eq!(pkg.compatibility_score, 100);
        pkg.set_compatibility(50);
        assert_eq!(pkg.compatibility_score, 50);
    }

    #[test]
    fn package_default_compatibility_is_zero() {
        let pkg = make_test_package();
        assert_eq!(pkg.compatibility_score, 0);
    }

    // ------------------------------------------------------------------
    // Default impl
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn default_registry_is_empty() {
        let reg = ExternalRepoRegistry::default();
        assert!(reg.list_bridges().await.is_empty());
        assert!(reg.list_packages(None).await.is_empty());
    }
}
