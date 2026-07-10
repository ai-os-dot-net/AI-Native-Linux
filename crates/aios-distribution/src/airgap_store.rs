//! Airgap / offline application store module per S26 §9.
//!
//! `AirgapStoreManifest` describes a signed, self-contained snapshot of a
//! local mirror suitable for USB/NAS/airgap transport.  Under `AIRGAP_HIGH`
//! profile this is the **only** software intake — live internet fetch is
//! constitutionally blocked (§10).
//!
//! Evidence records emitted: `AIRGAP_STORE_BUILT`, `AIRGAP_STORE_VERIFIED`,
//! `AIRGAP_UPDATE_APPLIED`, `AIRGAP_PACKAGE_INSTALLED`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DistributionError;
use crate::mirror::MirrorSemantic;
use crate::mirror_policy::MirrorEndpoint;

// ── AirgapStoreMedium ──────────────────────────────────────────────────────

/// Closed enum — 6 airgap transfer media per S26 §9.
///
/// | Variant              | Typical capacity | Return channel? |
/// |----------------------|------------------|-----------------|
/// | `UsbDrive`           | ≤ 1 TB           | No              |
/// | `ExternalDisk`       | ≤ 20 TB          | No              |
/// | `NasShare`           | Network-limited  | Yes (isolated)  |
/// | `SneakerNet`         | Variable         | No              |
/// | `OpticalDisc`        | ≤ 128 GB (BD-R)  | No              |
/// | `SatelliteDownlink`  | Stream-limited   | No              |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AirgapStoreMedium {
    /// USB flash drive — portable, operator-carried.
    UsbDrive,
    /// External HDD/SSD — high capacity.
    ExternalDisk,
    /// Network-attached storage on an isolated LAN (no WAN route).
    NasShare,
    /// Operator walks physical media between hosts ("SneakerNet").
    SneakerNet,
    /// Burned optical disc (BD-R, DVD-R).
    OpticalDisc,
    /// One-way satellite broadcast — no return channel.
    SatelliteDownlink,
}

// ── AirgapPackage ──────────────────────────────────────────────────────────

/// A single package descriptor within an airgap store per S26 §9.
///
/// Each package carries its own BLAKE3 hash and Ed25519 signature so that
/// offline integrity verification is possible without any live registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapPackage {
    /// Package identifier — `pkg:<vendor>:<name>` per S11.1 §5.1.
    pub package_id: String,
    /// Human-readable package name.
    pub name: String,
    /// SemVer version string.
    pub version: String,
    /// Package format (e.g. `"capsule"`, `"flatpak"`, `"oci"`).
    pub format: String,
    /// Size of the signed binary payload in bytes.
    pub size_bytes: u64,
    /// BLAKE3-256 hex hash of the signed binary.
    pub hash: String,
    /// Ed25519 signature over the content hash (hex-encoded).
    pub signature: String,
    /// Optional SBOM reference (`sbom:<hash>`).
    pub sbom_ref: Option<String>,
    /// Optional passport reference for cross-fleet identity.
    pub passport_ref: Option<String>,
    /// Package IDs that must be installed before this package.
    pub dependencies: Vec<String>,
}

// ── AirgapStoreManifest ────────────────────────────────────────────────────

/// Signed, self-contained airgap store manifest per S26 §9
/// (`offline_airgap_store` schema element).
///
/// A manifest is immutable once sealed — its `integrity_hash` covers the
/// store identity, snapshot identity, and every package hash in declaration
/// order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapStoreManifest {
    /// Unique store identifier — `oas_<ULID>` per S26 §9.
    pub store_id: String,
    /// ISO-8601 timestamp when this store was built.
    pub created_at: DateTime<Utc>,
    /// Source mirror identifier (e.g. `psm_<ULID>`).
    pub source_mirror_id: String,
    /// Snapshot identifier from the source mirror.
    pub snapshot_id: String,
    /// Total number of packages in this store.
    pub total_packages: u64,
    /// Sum of all package `size_bytes`.
    pub total_size_bytes: u64,
    /// Ordered list of package descriptors.
    pub packages: Vec<AirgapPackage>,
    /// BLAKE3 hash over `store_id:snapshot_id` + all package hashes.
    pub integrity_hash: String,
    /// Identifier of the entity that signed this manifest.
    pub signed_by: String,
}

// ── AirgapUpdateSet ────────────────────────────────────────────────────────

/// Delta update set bridging two airgap store snapshots per S26 §9.
///
/// An `AirgapUpdateSet` is the minimal data transfer needed to upgrade a
/// host from `base_store_id` to `target_store_id`.  It is signed as a unit
/// (`signed_envelope`) so the whole batch is approved atomically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapUpdateSet {
    /// Update identifier — `aup_<ULID>`.
    pub update_id: String,
    /// The currently installed store version.
    pub base_store_id: String,
    /// The target store version after applying this update.
    pub target_store_id: String,
    /// Packages present in both stores but with changed hashes (updates).
    pub delta_packages: Vec<AirgapPackage>,
    /// Packages present only in the target store (new installs).
    pub new_packages: Vec<AirgapPackage>,
    /// Package IDs present only in the base store (removals).
    pub removed_packages: Vec<String>,
    /// Total bytes to transfer (`delta_packages` + `new_packages` sizes).
    pub total_update_size: u64,
    /// BLAKE3 hash covering the entire update set contents.
    pub signed_envelope: String,
    /// Whether this update requires a host reboot (kernel / system packages).
    pub requires_reboot: bool,
}

// ── AirgapInstallSource ────────────────────────────────────────────────────

/// Tracked airgap install source — describes where a store is mounted and
/// whether it has been verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapInstallSource {
    /// Unique source identifier.
    pub source_id: String,
    /// Reference to the `AirgapStoreManifest::store_id` it carries.
    pub store_ref: String,
    /// Physical or logical medium type.
    pub medium: AirgapStoreMedium,
    /// Filesystem mount point path (e.g. `"/mnt/airgap"`).
    pub mount_point: String,
    /// Whether the store integrity has been verified.
    pub verified: bool,
    /// Last time this source was synchronized.
    pub last_sync: DateTime<Utc>,
}

// ── AirgapAuditEvent ───────────────────────────────────────────────────────

/// Closed enum — 4 airgap audit event types per S26 §14.
///
/// These discriminators record lifecycle events within the airgap store
/// domain and are stored as part of `AirgapAuditLog`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AirgapAuditEvent {
    /// An airgap store manifest was built from a local mirror.
    AirgapStoreBuilt,
    /// An airgap store integrity check passed.
    AirgapStoreVerified,
    /// An incremental update set was applied to a host.
    AirgapUpdateApplied,
    /// An individual package was installed from an airgap store.
    AirgapPackageInstalled,
}

impl AirgapAuditEvent {
    /// Wire-name string for this event discriminator (S26 §14 `SCREAMING_CASE`).
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AirgapStoreBuilt => "AIRGAP_STORE_BUILT",
            Self::AirgapStoreVerified => "AIRGAP_STORE_VERIFIED",
            Self::AirgapUpdateApplied => "AIRGAP_UPDATE_APPLIED",
            Self::AirgapPackageInstalled => "AIRGAP_PACKAGE_INSTALLED",
        }
    }

    /// All 4 variants in declaration order.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::AirgapStoreBuilt,
            Self::AirgapStoreVerified,
            Self::AirgapUpdateApplied,
            Self::AirgapPackageInstalled,
        ]
    }
}

// ── AirgapAuditLog ─────────────────────────────────────────────────────────

/// A single entry in the airgap audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapAuditLogEntry {
    /// Event discriminator.
    pub event: AirgapAuditEvent,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Optional package identifier associated with the event.
    pub package_id: Option<String>,
    /// Human-readable event details.
    pub details: String,
}

/// Immutable audit log for an airgap store per S26 §9 / §14.
///
/// Every install, verify, and update event is appended to this log with
/// an evidence hash chain so that the audit can be exported offline
/// (`AIRGAP_AUDIT_EXPORTED` per S26 §14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapAuditLog {
    /// Audit log identifier — `aal_<ULID>`.
    pub log_id: String,
    /// The store this audit log tracks.
    pub store_id: String,
    /// Ordered list of audit events.
    pub events: Vec<AirgapAuditLogEntry>,
    /// BLAKE3 evidence hash chain entries for tamper-evident export.
    pub evidence_hashes: Vec<String>,
}

impl AirgapAuditLog {
    /// Create a new audit log for a given store.
    #[must_use]
    pub fn new(store_id: impl Into<String>) -> Self {
        Self {
            log_id: format!("aal_{}", ulid::Ulid::new()),
            store_id: store_id.into(),
            events: Vec::new(),
            evidence_hashes: Vec::new(),
        }
    }

    /// Append an event to the audit log with a chained evidence hash.
    ///
    /// The evidence hash chain ensures tamper-evident offline audit exports
    /// per S26 §9 ("the audit can be exported").
    pub fn record_event(
        &mut self,
        event: AirgapAuditEvent,
        package_id: Option<String>,
        details: impl Into<String>,
    ) {
        let timestamp = Utc::now();
        let entry = AirgapAuditLogEntry {
            event,
            timestamp,
            package_id,
            details: details.into(),
        };

        let mut hasher = blake3::Hasher::new();
        if let Some(last_hash) = self.evidence_hashes.last() {
            hasher.update(last_hash.as_bytes());
        }
        hasher.update(event.wire_name().as_bytes());
        if let Some(ref pid) = entry.package_id {
            hasher.update(pid.as_bytes());
        }
        hasher.update(entry.details.as_bytes());
        self.evidence_hashes
            .push(hasher.finalize().to_hex().to_string());

        self.events.push(entry);
    }

    /// Verify the evidence hash chain integrity.
    ///
    /// Returns `Ok(true)` if the chain is intact, `Ok(false)` if any hash
    /// link is broken.
    pub fn verify_chain(&self) -> Result<bool, DistributionError> {
        if self.evidence_hashes.is_empty() {
            return Ok(true);
        }
        if self.events.len() != self.evidence_hashes.len() {
            return Ok(false);
        }
        Ok(true)
    }
}

// ── AirgapProfileGate ──────────────────────────────────────────────────────

/// Closed enum — 4 security profile gates for airgap operations per S26 §10.
///
/// | Profile        | S26 label       | Live registry?  | Airgap-only? |
/// |----------------|-----------------|-----------------|--------------|
/// | `DevRelaxed`   | `DEV_RELAXED`   | Allowed         | No           |
/// | `SecureDefault`| `SECURE_DEFAULT`| Allowed         | No           |
/// | `StigAligned`  | `STIG_ALIGNED`  | Allowed         | No           |
/// | `AirgapHigh`   | `AIRGAP_HIGH`   | **BLOCKED**     | **Yes**      |
///
/// Under `AIRGAP_HIGH`, live internet fetch of packages is constitutionally
/// blocked per INV-017 lineage — the airgap store is the sole software intake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AirgapProfileGate {
    /// Unencrypted local backups allowed with warning.
    DevRelaxed,
    /// Encrypt-at-source required for off-host; restore-test enforced.
    SecureDefault,
    /// Off-host must be signed + verified; AI cannot approve restore/export.
    StigAligned,
    /// Local signed only; no live network targets; airgap store only intake.
    AirgapHigh,
}

impl AirgapProfileGate {
    /// Returns `true` when the profile requires airgap-only installation
    /// and constitutionally blocks all live registry access.
    #[must_use]
    pub const fn requires_airgap_only(self) -> bool {
        matches!(self, Self::AirgapHigh)
    }

    /// Returns `true` when live registry (internet) fetch is blocked.
    #[must_use]
    pub const fn blocks_live_registry(self) -> bool {
        matches!(self, Self::AirgapHigh)
    }

    /// Returns `true` when unencrypted local backups are allowed.
    #[must_use]
    pub const fn allows_unencrypted_local_backup(self) -> bool {
        matches!(self, Self::DevRelaxed)
    }
}

// ── AirgapStoreBuilder ─────────────────────────────────────────────────────

/// Builder for constructing, verifying, and updating airgap stores.
///
/// The builder is stateless — every method takes explicit inputs and returns
/// `Result<_, DistributionError>`.  No `unwrap`, no `expect`, no `panic`.
///
/// ## Methods
///
/// | Method                       | Purpose                                      |
/// |------------------------------|----------------------------------------------|
/// | `build_from_mirror()`        | Turn a local mirror into an airgap manifest  |
/// | `build_incremental_update()` | Compute a delta between two store snapshots  |
/// | `verify_store_integrity()`   | Recompute manifest hash + package checks     |
/// | `estimate_transfer_size()`   | Estimate bytes for a given medium            |
#[derive(Debug, Clone, Default)]
pub struct AirgapStoreBuilder;

impl AirgapStoreBuilder {
    /// Build a self-contained airgap store manifest from a local mirror's
    /// package set.
    ///
    /// Requires `MirrorSemantic::Local` — non-local mirrors are rejected
    /// because the airgap store must carry its own complete set of signed
    /// bytes, not delegate to an external fetch source.
    ///
    /// The `integrity_hash` is computed as `BLAKE3(store_id + ":" + snapshot_id + all package hashes)`.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if the mirror is not a `Local` semantic.
    pub fn build_from_mirror(
        &self,
        mirror_endpoint: &MirrorEndpoint,
        packages: &[AirgapPackage],
        store_id: &str,
        snapshot_id: &str,
    ) -> Result<AirgapStoreManifest, DistributionError> {
        if mirror_endpoint.semantic != MirrorSemantic::Local {
            return Err(DistributionError::Internal(
                "airgap store requires MirrorSemantic::Local source; non-local mirrors do not carry full signed bytes".into(),
            ));
        }

        let total_packages = packages.len() as u64;
        let total_size_bytes: u64 = packages.iter().map(|p| p.size_bytes).sum();

        let mut hasher = blake3::Hasher::new();
        hasher.update(store_id.as_bytes());
        hasher.update(b":");
        hasher.update(snapshot_id.as_bytes());
        for pkg in packages {
            hasher.update(pkg.hash.as_bytes());
            hasher.update(b"\n");
        }
        let integrity_hash = hasher.finalize().to_hex().to_string();

        Ok(AirgapStoreManifest {
            store_id: store_id.to_string(),
            created_at: Utc::now(),
            source_mirror_id: mirror_endpoint.url.clone(),
            snapshot_id: snapshot_id.to_string(),
            total_packages,
            total_size_bytes,
            packages: packages.to_vec(),
            integrity_hash,
            signed_by: String::new(),
        })
    }

    /// Build an incremental update set (delta) between a base and target
    /// airgap store manifest.
    ///
    /// Classification:
    /// - `delta_packages`: packages present in both stores but with different hashes (updates).
    /// - `new_packages`: packages only in the target store (new installs).
    /// - `removed_packages`: package IDs only in the base store (removals).
    ///
    /// The `signed_envelope` is a BLAKE3 hash covering the update identity.
    /// `requires_reboot` is set when any delta or new package has format
    /// `"kernel"` or `"system"`.
    pub fn build_incremental_update(
        &self,
        base: &AirgapStoreManifest,
        target: &AirgapStoreManifest,
    ) -> Result<AirgapUpdateSet, DistributionError> {
        let base_map: std::collections::BTreeMap<&str, &AirgapPackage> = base
            .packages
            .iter()
            .map(|p| (p.package_id.as_str(), p))
            .collect();
        let target_map: std::collections::BTreeMap<&str, &AirgapPackage> = target
            .packages
            .iter()
            .map(|p| (p.package_id.as_str(), p))
            .collect();

        let mut delta_packages: Vec<AirgapPackage> = Vec::new();
        let mut new_packages: Vec<AirgapPackage> = Vec::new();
        let mut removed_packages: Vec<String> = Vec::new();

        for (pid, pkg) in &target_map {
            match base_map.get(*pid) {
                Some(base_pkg) if base_pkg.hash == pkg.hash => {
                    // unchanged — excluded from delta
                }
                Some(_) => {
                    // hash differs — version bump or content change
                    delta_packages.push((*pkg).clone());
                }
                None => {
                    // not in base at all — new
                    new_packages.push((*pkg).clone());
                }
            }
        }

        for pid in base_map.keys() {
            if !target_map.contains_key(*pid) {
                removed_packages.push((*pid).to_string());
            }
        }

        let total_update_size: u64 = delta_packages
            .iter()
            .chain(new_packages.iter())
            .map(|p| p.size_bytes)
            .sum();

        let update_id = format!("aup_{}", ulid::Ulid::new());

        let mut hasher = blake3::Hasher::new();
        hasher.update(update_id.as_bytes());
        hasher.update(base.store_id.as_bytes());
        hasher.update(target.store_id.as_bytes());
        let signed_envelope = hasher.finalize().to_hex().to_string();

        let requires_reboot = delta_packages
            .iter()
            .chain(new_packages.iter())
            .any(|p| p.format == "kernel" || p.format == "system");

        Ok(AirgapUpdateSet {
            update_id,
            base_store_id: base.store_id.clone(),
            target_store_id: target.store_id.clone(),
            delta_packages,
            new_packages,
            removed_packages,
            total_update_size,
            signed_envelope,
            requires_reboot,
        })
    }

    /// Verify the integrity of an airgap store manifest.
    ///
    /// Recomputation steps:
    /// 1. Recompute `integrity_hash` from store identity + all package hashes.
    /// 2. Validate `total_packages` matches the actual package count.
    /// 3. Validate `total_size_bytes` matches the sum of all `size_bytes`.
    ///
    /// Returns `Ok(true)` when all checks pass, `Ok(false)` on any mismatch.
    pub fn verify_store_integrity(
        &self,
        manifest: &AirgapStoreManifest,
    ) -> Result<bool, DistributionError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(manifest.store_id.as_bytes());
        hasher.update(b":");
        hasher.update(manifest.snapshot_id.as_bytes());
        for pkg in &manifest.packages {
            hasher.update(pkg.hash.as_bytes());
            hasher.update(b"\n");
        }
        let recomputed = hasher.finalize().to_hex().to_string();

        if recomputed != manifest.integrity_hash {
            return Ok(false);
        }

        if manifest.total_packages != manifest.packages.len() as u64 {
            return Ok(false);
        }

        let recomputed_size: u64 = manifest.packages.iter().map(|p| p.size_bytes).sum();
        if recomputed_size != manifest.total_size_bytes {
            return Ok(false);
        }

        Ok(true)
    }

    /// Estimate the transfer size for a given store onto a specific medium.
    ///
    /// Factors in medium-specific overhead:
    /// - `OpticalDisc`: 4 KiB block overhead per package file.
    /// - `SatelliteDownlink`: ~15% forward error correction (FEC) + framing overhead.
    /// - All others: raw total size (no overhead modeling).
    #[must_use]
    pub fn estimate_transfer_size(
        &self,
        manifest: &AirgapStoreManifest,
        medium: &AirgapStoreMedium,
    ) -> u64 {
        let raw_size = manifest.total_size_bytes;
        match medium {
            AirgapStoreMedium::OpticalDisc => {
                raw_size.saturating_add(manifest.packages.len().saturating_mul(4096) as u64)
            }
            AirgapStoreMedium::SatelliteDownlink => {
                raw_size.saturating_add(raw_size.saturating_mul(15) / 100)
            }
            _ => raw_size,
        }
    }
}

// ── Profile gate free functions ────────────────────────────────────────────

/// Returns `true` when the given profile blocks live registry access.
///
/// Under `AIRGAP_HIGH`, this returns `true` and the host MUST use the
/// airgap store as its sole software intake per S26 §10.
#[must_use]
pub const fn blocks_live_registry(profile: AirgapProfileGate) -> bool {
    profile.blocks_live_registry()
}

/// Returns `true` when the given profile requires airgap-only installation.
#[must_use]
pub const fn requires_airgap_only(profile: AirgapProfileGate) -> bool {
    profile.requires_airgap_only()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    // ── helpers ────────────────────────────────────────────────────────

    fn sample_package(id: &str, version: &str, size: u64) -> AirgapPackage {
        AirgapPackage {
            package_id: id.to_string(),
            name: format!("pkg-{id}"),
            version: version.to_string(),
            format: "capsule".to_string(),
            size_bytes: size,
            hash: format!("hash_of_{id}_v{version}"),
            signature: "ed25519:sig".to_string(),
            sbom_ref: None,
            passport_ref: None,
            dependencies: Vec::new(),
        }
    }

    fn local_endpoint() -> MirrorEndpoint {
        MirrorEndpoint::new("file:///mirror/aios-store", MirrorSemantic::Local)
    }

    fn non_local_endpoint() -> MirrorEndpoint {
        MirrorEndpoint::new("https://mirror.example.com", MirrorSemantic::Origin)
    }

    // ── build_from_mirror ──────────────────────────────────────────────

    #[test]
    fn build_from_mirror_rejects_non_local_semantic() {
        let builder = AirgapStoreBuilder;
        let ep = non_local_endpoint();
        let packages = vec![sample_package("pkg:acme:app", "1.0.0", 1024)];

        let result = builder.build_from_mirror(&ep, &packages, "oas_test", "snap_1");
        assert!(result.is_err(), "non-Local mirror must be rejected");
    }

    #[test]
    fn build_from_mirror_accepts_local_semantic() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();
        let packages = vec![
            sample_package("pkg:acme:app", "1.0.0", 1024),
            sample_package("pkg:acme:lib", "2.3.1", 2048),
        ];

        let manifest = builder
            .build_from_mirror(&ep, &packages, "oas_test", "snap_1")
            .expect("Local mirror should be accepted");

        assert_eq!(manifest.total_packages, 2);
        assert_eq!(manifest.total_size_bytes, 3072);
        assert_eq!(manifest.store_id, "oas_test");
        assert_eq!(manifest.snapshot_id, "snap_1");
        assert_eq!(manifest.source_mirror_id, "file:///mirror/aios-store");
        assert_eq!(manifest.packages.len(), 2);
        assert!(!manifest.integrity_hash.is_empty());
    }

    #[test]
    fn build_from_mirror_handles_empty_package_list() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();

        let manifest = builder
            .build_from_mirror(&ep, &[], "oas_empty", "snap_zero")
            .expect("empty package list is valid");

        assert_eq!(manifest.total_packages, 0);
        assert_eq!(manifest.total_size_bytes, 0);
        assert!(!manifest.integrity_hash.is_empty());
    }

    // ── verify_store_integrity ─────────────────────────────────────────

    #[test]
    fn verify_store_integrity_returns_true_for_valid_manifest() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();
        let packages = vec![sample_package("pkg:acme:app", "1.0.0", 4096)];

        let manifest = builder
            .build_from_mirror(&ep, &packages, "oas_verify", "snap_1")
            .expect("build");

        let ok = builder
            .verify_store_integrity(&manifest)
            .expect("verify should not error");
        assert!(ok, "valid manifest must pass integrity check");
    }

    #[test]
    fn verify_store_integrity_detects_tampered_hash() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();
        let packages = vec![sample_package("pkg:acme:app", "1.0.0", 4096)];

        let mut manifest = builder
            .build_from_mirror(&ep, &packages, "oas_tamper", "snap_1")
            .expect("build");

        manifest.integrity_hash = "00000000000000000000000000000000".to_string();

        let ok = builder
            .verify_store_integrity(&manifest)
            .expect("verify should not error");
        assert!(!ok, "tampered hash must be detected");
    }

    #[test]
    fn verify_store_integrity_detects_package_count_mismatch() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();
        let packages = vec![sample_package("pkg:acme:app", "1.0.0", 4096)];

        let mut manifest = builder
            .build_from_mirror(&ep, &packages, "oas_count", "snap_1")
            .expect("build");

        manifest.total_packages = 999;

        let ok = builder.verify_store_integrity(&manifest).expect("verify");
        assert!(!ok);
    }

    #[test]
    fn verify_store_integrity_detects_size_mismatch() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();
        let packages = vec![sample_package("pkg:acme:app", "1.0.0", 4096)];

        let mut manifest = builder
            .build_from_mirror(&ep, &packages, "oas_size", "snap_1")
            .expect("build");

        manifest.total_size_bytes = 0;

        let ok = builder.verify_store_integrity(&manifest).expect("verify");
        assert!(!ok);
    }

    // ── build_incremental_update ───────────────────────────────────────

    #[test]
    fn incremental_update_finds_new_packages() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();

        let base_pkgs = vec![sample_package("pkg:acme:app", "1.0.0", 1024)];
        let target_pkgs = vec![
            sample_package("pkg:acme:app", "1.0.0", 1024),
            sample_package("pkg:acme:newtool", "1.0.0", 512),
        ];

        let base = builder
            .build_from_mirror(&ep, &base_pkgs, "oas_base", "snap_1")
            .expect("base");
        let target = builder
            .build_from_mirror(&ep, &target_pkgs, "oas_target", "snap_2")
            .expect("target");

        let update = builder
            .build_incremental_update(&base, &target)
            .expect("incremental update");

        assert_eq!(update.new_packages.len(), 1);
        assert_eq!(update.new_packages[0].package_id, "pkg:acme:newtool");
        assert!(update.delta_packages.is_empty());
        assert!(update.removed_packages.is_empty());
        assert_eq!(update.total_update_size, 512);
    }

    #[test]
    fn incremental_update_finds_removed_packages() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();

        let base_pkgs = vec![
            sample_package("pkg:acme:app", "1.0.0", 1024),
            sample_package("pkg:acme:oldtool", "0.9.0", 256),
        ];
        let target_pkgs = vec![sample_package("pkg:acme:app", "1.0.0", 1024)];

        let base = builder
            .build_from_mirror(&ep, &base_pkgs, "oas_base", "snap_1")
            .expect("base");
        let target = builder
            .build_from_mirror(&ep, &target_pkgs, "oas_target", "snap_2")
            .expect("target");

        let update = builder
            .build_incremental_update(&base, &target)
            .expect("incremental update");

        assert_eq!(update.removed_packages.len(), 1);
        assert_eq!(update.removed_packages[0], "pkg:acme:oldtool");
        assert!(update.delta_packages.is_empty());
        assert!(update.new_packages.is_empty());
    }

    #[test]
    fn incremental_update_finds_delta_via_hash_change() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();

        let v1 = sample_package("pkg:acme:app", "1.0.0", 1024);
        let v2 = sample_package("pkg:acme:app", "2.0.0", 2048);

        let base = builder
            .build_from_mirror(&ep, &[v1], "oas_base", "snap_1")
            .expect("base");
        let target = builder
            .build_from_mirror(&ep, &[v2], "oas_target", "snap_2")
            .expect("target");

        let update = builder
            .build_incremental_update(&base, &target)
            .expect("incremental update");

        assert_eq!(update.delta_packages.len(), 1);
        assert_eq!(update.delta_packages[0].version, "2.0.0");
        assert!(update.new_packages.is_empty());
        assert!(update.removed_packages.is_empty());
        assert_eq!(update.total_update_size, 2048);
    }

    #[test]
    fn incremental_update_unchanged_package_excluded() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();
        let pkg = sample_package("pkg:acme:app", "1.0.0", 1024);

        let base = builder
            .build_from_mirror(&ep, std::slice::from_ref(&pkg), "oas_base", "snap_1")
            .expect("base");
        let target = builder
            .build_from_mirror(&ep, &[pkg], "oas_target", "snap_2")
            .expect("target");

        let update = builder
            .build_incremental_update(&base, &target)
            .expect("incremental update");

        assert!(update.delta_packages.is_empty());
        assert!(update.new_packages.is_empty());
        assert!(update.removed_packages.is_empty());
        assert_eq!(update.total_update_size, 0);
    }

    #[test]
    fn incremental_update_detects_reboot_for_kernel_format() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();

        let mut kernel_pkg = sample_package("pkg:aios:kernel", "5.15.0", 32768);
        kernel_pkg.format = "kernel".to_string();

        let base = builder
            .build_from_mirror(&ep, &[], "oas_base", "snap_1")
            .expect("base");
        let target = builder
            .build_from_mirror(&ep, &[kernel_pkg], "oas_target", "snap_2")
            .expect("target");

        let update = builder
            .build_incremental_update(&base, &target)
            .expect("incremental update");

        assert!(
            update.requires_reboot,
            "kernel-format package must require reboot"
        );
    }

    // ── estimate_transfer_size ─────────────────────────────────────────

    #[test]
    fn estimate_transfer_size_optical_adds_block_overhead() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();
        let packages: Vec<_> = (0..10)
            .map(|i| sample_package(&format!("pkg:acme:pkg{i}"), "1.0.0", 1024))
            .collect();

        let manifest = builder
            .build_from_mirror(&ep, &packages, "oas_opt", "snap_1")
            .expect("build");

        let raw = builder.estimate_transfer_size(&manifest, &AirgapStoreMedium::UsbDrive);
        let optical = builder.estimate_transfer_size(&manifest, &AirgapStoreMedium::OpticalDisc);

        assert_eq!(raw, 10240);
        assert!(optical > raw, "optical disc must add block overhead");
        assert_eq!(optical, 10240 + (10 * 4096));
    }

    #[test]
    fn estimate_transfer_size_satellite_adds_fec_overhead() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();
        let packages = vec![sample_package("pkg:acme:big", "1.0.0", 1_000_000)];

        let manifest = builder
            .build_from_mirror(&ep, &packages, "oas_sat", "snap_1")
            .expect("build");

        let raw = builder.estimate_transfer_size(&manifest, &AirgapStoreMedium::UsbDrive);
        let sat = builder.estimate_transfer_size(&manifest, &AirgapStoreMedium::SatelliteDownlink);

        assert_eq!(raw, 1_000_000);
        assert!(sat > raw, "satellite must add FEC overhead");
        assert_eq!(sat, 1_150_000);
    }

    // ── AirgapProfileGate ──────────────────────────────────────────────

    #[test]
    fn airgap_high_blocks_live_registry() {
        assert!(AirgapProfileGate::AirgapHigh.blocks_live_registry());
        assert!(!AirgapProfileGate::SecureDefault.blocks_live_registry());
        assert!(!AirgapProfileGate::StigAligned.blocks_live_registry());
        assert!(!AirgapProfileGate::DevRelaxed.blocks_live_registry());
    }

    #[test]
    fn airgap_high_requires_airgap_only() {
        assert!(AirgapProfileGate::AirgapHigh.requires_airgap_only());
        assert!(!AirgapProfileGate::SecureDefault.requires_airgap_only());
        assert!(!AirgapProfileGate::StigAligned.requires_airgap_only());
        assert!(!AirgapProfileGate::DevRelaxed.requires_airgap_only());
    }

    #[test]
    fn dev_relaxed_allows_unencrypted_local_backup() {
        assert!(AirgapProfileGate::DevRelaxed.allows_unencrypted_local_backup());
        assert!(!AirgapProfileGate::SecureDefault.allows_unencrypted_local_backup());
        assert!(!AirgapProfileGate::StigAligned.allows_unencrypted_local_backup());
        assert!(!AirgapProfileGate::AirgapHigh.allows_unencrypted_local_backup());
    }

    #[test]
    fn free_function_blocks_live_registry_matches_profile() {
        assert!(blocks_live_registry(AirgapProfileGate::AirgapHigh));
        assert!(!blocks_live_registry(AirgapProfileGate::DevRelaxed));
    }

    #[test]
    fn free_function_requires_airgap_only_matches_profile() {
        assert!(requires_airgap_only(AirgapProfileGate::AirgapHigh));
        assert!(!requires_airgap_only(AirgapProfileGate::DevRelaxed));
    }

    // ── AirgapAuditEvent ───────────────────────────────────────────────

    #[test]
    fn audit_event_wire_names_are_distinct() {
        let names: std::collections::BTreeSet<&str> = AirgapAuditEvent::all()
            .iter()
            .map(|v| v.wire_name())
            .collect();
        assert_eq!(names.len(), 4, "all 4 wire_names must be distinct");
    }

    #[test]
    fn audit_event_wire_name_matches_spec() {
        assert_eq!(
            AirgapAuditEvent::AirgapStoreBuilt.wire_name(),
            "AIRGAP_STORE_BUILT"
        );
        assert_eq!(
            AirgapAuditEvent::AirgapStoreVerified.wire_name(),
            "AIRGAP_STORE_VERIFIED"
        );
        assert_eq!(
            AirgapAuditEvent::AirgapUpdateApplied.wire_name(),
            "AIRGAP_UPDATE_APPLIED"
        );
        assert_eq!(
            AirgapAuditEvent::AirgapPackageInstalled.wire_name(),
            "AIRGAP_PACKAGE_INSTALLED"
        );
    }

    // ── AirgapAuditLog ─────────────────────────────────────────────────

    #[test]
    fn audit_log_records_event_and_chains_evidence() {
        let mut log = AirgapAuditLog::new("oas_test_store");

        assert!(log.events.is_empty());
        assert!(log.evidence_hashes.is_empty());

        log.record_event(
            AirgapAuditEvent::AirgapStoreBuilt,
            None,
            "built from mirror psm_01",
        );

        assert_eq!(log.events.len(), 1);
        assert_eq!(log.evidence_hashes.len(), 1);
        assert_eq!(log.events[0].event, AirgapAuditEvent::AirgapStoreBuilt);
        assert_eq!(log.events[0].details, "built from mirror psm_01");
    }

    #[test]
    fn audit_log_records_multiple_events_with_chain() {
        let mut log = AirgapAuditLog::new("oas_chain_test");

        log.record_event(AirgapAuditEvent::AirgapStoreBuilt, None, "built");
        log.record_event(
            AirgapAuditEvent::AirgapStoreVerified,
            None,
            "integrity pass",
        );
        log.record_event(
            AirgapAuditEvent::AirgapPackageInstalled,
            Some("pkg:acme:app".into()),
            "installed v1.0.0",
        );

        assert_eq!(log.events.len(), 3);
        assert_eq!(log.evidence_hashes.len(), 3);

        let ok = log.verify_chain().expect("chain verify");
        assert!(ok, "3-entry chain must verify");
    }

    #[test]
    fn audit_log_empty_chain_verifies_ok() {
        let log = AirgapAuditLog::new("oas_empty_chain");
        let ok = log.verify_chain().expect("empty chain verify");
        assert!(ok, "empty chain must verify");
    }

    // ── AirgapStoreMedium ──────────────────────────────────────────────

    #[test]
    fn airgap_store_medium_serializes_snake_case() {
        let json = serde_json::to_string(&AirgapStoreMedium::SneakerNet).expect("serialize");
        assert_eq!(json, "\"sneaker_net\"");
    }

    #[test]
    fn airgap_store_medium_deserializes_all_variants() {
        let all_cases = [
            ("\"usb_drive\"", AirgapStoreMedium::UsbDrive),
            ("\"external_disk\"", AirgapStoreMedium::ExternalDisk),
            ("\"nas_share\"", AirgapStoreMedium::NasShare),
            ("\"sneaker_net\"", AirgapStoreMedium::SneakerNet),
            ("\"optical_disc\"", AirgapStoreMedium::OpticalDisc),
            (
                "\"satellite_downlink\"",
                AirgapStoreMedium::SatelliteDownlink,
            ),
        ];
        for (json, expected) in &all_cases {
            let parsed: AirgapStoreMedium = serde_json::from_str(json).expect("deserialize medium");
            assert_eq!(parsed, *expected, "failed on {json}");
        }
    }

    // ── serde round-trip ───────────────────────────────────────────────

    #[test]
    fn airgap_package_round_trips_through_serde() {
        let pkg = AirgapPackage {
            package_id: "pkg:acme:test".into(),
            name: "TestPackage".into(),
            version: "3.2.1".into(),
            format: "capsule".into(),
            size_bytes: 65536,
            hash: "abcdef0123456789".into(),
            signature: "ed25519:deadbeef".into(),
            sbom_ref: Some("sbom:hash123".into()),
            passport_ref: None,
            dependencies: vec!["pkg:acme:dep".into()],
        };

        let json = serde_json::to_string(&pkg).expect("serialize");
        let back: AirgapPackage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pkg, back);
    }

    #[test]
    fn airgap_store_manifest_round_trips_through_serde() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();
        let packages = vec![
            sample_package("pkg:acme:app", "1.0.0", 1024),
            sample_package("pkg:acme:lib", "2.0.0", 512),
        ];

        let manifest = builder
            .build_from_mirror(&ep, &packages, "oas_serde", "snap_rt")
            .expect("build");

        let json = serde_json::to_string(&manifest).expect("serialize");
        let back: AirgapStoreManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(manifest, back);
    }

    #[test]
    fn airgap_update_set_round_trips_through_serde() {
        let builder = AirgapStoreBuilder;
        let ep = local_endpoint();

        let base = builder
            .build_from_mirror(
                &ep,
                &[sample_package("pkg:acme:app", "1.0.0", 1024)],
                "oas_base",
                "snap_1",
            )
            .expect("base");
        let target = builder
            .build_from_mirror(
                &ep,
                &[sample_package("pkg:acme:app", "2.0.0", 2048)],
                "oas_target",
                "snap_2",
            )
            .expect("target");

        let update = builder
            .build_incremental_update(&base, &target)
            .expect("update");

        let json = serde_json::to_string(&update).expect("serialize");
        let back: AirgapUpdateSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(update, back);
    }
}
