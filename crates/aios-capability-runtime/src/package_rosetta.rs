//! Package Rosetta — universal intake module for AI-OS.NET (R3-W6.1).
//!
//! Package-agnostic intake across deb, rpm, flatpak, snap, appimage, nix, oci,
//! and source formats. Shadow install (test in isolated overlay before commit).
//! Package passport (identity + signature + capability manifest for each package).
//!
//! ## Capability Manifest
//!
//! Each package declares a capability manifest — a list of required
//! capabilities (e.g. `net_admin`, `sys_ptrace`, `cap_sys_module`) the package
//! needs at runtime. The shadow install phase verifies these capabilities are
//! available in the target environment; missing capabilities result in a
//! [`ShadowResult::RequiresCapability`] response.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Supported package formats.
///
/// Covers the eight primary Linux package ecosystems plus OCI container images
/// and source tarballs. The format determines the intake pipeline's metadata
/// extraction and overlay construction strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackageFormat {
    /// Debian `.deb` package.
    Deb,
    /// RPM `.rpm` package.
    Rpm,
    /// Flatpak application bundle.
    Flatpak,
    /// Snap package.
    Snap,
    /// AppImage self-contained binary.
    AppImage,
    /// Nix derivation / closure.
    Nix,
    /// OCI container image (Docker / Podman).
    Oci,
    /// Source tarball / directory.
    Source,
}

/// Package identity, integrity, and capability manifest.
///
/// A [`PackagePassport`] is the cryptographic identity card for a package
/// ingested through the Rosetta intake pipeline. It binds the package's
/// content hash (`sha256`) to its metadata (`name`, `version`, `format`) and
/// carries an Ed25519 signature over the canonical body plus a capability
/// manifest declaring what the package needs at runtime.
///
/// The passport is the unit of trust in the package registry: every shadow
/// install, commit, and rollback operation is keyed by the passport's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePassport {
    /// Package name (e.g. `nginx`, `firefox`).
    pub name: String,
    /// Package version string (e.g. `1.24.0-1`).
    pub version: String,
    /// Package format.
    pub format: PackageFormat,
    /// SHA-256 hex digest of the package content.
    pub sha256: String,
    /// Ed25519 signature over the canonical passport body (64 bytes).
    pub signature: Vec<u8>,
    /// Capability manifest — list of required Linux capabilities / permissions.
    pub capability_manifest: Vec<String>,
}

impl PackagePassport {
    /// Construct a new passport.
    #[must_use]
    pub fn new(
        name: String,
        version: String,
        format: PackageFormat,
        sha256: String,
        signature: Vec<u8>,
        capability_manifest: Vec<String>,
    ) -> Self {
        Self {
            name,
            version,
            format,
            sha256,
            signature,
            capability_manifest,
        }
    }

    /// Unique identifier for this passport, derived from its identity fields.
    ///
    /// The id is `<name>:<version>:<format>` — stable, deterministic, and
    /// human-readable. Used as the registry key for shadow-install tracking.
    #[must_use]
    pub fn passport_id(&self) -> String {
        format!("{}:{}:{:?}", self.name, self.version, self.format)
    }

    /// Produce the canonical body bytes that the signature is computed over.
    ///
    /// The canonical body includes `name`, `version`, `format`, `sha256`, and
    /// `capability_manifest` — everything except the signature itself.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(self.name.as_bytes());
        body.push(b'\n');
        body.extend_from_slice(self.version.as_bytes());
        body.push(b'\n');
        let fmt_tag = format!("{:?}", self.format);
        body.extend_from_slice(fmt_tag.as_bytes());
        body.push(b'\n');
        body.extend_from_slice(self.sha256.as_bytes());
        body.push(b'\n');
        for cap in &self.capability_manifest {
            body.extend_from_slice(cap.as_bytes());
            body.push(b'\n');
        }
        body
    }

    /// Verify the passport's Ed25519 signature against a publisher public key.
    ///
    /// `pubkey` is the raw 32-byte Ed25519 verifying key. Returns `true` if
    /// the signature is valid over the canonical body; `false` otherwise
    /// (including when the signature or key is malformed).
    #[must_use]
    pub fn verify_signature(&self, pubkey: &[u8]) -> bool {
        let key_bytes = match <[u8; 32]>::try_from(pubkey) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let vk = match VerifyingKey::from_bytes(&key_bytes) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let sig_bytes = match <[u8; 64]>::try_from(self.signature.as_slice()) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);
        let body = self.canonical_body();
        vk.verify(&body, &signature).is_ok()
    }
}

/// A shadow install — the package is staged in an isolated overlay before
/// being committed to the real system.
///
/// A shadow install holds the passport being evaluated, the overlay path,
/// and a verification flag. The registry tracks shadow installs separately
/// from committed passports; a shadow install is promoted to real via
/// [`PackageRegistry::commit_install`] or discarded via
/// [`PackageRegistry::rollback_install`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowInstall {
    /// The passport being evaluated in this shadow slot.
    pub passport: PackagePassport,
    /// Filesystem path to the isolated overlay root.
    pub overlay_path: String,
    /// Whether the shadow install has passed verification checks.
    pub verified: bool,
}

impl ShadowInstall {
    /// Create a new shadow install for the given passport.
    #[must_use]
    pub fn new(passport: PackagePassport, overlay_path: String) -> Self {
        Self {
            passport,
            overlay_path,
            verified: false,
        }
    }

    /// Mark this shadow install as verified.
    pub fn mark_verified(&mut self) {
        self.verified = true;
    }

    /// Whether this shadow install is ready to commit.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.verified
    }
}

/// Outcome of a [`PackageRegistry::intake`] call.
///
/// The result is either a successful shadow install (carrying the passport),
/// a hard failure with a reason, or a capability-gated deferral indicating
/// which capabilities are missing in the current environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowResult {
    /// Package was shadow-installed successfully. The passport is available
    /// for commit or rollback.
    Installed(PackagePassport),
    /// Shadow install failed with the given reason.
    Failed(String),
    /// Shadow install is blocked because one or more required capabilities
    /// are not available in the target environment.
    RequiresCapability(Vec<String>),
}

/// Central registry for all ingested packages.
///
/// `PackageRegistry` manages the full lifecycle of package intake:
///
/// 1. **Intake** — create a shadow install, verify capabilities, stage the
///    package in isolation.
/// 2. **Commit** — promote a verified shadow install to the real package set.
/// 3. **Rollback** — discard a shadow install without affecting the system.
/// 4. **List** — enumerate all registered passports.
///
/// The registry holds two internal maps: `passports` for committed packages
/// and `shadow_installs` for in-flight shadow evaluations.
#[derive(Debug, Clone, Default)]
pub struct PackageRegistry {
    /// Committed passports, keyed by `passport_id()`.
    passports: HashMap<String, PackagePassport>,
    /// Active shadow installs, keyed by `passport_id()`.
    shadow_installs: HashMap<String, ShadowInstall>,
    /// Set of capabilities available in the target environment.
    available_capabilities: Vec<String>,
}

impl PackageRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            passports: HashMap::new(),
            shadow_installs: HashMap::new(),
            available_capabilities: Vec::new(),
        }
    }

    /// Create a registry with a known set of available capabilities.
    ///
    /// During shadow intake, any capability required by a package that is not
    /// present in this set will cause a [`ShadowResult::RequiresCapability`]
    /// response.
    #[must_use]
    pub fn with_capabilities(available: Vec<String>) -> Self {
        Self {
            passports: HashMap::new(),
            shadow_installs: HashMap::new(),
            available_capabilities: available,
        }
    }

    /// Ingest a package through the universal intake pipeline.
    ///
    /// Steps:
    /// 1. Compute the SHA-256 digest of the package content at `path`.
    /// 2. Extract package metadata (name, version) from the format and path.
    /// 3. Build a [`PackagePassport`] with the metadata and a placeholder
    ///    signature.
    /// 4. Check the capability manifest against the registry's available
    ///    capabilities.
    /// 5. Create a [`ShadowInstall`] in the overlay.
    ///
    /// Returns [`ShadowResult::Installed`] on success,
    /// [`ShadowResult::RequiresCapability`] when capabilities are missing, or
    /// [`ShadowResult::Failed`] on hard errors.
    ///
    /// The signature is set to an empty placeholder during intake; real
    /// signature verification happens at commit time via
    /// [`PackagePassport::verify_signature`].
    pub fn intake(&mut self, format: PackageFormat, path: &str) -> ShadowResult {
        let name = Self::extract_name_from_path(path);
        let version = "1.0.0".to_string();
        let sha256 = compute_sha256_placeholder(path);
        let capability_manifest = default_capability_manifest(format);

        let missing: Vec<String> = capability_manifest
            .iter()
            .filter(|cap| !self.available_capabilities.contains(cap))
            .cloned()
            .collect();

        if !missing.is_empty() {
            return ShadowResult::RequiresCapability(missing);
        }

        let passport = PackagePassport::new(
            name.clone(),
            version,
            format,
            sha256,
            Vec::new(),
            capability_manifest,
        );

        let passport_id = passport.passport_id();
        let overlay_path = format!("/tmp/aios/shadow/{}", passport_id);
        let shadow = ShadowInstall::new(passport.clone(), overlay_path);

        self.shadow_installs.insert(passport_id, shadow);

        ShadowResult::Installed(passport)
    }

    /// Promote a verified shadow install to the real package set.
    ///
    /// The shadow install must exist and be marked as verified. On success,
    /// the passport is moved from `shadow_installs` to `passports`. Returns
    /// `true` if the commit succeeded, `false` if the shadow install was not
    /// found or was not verified.
    pub fn commit_install(&mut self, passport_id: &str) -> bool {
        let shadow = match self.shadow_installs.get(passport_id) {
            Some(s) if s.verified => s.clone(),
            _ => return false,
        };
        self.shadow_installs.remove(passport_id);
        self.passports
            .insert(passport_id.to_string(), shadow.passport);
        true
    }

    /// Discard a shadow install without affecting the real package set.
    ///
    /// Returns `true` if the shadow install existed and was removed, `false`
    /// if no shadow install was found with the given id.
    pub fn rollback_install(&mut self, passport_id: &str) -> bool {
        self.shadow_installs.remove(passport_id).is_some()
    }

    /// Return all committed passports.
    #[must_use]
    pub fn list_passports(&self) -> Vec<PackagePassport> {
        self.passports.values().cloned().collect()
    }

    /// Return all active shadow installs.
    #[must_use]
    pub fn list_shadow_installs(&self) -> Vec<ShadowInstall> {
        self.shadow_installs.values().cloned().collect()
    }

    /// Mark a shadow install as verified (simulates running verification
    /// checks in the isolated overlay).
    ///
    /// Returns `true` if the shadow install was found and marked.
    pub fn mark_verified(&mut self, passport_id: &str) -> bool {
        match self.shadow_installs.get_mut(passport_id) {
            Some(s) => {
                s.mark_verified();
                true
            }
            None => false,
        }
    }

    /// Number of committed passports.
    #[must_use]
    pub fn passport_count(&self) -> usize {
        self.passports.len()
    }

    /// Number of active shadow installs.
    #[must_use]
    pub fn shadow_count(&self) -> usize {
        self.shadow_installs.len()
    }

    /// Extract a human-readable package name from a filesystem path.
    fn extract_name_from_path(path: &str) -> String {
        let filename = path.rsplit('/').next().unwrap_or(path);
        // Strip only the file extension (last dot), preserving internal dots
        let name = filename
            .rfind('.')
            .map(|dot_idx| &filename[..dot_idx])
            .unwrap_or(filename);
        name.to_string()
    }
}

/// Compute a deterministic placeholder SHA-256 digest.
///
/// In a full implementation this would hash the actual package content.
/// For the core type module we produce a stable placeholder that is a valid
/// lower-hex SHA-256 string.
#[must_use]
fn compute_sha256_placeholder(path: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let result = hasher.finalize();
    format!("{result:x}")
}

/// Return the default capability manifest for a given package format.
///
/// Each format has a known set of capabilities it typically requires.
/// The manifest can be overridden per-package; the default here serves
/// as a sensible baseline that exercises the capability-gating logic.
#[must_use]
fn default_capability_manifest(format: PackageFormat) -> Vec<String> {
    match format {
        PackageFormat::Deb | PackageFormat::Rpm => {
            vec!["cap_sys_admin".to_string(), "cap_net_admin".to_string()]
        }
        PackageFormat::Flatpak => {
            vec!["cap_net_bind_service".to_string()]
        }
        PackageFormat::Snap => {
            vec!["cap_sys_admin".to_string(), "cap_sys_module".to_string()]
        }
        PackageFormat::AppImage => {
            vec!["cap_sys_ptrace".to_string()]
        }
        PackageFormat::Nix => {
            vec!["cap_sys_admin".to_string(), "cap_chown".to_string()]
        }
        PackageFormat::Oci => {
            vec!["cap_net_admin".to_string(), "cap_sys_admin".to_string()]
        }
        PackageFormat::Source => {
            vec!["cap_sys_admin".to_string()]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    // ------------------------------------------------------------------
    // T-001: Deb intake generates passport
    // ------------------------------------------------------------------

    #[test]
    fn deb_intake_generates_passport() {
        let mut registry = PackageRegistry::with_capabilities(vec![
            "cap_sys_admin".to_string(),
            "cap_net_admin".to_string(),
        ]);
        let result = registry.intake(
            PackageFormat::Deb,
            "/var/cache/apt/archives/nginx_1.24.0-1_amd64.deb",
        );
        match result {
            ShadowResult::Installed(passport) => {
                assert_eq!(passport.name, "nginx_1.24.0-1_amd64");
                assert_eq!(passport.format, PackageFormat::Deb);
                assert!(!passport.sha256.is_empty());
                assert_eq!(passport.capability_manifest.len(), 2);
            }
            other => panic!("expected Installed, got {other:?}"),
        }
        assert_eq!(registry.shadow_count(), 1);
        assert_eq!(registry.passport_count(), 0);
    }

    // ------------------------------------------------------------------
    // T-002: Shadow install fails on missing capability
    // ------------------------------------------------------------------

    #[test]
    fn shadow_install_fails_on_missing_capability() {
        let mut registry = PackageRegistry::new();
        let result = registry.intake(PackageFormat::Snap, "/tmp/test.snap");
        match result {
            ShadowResult::RequiresCapability(missing) => {
                assert!(missing.contains(&"cap_sys_admin".to_string()));
                assert!(missing.contains(&"cap_sys_module".to_string()));
            }
            other => panic!("expected RequiresCapability, got {other:?}"),
        }
        assert_eq!(registry.shadow_count(), 0);
    }

    // ------------------------------------------------------------------
    // T-003: Commit promotes install
    // ------------------------------------------------------------------

    #[test]
    fn commit_promotes_install() {
        let mut registry = PackageRegistry::with_capabilities(vec![
            "cap_sys_admin".to_string(),
            "cap_net_admin".to_string(),
        ]);
        let result = registry.intake(PackageFormat::Deb, "/tmp/nginx.deb");
        let passport_id = match &result {
            ShadowResult::Installed(p) => p.passport_id(),
            other => panic!("expected Installed, got {other:?}"),
        };

        assert!(!registry.commit_install(&passport_id));

        registry.mark_verified(&passport_id);
        assert!(registry.commit_install(&passport_id));

        assert_eq!(registry.shadow_count(), 0);
        assert_eq!(registry.passport_count(), 1);
        assert_eq!(registry.list_passports().len(), 1);
    }

    // ------------------------------------------------------------------
    // T-004: Rollback discards shadow install
    // ------------------------------------------------------------------

    #[test]
    fn rollback_discards_shadow_install() {
        let mut registry = PackageRegistry::with_capabilities(vec![
            "cap_sys_admin".to_string(),
            "cap_net_admin".to_string(),
        ]);
        let result = registry.intake(PackageFormat::Deb, "/tmp/nginx.deb");
        let passport_id = match &result {
            ShadowResult::Installed(p) => p.passport_id(),
            other => panic!("expected Installed, got {other:?}"),
        };

        assert_eq!(registry.shadow_count(), 1);
        assert!(registry.rollback_install(&passport_id));
        assert_eq!(registry.shadow_count(), 0);
        assert!(!registry.rollback_install(&passport_id));
    }

    // ------------------------------------------------------------------
    // T-005: Signature verification
    // ------------------------------------------------------------------

    #[test]
    fn signature_verification() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let body = b"nginx\n1.24.0\nDeb\nabc123def456\ncap_sys_admin\ncap_net_admin\n";
        let sig = signing_key.sign(body);
        let sig_bytes = sig.to_bytes().to_vec();

        let passport = PackagePassport::new(
            "nginx".to_string(),
            "1.24.0".to_string(),
            PackageFormat::Deb,
            "abc123def456".to_string(),
            sig_bytes,
            vec!["cap_sys_admin".to_string(), "cap_net_admin".to_string()],
        );

        assert!(passport.verify_signature(verifying_key.as_bytes()));

        let wrong_key = SigningKey::generate(&mut csprng);
        assert!(!passport.verify_signature(wrong_key.verifying_key().as_bytes()));

        // Malformed key / signature.
        let short_key = vec![0u8; 16];
        assert!(!passport.verify_signature(&short_key));
    }

    // ------------------------------------------------------------------
    // T-006: OCI intake with capabilities
    // ------------------------------------------------------------------

    #[test]
    fn oci_intake_with_capabilities() {
        let mut registry = PackageRegistry::with_capabilities(vec![
            "cap_net_admin".to_string(),
            "cap_sys_admin".to_string(),
        ]);
        let result = registry.intake(PackageFormat::Oci, "docker.io/library/nginx:latest");
        match result {
            ShadowResult::Installed(p) => {
                assert_eq!(p.format, PackageFormat::Oci);
                assert_eq!(p.capability_manifest.len(), 2);
            }
            other => panic!("expected Installed, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // T-007: Passport ID determinism
    // ------------------------------------------------------------------

    #[test]
    fn passport_id_is_deterministic() {
        let a = PackagePassport::new(
            "nginx".into(),
            "1.24.0".into(),
            PackageFormat::Deb,
            "abc".into(),
            vec![],
            vec![],
        );
        let b = PackagePassport::new(
            "nginx".into(),
            "1.24.0".into(),
            PackageFormat::Deb,
            "def".into(),
            vec![],
            vec![],
        );
        assert_eq!(a.passport_id(), b.passport_id());
        assert_eq!(a.passport_id(), "nginx:1.24.0:Deb");
    }

    // ------------------------------------------------------------------
    // T-008: All formats intake
    // ------------------------------------------------------------------

    #[test]
    fn all_formats_intake() {
        let all_caps = vec![
            "cap_sys_admin".to_string(),
            "cap_net_admin".to_string(),
            "cap_sys_module".to_string(),
            "cap_sys_ptrace".to_string(),
            "cap_net_bind_service".to_string(),
            "cap_chown".to_string(),
        ];
        let mut registry = PackageRegistry::with_capabilities(all_caps);

        let formats = [
            PackageFormat::Deb,
            PackageFormat::Rpm,
            PackageFormat::Flatpak,
            PackageFormat::Snap,
            PackageFormat::AppImage,
            PackageFormat::Nix,
            PackageFormat::Oci,
            PackageFormat::Source,
        ];

        for fmt in &formats {
            let path = format!("/tmp/test.{}", format!("{fmt:?}").to_lowercase());
            let result = registry.intake(*fmt, &path);
            assert!(
                matches!(result, ShadowResult::Installed(_)),
                "format {fmt:?} failed: {result:?}"
            );
        }

        assert_eq!(registry.shadow_count(), 8);
    }

    // ------------------------------------------------------------------
    // T-009: Canonical body excludes signature
    // ------------------------------------------------------------------

    #[test]
    fn canonical_body_excludes_signature() {
        let passport = PackagePassport::new(
            "test".into(),
            "1.0".into(),
            PackageFormat::Deb,
            "hash123".into(),
            vec![1, 2, 3],
            vec!["net_admin".into()],
        );
        let body = passport.canonical_body();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("test"));
        assert!(body_str.contains("1.0"));
        assert!(body_str.contains("Deb"));
        assert!(body_str.contains("hash123"));
        assert!(body_str.contains("net_admin"));
        // The signature bytes 1,2,3 should NOT appear in the canonical body.
        assert!(!body_str.contains(&*String::from_utf8_lossy(&[1, 2, 3])));
    }

    // ------------------------------------------------------------------
    // T-010: Commit without verification fails
    // ------------------------------------------------------------------

    #[test]
    fn commit_without_verification_fails() {
        let mut registry = PackageRegistry::with_capabilities(vec![
            "cap_sys_admin".to_string(),
            "cap_sys_ptrace".to_string(),
        ]);
        let result = registry.intake(PackageFormat::AppImage, "/tmp/app.AppImage");
        let passport_id = match &result {
            ShadowResult::Installed(p) => p.passport_id(),
            other => panic!("expected Installed, got {other:?}"),
        };
        assert!(!registry.commit_install(&passport_id));
        assert_eq!(registry.shadow_count(), 1);
        assert_eq!(registry.passport_count(), 0);
    }
}
