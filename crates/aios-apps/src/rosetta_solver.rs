//! S21 Package Rosetta Solver — universal intake plane for foreign packages.
//!
//! The RosettaSolver analyses any foreign package, proposes the best AIOS
//! runtime and conversion strategy, scores compatibility, and manages
//! shadow-install lifecycle. It never executes foreign code on the host;
//! all observations happen in the Universal App Lab (S12.1 Phase A extension).
//!
//! ## Architecture
//!
//! ```text
//! foreign package → analyze → propose translation → shadow install → promote or block
//! ```
//!
//! - [`PackageFormat`] — 10 closed variants per S21 intake
//! - [`PackagePassport`] — holistic core state object (§5)
//! - [`RosettaTranslation`] — translation proposal with strategy + hints
//! - [`ConversionStrategy`] — 7 closed conversion paths
//! - [`CompatibilityScore`] — 0–100 explainable score
//! - [`ShadowInstall`] — dry install in overlay, never on live host
//! - [`ShadowInstallState`] — 6 closed lifecycle states
//! - [`RosettaSolver`] — the solver engine

use crate::ecosystem::EcosystemRuntime;
use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

// ---------------------------------------------------------------------------
// S21 §4 — PackageFormat (10 closed values)
// ---------------------------------------------------------------------------

/// S21 §4 — the closed set of foreign package formats the intake plane accepts.
///
/// Exe and Msi extend the S12.2 set to cover Windows installers.
/// Unknown formats are rejected by the intake loader and routed to the
/// Universal App Lab as `unidentified`.
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
pub enum PackageFormat {
    /// Debian `.deb` package with control metadata and maintainer scripts.
    Deb,
    /// RPM `.rpm` package with spec metadata and scriptlets.
    Rpm,
    /// Flatpak application bundle with manifest + portals.
    Flatpak,
    /// Snap package with plugs/slots interface model.
    Snap,
    /// AppImage self-contained portable binary.
    Appimage,
    /// Nix derivation / closure with reproducible environment.
    Nix,
    /// OCI container image (Docker/Podman-compatible).
    Oci,
    /// Source tarball or directory requiring hermetic build.
    Source,
    /// Windows PE `.exe` binary for Wine/Proton translation.
    Exe,
    /// Windows `.msi` installer package.
    Msi,
}

// ---------------------------------------------------------------------------
// S21 §5 — PackagePassport
// ---------------------------------------------------------------------------

/// S21 §5 — the holistic core state object for every catalogued or installed
/// software artifact. The passport is the machine-readable, operator-facing
/// truth surface; AI and renderers MUST read the passport before falling back
/// to raw package metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackagePassport {
    /// Globally unique passport identifier (e.g. `pkgpass_<ULID>`).
    pub passport_id: String,
    /// Human-readable application identifier (e.g. `app:publisher:name`).
    pub app_id: String,
    /// Schema version for forward compatibility.
    pub schema: String,
    /// The original foreign format at intake time.
    pub original_format: PackageFormat,
    /// The ecosystem runtime selected by the solver.
    pub target_runtime: EcosystemRuntime,
    /// The conversion method selected by the solver.
    pub conversion_method: ConversionStrategy,
    /// All compatibility checks that passed or were waived.
    pub compatibility_checks: Vec<String>,
    /// BLAKE3 hex digest of the converted/repackaged artifact.
    pub converted_artifact_hash: Option<String>,
    /// Provenance attestation grade from upstream.
    pub conversion_provenance: ProvenanceGrade,
}

impl PackagePassport {
    /// Construct a new passport with the given identity and metadata.
    #[must_use]
    pub fn new(
        passport_id: String,
        app_id: String,
        original_format: PackageFormat,
        target_runtime: EcosystemRuntime,
        conversion_method: ConversionStrategy,
    ) -> Self {
        Self {
            passport_id,
            app_id,
            schema: "aios.passport.v1alpha1".into(),
            original_format,
            target_runtime,
            conversion_method,
            compatibility_checks: Vec::new(),
            converted_artifact_hash: None,
            conversion_provenance: ProvenanceGrade::None,
        }
    }

    /// Set the provenance grade for this passport.
    pub fn set_provenance(&mut self, grade: ProvenanceGrade) {
        self.conversion_provenance = grade;
    }

    /// Record a compatibility check that was performed.
    pub fn record_check(&mut self, check: String) {
        self.compatibility_checks.push(check);
    }

    /// Set the converted artifact hash.
    pub fn set_artifact_hash(&mut self, hash: String) {
        self.converted_artifact_hash = Some(hash);
    }

    /// Returns `true` when the passport has a provenance grade above `None`.
    #[must_use]
    pub fn has_provenance(&self) -> bool {
        self.conversion_provenance != ProvenanceGrade::None
    }

    /// Returns `true` when the converted artifact hash is known.
    #[must_use]
    pub fn hash_known(&self) -> bool {
        self.converted_artifact_hash.is_some()
    }
}

// ---------------------------------------------------------------------------
// S21 §5 — ProvenanceGrade (5 closed values)
// ---------------------------------------------------------------------------

/// S21 §5 — provenance attestation grade recorded in the passport.
/// Mirrors SLSA levels plus the `NONE` and `SIGNED_ASSET` tiers.
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
pub enum ProvenanceGrade {
    /// No known provenance.
    None,
    /// The artifact has a detached signature from the publisher.
    SignedAsset,
    /// SLSA Build Level 1.
    SlsaL1,
    /// SLSA Build Level 2.
    SlsaL2,
    /// SLSA Build Level 3.
    SlsaL3,
}

// ---------------------------------------------------------------------------
// S21 §7 — ConversionStrategy (7 closed values)
// ---------------------------------------------------------------------------

/// S21 §7 — the conversion path the Rosetta pipeline selects for a foreign
/// package. Each strategy maps to a specific S17 App Capsule runtime
/// materialization path.
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
pub enum ConversionStrategy {
    /// Wrap the foreign binary directly in a minimal AIOS capsule.
    DirectWrap,
    /// Re-package the foreign artifact into an AIOS package without recompiling.
    RePackage,
    /// Re-compile from source with AIOS SDK toolchain.
    ReCompile,
    /// Build from source in a hermetic builder sandbox.
    SourceBuild,
    /// Bridge through a container runtime (e.g. Distrobox, OCI).
    ContainerBridge,
    /// Full VM isolation for untranslatable workloads.
    VmIsolate,
    /// Emulate the foreign ABI through a translation layer (Wine, Darling, Waydroid).
    Emulate,
}

// ---------------------------------------------------------------------------
// S21 §7 — ComplexityBand (4 closed values)
// ---------------------------------------------------------------------------

/// S21 §7 — estimated conversion complexity for a Rosetta translation.
/// Used to surface expected effort and risk to the operator before approval.
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
pub enum ComplexityBand {
    /// Straightforward conversion with no blockers expected.
    Low,
    /// Some manual steps or dependency resolution needed.
    Medium,
    /// Significant translation effort; VM fallback likely.
    High,
    /// Conversion is not feasible without deep engineering work.
    Critical,
}

// ---------------------------------------------------------------------------
// S21 §7 — RosettaTranslation
// ---------------------------------------------------------------------------

/// S21 §7 — a complete translation proposal from foreign package to AIOS target.
///
/// Produced by [`RosettaSolver::propose_translation`] after analysing the
/// source package. Each field represents a typed answer that the operator-facing
/// surface can render without falling back to raw package metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosettaTranslation {
    /// Human-readable identifier for the source package.
    pub source_package: String,
    /// The format of the source package at intake.
    pub source_format: PackageFormat,
    /// The AIOS runtime selected as the best target.
    pub target_runtime: EcosystemRuntime,
    /// The conversion strategy selected.
    pub translation_strategy: ConversionStrategy,
    /// Estimated complexity of the conversion.
    pub estimated_complexity: ComplexityBand,
    /// Hints for the operator about what to expect (e.g. "needs GPU passthrough").
    pub declarer_hints: Vec<String>,
    /// Warnings that do not block conversion but require attention.
    pub compatibility_warnings: Vec<String>,
}

impl RosettaTranslation {
    /// Construct a new translation proposal.
    #[must_use]
    pub fn new(
        source_package: String,
        source_format: PackageFormat,
        target_runtime: EcosystemRuntime,
        translation_strategy: ConversionStrategy,
        estimated_complexity: ComplexityBand,
    ) -> Self {
        Self {
            source_package,
            source_format,
            target_runtime,
            translation_strategy,
            estimated_complexity,
            declarer_hints: Vec::new(),
            compatibility_warnings: Vec::new(),
        }
    }

    /// Add a hint for the operator.
    pub fn add_hint(&mut self, hint: String) {
        self.declarer_hints.push(hint);
    }

    /// Add a compatibility warning.
    pub fn add_warning(&mut self, warning: String) {
        self.compatibility_warnings.push(warning);
    }

    /// Returns `true` when the translation has any warnings.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        !self.compatibility_warnings.is_empty()
    }

    /// Returns `true` when the complexity is [`ComplexityBand::Critical`].
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.estimated_complexity == ComplexityBand::Critical
    }
}

// ---------------------------------------------------------------------------
// S21 §10 — CompatibilityScore
// ---------------------------------------------------------------------------

/// S21 §10 — explainable compatibility score produced by the solver.
///
/// The score is 0–100. Blocking issues prevent conversion entirely;
/// warnings reduce confidence but do not block; recommendations suggest
/// alternative paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityScore {
    /// Overall compatibility score from 0 (impossible) to 100 (fully native).
    pub score: u8,
    /// Issues that prevent the conversion from proceeding.
    pub blocking_issues: Vec<String>,
    /// Issues that reduce confidence but do not block.
    pub warnings: Vec<String>,
    /// Suggested alternative approaches or improvements.
    pub recommendations: Vec<String>,
}

impl CompatibilityScore {
    /// Construct a new compatibility score.
    ///
    /// The score is clamped to 0..=100.
    #[must_use]
    pub fn new(score: u8) -> Self {
        Self {
            score: score.min(100),
            blocking_issues: Vec::new(),
            warnings: Vec::new(),
            recommendations: Vec::new(),
        }
    }

    /// Add a blocking issue that prevents conversion.
    pub fn add_blocking_issue(&mut self, issue: String) {
        self.blocking_issues.push(issue);
    }

    /// Add a non-blocking warning.
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Add a recommendation for the operator.
    pub fn add_recommendation(&mut self, recommendation: String) {
        self.recommendations.push(recommendation);
    }

    /// Returns `true` when there are blocking issues.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        !self.blocking_issues.is_empty()
    }

    /// Returns `true` when the score is above 75 and there are no blockers.
    #[must_use]
    pub fn is_viable(&self) -> bool {
        self.score >= 75 && !self.is_blocked()
    }

    /// Returns a summary string suitable for operator-facing surfaces.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.is_blocked() {
            format!(
                "BLOCKED ({}/100): {}",
                self.score,
                self.blocking_issues.join("; ")
            )
        } else if self.score >= 75 {
            format!("COMPATIBLE ({}/100)", self.score)
        } else {
            format!("RISKY ({}/100): see warnings", self.score)
        }
    }
}

// ---------------------------------------------------------------------------
// S21 §9 — IsolationLevel (4 closed values)
// ---------------------------------------------------------------------------

/// S21 §9 — the isolation level for a shadow install or runtime capsule.
/// Mirrors and is always at least as strong as the S3.2 floor.
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
pub enum IsolationLevel {
    /// S3.2 sandbox profile; app-private scope only.
    Sandbox,
    /// Container namespace with file/network/device policy.
    Container,
    /// Full VM isolation (KVM/QEMU).
    Vm,
    /// Physical hardware isolation (separate device).
    Hardware,
}

// ---------------------------------------------------------------------------
// S21 §9 — ShadowInstallState (6 closed values)
// ---------------------------------------------------------------------------

/// S21 §9 — the lifecycle state of a shadow install.
/// Progresses through Staging → Installing → Verifying → Complete,
/// with Failed and RolledBack as terminal states.
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
pub enum ShadowInstallState {
    /// Package artifacts staged in overlay; not yet installing.
    Staging,
    /// Maintainer scripts / extraction running inside the lab sandbox.
    Installing,
    /// Post-install verification and capability extraction in progress.
    Verifying,
    /// Shadow install completed successfully; ready for promotion.
    Complete,
    /// Shadow install failed; overlay preserved for forensics.
    Failed,
    /// Shadow install was rolled back; overlay discarded.
    RolledBack,
}

// ---------------------------------------------------------------------------
// S21 §9 — ShadowInstall
// ---------------------------------------------------------------------------

/// S21 §9 — a dry install running in an overlay/ephemeral namespace.
///
/// The shadow install never touches the live host. Maintainer scripts
/// execute only inside the lab sandbox (INV-029). Promotion to real
/// install requires a verified shadow and operator approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowInstall {
    /// Unique identifier for this shadow install.
    pub install_id: String,
    /// The source package name being evaluated.
    pub source_package: String,
    /// The target AIOS runtime for this install.
    pub target_runtime: EcosystemRuntime,
    /// The isolation level of the shadow overlay.
    pub isolation_level: IsolationLevel,
    /// Filesystem path to the isolated overlay root.
    pub install_path: String,
    /// Current lifecycle state.
    pub state: ShadowInstallState,
}

impl ShadowInstall {
    /// Create a new shadow install in Staging state.
    #[must_use]
    pub fn new(
        install_id: String,
        source_package: String,
        target_runtime: EcosystemRuntime,
        isolation_level: IsolationLevel,
        install_path: String,
    ) -> Self {
        Self {
            install_id,
            source_package,
            target_runtime,
            isolation_level,
            install_path,
            state: ShadowInstallState::Staging,
        }
    }

    /// Transition the shadow install to the given state.
    pub fn transition(&mut self, new_state: ShadowInstallState) {
        self.state = new_state;
    }

    /// Returns `true` when the shadow install is in a terminal state
    /// (Complete, Failed, or RolledBack).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ShadowInstallState::Complete
                | ShadowInstallState::Failed
                | ShadowInstallState::RolledBack
        )
    }

    /// Returns `true` when the shadow install is ready for promotion.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state == ShadowInstallState::Complete
    }
}

// ---------------------------------------------------------------------------
// S21 §11 — RosettaSolver
// ---------------------------------------------------------------------------

/// S21 §11 — the Package Rosetta Solver engine.
///
/// Analyses foreign packages, proposes the best AIOS runtime + conversion
/// strategy, scores compatibility, and produces the seed inputs for the
/// shadow-install pipeline. This is the universal solver instantiated for
/// packages; it consumes the S21 intake catalogue and emits
/// [`RosettaTranslation`] and [`CompatibilityScore`] outputs.
///
/// ## Usage
///
/// ```text
/// let solver = RosettaSolver::new();
/// let analysis = solver.analyze_package("firefox", PackageFormat::Deb);
/// let translation = solver.propose_translation("firefox", PackageFormat::Deb);
/// let score = solver.validate_compatibility(PackageFormat::Deb, EcosystemRuntime::RuntimeFlatpak);
/// let best = solver.determine_best_runtime(PackageFormat::Deb);
/// ```
#[derive(Clone, Debug, Default)]
pub struct RosettaSolver {
    /// Currently available ecosystem runtimes.
    available_runtimes: Vec<EcosystemRuntime>,
    /// List of package formats that have been analysed in this session.
    analyses: Vec<String>,
}

impl RosettaSolver {
    /// Create a new solver with a default set of available runtimes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available_runtimes: default_runtimes(),
            analyses: Vec::new(),
        }
    }

    /// Create a solver with a custom set of available runtimes.
    #[must_use]
    pub fn with_runtimes(available_runtimes: Vec<EcosystemRuntime>) -> Self {
        Self {
            available_runtimes,
            analyses: Vec::new(),
        }
    }

    /// Analyse a package and record the analysis for later translation.
    ///
    /// Returns a human-readable analysis summary. The analysis is idempotent —
    /// repeated calls for the same package return the same result.
    #[must_use]
    pub fn analyze_package(&self, package_name: &str, format: PackageFormat) -> String {
        let complexity = self.estimate_complexity(format);
        let best = self.determine_best_runtime(format);
        format!(
            "{} ({}) → {} via {:?} [{:?} complexity]",
            package_name, format, best, best, complexity
        )
    }

    /// Propose a complete translation from a foreign package to an AIOS target.
    ///
    /// The translation includes the selected target runtime, conversion strategy,
    /// estimated complexity, and declarer hints. Compatibility warnings are
    /// populated based on the format and target runtime mismatch risk.
    #[must_use]
    pub fn propose_translation(
        &self,
        source_package: &str,
        source_format: PackageFormat,
    ) -> RosettaTranslation {
        let target = self.determine_best_runtime(source_format);
        let strategy = Self::strategy_for_format(source_format);
        let complexity = self.estimate_complexity(source_format);

        let mut translation = RosettaTranslation::new(
            source_package.to_string(),
            source_format,
            target,
            strategy,
            complexity,
        );

        match source_format {
            PackageFormat::Deb | PackageFormat::Rpm | PackageFormat::Appimage => {
                translation.add_hint("maintainer scripts will be observed in lab".into());
                translation.add_hint("dependency graph will be resolved".into());
            }
            PackageFormat::Flatpak => {
                translation.add_hint("Flatpak manifest portals mapped to AIOS capabilities".into());
            }
            PackageFormat::Snap => {
                translation.add_hint("Snap plugs/slots mapped to sandbox profile".into());
            }
            PackageFormat::Nix => {
                translation.add_hint("derivation hash recorded as provenance".into());
            }
            PackageFormat::Oci => {
                translation.add_hint("container image; Docker socket never exposed".into());
            }
            PackageFormat::Source => {
                translation.add_hint("hermetic build sandbox required".into());
                translation.add_hint("SBOM + provenance will be generated".into());
            }
            PackageFormat::Exe | PackageFormat::Msi => {
                translation.add_hint("Windows binary; Wine/Proton translation layer".into());
                translation.add_hint("VM fallback available if translation fails".into());
            }
        }

        if complexity > ComplexityBand::Medium {
            translation.add_warning(format!(
                "Conversion complexity is {:?}; review expected effort",
                complexity
            ));
        }

        if let Some(warning) = Self::format_runtime_mismatch_warning(source_format, target) {
            translation.add_warning(warning);
        }

        translation
    }

    /// Estimate the conversion complexity for a given format.
    ///
    /// Native Linux formats score Low; container formats score Medium;
    /// foreign-ABI formats score High; raw source builds score Medium.
    #[must_use]
    pub fn estimate_complexity(&self, format: PackageFormat) -> ComplexityBand {
        match format {
            PackageFormat::Deb | PackageFormat::Rpm => ComplexityBand::Low,
            PackageFormat::Flatpak | PackageFormat::Snap => ComplexityBand::Low,
            PackageFormat::Appimage => ComplexityBand::Low,
            PackageFormat::Nix => ComplexityBand::Medium,
            PackageFormat::Oci => ComplexityBand::Medium,
            PackageFormat::Source => ComplexityBand::Medium,
            PackageFormat::Exe | PackageFormat::Msi => ComplexityBand::High,
        }
    }

    /// Validate compatibility between a source format and a target runtime.
    ///
    /// Returns a [`CompatibilityScore`] with a 0–100 score, blocking issues,
    /// warnings, and recommendations. A score below 75 with blockers means
    /// the conversion is not recommended; a score of 100 means fully native.
    #[must_use]
    pub fn validate_compatibility(
        &self,
        format: PackageFormat,
        target: EcosystemRuntime,
    ) -> CompatibilityScore {
        let native_runtime = Self::native_runtime_for_format(format);
        if target == native_runtime {
            let mut score = CompatibilityScore::new(100);
            score.add_recommendation("Fully native execution path".into());
            return score;
        }

        if !self.available_runtimes.contains(&target) {
            let mut score = CompatibilityScore::new(0);
            score.add_blocking_issue(format!(
                "Target runtime {} is not available in this environment",
                target
            ));
            score
                .add_recommendation(format!("Install the {} runtime adapter first", target));
            return score;
        }

        let base: u8 = match format {
            PackageFormat::Deb | PackageFormat::Rpm => 90,
            PackageFormat::Flatpak => 85,
            PackageFormat::Snap => 80,
            PackageFormat::Appimage => 75,
            PackageFormat::Nix => 70,
            PackageFormat::Oci => 65,
            PackageFormat::Source => 60,
            PackageFormat::Exe | PackageFormat::Msi => 40,
        };

        let penalty: u8 = if target != Self::native_runtime_for_format(format) {
            15
        } else {
            0
        };

        let score_value = base.saturating_sub(penalty);
        let mut score = CompatibilityScore::new(score_value);

        if format == PackageFormat::Exe || format == PackageFormat::Msi {
            score.add_warning("Windows binary requires Wine/Proton or VM".into());
            score.add_recommendation("Consider the native Linux version if available".into());
        }

        if format == PackageFormat::Source {
            score.add_warning("Source build may fail in hermetic environment".into());
            score.add_recommendation("Pre-built binary preferred when available".into());
        }

        score
    }

    /// Determine the best ecosystem runtime for a given package format.
    ///
    /// Uses a deterministic mapping based on the format's native ABI and
    /// isolation requirements. The solver always prefers the native runtime
    /// over VM fallback; VM is only returned when no lighter runtime fits.
    #[must_use]
    pub fn determine_best_runtime(&self, format: PackageFormat) -> EcosystemRuntime {
        Self::native_runtime_for_format(format)
    }

    /// Return the current list of available runtimes.
    #[must_use]
    pub fn available_runtimes(&self) -> &[EcosystemRuntime] {
        &self.available_runtimes
    }

    /// Return the number of packages analysed in this session.
    #[must_use]
    pub fn analysis_count(&self) -> usize {
        self.analyses.len()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Map a package format to its native runtime.
    fn native_runtime_for_format(format: PackageFormat) -> EcosystemRuntime {
        match format {
            PackageFormat::Deb
            | PackageFormat::Rpm
            | PackageFormat::Appimage
            | PackageFormat::Source => EcosystemRuntime::RuntimeLinuxNative,
            PackageFormat::Flatpak => EcosystemRuntime::RuntimeFlatpak,
            PackageFormat::Snap => EcosystemRuntime::RuntimeSnap,
            PackageFormat::Nix => EcosystemRuntime::RuntimeDistrobox,
            PackageFormat::Oci => EcosystemRuntime::RuntimeLinuxNative,
            PackageFormat::Exe | PackageFormat::Msi => EcosystemRuntime::RuntimeWindowsProton,
        }
    }

    /// Select the conversion strategy for a given format.
    fn strategy_for_format(format: PackageFormat) -> ConversionStrategy {
        match format {
            PackageFormat::Deb | PackageFormat::Rpm => ConversionStrategy::RePackage,
            PackageFormat::Flatpak | PackageFormat::Snap => ConversionStrategy::DirectWrap,
            PackageFormat::Appimage => ConversionStrategy::DirectWrap,
            PackageFormat::Nix => ConversionStrategy::ContainerBridge,
            PackageFormat::Oci => ConversionStrategy::ContainerBridge,
            PackageFormat::Source => ConversionStrategy::SourceBuild,
            PackageFormat::Exe | PackageFormat::Msi => ConversionStrategy::Emulate,
        }
    }

    /// Return a warning string when the format and runtime are a suboptimal match.
    fn format_runtime_mismatch_warning(
        format: PackageFormat,
        target: EcosystemRuntime,
    ) -> Option<String> {
        let native = Self::native_runtime_for_format(format);
        if target != native {
            Some(format!(
                "Non-native runtime: {} format mapped to {} (native would be {})",
                format, target, native
            ))
        } else {
            None
        }
    }
}

/// Default set of all 12 ecosystem runtimes.
#[must_use]
fn default_runtimes() -> Vec<EcosystemRuntime> {
    use strum::IntoEnumIterator;
    EcosystemRuntime::iter().collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // T-001: PackageFormat closed enum has 10 variants
    // ------------------------------------------------------------------

    #[test]
    fn package_format_has_10_variants() {
        use strum::IntoEnumIterator;
        let variants: Vec<PackageFormat> = PackageFormat::iter().collect();
        assert_eq!(
            variants.len(),
            10,
            "S21 PackageFormat must have exactly 10 closed variants"
        );
    }

    // ------------------------------------------------------------------
    // T-002: PackagePassport construction and field access
    // ------------------------------------------------------------------

    #[test]
    fn package_passport_construction() {
        let passport = PackagePassport::new(
            "pkgpass_01J".into(),
            "app:mozilla:firefox".into(),
            PackageFormat::Deb,
            EcosystemRuntime::RuntimeLinuxNative,
            ConversionStrategy::RePackage,
        );
        assert_eq!(passport.passport_id, "pkgpass_01J");
        assert_eq!(passport.original_format, PackageFormat::Deb);
        assert_eq!(passport.target_runtime, EcosystemRuntime::RuntimeLinuxNative);
        assert_eq!(passport.schema, "aios.passport.v1alpha1");
        assert!(!passport.has_provenance());
        assert!(!passport.hash_known());
    }

    // ------------------------------------------------------------------
    // T-003: PackagePassport provenance and checks
    // ------------------------------------------------------------------

    #[test]
    fn package_passport_provenance_and_checks() {
        let mut passport = PackagePassport::new(
            "pkgpass_02".into(),
            "app:debian:nginx".into(),
            PackageFormat::Deb,
            EcosystemRuntime::RuntimeLinuxNative,
            ConversionStrategy::RePackage,
        );
        passport.set_provenance(ProvenanceGrade::SlsaL2);
        assert!(passport.has_provenance());
        assert_eq!(passport.conversion_provenance, ProvenanceGrade::SlsaL2);

        passport.record_check("dependency-graph-resolved".into());
        passport.record_check("no-setuid-binaries".into());
        assert_eq!(passport.compatibility_checks.len(), 2);

        passport.set_artifact_hash(
            "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c".into(),
        );
        assert!(passport.hash_known());
    }

    // ------------------------------------------------------------------
    // T-004: ConversionStrategy closed enum has 7 variants
    // ------------------------------------------------------------------

    #[test]
    fn conversion_strategy_has_7_variants() {
        use strum::IntoEnumIterator;
        let variants: Vec<ConversionStrategy> = ConversionStrategy::iter().collect();
        assert_eq!(
            variants.len(),
            7,
            "S21 ConversionStrategy must have exactly 7 closed variants"
        );
    }

    // ------------------------------------------------------------------
    // T-005: CompatibilityScore construction and blocking
    // ------------------------------------------------------------------

    #[test]
    fn compatibility_score_construction_and_blocking() {
        let mut score = CompatibilityScore::new(85);
        assert_eq!(score.score, 85);
        assert!(!score.is_blocked());
        assert!(score.is_viable());

        score.add_blocking_issue("kernel module required but not available".into());
        assert!(score.is_blocked());
        assert!(!score.is_viable());
    }

    // ------------------------------------------------------------------
    // T-006: CompatibilityScore clamping
    // ------------------------------------------------------------------

    #[test]
    fn compatibility_score_clamps_to_100() {
        let score = CompatibilityScore::new(150);
        assert_eq!(score.score, 100);
    }

    // ------------------------------------------------------------------
    // T-007: CompatibilityScore summary strings
    // ------------------------------------------------------------------

    #[test]
    fn compatibility_score_summary() {
        let mut blocked = CompatibilityScore::new(30);
        blocked.add_blocking_issue("unsupported ABI".into());
        assert!(blocked.summary().contains("BLOCKED"));

        let viable = CompatibilityScore::new(90);
        assert!(viable.summary().contains("COMPATIBLE"));

        let risky = CompatibilityScore::new(60);
        assert!(risky.summary().contains("RISKY"));
    }

    // ------------------------------------------------------------------
    // T-008: ShadowInstall lifecycle states
    // ------------------------------------------------------------------

    #[test]
    fn shadow_install_lifecycle() {
        let mut shadow = ShadowInstall::new(
            "shadow_01".into(),
            "firefox".into(),
            EcosystemRuntime::RuntimeLinuxNative,
            IsolationLevel::Sandbox,
            "/tmp/aios/shadow/firefox".into(),
        );

        assert_eq!(shadow.state, ShadowInstallState::Staging);
        assert!(!shadow.is_terminal());
        assert!(!shadow.is_ready());

        shadow.transition(ShadowInstallState::Installing);
        assert_eq!(shadow.state, ShadowInstallState::Installing);

        shadow.transition(ShadowInstallState::Verifying);
        shadow.transition(ShadowInstallState::Complete);
        assert!(shadow.is_terminal());
        assert!(shadow.is_ready());
    }

    // ------------------------------------------------------------------
    // T-009: ShadowInstallState closed enum has 6 variants
    // ------------------------------------------------------------------

    #[test]
    fn shadow_install_state_has_6_variants() {
        use strum::IntoEnumIterator;
        let variants: Vec<ShadowInstallState> = ShadowInstallState::iter().collect();
        assert_eq!(
            variants.len(),
            6,
            "S21 ShadowInstallState must have exactly 6 closed variants"
        );
    }

    // ------------------------------------------------------------------
    // T-010: RosettaSolver analyzes a native package
    // ------------------------------------------------------------------

    #[test]
    fn rosetta_solver_analyze_deb_package() {
        let solver = RosettaSolver::new();
        let analysis = solver.analyze_package("nginx", PackageFormat::Deb);
        assert!(analysis.starts_with("nginx"));
        assert!(analysis.contains("Deb"));
        assert!(analysis.contains("LinuxNative"));
    }

    // ------------------------------------------------------------------
    // T-011: RosettaSolver proposes translation for all formats
    // ------------------------------------------------------------------

    #[test]
    fn rosetta_solver_propose_all_formats() {
        let solver = RosettaSolver::new();
        let formats = [
            PackageFormat::Deb,
            PackageFormat::Rpm,
            PackageFormat::Flatpak,
            PackageFormat::Snap,
            PackageFormat::Appimage,
            PackageFormat::Nix,
            PackageFormat::Oci,
            PackageFormat::Source,
            PackageFormat::Exe,
            PackageFormat::Msi,
        ];
        for fmt in &formats {
            let translation = solver.propose_translation("test-app", *fmt);
            assert_eq!(translation.source_package, "test-app");
            assert_eq!(translation.source_format, *fmt);
            assert!(
                !translation.declarer_hints.is_empty(),
                "format {fmt:?} should have declarer hints"
            );
        }
    }

    // ------------------------------------------------------------------
    // T-012: RosettaSolver estimate_complexity for all formats
    // ------------------------------------------------------------------

    #[test]
    fn rosetta_solver_estimate_complexity() {
        let solver = RosettaSolver::new();
        assert_eq!(
            solver.estimate_complexity(PackageFormat::Deb),
            ComplexityBand::Low
        );
        assert_eq!(
            solver.estimate_complexity(PackageFormat::Flatpak),
            ComplexityBand::Low
        );
        assert_eq!(
            solver.estimate_complexity(PackageFormat::Nix),
            ComplexityBand::Medium
        );
        assert_eq!(
            solver.estimate_complexity(PackageFormat::Oci),
            ComplexityBand::Medium
        );
        assert_eq!(
            solver.estimate_complexity(PackageFormat::Exe),
            ComplexityBand::High
        );
        assert_eq!(
            solver.estimate_complexity(PackageFormat::Msi),
            ComplexityBand::High
        );
    }

    // ------------------------------------------------------------------
    // T-013: RosettaSolver determine_best_runtime
    // ------------------------------------------------------------------

    #[test]
    fn rosetta_solver_determine_best_runtime() {
        let solver = RosettaSolver::new();
        assert_eq!(
            solver.determine_best_runtime(PackageFormat::Deb),
            EcosystemRuntime::RuntimeLinuxNative
        );
        assert_eq!(
            solver.determine_best_runtime(PackageFormat::Flatpak),
            EcosystemRuntime::RuntimeFlatpak
        );
        assert_eq!(
            solver.determine_best_runtime(PackageFormat::Snap),
            EcosystemRuntime::RuntimeSnap
        );
        assert_eq!(
            solver.determine_best_runtime(PackageFormat::Exe),
            EcosystemRuntime::RuntimeWindowsProton
        );
        assert_eq!(
            solver.determine_best_runtime(PackageFormat::Msi),
            EcosystemRuntime::RuntimeWindowsProton
        );
    }

    // ------------------------------------------------------------------
    // T-014: RosettaSolver validate_compatibility native path
    // ------------------------------------------------------------------

    #[test]
    fn rosetta_solver_validate_native_compatibility() {
        let solver = RosettaSolver::new();
        let score = solver.validate_compatibility(
            PackageFormat::Deb,
            EcosystemRuntime::RuntimeLinuxNative,
        );
        assert_eq!(score.score, 100);
        assert!(!score.is_blocked());
        assert!(score.is_viable());
    }

    // ------------------------------------------------------------------
    // T-015: RosettaSolver validate_compatibility Windows format to non-native runtime
    // ------------------------------------------------------------------

    #[test]
    fn rosetta_solver_validate_windows_to_linux() {
        let solver = RosettaSolver::new();
        let score = solver.validate_compatibility(
            PackageFormat::Exe,
            EcosystemRuntime::RuntimeLinuxNative,
        );
        assert!(score.score < 100, "Exe→LinuxNative should not score 100");
        assert!(score.score > 0, "Windows should not be blocked");
        assert!(!score.warnings.is_empty());
    }

    // ------------------------------------------------------------------
    // T-016: RosettaSolver with custom runtimes
    // ------------------------------------------------------------------

    #[test]
    fn rosetta_solver_custom_runtimes() {
        let limited = vec![EcosystemRuntime::RuntimeLinuxNative];
        let solver = RosettaSolver::with_runtimes(limited);
        assert_eq!(solver.available_runtimes().len(), 1);

        let score = solver.validate_compatibility(
            PackageFormat::Oci,
            EcosystemRuntime::RuntimeFlatpak,
        );
        assert!(score.is_blocked());
        assert!(score
            .blocking_issues
            .iter()
            .any(|i| i.contains("not available")));
    }

    // ------------------------------------------------------------------
    // T-017: RosettaTranslation has_warnings and is_blocked
    // ------------------------------------------------------------------

    #[test]
    fn rosetta_translation_warnings_and_blocked() {
        let mut translation = RosettaTranslation::new(
            "risky.exe".into(),
            PackageFormat::Exe,
            EcosystemRuntime::RuntimeWindowsProton,
            ConversionStrategy::Emulate,
            ComplexityBand::High,
        );
        assert!(!translation.has_warnings());
        assert!(!translation.is_blocked());

        translation.add_warning("anti-cheat kernel driver required".into());
        assert!(translation.has_warnings());
        assert!(!translation.is_blocked());

        let blocked = RosettaTranslation::new(
            "broken.exe".into(),
            PackageFormat::Exe,
            EcosystemRuntime::RuntimeWindowsProton,
            ConversionStrategy::VmIsolate,
            ComplexityBand::Critical,
        );
        assert!(blocked.is_blocked());
    }

    // ------------------------------------------------------------------
    // T-018: ProvenanceGrade ordering
    // ------------------------------------------------------------------

    #[test]
    fn provenance_grade_ordering() {
        assert!(ProvenanceGrade::SignedAsset > ProvenanceGrade::None);
        assert!(ProvenanceGrade::SlsaL1 > ProvenanceGrade::SignedAsset);
        assert!(ProvenanceGrade::SlsaL3 > ProvenanceGrade::SlsaL2);
        assert!(ProvenanceGrade::SlsaL2 > ProvenanceGrade::None);
    }

    // ------------------------------------------------------------------
    // T-019: ShadowInstall terminal states
    // ------------------------------------------------------------------

    #[test]
    fn shadow_install_terminal_states() {
        let base = ShadowInstall::new(
            "sid_01".into(),
            "app".into(),
            EcosystemRuntime::RuntimeLinuxNative,
            IsolationLevel::Container,
            "/overlay/app".into(),
        );

        let mut failed = base.clone();
        failed.transition(ShadowInstallState::Failed);
        assert!(failed.is_terminal());
        assert!(!failed.is_ready());

        let mut rolled = base.clone();
        rolled.transition(ShadowInstallState::RolledBack);
        assert!(rolled.is_terminal());
        assert!(!rolled.is_ready());
    }

    // ------------------------------------------------------------------
    // T-020: RosettaSolver analysis count starts at zero
    // ------------------------------------------------------------------

    #[test]
    fn rosetta_solver_analysis_count() {
        let solver = RosettaSolver::new();
        assert_eq!(solver.analysis_count(), 0);
    }

    // ------------------------------------------------------------------
    // T-021: IsolationLevel closed enum has 4 variants
    // ------------------------------------------------------------------

    #[test]
    fn isolation_level_has_4_variants() {
        use strum::IntoEnumIterator;
        let variants: Vec<IsolationLevel> = IsolationLevel::iter().collect();
        assert_eq!(
            variants.len(),
            4,
            "S21 IsolationLevel must have exactly 4 closed variants"
        );
    }

    // ------------------------------------------------------------------
    // T-022: RosettaSolver propose_translation adds warnings for high complexity
    // ------------------------------------------------------------------

    #[test]
    fn rosetta_translation_has_warnings_for_high_complexity() {
        let solver = RosettaSolver::new();
        let translation = solver.propose_translation("setup.exe", PackageFormat::Exe);
        assert!(
            translation.has_warnings(),
            "Exe translation should have complexity warnings"
        );
    }

    // ------------------------------------------------------------------
    // T-023: Serde round-trip for key types
    // ------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_package_format() {
        for fmt in [PackageFormat::Deb, PackageFormat::Exe, PackageFormat::Msi] {
            let json = serde_json::to_string(&fmt).expect("serialize");
            let round: PackageFormat = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(fmt, round);
        }
    }

    #[test]
    fn serde_roundtrip_shadow_install_state() {
        for state in [
            ShadowInstallState::Staging,
            ShadowInstallState::Installing,
            ShadowInstallState::Complete,
            ShadowInstallState::Failed,
        ] {
            let json = serde_json::to_string(&state).expect("serialize");
            let round: ShadowInstallState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(state, round);
        }
    }

    #[test]
    fn serde_roundtrip_conversion_strategy() {
        let strategy = ConversionStrategy::Emulate;
        let json = serde_json::to_string(&strategy).expect("serialize");
        let round: ConversionStrategy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(strategy, round);
    }
}
