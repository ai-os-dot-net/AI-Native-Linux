#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
//! Measured Boot Attestation Chain — TPM PCR quote → measured boot log →
//! IMA appraisal → dm-verity root hash assembled into a single attestation
//! report validated against the per-profile [`MeasuredBootPolicy`] (S16.4).
//!
//! ## OS Research Provenance
//!
//! The measured boot attestation chain is the AIOS implementation of the
//! **dual-chain attestation root** mandated by DEC-R3-002. It combines:
//!
//! 1. **TPM PCR Quote** — hardware-rooted attestation via signed quotes
//!    over PCR registers 0–15 (SRTM) and 17–22 (DRTM).
//! 2. **Measured Boot Log** — the TCG event log recording every boot-stage
//!    measurement in insertion order.
//! 3. **IMA Appraisal** — Linux IMA/EVM file-integrity verification of
//!    security-critical binaries.
//! 4. **dm-verity Root Hash** — block-level immutable root filesystem
//!    integrity via Merkle tree verification.
//!
//! The chain is evaluated against a [`MeasuredBootPolicy`] derived from
//! the active [`super::SecurityProfile`]. A `DEV_RELAXED` host requires
//! minimal evidence; an `AIRGAP_HIGH` host demands the full chain with
//! no exceptions.
//!
//! ## Constitutional invariants
//!
//! - **INV-BOA-001 (Chain completeness):** An [`attest_boot_chain`] call
//!   MUST produce a `BootAttestationReport` with a populated `integrity_state`
//!   —  it never returns `RecoveryRequired` silently.
//! - **INV-BOA-002 (Policy precedence):** [`MeasuredBootPolicy`] MUST be
//!   derived from the active [`SecurityProfile`]; lowest-profile policies
//!   are the most permissive, highest-profile are the most restrictive.
//! - **INV-BOA-003 (Evidence immutability):** A `BootAttestedPayload` record
//!   is immutable once created; it carries the complete chain state at
//!   attestation time.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};
use thiserror::Error;

use super::ima::ImaAppraisalState;
use super::security_profile::SecurityProfile;
use super::tpm::PcrBank;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during boot attestation chain assembly.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BootAttestationError {
    /// The TPM quote required by policy is missing or invalid.
    #[error("tpm quote required but not provided or invalid")]
    TpmQuoteMissing,
    /// The PCR bank used in the quote does not match the policy requirement.
    #[error("pcr bank mismatch: got {observed}, required {required}")]
    PcrBankMismatch {
        /// The PCR bank observed in the quote.
        observed: PcrBank,
        /// The PCR bank required by the policy.
        required: PcrBank,
    },
    /// IMA appraisal is required by policy but no appraisal result is available.
    #[error("ima appraisal required but not available")]
    ImaAppraisalMissing,
    /// IMA appraisal detected integrity violations.
    #[error("ima appraisal detected {count} integrity violation(s)")]
    ImaAppraisalViolation {
        /// Number of violations detected.
        count: usize,
    },
    /// dm-verity root hash verification is required but failed or is missing.
    #[error("dm-verity root hash verification required but failed")]
    VerityRootHashMissing,
    /// An untrusted IMA appraisal state was detected on a profile that does
    /// not tolerate it.
    #[error("ima appraisal state is {state} but profile requires trusted")]
    ImaAppraisalUntrusted {
        /// The observed IMA appraisal state.
        state: ImaAppraisalState,
    },
    /// The provided kernel command-line hash does not match any allowed hash.
    #[error("kernel command-line hash is not in the allowed set")]
    KernelCmdlineHashNotAllowed,
    /// The boot attestation chain is incomplete — a required component is
    /// absent and the profile does not permit it.
    #[error("boot chain incomplete: {detail}")]
    ChainIncomplete {
        /// Human-readable detail about what is missing.
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// BootIntegrityState — closed enum for boot integrity verdict
// ---------------------------------------------------------------------------

/// The integrity state of the boot chain after full attestation.
///
/// Ordered from most trusted to least trusted.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BootIntegrityState {
    /// All attestation checks passed. The boot chain matches the expected
    /// golden measurements and the system is in a trusted state.
    Trusted,
    /// The boot chain has minor deviations that do not immediately
    /// compromise the system but require operator review. Examples:
    /// a non-critical IMA measurement mismatch, a stale but still-valid
    /// TPM quote.
    Degraded,
    /// One or more attestation checks failed. The boot chain has been
    /// compromised or is running unapproved code. The system continues
    /// to operate but is not in a trusted state.
    Untrusted,
    /// A critical integrity check failed. The system cannot continue
    /// normal operation and must drop to the S9.1 recovery boundary.
    /// This is the terminal state for hard-fail conditions.
    RecoveryRequired,
}

impl BootIntegrityState {
    /// Human-readable label for evidence records.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Degraded => "DEGRADED",
            Self::Untrusted => "UNTRUSTED",
            Self::RecoveryRequired => "RECOVERY_REQUIRED",
        }
    }

    /// Whether this state allows normal system operation.
    #[must_use]
    pub fn is_operational(self) -> bool {
        matches!(self, Self::Trusted | Self::Degraded)
    }

    /// Whether this state requires immediate recovery action.
    #[must_use]
    pub fn requires_recovery(self) -> bool {
        matches!(self, Self::RecoveryRequired)
    }

    /// Whether this is a trusted state (strict check).
    #[must_use]
    pub fn is_trusted(self) -> bool {
        matches!(self, Self::Trusted)
    }
}

impl fmt::Display for BootIntegrityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// MeasuredBootPolicy — per-profile boot attestation requirements
// ---------------------------------------------------------------------------

/// Per-profile requirements for boot attestation.
///
/// The policy defines which components of the attestation chain are
/// mandatory, which PCR bank is required, and which kernel command-line
/// hashes are permitted. It is derived from the active [`SecurityProfile`].
///
/// INV-BOA-002: The policy is monotonically more restrictive as the
/// security profile increases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredBootPolicy {
    /// The security profile this policy applies to.
    pub profile: SecurityProfile,
    /// Whether a TPM is required for this profile.
    pub tpm_required: bool,
    /// Whether IMA appraisal is required for this profile.
    pub ima_required: bool,
    /// Whether dm-verity root hash verification is required.
    pub verity_required: bool,
    /// The minimum PCR bank required for TPM quotes.
    pub pcr_bank: PcrBank,
    /// Allowed kernel command-line SHA-256 hashes. If empty, any
    /// command-line is accepted.
    pub allowed_kernel_cmdline_hashes: Vec<[u8; 32]>,
}

impl MeasuredBootPolicy {
    /// Derive the canonical boot attestation policy for a given
    /// [`SecurityProfile`].
    ///
    /// The policy is derived from S16.4 §10:
    ///
    /// | Dimension           | DEV_RELAXED    | SECURE_DEFAULT | STIG_ALIGNED  | AIRGAP_HIGH   |
    /// |---------------------|----------------|----------------|---------------|---------------|
    /// | TPM required        | false          | false          | true*         | true          |
    /// | IMA required        | false          | false          | true          | true          |
    /// | Verity required     | false          | false          | true*         | true          |
    /// | PCR bank floor      | SHA1           | SHA256         | SHA256        | SHA256        |
    #[must_use]
    pub fn for_profile(profile: SecurityProfile) -> Self {
        match profile {
            SecurityProfile::DevRelaxed => Self {
                profile,
                tpm_required: false,
                ima_required: false,
                verity_required: false,
                pcr_bank: PcrBank::Sha1,
                allowed_kernel_cmdline_hashes: Vec::new(),
            },
            SecurityProfile::SecureDefault => Self {
                profile,
                tpm_required: false,
                ima_required: false,
                verity_required: false,
                pcr_bank: PcrBank::Sha256,
                allowed_kernel_cmdline_hashes: Vec::new(),
            },
            SecurityProfile::StigAligned => Self {
                profile,
                tpm_required: true,
                ima_required: true,
                verity_required: true,
                pcr_bank: PcrBank::Sha256,
                allowed_kernel_cmdline_hashes: Vec::new(),
            },
            SecurityProfile::AirgapHigh => Self {
                profile,
                tpm_required: true,
                ima_required: true,
                verity_required: true,
                pcr_bank: PcrBank::Sha256,
                allowed_kernel_cmdline_hashes: Vec::new(),
            },
        }
    }

    /// Whether this policy permits TPM-absent hardware to satisfy the
    /// attestation requirements.
    #[must_use]
    pub fn allows_tpm_absent(&self) -> bool {
        !self.tpm_required
    }

    /// Whether this policy is satisfied by the given integrity state.
    ///
    /// - `Trusted` satisfies every policy.
    /// - `Degraded` satisfies `DEV_RELAXED` and `SECURE_DEFAULT`.
    /// - `Untrusted` does not satisfy any non-dev policy.
    /// - `RecoveryRequired` satisfies no policy.
    #[must_use]
    pub fn accepts_state(&self, state: BootIntegrityState) -> bool {
        match (self.profile, state) {
            (_, BootIntegrityState::Trusted) => true,
            (SecurityProfile::DevRelaxed, BootIntegrityState::Degraded) => true,
            (SecurityProfile::SecureDefault, BootIntegrityState::Degraded) => true,
            (_, BootIntegrityState::Degraded) => false,
            (SecurityProfile::DevRelaxed, BootIntegrityState::Untrusted) => true,
            (_, BootIntegrityState::Untrusted) => false,
            (_, BootIntegrityState::RecoveryRequired) => false,
        }
    }

    /// Add an allowed kernel command-line hash.
    pub fn allow_cmdline_hash(&mut self, hash: [u8; 32]) {
        self.allowed_kernel_cmdline_hashes.push(hash);
    }

    /// Check whether a given kernel command-line hash is allowed.
    #[must_use]
    pub fn is_cmdline_hash_allowed(&self, hash: &[u8; 32]) -> bool {
        if self.allowed_kernel_cmdline_hashes.is_empty() {
            return true;
        }
        self.allowed_kernel_cmdline_hashes.contains(hash)
    }
}

impl Default for MeasuredBootPolicy {
    fn default() -> Self {
        Self::for_profile(SecurityProfile::DevRelaxed)
    }
}

// ---------------------------------------------------------------------------
// BootAttestationReport — the assembled attestation result
// ---------------------------------------------------------------------------

/// The complete result of a boot attestation chain evaluation.
///
/// Contains all the evidence gathered from each layer of the attestation
/// chain, plus the overall integrity state verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootAttestationReport {
    /// The overall boot integrity state after evaluating all layers.
    pub integrity_state: BootIntegrityState,
    /// The security profile against which the chain was evaluated.
    pub evaluated_profile: SecurityProfile,
    /// Whether a TPM quote was provided and verified.
    pub tpm_quote_provided: bool,
    /// Whether the TPM PCR values matched the golden expectations.
    /// `None` if no TPM quote was provided.
    pub pcr_values_matched: Option<bool>,
    /// Hex-encoded PCR quote digest, when available.
    pub pcr_quote_digest_hex: Option<String>,
    /// The IMA appraisal result. `None` if IMA was not evaluated.
    pub ima_appraisal_result: Option<ImaAppraisalState>,
    /// Number of IMA integrity violations detected.
    pub ima_violation_count: u64,
    /// The dm-verity root hash, when available.
    pub verity_root_hash: Option<[u8; 32]>,
    /// Whether the verity root hash was verified.
    pub verity_root_verified: bool,
    /// SHA-256 hash of the kernel command-line.
    pub kernel_cmdline_hash: Option<[u8; 32]>,
    /// SHA-256 hash of the initramfs.
    pub initramfs_hash: Option<[u8; 32]>,
    /// Unix timestamp (seconds) when the attestation was performed.
    pub boot_timestamp: u64,
    /// Human-readable summary of the attestation result.
    pub summary: String,
}

impl BootAttestationReport {
    /// Create a new attestation report for a given profile and state.
    #[must_use]
    pub fn new(
        profile: SecurityProfile,
        state: BootIntegrityState,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            integrity_state: state,
            evaluated_profile: profile,
            tpm_quote_provided: false,
            pcr_values_matched: None,
            pcr_quote_digest_hex: None,
            ima_appraisal_result: None,
            ima_violation_count: 0,
            verity_root_hash: None,
            verity_root_verified: false,
            kernel_cmdline_hash: None,
            initramfs_hash: None,
            boot_timestamp: current_time_secs(),
            summary: summary.into(),
        }
    }

    /// Record that a TPM quote was provided with a specific result.
    pub fn with_tpm_quote(
        mut self,
        quote_digest_hex: impl Into<String>,
        pcr_matched: bool,
    ) -> Self {
        self.tpm_quote_provided = true;
        self.pcr_values_matched = Some(pcr_matched);
        self.pcr_quote_digest_hex = Some(quote_digest_hex.into());
        self
    }

    /// Record the IMA appraisal result.
    pub fn with_ima_appraisal(mut self, result: ImaAppraisalState, violation_count: u64) -> Self {
        self.ima_appraisal_result = Some(result);
        self.ima_violation_count = violation_count;
        self
    }

    /// Record the dm-verity root hash verification result.
    pub fn with_verity_root(mut self, root_hash: [u8; 32], verified: bool) -> Self {
        self.verity_root_hash = Some(root_hash);
        self.verity_root_verified = verified;
        self
    }

    /// Record the kernel command-line hash.
    pub fn with_kernel_cmdline_hash(mut self, hash: [u8; 32]) -> Self {
        self.kernel_cmdline_hash = Some(hash);
        self
    }

    /// Record the initramfs hash.
    pub fn with_initramfs_hash(mut self, hash: [u8; 32]) -> Self {
        self.initramfs_hash = Some(hash);
        self
    }

    /// Whether this report indicates a trusted boot.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        self.integrity_state.is_trusted()
    }

    /// Whether the active profile accepts this attestation result.
    #[must_use]
    pub fn is_accepted_by_profile(&self) -> bool {
        MeasuredBootPolicy::for_profile(self.evaluated_profile).accepts_state(self.integrity_state)
    }
}

// ---------------------------------------------------------------------------
// BootAttestedPayload — typed evidence record for BOOT_ATTESTED
// ---------------------------------------------------------------------------

/// Evidence payload for the `BOOT_ATTESTED` record type (S16.4 §11).
///
/// Emitted at every boot after the attestation chain is evaluated.
/// The payload is immutable once created (INV-BOA-003).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootAttestedPayload {
    /// The overall boot integrity state.
    pub integrity_state: BootIntegrityState,
    /// The security profile against which the chain was evaluated.
    pub evaluated_profile: String,
    /// Whether the TPM quote was provided.
    pub tpm_quote_provided: bool,
    /// Whether PCR values matched golden expectations. `None` if no quote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_values_matched: Option<bool>,
    /// IMA appraisal result label. `None` if not evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ima_appraisal_result: Option<String>,
    /// Number of IMA violations detected.
    #[serde(default)]
    pub ima_violation_count: u64,
    /// Whether dm-verity root hash was verified.
    pub verity_root_verified: bool,
    /// Unix timestamp of the attestation.
    pub boot_timestamp: u64,
    /// Human-readable summary.
    pub summary: String,
}

impl BootAttestedPayload {
    /// Create a payload from a boot attestation report.
    #[must_use]
    pub fn from_report(report: &BootAttestationReport) -> Self {
        Self {
            integrity_state: report.integrity_state,
            evaluated_profile: report.evaluated_profile.label().to_string(),
            tpm_quote_provided: report.tpm_quote_provided,
            pcr_values_matched: report.pcr_values_matched,
            ima_appraisal_result: report.ima_appraisal_result.map(|s| s.label().to_string()),
            ima_violation_count: report.ima_violation_count,
            verity_root_verified: report.verity_root_verified,
            boot_timestamp: report.boot_timestamp,
            summary: report.summary.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// BootAttestationChain — chains TPM → IMA → verity → report
// ---------------------------------------------------------------------------

/// The boot attestation chain assembles TPM PCR quote, measured boot
/// log, IMA appraisal, and dm-verity root hash into a single attestation
/// report.
///
/// The chain is evaluated against a [`MeasuredBootPolicy`] and produces
/// a [`BootAttestationReport`] with a definitive [`BootIntegrityState`].
#[derive(Debug, Clone)]
pub struct BootAttestationChain {
    /// The security profile against which the chain is evaluated.
    pub profile: SecurityProfile,
    /// Whether a TPM quote was provided for this boot.
    pub tpm_quote_provided: bool,
    /// Whether the TPM PCR values matched golden expectations.
    pub pcr_values_matched: Option<bool>,
    /// Hex-encoded PCR quote digest.
    pub pcr_quote_digest_hex: Option<String>,
    /// The IMA appraisal result.
    pub ima_appraisal_result: Option<ImaAppraisalState>,
    /// Number of IMA integrity violations.
    pub ima_violation_count: u64,
    /// The dm-verity root hash.
    pub verity_root_hash: Option<[u8; 32]>,
    /// Whether the verity root hash was verified.
    pub verity_root_verified: bool,
    /// SHA-256 hash of the kernel command-line.
    pub kernel_cmdline_hash: Option<[u8; 32]>,
    /// SHA-256 hash of the initramfs.
    pub initramfs_hash: Option<[u8; 32]>,
}

impl BootAttestationChain {
    /// Create a new attestation chain for the given profile.
    #[must_use]
    pub fn new(profile: SecurityProfile) -> Self {
        Self {
            profile,
            tpm_quote_provided: false,
            pcr_values_matched: None,
            pcr_quote_digest_hex: None,
            ima_appraisal_result: None,
            ima_violation_count: 0,
            verity_root_hash: None,
            verity_root_verified: false,
            kernel_cmdline_hash: None,
            initramfs_hash: None,
        }
    }

    /// Record TPM quote information.
    pub fn with_tpm_quote(
        mut self,
        quote_digest_hex: impl Into<String>,
        pcr_matched: bool,
    ) -> Self {
        self.tpm_quote_provided = true;
        self.pcr_values_matched = Some(pcr_matched);
        self.pcr_quote_digest_hex = Some(quote_digest_hex.into());
        self
    }

    /// Record IMA appraisal information.
    pub fn with_ima_appraisal(mut self, result: ImaAppraisalState, violation_count: u64) -> Self {
        self.ima_appraisal_result = Some(result);
        self.ima_violation_count = violation_count;
        self
    }

    /// Record dm-verity root hash information.
    pub fn with_verity_root(mut self, root_hash: [u8; 32], verified: bool) -> Self {
        self.verity_root_hash = Some(root_hash);
        self.verity_root_verified = verified;
        self
    }

    /// Record kernel command-line hash.
    pub fn with_kernel_cmdline_hash(mut self, hash: [u8; 32]) -> Self {
        self.kernel_cmdline_hash = Some(hash);
        self
    }

    /// Record initramfs hash.
    pub fn with_initramfs_hash(mut self, hash: [u8; 32]) -> Self {
        self.initramfs_hash = Some(hash);
        self
    }
}

// ---------------------------------------------------------------------------
// attest_boot_chain — main attestation function
// ---------------------------------------------------------------------------

/// Assemble and evaluate the full boot attestation chain.
///
/// This is the primary entry point for boot-time attestation. It takes a
/// [`BootAttestationChain`] with the gathered evidence and validates it
/// against the policy derived from the active [`SecurityProfile`].
///
/// Returns a [`BootAttestationReport`] with the definitive integrity state.
///
/// # Errors
///
/// Returns a [`BootAttestationError`] if a policy-required component is
/// missing or invalid.
pub fn attest_boot_chain(
    chain: &BootAttestationChain,
) -> Result<BootAttestationReport, BootAttestationError> {
    let policy = MeasuredBootPolicy::for_profile(chain.profile);
    let mut report = BootAttestationReport::new(
        chain.profile,
        BootIntegrityState::Trusted,
        "boot attestation chain pending evaluation",
    );

    if chain.tpm_quote_provided {
        let pcr_matched = chain.pcr_values_matched.unwrap_or(false);
        report = report.with_tpm_quote(
            chain.pcr_quote_digest_hex.clone().unwrap_or_default(),
            pcr_matched,
        );
    }

    if let Some(ima_result) = chain.ima_appraisal_result {
        report = report.with_ima_appraisal(ima_result, chain.ima_violation_count);
    }

    if let Some(root_hash) = chain.verity_root_hash {
        report = report.with_verity_root(root_hash, chain.verity_root_verified);
    }

    if let Some(hash) = chain.kernel_cmdline_hash {
        report = report.with_kernel_cmdline_hash(hash);
    }

    if let Some(hash) = chain.initramfs_hash {
        report = report.with_initramfs_hash(hash);
    }

    let state = evaluate_chain_state(chain, &policy)?;
    report.integrity_state = state;
    report.summary = build_summary(&report);

    Ok(report)
}

/// Evaluate the chain state against the policy and return the appropriate
/// [`BootIntegrityState`].
fn evaluate_chain_state(
    chain: &BootAttestationChain,
    policy: &MeasuredBootPolicy,
) -> Result<BootIntegrityState, BootAttestationError> {
    let mut degraded = false;

    // --- TPM quote evaluation ---
    if policy.tpm_required {
        if !chain.tpm_quote_provided {
            return Ok(BootIntegrityState::RecoveryRequired);
        }
        match chain.pcr_values_matched {
            Some(true) => {}
            Some(false) => {
                return Ok(BootIntegrityState::RecoveryRequired);
            }
            None => {
                degraded = true;
            }
        }
    } else if chain.tpm_quote_provided && chain.pcr_values_matched == Some(false) {
        degraded = true;
    }

    // --- IMA appraisal evaluation ---
    if policy.ima_required {
        match chain.ima_appraisal_result {
            Some(ImaAppraisalState::Trusted) | Some(ImaAppraisalState::Exempt) => {}
            Some(ImaAppraisalState::Untrusted) => {
                return Ok(BootIntegrityState::RecoveryRequired);
            }
            Some(ImaAppraisalState::Unknown) => {
                degraded = true;
            }
            None => {
                return Ok(BootIntegrityState::RecoveryRequired);
            }
        }
    } else if let Some(result) = chain.ima_appraisal_result {
        if result.is_violation() {
            degraded = true;
        }
    }

    // --- Verity root hash evaluation ---
    if policy.verity_required {
        if chain.verity_root_hash.is_none() || !chain.verity_root_verified {
            return Ok(BootIntegrityState::RecoveryRequired);
        }
    } else if chain.verity_root_hash.is_some() && !chain.verity_root_verified {
        degraded = true;
    }

    // --- Kernel command-line hash evaluation ---
    if let Some(cmdline_hash) = &chain.kernel_cmdline_hash {
        if !policy.is_cmdline_hash_allowed(cmdline_hash) {
            if policy.profile == SecurityProfile::AirgapHigh
                || policy.profile == SecurityProfile::StigAligned
            {
                return Ok(BootIntegrityState::RecoveryRequired);
            }
            degraded = true;
        }
    }

    if degraded {
        Ok(BootIntegrityState::Degraded)
    } else {
        Ok(BootIntegrityState::Trusted)
    }
}

/// Build a human-readable summary from the attestation report.
fn build_summary(report: &BootAttestationReport) -> String {
    let mut parts: Vec<String> = Vec::new();

    parts.push(format!(
        "boot integrity: {}",
        report.integrity_state.label()
    ));

    if report.tpm_quote_provided {
        match report.pcr_values_matched {
            Some(true) => parts.push("tpm quote verified".into()),
            Some(false) => parts.push("tpm quote mismatch".into()),
            None => parts.push("tpm quote present (unverified)".into()),
        }
    } else {
        parts.push("tpm quote not provided".into());
    }

    if let Some(ima_result) = report.ima_appraisal_result {
        parts.push(format!(
            "ima appraisal: {} ({} violations)",
            ima_result.label(),
            report.ima_violation_count,
        ));
    }

    if report.verity_root_hash.is_some() {
        parts.push(format!(
            "verity root: {}",
            if report.verity_root_verified {
                "verified"
            } else {
                "unverified"
            },
        ));
    }

    parts.join("; ")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Current wall-clock time in seconds since Unix epoch.
fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ===========================================================================
// Tests — INV-BOA-001 through INV-BOA-003
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;
    use strum::EnumCount;

    fn sha256_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = seed;
        h
    }

    fn chain_for(profile: SecurityProfile) -> BootAttestationChain {
        BootAttestationChain::new(profile)
    }

    // -------------------------------------------------------------------
    // BootIntegrityState tests
    // -------------------------------------------------------------------

    #[test]
    fn boot_integrity_state_labels_are_stable() {
        assert_eq!(BootIntegrityState::Trusted.label(), "TRUSTED");
        assert_eq!(BootIntegrityState::Degraded.label(), "DEGRADED");
        assert_eq!(BootIntegrityState::Untrusted.label(), "UNTRUSTED");
        assert_eq!(
            BootIntegrityState::RecoveryRequired.label(),
            "RECOVERY_REQUIRED"
        );
    }

    #[test]
    fn boot_integrity_state_display_matches_label() {
        assert_eq!(format!("{}", BootIntegrityState::Trusted), "TRUSTED");
        assert_eq!(
            format!("{}", BootIntegrityState::RecoveryRequired),
            "RECOVERY_REQUIRED"
        );
    }

    #[test]
    fn boot_integrity_state_is_operational() {
        assert!(BootIntegrityState::Trusted.is_operational());
        assert!(BootIntegrityState::Degraded.is_operational());
        assert!(!BootIntegrityState::Untrusted.is_operational());
        assert!(!BootIntegrityState::RecoveryRequired.is_operational());
    }

    #[test]
    fn boot_integrity_state_requires_recovery() {
        assert!(!BootIntegrityState::Trusted.requires_recovery());
        assert!(!BootIntegrityState::Degraded.requires_recovery());
        assert!(!BootIntegrityState::Untrusted.requires_recovery());
        assert!(BootIntegrityState::RecoveryRequired.requires_recovery());
    }

    #[test]
    fn boot_integrity_state_is_trusted() {
        assert!(BootIntegrityState::Trusted.is_trusted());
        assert!(!BootIntegrityState::Degraded.is_trusted());
        assert!(!BootIntegrityState::Untrusted.is_trusted());
        assert!(!BootIntegrityState::RecoveryRequired.is_trusted());
    }

    #[test]
    fn boot_integrity_state_ordering() {
        assert!(BootIntegrityState::Trusted < BootIntegrityState::Degraded);
        assert!(BootIntegrityState::Degraded < BootIntegrityState::Untrusted);
        assert!(BootIntegrityState::Untrusted < BootIntegrityState::RecoveryRequired);
    }

    #[test]
    fn boot_integrity_state_enum_count() {
        assert_eq!(BootIntegrityState::COUNT, 4);
    }

    #[test]
    fn boot_integrity_state_serde_roundtrip_screaming_snake() {
        let json = serde_json::to_string(&BootIntegrityState::RecoveryRequired).unwrap();
        assert!(json.contains("RECOVERY_REQUIRED"));
        let back: BootIntegrityState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, BootIntegrityState::RecoveryRequired);
    }

    // -------------------------------------------------------------------
    // MeasuredBootPolicy tests
    // -------------------------------------------------------------------

    #[test]
    fn policy_for_dev_relaxed_has_no_requirements() {
        let p = MeasuredBootPolicy::for_profile(SecurityProfile::DevRelaxed);
        assert!(!p.tpm_required);
        assert!(!p.ima_required);
        assert!(!p.verity_required);
        assert_eq!(p.pcr_bank, PcrBank::Sha1);
        assert!(p.allows_tpm_absent());
    }

    #[test]
    fn policy_for_airgap_high_has_all_requirements() {
        let p = MeasuredBootPolicy::for_profile(SecurityProfile::AirgapHigh);
        assert!(p.tpm_required);
        assert!(p.ima_required);
        assert!(p.verity_required);
        assert_eq!(p.pcr_bank, PcrBank::Sha256);
        assert!(!p.allows_tpm_absent());
    }

    #[test]
    fn policy_for_stig_aligned_has_all_requirements() {
        let p = MeasuredBootPolicy::for_profile(SecurityProfile::StigAligned);
        assert!(p.tpm_required);
        assert!(p.ima_required);
        assert!(p.verity_required);
    }

    #[test]
    fn policy_for_secure_default_is_intermediate() {
        let p = MeasuredBootPolicy::for_profile(SecurityProfile::SecureDefault);
        assert!(!p.tpm_required);
        assert!(!p.ima_required);
        assert!(!p.verity_required);
        assert_eq!(p.pcr_bank, PcrBank::Sha256);
        assert!(p.allows_tpm_absent());
    }

    #[test]
    fn policy_accepts_trusted_state_for_all_profiles() {
        for profile in &[
            SecurityProfile::DevRelaxed,
            SecurityProfile::SecureDefault,
            SecurityProfile::StigAligned,
            SecurityProfile::AirgapHigh,
        ] {
            let policy = MeasuredBootPolicy::for_profile(*profile);
            assert!(
                policy.accepts_state(BootIntegrityState::Trusted),
                "{profile} should accept Trusted"
            );
        }
    }

    #[test]
    fn policy_dev_relaxed_accepts_untrusted() {
        let policy = MeasuredBootPolicy::for_profile(SecurityProfile::DevRelaxed);
        assert!(policy.accepts_state(BootIntegrityState::Untrusted));
    }

    #[test]
    fn policy_airgap_high_rejects_untrusted() {
        let policy = MeasuredBootPolicy::for_profile(SecurityProfile::AirgapHigh);
        assert!(!policy.accepts_state(BootIntegrityState::Untrusted));
    }

    #[test]
    fn policy_no_profile_accepts_recovery_required() {
        for profile in &[
            SecurityProfile::DevRelaxed,
            SecurityProfile::SecureDefault,
            SecurityProfile::StigAligned,
            SecurityProfile::AirgapHigh,
        ] {
            let policy = MeasuredBootPolicy::for_profile(*profile);
            assert!(
                !policy.accepts_state(BootIntegrityState::RecoveryRequired),
                "{profile} should reject RecoveryRequired"
            );
        }
    }

    #[test]
    fn policy_cmdline_hash_empty_allows_any() {
        let policy = MeasuredBootPolicy::for_profile(SecurityProfile::DevRelaxed);
        assert!(policy.is_cmdline_hash_allowed(&[0u8; 32]));
        assert!(policy.is_cmdline_hash_allowed(&[0xffu8; 32]));
    }

    #[test]
    fn policy_cmdline_hash_allowlist_respected() {
        let mut policy = MeasuredBootPolicy::for_profile(SecurityProfile::AirgapHigh);
        let allowed = sha256_hash(42);
        policy.allow_cmdline_hash(allowed);

        assert!(policy.is_cmdline_hash_allowed(&allowed));
        assert!(!policy.is_cmdline_hash_allowed(&sha256_hash(99)));
    }

    // -------------------------------------------------------------------
    // attest_boot_chain — trusted path
    // -------------------------------------------------------------------

    #[test]
    fn attest_boot_chain_dev_relaxed_trusted_with_no_evidence() {
        let chain = chain_for(SecurityProfile::DevRelaxed);
        let report = attest_boot_chain(&chain).expect("attestation should succeed");
        assert_eq!(report.integrity_state, BootIntegrityState::Trusted);
    }

    #[test]
    fn attest_boot_chain_airgap_high_no_tpm_fails_to_recovery() {
        let chain = chain_for(SecurityProfile::AirgapHigh)
            .with_ima_appraisal(ImaAppraisalState::Trusted, 0)
            .with_verity_root(sha256_hash(1), true);
        let report = attest_boot_chain(&chain).expect("attestation should succeed");
        assert_eq!(report.integrity_state, BootIntegrityState::RecoveryRequired);
    }

    #[test]
    fn attest_boot_chain_airgap_high_full_chain_succeeds() {
        let chain = chain_for(SecurityProfile::AirgapHigh)
            .with_tpm_quote("abc123", true)
            .with_ima_appraisal(ImaAppraisalState::Trusted, 0)
            .with_verity_root(sha256_hash(1), true)
            .with_kernel_cmdline_hash(sha256_hash(10))
            .with_initramfs_hash(sha256_hash(20));
        let report = attest_boot_chain(&chain).expect("attestation should succeed");
        assert_eq!(report.integrity_state, BootIntegrityState::Trusted);
    }

    // -------------------------------------------------------------------
    // attest_boot_chain — degraded path
    // -------------------------------------------------------------------

    #[test]
    fn attest_boot_chain_secure_default_tpm_mismatch_degraded() {
        let chain = chain_for(SecurityProfile::SecureDefault).with_tpm_quote("mismatch-hex", false);
        let report = attest_boot_chain(&chain).expect("attestation should succeed");
        assert_eq!(report.integrity_state, BootIntegrityState::Degraded);
    }

    #[test]
    fn attest_boot_chain_stig_aligned_ima_untrusted_fails() {
        let chain = chain_for(SecurityProfile::StigAligned)
            .with_tpm_quote("abc", true)
            .with_ima_appraisal(ImaAppraisalState::Untrusted, 1)
            .with_verity_root(sha256_hash(1), true);
        let report = attest_boot_chain(&chain).expect("attestation should succeed");
        assert_eq!(report.integrity_state, BootIntegrityState::RecoveryRequired);
    }

    #[test]
    fn attest_boot_chain_stig_aligned_verity_missing_fails() {
        let chain = chain_for(SecurityProfile::StigAligned)
            .with_tpm_quote("abc", true)
            .with_ima_appraisal(ImaAppraisalState::Trusted, 0);
        let report = attest_boot_chain(&chain).expect("attestation should succeed");
        assert_eq!(report.integrity_state, BootIntegrityState::RecoveryRequired);
    }

    // -------------------------------------------------------------------
    // BootAttestationReport tests
    // -------------------------------------------------------------------

    #[test]
    fn report_builder_chains_methods() {
        let report = BootAttestationReport::new(
            SecurityProfile::StigAligned,
            BootIntegrityState::Trusted,
            "all clear",
        )
        .with_tpm_quote("abcdef", true)
        .with_ima_appraisal(ImaAppraisalState::Trusted, 0)
        .with_verity_root(sha256_hash(3), true)
        .with_kernel_cmdline_hash(sha256_hash(4))
        .with_initramfs_hash(sha256_hash(5));

        assert_eq!(report.integrity_state, BootIntegrityState::Trusted);
        assert!(report.tpm_quote_provided);
        assert_eq!(report.pcr_values_matched, Some(true));
        assert_eq!(report.pcr_quote_digest_hex, Some("abcdef".to_string()));
        assert_eq!(
            report.ima_appraisal_result,
            Some(ImaAppraisalState::Trusted)
        );
        assert_eq!(report.ima_violation_count, 0);
        assert_eq!(report.verity_root_hash, Some(sha256_hash(3)));
        assert!(report.verity_root_verified);
        assert_eq!(report.kernel_cmdline_hash, Some(sha256_hash(4)));
        assert_eq!(report.initramfs_hash, Some(sha256_hash(5)));
        assert!(report.is_trusted());
    }

    #[test]
    fn report_is_accepted_by_profile_checks_policy() {
        let report = BootAttestationReport::new(
            SecurityProfile::AirgapHigh,
            BootIntegrityState::Untrusted,
            "compromised boot",
        );
        assert!(!report.is_accepted_by_profile());

        let trusted_report = BootAttestationReport::new(
            SecurityProfile::AirgapHigh,
            BootIntegrityState::Trusted,
            "clean boot",
        );
        assert!(trusted_report.is_accepted_by_profile());
    }

    // -------------------------------------------------------------------
    // BootAttestedPayload tests
    // -------------------------------------------------------------------

    #[test]
    fn payload_from_report_round_trips_through_json() {
        let mut chain = BootAttestationChain::new(SecurityProfile::StigAligned)
            .with_tpm_quote("feedface", true)
            .with_ima_appraisal(ImaAppraisalState::Trusted, 0)
            .with_verity_root(sha256_hash(7), true);
        chain.profile = SecurityProfile::StigAligned;

        let report = attest_boot_chain(&chain).expect("attestation should succeed");

        let payload = BootAttestedPayload::from_report(&report);
        let json = serde_json::to_string(&payload).expect("serialization should succeed");
        let back: BootAttestedPayload =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(back.integrity_state, BootIntegrityState::Trusted);
        assert_eq!(back.evaluated_profile, "STIG_ALIGNED");
        assert!(back.tpm_quote_provided);
        assert_eq!(back.pcr_values_matched, Some(true));
        assert_eq!(back.ima_appraisal_result.as_deref(), Some("TRUSTED"));
        assert_eq!(back.ima_violation_count, 0);
        assert!(back.verity_root_verified);
        assert!(back.summary.contains("TRUSTED"));
    }

    // -------------------------------------------------------------------
    // BootAttestationChain tests
    // -------------------------------------------------------------------

    #[test]
    fn chain_new_starts_with_defaults() {
        let chain = BootAttestationChain::new(SecurityProfile::DevRelaxed);
        assert_eq!(chain.profile, SecurityProfile::DevRelaxed);
        assert!(!chain.tpm_quote_provided);
        assert!(chain.pcr_values_matched.is_none());
        assert!(chain.ima_appraisal_result.is_none());
        assert!(chain.verity_root_hash.is_none());
    }

    #[test]
    fn chain_builder_methods_preserve_values() {
        let chain = BootAttestationChain::new(SecurityProfile::AirgapHigh)
            .with_tpm_quote("deadbeef", true)
            .with_ima_appraisal(ImaAppraisalState::Trusted, 0)
            .with_verity_root(sha256_hash(8), true)
            .with_kernel_cmdline_hash(sha256_hash(9))
            .with_initramfs_hash(sha256_hash(10));

        assert!(chain.tpm_quote_provided);
        assert_eq!(chain.pcr_values_matched, Some(true));
        assert_eq!(chain.ima_appraisal_result, Some(ImaAppraisalState::Trusted));
        assert_eq!(chain.verity_root_hash, Some(sha256_hash(8)));
        assert!(chain.verity_root_verified);
        assert_eq!(chain.kernel_cmdline_hash, Some(sha256_hash(9)));
        assert_eq!(chain.initramfs_hash, Some(sha256_hash(10)));
    }

    // -------------------------------------------------------------------
    // Error tests
    // -------------------------------------------------------------------

    #[test]
    fn error_display_formats_are_readable() {
        let e = BootAttestationError::TpmQuoteMissing;
        assert!(e.to_string().contains("tpm quote"));

        let e = BootAttestationError::PcrBankMismatch {
            observed: PcrBank::Sha1,
            required: PcrBank::Sha256,
        };
        assert!(e.to_string().contains("SHA1"));
        assert!(e.to_string().contains("SHA256"));

        let e = BootAttestationError::ImaAppraisalViolation { count: 3 };
        assert!(e.to_string().contains("3"));

        let e = BootAttestationError::ChainIncomplete {
            detail: "missing TPM".into(),
        };
        assert!(e.to_string().contains("missing TPM"));
    }

    // -------------------------------------------------------------------
    // Cross-cutting: policy monotonicity
    // -------------------------------------------------------------------

    #[test]
    fn policy_strictness_is_monotonic_with_profile() {
        let dev = MeasuredBootPolicy::for_profile(SecurityProfile::DevRelaxed);
        let sec = MeasuredBootPolicy::for_profile(SecurityProfile::SecureDefault);
        let stig = MeasuredBootPolicy::for_profile(SecurityProfile::StigAligned);
        let air = MeasuredBootPolicy::for_profile(SecurityProfile::AirgapHigh);

        assert!(!dev.tpm_required);
        assert!(!sec.tpm_required);
        assert!(stig.tpm_required);
        assert!(air.tpm_required);
    }

    // -------------------------------------------------------------------
    // Cross-cutting: cmdline hash enforcement
    // -------------------------------------------------------------------

    #[test]
    fn attest_boot_chain_cmdline_hash_allowed_when_list_empty() {
        let chain = chain_for(SecurityProfile::AirgapHigh)
            .with_tpm_quote("abc", true)
            .with_ima_appraisal(ImaAppraisalState::Trusted, 0)
            .with_verity_root(sha256_hash(1), true)
            .with_kernel_cmdline_hash(sha256_hash(42));

        let report = attest_boot_chain(&chain).expect("attestation should succeed");
        assert_eq!(report.integrity_state, BootIntegrityState::Trusted);
    }

    #[test]
    fn attest_boot_chain_cmdline_hash_with_empty_list_is_trusted_on_secure_default() {
        let chain =
            chain_for(SecurityProfile::SecureDefault).with_kernel_cmdline_hash(sha256_hash(88));

        let report = attest_boot_chain(&chain).expect("attestation should succeed");
        assert_eq!(report.integrity_state, BootIntegrityState::Trusted);
    }

    // -------------------------------------------------------------------
    // EDGE: AIRGAP_HIGH with all evidence
    // -------------------------------------------------------------------

    #[test]
    fn attest_boot_chain_airgap_high_ima_exempt_is_trusted() {
        let chain = chain_for(SecurityProfile::AirgapHigh)
            .with_tpm_quote("abc", true)
            .with_ima_appraisal(ImaAppraisalState::Exempt, 0)
            .with_verity_root(sha256_hash(1), true);
        let report = attest_boot_chain(&chain).expect("attestation should succeed");
        assert_eq!(report.integrity_state, BootIntegrityState::Trusted);
    }

    #[test]
    fn attest_boot_chain_airgap_high_ima_unknown_is_degraded() {
        let chain = chain_for(SecurityProfile::AirgapHigh)
            .with_tpm_quote("abc", true)
            .with_ima_appraisal(ImaAppraisalState::Unknown, 0)
            .with_verity_root(sha256_hash(1), true);
        let report = attest_boot_chain(&chain).expect("attestation should succeed");
        assert_eq!(report.integrity_state, BootIntegrityState::Degraded);
    }
}
