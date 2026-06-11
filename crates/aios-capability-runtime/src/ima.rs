//! IMA/EVM Integrity Measurement Architecture — Linux IMA measurement
//! and appraisal with EVM extended-attribute verification (Rev.3 S16.4).
//!
//! ## OS Research Provenance
//!
//! The Linux **Integrity Measurement Architecture (IMA)**, merged into
//! mainline in 2.6.30 (2009), provides a mandatory file-integrity
//! subsystem. IMA measures every file before it is executed, mmap'd, or
//! opened, accumulating an ordered measurement list that can be
//! verified against a known-good reference ("golden hash" table).
//!
//! **Extended Verification Module (EVM)** (Linux 3.2, 2012) extends IMA
//! by protecting file extended attributes (`security.ima` and
//! `security.evm`) with an HMAC or digital signature. Together they form
//! the kernel's *Trusted Computing Base (TCB)* integrity anchor.
//!
//! Key architectural decisions inherited from the kernel IMA subsystem:
//!
//! 1. **Measurement before access** — IMA hooks into
//!    `security_file_mmap`, `security_bprm_check`, and
//!    `security_file_open` (with the `ima_file_check` LSM hook). No
//!    file content is trusted until measured.
//! 2. **Append-only measurement log** — once a measurement is recorded,
//!    it cannot be removed. The log is a WORM (write-once, read-many)
//!    data structure extended by the TPM PCR 10.
//! 3. **Policy-driven measurement** — the IMA policy (loaded via
//!    `ima_policy=` kernel command-line or the `securityfs` interface)
//!    determines *which* files are measured and *whether* appraisal
//!    is required.
//! 4. **Appraisal modes** — appraisal compares the current file hash
//!    against `security.ima`; a mismatch blocks access (enforcing
//!    mode) or logs a warning (permissive mode).
//!
//! ### Mapping to AIOS Capability Runtime
//!
//! | Linux IMA/EVM concept      | AIOS equivalent                          |
//! |----------------------------|------------------------------------------|
//! | IMA measurement list       | [`ImaMeasurementList`]                   |
//! | Single measurement entry   | [`ImaMeasurement`]                       |
//! | IMA appraisal result       | [`ImaAppraisalState`]                    |
//! | IMA policy (include/exclude)| [`ImaPolicy`]                            |
//! | Verifier (kernel appraisal)| [`ImaVerifier`]                          |
//! | Appraisal violation        | [`IntegrityViolation`]                   |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-IMA-001 (Measurement ordering):** The measurement list is
//!   strictly ordered by insertion time. Earlier measurements have
//!   lower indices.
//! - **INV-IMA-002 (Hash integrity):** Every measurement carries a
//!   non-empty hash digest; the hash length is a compile-time known
//!   constant (SHA-256: 32 bytes).
//! - **INV-IMA-003 (Appraisal non-bypass):** A measurement without a
//!   corresponding golden hash entry results in `Unknown` appraisal
//!   state; no file is implicitly trusted.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use strum_macros::{EnumCount, EnumIter};

// ---------------------------------------------------------------------------
// ImaMeasurement — single file-integrity measurement
// ---------------------------------------------------------------------------

/// A single IMA measurement record: file path, SHA-256 hash digest,
/// and a monotonic timestamp.
///
/// Mirrors the kernel's `struct ima_template_entry` with only the
/// fields relevant to the AIOS capability runtime's integrity layer.
///
/// # Examples
///
/// ```rust
/// # use aios_capability_runtime::ima::ImaMeasurement;
/// let m = ImaMeasurement::new("/bin/capsule", vec![0u8; 32]);
/// assert!(m.is_some());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImaMeasurement {
    /// Absolute file path measured.
    pub file_path: String,
    /// SHA-256 hash digest (32 bytes per INV-IMA-002).
    pub hash_digest: Vec<u8>,
    /// Nanoseconds since Unix epoch when the measurement was recorded.
    pub timestamp_ns: u128,
}

impl ImaMeasurement {
    /// Create a new measurement with the current system time as the
    /// timestamp.
    ///
    /// Returns `None` if the file path is empty or the hash digest is
    /// not 32 bytes (INV-IMA-002).
    #[must_use]
    pub fn new(file_path: &str, hash_digest: Vec<u8>) -> Option<Self> {
        if file_path.is_empty() || hash_digest.len() != Self::EXPECTED_HASH_LEN {
            return None;
        }
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Some(Self {
            file_path: file_path.into(),
            hash_digest,
            timestamp_ns,
        })
    }

    /// Create a measurement with an explicit timestamp (for testing
    /// and replay scenarios).
    ///
    /// Returns `None` if the file path is empty or the hash digest is
    /// not 32 bytes.
    #[must_use]
    pub fn with_timestamp(
        file_path: &str,
        hash_digest: Vec<u8>,
        timestamp_ns: u128,
    ) -> Option<Self> {
        if file_path.is_empty() || hash_digest.len() != Self::EXPECTED_HASH_LEN {
            return None;
        }
        Some(Self {
            file_path: file_path.into(),
            hash_digest,
            timestamp_ns,
        })
    }

    /// Expected length of the SHA-256 hash digest in bytes.
    pub const EXPECTED_HASH_LEN: usize = 32;

    /// Whether this measurement carries a valid hash (INV-IMA-002).
    #[must_use]
    pub fn has_valid_hash(&self) -> bool {
        self.hash_digest.len() == Self::EXPECTED_HASH_LEN && !self.hash_digest.iter().all(|b| *b == 0)
    }

    /// The hash digest as a hex-encoded string for logging and evidence.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        self.hash_digest.iter().fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

impl fmt::Display for ImaMeasurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [sha256:{}] @{}ns",
            self.file_path,
            self.hash_hex(),
            self.timestamp_ns,
        )
    }
}

// ---------------------------------------------------------------------------
// ImaMeasurementList — ordered measurement log
// ---------------------------------------------------------------------------

/// An ordered, append-only list of IMA measurements (the IMA log).
///
/// INV-IMA-001: measurements are ordered by insertion time. The list
/// is a WORM (write-once, read-many) data structure. Entries are never
/// removed.
///
/// # Examples
///
/// ```rust
/// # use aios_capability_runtime::ima::{ImaMeasurementList, ImaMeasurement};
/// let mut log = ImaMeasurementList::new();
/// let m = ImaMeasurement::with_timestamp("/bin/sh", vec![1u8; 32], 100).unwrap();
/// log.record(m);
/// assert_eq!(log.len(), 1);
/// ```
#[derive(Debug, Clone, Default)]
pub struct ImaMeasurementList {
    entries: Vec<ImaMeasurement>,
}

impl ImaMeasurementList {
    /// Create an empty measurement list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record a new measurement (append-only; INV-IMA-001).
    pub fn record(&mut self, measurement: ImaMeasurement) {
        self.entries.push(measurement);
    }

    /// Number of measurements in the log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Immutable reference to all entries, in insertion order.
    #[must_use]
    pub fn entries(&self) -> &[ImaMeasurement] {
        &self.entries
    }

    /// Iterate over measurements in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &ImaMeasurement> {
        self.entries.iter()
    }

    /// Look up the most recent measurement for a given file path.
    #[must_use]
    pub fn latest_for(&self, file_path: &str) -> Option<&ImaMeasurement> {
        self.entries
            .iter()
            .rev()
            .find(|m| m.file_path == file_path)
    }

    /// All unique file paths present in the log.
    #[must_use]
    pub fn unique_paths(&self) -> Vec<&str> {
        let mut paths: Vec<&str> = self
            .entries
            .iter()
            .map(|m| m.file_path.as_str())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        paths
    }
}

// ---------------------------------------------------------------------------
// ImaAppraisalState — result of a single-file appraisal
// ---------------------------------------------------------------------------

/// Result of comparing a measured file hash against the expected
/// ("golden") hash.
///
/// - `Trusted` — hash matches the golden reference.
/// - `Untrusted` — hash does NOT match (integrity violation).
/// - `Unknown` — no golden reference exists for this file.
/// - `Exempt` — the file is exempt from appraisal by policy.
///
/// # Examples
///
/// ```rust
/// # use aios_capability_runtime::ima::ImaAppraisalState;
/// assert!(ImaAppraisalState::Trusted.is_clean());
/// assert!(!ImaAppraisalState::Untrusted.is_clean());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ImaAppraisalState {
    /// File hash matches the expected (golden) hash.
    Trusted,
    /// File hash does NOT match the expected hash — integrity breach.
    Untrusted,
    /// No golden reference exists; file cannot be verified.
    Unknown,
    /// File is explicitly exempt from appraisal by policy.
    Exempt,
}

impl ImaAppraisalState {
    /// Whether the appraisal result is "clean" (no violation detected).
    #[must_use]
    pub fn is_clean(self) -> bool {
        matches!(self, Self::Trusted | Self::Exempt)
    }

    /// Whether this state represents a detected integrity violation.
    #[must_use]
    pub fn is_violation(self) -> bool {
        matches!(self, Self::Untrusted)
    }

    /// Human-readable label for evidence records.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Untrusted => "UNTRUSTED",
            Self::Unknown => "UNKNOWN",
            Self::Exempt => "EXEMPT",
        }
    }
}

impl fmt::Display for ImaAppraisalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// ImaPolicy — measurement / appraisal policy (include / exclude rules)
// ---------------------------------------------------------------------------

/// Rule set that determines which files are subject to IMA measurement
/// and appraisal.
///
/// The policy operates on file-path patterns:
/// - **Include patterns**: only files matching at least one include
///   pattern are measured. If the include set is empty, *all* files
///   are considered included (measure-everything default).
/// - **Exclude patterns**: files matching any exclude pattern are
///   skipped, even if they match an include pattern.
///
/// Pattern syntax follows simple glob rules: `*` matches any sequence
/// of non-`/` characters; `**` matches any sequence including `/`.
/// A trailing `/**` matches everything under a directory.
///
/// # Examples
///
/// ```rust
/// # use aios_capability_runtime::ima::ImaPolicy;
/// let mut policy = ImaPolicy::new();
/// policy.add_include("/bin/**");
/// policy.add_exclude("/bin/ignore");
/// assert!(policy.should_measure("/bin/capsule"));
/// assert!(!policy.should_measure("/usr/lib/noise.so"));
/// assert!(!policy.should_measure("/bin/ignore"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct ImaPolicy {
    /// Glob include patterns; empty means "measure everything by default".
    includes: Vec<String>,
    /// Glob exclude patterns; overrides includes.
    excludes: Vec<String>,
}

impl ImaPolicy {
    /// Create an empty policy (measure everything, exclude nothing).
    #[must_use]
    pub fn new() -> Self {
        Self {
            includes: Vec::new(),
            excludes: Vec::new(),
        }
    }

    /// Add an include pattern.
    pub fn add_include(&mut self, pattern: &str) {
        self.includes.push(pattern.into());
    }

    /// Add multiple include patterns.
    pub fn add_includes(&mut self, patterns: &[&str]) {
        for p in patterns {
            self.includes.push((*p).into());
        }
    }

    /// Add an exclude pattern.
    pub fn add_exclude(&mut self, pattern: &str) {
        self.excludes.push(pattern.into());
    }

    /// Add multiple exclude patterns.
    pub fn add_excludes(&mut self, patterns: &[&str]) {
        for p in patterns {
            self.excludes.push((*p).into());
        }
    }

    /// Returns a reference to all include patterns.
    #[must_use]
    pub fn includes(&self) -> &[String] {
        &self.includes
    }

    /// Returns a reference to all exclude patterns.
    #[must_use]
    pub fn excludes(&self) -> &[String] {
        &self.excludes
    }

    /// Whether the given file path should be measured under this policy.
    ///
    /// Rules (in order):
    /// 1. If the path matches any exclude pattern → `false`.
    /// 2. If includes are empty → `true` (measure-everything default).
    /// 3. If the path matches any include pattern → `true`.
    /// 4. Otherwise → `false`.
    #[must_use]
    pub fn should_measure(&self, path: &str) -> bool {
        if self.excludes.iter().any(|pat| Self::glob_match(pat, path)) {
            return false;
        }
        if self.includes.is_empty() {
            return true;
        }
        self.includes.iter().any(|pat| Self::glob_match(pat, path))
    }

    /// Simple glob matching: `*` matches any non-`/` characters; `**`
    /// matches any sequence including `/`.
    #[must_use]
    fn glob_match(pattern: &str, path: &str) -> bool {
        Self::glob_match_impl(pattern.as_bytes(), path.as_bytes())
    }

    fn glob_match_impl(pat: &[u8], path: &[u8]) -> bool {
        // ** recursive case
        if pat.len() >= 2 && pat[0] == b'*' && pat[1] == b'*' {
            let rest = &pat[2..];
            if rest.is_empty() {
                return true;
            }
            // Slash after ** (e.g., `**/foo`)
            if rest.starts_with(b"/") {
                let rest = &rest[1..];
                for i in 0..=path.len() {
                    if Self::glob_match_impl(rest, &path[i..]) {
                        return true;
                    }
                }
                return false;
            }
            // ** followed by literal — try every position
            for i in 0..=path.len() {
                if Self::glob_match_impl(rest, &path[i..]) {
                    return true;
                }
            }
            return false;
        }

        match (pat.first(), path.first()) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some(b'*'), _) => {
                // * matches any non-slash characters
                let mut j = 0;
                while j < path.len() && path[j] != b'/' {
                    if Self::glob_match_impl(&pat[1..], &path[j + 1..]) {
                        return true;
                    }
                    j += 1;
                }
                // Also try matching zero characters
                Self::glob_match_impl(&pat[1..], path)
            }
            (Some(a), Some(b)) if a == b => {
                Self::glob_match_impl(&pat[1..], &path[1..])
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// IntegrityViolation — typed evidence of an appraisal failure
// ---------------------------------------------------------------------------

/// Typed evidence record for a single file that failed IMA appraisal.
///
/// Carries enough forensic detail to reconstruct the violation: the
/// file path, the measured hash, the expected (golden) hash, and the
/// appraisal result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityViolation {
    /// The file path that failed appraisal.
    pub file_path: String,
    /// The SHA-256 hash observed at measurement time.
    pub measured_hash: Vec<u8>,
    /// The expected (golden / known-good) hash.
    pub expected_hash: Vec<u8>,
    /// The appraisal state that triggered the violation.
    pub state: ImaAppraisalState,
}

impl IntegrityViolation {
    /// Create a new integrity violation record.
    ///
    /// Returns `None` if the state is not a violation (i.e., not
    /// `Untrusted`).
    #[must_use]
    pub fn new(
        file_path: &str,
        measured_hash: Vec<u8>,
        expected_hash: Vec<u8>,
        state: ImaAppraisalState,
    ) -> Option<Self> {
        if !state.is_violation() {
            return None;
        }
        Some(Self {
            file_path: file_path.into(),
            measured_hash,
            expected_hash,
            state,
        })
    }

    /// Human-readable summary line for audit logs.
    #[must_use]
    pub fn summary(&self) -> String {
        let measured_hex = Self::hex(&self.measured_hash);
        let expected_hex = Self::hex(&self.expected_hash);
        format!(
            "INTEGRITY VIOLATION [{}] measured:{} expected:{} state:{}",
            self.file_path,
            measured_hex,
            expected_hex,
            self.state.label(),
        )
    }

    /// Hex-encode a byte slice for display.
    #[must_use]
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

impl fmt::Display for IntegrityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

// ---------------------------------------------------------------------------
// ImaVerifier — appraisal engine
// ---------------------------------------------------------------------------

/// Verifies an IMA measurement list against a known-good ("golden")
/// hash table.
///
/// The verifier implements the kernel's appraisal logic: for every
/// measurement in the log, look up the expected hash and compare.
/// Mismatches produce [`IntegrityViolation`] records.
///
/// INV-IMA-003: files without a golden entry are appraised as
/// `Unknown` and are NOT implicitly trusted.
#[derive(Debug, Clone, Default)]
pub struct ImaVerifier;

impl ImaVerifier {
    /// Create a new verifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Verify the entire measurement list against the golden hash table.
    ///
    /// Returns a list of [`IntegrityViolation`] records for every
    /// measurement whose hash does not match the expected value.
    /// Measurements for files not present in the golden table are
    /// logged as `Unknown` but do NOT produce violations (per
    /// INV-IMA-003, `Unknown` is not a violation — it is an audit
    /// note).
    #[must_use]
    pub fn verify(
        &self,
        log: &ImaMeasurementList,
        golden: &HashMap<String, Vec<u8>>,
    ) -> Vec<IntegrityViolation> {
        let mut violations: Vec<IntegrityViolation> = Vec::new();

        for measurement in log.entries() {
            let file_path = &measurement.file_path;
            match golden.get(file_path) {
                Some(expected) => {
                    let state = Self::appraise_inner(measurement, expected);
                    if let Some(violation) = IntegrityViolation::new(
                        file_path,
                        measurement.hash_digest.clone(),
                        expected.clone(),
                        state,
                    ) {
                        violations.push(violation);
                    }
                }
                None => {
                    // INV-IMA-003: unknown is not a violation but is
                    // auditable; we do not produce a violation record.
                }
            }
        }

        violations
    }

    /// Appraise a single measurement against an expected hash.
    ///
    /// Returns:
    /// - `Trusted` if the hashes match.
    /// - `Untrusted` if the hashes differ.
    /// - `Unknown` if the expected hash is invalid (e.g., wrong length).
    #[must_use]
    pub fn appraise(measurement: &ImaMeasurement, expected_hash: &[u8]) -> ImaAppraisalState {
        Self::appraise_inner(measurement, expected_hash)
    }

    /// Internal appraisal logic (reused by `verify` and `appraise`).
    fn appraise_inner(measurement: &ImaMeasurement, expected_hash: &[u8]) -> ImaAppraisalState {
        if expected_hash.len() != ImaMeasurement::EXPECTED_HASH_LEN {
            return ImaAppraisalState::Unknown;
        }
        if measurement.hash_digest == expected_hash {
            ImaAppraisalState::Trusted
        } else {
            ImaAppraisalState::Untrusted
        }
    }
}

// ===========================================================================
// Tests — INV-IMA-001 through INV-IMA-003
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

    // convenience helper: 32-byte hash from a seed byte
    fn hash_from_seed(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    // convenience helper: create a measurement with explicit timestamp
    fn measure(path: &str, hash_seed: u8, ts_ns: u128) -> ImaMeasurement {
        ImaMeasurement::with_timestamp(path, hash_from_seed(hash_seed), ts_ns)
            .expect("test measurement should be valid")
    }

    // -------------------------------------------------------------------
    // ImaMeasurement
    // -------------------------------------------------------------------

    #[test]
    fn measurement_new_rejects_empty_path() {
        assert!(ImaMeasurement::new("", hash_from_seed(0)).is_none());
    }

    #[test]
    fn measurement_new_rejects_wrong_hash_length() {
        assert!(ImaMeasurement::new("/bin/sh", vec![0u8; 16]).is_none());
        assert!(ImaMeasurement::new("/bin/sh", vec![0u8; 64]).is_none());
        assert!(ImaMeasurement::new("/bin/sh", hash_from_seed(0)).is_some());
    }

    #[test]
    fn measurement_with_timestamp_stores_explicit_time() {
        let m = ImaMeasurement::with_timestamp("/etc/passwd", hash_from_seed(42), 999_000)
            .unwrap();
        assert_eq!(m.timestamp_ns, 999_000);
        assert_eq!(m.file_path, "/etc/passwd");
        assert_eq!(m.hash_digest, hash_from_seed(42));
    }

    #[test]
    fn measurement_hash_hex_is_correct_length() {
        let m = ImaMeasurement::with_timestamp("/bin/sh", hash_from_seed(0xab), 100).unwrap();
        let hex = m.hash_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn measurement_has_valid_hash_detects_all_zeros() {
        let m = ImaMeasurement::with_timestamp("/bin/sh", hash_from_seed(0x00), 100).unwrap();
        assert!(!m.has_valid_hash());

        let m2 = ImaMeasurement::with_timestamp("/bin/sh", hash_from_seed(0x01), 100).unwrap();
        assert!(m2.has_valid_hash());
    }

    #[test]
    fn measurement_display_format() {
        let m = ImaMeasurement::with_timestamp("/bin/capsule", hash_from_seed(0xff), 500).unwrap();
        let display = format!("{m}");
        assert!(display.starts_with("/bin/capsule [sha256:"));
        assert!(display.contains("@500ns"));
    }

    // -------------------------------------------------------------------
    // ImaMeasurementList (INV-IMA-001)
    // -------------------------------------------------------------------

    #[test]
    fn list_is_empty_on_creation() {
        let log = ImaMeasurementList::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn list_preserves_insertion_order() {
        let mut log = ImaMeasurementList::new();
        log.record(measure("/a", 1, 100));
        log.record(measure("/b", 2, 200));
        log.record(measure("/c", 3, 300));

        assert_eq!(log.len(), 3);
        assert_eq!(log.entries()[0].file_path, "/a");
        assert_eq!(log.entries()[1].file_path, "/b");
        assert_eq!(log.entries()[2].file_path, "/c");
    }

    #[test]
    fn list_latest_for_returns_most_recent() {
        let mut log = ImaMeasurementList::new();
        log.record(measure("/bin/sh", 1, 100));
        log.record(measure("/bin/sh", 2, 200));
        log.record(measure("/bin/sh", 3, 300));

        let latest = log.latest_for("/bin/sh").unwrap();
        assert_eq!(latest.hash_digest, hash_from_seed(3));
        assert_eq!(latest.timestamp_ns, 300);
    }

    #[test]
    fn list_latest_for_returns_none_for_missing_path() {
        let mut log = ImaMeasurementList::new();
        log.record(measure("/a", 1, 100));
        assert!(log.latest_for("/b").is_none());
    }

    #[test]
    fn list_unique_paths_deduplicates() {
        let mut log = ImaMeasurementList::new();
        log.record(measure("/a", 1, 100));
        log.record(measure("/b", 2, 200));
        log.record(measure("/a", 3, 300));
        log.record(measure("/c", 4, 400));

        let paths = log.unique_paths();
        assert_eq!(paths, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn list_iter_yields_all_entries_in_order() {
        let mut log = ImaMeasurementList::new();
        log.record(measure("/x", 10, 1));
        log.record(measure("/y", 20, 2));
        let collected: Vec<&ImaMeasurement> = log.iter().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].file_path, "/x");
        assert_eq!(collected[1].file_path, "/y");
    }

    // -------------------------------------------------------------------
    // ImaPolicy — include/exclude pattern matching
    // -------------------------------------------------------------------

    #[test]
    fn policy_empty_includes_measures_everything() {
        let policy = ImaPolicy::new();
        assert!(policy.should_measure("/anything"));
        assert!(policy.should_measure("/bin/sh"));
        assert!(policy.should_measure(""));
    }

    #[test]
    fn policy_include_restricts_to_matching_patterns() {
        let mut policy = ImaPolicy::new();
        policy.add_include("/bin/**");
        assert!(policy.should_measure("/bin/capsule"));
        assert!(policy.should_measure("/bin/sub/deep"));
        assert!(!policy.should_measure("/usr/lib/noise.so"));
        assert!(!policy.should_measure("/etc/passwd"));
    }

    #[test]
    fn policy_exclude_overrides_include() {
        let mut policy = ImaPolicy::new();
        policy.add_include("/bin/**");
        policy.add_exclude("/bin/ignore");
        policy.add_exclude("/bin/internal/*");
        assert!(policy.should_measure("/bin/capsule"));
        assert!(!policy.should_measure("/bin/ignore"));
        assert!(!policy.should_measure("/bin/internal/foo"));
        assert!(!policy.should_measure("/usr/lib/noise.so"));
    }

    #[test]
    fn policy_exclude_overrides_empty_includes() {
        let mut policy = ImaPolicy::new();
        policy.add_exclude("/tmp/**");
        assert!(policy.should_measure("/bin/capsule"));
        assert!(!policy.should_measure("/tmp/scratch"));
        assert!(!policy.should_measure("/tmp/a/b/c"));
    }

    #[test]
    fn policy_glob_star_matches_single_segment() {
        let mut policy = ImaPolicy::new();
        policy.add_include("/usr/*/capsule");
        assert!(policy.should_measure("/usr/lib/capsule"));
        assert!(policy.should_measure("/usr/bin/capsule"));
        assert!(!policy.should_measure("/usr/lib/sub/capsule"));
        assert!(!policy.should_measure("/usr/capsule"));
    }

    #[test]
    fn policy_glob_double_star_matches_multi_segment() {
        let mut policy = ImaPolicy::new();
        policy.add_include("/usr/**/capsule");
        assert!(policy.should_measure("/usr/lib/capsule"));
        assert!(policy.should_measure("/usr/a/b/c/capsule"));
        assert!(policy.should_measure("/usr/capsule"));
        assert!(!policy.should_measure("/bin/capsule"));
    }

    #[test]
    fn policy_exact_match() {
        let mut policy = ImaPolicy::new();
        policy.add_include("/etc/passwd");
        assert!(policy.should_measure("/etc/passwd"));
        assert!(!policy.should_measure("/etc/passwdx"));
        assert!(!policy.should_measure("/etc/passwd.bak"));
    }

    #[test]
    fn policy_multiple_includes_and_excludes() {
        let mut policy = ImaPolicy::new();
        policy.add_includes(&["/bin/**", "/sbin/**", "/lib/**"]);
        policy.add_excludes(&["/bin/log", "/lib/internal/**"]);
        assert!(policy.should_measure("/bin/bash"));
        assert!(policy.should_measure("/sbin/mount"));
        assert!(policy.should_measure("/lib/ld.so"));
        assert!(!policy.should_measure("/bin/log"));
        assert!(!policy.should_measure("/lib/internal/secret.so"));
        assert!(!policy.should_measure("/usr/bin/env"));
    }

    // -------------------------------------------------------------------
    // ImaAppraisalState
    // -------------------------------------------------------------------

    #[test]
    fn appraisal_trusted_is_clean() {
        assert!(ImaAppraisalState::Trusted.is_clean());
        assert!(!ImaAppraisalState::Trusted.is_violation());
    }

    #[test]
    fn appraisal_untrusted_is_violation() {
        assert!(!ImaAppraisalState::Untrusted.is_clean());
        assert!(ImaAppraisalState::Untrusted.is_violation());
    }

    #[test]
    fn appraisal_unknown_is_not_clean_nor_violation() {
        assert!(!ImaAppraisalState::Unknown.is_clean());
        assert!(!ImaAppraisalState::Unknown.is_violation());
    }

    #[test]
    fn appraisal_exempt_is_clean() {
        assert!(ImaAppraisalState::Exempt.is_clean());
        assert!(!ImaAppraisalState::Exempt.is_violation());
    }

    #[test]
    fn appraisal_labels_are_stable() {
        assert_eq!(ImaAppraisalState::Trusted.label(), "TRUSTED");
        assert_eq!(ImaAppraisalState::Untrusted.label(), "UNTRUSTED");
        assert_eq!(ImaAppraisalState::Unknown.label(), "UNKNOWN");
        assert_eq!(ImaAppraisalState::Exempt.label(), "EXEMPT");
    }

    // -------------------------------------------------------------------
    // ImaVerifier — verification and appraisal (INV-IMA-003)
    // -------------------------------------------------------------------

    #[test]
    fn verify_empty_log_produces_no_violations() {
        let log = ImaMeasurementList::new();
        let golden: HashMap<String, Vec<u8>> = HashMap::new();
        let verifier = ImaVerifier::new();
        let violations = verifier.verify(&log, &golden);
        assert!(violations.is_empty());
    }

    #[test]
    fn verify_matching_hashes_no_violations() {
        let mut log = ImaMeasurementList::new();
        log.record(measure("/bin/a", 1, 100));
        log.record(measure("/bin/b", 2, 200));

        let mut golden = HashMap::new();
        golden.insert("/bin/a".into(), hash_from_seed(1));
        golden.insert("/bin/b".into(), hash_from_seed(2));

        let verifier = ImaVerifier::new();
        let violations = verifier.verify(&log, &golden);
        assert!(violations.is_empty());
    }

    #[test]
    fn verify_mismatched_hashes_produces_violations() {
        let mut log = ImaMeasurementList::new();
        log.record(measure("/bin/a", 1, 100));
        log.record(measure("/bin/b", 99, 200));

        let mut golden = HashMap::new();
        golden.insert("/bin/a".into(), hash_from_seed(1));
        golden.insert("/bin/b".into(), hash_from_seed(2));

        let verifier = ImaVerifier::new();
        let violations = verifier.verify(&log, &golden);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].file_path, "/bin/b");
        assert_eq!(violations[0].measured_hash, hash_from_seed(99));
        assert_eq!(violations[0].expected_hash, hash_from_seed(2));
        assert_eq!(violations[0].state, ImaAppraisalState::Untrusted);
    }

    #[test]
    fn verify_multiple_mismatches_all_reported() {
        let mut log = ImaMeasurementList::new();
        log.record(measure("/a", 10, 1));
        log.record(measure("/b", 20, 2));
        log.record(measure("/c", 30, 3));

        let mut golden = HashMap::new();
        golden.insert("/a".into(), hash_from_seed(99));
        golden.insert("/b".into(), hash_from_seed(88));
        golden.insert("/c".into(), hash_from_seed(30));

        let verifier = ImaVerifier::new();
        let violations = verifier.verify(&log, &golden);
        assert_eq!(violations.len(), 2);
        let paths: Vec<&str> = violations.iter().map(|v| v.file_path.as_str()).collect();
        assert!(paths.contains(&"/a"));
        assert!(paths.contains(&"/b"));
        assert!(!paths.contains(&"/c"));
    }

    #[test]
    fn verify_unknown_files_do_not_produce_violations() {
        let mut log = ImaMeasurementList::new();
        log.record(measure("/known", 1, 100));
        log.record(measure("/unknown", 2, 200));

        let mut golden = HashMap::new();
        golden.insert("/known".into(), hash_from_seed(1));
        // /unknown is deliberately missing from golden table

        let verifier = ImaVerifier::new();
        let violations = verifier.verify(&log, &golden);
        assert!(violations.is_empty());
    }

    #[test]
    fn appraise_trusted_when_hashes_match() {
        let m = measure("/bin/sh", 42, 0);
        let state = ImaVerifier::appraise(&m, &hash_from_seed(42));
        assert_eq!(state, ImaAppraisalState::Trusted);
    }

    #[test]
    fn appraise_untrusted_when_hashes_differ() {
        let m = measure("/bin/sh", 42, 0);
        let state = ImaVerifier::appraise(&m, &hash_from_seed(99));
        assert_eq!(state, ImaAppraisalState::Untrusted);
    }

    #[test]
    fn appraise_unknown_when_expected_hash_is_wrong_length() {
        let m = measure("/bin/sh", 42, 0);
        let state = ImaVerifier::appraise(&m, &[0u8; 16]);
        assert_eq!(state, ImaAppraisalState::Unknown);
    }

    #[test]
    fn appraise_unknown_when_expected_hash_is_empty() {
        let m = measure("/bin/sh", 42, 0);
        let state = ImaVerifier::appraise(&m, &[]);
        assert_eq!(state, ImaAppraisalState::Unknown);
    }

    // -------------------------------------------------------------------
    // IntegrityViolation
    // -------------------------------------------------------------------

    #[test]
    fn violation_new_rejects_non_violation_states() {
        let measured = hash_from_seed(1);
        let expected = hash_from_seed(2);

        assert!(IntegrityViolation::new(
            "/f", measured.clone(), expected.clone(), ImaAppraisalState::Untrusted
        ).is_some());

        assert!(IntegrityViolation::new(
            "/f", measured.clone(), expected.clone(), ImaAppraisalState::Trusted
        ).is_none());

        assert!(IntegrityViolation::new(
            "/f", measured.clone(), expected.clone(), ImaAppraisalState::Unknown
        ).is_none());

        assert!(IntegrityViolation::new(
            "/f", measured.clone(), expected.clone(), ImaAppraisalState::Exempt
        ).is_none());
    }

    #[test]
    fn violation_summary_contains_key_information() {
        let v = IntegrityViolation::new(
            "/bin/evil",
            hash_from_seed(0xab),
            hash_from_seed(0xcd),
            ImaAppraisalState::Untrusted,
        )
        .unwrap();
        let summary = v.summary();
        assert!(summary.contains("INTEGRITY VIOLATION"));
        assert!(summary.contains("/bin/evil"));
        assert!(summary.contains("UNTRUSTED"));
    }

    #[test]
    fn violation_display_matches_summary() {
        let v = IntegrityViolation::new(
            "/f",
            hash_from_seed(1),
            hash_from_seed(2),
            ImaAppraisalState::Untrusted,
        )
        .unwrap();
        assert_eq!(format!("{v}"), v.summary());
    }

    // -------------------------------------------------------------------
    // Cross-cutting: complex verification scenarios
    // -------------------------------------------------------------------

    #[test]
    fn verify_with_policy_prefiltered_log() {
        let mut policy = ImaPolicy::new();
        policy.add_includes(&["/bin/**"]);
        policy.add_exclude("/bin/private");

        let mut log = ImaMeasurementList::new();
        log.record(measure("/bin/good", 1, 100));
        log.record(measure("/bin/bad", 99, 200));
        log.record(measure("/bin/private", 3, 300));

        let mut golden = HashMap::new();
        golden.insert("/bin/good".into(), hash_from_seed(1));
        golden.insert("/bin/bad".into(), hash_from_seed(2));
        golden.insert("/bin/private".into(), hash_from_seed(3));

        let verifier = ImaVerifier::new();
        let violations = verifier.verify(&log, &golden);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].file_path, "/bin/bad");

        let measured_by_policy: Vec<bool> = log
            .entries()
            .iter()
            .map(|m| policy.should_measure(&m.file_path))
            .collect();
        assert_eq!(measured_by_policy, vec![true, true, false]);
    }

    #[test]
    fn ima_measurement_list_default_is_empty() {
        let log: ImaMeasurementList = Default::default();
        assert!(log.is_empty());
    }

    #[test]
    fn ima_policy_default_is_measure_all() {
        let policy: ImaPolicy = Default::default();
        assert!(policy.should_measure("/anything"));
    }
}
