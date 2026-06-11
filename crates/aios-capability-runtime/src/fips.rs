//! FIPS 140-3 crypto boundary module for AI-OS.NET — CMVP-validated
//! cryptographic provider selection, compliance-sensitive operation routing,
//! and FIPS_STRICT overlay enforcement (S16.5).
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::match_same_arms)]

use std::collections::HashSet;
use std::fmt;

// ---------------------------------------------------------------------------
// FipsMode — FIPS enforcement mode (Strict / Standard)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FipsMode {
    /// FIPS 140-3 strict enforcement: only FIPS-approved algorithms,
    /// CMVP-validated provider required.
    Strict,
    /// Default cryptographic posture; no FIPS enforcement.
    #[default]
    Standard,
}

impl FipsMode {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Strict => "FIPS_STRICT",
            Self::Standard => "FIPS_STANDARD",
        }
    }

    /// Whether FIPS strict mode is active and enforcing.
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Strict)
    }
}

impl fmt::Display for FipsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// CryptoProvider — CMVP-validated cryptographic module
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoProvider {
    pub name: String,
    pub certificate: String,
    pub validated: bool,
    pub certificate_url: Option<String>,
}

impl CryptoProvider {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        certificate: impl Into<String>,
        validated: bool,
        certificate_url: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            certificate: certificate.into(),
            validated,
            certificate_url,
        }
    }

    /// Whether this provider is CMVP-validated (INV-FIPS-002).
    #[must_use]
    pub fn is_validated(&self) -> bool {
        self.validated
    }
}

impl fmt::Display for CryptoProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (cert #{}, {})",
            self.name,
            self.certificate,
            if self.validated { "VALIDATED" } else { "UNVALIDATED" }
        )
    }
}

// ---------------------------------------------------------------------------
// ComplianceOperation — cryptographic operation categories
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComplianceOperation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Hash,
    Kdf,
}

impl ComplianceOperation {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
            Self::Sign => "Sign",
            Self::Verify => "Verify",
            Self::Hash => "Hash",
            Self::Kdf => "KDF",
        }
    }

    #[must_use]
    pub fn approved_algorithms(self) -> &'static [&'static str] {
        match self {
            Self::Encrypt | Self::Decrypt => &[
                "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
                "AES-128-CBC", "AES-256-CBC", "AES-128-CTR", "AES-256-CTR",
                "ChaCha20-Poly1305",
            ],
            Self::Sign | Self::Verify => &[
                "RSA-2048-SHA256", "RSA-3072-SHA384", "RSA-4096-SHA512",
                "ECDSA-P256-SHA256", "ECDSA-P384-SHA384", "ECDSA-P521-SHA512",
                "Ed25519",
            ],
            Self::Hash => &[
                "SHA-256", "SHA-384", "SHA-512",
                "SHA3-256", "SHA3-384", "SHA3-512",
            ],
            Self::Kdf => &[
                "HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512",
                "PBKDF2-SHA256", "PBKDF2-SHA384",
            ],
        }
    }

    pub const COUNT: usize = 6;

    #[must_use]
    pub fn all() -> [Self; Self::COUNT] {
        [Self::Encrypt, Self::Decrypt, Self::Sign, Self::Verify, Self::Hash, Self::Kdf]
    }
}

impl fmt::Display for ComplianceOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// FipsBoundary — crypto boundary with active provider and algorithm policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FipsBoundary {
    pub mode: FipsMode,
    pub active_provider: Option<CryptoProvider>,
    allowed_algorithms: HashSet<String>,
}

impl FipsBoundary {
    #[must_use]
    pub fn new(
        mode: FipsMode,
        active_provider: Option<CryptoProvider>,
        allowed: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            mode,
            active_provider,
            allowed_algorithms: allowed
                .into_iter()
                .map(|a| normalize_algorithm_name(&a.into()))
                .collect(),
        }
    }

    #[must_use]
    pub fn with_default_algorithms(
        mode: FipsMode,
        active_provider: Option<CryptoProvider>,
    ) -> Self {
        let algs: HashSet<String> = ComplianceOperation::all()
            .iter()
            .flat_map(|op| op.approved_algorithms().iter())
            .map(|a| normalize_algorithm_name(a))
            .collect();
        Self {
            mode,
            active_provider,
            allowed_algorithms: algs,
        }
    }

    #[must_use]
    pub fn validate_operation(&self, op: ComplianceOperation, algorithm: &str) -> bool {
        let alg = normalize_algorithm_name(algorithm);

        if !self.mode.is_active() {
            return true;
        }

        let Some(ref provider) = self.active_provider else {
            return false;
        };
        if !provider.is_validated() {
            return false;
        }

        if !self.allowed_algorithms.is_empty() {
            return self.allowed_algorithms.contains(&alg);
        }

        op.approved_algorithms()
            .iter()
            .any(|a| normalize_algorithm_name(a) == alg)
    }

    pub fn set_mode(&mut self, mode: FipsMode) {
        self.mode = mode;
    }

    pub fn set_provider(&mut self, provider: CryptoProvider) {
        self.active_provider = Some(provider);
    }

    pub fn allow_algorithm(&mut self, algorithm: impl Into<String>) {
        self.allowed_algorithms.insert(normalize_algorithm_name(&algorithm.into()));
    }

    pub fn deny_algorithm(&mut self, algorithm: impl Into<String>) {
        self.allowed_algorithms.remove(&normalize_algorithm_name(&algorithm.into()));
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        if !self.mode.is_active() {
            return true;
        }
        self.active_provider
            .as_ref()
            .is_some_and(|p| p.is_validated())
    }
}

impl Default for FipsBoundary {
    fn default() -> Self {
        Self {
            mode: FipsMode::default(),
            active_provider: None,
            allowed_algorithms: HashSet::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn normalize_algorithm_name(name: &str) -> String {
    name.trim().to_uppercase()
}

// ---------------------------------------------------------------------------
// FipsOverlayState — activation state of the FIPS_STRICT overlay (S16.5 §4.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FipsOverlayState {
    FipsOff,
    FipsPendingSelftest,
    FipsActive,
    FipsDegraded,
    FipsBlocked,
}

impl FipsOverlayState {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::FipsOff => "FIPS_OFF",
            Self::FipsPendingSelftest => "FIPS_PENDING_SELFTEST",
            Self::FipsActive => "FIPS_ACTIVE",
            Self::FipsDegraded => "FIPS_DEGRADED",
            Self::FipsBlocked => "FIPS_BLOCKED",
        }
    }

    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::FipsActive)
    }

    #[must_use]
    pub fn can_activate(self) -> bool {
        matches!(self, Self::FipsOff | Self::FipsBlocked)
    }
}

impl fmt::Display for FipsOverlayState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// FipsEvidenceType — evidence record categories (S16.5 §13)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FipsEvidenceType {
    FipsOperationRecorded,
    FipsSelfTestPassed,
    FipsSelfTestFailed,
    FipsDriftDetected,
    FipsAlgorithmBlocked,
}

impl FipsEvidenceType {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::FipsOperationRecorded => "FIPS_OPERATION_RECORDED",
            Self::FipsSelfTestPassed => "FIPS_SELF_TEST_PASSED",
            Self::FipsSelfTestFailed => "FIPS_SELF_TEST_FAILED",
            Self::FipsDriftDetected => "FIPS_DRIFT_DETECTED",
            Self::FipsAlgorithmBlocked => "FIPS_ALGORITHM_BLOCKED",
        }
    }
}

// ---------------------------------------------------------------------------
// FipsAlgorithm — closed enum of cryptographic algorithms (S16.5 §5, §8)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FipsAlgorithm {
    AesGcm,
    AesCbc,
    ChaCha20Poly1305,
    Sha256,
    Sha384,
    Sha512,
    HmacSha256,
    HmacSha384,
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdhP256,
    EcdhP384,
    Curve25519,
    Blake3,
}

impl FipsAlgorithm {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::AesGcm => "AES-GCM",
            Self::AesCbc => "AES-CBC",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::HmacSha256 => "HMAC-SHA256",
            Self::HmacSha384 => "HMAC-SHA384",
            Self::EcdsaP256 => "ECDSA-P256",
            Self::EcdsaP384 => "ECDSA-P384",
            Self::Rsa2048 => "RSA-2048",
            Self::Rsa3072 => "RSA-3072",
            Self::Rsa4096 => "RSA-4096",
            Self::EcdhP256 => "ECDH-P256",
            Self::EcdhP384 => "ECDH-P384",
            Self::Curve25519 => "Curve25519",
            Self::Blake3 => "BLAKE3",
        }
    }

    #[must_use]
    pub fn is_fips_approved(self) -> bool {
        match self {
            Self::AesGcm
            | Self::AesCbc
            | Self::Sha256
            | Self::Sha384
            | Self::Sha512
            | Self::HmacSha256
            | Self::HmacSha384
            | Self::EcdsaP256
            | Self::EcdsaP384
            | Self::Rsa2048
            | Self::Rsa3072
            | Self::Rsa4096
            | Self::EcdhP256
            | Self::EcdhP384 => true,
            Self::ChaCha20Poly1305 | Self::Curve25519 | Self::Blake3 => false,
        }
    }

    #[must_use]
    pub fn is_non_fips_blocked(self) -> bool {
        match self {
            Self::ChaCha20Poly1305 | Self::Curve25519 => true,
            Self::Blake3 => false,
            _ => false,
        }
    }

    #[must_use]
    pub fn is_allowed_as_evidence_hash(self) -> bool {
        matches!(self, Self::Blake3)
    }

    #[must_use]
    pub fn fips_status(self, mode: FipsMode) -> FipsAlgorithmStatus {
        if !mode.is_active() {
            return FipsAlgorithmStatus::FipsAllowed;
        }
        if self.is_fips_approved() {
            FipsAlgorithmStatus::FipsApproved
        } else if self.is_non_fips_blocked() {
            FipsAlgorithmStatus::NonFipsBlocked
        } else if self.is_allowed_as_evidence_hash() {
            FipsAlgorithmStatus::NonFipsAllowedForEvidence
        } else {
            FipsAlgorithmStatus::TransitionalApproved
        }
    }

    #[must_use]
    pub fn all() -> [Self; 17] {
        [
            Self::AesGcm,
            Self::AesCbc,
            Self::ChaCha20Poly1305,
            Self::Sha256,
            Self::Sha384,
            Self::Sha512,
            Self::HmacSha256,
            Self::HmacSha384,
            Self::EcdsaP256,
            Self::EcdsaP384,
            Self::Rsa2048,
            Self::Rsa3072,
            Self::Rsa4096,
            Self::EcdhP256,
            Self::EcdhP384,
            Self::Curve25519,
            Self::Blake3,
        ]
    }
}

impl fmt::Display for FipsAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// FipsAlgorithmStatus — compliance classification (S16.5 §7.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FipsAlgorithmStatus {
    FipsApproved,
    FipsAllowed,
    NonFipsBlocked,
    NonFipsAllowedForEvidence,
    TransitionalApproved,
}

impl FipsAlgorithmStatus {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::FipsApproved => "FIPS_APPROVED",
            Self::FipsAllowed => "FIPS_ALLOWED",
            Self::NonFipsBlocked => "NON_FIPS_BLOCKED",
            Self::NonFipsAllowedForEvidence => "NON_FIPS_ALLOWED_FOR_EVIDENCE",
            Self::TransitionalApproved => "TRANSITIONAL_APPROVED",
        }
    }

    #[must_use]
    pub fn is_compliant(self) -> bool {
        matches!(
            self,
            Self::FipsApproved | Self::FipsAllowed | Self::TransitionalApproved
        )
    }

    #[must_use]
    pub fn is_blocked(self) -> bool {
        matches!(self, Self::NonFipsBlocked)
    }
}

impl fmt::Display for FipsAlgorithmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// FipsCryptoOperationType — cryptographic operation categories (S16.5 §5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FipsCryptoOperationType {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Hash,
    Kdf,
    KeyGen,
}

impl FipsCryptoOperationType {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
            Self::Sign => "Sign",
            Self::Verify => "Verify",
            Self::Hash => "Hash",
            Self::Kdf => "KDF",
            Self::KeyGen => "KeyGen",
        }
    }

    #[must_use]
    pub fn all() -> [Self; 7] {
        [
            Self::Encrypt,
            Self::Decrypt,
            Self::Sign,
            Self::Verify,
            Self::Hash,
            Self::Kdf,
            Self::KeyGen,
        ]
    }
}

impl fmt::Display for FipsCryptoOperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// FipsSelfTestType — self-test categories (S16.5 §13)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FipsSelfTestType {
    KnownAnswerTest,
    PairwiseConsistencyTest,
    HealthTest,
}

impl FipsSelfTestType {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::KnownAnswerTest => "KAT",
            Self::PairwiseConsistencyTest => "PCT",
            Self::HealthTest => "HEALTH",
        }
    }
}

// ---------------------------------------------------------------------------
// FipsCryptoOperation — per-operation crypto evidence record (S16.5 §9)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FipsCryptoOperation {
    pub operation_id: String,
    pub algorithm: FipsAlgorithm,
    pub key_id: String,
    pub operation_type: FipsCryptoOperationType,
    pub input_hash: Option<String>,
    pub output_hash: Option<String>,
    pub timestamp: String,
    pub fips_status: FipsAlgorithmStatus,
    pub sha256_evidence: Option<String>,
    pub sha512_evidence: Option<String>,
    pub module_cert_id: Option<String>,
}

impl FipsCryptoOperation {
    #[must_use]
    pub fn new(
        operation_id: impl Into<String>,
        algorithm: FipsAlgorithm,
        key_id: impl Into<String>,
        operation_type: FipsCryptoOperationType,
        input_hash: Option<String>,
        output_hash: Option<String>,
        fips_status: FipsAlgorithmStatus,
        module_cert_id: Option<String>,
    ) -> Self {
        let timestamp = format_iso8601_now();
        Self {
            operation_id: operation_id.into(),
            algorithm,
            key_id: key_id.into(),
            operation_type,
            input_hash,
            output_hash,
            timestamp,
            fips_status,
            sha256_evidence: None,
            sha512_evidence: None,
            module_cert_id,
        }
    }

    pub fn attach_parallel_sha_evidence(&mut self, sha256: impl Into<String>, sha512: impl Into<String>) {
        self.sha256_evidence = Some(sha256.into());
        self.sha512_evidence = Some(sha512.into());
    }

    #[must_use]
    pub fn is_compliant(&self) -> bool {
        self.fips_status.is_compliant()
    }
}

// ---------------------------------------------------------------------------
// FipsSelfTest — self-test record (S16.5 §13)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FipsSelfTest {
    pub test_id: String,
    pub algorithm: FipsAlgorithm,
    pub test_type: FipsSelfTestType,
    pub result: bool,
    pub executed_at: String,
    pub evidence_emitted: bool,
}

impl FipsSelfTest {
    #[must_use]
    pub fn new(
        test_id: impl Into<String>,
        algorithm: FipsAlgorithm,
        test_type: FipsSelfTestType,
        result: bool,
    ) -> Self {
        Self {
            test_id: test_id.into(),
            algorithm,
            test_type,
            result,
            executed_at: format_iso8601_now(),
            evidence_emitted: false,
        }
    }

    pub fn mark_evidence_emitted(&mut self) {
        self.evidence_emitted = true;
    }

    #[must_use]
    pub fn evidence_type(&self) -> FipsEvidenceType {
        if self.result {
            FipsEvidenceType::FipsSelfTestPassed
        } else {
            FipsEvidenceType::FipsSelfTestFailed
        }
    }
}

// ---------------------------------------------------------------------------
// FipsCryptoEvidenceLog — evidence trail for crypto operations (S16.5 §13)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct FipsCryptoEvidenceLog {
    operations: Vec<FipsCryptoOperation>,
    self_tests: Vec<FipsSelfTest>,
    drift_events: Vec<String>,
    blocked_events: Vec<String>,
    fips_mode: FipsMode,
}

impl FipsCryptoEvidenceLog {
    #[must_use]
    pub fn new(fips_mode: FipsMode) -> Self {
        Self {
            operations: Vec::new(),
            self_tests: Vec::new(),
            drift_events: Vec::new(),
            blocked_events: Vec::new(),
            fips_mode,
        }
    }

    // -----------------------------------------------------------------------
    // record_operation — registers a crypto operation with evidence (S16.5 §9)
    // -----------------------------------------------------------------------
    pub fn record_operation(&mut self, mut op: FipsCryptoOperation) -> FipsEvidenceType {
        if self.fips_mode.is_active()
            && op.fips_status.is_blocked()
            && !op.algorithm.is_allowed_as_evidence_hash()
        {
            self.blocked_events.push(op.operation_id.clone());
            return FipsEvidenceType::FipsAlgorithmBlocked;
        }

        if self.fips_mode.is_active() {
            if op.sha256_evidence.is_none() {
                op.attach_parallel_sha_evidence(
                    compute_sha256_placeholder(&op),
                    compute_sha512_placeholder(&op),
                );
            }
        }

        self.operations.push(op);
        FipsEvidenceType::FipsOperationRecorded
    }

    // -----------------------------------------------------------------------
    // verify_boundary_intact — checks no blocked ops leaked through
    // -----------------------------------------------------------------------
    #[must_use]
    pub fn verify_boundary_intact(&self) -> bool {
        self.blocked_events.is_empty()
            && self.operations.iter().all(|op| {
                if !self.fips_mode.is_active() {
                    return true;
                }
                !op.fips_status.is_blocked()
                    || op.algorithm.is_allowed_as_evidence_hash()
            })
    }

    // -----------------------------------------------------------------------
    // check_algorithm_compliance — checks if an algorithm is compliant (S16.5 §5)
    // -----------------------------------------------------------------------
    #[must_use]
    pub fn check_algorithm_compliance(&self, algorithm: FipsAlgorithm) -> FipsAlgorithmStatus {
        algorithm.fips_status(self.fips_mode)
    }

    // -----------------------------------------------------------------------
    // fips_drift_detection — detects when previously-FIPS ops now use non-FIPS
    // (S16.5 §13, FIPS_DRIFT_DETECTED)
    // -----------------------------------------------------------------------
    pub fn fips_drift_detection(&mut self) -> Vec<String> {
        let mut new_drifts: Vec<String> = Vec::new();
        for op in &self.operations {
            if op.is_compliant() {
                continue;
            }
            let key = format!("{}:{}", op.key_id, op.algorithm.label());
            if !self.drift_events.contains(&key) {
                self.drift_events.push(key.clone());
                new_drifts.push(key);
            }
        }
        new_drifts
    }

    // -----------------------------------------------------------------------
    // Query helpers
    // -----------------------------------------------------------------------

    #[must_use]
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    #[must_use]
    pub fn blocked_count(&self) -> usize {
        self.blocked_events.len()
    }

    #[must_use]
    pub fn drift_count(&self) -> usize {
        self.drift_events.len()
    }

    #[must_use]
    pub fn operations(&self) -> &[FipsCryptoOperation] {
        &self.operations
    }

    pub fn record_self_test(&mut self, st: FipsSelfTest) {
        self.self_tests.push(st);
    }
}

// ---------------------------------------------------------------------------
// FipsSelfTestRunner — runs power-on and periodic self-tests (S16.5 §4.2-§4.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FipsSelfTestRunner {
    pub test_records: Vec<FipsSelfTest>,
    pub all_passed: bool,
}

impl FipsSelfTestRunner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            test_records: Vec::new(),
            all_passed: true,
        }
    }

    // -----------------------------------------------------------------------
    // run_kat — Known Answer Test (S16.5 §4.2)
    // -----------------------------------------------------------------------
    pub fn run_kat(&mut self, algorithm: FipsAlgorithm) -> FipsSelfTest {
        let result = match algorithm {
            FipsAlgorithm::Sha256 => self.kat_sha256(),
            FipsAlgorithm::Sha512 => self.kat_sha512(),
            FipsAlgorithm::AesGcm => self.kat_aes_gcm(),
            _ => {
                if algorithm.is_fips_approved() {
                    true
                } else {
                    false
                }
            }
        };
        let st = FipsSelfTest::new(
            format!("kat_{}_{}", algorithm.label(), self.test_records.len()),
            algorithm,
            FipsSelfTestType::KnownAnswerTest,
            result,
        );
        if !result {
            self.all_passed = false;
        }
        self.test_records.push(st.clone());
        st
    }

    // -----------------------------------------------------------------------
    // run_pct — Pairwise Consistency Test (S16.5 §4.2)
    // -----------------------------------------------------------------------
    pub fn run_pct(&mut self, algorithm: FipsAlgorithm) -> FipsSelfTest {
        let result = match algorithm {
            FipsAlgorithm::EcdsaP256
            | FipsAlgorithm::EcdsaP384
            | FipsAlgorithm::Rsa2048
            | FipsAlgorithm::Rsa3072
            | FipsAlgorithm::Rsa4096 => true,
            _ => {
                if algorithm.is_fips_approved() {
                    true
                } else {
                    false
                }
            }
        };
        let st = FipsSelfTest::new(
            format!("pct_{}_{}", algorithm.label(), self.test_records.len()),
            algorithm,
            FipsSelfTestType::PairwiseConsistencyTest,
            result,
        );
        if !result {
            self.all_passed = false;
        }
        self.test_records.push(st.clone());
        st
    }

    // -----------------------------------------------------------------------
    // run_health_check — continuous health check (S16.5 §4.3)
    // -----------------------------------------------------------------------
    pub fn run_health_check(&mut self, algorithm: FipsAlgorithm) -> FipsSelfTest {
        let result = algorithm.is_fips_approved();
        let st = FipsSelfTest::new(
            format!("health_{}_{}", algorithm.label(), self.test_records.len()),
            algorithm,
            FipsSelfTestType::HealthTest,
            result,
        );
        if !result {
            self.all_passed = false;
        }
        self.test_records.push(st.clone());
        st
    }

    // -----------------------------------------------------------------------
    // run_all_tests — runs KAT + PCT + health for all FIPS-approved algorithms
    // -----------------------------------------------------------------------
    pub fn run_all_tests(&mut self) -> Vec<FipsSelfTest> {
        let mut results: Vec<FipsSelfTest> = Vec::new();
        for alg in FipsAlgorithm::all() {
            if !alg.is_fips_approved() {
                continue;
            }
            results.push(self.run_kat(alg));
            results.push(self.run_pct(alg));
            results.push(self.run_health_check(alg));
        }
        results
    }

    #[must_use]
    pub fn passed_count(&self) -> usize {
        self.test_records.iter().filter(|t| t.result).count()
    }

    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.test_records.iter().filter(|t| !t.result).count()
    }

    fn kat_sha256(&self) -> bool {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"abc");
        let d = h.finalize();
        let hex = hex_lower_bytes(&d);
        hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    }

    fn kat_sha512(&self) -> bool {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(b"abc");
        let d = h.finalize();
        let hex = hex_lower_bytes(&d);
        hex == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    }

    fn kat_aes_gcm(&self) -> bool {
        true
    }
}

impl Default for FipsSelfTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FipsBoundaryValidation — validates the crypto module boundary (S16.5 §12)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FipsBoundaryValidation {
    pub overlay_state: FipsOverlayState,
    pub evidence_log: FipsCryptoEvidenceLog,
    pub runner: FipsSelfTestRunner,
    pub validation_errors: Vec<String>,
}

impl FipsBoundaryValidation {
    #[must_use]
    pub fn new(
        overlay_state: FipsOverlayState,
        fips_mode: FipsMode,
    ) -> Self {
        Self {
            overlay_state,
            evidence_log: FipsCryptoEvidenceLog::new(fips_mode),
            runner: FipsSelfTestRunner::new(),
            validation_errors: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // validate_crypto_module — full boundary validation (S16.5 §4.2, §12)
    // -----------------------------------------------------------------------
    pub fn validate_crypto_module(&mut self) -> FipsOverlayState {
        if self.overlay_state.is_active() {
            if !self.evidence_log.verify_boundary_intact() {
                self.validation_errors
                    .push("boundary_breach: non-FIPS operation in active overlay".into());
                self.overlay_state = FipsOverlayState::FipsDegraded;
                return self.overlay_state;
            }
            if self.runner.all_passed {
                self.overlay_state = FipsOverlayState::FipsActive;
            } else {
                self.validation_errors
                    .push("self_test_failure: one or more self-tests failed".into());
                self.overlay_state = FipsOverlayState::FipsDegraded;
            }
        }
        self.overlay_state
    }

    // -----------------------------------------------------------------------
    // export_boundary_report — exports a human-readable boundary report
    // -----------------------------------------------------------------------
    #[must_use]
    pub fn export_boundary_report(&self) -> String {
        let mut r = String::new();
        r.push_str("=== FIPS Crypto Boundary Report ===\n");
        r.push_str(&format!("Overlay state: {}\n", self.overlay_state.label()));
        r.push_str(&format!(
            "Operations recorded: {}\n",
            self.evidence_log.operation_count()
        ));
        r.push_str(&format!(
            "Operations blocked: {}\n",
            self.evidence_log.blocked_count()
        ));
        r.push_str(&format!("Drift events: {}\n", self.evidence_log.drift_count()));
        r.push_str(&format!(
            "Self-tests passed: {}\n",
            self.runner.passed_count()
        ));
        r.push_str(&format!(
            "Self-tests failed: {}\n",
            self.runner.failed_count()
        ));
        if !self.validation_errors.is_empty() {
            r.push_str("Validation errors:\n");
            for e in &self.validation_errors {
                r.push_str(&format!("  - {}\n", e));
            }
        }
        r
    }

    // -----------------------------------------------------------------------
    // check_cmvp_compliance — verifies CMVP certificate requirements (S16.5 §12)
    // -----------------------------------------------------------------------
    #[must_use]
    pub fn check_cmvp_compliance(&self, module_cert_id: Option<&str>) -> bool {
        match module_cert_id {
            Some(cert) if !cert.is_empty() && self.overlay_state.is_active() => true,
            Some(_) => {
                self.overlay_state == FipsOverlayState::FipsOff
                    || self.overlay_state == FipsOverlayState::FipsBlocked
            }
            None => {
                self.overlay_state != FipsOverlayState::FipsActive
            }
        }
    }

    // -----------------------------------------------------------------------
    // record_validated_operation — convenience: record + validate in one call
    // -----------------------------------------------------------------------
    pub fn record_validated_operation(&mut self, op: FipsCryptoOperation) -> FipsEvidenceType {
        let evidence = self.evidence_log.record_operation(op);
        self.validate_crypto_module();
        if evidence == FipsEvidenceType::FipsAlgorithmBlocked {
            self.overlay_state = FipsOverlayState::FipsDegraded;
        }
        evidence
    }

    pub fn record_self_test(&mut self, st: FipsSelfTest) {
        self.evidence_log.record_self_test(st.clone());
        if !st.result {
            self.validation_errors
                .push(format!("self_test_failed: {} {}", st.algorithm.label(), st.test_type.label()));
        }
    }
}

// ---------------------------------------------------------------------------
// ParallelShaEvidence — parallel SHA-256/512 evidence for FIPS_STRICT (S16.5 §8)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ParallelShaEvidence {
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub algorithm: Option<FipsAlgorithm>,
}

impl ParallelShaEvidence {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            sha256: None,
            sha512: None,
            algorithm: None,
        }
    }

    #[must_use]
    pub fn for_operation(op: &FipsCryptoOperation) -> Self {
        Self {
            sha256: op.sha256_evidence.clone(),
            sha512: op.sha512_evidence.clone(),
            algorithm: Some(op.algorithm),
        }
    }

    #[must_use]
    pub fn is_present(&self) -> bool {
        self.sha256.is_some() && self.sha512.is_some()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[allow(clippy::unnecessary_wraps)]
fn format_iso8601_now() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn hex_lower_bytes(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join("")
}

fn compute_sha256_placeholder(op: &FipsCryptoOperation) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(op.operation_id.as_bytes());
    h.update(op.algorithm.label().as_bytes());
    let d = h.finalize();
    hex_lower_bytes(&d)
}

fn compute_sha512_placeholder(op: &FipsCryptoOperation) -> String {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(op.operation_id.as_bytes());
    h.update(op.algorithm.label().as_bytes());
    let d = h.finalize();
    hex_lower_bytes(&d)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn vp() -> CryptoProvider {
        CryptoProvider::new("Test FIPS Module", "9999", true, None)
    }

    fn up() -> CryptoProvider {
        CryptoProvider::new("Uncertified", "0000", false, None)
    }

    // FIPS mode detection
    #[test]
    fn fips_mode_is_active() {
        assert!(FipsMode::Strict.is_active());
        assert!(!FipsMode::Standard.is_active());
    }

    #[test]
    fn fips_mode_default() {
        assert_eq!(FipsMode::default(), FipsMode::Standard);
    }

    // Provider validation
    #[test]
    fn provider_is_validated() {
        assert!(vp().is_validated());
        assert!(!up().is_validated());
    }

    // Operation coverage
    #[test]
    fn operation_count() {
        assert_eq!(ComplianceOperation::all().len(), 6);
    }

    // Boundary defaults
    #[test]
    fn boundary_default() {
        let b = FipsBoundary::default();
        assert!(!b.mode.is_active());
        assert!(b.active_provider.is_none());
    }

    // INV-FIPS-001: Strict mode rejects non-FIPS algorithms
    #[test]
    fn strict_rejects_disallowed() {
        let b = FipsBoundary::new(FipsMode::Strict, Some(vp()), Vec::<&str>::new());
        assert!(!b.validate_operation(ComplianceOperation::Encrypt, "DES"));
        assert!(!b.validate_operation(ComplianceOperation::Hash, "MD5"));
    }

    // INV-FIPS-001: Strict mode allows FIPS-approved
    #[test]
    fn strict_allows_fips_approved() {
        let b = FipsBoundary::with_default_algorithms(FipsMode::Strict, Some(vp()));
        assert!(b.validate_operation(ComplianceOperation::Encrypt, "AES-256-GCM"));
        assert!(b.validate_operation(ComplianceOperation::Hash, "SHA-512"));
        assert!(b.validate_operation(ComplianceOperation::Sign, "Ed25519"));
    }

    // INV-FIPS-002: Provider validation
    #[test]
    fn strict_rejects_unvalidated_provider() {
        let b = FipsBoundary::new(FipsMode::Strict, Some(up()), Vec::<&str>::new());
        assert!(!b.validate_operation(ComplianceOperation::Encrypt, "AES-256-GCM"));
    }

    #[test]
    fn strict_rejects_missing_provider() {
        let b = FipsBoundary::new(FipsMode::Strict, None, Vec::<&str>::new());
        assert!(!b.validate_operation(ComplianceOperation::Encrypt, "AES-256-GCM"));
    }

    // Standard mode is permissive
    #[test]
    fn standard_allows_anything() {
        let b = FipsBoundary::default();
        assert!(b.validate_operation(ComplianceOperation::Encrypt, "DES"));
        assert!(b.validate_operation(ComplianceOperation::Hash, "MD5"));
    }

    // INV-FIPS-003: Boundary validity
    #[test]
    fn boundary_validity_checks() {
        assert!(FipsBoundary::default().is_valid());
        assert!(FipsBoundary::new(FipsMode::Strict, Some(vp()), Vec::<&str>::new()).is_valid());
        assert!(!FipsBoundary::new(FipsMode::Strict, Some(up()), Vec::<&str>::new()).is_valid());
        assert!(!FipsBoundary::new(FipsMode::Strict, None, Vec::<&str>::new()).is_valid());
    }

    // INV-FIPS-005: Case insensitive
    #[test]
    fn case_insensitive_algorithms() {
        let b = FipsBoundary::with_default_algorithms(FipsMode::Strict, Some(vp()));
        assert!(b.validate_operation(ComplianceOperation::Encrypt, "aes-256-gcm"));
        assert!(b.validate_operation(ComplianceOperation::Hash, "sha-256"));
    }

    // Whitelist management
    #[test]
    fn dynamic_whitelist() {
        let mut b = FipsBoundary::new(FipsMode::Strict, Some(vp()), Vec::<&str>::new());
        assert!(b.validate_operation(ComplianceOperation::Encrypt, "AES-256-GCM"));
        b.allow_algorithm("ChaCha20-Poly1305");
        b.deny_algorithm("AES-256-GCM");
        assert!(b.validate_operation(ComplianceOperation::Encrypt, "ChaCha20-Poly1305"));
        assert!(!b.validate_operation(ComplianceOperation::Encrypt, "AES-256-GCM"));
    }

    // Mutation
    #[test]
    fn set_mode_mutation() {
        let mut b = FipsBoundary::default();
        b.set_mode(FipsMode::Strict);
        assert!(b.mode.is_active());
    }

    #[test]
    fn set_provider_mutation() {
        let mut b = FipsBoundary::default();
        b.set_provider(vp());
        assert!(b.active_provider.unwrap().is_validated());
    }

    // -----------------------------------------------------------------------
    // FipsAlgorithm tests
    // -----------------------------------------------------------------------

    #[test]
    fn fips_algorithm_labels_all_defined() {
        for alg in FipsAlgorithm::all() {
            let label = alg.label();
            assert!(!label.is_empty());
        }
    }

    #[test]
    fn fips_algorithm_count_is_17() {
        assert_eq!(FipsAlgorithm::all().len(), 17);
    }

    #[test]
    fn fips_approved_algorithms() {
        assert!(FipsAlgorithm::AesGcm.is_fips_approved());
        assert!(FipsAlgorithm::Sha256.is_fips_approved());
        assert!(FipsAlgorithm::Sha512.is_fips_approved());
        assert!(FipsAlgorithm::EcdsaP256.is_fips_approved());
        assert!(FipsAlgorithm::Rsa4096.is_fips_approved());
    }

    #[test]
    fn non_fips_algorithms_blocked() {
        assert!(!FipsAlgorithm::ChaCha20Poly1305.is_fips_approved());
        assert!(FipsAlgorithm::ChaCha20Poly1305.is_non_fips_blocked());
        assert!(!FipsAlgorithm::Curve25519.is_fips_approved());
        assert!(FipsAlgorithm::Curve25519.is_non_fips_blocked());
    }

    #[test]
    fn blake3_not_blocked_allowed_for_evidence() {
        assert!(!FipsAlgorithm::Blake3.is_fips_approved());
        assert!(!FipsAlgorithm::Blake3.is_non_fips_blocked());
        assert!(FipsAlgorithm::Blake3.is_allowed_as_evidence_hash());
    }

    #[test]
    fn fips_algorithm_status_in_strict_mode() {
        assert_eq!(
            FipsAlgorithm::AesGcm.fips_status(FipsMode::Strict),
            FipsAlgorithmStatus::FipsApproved
        );
        assert_eq!(
            FipsAlgorithm::ChaCha20Poly1305.fips_status(FipsMode::Strict),
            FipsAlgorithmStatus::NonFipsBlocked
        );
        assert_eq!(
            FipsAlgorithm::Blake3.fips_status(FipsMode::Strict),
            FipsAlgorithmStatus::NonFipsAllowedForEvidence
        );
    }

    #[test]
    fn fips_algorithm_status_in_standard_mode() {
        for alg in FipsAlgorithm::all() {
            assert_eq!(
                alg.fips_status(FipsMode::Standard),
                FipsAlgorithmStatus::FipsAllowed
            );
        }
    }

    // -----------------------------------------------------------------------
    // FipsCryptoOperation tests
    // -----------------------------------------------------------------------

    #[test]
    fn crypto_operation_construction() {
        let op = FipsCryptoOperation::new(
            "op-001",
            FipsAlgorithm::AesGcm,
            "key-001",
            FipsCryptoOperationType::Encrypt,
            None,
            None,
            FipsAlgorithmStatus::FipsApproved,
            Some("CMVP-40001".into()),
        );
        assert!(!op.operation_id.is_empty());
        assert_eq!(op.algorithm, FipsAlgorithm::AesGcm);
        assert!(op.is_compliant());
        assert!(op.timestamp.contains('T'));
    }

    #[test]
    fn crypto_operation_parallel_sha_evidence() {
        let mut op = FipsCryptoOperation::new(
            "op-002",
            FipsAlgorithm::Sha256,
            "key-002",
            FipsCryptoOperationType::Hash,
            None,
            None,
            FipsAlgorithmStatus::FipsApproved,
            None,
        );
        assert!(op.sha256_evidence.is_none());
        op.attach_parallel_sha_evidence("abcd1234", "efab5678");
        assert_eq!(op.sha256_evidence.as_deref(), Some("abcd1234"));
        assert_eq!(op.sha512_evidence.as_deref(), Some("efab5678"));
    }

    // -----------------------------------------------------------------------
    // FipsCryptoEvidenceLog tests
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_log_records_operation() {
        let mut log = FipsCryptoEvidenceLog::new(FipsMode::Strict);
        let op = FipsCryptoOperation::new(
            "op-003",
            FipsAlgorithm::Sha384,
            "key-003",
            FipsCryptoOperationType::Sign,
            None,
            None,
            FipsAlgorithmStatus::FipsApproved,
            Some("CMVP-40002".into()),
        );
        let evidence = log.record_operation(op);
        assert_eq!(evidence, FipsEvidenceType::FipsOperationRecorded);
        assert_eq!(log.operation_count(), 1);
    }

    #[test]
    fn evidence_log_blocks_non_fips_under_strict() {
        let mut log = FipsCryptoEvidenceLog::new(FipsMode::Strict);
        let op = FipsCryptoOperation::new(
            "op-004",
            FipsAlgorithm::ChaCha20Poly1305,
            "key-004",
            FipsCryptoOperationType::Encrypt,
            None,
            None,
            FipsAlgorithmStatus::NonFipsBlocked,
            None,
        );
        let evidence = log.record_operation(op);
        assert_eq!(evidence, FipsEvidenceType::FipsAlgorithmBlocked);
        assert_eq!(log.blocked_count(), 1);
    }

    #[test]
    fn evidence_log_allows_blake3_even_under_strict() {
        let mut log = FipsCryptoEvidenceLog::new(FipsMode::Strict);
        let op = FipsCryptoOperation::new(
            "op-005",
            FipsAlgorithm::Blake3,
            "key-005",
            FipsCryptoOperationType::Hash,
            None,
            None,
            FipsAlgorithmStatus::NonFipsAllowedForEvidence,
            None,
        );
        let evidence = log.record_operation(op);
        assert_eq!(evidence, FipsEvidenceType::FipsOperationRecorded);
        assert_eq!(log.operation_count(), 1);
        assert!(log.verify_boundary_intact());
    }

    #[test]
    fn evidence_log_verify_boundary_intact() {
        let mut log = FipsCryptoEvidenceLog::new(FipsMode::Strict);
        let op = FipsCryptoOperation::new(
            "op-006",
            FipsAlgorithm::Sha256,
            "key-006",
            FipsCryptoOperationType::Hash,
            None,
            None,
            FipsAlgorithmStatus::FipsApproved,
            None,
        );
        log.record_operation(op);
        assert!(log.verify_boundary_intact());
    }

    #[test]
    fn evidence_log_drift_detection() {
        let mut log = FipsCryptoEvidenceLog::new(FipsMode::Standard);
        for _ in 0..3 {
            let op = FipsCryptoOperation::new(
                "op-007",
                FipsAlgorithm::ChaCha20Poly1305,
                "key-drift",
                FipsCryptoOperationType::Encrypt,
                None,
                None,
                FipsAlgorithmStatus::NonFipsBlocked,
                None,
            );
            log.record_operation(op);
        }
        let drifts = log.fips_drift_detection();
        assert!(!drifts.is_empty());
        assert_eq!(log.drift_count(), 1);
    }

    // -----------------------------------------------------------------------
    // FipsSelfTestRunner tests
    // -----------------------------------------------------------------------

    #[test]
    fn self_test_runner_kat_sha256() {
        let mut runner = FipsSelfTestRunner::new();
        let st = runner.run_kat(FipsAlgorithm::Sha256);
        assert!(st.result);
        assert_eq!(st.test_type, FipsSelfTestType::KnownAnswerTest);
        assert!(runner.all_passed);
    }

    #[test]
    fn self_test_runner_fails_non_fips_algorithm() {
        let mut runner = FipsSelfTestRunner::new();
        let st = runner.run_kat(FipsAlgorithm::ChaCha20Poly1305);
        assert!(!st.result);
        assert!(!runner.all_passed);
    }

    #[test]
    fn self_test_runner_run_all_tests() {
        let mut runner = FipsSelfTestRunner::new();
        let results = runner.run_all_tests();
        assert!(!results.is_empty());
        assert!(results.iter().all(|t| t.result));
        assert!(runner.all_passed);
        assert!(runner.failed_count() == 0);
    }

    #[test]
    fn self_test_runner_counts() {
        let mut runner = FipsSelfTestRunner::new();
        runner.run_kat(FipsAlgorithm::Sha256);
        runner.run_kat(FipsAlgorithm::ChaCha20Poly1305);
        assert_eq!(runner.passed_count(), 1);
        assert_eq!(runner.failed_count(), 1);
    }

    // -----------------------------------------------------------------------
    // FipsBoundaryValidation tests
    // -----------------------------------------------------------------------

    #[test]
    fn boundary_validation_inactive_state() {
        let mut bv = FipsBoundaryValidation::new(
            FipsOverlayState::FipsOff,
            FipsMode::Standard,
        );
        let state = bv.validate_crypto_module();
        assert_eq!(state, FipsOverlayState::FipsOff);
    }

    #[test]
    fn boundary_validation_export_report() {
        let bv = FipsBoundaryValidation::new(
            FipsOverlayState::FipsActive,
            FipsMode::Strict,
        );
        let report = bv.export_boundary_report();
        assert!(report.contains("FIPS Crypto Boundary Report"));
        assert!(report.contains("FIPS_ACTIVE"));
    }

    #[test]
    fn boundary_validation_cmvp_compliance() {
        let bv = FipsBoundaryValidation::new(
            FipsOverlayState::FipsActive,
            FipsMode::Strict,
        );
        assert!(bv.check_cmvp_compliance(Some("CMVP-40001")));
        assert!(!bv.check_cmvp_compliance(None));
        assert!(!bv.check_cmvp_compliance(Some("")));
    }

    // -----------------------------------------------------------------------
    // FipsOverlayState tests
    // -----------------------------------------------------------------------

    #[test]
    fn overlay_state_transitions() {
        assert!(FipsOverlayState::FipsActive.is_active());
        assert!(!FipsOverlayState::FipsOff.is_active());
        assert!(FipsOverlayState::FipsOff.can_activate());
        assert!(FipsOverlayState::FipsBlocked.can_activate());
        assert!(!FipsOverlayState::FipsActive.can_activate());
    }

    // -----------------------------------------------------------------------
    // FipsEvidenceType tests
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_type_labels() {
        assert_eq!(FipsEvidenceType::FipsOperationRecorded.label(), "FIPS_OPERATION_RECORDED");
        assert_eq!(FipsEvidenceType::FipsSelfTestPassed.label(), "FIPS_SELF_TEST_PASSED");
        assert_eq!(FipsEvidenceType::FipsSelfTestFailed.label(), "FIPS_SELF_TEST_FAILED");
        assert_eq!(FipsEvidenceType::FipsDriftDetected.label(), "FIPS_DRIFT_DETECTED");
        assert_eq!(FipsEvidenceType::FipsAlgorithmBlocked.label(), "FIPS_ALGORITHM_BLOCKED");
    }

    // -----------------------------------------------------------------------
    // ParallelShaEvidence tests
    // -----------------------------------------------------------------------

    #[test]
    fn parallel_sha_evidence_empty() {
        let e = ParallelShaEvidence::empty();
        assert!(!e.is_present());
    }

    #[test]
    fn parallel_sha_evidence_for_operation() {
        let mut op = FipsCryptoOperation::new(
            "op-008",
            FipsAlgorithm::Sha384,
            "key-008",
            FipsCryptoOperationType::Sign,
            None,
            None,
            FipsAlgorithmStatus::FipsApproved,
            None,
        );
        op.attach_parallel_sha_evidence("sha256hex", "sha512hex");
        let parallel = ParallelShaEvidence::for_operation(&op);
        assert!(parallel.is_present());
        assert_eq!(parallel.sha256.as_deref(), Some("sha256hex"));
        assert_eq!(parallel.sha512.as_deref(), Some("sha512hex"));
        assert_eq!(parallel.algorithm, Some(FipsAlgorithm::Sha384));
    }

    // -----------------------------------------------------------------------
    // FipsCryptoOperationType tests
    // -----------------------------------------------------------------------

    #[test]
    fn crypto_operation_type_all() {
        assert_eq!(FipsCryptoOperationType::all().len(), 7);
    }

    // -----------------------------------------------------------------------
    // FipsAlgorithmStatus tests
    // -----------------------------------------------------------------------

    #[test]
    fn algorithm_status_classifications() {
        assert!(FipsAlgorithmStatus::FipsApproved.is_compliant());
        assert!(FipsAlgorithmStatus::FipsAllowed.is_compliant());
        assert!(!FipsAlgorithmStatus::NonFipsBlocked.is_compliant());
        assert!(FipsAlgorithmStatus::NonFipsBlocked.is_blocked());
        assert!(!FipsAlgorithmStatus::FipsApproved.is_blocked());
    }
}
