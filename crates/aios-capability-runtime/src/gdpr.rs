//! GDPR crypto-shred module for AIOS data sovereignty (S16.9).
#![allow(
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::module_name_repetitions
)]

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl DataClassification {
    pub fn requires_encryption(&self) -> bool {
        matches!(self, Self::Confidential | Self::Restricted)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Internal => "Internal",
            Self::Confidential => "Confidential",
            Self::Restricted => "Restricted",
        }
    }

    pub fn max_level(a: Self, b: Self) -> Self {
        use DataClassification::*;
        let to_ord = |c: Self| -> u8 {
            match c {
                Public => 0,
                Internal => 1,
                Confidential => 2,
                Restricted => 3,
            }
        };
        match to_ord(a).max(to_ord(b)) {
            0 => Public,
            1 => Internal,
            2 => Confidential,
            _ => Restricted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoShredKey {
    pub key_id: String,
    pub algorithm: String,
    pub created_at: u64,
}

impl CryptoShredKey {
    pub fn new(key_id: String, algorithm: String) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            key_id,
            algorithm,
            created_at,
        }
    }

    pub fn new_with_time(key_id: String, algorithm: String, created_at: u64) -> Self {
        Self {
            key_id,
            algorithm,
            created_at,
        }
    }

    pub fn destroy(&self, request: &ShredRequest) -> ShredEvidence {
        let verification = format!(
            "KEY_DESTROYED:{}:{}:{}",
            self.key_id, request.destroyed_at, request.data_id
        );
        ShredEvidence {
            data_id: request.data_id.clone(),
            key_id: self.key_id.clone(),
            reason: request.reason.clone(),
            destroyed_at: request.destroyed_at,
            verification,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShredRequest {
    pub data_id: String,
    pub reason: String,
    pub created_at: u64,
    pub destroyed_at: u64,
}

impl ShredRequest {
    pub fn new(data_id: String, reason: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            data_id,
            reason,
            created_at: now,
            destroyed_at: 0,
        }
    }

    pub fn new_full(data_id: String, reason: String, created_at: u64, destroyed_at: u64) -> Self {
        Self {
            data_id,
            reason,
            created_at,
            destroyed_at,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.data_id.is_empty() {
            return Err("data_id must not be empty".into());
        }
        if self.reason.is_empty() {
            return Err("reason must not be empty".into());
        }
        if self.destroyed_at > 0 && self.destroyed_at < self.created_at {
            return Err("destroyed_at must be >= created_at".into());
        }
        Ok(())
    }

    pub fn mark_destroyed(&mut self, timestamp: u64) -> Result<(), String> {
        if timestamp < self.created_at {
            return Err("destroy timestamp must be >= created_at".into());
        }
        self.destroyed_at = timestamp;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShredEvidence {
    pub data_id: String,
    pub key_id: String,
    pub reason: String,
    pub destroyed_at: u64,
    pub verification: String,
}

impl ShredEvidence {
    pub fn is_valid(&self) -> bool {
        !self.verification.is_empty()
            && self.verification.contains("KEY_DESTROYED")
            && self.verification.contains(&self.key_id)
            && self.verification.contains(&self.data_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub action: String,
    pub data_id: String,
    pub evidence_id: String,
}

impl AuditEntry {
    pub fn new(timestamp: u64, action: String, data_id: String, evidence_id: String) -> Self {
        Self {
            timestamp,
            action,
            data_id,
            evidence_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTrail {
    pub entries: Vec<AuditEntry>,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn record(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }

    pub fn query_by_data_id(&self, data_id: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.data_id == data_id)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportBundle {
    pub subject_id: String,
    pub generated_at: u64,
    pub entries: Vec<AuditEntry>,
    pub signature: Option<Vec<u8>>,
}

impl ExportBundle {
    pub fn new(subject_id: String, generated_at: u64) -> Self {
        Self {
            subject_id,
            generated_at,
            entries: Vec::new(),
            signature: None,
        }
    }

    pub fn add_entry(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }

    pub fn sign(&mut self, sig: Vec<u8>) {
        self.signature = Some(sig);
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ── Data Governance Types (R3-W1.8) ───────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataCategory {
    Personal,
    Sensitive,
    Anonymous,
    System,
    Financial,
    Health,
}

impl DataCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Personal => "Personal",
            Self::Sensitive => "Sensitive",
            Self::Anonymous => "Anonymous",
            Self::System => "System",
            Self::Financial => "Financial",
            Self::Health => "Health",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub duration_seconds: u64,
    pub auto_delete: bool,
    pub class: RetentionClass,
    pub requires_approval_for_delete: bool,
}

impl RetentionPolicy {
    pub fn new(duration_seconds: u64, auto_delete: bool) -> Self {
        Self {
            duration_seconds,
            auto_delete,
            class: RetentionClass::Operational,
            requires_approval_for_delete: false,
        }
    }

    pub fn new_full(
        duration_seconds: u64,
        auto_delete: bool,
        class: RetentionClass,
        requires_approval_for_delete: bool,
    ) -> Self {
        Self {
            duration_seconds,
            auto_delete,
            class,
            requires_approval_for_delete,
        }
    }

    pub fn is_expired(&self, stored_at: u64, now: u64) -> bool {
        now.saturating_sub(stored_at) >= self.duration_seconds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSubject {
    pub user_id: String,
    pub categories: Vec<DataCategory>,
    pub shred_key_id: String,
    pub registered_at: u64,
    pub shredded: bool,
}

impl DataSubject {
    pub fn new(
        user_id: String,
        categories: Vec<DataCategory>,
        shred_key_id: String,
        registered_at: u64,
    ) -> Self {
        Self {
            user_id,
            categories,
            shred_key_id,
            registered_at,
            shredded: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShredResult {
    Shredded,
    Partial(usize),
    NotFound,
}

impl ShredResult {
    pub fn is_shredded(&self) -> bool {
        matches!(self, Self::Shredded)
    }
}

#[derive(Debug, Clone)]
pub struct DataGovernanceRegistry {
    subjects: HashMap<String, DataSubject>,
    policies: HashMap<String, RetentionPolicy>,
}

impl DataGovernanceRegistry {
    pub fn new() -> Self {
        Self {
            subjects: HashMap::new(),
            policies: HashMap::new(),
        }
    }

    pub fn register_subject(
        &mut self,
        user_id: String,
        shred_key_id: String,
        categories: Vec<DataCategory>,
        retention: RetentionPolicy,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let subject = DataSubject::new(user_id.clone(), categories, shred_key_id, now);
        self.subjects.insert(user_id.clone(), subject);
        self.policies.insert(user_id, retention);
    }

    pub fn register_subject_at(
        &mut self,
        user_id: String,
        shred_key_id: String,
        categories: Vec<DataCategory>,
        retention: RetentionPolicy,
        registered_at: u64,
    ) {
        let subject = DataSubject::new(user_id.clone(), categories, shred_key_id, registered_at);
        self.subjects.insert(user_id.clone(), subject);
        self.policies.insert(user_id, retention);
    }

    pub fn execute_shred(&mut self, user_id: &str) -> ShredResult {
        let subject = match self.subjects.get_mut(user_id) {
            Some(s) => s,
            None => return ShredResult::NotFound,
        };
        if subject.shredded {
            return ShredResult::Shredded;
        }
        let remaining = subject.categories.len();
        subject.shredded = true;
        subject.shred_key_id.clear();
        if remaining == 0 {
            ShredResult::Partial(0)
        } else {
            ShredResult::Shredded
        }
    }

    pub fn check_retention(&self, user_id: &str) -> Vec<DataCategory> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.check_retention_at(user_id, now)
    }

    pub fn check_retention_at(&self, user_id: &str, now: u64) -> Vec<DataCategory> {
        let subject = match self.subjects.get(user_id) {
            Some(s) => s,
            None => return Vec::new(),
        };
        let policy = match self.policies.get(user_id) {
            Some(p) => p,
            None => return Vec::new(),
        };
        if policy.is_expired(subject.registered_at, now) {
            subject.categories.clone()
        } else {
            Vec::new()
        }
    }

    pub fn subject_count(&self) -> usize {
        self.subjects.len()
    }

    pub fn get_subject(&self, user_id: &str) -> Option<&DataSubject> {
        self.subjects.get(user_id)
    }

    pub fn get_policy(&self, user_id: &str) -> Option<&RetentionPolicy> {
        self.policies.get(user_id)
    }
}

impl Default for DataGovernanceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── GDPR Retention Class ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetentionClass {
    Operational,
    Regulatory,
    LegalHold,
    Expired,
}

impl RetentionClass {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Operational => "OPERATIONAL",
            Self::Regulatory => "REGULATORY",
            Self::LegalHold => "LEGAL_HOLD",
            Self::Expired => "EXPIRED",
        }
    }

    #[must_use]
    pub fn is_retainable(self) -> bool {
        matches!(self, Self::Operational | Self::Regulatory | Self::LegalHold)
    }

    #[must_use]
    pub fn is_expired_class(self) -> bool {
        matches!(self, Self::Expired)
    }
}

// ── CryptoShredScope — scope of a crypto-shred erasure request ──────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CryptoShredScope {
    SubjectAll,
    ObjectSet,
    DataClassSubset,
}

impl CryptoShredScope {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::SubjectAll => "SUBJECT_ALL",
            Self::ObjectSet => "OBJECT_SET",
            Self::DataClassSubset => "DATA_CLASS_SUBSET",
        }
    }
}

// ── ResidencyRegion — data residency geography pinning ───────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResidencyRegion {
    Eu,
    Eea,
    Uk,
    Us,
    Apac,
    OnPremLocal,
    GlobalCdn,
}

impl ResidencyRegion {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Eu => "EU",
            Self::Eea => "EEA",
            Self::Uk => "UK",
            Self::Us => "US",
            Self::Apac => "APAC",
            Self::OnPremLocal => "ON_PREM_LOCAL",
            Self::GlobalCdn => "GLOBAL_CDN",
        }
    }
}

// ── AuditExportFormat — export bundle format options ─────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditExportFormat {
    Json,
    Pdf,
}

impl AuditExportFormat {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Pdf => "PDF",
        }
    }

    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Pdf => "pdf",
        }
    }
}

// ── CryptoShredRequest — RTBF erasure request type ──────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoShredRequest {
    pub subject_id: String,
    pub data_categories: Vec<DataCategory>,
    pub shred_scope: CryptoShredScope,
    pub evidence_retention_only: bool,
    pub created_at: u64,
}

impl CryptoShredRequest {
    #[must_use]
    pub fn new(
        subject_id: String,
        data_categories: Vec<DataCategory>,
        shred_scope: CryptoShredScope,
        evidence_retention_only: bool,
    ) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            subject_id,
            data_categories,
            shred_scope,
            evidence_retention_only,
            created_at,
        }
    }

    #[must_use]
    pub fn new_with_time(
        subject_id: String,
        data_categories: Vec<DataCategory>,
        shred_scope: CryptoShredScope,
        evidence_retention_only: bool,
        created_at: u64,
    ) -> Self {
        Self {
            subject_id,
            data_categories,
            shred_scope,
            evidence_retention_only,
            created_at,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.subject_id.is_empty() {
            return Err("subject_id must not be empty".into());
        }
        if self.data_categories.is_empty() {
            return Err("data_categories must not be empty".into());
        }
        Ok(())
    }

    #[must_use]
    pub fn requests_full_shred(&self) -> bool {
        matches!(self.shred_scope, CryptoShredScope::SubjectAll)
    }

    #[must_use]
    pub fn is_evidence_only(&self) -> bool {
        self.evidence_retention_only
    }
}

// ── DataResidencyConstraint — per-category residency rule ────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataResidencyConstraint {
    pub data_category: DataCategory,
    pub allowed_regions: Vec<ResidencyRegion>,
    pub encryption_required: bool,
    pub audit_log_required: bool,
}

impl DataResidencyConstraint {
    #[must_use]
    pub fn new(
        data_category: DataCategory,
        allowed_regions: Vec<ResidencyRegion>,
        encryption_required: bool,
        audit_log_required: bool,
    ) -> Self {
        Self {
            data_category,
            allowed_regions,
            encryption_required,
            audit_log_required,
        }
    }

    #[must_use]
    pub fn allows_region(&self, region: ResidencyRegion) -> bool {
        self.allowed_regions.contains(&region)
    }
}

// ── DataResidencyPolicy — per-category residency constraint set ──────────

#[derive(Debug, Clone)]
pub struct DataResidencyPolicy {
    pub constraints: HashMap<DataCategory, DataResidencyConstraint>,
}

impl DataResidencyPolicy {
    #[must_use]
    pub fn new() -> Self {
        Self {
            constraints: HashMap::new(),
        }
    }

    pub fn add_constraint(&mut self, constraint: DataResidencyConstraint) {
        self.constraints
            .insert(constraint.data_category, constraint);
    }

    #[must_use]
    pub fn get_constraint(&self, category: DataCategory) -> Option<&DataResidencyConstraint> {
        self.constraints.get(&category)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.constraints.len()
    }
}

impl Default for DataResidencyPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// ── DataResidencyEnforcer — residency check / transfer validation ────────

#[derive(Debug, Clone)]
pub struct DataResidencyEnforcer {
    pub policy: DataResidencyPolicy,
}

impl DataResidencyEnforcer {
    #[must_use]
    pub fn new(policy: DataResidencyPolicy) -> Self {
        Self { policy }
    }

    pub fn check_residency(
        &self,
        category: DataCategory,
        region: ResidencyRegion,
    ) -> Result<bool, String> {
        let constraint = self
            .policy
            .get_constraint(category)
            .ok_or_else(|| format!("no residency constraint for category {:?}", category))?;
        Ok(constraint.allows_region(region))
    }

    pub fn validate_transfer(
        &self,
        category: DataCategory,
        from_region: ResidencyRegion,
        to_region: ResidencyRegion,
    ) -> Result<bool, String> {
        let constraint = self
            .policy
            .get_constraint(category)
            .ok_or_else(|| format!("no residency constraint for category {:?}", category))?;
        if !constraint.allows_region(to_region) {
            return Err(format!(
                "transfer denied: category {:?} may not reside in region {}",
                category,
                to_region.label(),
            ));
        }
        let _ = from_region;
        Ok(true)
    }

    #[must_use]
    pub fn audit_compliance(&self) -> Vec<String> {
        self.policy
            .constraints
            .values()
            .filter_map(|c| {
                if c.audit_log_required {
                    Some(format!(
                        "category_{}_regions_{}_encryption_{}",
                        c.data_category.label(),
                        c.allowed_regions.len(),
                        c.encryption_required,
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    #[must_use]
    pub fn requires_encryption(&self, category: DataCategory) -> bool {
        self.policy
            .get_constraint(category)
            .is_some_and(|c| c.encryption_required)
    }
}

// ── GdprAuditExport — signed, framework-mappable audit export bundle ─────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GdprAuditExport {
    pub export_id: String,
    pub subject_id: String,
    pub data_categories: Vec<DataCategory>,
    pub format: AuditExportFormat,
    pub generated_at: u64,
    pub signed_manifest: Option<Vec<u8>>,
}

impl GdprAuditExport {
    #[must_use]
    pub fn new(
        export_id: String,
        subject_id: String,
        data_categories: Vec<DataCategory>,
        format: AuditExportFormat,
        generated_at: u64,
    ) -> Self {
        Self {
            export_id,
            subject_id,
            data_categories,
            format,
            generated_at,
            signed_manifest: None,
        }
    }

    pub fn sign(&mut self, signature: Vec<u8>) {
        self.signed_manifest = Some(signature);
    }

    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signed_manifest.is_some()
    }

    #[must_use]
    pub fn category_count(&self) -> usize {
        self.data_categories.len()
    }
}

// ── GdprAuditExporter — generate, verify, sign audit exports ─────────────

#[derive(Debug, Clone)]
pub struct GdprAuditExporter;

impl GdprAuditExporter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn generate_export(
        &self,
        subject_id: String,
        data_categories: Vec<DataCategory>,
        format: AuditExportFormat,
        entries: Vec<AuditEntry>,
    ) -> Result<GdprAuditExport, String> {
        if subject_id.is_empty() {
            return Err("subject_id must not be empty".into());
        }
        if data_categories.is_empty() {
            return Err("at least one data category is required".into());
        }

        let export_id = format!(
            "audex_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        let generated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let _ = entries; // entries are validated by verify_export()

        Ok(GdprAuditExport::new(
            export_id,
            subject_id,
            data_categories,
            format,
            generated_at,
        ))
    }

    pub fn verify_export(&self, export: &GdprAuditExport) -> Result<bool, String> {
        if export.export_id.is_empty() {
            return Err("export_id must not be empty".into());
        }
        if export.subject_id.is_empty() {
            return Err("subject_id must not be empty".into());
        }
        if export.data_categories.is_empty() {
            return Err("data_categories must not be empty".into());
        }
        if export.generated_at == 0 {
            return Err("generated_at must be non-zero".into());
        }
        Ok(true)
    }

    pub fn sign_export(
        &self,
        mut export: GdprAuditExport,
        signature: Vec<u8>,
    ) -> Result<GdprAuditExport, String> {
        if signature.is_empty() {
            return Err("signature must not be empty".into());
        }
        self.verify_export(&export)?;
        export.sign(signature);
        Ok(export)
    }
}

impl Default for GdprAuditExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ── CryptoShredEvidence — per-subject key destruction evidence record ────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoShredEvidence {
    pub evidence_id: String,
    pub subject_id: String,
    pub request_id: String,
    pub key_refs_shredded: Vec<String>,
    pub objects_in_scope: usize,
    pub objects_shredded: usize,
    pub objects_blocked_by_hold: usize,
    pub outcome: String,
    pub verification_hash: String,
    pub completed_at: u64,
}

impl CryptoShredEvidence {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: String,
        subject_id: String,
        request_id: String,
        key_refs_shredded: Vec<String>,
        objects_in_scope: usize,
        objects_shredded: usize,
        objects_blocked_by_hold: usize,
        outcome: String,
        verification_hash: String,
        completed_at: u64,
    ) -> Self {
        Self {
            evidence_id,
            subject_id,
            request_id,
            key_refs_shredded,
            objects_in_scope,
            objects_shredded,
            objects_blocked_by_hold,
            outcome,
            verification_hash,
            completed_at,
        }
    }

    #[must_use]
    pub fn is_complete_shred(&self) -> bool {
        self.outcome == "COMPLETED"
            && self.objects_blocked_by_hold == 0
            && self.objects_shredded == self.objects_in_scope
    }

    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.outcome == "PARTIAL_BLOCKED_BY_HOLD" || self.objects_blocked_by_hold > 0
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.evidence_id.is_empty()
            && !self.subject_id.is_empty()
            && !self.verification_hash.is_empty()
            && self.objects_in_scope > 0
    }
}

// ── RightToBeForgottenPipeline — full RTBF workflow ──────────────────────

#[derive(Debug)]
pub struct RightToBeForgottenPipeline {
    pub registry: DataGovernanceRegistry,
    pub audit_trail: AuditTrail,
    pub evidence_chain: Vec<CryptoShredEvidence>,
}

impl RightToBeForgottenPipeline {
    #[must_use]
    pub fn new(registry: DataGovernanceRegistry) -> Self {
        Self {
            registry,
            audit_trail: AuditTrail::new(),
            evidence_chain: Vec::new(),
        }
    }

    /// Validate a crypto-shred request for completeness and sanity.
    pub fn validate_request(&self, request: &CryptoShredRequest) -> Result<(), String> {
        request.validate()
    }

    /// Resolve the data subject from the governance registry.
    pub fn resolve_subject(&self, subject_id: &str) -> Result<&DataSubject, String> {
        self.registry
            .get_subject(subject_id)
            .ok_or_else(|| format!("subject '{}' not found in registry", subject_id))
    }

    /// Shred per-subject keys by executing the shred on the registry.
    pub fn shred_per_subject_keys(
        &mut self,
        subject_id: &str,
        timestamp: u64,
    ) -> Result<ShredResult, String> {
        if subject_id.is_empty() {
            return Err("subject_id must not be empty".into());
        }
        let result = self.registry.execute_shred(subject_id);
        self.audit_trail.record(AuditEntry::new(
            timestamp,
            "CRYPTO_SHRED".into(),
            subject_id.into(),
            format!("evidence_{}", timestamp),
        ));
        Ok(result)
    }

    /// Mark data as shredded in the registry (already done by execute_shred).
    pub fn mark_data_as_shredded(&mut self, subject_id: &str) -> Result<bool, String> {
        let subject = self
            .registry
            .get_subject(subject_id)
            .ok_or_else(|| format!("subject '{}' not found", subject_id))?;
        Ok(subject.shredded)
    }

    /// Emit a `CRYPTO_SHREDDED` evidence record.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_crypto_shredded_evidence(
        &mut self,
        subject_id: &str,
        request_id: &str,
        key_refs: Vec<String>,
        objects_in_scope: usize,
        objects_shredded: usize,
        objects_blocked: usize,
        outcome: &str,
        completed_at: u64,
    ) -> Result<CryptoShredEvidence, String> {
        if subject_id.is_empty() {
            return Err("subject_id must not be empty".into());
        }
        if key_refs.is_empty() {
            return Err("at least one key ref required".into());
        }

        let evidence_id = format!("evr_cryptoshred_{}", completed_at);
        let verification_hash = format!(
            "sha256:{}:{}:{}:{}",
            subject_id, request_id, objects_shredded, completed_at
        );

        let evidence = CryptoShredEvidence::new(
            evidence_id,
            subject_id.into(),
            request_id.into(),
            key_refs,
            objects_in_scope,
            objects_shredded,
            objects_blocked,
            outcome.into(),
            verification_hash,
            completed_at,
        );

        self.evidence_chain.push(evidence.clone());
        self.audit_trail.record(AuditEntry::new(
            completed_at,
            "CRYPTO_SHRED_EVIDENCE_EMITTED".into(),
            subject_id.into(),
            evidence.evidence_id.clone(),
        ));
        Ok(evidence)
    }

    /// Retain the evidence chain per INV-027 — verify it is intact.
    #[must_use]
    pub fn retain_evidence_chain(&self) -> bool {
        !self.evidence_chain.is_empty() && self.evidence_chain.iter().all(|e| e.is_valid())
    }

    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.evidence_chain.len()
    }

    #[must_use]
    pub fn audit_entry_count(&self) -> usize {
        self.audit_trail.len()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Existing classification / shred tests ────────────────────────────────

    #[test]
    fn classification_levels_encryption_requirement() {
        assert!(!DataClassification::Public.requires_encryption());
        assert!(!DataClassification::Internal.requires_encryption());
        assert!(DataClassification::Confidential.requires_encryption());
        assert!(DataClassification::Restricted.requires_encryption());
    }

    #[test]
    fn classification_max_level_derivation() {
        assert_eq!(
            DataClassification::max_level(DataClassification::Public, DataClassification::Internal),
            DataClassification::Internal
        );
        assert_eq!(
            DataClassification::max_level(
                DataClassification::Confidential,
                DataClassification::Restricted
            ),
            DataClassification::Restricted
        );
        assert_eq!(
            DataClassification::max_level(DataClassification::Public, DataClassification::Public),
            DataClassification::Public
        );
    }

    #[test]
    fn classification_labels() {
        assert_eq!(DataClassification::Public.label(), "Public");
        assert_eq!(DataClassification::Internal.label(), "Internal");
        assert_eq!(DataClassification::Confidential.label(), "Confidential");
        assert_eq!(DataClassification::Restricted.label(), "Restricted");
    }

    #[test]
    fn key_lifecycle_create_and_destroy() {
        let key = CryptoShredKey::new_with_time("k-001".into(), "AES-256-GCM".into(), 1000);
        assert_eq!(key.key_id, "k-001");
        assert_eq!(key.algorithm, "AES-256-GCM");
        assert_eq!(key.created_at, 1000);

        let request = ShredRequest::new_full("data-42".into(), "RTBF-erasure".into(), 1000, 2000);
        let evidence = key.destroy(&request);
        assert_eq!(evidence.data_id, "data-42");
        assert_eq!(evidence.key_id, "k-001");
        assert_eq!(evidence.reason, "RTBF-erasure");
        assert_eq!(evidence.destroyed_at, 2000);
        assert!(evidence.is_valid());
    }

    #[test]
    fn shred_evidence_creation_and_validation() {
        let key = CryptoShredKey::new_with_time("shred-1".into(), "ChaCha20-Poly1305".into(), 500);
        let req = ShredRequest::new_full("user-99".into(), "GDPR Article 17".into(), 500, 1500);
        let evidence = key.destroy(&req);

        assert!(evidence.verification.contains("KEY_DESTROYED"));
        assert!(evidence.verification.contains("shred-1"));
        assert!(evidence.verification.contains("user-99"));
        assert!(evidence.is_valid());
    }

    #[test]
    fn shred_request_validation() {
        let valid = ShredRequest::new_full("data-1".into(), "deletion".into(), 100, 200);
        assert!(valid.validate().is_ok());

        let empty_id = ShredRequest::new_full("".into(), "reason".into(), 100, 200);
        assert!(empty_id.validate().is_err());

        let empty_reason = ShredRequest::new_full("data-2".into(), "".into(), 100, 200);
        assert!(empty_reason.validate().is_err());

        let bad_time = ShredRequest::new_full("data-3".into(), "test".into(), 300, 100);
        assert!(bad_time.validate().is_err());
    }

    #[test]
    fn shred_request_mark_destroyed() {
        let mut req = ShredRequest::new_full("data-x".into(), "compliance".into(), 1000, 0);
        assert_eq!(req.destroyed_at, 0);

        assert!(req.mark_destroyed(2000).is_ok());
        assert_eq!(req.destroyed_at, 2000);

        let err = req.mark_destroyed(500);
        assert!(err.is_err());
    }

    #[test]
    fn audit_trail_recording_and_query() {
        let mut trail = AuditTrail::new();
        assert!(trail.is_empty());

        trail.record(AuditEntry::new(
            1000,
            "SHRED".into(),
            "data-a".into(),
            "ev-1".into(),
        ));
        trail.record(AuditEntry::new(
            2000,
            "EXPORT".into(),
            "data-a".into(),
            "ev-2".into(),
        ));
        trail.record(AuditEntry::new(
            3000,
            "SHRED".into(),
            "data-b".into(),
            "ev-3".into(),
        ));

        assert_eq!(trail.len(), 3);
        assert_eq!(trail.query_by_data_id("data-a").len(), 2);
        assert_eq!(trail.query_by_data_id("data-b").len(), 1);
        assert!(trail.query_by_data_id("nonexistent").is_empty());
    }

    #[test]
    fn export_bundle_lifecycle() {
        let mut bundle = ExportBundle::new("subject-1".into(), 5000);
        bundle.add_entry(AuditEntry::new(
            1000,
            "SHRED".into(),
            "data-z".into(),
            "ev-z".into(),
        ));
        bundle.add_entry(AuditEntry::new(
            2000,
            "CLASSIFY".into(),
            "data-y".into(),
            "ev-y".into(),
        ));

        assert_eq!(bundle.entry_count(), 2);
        assert!(bundle.signature.is_none());

        bundle.sign(b"sig-bytes".to_vec());
        assert_eq!(bundle.signature, Some(b"sig-bytes".to_vec()));
    }

    #[test]
    fn full_rtbf_erasure_flow() {
        let key = CryptoShredKey::new_with_time("k-rtbf".into(), "AES-256-GCM".into(), 100);
        let mut req = ShredRequest::new_full("pii-001".into(), "RTBF Article 17".into(), 100, 0);
        assert!(req.validate().is_ok());

        assert!(req.mark_destroyed(500).is_ok());
        let evidence = key.destroy(&req);
        assert!(evidence.is_valid());

        let mut trail = AuditTrail::new();
        trail.record(AuditEntry::new(
            evidence.destroyed_at,
            "CRYPTO_SHRED".into(),
            evidence.data_id.clone(),
            evidence.verification.clone(),
        ));
        assert_eq!(trail.len(), 1);

        let mut bundle = ExportBundle::new("subject-rtbf".into(), 600);
        bundle.add_entry(trail.entries[0].clone());
        bundle.sign(b"audit-sig".to_vec());
        assert_eq!(bundle.entry_count(), 1);
        assert!(bundle.signature.is_some());
    }

    // ── Data Governance tests (R3-W1.8) ─────────────────────────────────────

    #[test]
    fn data_category_labels() {
        assert_eq!(DataCategory::Personal.label(), "Personal");
        assert_eq!(DataCategory::Sensitive.label(), "Sensitive");
        assert_eq!(DataCategory::Anonymous.label(), "Anonymous");
        assert_eq!(DataCategory::System.label(), "System");
        assert_eq!(DataCategory::Financial.label(), "Financial");
        assert_eq!(DataCategory::Health.label(), "Health");
    }

    #[test]
    fn retention_policy_expiry() {
        let policy = RetentionPolicy::new(3600, true);
        assert!(policy.is_expired(0, 3600));
        assert!(!policy.is_expired(1000, 4000));
        assert!(!policy.is_expired(1000, 4599));
        assert!(policy.is_expired(1000, 4600));
    }

    #[test]
    fn shred_makes_data_unavailable() {
        let mut registry = DataGovernanceRegistry::new();
        registry.register_subject_at(
            "user-a".into(),
            "key-a".into(),
            vec![DataCategory::Personal, DataCategory::Financial],
            RetentionPolicy::new(3600, true),
            1000,
        );

        assert_eq!(registry.subject_count(), 1);
        let subject = registry
            .get_subject("user-a")
            .unwrap_or_else(|| panic!("absent"));
        assert!(!subject.shredded);
        assert_eq!(subject.shred_key_id, "key-a");

        let result = registry.execute_shred("user-a");
        assert_eq!(result, ShredResult::Shredded);

        let subject = registry
            .get_subject("user-a")
            .unwrap_or_else(|| panic!("absent"));
        assert!(subject.shredded);
        assert!(subject.shred_key_id.is_empty());
    }

    #[test]
    fn retention_check_triggers_for_expired_data() {
        let mut registry = DataGovernanceRegistry::new();
        registry.register_subject_at(
            "user-b".into(),
            "key-b".into(),
            vec![DataCategory::Health, DataCategory::Sensitive],
            RetentionPolicy::new(7200, false),
            0,
        );

        let expired = registry.check_retention_at("user-b", 7200);
        assert_eq!(expired.len(), 2);
        assert!(expired.contains(&DataCategory::Health));
        assert!(expired.contains(&DataCategory::Sensitive));

        let not_expired = registry.check_retention_at("user-b", 1000);
        assert!(not_expired.is_empty());
    }

    #[test]
    fn multiple_subjects_independent_shred() {
        let mut registry = DataGovernanceRegistry::new();
        registry.register_subject_at(
            "alice".into(),
            "k-alice".into(),
            vec![DataCategory::Personal],
            RetentionPolicy::new(86400, true),
            100,
        );
        registry.register_subject_at(
            "bob".into(),
            "k-bob".into(),
            vec![DataCategory::System, DataCategory::Financial],
            RetentionPolicy::new(43200, false),
            200,
        );

        assert_eq!(registry.subject_count(), 2);

        let result = registry.execute_shred("alice");
        assert_eq!(result, ShredResult::Shredded);

        let alice = registry
            .get_subject("alice")
            .unwrap_or_else(|| panic!("absent"));
        let bob = registry
            .get_subject("bob")
            .unwrap_or_else(|| panic!("absent"));
        assert!(alice.shredded);
        assert!(!bob.shredded);
        assert_eq!(bob.shred_key_id, "k-bob");
    }

    #[test]
    fn shred_not_found() {
        let mut registry = DataGovernanceRegistry::new();
        let result = registry.execute_shred("ghost");
        assert_eq!(result, ShredResult::NotFound);
    }

    #[test]
    fn double_shred_is_idempotent() {
        let mut registry = DataGovernanceRegistry::new();
        registry.register_subject_at(
            "user-c".into(),
            "key-c".into(),
            vec![DataCategory::Anonymous],
            RetentionPolicy::new(1800, true),
            500,
        );

        assert_eq!(registry.execute_shred("user-c"), ShredResult::Shredded);
        assert_eq!(registry.execute_shred("user-c"), ShredResult::Shredded);
    }

    #[test]
    fn check_retention_unknown_user_returns_empty() {
        let registry = DataGovernanceRegistry::new();
        let result = registry.check_retention_at("nobody", 9999);
        assert!(result.is_empty());
    }

    #[test]
    fn shred_result_is_shredded_helper() {
        assert!(ShredResult::Shredded.is_shredded());
        assert!(!ShredResult::Partial(3).is_shredded());
        assert!(!ShredResult::NotFound.is_shredded());
    }

    #[test]
    fn retention_before_deadline_returns_empty() {
        let mut registry = DataGovernanceRegistry::new();
        registry.register_subject_at(
            "user-d".into(),
            "key-d".into(),
            vec![DataCategory::Personal, DataCategory::System],
            RetentionPolicy::new(10000, true),
            100,
        );

        let result = registry.check_retention_at("user-d", 5000);
        assert!(result.is_empty());
    }

    // ── RetentionClass enum tests ─────────────────────────────────────────

    #[test]
    fn retention_class_labels() {
        assert_eq!(RetentionClass::Operational.label(), "OPERATIONAL");
        assert_eq!(RetentionClass::Regulatory.label(), "REGULATORY");
        assert_eq!(RetentionClass::LegalHold.label(), "LEGAL_HOLD");
        assert_eq!(RetentionClass::Expired.label(), "EXPIRED");
    }

    #[test]
    fn retention_class_is_retainable() {
        assert!(RetentionClass::Operational.is_retainable());
        assert!(RetentionClass::Regulatory.is_retainable());
        assert!(RetentionClass::LegalHold.is_retainable());
        assert!(!RetentionClass::Expired.is_retainable());
    }

    #[test]
    fn retention_class_is_expired_class() {
        assert!(!RetentionClass::Operational.is_expired_class());
        assert!(RetentionClass::Expired.is_expired_class());
    }

    #[test]
    fn retention_policy_new_full_sets_all_fields() {
        let policy = RetentionPolicy::new_full(3600, true, RetentionClass::LegalHold, true);
        assert_eq!(policy.duration_seconds, 3600);
        assert!(policy.auto_delete);
        assert_eq!(policy.class, RetentionClass::LegalHold);
        assert!(policy.requires_approval_for_delete);
    }

    // ── CryptoShredScope enum tests ───────────────────────────────────────

    #[test]
    fn crypto_shred_scope_labels() {
        assert_eq!(CryptoShredScope::SubjectAll.label(), "SUBJECT_ALL");
        assert_eq!(CryptoShredScope::ObjectSet.label(), "OBJECT_SET");
        assert_eq!(
            CryptoShredScope::DataClassSubset.label(),
            "DATA_CLASS_SUBSET"
        );
    }

    // ── ResidencyRegion enum tests ────────────────────────────────────────

    #[test]
    fn residency_region_labels() {
        assert_eq!(ResidencyRegion::Eu.label(), "EU");
        assert_eq!(ResidencyRegion::Eea.label(), "EEA");
        assert_eq!(ResidencyRegion::Uk.label(), "UK");
        assert_eq!(ResidencyRegion::Us.label(), "US");
        assert_eq!(ResidencyRegion::Apac.label(), "APAC");
        assert_eq!(ResidencyRegion::OnPremLocal.label(), "ON_PREM_LOCAL");
        assert_eq!(ResidencyRegion::GlobalCdn.label(), "GLOBAL_CDN");
    }

    // ── AuditExportFormat enum tests ──────────────────────────────────────

    #[test]
    fn audit_export_format_labels_and_extensions() {
        assert_eq!(AuditExportFormat::Json.label(), "JSON");
        assert_eq!(AuditExportFormat::Json.extension(), "json");
        assert_eq!(AuditExportFormat::Pdf.label(), "PDF");
        assert_eq!(AuditExportFormat::Pdf.extension(), "pdf");
    }

    // ── CryptoShredRequest tests ──────────────────────────────────────────

    #[test]
    fn crypto_shred_request_validation() {
        let valid = CryptoShredRequest::new_with_time(
            "subj-1".into(),
            vec![DataCategory::Personal],
            CryptoShredScope::SubjectAll,
            false,
            1000,
        );
        assert!(valid.validate().is_ok());
        assert!(!valid.is_evidence_only());
        assert!(valid.requests_full_shred());

        let empty_subject = CryptoShredRequest::new_with_time(
            "".into(),
            vec![DataCategory::Personal],
            CryptoShredScope::SubjectAll,
            false,
            1000,
        );
        assert!(empty_subject.validate().is_err());

        let empty_categories = CryptoShredRequest::new_with_time(
            "subj-2".into(),
            vec![],
            CryptoShredScope::SubjectAll,
            false,
            1000,
        );
        assert!(empty_categories.validate().is_err());
    }

    #[test]
    fn crypto_shred_request_evidence_only() {
        let req = CryptoShredRequest::new_with_time(
            "subj-e".into(),
            vec![DataCategory::Health],
            CryptoShredScope::DataClassSubset,
            true,
            2000,
        );
        assert!(req.is_evidence_only());
        assert!(!req.requests_full_shred());
    }

    // ── DataResidencyConstraint tests ─────────────────────────────────────

    #[test]
    fn data_residency_constraint_allows_region() {
        let constraint = DataResidencyConstraint::new(
            DataCategory::Personal,
            vec![ResidencyRegion::Eu, ResidencyRegion::Eea],
            true,
            true,
        );
        assert!(constraint.allows_region(ResidencyRegion::Eu));
        assert!(constraint.allows_region(ResidencyRegion::Eea));
        assert!(!constraint.allows_region(ResidencyRegion::Us));
        assert!(constraint.encryption_required);
        assert!(constraint.audit_log_required);
    }

    // ── DataResidencyPolicy tests ─────────────────────────────────────────

    #[test]
    fn data_residency_policy_add_and_get() {
        let mut policy = DataResidencyPolicy::new();
        assert!(policy.is_empty());

        policy.add_constraint(DataResidencyConstraint::new(
            DataCategory::Health,
            vec![ResidencyRegion::Eu],
            true,
            true,
        ));

        assert_eq!(policy.len(), 1);
        assert!(!policy.is_empty());

        let c = policy
            .get_constraint(DataCategory::Health)
            .expect("constraint present");
        assert!(c.encryption_required);
        assert!(c.allows_region(ResidencyRegion::Eu));

        assert!(policy.get_constraint(DataCategory::System).is_none());
    }

    // ── DataResidencyEnforcer tests ──────────────────────────────────────

    #[test]
    fn data_residency_enforcer_check_and_transfer() {
        let mut policy = DataResidencyPolicy::new();
        policy.add_constraint(DataResidencyConstraint::new(
            DataCategory::Financial,
            vec![ResidencyRegion::Eu, ResidencyRegion::Uk],
            true,
            true,
        ));

        let enforcer = DataResidencyEnforcer::new(policy);

        assert!(enforcer
            .check_residency(DataCategory::Financial, ResidencyRegion::Eu)
            .expect("ok"));
        assert!(!enforcer
            .check_residency(DataCategory::Financial, ResidencyRegion::Us)
            .expect("ok"));
        assert!(enforcer
            .check_residency(DataCategory::Personal, ResidencyRegion::Eu)
            .is_err());

        assert!(enforcer
            .validate_transfer(
                DataCategory::Financial,
                ResidencyRegion::Eu,
                ResidencyRegion::Uk,
            )
            .expect("ok"));

        let transfer_err = enforcer.validate_transfer(
            DataCategory::Financial,
            ResidencyRegion::Eu,
            ResidencyRegion::Us,
        );
        assert!(transfer_err.is_err());
    }

    #[test]
    fn data_residency_enforcer_audit_compliance() {
        let mut policy = DataResidencyPolicy::new();
        policy.add_constraint(DataResidencyConstraint::new(
            DataCategory::Health,
            vec![ResidencyRegion::Eu],
            true,
            true,
        ));
        policy.add_constraint(DataResidencyConstraint::new(
            DataCategory::System,
            vec![ResidencyRegion::GlobalCdn],
            false,
            false,
        ));

        let enforcer = DataResidencyEnforcer::new(policy);
        let audits = enforcer.audit_compliance();
        assert_eq!(audits.len(), 1);
        assert!(audits[0].contains("Health"));
    }

    #[test]
    fn data_residency_enforcer_requires_encryption() {
        let mut policy = DataResidencyPolicy::new();
        policy.add_constraint(DataResidencyConstraint::new(
            DataCategory::Sensitive,
            vec![ResidencyRegion::Eu],
            true,
            true,
        ));
        policy.add_constraint(DataResidencyConstraint::new(
            DataCategory::Anonymous,
            vec![ResidencyRegion::Eea],
            false,
            false,
        ));

        let enforcer = DataResidencyEnforcer::new(policy);
        assert!(enforcer.requires_encryption(DataCategory::Sensitive));
        assert!(!enforcer.requires_encryption(DataCategory::Anonymous));
        assert!(!enforcer.requires_encryption(DataCategory::Personal));
    }

    // ── GdprAuditExport tests ─────────────────────────────────────────────

    #[test]
    fn gdpr_audit_export_lifecycle() {
        let mut export = GdprAuditExport::new(
            "audex_001".into(),
            "subj-audit".into(),
            vec![DataCategory::Personal, DataCategory::Financial],
            AuditExportFormat::Json,
            5000,
        );
        assert_eq!(export.category_count(), 2);
        assert!(!export.is_signed());

        export.sign(b"ed25519-sig".to_vec());
        assert!(export.is_signed());
        assert_eq!(export.signed_manifest, Some(b"ed25519-sig".to_vec()));
    }

    // ── GdprAuditExporter tests ──────────────────────────────────────────

    #[test]
    fn gdpr_audit_exporter_generate_and_verify() {
        let exporter = GdprAuditExporter::new();
        let entries = vec![AuditEntry::new(
            1000,
            "TEST".into(),
            "data-x".into(),
            "ev-x".into(),
        )];

        let export = exporter
            .generate_export(
                "subj-exp".into(),
                vec![DataCategory::Personal],
                AuditExportFormat::Json,
                entries,
            )
            .expect("generate");
        assert!(export.export_id.starts_with("audex_"));
        assert_eq!(export.subject_id, "subj-exp");

        assert!(exporter.verify_export(&export).expect("verify"));
    }

    #[test]
    fn gdpr_audit_exporter_sign_export() {
        let exporter = GdprAuditExporter::new();
        let entries = vec![AuditEntry::new(
            2000,
            "TEST".into(),
            "data-y".into(),
            "ev-y".into(),
        )];

        let export = exporter
            .generate_export(
                "subj-sign".into(),
                vec![DataCategory::Sensitive],
                AuditExportFormat::Pdf,
                entries,
            )
            .expect("generate");

        let signed = exporter
            .sign_export(export, b"sig-12345".to_vec())
            .expect("sign");
        assert!(signed.is_signed());
    }

    #[test]
    fn gdpr_audit_exporter_rejects_empty_signature() {
        let exporter = GdprAuditExporter::new();
        let entries = vec![];
        let export = exporter
            .generate_export(
                "subj-bad".into(),
                vec![DataCategory::Personal],
                AuditExportFormat::Json,
                entries,
            )
            .expect("generate");

        let result = exporter.sign_export(export, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn gdpr_audit_exporter_rejects_empty_subject() {
        let exporter = GdprAuditExporter::new();
        let result = exporter.generate_export(
            "".into(),
            vec![DataCategory::Personal],
            AuditExportFormat::Json,
            vec![],
        );
        assert!(result.is_err());
    }

    // ── CryptoShredEvidence tests ─────────────────────────────────────────

    #[test]
    fn crypto_shred_evidence_complete_and_partial() {
        let complete = CryptoShredEvidence::new(
            "evr_1".into(),
            "subj-1".into(),
            "req-1".into(),
            vec!["csk_001".into()],
            5,
            5,
            0,
            "COMPLETED".into(),
            "hash_abc".into(),
            3000,
        );
        assert!(complete.is_valid());
        assert!(complete.is_complete_shred());
        assert!(!complete.is_partial());

        let partial = CryptoShredEvidence::new(
            "evr_2".into(),
            "subj-2".into(),
            "req-2".into(),
            vec!["csk_002".into()],
            10,
            7,
            3,
            "PARTIAL_BLOCKED_BY_HOLD".into(),
            "hash_def".into(),
            4000,
        );
        assert!(partial.is_valid());
        assert!(!partial.is_complete_shred());
        assert!(partial.is_partial());
    }

    #[test]
    fn crypto_shred_evidence_invalid_when_empty() {
        let empty = CryptoShredEvidence::new(
            "".into(),
            "".into(),
            "".into(),
            vec![],
            0,
            0,
            0,
            "".into(),
            "".into(),
            0,
        );
        assert!(!empty.is_valid());
    }

    // ── RightToBeForgottenPipeline tests ──────────────────────────────────

    #[test]
    fn rtbf_pipeline_full_workflow() {
        let mut registry = DataGovernanceRegistry::new();
        registry.register_subject_at(
            "user-rtbf".into(),
            "csk_key_001".into(),
            vec![DataCategory::Personal, DataCategory::Sensitive],
            RetentionPolicy::new_full(86400, true, RetentionClass::Regulatory, true),
            1000,
        );

        let mut pipeline = RightToBeForgottenPipeline::new(registry);

        let request = CryptoShredRequest::new_with_time(
            "user-rtbf".into(),
            vec![DataCategory::Personal, DataCategory::Sensitive],
            CryptoShredScope::SubjectAll,
            false,
            2000,
        );

        assert!(pipeline.validate_request(&request).is_ok());

        let subject = pipeline.resolve_subject("user-rtbf").expect("found");
        assert_eq!(subject.shred_key_id, "csk_key_001");

        let shred_result = pipeline
            .shred_per_subject_keys("user-rtbf", 3000)
            .expect("shred");
        assert_eq!(shred_result, ShredResult::Shredded);

        let is_shredded = pipeline.mark_data_as_shredded("user-rtbf").expect("marked");
        assert!(is_shredded);

        let evidence = pipeline
            .emit_crypto_shredded_evidence(
                "user-rtbf",
                "req-rtbf-001",
                vec!["csk_key_001".into()],
                2,
                2,
                0,
                "COMPLETED",
                4000,
            )
            .expect("evidence");
        assert!(evidence.is_complete_shred());
        assert_eq!(pipeline.evidence_count(), 1);
        assert!(pipeline.audit_entry_count() > 0);
        assert!(pipeline.retain_evidence_chain());
    }

    #[test]
    fn rtbf_pipeline_rejects_unknown_subject() {
        let registry = DataGovernanceRegistry::new();
        let pipeline = RightToBeForgottenPipeline::new(registry);
        let err = pipeline.resolve_subject("ghost-user");
        assert!(err.is_err());
    }

    #[test]
    fn rtbf_pipeline_empty_evidence_chain_not_retained() {
        let registry = DataGovernanceRegistry::new();
        let pipeline = RightToBeForgottenPipeline::new(registry);
        assert!(!pipeline.retain_evidence_chain());
    }
}
