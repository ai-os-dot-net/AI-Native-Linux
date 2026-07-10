//! L10 System Integration Layer for AIOS (S11.4).
//!
//! Typed core skeleton: closed vocabularies + error enum + identifier types.
//! Vendor registry, standards subscriptions, CVE shape, system composition,
//! orchestrator binary, gRPC, evidence, cross-crate land in later tasks.
#![allow(clippy::too_long_first_doc_paragraph)]
/// External bridge contracts (Flathub/OCI/apt/dnf/pacman).
pub mod bridges;
/// System composition graph types (S11.4 §2 I5).
pub mod composition;
/// Composition engine: validation, topological ordering, default wiring (S11.4 §2 I5).
pub mod composition_engine;
/// AIOS-invariant ↔ external control framework mapping with baseline snapshots.
pub mod control_map;
/// CVE severity, status, and identifier types.
pub mod cve;
/// CVE feed integration shape — typed framework for CVE ingestion and package binding.
pub mod cve_feed;
/// Integration-layer structured error catalogue.
pub mod error;
/// L10 Integration Evidence Emitter — typed lifecycle event emission into the
/// append-only Evidence Log (S11.4 ↔ S3.1).
pub mod evidence;
/// External repository bridges (Flathub, Snap Store, Docker Hub, AUR, etc.).
pub mod external_repos;
/// System integration test harness (M18 T-185) — wires all 9 L10 subsystems
/// behind a shared in-memory evidence emitter for acceptance-grade E2E tests.
pub mod harness;
/// Identifier newtypes for integration resources.
pub mod ids;
/// 6-state integration lifecycle FSM (S11.4 §2 I1).
pub mod lifecycle;
/// Marketplace API integration bridge — capsule discovery, install, sync, feeds,
/// billing plans, and license verification (S11.4 §3).
pub mod marketplace_bridge;
/// Service composition orchestrator — typed scaffold for the boot sequence.
pub mod orchestrator;
/// Unified Record Catalogue — canonical index of every `RecordType` the AIOS
/// evidence system can emit, keyed by wire name with ownership metadata.
pub mod record_catalogue;
/// gRPC IntegrationService surface — tonic server/client stubs, conversions, server adapter.
pub mod service;
/// Compliance standard taxonomy and subscription types.
pub mod standard;
/// Compliance standard subscription registry (S11.4 §2 I4).
pub mod standard_registry;
/// Vendor contract types (S11.4 §2 I2).
pub mod vendor;
/// Ed25519-signed vendor contract registry (S11.4 §2 I2).
pub mod vendor_registry;

pub use bridges::{
    default_apt_contract, default_dnf_contract, default_flathub_contract, default_oci_contract,
    default_pacman_contract, BridgeContract, BridgeKind, CapabilityExtractorRule,
    ExternalBridgeRegistry, ManifestTranslationRules,
};
pub use composition::{ComposedService, ServiceComposition, ServiceDependency};
pub use composition_engine::{
    compute_topological_order, default_aios_composition, CompositionEngine,
};
pub use control_map::{
    AiosInvariant, ComplianceBaseline, ControlDriftReport, ControlFrameworkRef, ControlMapRegistry,
    ControlMapping,
};
pub use cve::{CveId, CveSeverity, CveStatus};
pub use cve_feed::{
    cvss_to_enforcement, is_valid_cve_id, CveEnforcementLevel, CveFeedShape, CveRecord,
    PackageCveBinding,
};
pub use error::{IntegrationError, IntegrationErrorCode};
pub use evidence::{
    EvidenceReceipt, InMemoryIntegrationEvidenceEmitter, IntegrationEvidenceEmitter,
    IntegrationRecordType, WithIntegrationEmitter,
};
pub use harness::SystemIntegrationHarness;
pub use ids::{
    ComposedSystemId, ExternalRepoBridgeId, IntegrationId, StandardSubscriptionId, VendorContractId,
};
pub use lifecycle::{IntegrationLifecycleLabel, IntegrationLifecycleState};
pub use orchestrator::{Orchestrator, ServiceHealthSummary, ServiceScaffoldStatus};
pub use record_catalogue::{
    default_index_entries, CatalogueEntry, RecordTypeOwnership, UnifiedRecordCatalogue,
};
pub use standard::{StandardKind, StandardSubscription};
pub use standard_registry::{
    standard_kind_to_canonical_url, ExternalStandardRegistry, StandardReviewRecord,
    SubscriptionStatus,
};
pub use vendor::{VendorIntegrationContract, VendorKind, VendorTrustClass};
pub use vendor_registry::VendorIntegrationRegistry;

pub use external_repos::{
    permitted_repo_kinds, repo_kind_permitted, ExternalPackage, ExternalRepoBridge,
    ExternalRepoKind, ExternalRepoRegistry, RepoHealthCheck, RepoSyncState, SecurityProfile,
};
pub use marketplace_bridge::{
    BillingPlan, CapsuleDetail, CapsuleDiscoveryService, FeedKind, FeedSubscription,
    InstallFromMarketplace, InstallOutcome, LicenseVerification, MarketplaceIntegration,
    MarketplaceListing, MarketplaceSync, SyncOutcome, UpdatePolicy,
};

/// Crate version marker used by closure-invariant tests in T-186.
pub const DEFAULT_CODE_VERSION: &str = "aios-integration/0.1.0-T186";
