//! `aios-backup` — S26 Backup, Disaster Recovery, and Capsule Mobility.
//!
//! Constitutional invariants encoded here:
//! - INV-033: encrypt_at_source is ALWAYS true
//! - INV-033: at least one OFF_HOST target per contract
//! - AI may NEVER execute DR scenarios
//! - Crypto-shred only from Sealed state

#![forbid(unsafe_code)]

pub mod backup_set;
pub mod capsule_mobility;
pub mod contract;
pub mod crypto_shred;
pub mod dr_runbook;
pub mod enums;
pub mod restore_plan;

pub use backup_set::BackupSet;
pub use capsule_mobility::{CapsuleExport, CapsuleImport};
pub use contract::ConstitutionalBackupContract;
pub use crypto_shred::crypto_shred_backup_set;
pub use dr_runbook::DrRunbook;
pub use enums::{BackupSetState, CapsuleImportDecision, DrScenario, KeyCustody, RestoreMode};
pub use restore_plan::RestorePlan;
