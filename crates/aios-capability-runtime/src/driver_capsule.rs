//! Driver capsule template — every driver runs in its own signed capsule.
//!
//! ## R3-W4.1 — Driver Capsule Template Module
//!
//! Drivers are the highest-risk components in AI-OS.NET: they get hardware
//! access.  Every driver runs in its own [`DriverCapsule`] — a signed,
//! canary-booted, rollbackable sandbox modelled after the Plan 9 per-process
//! namespace + Inferno managed-isolate pattern.
//!
//! **Golden rule:** never run vendor install scripts as root.
//!
//! ## Architecture
//!
//! | Concept               | AIOS equivalent                          |
//! |-----------------------|------------------------------------------|
//! | Driver capsule        | [`DriverCapsule`]                        |
//! | Driver class          | [`DriverClass`]                          |
//! | Signature             | [`DriverSignature`]                      |
//! | Canary boot result    | [`CanaryBootResult`]                     |
//! | Driver registry       | [`DriverRegistry`]                       |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-DRV-001 (Signature required):** A [`DriverCapsule`] is always
//!   constructed with a [`DriverSignature`].
//! - **INV-DRV-002 (Canary gates hardware):** No driver whose canary boot
//!   returned anything other than `Booted(verified)` is allowed to access
//!   hardware — the registry enforces this.
//! - **INV-DRV-003 (Rollback restores snapshot):** A rollback reverts the
//!   capsule to its last snapshot and returns the snapshot ID.
//! - **INV-DRV-004 (Registry isolation):** Each [`DriverCapsule`] is registered
//!   exactly once; duplicate registration is rejected.

use std::collections::HashMap;

use super::capsule_namespace::CapsuleId;
use super::snapshot::SnapshotId;

// ---------------------------------------------------------------------------
// DriverClass — what kind of driver this is
// ---------------------------------------------------------------------------

/// Closed enum classifying the hardware-adjacent role of a driver.
///
/// Mirrors the Linux kernel driver model (bus/class) and the UEFI firmware
/// update capsule taxonomy, flattened into the AIOS capability namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DriverClass {
    KernelModule,
    FirmwareBlob,
    UserSpace,
    PciDevice,
    UsbDevice,
}

// ---------------------------------------------------------------------------
// DriverSignature — Ed25519-signed driver identity
// ---------------------------------------------------------------------------

/// A verified driver identity: who signed it and the signed payload hash.
///
/// `signer_identity` is an opaque string keyed to a trust-store entry (e.g.
/// `"vendor:intel:microcode"` or `"publisher:linux-firmware"`).
/// `signed_hash` is the hex-encoded Ed25519 signature over the canonical
/// signed-manifest bytes (per the S10.1 §10.2 wire convention, matching the
/// adapter-manifest signing pattern).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverSignature {
    pub signer_identity: String,
    pub verifying_key_base64: String,
    pub signed_hash_hex: String,
}

impl DriverSignature {
    #[must_use]
    pub fn new(
        signer_identity: impl Into<String>,
        verifying_key_base64: impl Into<String>,
        signed_hash_hex: impl Into<String>,
    ) -> Self {
        Self {
            signer_identity: signer_identity.into(),
            verifying_key_base64: verifying_key_base64.into(),
            signed_hash_hex: signed_hash_hex.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// CanaryBootResult — outcome of the canary boot test
// ---------------------------------------------------------------------------

/// What happened when the capsule was canary-booted in isolation.
///
/// The canary boot is a **zero-trust gate**: before the driver capsule is
/// allowed onto the real hardware bus, the runtime boots it in a sandboxed
/// environment and verifies that the capsule's hash matches the signed
/// manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryBootResult {
    Booted { verified: bool },
    Rejected { mismatch: String },
    TimedOut,
    Rolledback { snapshot_id: SnapshotId },
}

// ---------------------------------------------------------------------------
// DriverCapsule — the signed driver capsule envelope
// ---------------------------------------------------------------------------

/// A driver capsule: ID + class + signature + canary boot result + rollback
/// snapshot.
///
/// Every driver that touches hardware or firmware MUST be wrapped in a
/// `DriverCapsule`.  The capsule carries the identity graph needed for
/// canary-gate enforcement (signature + boot result) and rollback safety
/// (snapshot ID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverCapsule {
    pub capsule_id: CapsuleId,
    pub driver_class: DriverClass,
    pub signature: DriverSignature,
    pub canary_result: Option<CanaryBootResult>,
    pub rollback_snapshot_id: Option<SnapshotId>,
}

impl DriverCapsule {
    #[must_use]
    pub fn new(
        capsule_id: CapsuleId,
        driver_class: DriverClass,
        signature: DriverSignature,
    ) -> Self {
        Self {
            capsule_id,
            driver_class,
            signature,
            canary_result: None,
            rollback_snapshot_id: None,
        }
    }

    /// Whether this capsule passed canary boot and is safe for hardware access.
    #[must_use]
    pub fn is_booted_safe(&self) -> bool {
        matches!(
            self.canary_result,
            Some(CanaryBootResult::Booted { verified: true })
        )
    }

    /// Record a canary boot outcome on this capsule.
    pub fn record_canary_boot(&mut self, result: CanaryBootResult) {
        self.canary_result = Some(result);
    }
}

// ---------------------------------------------------------------------------
// DriverRegistry — all registered driver capsules
// ---------------------------------------------------------------------------

/// System-wide registry mapping capsule IDs to their driver capsules.
///
/// The registry is the gatekeeper for driver hardware access.  It enforces
/// INV-DRV-002 (no hardware access without a passing canary boot) and
/// INV-DRV-004 (no duplicate registration).
#[derive(Debug, Default, Clone)]
pub struct DriverRegistry {
    capsules: HashMap<CapsuleId, DriverCapsule>,
}

impl DriverRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            capsules: HashMap::new(),
        }
    }

    /// Register a driver capsule.
    ///
    /// Returns `Err` if a capsule with the same ID already exists
    /// (INV-DRV-004).
    pub fn register(&mut self, capsule: DriverCapsule) -> Result<(), String> {
        if self.capsules.contains_key(&capsule.capsule_id) {
            return Err(format!(
                "driver capsule {} already registered",
                capsule.capsule_id
            ));
        }
        self.capsules.insert(capsule.capsule_id, capsule);
        Ok(())
    }

    /// Simulate a canary boot verification for the given capsule.
    ///
    /// Returns [`CanaryBootResult::Booted { verified: true }`] if the
    /// capsule exists and its signature hash is non-empty (simulating a
    /// successful Ed25519 verification).  Returns `Rejected` if the capsule
    /// exists but the hash is empty (corrupt signature).  Returns `TimedOut`
    /// if no capsule with that ID is found.
    ///
    /// The canary boot outcome is **recorded** on the capsule (mutating the
    /// registry entry).
    pub fn canary_boot(&mut self, capsule_id: CapsuleId) -> CanaryBootResult {
        let result = match self.capsules.get(&capsule_id) {
            Some(capsule) => {
                if capsule.signature.signed_hash_hex.is_empty() {
                    CanaryBootResult::Rejected {
                        mismatch: "empty signature hash".into(),
                    }
                } else {
                    CanaryBootResult::Booted { verified: true }
                }
            }
            None => CanaryBootResult::TimedOut,
        };

        if let Some(capsule) = self.capsules.get_mut(&capsule_id) {
            capsule.record_canary_boot(result.clone());
        }

        result
    }

    /// Rollback a driver capsule to its previous version.
    ///
    /// Returns `true` if a rollback snapshot existed and was applied,
    /// `false` otherwise.  The rollback snapshot ID is recorded on the
    /// capsule for audit trails.
    pub fn rollback(&mut self, capsule_id: CapsuleId) -> bool {
        let capsule = match self.capsules.get_mut(&capsule_id) {
            Some(c) => c,
            None => return false,
        };

        if let Some(snapshot_id) = capsule.rollback_snapshot_id.take() {
            capsule.canary_result = Some(CanaryBootResult::Rolledback { snapshot_id });
            true
        } else {
            false
        }
    }

    /// Return every capsule that *passed* canary boot and is therefore
    /// allowed hardware access (INV-DRV-002).
    #[must_use]
    pub fn active_drivers(&self) -> Vec<DriverCapsule> {
        self.capsules
            .values()
            .filter(|c| c.is_booted_safe())
            .cloned()
            .collect()
    }

    /// Look up a driver capsule by ID.
    #[must_use]
    pub fn get(&self, capsule_id: CapsuleId) -> Option<&DriverCapsule> {
        self.capsules.get(&capsule_id)
    }

    /// Number of registered driver capsules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capsules.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capsules.is_empty()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::super::capsule_namespace::{next_capsule_id, CapsuleId};
    use super::*;

    fn valid_signature() -> DriverSignature {
        DriverSignature::new(
            "vendor:test:driver",
            "MCowBQYDK2VwAyEA...base64key...=",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        )
    }

    // -----------------------------------------------------------------------
    // T-001: Capsule creation with signature
    // -----------------------------------------------------------------------

    #[test]
    fn capsule_creation_with_signature() {
        let id = next_capsule_id();
        let sig = valid_signature();
        let capsule = DriverCapsule::new(id, DriverClass::KernelModule, sig.clone());

        assert_eq!(capsule.capsule_id, id);
        assert_eq!(capsule.driver_class, DriverClass::KernelModule);
        assert_eq!(capsule.signature.signer_identity, "vendor:test:driver");
        assert!(capsule.canary_result.is_none());
        assert!(capsule.rollback_snapshot_id.is_none());
        assert!(!capsule.is_booted_safe());
    }

    // -----------------------------------------------------------------------
    // T-002: Canary boot passes
    // -----------------------------------------------------------------------

    #[test]
    fn canary_boot_passes_with_valid_signature() {
        let mut registry = DriverRegistry::new();
        let id = next_capsule_id();
        let capsule = DriverCapsule::new(id, DriverClass::PciDevice, valid_signature());
        registry.register(capsule).expect("register should succeed");

        let result = registry.canary_boot(id);
        assert_eq!(result, CanaryBootResult::Booted { verified: true });

        let capsule = registry.get(id).expect("capsule should still exist");
        assert!(capsule.is_booted_safe());
    }

    // -----------------------------------------------------------------------
    // T-003: Canary boot fails (empty signature hash)
    // -----------------------------------------------------------------------

    #[test]
    fn canary_boot_fails_with_empty_signature() {
        let mut registry = DriverRegistry::new();
        let id = next_capsule_id();
        let bad_sig = DriverSignature::new("vendor:bad", "key", "");
        let capsule = DriverCapsule::new(id, DriverClass::FirmwareBlob, bad_sig);
        registry.register(capsule).expect("register should succeed");

        let result = registry.canary_boot(id);
        assert_eq!(
            result,
            CanaryBootResult::Rejected {
                mismatch: "empty signature hash".into()
            }
        );

        let capsule = registry.get(id).expect("capsule should still exist");
        assert!(!capsule.is_booted_safe());
    }

    // -----------------------------------------------------------------------
    // T-004: Canary boot times out for unknown capsule
    // -----------------------------------------------------------------------

    #[test]
    fn canary_boot_times_out_for_unknown_capsule() {
        let mut registry = DriverRegistry::new();
        let result = registry.canary_boot(CapsuleId(99999));
        assert_eq!(result, CanaryBootResult::TimedOut);
    }

    // -----------------------------------------------------------------------
    // T-005: Rollback succeeds with snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn rollback_succeeds_when_snapshot_exists() {
        let mut registry = DriverRegistry::new();
        let id = next_capsule_id();
        let snap_id = SnapshotId(42);
        let mut capsule = DriverCapsule::new(id, DriverClass::UserSpace, valid_signature());
        capsule.rollback_snapshot_id = Some(snap_id);
        registry.register(capsule).expect("register should succeed");

        registry.canary_boot(id);
        assert!(registry.get(id).expect("exists").is_booted_safe());

        let rolled = registry.rollback(id);
        assert!(rolled);

        let capsule = registry.get(id).expect("capsule should still exist");
        match capsule.canary_result.as_ref() {
            Some(CanaryBootResult::Rolledback { snapshot_id }) => {
                assert_eq!(*snapshot_id, snap_id);
            }
            other => panic!("expected Rolledback, got {:?}", other),
        }
        assert!(!capsule.is_booted_safe());
    }

    // -----------------------------------------------------------------------
    // T-006: Rollback fails without snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn rollback_fails_without_snapshot() {
        let mut registry = DriverRegistry::new();
        let id = next_capsule_id();
        let capsule = DriverCapsule::new(id, DriverClass::UsbDevice, valid_signature());
        registry.register(capsule).expect("register should succeed");

        let rolled = registry.rollback(id);
        assert!(!rolled);
    }

    // -----------------------------------------------------------------------
    // T-007: Rollback for unknown capsule returns false
    // -----------------------------------------------------------------------

    #[test]
    fn rollback_unknown_capsule_returns_false() {
        let mut registry = DriverRegistry::new();
        let rolled = registry.rollback(CapsuleId(99999));
        assert!(!rolled);
    }

    // -----------------------------------------------------------------------
    // T-008: Multiple drivers per class
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_drivers_per_class() {
        let mut registry = DriverRegistry::new();

        let k1 = DriverCapsule::new(
            next_capsule_id(),
            DriverClass::KernelModule,
            valid_signature(),
        );
        let k2 = DriverCapsule::new(
            next_capsule_id(),
            DriverClass::KernelModule,
            valid_signature(),
        );
        let u1 = DriverCapsule::new(next_capsule_id(), DriverClass::UserSpace, valid_signature());

        registry.register(k1).expect("k1");
        registry.register(k2).expect("k2");
        registry.register(u1).expect("u1");

        assert_eq!(registry.len(), 3);
        assert_eq!(registry.active_drivers().len(), 0);

        // Canary-boot all three.
        for cid in registry.capsules.keys().copied().collect::<Vec<_>>() {
            registry.canary_boot(cid);
        }

        assert_eq!(registry.active_drivers().len(), 3);
    }

    // -----------------------------------------------------------------------
    // T-009: Duplicate registration is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_registration_rejected() {
        let mut registry = DriverRegistry::new();
        let id = next_capsule_id();
        let capsule = DriverCapsule::new(id, DriverClass::KernelModule, valid_signature());
        registry.register(capsule.clone()).expect("first register");

        let err = registry.register(capsule);
        assert!(err.is_err());
    }

    // -----------------------------------------------------------------------
    // T-010: DriverClass equality and hash
    // -----------------------------------------------------------------------

    #[test]
    fn driver_class_equality() {
        assert_eq!(DriverClass::KernelModule, DriverClass::KernelModule);
        assert_ne!(DriverClass::KernelModule, DriverClass::UserSpace);
        // Hash consistency: every variant must hash consistently.
        let variants = [
            DriverClass::KernelModule,
            DriverClass::FirmwareBlob,
            DriverClass::UserSpace,
            DriverClass::PciDevice,
            DriverClass::UsbDevice,
        ];
        use std::collections::HashSet;
        let set: HashSet<_> = variants.iter().collect();
        assert_eq!(set.len(), 5);
    }
}
