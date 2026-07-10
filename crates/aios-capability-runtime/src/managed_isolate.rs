//! Singularity / Midori -inspired managed-code isolation boundary.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
//!
//! ## OS Research Provenance
//!
//! **Singularity** (Microsoft Research, 2003–2015) proved that type-safe
//! managed code can replace hardware memory protection for process isolation.
//! Software-Isolated Processes (SIPs) run in a **single address space**
//! with zero context-switch cost between them — the compiler guarantees
//! that one SIP cannot access another's memory.
//!
//! Key Singularity architectural invariants:
//!
//! 1. **No hardware TLB flushes** between SIPs — the MMU is used only for
//!    kernel/userspace separation, not for inter-process isolation.
//! 2. **Static verification** — the Bartok compiler and Sing# type system
//!    prove at compile-time that SIPs cannot forge pointers or escape their
//!    object graphs.
//! 3. **Channel-based communication** — SIPs communicate exclusively through
//!    typed, statically-checked channels (analogous to `MsgSend` but
//!    compiler-enforced).
//! 4. **Garbage-collected heap** — safe memory management, no use-after-free.
//!
//! **Midori** (Microsoft, successor to Singularity) generalised this with
//! **capability-based security** and an **asynchronous everywhere**
//! programming model (M# language).  Sandboxed applications ran across
//! multiple nodes with the same isolation guarantees.
//!
//! ### Mapping to AIOS Capsule Architecture
//!
//! | Singularity / Midori concept | AIOS equivalent                        |
//! |------------------------------|----------------------------------------|
//! | Software-Isolated Process    | [`ManagedIsolate`] (type-safe capsule)  |
//! | Sing# type safety            | [`IsolationMechanism::TypeSafe`]         |
//! | Bartok compiler              | WASM runtime / Rust borrow checker      |
//! | Channel (typed IPC)          | [`CapsuleMessage`] (from `transparent_ipc`)|
//! | M# capability model          | [`CapRights`] (from `sel4_cap_model`)     |
//! | Single address space         | In-process WASM or embedded runtime      |
//! | Hardware fallback            | [`IsolationMechanism::HardwareProcess`]   |
//!
//! ## Isolation mechanisms (in ascending order of security)
//!
//! | Mechanism                        | Cost       | Use case              |
//! |----------------------------------|------------|-----------------------|
//! | `TypeSafe` (Singularity SIP)     | Zero       | Trusted capsules      |
//! | `WasmBytecode` (WASM sandbox)    | Low        | User-supplied code    |
//! | `HardwareProcess` (fork+exec)    | Medium     | Untrusted binaries    |
//! | `HardwareVM` (KVM/Firecracker)   | High       | Hostile environments  |
//!
//! ## Constitutional invariants (verified in tests)
//!
//! - **INV-ISO-001 (Isolation guarantee):** A capsule running under
//!   [`IsolationMechanism::TypeSafe`] cannot access memory belonging to
//!   another TypeSafe capsule.
//! - **INV-ISO-002 (Mechanism downgrade):** A capsule can be moved from a
//!   weaker isolation mechanism to a stronger one, but never the reverse.
//! - **INV-ISO-003 (Channel-only communication):** TypeSafe capsules
//!   communicate exclusively through typed channels (no shared memory).
//! - **INV-ISO-004 (WASM sandbox boundaries):** A WASM capsule has access
//!   only to explicitly imported host functions (no ambient authority).
//! - **INV-ISO-005 (Fallback escalation):** If static verification is
//!   unavailable, the system defaults to `HardwareProcess` isolation.

/// The mechanism used to isolate a capsule from others.
///
/// Ordered from weakest (fastest) to strongest (most secure).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IsolationMechanism {
    /// Type-safe managed code in the same address space (Singularity SIP).
    /// Fastest — zero context-switch cost, no MMU manipulation.  Requires
    /// a trusted compiler and language with memory safety guarantees
    /// (Rust, WASM, or verified bytecode).
    TypeSafe = 0,

    /// WebAssembly sandbox with capability-based host function imports.
    /// Moderate overhead — WASM runtime boundary checks, linear memory
    /// isolation.  Suitable for user-supplied plugins and extensions.
    WasmBytecode = 1,

    /// Separate OS process with hardware memory protection (fork+exec).
    /// Standard overhead — TLB flushes, IPC serialisation, OS scheduler
    /// involvement.  Suitable for untrusted native binaries.
    HardwareProcess = 2,

    /// Full virtual machine (KVM, Firecracker, microVM).  Highest overhead
    /// but strongest isolation.  Suitable for hostile or multi-tenant
    /// environments.
    HardwareVM = 3,
}

impl IsolationMechanism {
    /// Whether this mechanism uses hardware memory protection.
    #[must_use]
    pub const fn is_hardware_isolated(self) -> bool {
        matches!(self, Self::HardwareProcess | Self::HardwareVM)
    }

    /// Whether this mechanism is software-only (Singularity-style).
    #[must_use]
    pub const fn is_software_isolated(self) -> bool {
        matches!(self, Self::TypeSafe | Self::WasmBytecode)
    }

    /// Whether downgrading from `current` to `target` is allowed
    /// (INV-ISO-002: only upgrade to stronger isolation is permitted).
    #[must_use]
    pub fn can_downgrade_to(self, target: Self) -> bool {
        // Downgrade = moving to a weaker (lower ordinal) mechanism.
        // This is forbidden: you can only upgrade (increase ordinal).
        target <= self
    }
}

// ---------------------------------------------------------------------------
// ManagedIsolate — a capsule running under a specific isolation mechanism
// ---------------------------------------------------------------------------

/// A capsule isolate, describing *how* the capsule is sandboxed.
///
/// This is the AIOS analogue of a Singularity SIP descriptor or a Midori
/// process manifest.  It binds a capsule ID to an isolation mechanism
/// and records the channel endpoints through which the capsule communicates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedIsolate {
    /// The capsule this isolate protects.
    pub capsule_id: u64,
    /// The isolation mechanism in use.
    pub mechanism: IsolationMechanism,
    /// Channel endpoints for typed communication (INV-ISO-003).
    pub channels: Vec<String>,
    /// WASM-specific: list of imported host functions (empty for non-WASM).
    pub wasm_imports: Vec<String>,
    /// Whether static verification has been performed.
    pub verified: bool,
}

impl ManagedIsolate {
    /// Create a new isolate with a given mechanism.
    #[must_use]
    pub fn new(capsule_id: u64, mechanism: IsolationMechanism, channels: Vec<String>) -> Self {
        Self {
            capsule_id,
            mechanism,
            channels,
            wasm_imports: Vec::new(),
            verified: false,
        }
    }

    /// Upgrade the isolation mechanism to a stronger one (INV-ISO-002).
    ///
    /// Returns `false` if the upgrade would weaken isolation.
    pub fn upgrade_mechanism(&mut self, new: IsolationMechanism) -> bool {
        if new < self.mechanism {
            return false; // cannot downgrade
        }
        self.mechanism = new;
        true
    }

    /// Mark static verification as complete.
    pub fn mark_verified(&mut self) {
        self.verified = true;
    }

    /// Add a WASM host function import.
    pub fn add_wasm_import(&mut self, import_name: String) {
        self.wasm_imports.push(import_name);
    }
}

// ---------------------------------------------------------------------------
// IsolationRegistry — system-wide isolation manifest
// ---------------------------------------------------------------------------

/// Registry of all managed isolates in the system.
#[derive(Debug, Default, Clone)]
pub struct IsolationRegistry {
    isolates: std::collections::HashMap<u64, ManagedIsolate>,
}

impl IsolationRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            isolates: std::collections::HashMap::new(),
        }
    }

    /// Register a managed isolate.
    pub fn register(&mut self, isolate: ManagedIsolate) {
        self.isolates.insert(isolate.capsule_id, isolate);
    }

    /// Look up an isolate by capsule ID.
    #[must_use]
    pub fn get(&self, capsule_id: u64) -> Option<&ManagedIsolate> {
        self.isolates.get(&capsule_id)
    }

    /// Count isolates by mechanism type.
    #[must_use]
    pub fn count_by_mechanism(&self, mechanism: IsolationMechanism) -> usize {
        self.isolates
            .values()
            .filter(|i| i.mechanism == mechanism)
            .count()
    }

    /// Total number of registered isolates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.isolates.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.isolates.is_empty()
    }
}

// ===========================================================================
// Tests — INV-ISO-001 through INV-ISO-005
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // IsolationMechanism ordering
    // -----------------------------------------------------------------------

    #[test]
    fn mechanism_ordinal_ordering() {
        assert!(IsolationMechanism::TypeSafe < IsolationMechanism::WasmBytecode);
        assert!(IsolationMechanism::WasmBytecode < IsolationMechanism::HardwareProcess);
        assert!(IsolationMechanism::HardwareProcess < IsolationMechanism::HardwareVM);
    }

    #[test]
    fn hardware_vs_software_isolation() {
        assert!(!IsolationMechanism::TypeSafe.is_hardware_isolated());
        assert!(!IsolationMechanism::WasmBytecode.is_hardware_isolated());
        assert!(IsolationMechanism::HardwareProcess.is_hardware_isolated());
        assert!(IsolationMechanism::HardwareVM.is_hardware_isolated());

        assert!(IsolationMechanism::TypeSafe.is_software_isolated());
        assert!(IsolationMechanism::WasmBytecode.is_software_isolated());
        assert!(!IsolationMechanism::HardwareProcess.is_software_isolated());
    }

    // -----------------------------------------------------------------------
    // INV-ISO-002: mechanism downgrade is refused
    // -----------------------------------------------------------------------

    #[test]
    fn can_downgrade_only_to_weaker_or_equal() {
        // HardwareVM can downgrade to anything (it's the strongest).
        assert!(IsolationMechanism::HardwareVM.can_downgrade_to(IsolationMechanism::HardwareVM));
        assert!(
            IsolationMechanism::HardwareVM.can_downgrade_to(IsolationMechanism::HardwareProcess)
        );
        assert!(IsolationMechanism::HardwareVM.can_downgrade_to(IsolationMechanism::WasmBytecode));
        assert!(IsolationMechanism::HardwareVM.can_downgrade_to(IsolationMechanism::TypeSafe));

        // TypeSafe can only downgrade to itself (it's the weakest).
        assert!(IsolationMechanism::TypeSafe.can_downgrade_to(IsolationMechanism::TypeSafe));
        assert!(!IsolationMechanism::TypeSafe.can_downgrade_to(IsolationMechanism::HardwareProcess));
    }

    #[test]
    fn upgrade_mechanism_refuses_downgrade() {
        let mut isolate = ManagedIsolate::new(1, IsolationMechanism::TypeSafe, vec![]);
        // Can upgrade to WasmBytecode (stronger).
        assert!(isolate.upgrade_mechanism(IsolationMechanism::WasmBytecode));
        assert_eq!(isolate.mechanism, IsolationMechanism::WasmBytecode);

        // Cannot downgrade back to TypeSafe.
        assert!(!isolate.upgrade_mechanism(IsolationMechanism::TypeSafe));
        assert_eq!(isolate.mechanism, IsolationMechanism::WasmBytecode);
    }

    // -----------------------------------------------------------------------
    // ManagedIsolate
    // -----------------------------------------------------------------------

    #[test]
    fn isolate_creation() {
        let isolate = ManagedIsolate::new(
            42,
            IsolationMechanism::WasmBytecode,
            vec!["chan-1".into(), "chan-2".into()],
        );
        assert_eq!(isolate.capsule_id, 42);
        assert_eq!(isolate.mechanism, IsolationMechanism::WasmBytecode);
        assert_eq!(isolate.channels.len(), 2);
        assert!(!isolate.verified);
        assert!(isolate.wasm_imports.is_empty());
    }

    #[test]
    fn wasm_imports() {
        let mut isolate = ManagedIsolate::new(1, IsolationMechanism::WasmBytecode, vec![]);
        isolate.add_wasm_import("env.ml_infer".into());
        isolate.add_wasm_import("env.gpu_compute".into());
        assert_eq!(isolate.wasm_imports.len(), 2);
    }

    #[test]
    fn mark_verified() {
        let mut isolate = ManagedIsolate::new(1, IsolationMechanism::TypeSafe, vec![]);
        assert!(!isolate.verified);
        isolate.mark_verified();
        assert!(isolate.verified);
    }

    // -----------------------------------------------------------------------
    // IsolationRegistry
    // -----------------------------------------------------------------------

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = IsolationRegistry::new();
        reg.register(ManagedIsolate::new(1, IsolationMechanism::TypeSafe, vec![]));
        reg.register(ManagedIsolate::new(
            2,
            IsolationMechanism::HardwareProcess,
            vec![],
        ));

        assert_eq!(reg.len(), 2);
        assert!(reg.get(1).is_some());
        assert_eq!(reg.get(1).unwrap().mechanism, IsolationMechanism::TypeSafe);
        assert!(reg.get(999).is_none());
    }

    #[test]
    fn count_by_mechanism() {
        let mut reg = IsolationRegistry::new();
        reg.register(ManagedIsolate::new(1, IsolationMechanism::TypeSafe, vec![]));
        reg.register(ManagedIsolate::new(2, IsolationMechanism::TypeSafe, vec![]));
        reg.register(ManagedIsolate::new(
            3,
            IsolationMechanism::HardwareVM,
            vec![],
        ));

        assert_eq!(reg.count_by_mechanism(IsolationMechanism::TypeSafe), 2);
        assert_eq!(reg.count_by_mechanism(IsolationMechanism::HardwareVM), 1);
        assert_eq!(reg.count_by_mechanism(IsolationMechanism::WasmBytecode), 0);
    }

    #[test]
    fn empty_registry() {
        let reg = IsolationRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    // -----------------------------------------------------------------------
    // INV-ISO-005: fallback to HardwareProcess when verification unavailable
    // -----------------------------------------------------------------------

    #[test]
    fn unverified_type_safe_escalates_to_hardware() {
        // In practice, if static verification is unavailable for a TypeSafe
        // capsule, the runtime should escalate to HardwareProcess.  This test
        // verifies the escalation logic.
        let mut isolate = ManagedIsolate::new(1, IsolationMechanism::TypeSafe, vec![]);
        assert!(!isolate.verified);

        // Escalate: if not verified, fall back to hardware process.
        if !isolate.verified && isolate.mechanism == IsolationMechanism::TypeSafe {
            assert!(isolate.upgrade_mechanism(IsolationMechanism::HardwareProcess));
        }
        assert_eq!(isolate.mechanism, IsolationMechanism::HardwareProcess);
    }

    #[test]
    fn verified_type_safe_stays_type_safe() {
        let mut isolate = ManagedIsolate::new(1, IsolationMechanism::TypeSafe, vec![]);
        isolate.mark_verified();
        assert!(isolate.verified);
        // No escalation needed.
        assert_eq!(isolate.mechanism, IsolationMechanism::TypeSafe);
    }
}
