//! Kernel personality and portability module for AI-OS.NET (R3-W5.1).
//!
//! Linux is the gold path. BSD, RTOS, microVM, WASI, unikernel kernels are
//! admitted only through a signed [`KernelCapabilityMatrix`] with canary boot.
//! Never pretend all kernels are equivalent.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Identifies the kernel that the AI-OS runtime is executing on.
///
/// Linux is the gold path. Every other personality is secondary and must
/// pass capability admission through the [`KernelCapabilityMatrix`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KernelPersonality {
    /// Linux kernel, gold path — always admitted for any capability set.
    Linux(String),
    FreeBsd,
    OpenBsd,
    /// MicroVM kernels (e.g. Firecracker, Cloud Hypervisor).
    MicroVm,
    /// WASI-compatible runtime (e.g. Wasmtime, Wasmer).
    Wasi,
    /// Unikernel (e.g. MirageOS, OSv, Nanos).
    Unikernel,
    /// Custom, non-standard kernel — always requires canary boot.
    Custom(String),
}

impl KernelPersonality {
    /// Returns `true` if this personality is the Linux gold path.
    ///
    /// Only `Linux(..)` variants are the gold path. Every other personality
    /// must be explicitly admitted through the capability matrix.
    #[must_use]
    pub fn is_linux_gold_path(&self) -> bool {
        matches!(self, Self::Linux(_))
    }

    /// Human-readable label for this personality.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Linux(ref v) => format!("Linux/{v}"),
            Self::FreeBsd => "FreeBSD".into(),
            Self::OpenBsd => "OpenBSD".into(),
            Self::MicroVm => "MicroVM".into(),
            Self::Wasi => "WASI".into(),
            Self::Unikernel => "Unikernel".into(),
            Self::Custom(ref n) => format!("Custom/{n}"),
        }
    }
}

/// A capability that a given kernel personality may or may not support.
///
/// Each variant represents a concrete runtime feature that capsules or
/// the AI-OS control plane may depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelCapability {
    /// seccomp-bpf / pledge-style system-call filtering.
    SyscallFilter,
    /// File-system namespace isolation (mount namespaces, chroot, pivot_root).
    FilesystemIsolation,
    /// cgroups / resource-control groups for memory, CPU, I/O.
    ResourceControl,
    /// Per-process or per-namespace network stack isolation.
    NetworkIsolation,
    /// PID namespace isolation.
    PidIsolation,
    /// IPC namespace isolation.
    IpcIsolation,
    /// User namespace / UID remapping.
    UserNamespace,
    /// Linux capabilities(7) — fine-grained privilege bits.
    LinuxCapabilities,
    /// SECCOMP BPF advanced filter rule programme.
    SeccompAdvanced,
    /// Landlock unprivileged sandbox.
    Landlock,
    /// SELinux mandatory access control.
    SelinuxMac,
    /// AppArmor mandatory access control.
    AppArmorMac,
    /// TPM 2.0 measured boot / remote attestation.
    TpmAttestation,
    /// IMA/EVM integrity measurement and appraisal.
    ImaEVM,
    /// dm-verity / fs-verity immutable root.
    VerityIntegrity,
    /// DTrace / eBPF dynamic tracing.
    DynamicTracing,
    /// KVM / hardware-accelerated virtualisation.
    HypervisorSupport,
    /// io_uring high-performance async I/O.
    IoUring,
    /// FUSE / user-space file systems.
    Fuse,
    /// KSM / memory deduplication.
    MemoryDeduplication,
    /// Transparent Huge Pages.
    TransparentHugePages,
}

impl KernelCapability {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SyscallFilter => "SyscallFilter",
            Self::FilesystemIsolation => "FilesystemIsolation",
            Self::ResourceControl => "ResourceControl",
            Self::NetworkIsolation => "NetworkIsolation",
            Self::PidIsolation => "PidIsolation",
            Self::IpcIsolation => "IpcIsolation",
            Self::UserNamespace => "UserNamespace",
            Self::LinuxCapabilities => "LinuxCapabilities",
            Self::SeccompAdvanced => "SeccompAdvanced",
            Self::Landlock => "Landlock",
            Self::SelinuxMac => "SELinux",
            Self::AppArmorMac => "AppArmor",
            Self::TpmAttestation => "TpmAttestation",
            Self::ImaEVM => "IMA/EVM",
            Self::VerityIntegrity => "VerityIntegrity",
            Self::DynamicTracing => "DynamicTracing",
            Self::HypervisorSupport => "HypervisorSupport",
            Self::IoUring => "IoUring",
            Self::Fuse => "FUSE",
            Self::MemoryDeduplication => "MemoryDeduplication",
            Self::TransparentHugePages => "TransparentHugePages",
        }
    }
}

/// Decision from the kernel admission check.
///
/// - [`Admitted`](Self::Admitted): kernel is trusted and possesses all
///   required capabilities.
/// - [`CanaryRequired`](Self::CanaryRequired): kernel personality is known
///   but must pass a signed canary boot challenge before admission.
/// - [`Rejected`](Self::Rejected): kernel is unknown or lacks required
///   capabilities; admission is denied with a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelAdmissionDecision {
    Admitted,
    CanaryRequired,
    Rejected(String),
}

impl KernelAdmissionDecision {
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted)
    }

    #[must_use]
    pub fn is_canary_required(&self) -> bool {
        matches!(self, Self::CanaryRequired)
    }
}

/// Per-kernel-personality capability map.
///
/// Maintains a mapping from each registered [`KernelPersonality`] to the
/// set of [`KernelCapability`]s it supports.  Used by the runtime to decide
/// whether the active kernel can host a given capsule workload.
#[derive(Debug, Clone, Default)]
pub struct KernelCapabilityMatrix {
    entries: HashMap<KernelPersonality, Vec<KernelCapability>>,
}

impl KernelCapabilityMatrix {
    /// Create an empty capability matrix.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Create a matrix pre-seeded with the Linux gold-path entry.
    ///
    /// Linux is registered with *every* capability in the enum.
    #[must_use]
    pub fn with_linux_gold() -> Self {
        let mut matrix = Self::new();
        matrix.register(
            KernelPersonality::Linux("6.x".into()),
            KernelCapability::all_caps(),
        );
        matrix
    }

    /// Register a kernel personality with its supported capabilities.
    ///
    /// If the personality was already registered, its capability set is
    /// **replaced** with the new vector.
    pub fn register(
        &mut self,
        personality: KernelPersonality,
        capabilities: Vec<KernelCapability>,
    ) {
        self.entries.insert(personality, capabilities);
    }

    /// Evaluate whether `personality` is admitted for the given required
    /// capability set.
    ///
    /// # Decision rules
    ///
    /// 1. **Linux gold path** — always [`Admitted`](KernelAdmissionDecision::Admitted),
    ///    regardless of the required capability set.
    /// 2. **Known personality** — if the personality is registered and its
    ///    supported capabilities are a superset of `required_caps`, it is
    ///    admitted.  Otherwise, it is rejected with a reason listing the
    ///    missing capabilities.
    /// 3. **Unknown personality** — [`Rejected`](KernelAdmissionDecision::Rejected)
    ///    with a descriptive reason.
    /// 4. **Custom personality** — always [`CanaryRequired`](KernelAdmissionDecision::CanaryRequired)
    ///    even if registered (signature challenge must pass first).
    #[must_use]
    pub fn admit(
        &self,
        personality: &KernelPersonality,
        required_caps: &[KernelCapability],
    ) -> KernelAdmissionDecision {
        // Rule 1 — Linux is always admitted.
        if personality.is_linux_gold_path() {
            return KernelAdmissionDecision::Admitted;
        }

        // Rule 4 — Custom personalities always require canary boot.
        if matches!(personality, KernelPersonality::Custom(_)) {
            return KernelAdmissionDecision::CanaryRequired;
        }

        // Rule 3 — Unknown personality.
        let supported = match self.entries.get(personality) {
            Some(caps) => caps,
            None => {
                return KernelAdmissionDecision::Rejected(format!(
                    "kernel personality '{}' is not registered in the capability matrix",
                    personality.label()
                ));
            }
        };

        // Rule 2 — Check that every required capability is present.
        let missing: Vec<String> = required_caps
            .iter()
            .filter(|c| !supported.contains(c))
            .map(|c| c.as_str().to_string())
            .collect();

        if missing.is_empty() {
            KernelAdmissionDecision::Admitted
        } else {
            KernelAdmissionDecision::Rejected(format!(
                "kernel '{}' lacks required capabilities: {}",
                personality.label(),
                missing.join(", ")
            ))
        }
    }

    /// Check whether a personality has been registered.
    #[must_use]
    pub fn is_registered(&self, personality: &KernelPersonality) -> bool {
        self.entries.contains_key(personality)
    }

    /// Return the number of registered personalities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if no personalities are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all registered (personality, capabilities) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&KernelPersonality, &Vec<KernelCapability>)> {
        self.entries.iter()
    }
}

impl KernelCapability {
    /// Every capability variant.
    #[must_use]
    pub fn all_caps() -> Vec<KernelCapability> {
        vec![
            Self::SyscallFilter,
            Self::FilesystemIsolation,
            Self::ResourceControl,
            Self::NetworkIsolation,
            Self::PidIsolation,
            Self::IpcIsolation,
            Self::UserNamespace,
            Self::LinuxCapabilities,
            Self::SeccompAdvanced,
            Self::Landlock,
            Self::SelinuxMac,
            Self::AppArmorMac,
            Self::TpmAttestation,
            Self::ImaEVM,
            Self::VerityIntegrity,
            Self::DynamicTracing,
            Self::HypervisorSupport,
            Self::IoUring,
            Self::Fuse,
            Self::MemoryDeduplication,
            Self::TransparentHugePages,
        ]
    }
}

/// Registry of all known kernel personalities.
///
/// Tracks which kernel personality is currently **active**.  The active
/// personality determines the capability set available to capsules and
/// influences admission decisions.
#[derive(Debug, Clone)]
pub struct PersonalityRegistry {
    active: Arc<RwLock<KernelPersonality>>,
}

impl Default for PersonalityRegistry {
    fn default() -> Self {
        Self {
            active: Arc::new(RwLock::new(KernelPersonality::Linux("6.x".into()))),
        }
    }
}

impl PersonalityRegistry {
    /// Create a new registry with Linux as the default active personality.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry with a specific initial personality.
    #[must_use]
    pub fn with_personality(personality: KernelPersonality) -> Self {
        Self {
            active: Arc::new(RwLock::new(personality)),
        }
    }

    /// Switch the active kernel personality.
    ///
    /// # Guard rules
    ///
    /// - Switching **to** Linux from any other personality is always
    ///   permitted.
    /// - Switching **from** Linux to a non-Linux personality is denied
    ///   (downgrade protection — you cannot leave the gold path once on it).
    /// - Switching between non-Linux personalities is permitted.
    ///
    /// # Errors
    ///
    /// Returns `Err` with a descriptive message if the switch is denied.
    pub fn switch_to(&self, personality: KernelPersonality) -> Result<(), String> {
        let current = self.current();

        if current.is_linux_gold_path() && !personality.is_linux_gold_path() {
            return Err(format!(
                "cannot downgrade from Linux gold path '{}' to '{}'",
                current.label(),
                personality.label()
            ));
        }

        let mut active = self
            .active
            .write()
            .map_err(|e| format!("personality registry lock poisoned: {e}"))?;
        *active = personality;
        Ok(())
    }

    /// Return the currently active kernel personality.
    #[must_use]
    pub fn current(&self) -> KernelPersonality {
        self.active
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| KernelPersonality::Linux("6.x-recovery".into()))
    }

    /// Return a clone of the inner `Arc<RwLock<KernelPersonality>>` for
    /// sharing across threads.
    #[must_use]
    pub fn shared_active(&self) -> Arc<RwLock<KernelPersonality>> {
        Arc::clone(&self.active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ──────────────────────────────────────────────────

    fn linux_6x() -> KernelPersonality {
        KernelPersonality::Linux("6.x".into())
    }

    fn freebsd() -> KernelPersonality {
        KernelPersonality::FreeBsd
    }

    fn microvm() -> KernelPersonality {
        KernelPersonality::MicroVm
    }

    // ── Tests ─────────────────────────────────────────────────────────

    #[test]
    fn linux_gold_path_always_admitted() {
        let matrix = KernelCapabilityMatrix::with_linux_gold();
        // Even with caps Linux doesn't supposedly support (it supports all anyway),
        // the gold path rule means immediate Admitted.
        let decision = matrix.admit(&linux_6x(), &[KernelCapability::Landlock]);
        assert_eq!(decision, KernelAdmissionDecision::Admitted);
    }

    #[test]
    fn linux_gold_path_admitted_even_with_no_matrix_entry() {
        let matrix = KernelCapabilityMatrix::new(); // empty matrix
        let decision = matrix.admit(&linux_6x(), &[]);
        assert_eq!(decision, KernelAdmissionDecision::Admitted);
    }

    #[test]
    fn unknown_kernel_rejected() {
        let matrix = KernelCapabilityMatrix::new();
        let decision = matrix.admit(&freebsd(), &[]);
        assert!(matches!(decision, KernelAdmissionDecision::Rejected(_)));
        if let KernelAdmissionDecision::Rejected(reason) = decision {
            assert!(reason.contains("not registered"), "reason: {reason}");
        }
    }

    #[test]
    fn registered_kernel_with_sufficient_caps_admitted() {
        let mut matrix = KernelCapabilityMatrix::new();
        matrix.register(freebsd(), vec![KernelCapability::SyscallFilter]);
        let decision = matrix.admit(&freebsd(), &[KernelCapability::SyscallFilter]);
        assert_eq!(decision, KernelAdmissionDecision::Admitted);
    }

    #[test]
    fn registered_kernel_missing_required_caps_rejected() {
        let mut matrix = KernelCapabilityMatrix::new();
        matrix.register(
            microvm(),
            vec![KernelCapability::SyscallFilter, KernelCapability::Fuse],
        );
        let decision = matrix.admit(
            &microvm(),
            &[
                KernelCapability::SyscallFilter,
                KernelCapability::TpmAttestation,
            ],
        );
        assert!(matches!(decision, KernelAdmissionDecision::Rejected(_)));
        if let KernelAdmissionDecision::Rejected(reason) = decision {
            assert!(reason.contains("TpmAttestation"), "reason: {reason}");
        }
    }

    #[test]
    fn custom_personality_always_requires_canary() {
        let mut matrix = KernelCapabilityMatrix::new();
        let custom = KernelPersonality::Custom("research-os".into());
        matrix.register(custom.clone(), KernelCapability::all_caps());
        // Even with all capabilities, Custom always requires canary.
        let decision = matrix.admit(&custom, &[]);
        assert_eq!(decision, KernelAdmissionDecision::CanaryRequired);
    }

    #[test]
    fn personality_registry_switch_guards_downgrade_from_linux() {
        let registry = PersonalityRegistry::new();
        assert!(registry.current().is_linux_gold_path());

        // Attempting to switch from Linux → FreeBSD must fail.
        let result = registry.switch_to(freebsd());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("downgrade"));

        // Still on Linux.
        assert!(registry.current().is_linux_gold_path());
    }

    #[test]
    fn personality_registry_switch_between_non_linux() {
        let registry = PersonalityRegistry::with_personality(microvm());
        assert!(!registry.current().is_linux_gold_path());

        let result = registry.switch_to(freebsd());
        assert!(result.is_ok());

        assert_eq!(registry.current(), freebsd());
    }

    #[test]
    fn personality_registry_switch_to_linux_always_allowed() {
        let registry = PersonalityRegistry::with_personality(microvm());
        let result = registry.switch_to(linux_6x());
        assert!(result.is_ok());
        assert!(registry.current().is_linux_gold_path());
    }

    #[test]
    fn linux_gold_path_detection() {
        assert!(linux_6x().is_linux_gold_path());
        assert!(KernelPersonality::Linux("5.15".into()).is_linux_gold_path());
        assert!(!freebsd().is_linux_gold_path());
        assert!(!KernelPersonality::OpenBsd.is_linux_gold_path());
        assert!(!KernelPersonality::MicroVm.is_linux_gold_path());
        assert!(!KernelPersonality::Wasi.is_linux_gold_path());
        assert!(!KernelPersonality::Unikernel.is_linux_gold_path());
        assert!(!KernelPersonality::Custom("hurd".into()).is_linux_gold_path());
    }

    #[test]
    fn kernel_personality_label() {
        assert_eq!(linux_6x().label(), "Linux/6.x");
        assert_eq!(KernelPersonality::FreeBsd.label(), "FreeBSD");
        assert_eq!(
            KernelPersonality::Custom("my-os".into()).label(),
            "Custom/my-os"
        );
    }

    #[test]
    fn admission_decision_helpers() {
        assert!(KernelAdmissionDecision::Admitted.is_admitted());
        assert!(!KernelAdmissionDecision::Rejected("nope".into()).is_admitted());
        assert!(KernelAdmissionDecision::CanaryRequired.is_canary_required());
        assert!(!KernelAdmissionDecision::Admitted.is_canary_required());
    }

    #[test]
    fn matrix_default_empty() {
        let matrix = KernelCapabilityMatrix::new();
        assert!(matrix.is_empty());
        assert_eq!(matrix.len(), 0);
    }

    #[test]
    fn matrix_with_linux_gold_has_one_entry() {
        let matrix = KernelCapabilityMatrix::with_linux_gold();
        assert_eq!(matrix.len(), 1);
        assert!(matrix.is_registered(&linux_6x()));
    }

    #[test]
    fn all_caps_has_expected_count() {
        assert_eq!(KernelCapability::all_caps().len(), 21);
    }
}
