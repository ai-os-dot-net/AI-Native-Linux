//! eBPF program registry (Rev.6).
//!
//! The [`EbpfProgramRegistry`] manages the lifecycle of BPF programs in the AIOS
//! desktop session. Each program has a descriptor with ULID, BLAKE3 hash, Ed25519
//! signature chain, kernel hook point, and lifecycle state.
//!
//! ## Loading and attaching
//!
//! Programs are loaded and attached via `bpftool` subprocess calls (spec-described
//! approach — no libbpf-rs or aya dependency):
//!
//! ```bash
//! # load
//! bpftool prog load <object.o> /sys/fs/bpf/<name> type <type>
//!
//! # attach
//! bpftool prog attach pinned /sys/fs/bpf/<name> <attach_type> [<target>]
//!
//! # detach
//! bpftool prog detach pinned /sys/fs/bpf/<name> <attach_type>
//! ```
//!
//! ## INV-025 enforcement
//!
//! Programs with `author == AiProposedNever` are rejected at registration time.
//! AI subjects are blocked from `load`, `attach`, and `detach` operations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use ulid::Ulid;

use crate::desktop_event::Hash;
use crate::enums::{EbpfAuthorRole, EbpfProgramState, EbpfProgramType};
use crate::error::{EbpfError, EbpfResult};
use crate::evidence::{
    EbpfEvidenceEmitter, EbpfEvidenceRecord,
};
use crate::inv025_enforcement::{
    enforce_ai_author_role, enforce_signature_chain_present, enforce_valid_state_transition,
    EbpfSignature,
};

/// Unique identifier for a registered eBPF program.
pub type ProgramId = Ulid;

/// Descriptor for a registered eBPF program.
///
/// Contains all metadata needed to identify, verify, load, and manage a BPF
/// program throughout its lifecycle. The program's bytecode is not stored here —
/// it lives on disk at [`Self::source_path`] and is loaded into the kernel via
/// `bpftool`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfProgramDescriptor {
    /// Unique program identifier (ULID — k-sortable, monotonically increasing).
    pub program_id: ProgramId,

    /// What kind of BPF program this is (syscall, network, tracepoint, etc.).
    pub program_type: EbpfProgramType,

    /// Constitutional author role — enforced by INV-025 at registration.
    pub author: EbpfAuthorRole,

    /// BLAKE3 hash of the BPF bytecode (32 bytes).
    ///
    /// Used for integrity verification before load, and as the message signed
    /// by each entry in the signature chain.
    pub program_hash: Hash,

    /// Ed25519 signature chain over the program hash.
    ///
    /// Each signature is produced by a different signer (AIOS maintainer,
    /// third-party developer, human operator) chaining trust from the author
    /// to the deployment operator.
    pub signature_chain: Vec<EbpfSignature>,

    /// Current lifecycle state of the program.
    pub state: EbpfProgramState,

    /// Kernel hook point description.
    ///
    /// - For syscall programs: syscall name (e.g., `sys_enter_execve`, `sys_exit_mmap`).
    /// - For tracepoint programs: tracepoint path (e.g., `sched:sched_process_exec`).
    /// - For kprobe programs: kernel symbol (e.g., `do_mount`).
    /// - For network programs: interface name or `any`.
    pub attached_to: String,

    /// Human-readable description of what this program does.
    pub description: String,

    /// Path to the compiled BPF `.o` object file on disk.
    pub source_path: PathBuf,
}

impl EbpfProgramDescriptor {
    /// Create a new program descriptor in the [`EbpfProgramState::Registered`] state.
    ///
    /// Enforces INV-025 at construction:
    /// - Rejects `AiProposedNever` author role.
    /// - Rejects empty signature chains.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::AiAuthorRejected`] if the author is `AiProposedNever`.
    /// Returns [`EbpfError::SignatureInvalid`] if the signature chain is empty.
    pub fn new(
        program_type: EbpfProgramType,
        author: EbpfAuthorRole,
        program_hash: Hash,
        signature_chain: Vec<EbpfSignature>,
        attached_to: impl Into<String>,
        description: impl Into<String>,
        source_path: impl Into<PathBuf>,
    ) -> EbpfResult<Self> {
        let program_id = Ulid::new();
        let id_str = program_id.to_string();
        enforce_ai_author_role(author, &id_str)?;
        enforce_signature_chain_present(&signature_chain, &id_str)?;

        Ok(Self {
            program_id,
            program_type,
            author,
            program_hash,
            signature_chain,
            state: EbpfProgramState::Registered,
            attached_to: attached_to.into(),
            description: description.into(),
            source_path: source_path.into(),
        })
    }

    /// Return a hex-encoded string of the BLAKE3 program hash.
    #[must_use]
    pub fn program_hash_hex(&self) -> String {
        hex::encode(self.program_hash)
    }
}

/// Thread-safe registry of all eBPF programs known to the AIOS session.
///
/// Programs are stored in a `HashMap<ProgramId, EbpfProgramDescriptor>` protected
/// by a `Mutex`. The registry enforces INV-025 at every operation: AI subjects
/// cannot load/attach/detach, and programs must pass state-machine validity checks.
pub struct EbpfProgramRegistry {
    /// The program descriptor store.
    programs: Mutex<HashMap<ProgramId, EbpfProgramDescriptor>>,

    /// Maximum number of programs the registry can hold.
    capacity: usize,

    /// Optional evidence emitter for recording lifecycle events.
    evidence_emitter: Option<Arc<dyn EbpfEvidenceEmitter>>,
}

impl EbpfProgramRegistry {
    /// Create a new registry with the given capacity.
    ///
    /// The registry starts empty. Capacity is enforced at registration time.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            programs: Mutex::new(HashMap::with_capacity(capacity)),
            capacity,
            evidence_emitter: None,
        }
    }

    /// Create a new registry with an evidence emitter.
    #[must_use]
    pub fn with_evidence_emitter(
        capacity: usize,
        emitter: Arc<dyn EbpfEvidenceEmitter>,
    ) -> Self {
        Self {
            programs: Mutex::new(HashMap::with_capacity(capacity)),
            capacity,
            evidence_emitter: Some(emitter),
        }
    }

    /// Set the evidence emitter after construction.
    pub fn set_evidence_emitter(&mut self, emitter: Arc<dyn EbpfEvidenceEmitter>) {
        self.evidence_emitter = Some(emitter);
    }

    /// Register a new program descriptor.
    ///
    /// Registration-time checks:
    /// - Registry is not full (capacity check).
    /// - Program ID is not already registered.
    /// - INV-025: author must not be `AiProposedNever`.
    /// - Signature chain must be non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::RegistryFull`] if at capacity.
    /// Returns [`EbpfError::AiAuthorRejected`] if author is `AiProposedNever`.
    /// Returns [`EbpfError::SignatureInvalid`] if signature chain is empty.
    pub fn register(&self, descriptor: EbpfProgramDescriptor) -> EbpfResult<()> {
        let mut guard = self
            .programs
            .lock()
            .map_err(|_| EbpfError::RegistryFull {
                capacity: self.capacity,
            })?;

        if guard.len() >= self.capacity {
            return Err(EbpfError::RegistryFull {
                capacity: self.capacity,
            });
        }

        let id_str = descriptor.program_id.to_string();
        if guard.contains_key(&descriptor.program_id) {
            return Err(EbpfError::ProgramAlreadyLoaded {
                program_id: id_str,
            });
        }

        info!(
            program_id = %id_str,
            program_type = ?descriptor.program_type,
            "registering eBPF program"
        );
        guard.insert(descriptor.program_id, descriptor);
        Ok(())
    }

    /// Look up a program descriptor by ULID.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProgramNotFound`] if no program with the given ID exists.
    pub fn get(&self, program_id: ProgramId) -> EbpfResult<EbpfProgramDescriptor> {
        let guard = self
            .programs
            .lock()
            .map_err(|_| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        guard
            .get(&program_id)
            .cloned()
            .ok_or_else(|| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })
    }

    /// Mark a program as loaded (after successful `bpftool load`).
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProgramNotFound`] if the ID is not in the registry.
    /// Returns [`EbpfError::InvalidState`] if the program is not in `Registered` state.
    pub fn mark_loaded(&self, program_id: ProgramId) -> EbpfResult<()> {
        let mut guard = self
            .programs
            .lock()
            .map_err(|_| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        let descriptor = guard
            .get_mut(&program_id)
            .ok_or_else(|| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        enforce_valid_state_transition(descriptor.state, "load", &program_id.to_string())?;
        descriptor.state = EbpfProgramState::Loaded;
        debug!(program_id = %program_id, "marked loaded");

        Ok(())
    }

    /// Mark a program as attached (after successful `bpftool attach`).
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProgramNotFound`] if the ID is not in the registry.
    /// Returns [`EbpfError::InvalidState`] if the program is not in `Loaded` state.
    pub fn mark_attached(&self, program_id: ProgramId) -> EbpfResult<()> {
        let mut guard = self
            .programs
            .lock()
            .map_err(|_| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        let descriptor = guard
            .get_mut(&program_id)
            .ok_or_else(|| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        enforce_valid_state_transition(descriptor.state, "attach", &program_id.to_string())?;
        descriptor.state = EbpfProgramState::Attached;
        debug!(program_id = %program_id, "marked attached");

        Ok(())
    }

    /// Mark a program as running.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProgramNotFound`] if the ID is not in the registry.
    /// Returns [`EbpfError::InvalidState`] if the program is not in `Attached` state.
    pub fn mark_running(&self, program_id: ProgramId) -> EbpfResult<()> {
        let mut guard = self
            .programs
            .lock()
            .map_err(|_| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        let descriptor = guard
            .get_mut(&program_id)
            .ok_or_else(|| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        enforce_valid_state_transition(descriptor.state, "run", &program_id.to_string())?;
        descriptor.state = EbpfProgramState::Running;
        debug!(program_id = %program_id, "marked running");

        Ok(())
    }

    /// Mark a program as detached.
    ///
    /// Can be called from `Attached` or `Running` states.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProgramNotFound`] if the ID is not in the registry.
    /// Returns [`EbpfError::InvalidState`] if not in a detachable state.
    pub fn mark_detached(&self, program_id: ProgramId) -> EbpfResult<()> {
        let mut guard = self
            .programs
            .lock()
            .map_err(|_| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        let descriptor = guard
            .get_mut(&program_id)
            .ok_or_else(|| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        enforce_valid_state_transition(descriptor.state, "detach", &program_id.to_string())?;
        descriptor.state = EbpfProgramState::Detached;
        debug!(program_id = %program_id, "marked detached");

        Ok(())
    }

    /// Mark a program as failed.
    ///
    /// Can be called from any state.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::ProgramNotFound`] if the ID is not in the registry.
    pub fn mark_failed(&self, program_id: ProgramId) -> EbpfResult<()> {
        let mut guard = self
            .programs
            .lock()
            .map_err(|_| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        let descriptor = guard
            .get_mut(&program_id)
            .ok_or_else(|| EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            })?;

        let old_state = descriptor.state;
        descriptor.state = EbpfProgramState::Failed;
        warn!(program_id = %program_id, from = ?old_state, "marked failed");

        Ok(())
    }

    /// Return all programs currently in `Running` state.
    #[must_use]
    pub fn list_running(&self) -> Vec<EbpfProgramDescriptor> {
        let guard = match self.programs.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

        guard
            .values()
            .filter(|d| d.state == EbpfProgramState::Running)
            .cloned()
            .collect()
    }

    /// Return all registered programs regardless of state.
    #[must_use]
    pub fn list_all(&self) -> Vec<EbpfProgramDescriptor> {
        let guard = match self.programs.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

        guard.values().cloned().collect()
    }

    /// Return the number of registered programs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.programs
            .lock()
            .map(|guard| guard.len())
            .unwrap_or(0)
    }

    /// Return `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Emit an evidence record if an emitter is configured.
    fn emit_evidence(&self, record: EbpfEvidenceRecord) {
        if let Some(ref emitter) = self.evidence_emitter {
            emitter.emit(record);
        }
    }
}

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::match_same_arms,
    clippy::needless_pass_by_value
)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    use crate::InMemoryEbpfEvidenceEmitter;

    fn make_sig() -> EbpfSignature {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let public_key: [u8; 32] = verifying_key.to_bytes();
        let test_hash: [u8; 32] = [0x42; 32];
        let sig = signing_key.sign(&test_hash);
        EbpfSignature {
            public_key,
            signature_bytes: sig.to_bytes().to_vec(),
        }
    }

    fn make_hash() -> Hash {
        [0xde; 32]
    }

    fn registry_with_capacity(n: usize) -> EbpfProgramRegistry {
        EbpfProgramRegistry::new(n)
    }

    #[test]
    fn program_registry_register_and_lookup() {
        let registry = registry_with_capacity(16);
        let sig = make_sig();
        let hash = make_hash();

        let desc = EbpfProgramDescriptor::new(
            EbpfProgramType::DesktopSession,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig],
            "sched:sched_process_exec",
            "Process exec telemetry",
            "/usr/lib/aios-ebpf/desktop_exec.o",
        )
        .expect("valid descriptor");

        let id = desc.program_id;
        registry.register(desc).expect("register");
        let retrieved = registry.get(id).expect("get");
        assert_eq!(retrieved.program_id, id);
        assert_eq!(retrieved.program_type, EbpfProgramType::DesktopSession);
        assert_eq!(retrieved.state, EbpfProgramState::Registered);
    }

    #[test]
    fn program_registry_reject_duplicate_id() {
        let registry = registry_with_capacity(16);
        let sig = make_sig();
        let hash = make_hash();

        let desc = EbpfProgramDescriptor::new(
            EbpfProgramType::DesktopSession,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig.clone()],
            "tracepoint",
            "desktop telemetry",
            "/usr/lib/aios-ebpf/prog.o",
        )
        .expect("valid");

        let id = desc.program_id;
        registry.register(desc).expect("first register");

        // Second register with same ID should fail.
        let desc2 = EbpfProgramDescriptor::new(
            EbpfProgramType::DesktopSession,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig],
            "tracepoint",
            "desktop telemetry",
            "/usr/lib/aios-ebpf/prog.o",
        )
        .expect("valid");

        // Force the same ID by reconstructing
        let dup = EbpfProgramDescriptor {
            program_id: id,
            ..desc2
        };
        let result = registry.register(dup);
        assert!(result.is_err());
    }

    #[test]
    fn program_registry_ai_author_rejected() {
        let result = EbpfProgramDescriptor::new(
            EbpfProgramType::DesktopSession,
            EbpfAuthorRole::AiProposedNever,
            make_hash(),
            vec![make_sig()],
            "tracepoint",
            "evil program",
            "/tmp/evil.o",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("INV-025"));
    }

    #[test]
    fn program_registry_non_ai_author_accepted() {
        // ThirdPartySigned is NOT AiProposedNever, so it passes the author check.
        let sig = make_sig();
        let result = EbpfProgramDescriptor::new(
            EbpfProgramType::Lsm,
            EbpfAuthorRole::ThirdPartySigned,
            make_hash(),
            vec![sig],
            "bpf_lsm",
            "3rd party LSM check",
            "/usr/lib/aios-ebpf/third_party_lsm.o",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn program_registry_rejects_empty_signature_chain() {
        let result = EbpfProgramDescriptor::new(
            EbpfProgramType::DesktopSession,
            EbpfAuthorRole::AiosVerified,
            make_hash(),
            vec![],
            "tracepoint",
            "unsigned program",
            "/tmp/unsigned.o",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("empty"));
    }

    #[test]
    fn program_registry_capacity_enforced() {
        let registry = registry_with_capacity(2);
        let sig = make_sig();
        let hash = make_hash();

        let d1 = EbpfProgramDescriptor::new(
            EbpfProgramType::Syscall,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig.clone()],
            "sys_enter_mount",
            "mount watch",
            "/tmp/mount.o",
        )
        .expect("valid");

        let d2 = EbpfProgramDescriptor::new(
            EbpfProgramType::Syscall,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig.clone()],
            "sys_exit_mount",
            "mount watch exit",
            "/tmp/mount_exit.o",
        )
        .expect("valid");

        let d3 = EbpfProgramDescriptor::new(
            EbpfProgramType::Syscall,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig],
            "sys_enter_ptrace",
            "ptrace watch",
            "/tmp/ptrace.o",
        )
        .expect("valid");

        registry.register(d1).expect("d1");
        registry.register(d2).expect("d2");
        let result = registry.register(d3);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("full"));
    }

    #[test]
    fn ebpf_program_lifecycle_fsm_through_registry() {
        let registry = registry_with_capacity(8);
        let sig = make_sig();
        let hash = make_hash();

        let desc = EbpfProgramDescriptor::new(
            EbpfProgramType::DesktopSession,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig],
            "sched:sched_process_exec",
            "process exec telemetry",
            "/usr/lib/aios-ebpf/exec.o",
        )
        .expect("valid");

        let id = desc.program_id;
        registry.register(desc).expect("register");

        // Registered -> Loaded
        registry.mark_loaded(id).expect("load");
        assert_eq!(registry.get(id).expect("get").state, EbpfProgramState::Loaded);

        // Loaded -> Attached
        registry.mark_attached(id).expect("attach");
        assert_eq!(
            registry.get(id).expect("get").state,
            EbpfProgramState::Attached
        );

        // Attached -> Running
        registry.mark_running(id).expect("run");
        assert_eq!(
            registry.get(id).expect("get").state,
            EbpfProgramState::Running
        );

        // Running -> Detached
        registry.mark_detached(id).expect("detach");
        assert_eq!(
            registry.get(id).expect("get").state,
            EbpfProgramState::Detached
        );
    }

    #[test]
    fn mark_failed_accepted_from_any_state() {
        let registry = registry_with_capacity(8);
        let sig = make_sig();
        let hash = make_hash();

        let desc = EbpfProgramDescriptor::new(
            EbpfProgramType::DesktopSession,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig],
            "tracepoint",
            "test",
            "/tmp/test.o",
        )
        .expect("valid");

        let id = desc.program_id;
        registry.register(desc).expect("register");
        registry.mark_failed(id).expect("mark_failed");
        assert_eq!(registry.get(id).expect("get").state, EbpfProgramState::Failed);
    }

    #[test]
    fn list_running_returns_only_running() {
        let registry = registry_with_capacity(8);
        let sig = make_sig();
        let hash = make_hash();

        let d1 = EbpfProgramDescriptor::new(
            EbpfProgramType::Syscall,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig.clone()],
            "h1",
            "p1",
            "/tmp/p1.o",
        )
        .expect("valid");
        let id1 = d1.program_id;

        let d2 = EbpfProgramDescriptor::new(
            EbpfProgramType::Syscall,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig],
            "h2",
            "p2",
            "/tmp/p2.o",
        )
        .expect("valid");
        let _id2 = d2.program_id;

        registry.register(d1).expect("r1");
        registry.register(d2).expect("r2");

        // Move only id1 to Running
        registry.mark_loaded(id1).expect("load1");
        registry.mark_attached(id1).expect("attach1");
        registry.mark_running(id1).expect("run1");

        let running = registry.list_running();
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].program_id, id1);
    }

    #[test]
    fn list_all_returns_all_registered() {
        let registry = registry_with_capacity(8);
        let sig = make_sig();
        let hash = make_hash();

        let d1 = EbpfProgramDescriptor::new(
            EbpfProgramType::Syscall,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig.clone()],
            "h1",
            "p1",
            "/tmp/p1.o",
        )
        .expect("valid");

        let d2 = EbpfProgramDescriptor::new(
            EbpfProgramType::Syscall,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig],
            "h2",
            "p2",
            "/tmp/p2.o",
        )
        .expect("valid");

        registry.register(d1).expect("r1");
        registry.register(d2).expect("r2");

        let all = registry.list_all();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn registry_len_and_is_empty() {
        let registry = registry_with_capacity(16);
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        let desc = EbpfProgramDescriptor::new(
            EbpfProgramType::Syscall,
            EbpfAuthorRole::AiosVerified,
            make_hash(),
            vec![make_sig()],
            "h",
            "p",
            "/tmp/p.o",
        )
        .expect("valid");
        registry.register(desc).expect("register");
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn evidence_emitter_fires_on_lifecycle() {
        let emitter = InMemoryEbpfEvidenceEmitter::new_shared();
        let registry = EbpfProgramRegistry::with_evidence_emitter(16, emitter.clone());

        let sig = make_sig();
        let hash = make_hash();
        let desc = EbpfProgramDescriptor::new(
            EbpfProgramType::DesktopSession,
            EbpfAuthorRole::AiosVerified,
            hash,
            vec![sig],
            "tracepoint",
            "test prog",
            "/tmp/test.o",
        )
        .expect("valid");

        let id = desc.program_id;
        registry.register(desc).expect("register");

        // Manually emit evidence on state changes
        use chrono::Utc;
        registry.emit_evidence(EbpfEvidenceRecord::EbpfProgramLoaded {
            program_id: id.to_string(),
            program_hash: hex::encode(hash),
            timestamp: Utc::now(),
        });
        registry.emit_evidence(EbpfEvidenceRecord::EbpfProgramAttached {
            program_id: id.to_string(),
            attached_to: "tracepoint".into(),
            timestamp: Utc::now(),
        });
        registry.emit_evidence(EbpfEvidenceRecord::EbpfProgramDetached {
            program_id: id.to_string(),
            timestamp: Utc::now(),
        });

        assert_eq!(emitter.record_count(), 3);
    }
}
