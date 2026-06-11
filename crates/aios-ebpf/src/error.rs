//! Error taxonomy for the eBPF Desktop Telemetry subsystem (Rev.6).
//!
//! The closed [`EbpfError`] enum covers all failure modes that can occur during
//! BPF program lifecycle management, desktop telemetry collection, and INV-025
//! constitutional enforcement.

use thiserror::Error;

/// Closed error taxonomy for eBPF operations per Rev.6 spec.
///
/// Every fallible path in the eBPF subsystem returns a typed [`Self`] variant. No
/// `Other(String)` fallback — every error is accounted for.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EbpfError {
    /// The requested program ID does not exist in the registry.
    #[error("eBPF program not found: program_id={program_id}")]
    ProgramNotFound {
        /// The ULID of the program that was looked up.
        program_id: String,
    },

    /// A program with this ID is already registered and cannot be duplicated.
    #[error("eBPF program already loaded: program_id={program_id}")]
    ProgramAlreadyLoaded {
        /// The ULID of the program already present.
        program_id: String,
    },

    /// The `bpftool load` subprocess failed.
    ///
    /// BPF programs are loaded via `bpftool prog load <object.o> /sys/fs/bpf/<name>`
    /// (spec-described approach — no libbpf-rs or aya dependency). This error wraps
    /// the exit code, stderr, and the object path that was attempted.
    #[error("failed to load eBPF program from `{object_path}`: exit_code={exit_code:?}, stderr={stderr}")]
    LoadFailed {
        /// Path to the BPF `.o` object file.
        object_path: String,
        /// Exit code of the `bpftool` subprocess.
        exit_code: Option<i32>,
        /// Captured stderr output (truncated to 4096 bytes).
        stderr: String,
    },

    /// The `bpftool attach` subprocess failed.
    #[error("failed to attach eBPF program {program_id} to `{hook_point}`: {detail}")]
    AttachFailed {
        /// The ULID of the program whose attach failed.
        program_id: String,
        /// Kernel hook point (syscall name, tracepoint path, kprobe symbol).
        hook_point: String,
        /// Human-readable detail from stderr or system error.
        detail: String,
    },

    /// The `bpftool detach` subprocess failed.
    #[error("failed to detach eBPF program {program_id}: {detail}")]
    DetachFailed {
        /// The ULID of the program whose detach failed.
        program_id: String,
        /// Human-readable detail from stderr or system error.
        detail: String,
    },

    /// INV-025 constitutional violation: an AI subject attempted to manage eBPF programs.
    ///
    /// Per INV-025, AI_SUBJECT MUST NEVER load, attach, or detach eBPF programs.
    /// Only SYSTEM_SERVICE or HUMAN_OPERATOR subjects may manage eBPF.
    #[error("INV-025 violation: AI subject `{subject}` attempted to {operation} eBPF program {program_id}")]
    AiAuthorRejected {
        /// The AI subject identifier that was rejected.
        subject: String,
        /// What eBPF operation was attempted (load, attach, detach).
        operation: String,
        /// The ULID of the program that was targeted.
        program_id: String,
    },

    /// The Ed25519 signature chain for an eBPF program is missing or invalid.
    #[error("invalid signature chain for eBPF program {program_id}: {detail}")]
    SignatureInvalid {
        /// The ULID of the program with invalid signatures.
        program_id: String,
        /// Reason for invalidity (missing signatures, verification failure).
        detail: String,
    },

    /// The in-memory program registry has reached its configured capacity.
    #[error("eBPF program registry is full: capacity={capacity}")]
    RegistryFull {
        /// The maximum number of programs the registry can hold.
        capacity: usize,
    },

    /// The desktop telemetry buffer has overflowed and events were dropped.
    #[error("desktop telemetry buffer overflow: buffer_id={buffer_id}, capacity={capacity}")]
    BufferOverflow {
        /// The ULID of the buffer that overflowed.
        buffer_id: String,
        /// The configured capacity of the buffer.
        capacity: usize,
    },

    /// A BPF program is not in a state that permits the requested operation.
    #[error("invalid state transition for eBPF program {program_id}: current_state={current_state:?}, attempted={attempted}")]
    InvalidState {
        /// The ULID of the program.
        program_id: String,
        /// The current state of the program.
        current_state: String,
        /// What operation was attempted.
        attempted: String,
    },
}

/// Type alias for all fallible eBPF operations.
pub type EbpfResult<T> = Result<T, EbpfError>;

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_message() {
        let e = EbpfError::ProgramNotFound {
            program_id: "01HABC".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("01HABC"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn error_display_load_failed() {
        let e = EbpfError::LoadFailed {
            object_path: "/tmp/test.o".into(),
            exit_code: Some(1),
            stderr: "verifier rejected".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("/tmp/test.o"));
        assert!(msg.contains("verifier rejected"));
    }

    #[test]
    fn error_display_ai_author_rejected() {
        let e = EbpfError::AiAuthorRejected {
            subject: "ai:gpt-5".into(),
            operation: "load".into(),
            program_id: "01HDEF".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("INV-025"));
        assert!(msg.contains("ai:gpt-5"));
        assert!(msg.contains("load"));
        assert!(msg.contains("01HDEF"));
    }

    #[test]
    fn error_display_signature_invalid() {
        let e = EbpfError::SignatureInvalid {
            program_id: "01HGHI".into(),
            detail: "missing signature at index 2".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("01HGHI"));
        assert!(msg.contains("missing signature"));
    }

    #[test]
    fn error_display_registry_full() {
        let e = EbpfError::RegistryFull { capacity: 256 };
        let msg = e.to_string();
        assert!(msg.contains("full"));
        assert!(msg.contains("256"));
    }

    #[test]
    fn error_display_buffer_overflow() {
        let e = EbpfError::BufferOverflow {
            buffer_id: "01HJKL".into(),
            capacity: 1024,
        };
        let msg = e.to_string();
        assert!(msg.contains("overflow"));
        assert!(msg.contains("01HJKL"));
    }

    #[test]
    fn error_display_invalid_state() {
        let e = EbpfError::InvalidState {
            program_id: "01HMNO".into(),
            current_state: "Loaded".into(),
            attempted: "attach".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("01HMNO"));
        assert!(msg.contains("Loaded"));
        assert!(msg.contains("attach"));
    }

    #[test]
    fn error_clone_roundtrip() {
        let e = EbpfError::AiAuthorRejected {
            subject: "ai:test".into(),
            operation: "detach".into(),
            program_id: "01HPQR".into(),
        };
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }
}
