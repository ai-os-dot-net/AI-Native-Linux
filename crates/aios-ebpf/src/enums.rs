//! Closed enum types for the eBPF Desktop Telemetry subsystem (Rev.6).
//!
//! These enums define the finite set of BPF program types, lifecycle states,
//! author roles (enforcing INV-025), desktop event classes, and evidence grades
//! that the subsystem operates on.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

/// Kernel hook point classification for BPF programs.
///
/// Determines what kernel subsystem the BPF program attaches to. The
/// `DesktopSession` variant is the AIOS-specific hook point for desktop
/// session telemetry — capturing process exec, network flows, GPU buffers,
/// Wayland protocol messages, etc.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCountMacro,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EbpfProgramType {
    /// BPF program attached to a Linux syscall (via `SEC("syscall")`).
    Syscall,
    /// BPF program attached to a network event (XDP, TC, socket filter).
    Network,
    /// BPF program attached to a kernel tracepoint.
    Tracepoint,
    /// BPF program attached to a kprobe/kretprobe.
    Kprobe,
    /// BPF program attached to a Linux Security Module hook.
    Lsm,
    /// AIOS desktop session telemetry program.
    DesktopSession,
}

/// Lifecycle state of a registered eBPF program.
///
/// State machine: Registered to Loaded to Attached to Running.
/// Any state can transition to Detached (back to Registered).
/// Any state can transition to Failed.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCountMacro,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EbpfProgramState {
    /// The program descriptor is registered but no bytecode is loaded.
    Registered,
    /// Bytecode is loaded into the kernel via `bpftool load` but not yet attached.
    Loaded,
    /// The program is attached to its kernel hook point.
    Attached,
    /// The program is attached and actively producing events.
    Running,
    /// The program has been detached from its hook point.
    Detached,
    /// Load, attach, or runtime verification failed.
    Failed,
}

/// The constitutional author role for an eBPF program.
///
/// ### INV-025 enforcement
///
/// - `AiosVerified`: Program is pre-vetted and signed by AIOS maintainers.
///   Full Ed25519 signature chain required. These are the ONLY programs
///   that may be loaded.
/// - `ThirdPartySigned`: Program signed by a registered third party.
///   Requires explicit human-operator approval.
/// - `AiProposedNever`: AI MUST NEVER load/attach/detach eBPF programs.
///   Any attempt is rejected with [`EbpfError::AiAuthorRejected`]. This
///   variant exists as a sentinel — no program with this role can be
///   registered.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCountMacro,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EbpfAuthorRole {
    /// Program vetted and signed by AIOS system maintainers.
    AiosVerified,
    /// Program signed by a registered third party (requires operator approval).
    ThirdPartySigned,
    /// AI-proposed programs — always rejected (INV-025 sentinel).
    AiProposedNever,
}

/// Desktop session event classes captured by eBPF telemetry.
///
/// Each variant maps to a specific BPF probe point in the desktop session:
/// tracepoints for process lifecycle, kprobes for syscalls, network hooks,
/// GPU driver traces, Wayland compositor hooks, etc.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCountMacro,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DesktopEventClass {
    /// `tracepoint:sched:sched_process_exec` — process execution detected.
    ProcessExec,
    /// `tracepoint:sched:sched_process_exit` — process exit detected.
    ProcessExit,
    /// Network flow event (TCP connect, UDP send, etc.).
    NetworkFlow,
    /// GPU buffer allocation/deallocation event.
    GpuBuffer,
    /// Wayland protocol message (wl_surface, zwlr_screencopy, etc.).
    WaylandProtocol,
    /// File access event (open, read, write, unlink).
    FileAccess,
    /// SELinux AVC denial event.
    SelinuxAvc,
    /// Capability use event (CAP_NET_RAW, CAP_SYS_ADMIN, etc.).
    CapabilityUse,
    /// Linux namespace creation event.
    NamespaceCreate,
    /// Linux namespace join event.
    NamespaceJoin,
}

/// Evidence grading for observed eBPF desktop events.
///
/// Every observed event is classified into one of these grades by the
/// telemetry classifier. The grade determines downstream action:
/// audit-only, elevation to policy kernel, or immediate blocking.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCountMacro,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EbpfEvidenceGrade {
    /// Event is verified benign — record for audit.
    Verified,
    /// Event is suspicious — elevate to policy kernel for decision.
    Suspicious,
    /// Event is a policy violation — block the action.
    Blocked,
    /// Event is recorded for audit purposes only (no action taken).
    AuditOnly,
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
    clippy::match_same_arms
)]
mod tests {
    use super::*;
    use strum::{EnumCount, IntoEnumIterator};

    #[test]
    fn ebpf_program_type_variant_count() {
        assert_eq!(EbpfProgramType::COUNT, 6);
    }

    #[test]
    fn ebpf_program_state_variant_count() {
        assert_eq!(EbpfProgramState::COUNT, 6);
    }

    #[test]
    fn ebpf_author_role_variant_count() {
        assert_eq!(EbpfAuthorRole::COUNT, 3);
    }

    #[test]
    fn desktop_event_class_variant_count() {
        assert_eq!(DesktopEventClass::COUNT, 10);
    }

    #[test]
    fn ebpf_evidence_grade_variant_count() {
        assert_eq!(EbpfEvidenceGrade::COUNT, 4);
    }

    #[test]
    fn desktop_event_class_from_str_roundtrip() {
        let pairs = [
            ("PROCESS_EXEC", DesktopEventClass::ProcessExec),
            ("PROCESS_EXIT", DesktopEventClass::ProcessExit),
            ("NETWORK_FLOW", DesktopEventClass::NetworkFlow),
            ("GPU_BUFFER", DesktopEventClass::GpuBuffer),
            ("WAYLAND_PROTOCOL", DesktopEventClass::WaylandProtocol),
            ("FILE_ACCESS", DesktopEventClass::FileAccess),
            ("SELINUX_AVC", DesktopEventClass::SelinuxAvc),
            ("CAPABILITY_USE", DesktopEventClass::CapabilityUse),
            ("NAMESPACE_CREATE", DesktopEventClass::NamespaceCreate),
            ("NAMESPACE_JOIN", DesktopEventClass::NamespaceJoin),
        ];
        for (expected_str, variant) in &pairs {
            let serialized = serde_json::to_string(variant).expect("serialize");
            assert_eq!(
                serialized,
                format!("\"{expected_str}\""),
                "variant {variant:?}"
            );
            let back: DesktopEventClass =
                serde_json::from_str(&serialized).expect("deserialize");
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn ebpf_program_type_iter_all() {
        let variants: Vec<_> = EbpfProgramType::iter().collect();
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn ebpf_program_state_iter_all() {
        let variants: Vec<_> = EbpfProgramState::iter().collect();
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn ebpf_author_role_iter_all() {
        let variants: Vec<_> = EbpfAuthorRole::iter().collect();
        assert_eq!(variants.len(), 3);
    }

    #[test]
    fn desktop_event_class_iter_all() {
        let variants: Vec<_> = DesktopEventClass::iter().collect();
        assert_eq!(variants.len(), 10);
    }

    #[test]
    fn ebpf_evidence_grade_iter_all() {
        let variants: Vec<_> = EbpfEvidenceGrade::iter().collect();
        assert_eq!(variants.len(), 4);
    }

    #[test]
    fn serde_roundtrip_all_ebpf_program_types() {
        for v in EbpfProgramType::iter() {
            let json = serde_json::to_string(&v).expect("serialize");
            let back: EbpfProgramType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn serde_roundtrip_all_ebpf_program_states() {
        for v in EbpfProgramState::iter() {
            let json = serde_json::to_string(&v).expect("serialize");
            let back: EbpfProgramState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn serde_roundtrip_all_ebpf_author_roles() {
        for v in EbpfAuthorRole::iter() {
            let json = serde_json::to_string(&v).expect("serialize");
            let back: EbpfAuthorRole = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn serde_roundtrip_all_desktop_event_classes() {
        for v in DesktopEventClass::iter() {
            let json = serde_json::to_string(&v).expect("serialize");
            let back: DesktopEventClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn serde_roundtrip_all_evidence_grades() {
        for v in EbpfEvidenceGrade::iter() {
            let json = serde_json::to_string(&v).expect("serialize");
            let back: EbpfEvidenceGrade = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, back);
        }
    }
}
