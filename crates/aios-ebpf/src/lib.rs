//! `aios-ebpf` — eBPF Desktop Telemetry Foundation for AI-OS.NET (Rev.6).
//!
//! ## Overview
//!
//! This crate implements the **Rev.6 eBPF Desktop Telemetry Foundation**:
//!
//! - **Program Registry** — lifecycle management for BPF programs (register, load, attach, detach).
//! - **Desktop Telemetry Collector** — polls BPF ring buffers for desktop session events.
//! - **Desktop Event Types** — process exec/exit, network flows, GPU buffers, Wayland protocol,
//!   file access, SELinux AVCs, capability use, namespace create/join.
//! - **INV-025 Enforcement** — AI subjects can NEVER manage eBPF programs.
//! - **Evidence Emission** — lifecycle and observation events flow to the AIOS Evidence Log.
//!
//! ## Loading BPF programs
//!
//! This crate does NOT depend on `libbpf-rs` or `aya`. Instead, BPF programs are
//! loaded via the `bpftool` CLI (described in module-level comments):
//!
//! ```bash
//! bpftool prog load <object.o> /sys/fs/bpf/<name> type <type>
//! bpftool prog attach pinned /sys/fs/bpf/<name> <attach_type>
//! ```
//!
//! ## INV-025 constitutional rule
//!
//! AI subjects (`AiProposedNever` author role) are rejected at registration time.
//! AI subjects cannot call `load`, `attach`, or `detach` — only `SYSTEM_SERVICE` or
//! `HUMAN_OPERATOR` can manage BPF programs.

#![forbid(unsafe_code)]

pub mod desktop_event;
pub mod desktop_telemetry;
pub mod enums;
pub mod error;
pub mod evidence;
pub mod inv025_enforcement;
pub mod program_registry;

// Re-exports for convenient access
pub use desktop_event::DesktopEvent;
pub use desktop_telemetry::{DesktopEventBuffer, DesktopTelemetryCollector};
pub use enums::{
    DesktopEventClass, EbpfAuthorRole, EbpfEvidenceGrade, EbpfProgramState, EbpfProgramType,
};
pub use error::{EbpfError, EbpfResult};
pub use evidence::{
    EbpfEvidenceEmitter, EbpfEvidenceRecord, InMemoryEbpfEvidenceEmitter,
};
pub use inv025_enforcement::{
    EbpfSignature, EbpfSubject, enforce_ai_author_role,
    enforce_inv025, enforce_signature_chain_present,
    enforce_valid_state_transition, is_drop_only_template,
};
pub use program_registry::{EbpfProgramDescriptor, EbpfProgramRegistry, ProgramId};
