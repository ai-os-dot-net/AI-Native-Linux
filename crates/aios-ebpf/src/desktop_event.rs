//! Desktop telemetry event record (Rev.6).
//!
//! [`DesktopEvent`] is the canonical event type observed by eBPF desktop session
//! probes. Each event carries a unique ULID, timestamp, classification, process
//! metadata, capsule context, and evidence grade.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::enums::{DesktopEventClass, EbpfEvidenceGrade};

/// Hash type alias — BLAKE3 32-byte output, used for binary integrity hashes.
pub type Hash = [u8; 32];

/// A single event observed by an eBPF desktop session probe.
///
/// Events flow through the telemetry pipeline:
/// eBPF probe → BPF ring buffer → `bpftool map dump` → collector → classifier → evidence.
///
/// Each event is timestamped at collection time with the host's monotonic clock,
/// carries the originating PID and comm string, and links back to a sandbox capsule
/// when the subject process runs inside one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopEvent {
    /// Unique event identifier (ULID — k-sortable, monotonically increasing).
    pub event_id: Ulid,

    /// Host-local timestamp when the event was observed (collected from BPF ring buffer).
    pub timestamp: DateTime<Utc>,

    /// What kind of desktop event this is (process exec, network flow, GPU buffer, etc.).
    pub event_class: DesktopEventClass,

    /// PID of the process that generated this event.
    pub subject_pid: u32,

    /// `comm` (16-char kernel task name) of the originating process.
    pub subject_comm: String,

    /// If the subject runs inside an AIOS sandbox capsule, the capsule's ULID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_capsule_id: Option<Ulid>,

    /// Event-specific detail as a JSON string.
    ///
    /// The schema of this field depends on [`Self::event_class`]:
    /// - `ProcessExec`: `{"filename": "/bin/bash", "argv": [...], "envp_count": 12}`
    /// - `NetworkFlow`: `{"saddr": "10.0.0.1", "dport": 443, "proto": "tcp"}`
    /// - `GpuBuffer`: `{"device": "/dev/dri/card0", "size_bytes": 16777216}`
    /// - `WaylandProtocol`: `{"interface": "wl_surface", "opcode": 3, "size": 128}`
    /// - `FileAccess`: `{"path": "/etc/shadow", "flags": "O_RDONLY"}`
    /// - `SelinuxAvc`: `{"scontext": "u:r:unconfined_t", "tcontext": "u:object_r:shadow_t"}`
    /// - `CapabilityUse`: `{"cap": "CAP_SYS_ADMIN", "audit": 1}`
    /// - `NamespaceCreate`: `{"type": "mnt", "new_ns_inode": 4026531841}`
    /// - `NamespaceJoin`: `{"type": "net", "target_ns_inode": 4026531840}`
    pub detail: String,

    /// Evidence grade assigned by the classifier.
    ///
    /// Defaults to [`EbpfEvidenceGrade::AuditOnly`] for events that pass all policies.
    pub evidence_grade: EbpfEvidenceGrade,

    /// SHA-256 hash of the binary on disk at collection time, if the event class
    /// involves a binary file (ProcessExec, FileAccess). Computed by the collector
    /// via `sha256sum` on the resolved inode path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_sha256: Option<Hash>,
}

impl DesktopEvent {
    /// Create a new `DesktopEvent` with a fresh ULID, the current UTC timestamp,
    /// and a default [`EbpfEvidenceGrade::AuditOnly`] grade.
    ///
    /// The caller must supply the event's class, PID, comm, and detail. The
    /// classifier will update `evidence_grade` after analysis.
    #[must_use]
    pub fn new(
        event_class: DesktopEventClass,
        subject_pid: u32,
        subject_comm: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_id: Ulid::new(),
            timestamp: Utc::now(),
            event_class,
            subject_pid,
            subject_comm: subject_comm.into(),
            subject_capsule_id: None,
            detail: detail.into(),
            evidence_grade: EbpfEvidenceGrade::AuditOnly,
            binary_sha256: None,
        }
    }

    /// Set the capsule ID for this event (used when the subject process runs inside
    /// a sandbox capsule).
    #[must_use]
    pub fn with_capsule_id(mut self, capsule_id: Ulid) -> Self {
        self.subject_capsule_id = Some(capsule_id);
        self
    }

    /// Set the evidence grade (called by the classifier after analysis).
    #[must_use]
    pub fn with_evidence_grade(mut self, grade: EbpfEvidenceGrade) -> Self {
        self.evidence_grade = grade;
        self
    }

    /// Record the SHA-256 hash of the subject binary.
    #[must_use]
    pub fn with_binary_sha256(mut self, sha256: Hash) -> Self {
        self.binary_sha256 = Some(sha256);
        self
    }

    /// Returns `true` if this event represents a policy violation (`Blocked` grade).
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.evidence_grade == EbpfEvidenceGrade::Blocked
    }

    /// Returns `true` if this event should be elevated to the policy kernel (`Suspicious` grade).
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.evidence_grade == EbpfEvidenceGrade::Suspicious
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
    clippy::match_same_arms
)]
mod tests {
    use super::*;

    #[test]
    fn desktop_event_defaults_to_audit_only() {
        let event = DesktopEvent::new(
            DesktopEventClass::ProcessExec,
            12345,
            "bash",
            r#"{"filename":"/bin/bash"}"#,
        );
        assert_eq!(event.subject_pid, 12345);
        assert_eq!(event.subject_comm, "bash");
        assert_eq!(event.evidence_grade, EbpfEvidenceGrade::AuditOnly);
        assert!(event.subject_capsule_id.is_none());
        assert!(event.binary_sha256.is_none());
    }

    #[test]
    fn desktop_event_binary_sha256_recorded() {
        let sha256: Hash = [0xab; 32];
        let event = DesktopEvent::new(
            DesktopEventClass::ProcessExec,
            42,
            "nginx",
            r#"{"filename":"/usr/sbin/nginx"}"#,
        )
        .with_binary_sha256(sha256);
        assert_eq!(event.binary_sha256, Some(sha256));
    }

    #[test]
    fn desktop_event_with_capsule_id() {
        let capsule = Ulid::new();
        let event = DesktopEvent::new(
            DesktopEventClass::FileAccess,
            54321,
            "firefox",
            r#"{"path":"/home/user/.mozilla/firefox/profiles.ini"}"#,
        )
        .with_capsule_id(capsule);
        assert_eq!(event.subject_capsule_id, Some(capsule));
    }

    #[test]
    fn desktop_event_with_evidence_grade() {
        let event = DesktopEvent::new(
            DesktopEventClass::NetworkFlow,
            8080,
            "curl",
            r#"{"saddr":"10.0.0.1","dport":443}"#,
        )
        .with_evidence_grade(EbpfEvidenceGrade::Suspicious);
        assert_eq!(event.evidence_grade, EbpfEvidenceGrade::Suspicious);
        assert!(event.is_suspicious());
        assert!(!event.is_blocked());
    }

    #[test]
    fn desktop_event_is_blocked() {
        let event = DesktopEvent::new(
            DesktopEventClass::ProcessExec,
            1,
            "malware",
            r#"{"filename":"/tmp/evil"}"#,
        )
        .with_evidence_grade(EbpfEvidenceGrade::Blocked);
        assert!(event.is_blocked());
    }

    #[test]
    fn desktop_event_is_not_blocked_by_default() {
        let event = DesktopEvent::new(
            DesktopEventClass::ProcessExec,
            1,
            "id",
            r#"{"filename":"/usr/bin/id"}"#,
        );
        assert!(!event.is_blocked());
        assert!(!event.is_suspicious());
    }

    #[test]
    fn desktop_event_unique_ids() {
        let e1 = DesktopEvent::new(DesktopEventClass::ProcessExec, 1, "a", "{}");
        let e2 = DesktopEvent::new(DesktopEventClass::ProcessExec, 2, "b", "{}");
        // ULIDs are monotonic and should differ within the same millisecond.
        assert_ne!(e1.event_id, e2.event_id);
    }

    #[test]
    fn desktop_event_serde_roundtrip() {
        let sha256: Hash = [0xcd; 32];
        let capsule = Ulid::new();
        let event = DesktopEvent::new(
            DesktopEventClass::CapabilityUse,
            9999,
            "dbus-daemon",
            r#"{"cap":"CAP_NET_RAW"}"#,
        )
        .with_capsule_id(capsule)
        .with_evidence_grade(EbpfEvidenceGrade::Verified)
        .with_binary_sha256(sha256);

        let json = serde_json::to_value(&event).expect("serialize");
        let back: DesktopEvent = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back.event_id, event.event_id);
        assert_eq!(back.event_class, DesktopEventClass::CapabilityUse);
        assert_eq!(back.subject_pid, 9999);
        assert_eq!(back.subject_comm, "dbus-daemon");
        assert_eq!(back.subject_capsule_id, Some(capsule));
        assert_eq!(back.evidence_grade, EbpfEvidenceGrade::Verified);
        assert_eq!(back.binary_sha256, Some(sha256));
    }

    #[test]
    fn desktop_event_builder_chain() {
        let sha256: Hash = [0xef; 32];
        let event = DesktopEvent::new(
            DesktopEventClass::WaylandProtocol,
            1122,
            "weston",
            r#"{"interface":"wl_surface","opcode":3}"#,
        )
        .with_evidence_grade(EbpfEvidenceGrade::Blocked)
        .with_binary_sha256(sha256);

        assert_eq!(event.subject_pid, 1122);
        assert!(event.is_blocked());
        assert_eq!(event.binary_sha256, Some(sha256));
    }
}
