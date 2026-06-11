//! Evidence emission for eBPF Desktop Telemetry (Rev.6).
//!
//! [`EbpfEvidenceEmitter`] is the trait that bridges the eBPF telemetry subsystem
//! with the AIOS Evidence Log. Implementations record lifecycle events (program
//! loaded/attached/detached) and desktop observations (process exec, network flow,
//! GPU buffer, etc.) into the append-only evidence chain.
//!
//! The [`InMemoryEbpfEvidenceEmitter`] is a test/demo implementation that stores
//! records in a `Vec`. Production deployment would use an implementation that
//! writes to the RocksDB-backed evidence log via gRPC.

use std::fmt;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::desktop_event::DesktopEvent;
use crate::enums::{DesktopEventClass, EbpfEvidenceGrade};

/// Record types emitted by the eBPF telemetry subsystem.
///
/// Each variant corresponds to a lifecycle or observation event that should be
/// recorded in the AIOS Evidence Log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EbpfEvidenceRecord {
    /// A BPF program was loaded into the kernel.
    EbpfProgramLoaded {
        /// The ULID of the program that was loaded.
        program_id: String,
        /// The BLAKE3 hash of the BPF bytecode (hex-encoded).
        program_hash: String,
        /// UTC timestamp of the load operation.
        timestamp: DateTime<Utc>,
    },

    /// A BPF program was attached to a kernel hook point.
    EbpfProgramAttached {
        /// The ULID of the program that was attached.
        program_id: String,
        /// Kernel hook point (syscall, tracepoint, kprobe name).
        attached_to: String,
        /// UTC timestamp of the attach operation.
        timestamp: DateTime<Utc>,
    },

    /// A BPF program was detached from its kernel hook point.
    EbpfProgramDetached {
        /// The ULID of the program that was detached.
        program_id: String,
        /// UTC timestamp of the detach operation.
        timestamp: DateTime<Utc>,
    },

    /// A desktop telemetry event was observed.
    DesktopEventObserved {
        /// The observed event.
        event: DesktopEvent,
    },

    /// Desktop telemetry collection started.
    DesktopTelemetryStarted {
        /// The ULID of the collector that started.
        collector_id: String,
        /// The number of programs attached for telemetry.
        attached_program_count: usize,
        /// UTC timestamp of the start.
        timestamp: DateTime<Utc>,
    },

    /// Desktop telemetry collection stopped.
    DesktopTelemetryStopped {
        /// The ULID of the collector that stopped.
        collector_id: String,
        /// The number of programs detached.
        detached_program_count: usize,
        /// UTC timestamp of the stop.
        timestamp: DateTime<Utc>,
    },

    /// An AI author was rejected from managing eBPF (INV-025 enforcement).
    EbpfProgramRejectedAiAuthor {
        /// The AI subject that was rejected.
        subject: String,
        /// What operation was attempted.
        operation: String,
        /// The ULID of the program that was targeted.
        program_id: String,
        /// UTC timestamp of the rejection.
        timestamp: DateTime<Utc>,
    },

    /// A desktop event triggered a block action.
    DesktopEventBlocked {
        /// The event that was blocked.
        event: DesktopEvent,
        /// The reason for blocking.
        reason: String,
    },
}

impl fmt::Display for EbpfEvidenceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EbpfProgramLoaded {
                program_id,
                program_hash,
                timestamp,
            } => write!(
                f,
                "EbpfProgramLoaded(program_id={program_id}, hash={program_hash}, ts={timestamp})"
            ),
            Self::EbpfProgramAttached {
                program_id,
                attached_to,
                timestamp,
            } => write!(
                f,
                "EbpfProgramAttached(program_id={program_id}, hook={attached_to}, ts={timestamp})"
            ),
            Self::EbpfProgramDetached {
                program_id,
                timestamp,
            } => write!(
                f,
                "EbpfProgramDetached(program_id={program_id}, ts={timestamp})"
            ),
            Self::DesktopEventObserved { event } => {
                write!(
                    f,
                    "DesktopEventObserved(id={}, class={:?}, pid={})",
                    event.event_id, event.event_class, event.subject_pid
                )
            }
            Self::DesktopTelemetryStarted {
                collector_id,
                attached_program_count,
                timestamp,
            } => write!(
                f,
                "DesktopTelemetryStarted(collector={collector_id}, programs={attached_program_count}, ts={timestamp})"
            ),
            Self::DesktopTelemetryStopped {
                collector_id,
                detached_program_count,
                timestamp,
            } => write!(
                f,
                "DesktopTelemetryStopped(collector={collector_id}, programs={detached_program_count}, ts={timestamp})"
            ),
            Self::EbpfProgramRejectedAiAuthor {
                subject,
                operation,
                program_id,
                timestamp,
            } => write!(
                f,
                "EbpfProgramRejectedAiAuthor(subject={subject}, op={operation}, program={program_id}, ts={timestamp})"
            ),
            Self::DesktopEventBlocked { event, reason } => {
                write!(
                    f,
                    "DesktopEventBlocked(id={}, class={:?}, reason={reason})",
                    event.event_id, event.event_class
                )
            }
        }
    }
}

/// Trait for emitting eBPF telemetry evidence records.
///
/// Implementations bridge the eBPF subsystem with the AIOS Evidence Log (RocksDB
/// backend via gRPC). The trait is object-safe so it can be stored as
/// `Arc<dyn EbpfEvidenceEmitter>`.
pub trait EbpfEvidenceEmitter: Send + Sync {
    /// Emit a single evidence record to the log.
    fn emit(&self, record: EbpfEvidenceRecord);

    /// Drain all pending records (for batch flush).
    fn drain(&self) -> Vec<EbpfEvidenceRecord>;

    /// Return the number of records emitted since creation or last drain.
    fn record_count(&self) -> usize;
}

/// In-memory evidence emitter for test and demonstration use.
///
/// Stores all emitted records in a `Vec` protected by a `Mutex`. Not suitable
/// for production (no durability, no chain integrity). Production deployments
/// should use the gRPC-backed emitter that writes to the RocksDB evidence log.
pub struct InMemoryEbpfEvidenceEmitter {
    records: Mutex<Vec<EbpfEvidenceRecord>>,
}

impl InMemoryEbpfEvidenceEmitter {
    /// Create a new empty in-memory emitter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
        }
    }

    /// Create an `Arc<Self>` for shared ownership.
    #[must_use]
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

impl Default for InMemoryEbpfEvidenceEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfEvidenceEmitter for InMemoryEbpfEvidenceEmitter {
    fn emit(&self, record: EbpfEvidenceRecord) {
        if let Ok(mut guard) = self.records.lock() {
            guard.push(record);
        }
    }

    fn drain(&self) -> Vec<EbpfEvidenceRecord> {
        if let Ok(mut guard) = self.records.lock() {
            std::mem::take(&mut *guard)
        } else {
            Vec::new()
        }
    }

    fn record_count(&self) -> usize {
        self.records
            .lock()
            .map(|guard| guard.len())
            .unwrap_or(0)
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
    fn evidence_emitter_fires_on_load() {
        let emitter = InMemoryEbpfEvidenceEmitter::new();
        emitter.emit(EbpfEvidenceRecord::EbpfProgramLoaded {
            program_id: "01HABC".into(),
            program_hash: "abcdef".into(),
            timestamp: Utc::now(),
        });
        assert_eq!(emitter.record_count(), 1);
        let records = emitter.drain();
        assert_eq!(records.len(), 1);
        matches!(
            &records[0],
            EbpfEvidenceRecord::EbpfProgramLoaded { .. }
        );
        // After drain, count is zero.
        assert_eq!(emitter.record_count(), 0);
    }

    #[test]
    fn evidence_emitter_fires_on_attach() {
        let emitter = InMemoryEbpfEvidenceEmitter::new();
        emitter.emit(EbpfEvidenceRecord::EbpfProgramAttached {
            program_id: "01HDEF".into(),
            attached_to: "sys_enter_execve".into(),
            timestamp: Utc::now(),
        });
        assert_eq!(emitter.record_count(), 1);
        let records = emitter.drain();
        matches!(
            &records[0],
            EbpfEvidenceRecord::EbpfProgramAttached { .. }
        );
    }

    #[test]
    fn evidence_emitter_fires_on_detach() {
        let emitter = InMemoryEbpfEvidenceEmitter::new();
        emitter.emit(EbpfEvidenceRecord::EbpfProgramDetached {
            program_id: "01HGHI".into(),
            timestamp: Utc::now(),
        });
        let records = emitter.drain();
        assert_eq!(records.len(), 1);
        matches!(
            &records[0],
            EbpfEvidenceRecord::EbpfProgramDetached { .. }
        );
    }

    #[test]
    fn evidence_emitter_fires_on_event() {
        let emitter = InMemoryEbpfEvidenceEmitter::new();
        let event = DesktopEvent::new(
            DesktopEventClass::ProcessExec,
            42,
            "bash",
            r#"{"filename":"/bin/bash"}"#,
        );
        emitter.emit(EbpfEvidenceRecord::DesktopEventObserved {
            event: event.clone(),
        });
        let records = emitter.drain();
        assert_eq!(records.len(), 1);
        matches!(
            &records[0],
            EbpfEvidenceRecord::DesktopEventObserved { .. }
        );
    }

    #[test]
    fn evidence_emitter_multiple_records() {
        let emitter = InMemoryEbpfEvidenceEmitter::new();
        for i in 0..10 {
            emitter.emit(EbpfEvidenceRecord::EbpfProgramLoaded {
                program_id: format!("01H{i:04X}"),
                program_hash: format!("hash_{i}"),
                timestamp: Utc::now(),
            });
        }
        assert_eq!(emitter.record_count(), 10);
        let records = emitter.drain();
        assert_eq!(records.len(), 10);
    }

    #[test]
    fn evidence_emitter_shared_works() {
        let emitter = InMemoryEbpfEvidenceEmitter::new_shared();
        let e2 = emitter.clone();
        e2.emit(EbpfEvidenceRecord::EbpfProgramLoaded {
            program_id: "shared".into(),
            program_hash: "shared_hash".into(),
            timestamp: Utc::now(),
        });
        assert_eq!(emitter.record_count(), 1);
    }

    #[test]
    fn evidence_record_display_formatting() {
        let record = EbpfEvidenceRecord::EbpfProgramRejectedAiAuthor {
            subject: "ai:gpt-5".into(),
            operation: "load".into(),
            program_id: "01HREJ".into(),
            timestamp: Utc::now(),
        };
        let s = record.to_string();
        assert!(s.contains("RejectedAiAuthor"));
        assert!(s.contains("ai:gpt-5"));
        assert!(s.contains("load"));
    }

    #[test]
    fn desktop_event_blocked_record_serializes() {
        let event = DesktopEvent::new(
            DesktopEventClass::ProcessExec,
            999,
            "evil",
            r#"{"filename":"/tmp/malware"}"#,
        )
        .with_evidence_grade(EbpfEvidenceGrade::Blocked);
        let record = EbpfEvidenceRecord::DesktopEventBlocked {
            event: event.clone(),
            reason: "unknown binary".into(),
        };
        let s = record.to_string();
        assert!(s.contains("Blocked"));
        assert!(s.contains("unknown binary"));

        let json = serde_json::to_value(&record).expect("serialize");
        let back: EbpfEvidenceRecord = serde_json::from_value(json).expect("deserialize");
        assert_eq!(
            format!("{back:?}"),
            format!("{record:?}")
        );
    }

    #[test]
    fn constructor_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryEbpfEvidenceEmitter>();
    }
}
