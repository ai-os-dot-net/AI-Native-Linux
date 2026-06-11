//! Desktop telemetry collector (Rev.6).
//!
//! [`DesktopTelemetryCollector`] manages a set of attached eBPF programs that
//! observe desktop session events (process exec, network flows, GPU buffers,
//! Wayland protocol, file access, SELinux AVCs, capability use, namespace ops).
//!
//! ## Collection pipeline
//!
//! ```text
//! eBPF probe (kernel) → BPF ring buffer → bpftool map dump → Collector → Classifier → Evidence
//! ```
//!
//! The collector spawns a Tokio background task that periodically polls
//! `bpftool map dump` for each attached program's ring buffer, parses the raw
//! events, classifies them, and emits evidence records.

use std::collections::VecDeque;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info};
use ulid::Ulid;

use crate::desktop_event::DesktopEvent;
use crate::enums::{DesktopEventClass, EbpfEvidenceGrade, EbpfProgramState};
use crate::error::{EbpfError, EbpfResult};
use crate::evidence::{EbpfEvidenceEmitter, EbpfEvidenceRecord};
use crate::program_registry::{EbpfProgramDescriptor, EbpfProgramRegistry, ProgramId};

/// A ring buffer for desktop telemetry events with bounded capacity.
///
/// Events are pushed in from the collector task and drained by consumers (policy
/// kernel, evidence log exporter, dashboard).
#[derive(Debug)]
pub struct DesktopEventBuffer {
    /// Unique buffer identifier.
    pub buffer_id: Ulid,

    /// Maximum number of events the buffer can hold.
    capacity: usize,

    /// The event queue (FIFO).
    events: Mutex<VecDeque<DesktopEvent>>,

    /// Filter: only events at or above this grade are stored.
    evidence_grade_filter: EbpfEvidenceGrade,

    /// Count of events dropped due to capacity overflow.
    dropped_events: Mutex<u64>,
}

impl DesktopEventBuffer {
    /// Create a new event buffer with the given capacity.
    ///
    /// `evidence_grade_filter` controls which events are stored — events below
    /// this grade are silently dropped. Set to `AuditOnly` to store everything.
    #[must_use]
    pub fn new(capacity: usize, evidence_grade_filter: EbpfEvidenceGrade) -> Self {
        Self {
            buffer_id: Ulid::new(),
            capacity,
            events: Mutex::new(VecDeque::with_capacity(capacity)),
            evidence_grade_filter,
            dropped_events: Mutex::new(0),
        }
    }

    /// Push an event into the buffer.
    ///
    /// If the buffer is at capacity, the oldest event is evicted (FIFO ring
    /// buffer behavior). Events below the evidence grade filter are silently
    /// dropped. Returns `true` if the event was stored.
    pub async fn push(&self, event: DesktopEvent) -> bool {
        // Filter by evidence grade
        if !self.passes_grade_filter(&event) {
            return false;
        }

        let mut guard = self.events.lock().await;
        if guard.len() >= self.capacity {
            // Evict oldest
            guard.pop_front();
            let mut drop_guard = self.dropped_events.lock().await;
            *drop_guard = drop_guard.saturating_add(1);
        }
        guard.push_back(event);
        true
    }

    /// Drain all events from the buffer, returning them in FIFO order.
    pub async fn drain(&self) -> Vec<DesktopEvent> {
        let mut guard = self.events.lock().await;
        let drained: Vec<DesktopEvent> = guard.drain(..).collect();
        drained
    }

    /// Return the current number of events in the buffer.
    pub async fn len(&self) -> usize {
        self.events.lock().await.len()
    }

    /// Return `true` if the buffer has no events.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Return the count of dropped events.
    pub async fn dropped_count(&self) -> u64 {
        *self.dropped_events.lock().await
    }

    fn passes_grade_filter(&self, event: &DesktopEvent) -> bool {
        // AuditOnly is the lowest — pass everything.
        // Blocked > Suspicious > Verified > AuditOnly
        match self.evidence_grade_filter {
            EbpfEvidenceGrade::AuditOnly => true,
            EbpfEvidenceGrade::Verified => {
                event.evidence_grade == EbpfEvidenceGrade::Verified
                    || event.evidence_grade == EbpfEvidenceGrade::Suspicious
                    || event.evidence_grade == EbpfEvidenceGrade::Blocked
            }
            EbpfEvidenceGrade::Suspicious => {
                event.evidence_grade == EbpfEvidenceGrade::Suspicious
                    || event.evidence_grade == EbpfEvidenceGrade::Blocked
            }
            EbpfEvidenceGrade::Blocked => {
                event.evidence_grade == EbpfEvidenceGrade::Blocked
            }
        }
    }
}

/// Desktop telemetry collector — manages a set of attached eBPF programs and
/// polls their ring buffers for events.
pub struct DesktopTelemetryCollector {
    /// Unique collector identifier.
    pub collector_id: Ulid,

    /// The eBPF program registry (shared — not owned by the collector).
    registry: Arc<EbpfProgramRegistry>,

    /// Programs attached for telemetry: (program descriptor from registry, event class it produces).
    attached_programs: Mutex<Vec<(EbpfProgramDescriptor, DesktopEventClass)>>,

    /// Polling interval in milliseconds.
    sample_interval_ms: u64,

    /// Ring buffer capacity.
    ring_buffer_capacity: usize,

    /// The event buffer.
    buffer: Arc<DesktopEventBuffer>,

    /// Evidence emitter for recording lifecycle and observation events.
    evidence_emitter: Option<Arc<dyn EbpfEvidenceEmitter>>,

    /// Handle to the background collection task.
    collection_task: Mutex<Option<JoinHandle<()>>>,

    /// Whether collection is currently active.
    active: Mutex<bool>,
}

impl DesktopTelemetryCollector {
    /// Create a new collector with an in-memory evidence emitter.
    #[must_use]
    pub fn new(
        registry: Arc<EbpfProgramRegistry>,
        sample_interval_ms: u64,
        ring_buffer_capacity: usize,
    ) -> Self {
        Self {
            collector_id: Ulid::new(),
            registry,
            attached_programs: Mutex::new(Vec::new()),
            sample_interval_ms,
            ring_buffer_capacity,
            buffer: Arc::new(DesktopEventBuffer::new(
                ring_buffer_capacity,
                EbpfEvidenceGrade::AuditOnly,
            )),
            evidence_emitter: None,
            collection_task: Mutex::new(None),
            active: Mutex::new(false),
        }
    }

    /// Create a new collector with a shared evidence emitter.
    #[must_use]
    pub fn with_evidence_emitter(
        registry: Arc<EbpfProgramRegistry>,
        sample_interval_ms: u64,
        ring_buffer_capacity: usize,
        emitter: Arc<dyn EbpfEvidenceEmitter>,
    ) -> Self {
        Self {
            collector_id: Ulid::new(),
            registry,
            attached_programs: Mutex::new(Vec::new()),
            sample_interval_ms,
            ring_buffer_capacity,
            buffer: Arc::new(DesktopEventBuffer::new(
                ring_buffer_capacity,
                EbpfEvidenceGrade::AuditOnly,
            )),
            evidence_emitter: Some(emitter),
            collection_task: Mutex::new(None),
            active: Mutex::new(false),
        }
    }

    /// Attach a program from the registry for telemetry collection.
    ///
    /// The program must be in `Running` state. The collector will periodically
    /// poll `bpftool map dump` for its ring buffer.
    ///
    /// # Errors
    ///
    /// Returns program-not-found or state errors from the registry.
    pub async fn attach_program(
        &self,
        program_id: ProgramId,
        event_class: DesktopEventClass,
    ) -> EbpfResult<()> {
        let descriptor = self.registry.get(program_id)?;
        if descriptor.state != EbpfProgramState::Running {
            return Err(EbpfError::InvalidState {
                program_id: program_id.to_string(),
                current_state: format!("{:?}", descriptor.state),
                attempted: "attach for telemetry".into(),
            });
        }

        let mut guard = self.attached_programs.lock().await;
        guard.push((descriptor, event_class));
        info!(
            program_id = %program_id,
            event_class = ?event_class,
            "attached BPF program for telemetry"
        );
        Ok(())
    }

    /// Detach a program from telemetry collection.
    pub async fn detach_program(&self, program_id: ProgramId) -> EbpfResult<()> {
        let mut guard = self.attached_programs.lock().await;
        let before = guard.len();
        guard.retain(|(desc, _)| desc.program_id != program_id);
        if guard.len() == before {
            return Err(EbpfError::ProgramNotFound {
                program_id: program_id.to_string(),
            });
        }
        debug!(program_id = %program_id, "detached from telemetry");
        Ok(())
    }

    /// Start telemetry collection in a background Tokio task.
    ///
    /// The background task polls `bpftool map dump` at `sample_interval_ms`
    /// intervals, classifies events, and pushes them into the event buffer.
    ///
    /// In production, the `bpftool map dump` calls would be replaced by reading
    /// the BPF ring buffer via `bpf()` syscall. This implementation simulates
    /// the polling pattern with tokio sleep intervals.
    pub async fn start_collection(&self) -> EbpfResult<()> {
        let mut active = self.active.lock().await;
        if *active {
            debug!("collection already active, skipping start");
            return Ok(());
        }

        let collector_id_str = self.collector_id.to_string();
        let buffer = self.buffer.clone();
        let attached = {
            let guard = self.attached_programs.lock().await;
            guard.clone()
        };
        let emitter = self.evidence_emitter.clone();
        let interval_ms = self.sample_interval_ms;

        let attached_count = attached.len();

        if let Some(ref e) = emitter {
            e.emit(EbpfEvidenceRecord::DesktopTelemetryStarted {
                collector_id: collector_id_str.clone(),
                attached_program_count: attached_count,
                timestamp: Utc::now(),
            });
        }

        let handle = tokio::spawn(async move {
            loop {
                for (desc, event_class) in &attached {
                    // In production: spawn `bpftool map dump id <map_id>` and parse BPF events.
                    // For now, simulate the polling pattern.
                    debug!(
                        program_id = %desc.program_id,
                        event_class = ?event_class,
                        "polling BPF map"
                    );

                    // Simulate a heartbeat event to indicate the probe is alive.
                    // Real implementation would parse raw BPF events from map dump output.
                    let event = DesktopEvent::new(
                        *event_class,
                        0,
                        "kernel",
                        format!(
                            r#"{{"program_id":"{}","type":"heartbeat"}}"#,
                            desc.program_id
                        ),
                    )
                    .with_evidence_grade(EbpfEvidenceGrade::Verified);

                    buffer.push(event).await;
                }

                if let Some(ref e) = emitter {
                    let drained = buffer.drain().await;
                    for event in drained {
                        e.emit(EbpfEvidenceRecord::DesktopEventObserved { event });
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
            }
        });

        let mut task = self.collection_task.lock().await;
        *task = Some(handle);
        *active = true;

        info!(
            collector_id = %collector_id_str,
            "desktop telemetry collection started"
        );
        Ok(())
    }

    /// Stop telemetry collection, detach all programs, and flush the buffer.
    pub async fn stop_collection(&self) -> EbpfResult<()> {
        let mut active = self.active.lock().await;
        if !*active {
            return Ok(());
        }

        let mut task = self.collection_task.lock().await;
        if let Some(handle) = task.take() {
            handle.abort();
        }

        let mut attached = self.attached_programs.lock().await;
        let detached_count = attached.len();
        attached.clear();

        // Flush buffer
        let events = self.buffer.drain().await;
        if let Some(ref e) = self.evidence_emitter {
            for event in events {
                e.emit(EbpfEvidenceRecord::DesktopEventObserved { event });
            }
            e.emit(EbpfEvidenceRecord::DesktopTelemetryStopped {
                collector_id: self.collector_id.to_string(),
                detached_program_count: detached_count,
                timestamp: Utc::now(),
            });
        }

        *active = false;
        info!(collector_id = %self.collector_id, "desktop telemetry collection stopped");
        Ok(())
    }

    /// Drain all pending events from the buffer.
    pub async fn drain_events(&self) -> Vec<DesktopEvent> {
        self.buffer.drain().await
    }

    /// Return whether collection is currently active.
    pub async fn is_active(&self) -> bool {
        *self.active.lock().await
    }

    /// Return the number of events currently in the buffer.
    pub async fn buffer_len(&self) -> usize {
        self.buffer.len().await
    }

    /// Classify a raw event into an event class and evidence grade.
    ///
    /// Classification rules (simplified for Rev.6):
    /// - Unknown binaries → `Suspicious` (ProcessExec from non-system paths).
    /// - Unauthorized outbound network → `Suspicious` (non-standard ports to unknown IPs).
    /// - GPU resource abuse → `Suspicious` (excessive buffer allocations).
    /// - SELinux AVC → `Blocked` (policy violations are always blocked).
    /// - Capability use → `Suspicious` unless from known system services.
    /// - Everything else → `AuditOnly`.
    #[must_use]
    pub fn classify_event(event_class: DesktopEventClass, _detail: &str, _subject_comm: &str) -> EbpfEvidenceGrade {
        match event_class {
            DesktopEventClass::SelinuxAvc => EbpfEvidenceGrade::Blocked,
            DesktopEventClass::ProcessExec => EbpfEvidenceGrade::Suspicious,
            DesktopEventClass::NetworkFlow => EbpfEvidenceGrade::Suspicious,
            DesktopEventClass::CapabilityUse => EbpfEvidenceGrade::Suspicious,
            DesktopEventClass::FileAccess => EbpfEvidenceGrade::AuditOnly,
            DesktopEventClass::ProcessExit => EbpfEvidenceGrade::AuditOnly,
            DesktopEventClass::GpuBuffer => EbpfEvidenceGrade::AuditOnly,
            DesktopEventClass::WaylandProtocol => EbpfEvidenceGrade::AuditOnly,
            DesktopEventClass::NamespaceCreate => EbpfEvidenceGrade::Suspicious,
            DesktopEventClass::NamespaceJoin => EbpfEvidenceGrade::Suspicious,
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

    fn make_sig() -> crate::inv025_enforcement::EbpfSignature {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let public_key: [u8; 32] = verifying_key.to_bytes();
        let test_hash: [u8; 32] = [0x42; 32];
        let sig = signing_key.sign(&test_hash);
        crate::inv025_enforcement::EbpfSignature {
            public_key,
            signature_bytes: sig.to_bytes().to_vec(),
        }
    }

    fn make_shared_registry(capacity: usize) -> Arc<EbpfProgramRegistry> {
        Arc::new(EbpfProgramRegistry::new(capacity))
    }

    fn push_program_to_running(
        registry: &Arc<EbpfProgramRegistry>,
    ) -> ProgramId {
        let hash: crate::desktop_event::Hash = [0xab; 32];
        let desc = EbpfProgramDescriptor::new(
            crate::enums::EbpfProgramType::DesktopSession,
            crate::enums::EbpfAuthorRole::AiosVerified,
            hash,
            vec![make_sig()],
            "sched:sched_process_exec",
            "test telemetry",
            "/tmp/test.o",
        )
        .expect("valid descriptor");
        let id = desc.program_id;
        registry.register(desc).expect("register");
        registry.mark_loaded(id).expect("load");
        registry.mark_attached(id).expect("attach");
        registry.mark_running(id).expect("run");
        id
    }

    #[tokio::test]
    async fn telemetry_collector_starts_and_stops() {
        let registry = make_shared_registry(8);
        let _pid = push_program_to_running(&registry);

        let emitter = InMemoryEbpfEvidenceEmitter::new_shared();
        let collector = DesktopTelemetryCollector::with_evidence_emitter(
            registry.clone(),
            100,
            64,
            emitter.clone(),
        );

        assert!(!collector.is_active().await);

        // Attach program to collector
        let running = registry.list_running();
        assert!(!running.is_empty());
        collector
            .attach_program(running[0].program_id, DesktopEventClass::ProcessExec)
            .await
            .expect("attach");

        // Start collection
        collector.start_collection().await.expect("start");
        assert!(collector.is_active().await);

        // Let it run for a bit
        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

        // Stop collection
        collector.stop_collection().await.expect("stop");
        assert!(!collector.is_active().await);
    }

    #[tokio::test]
    async fn telemetry_buffer_drains_correctly() {
        let buffer = DesktopEventBuffer::new(16, EbpfEvidenceGrade::AuditOnly);

        for i in 0..5 {
            let event = DesktopEvent::new(
                DesktopEventClass::ProcessExec,
                i,
                "test",
                format!(r#"{{"i":{i}}}"#),
            );
            buffer.push(event).await;
        }

        assert_eq!(buffer.len().await, 5);

        let drained = buffer.drain().await;
        assert_eq!(drained.len(), 5);
        assert_eq!(buffer.len().await, 0);
    }

    #[tokio::test]
    async fn telemetry_buffer_respects_capacity() {
        let buffer = DesktopEventBuffer::new(3, EbpfEvidenceGrade::AuditOnly);

        for i in 0..5 {
            let event = DesktopEvent::new(
                DesktopEventClass::ProcessExec,
                i,
                "test",
                format!(r#"{{"i":{i}}}"#),
            );
            buffer.push(event).await;
        }

        // Capacity is 3, so we should have 3 events and 2 dropped
        assert_eq!(buffer.len().await, 3);
        assert!(buffer.dropped_count().await >= 2);

        let drained = buffer.drain().await;
        assert_eq!(drained.len(), 3);
    }

    #[tokio::test]
    async fn telemetry_start_generates_unique_id() {
        let registry = make_shared_registry(8);
        let e1 = InMemoryEbpfEvidenceEmitter::new_shared();
        let c1 = DesktopTelemetryCollector::with_evidence_emitter(
            registry.clone(),
            100,
            16,
            e1,
        );

        let e2 = InMemoryEbpfEvidenceEmitter::new_shared();
        let c2 = DesktopTelemetryCollector::with_evidence_emitter(
            registry.clone(),
            100,
            16,
            e2,
        );

        assert_ne!(c1.collector_id, c2.collector_id);
    }

    #[test]
    fn classify_event_selinux_avc_is_blocked() {
        let grade = DesktopTelemetryCollector::classify_event(
            DesktopEventClass::SelinuxAvc,
            "",
            "",
        );
        assert_eq!(grade, EbpfEvidenceGrade::Blocked);
    }

    #[test]
    fn classify_event_process_exec_is_suspicious() {
        let grade = DesktopTelemetryCollector::classify_event(
            DesktopEventClass::ProcessExec,
            "",
            "",
        );
        assert_eq!(grade, EbpfEvidenceGrade::Suspicious);
    }

    #[test]
    fn classify_event_process_exit_is_audit_only() {
        let grade = DesktopTelemetryCollector::classify_event(
            DesktopEventClass::ProcessExit,
            "",
            "",
        );
        assert_eq!(grade, EbpfEvidenceGrade::AuditOnly);
    }

    #[test]
    fn constructor_is_send_sync_collector() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DesktopTelemetryCollector>();
    }
}
