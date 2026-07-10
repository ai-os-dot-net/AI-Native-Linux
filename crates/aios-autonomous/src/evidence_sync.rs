use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::AutonomousError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceEntry {
    pub host_id: String,
    pub hash: String,
    pub timestamp: String,
}

impl EvidenceEntry {
    pub fn new(host_id: String, hash: String, timestamp: String) -> Self {
        Self {
            host_id,
            hash,
            timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncReport {
    pub hosts_synced: usize,
    pub hosts_failed: usize,
    pub divergence_detected: bool,
    pub divergent_hosts: Vec<String>,
}

impl SyncReport {
    pub fn new(
        hosts_synced: usize,
        hosts_failed: usize,
        divergence_detected: bool,
        divergent_hosts: Vec<String>,
    ) -> Self {
        Self {
            hosts_synced,
            hosts_failed,
            divergence_detected,
            divergent_hosts,
        }
    }
}

pub struct CrossMachineEvidenceSync {
    pub host_chain_heads: HashMap<String, String>,
    pub sync_interval_secs: u64,
    evidence_log: Vec<EvidenceEntry>,
}

impl CrossMachineEvidenceSync {
    pub fn new() -> Self {
        Self {
            host_chain_heads: HashMap::new(),
            sync_interval_secs: 30,
            evidence_log: Vec::new(),
        }
    }

    pub fn register_host(&mut self, host_id: &str, head_hash: &str) {
        self.host_chain_heads
            .insert(host_id.to_string(), head_hash.to_string());
    }

    pub fn push_evidence(&mut self, host_id: &str, hash: &str) -> Result<(), AutonomousError> {
        if host_id.trim().is_empty() {
            return Err(AutonomousError::EvidenceSyncFailed {
                host_id: "(empty)".into(),
                reason: "host_id must not be empty".into(),
            });
        }
        if hash.trim().is_empty() {
            return Err(AutonomousError::EvidenceSyncFailed {
                host_id: host_id.into(),
                reason: "hash must not be empty".into(),
            });
        }

        let timestamp = chrono::Utc::now().to_rfc3339();
        let entry = EvidenceEntry::new(host_id.into(), hash.into(), timestamp);
        self.evidence_log.push(entry);

        self.host_chain_heads
            .insert(host_id.to_string(), hash.to_string());
        Ok(())
    }

    pub fn pull_evidence(&self, host_id: &str) -> Option<String> {
        self.host_chain_heads.get(host_id).cloned()
    }

    pub fn sync_fleet_evidence(&self) -> SyncReport {
        let total = self.host_chain_heads.len();
        if total == 0 {
            return SyncReport::new(0, 0, false, Vec::new());
        }

        let diverged = self.detect_divergence();
        let divergence_detected = !diverged.is_empty();
        let hosts_failed = 0usize;
        let hosts_synced = total.saturating_sub(hosts_failed);

        SyncReport::new(hosts_synced, hosts_failed, divergence_detected, diverged)
    }

    pub fn detect_divergence(&self) -> Vec<String> {
        if self.host_chain_heads.is_empty() {
            return Vec::new();
        }

        let mut hash_counts: HashMap<&str, usize> = HashMap::new();
        for hash in self.host_chain_heads.values() {
            *hash_counts.entry(hash.as_str()).or_insert(0) += 1;
        }

        let majority_hash = hash_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(hash, _)| *hash);

        match majority_hash {
            Some(majority) => self
                .host_chain_heads
                .iter()
                .filter(|(_, head)| head.as_str() != majority)
                .map(|(host_id, _)| host_id.clone())
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn fleet_audit_trail(&self) -> Vec<EvidenceEntry> {
        self.evidence_log.clone()
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence_log.len()
    }
}

impl Default for CrossMachineEvidenceSync {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_single_host() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.register_host("host-01", "abc123def");
        let head = sync.pull_evidence("host-01");
        assert_eq!(head.as_deref(), Some("abc123def"));
    }

    #[test]
    fn register_multiple_hosts() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.register_host("host-01", "hash-01");
        sync.register_host("host-02", "hash-02");
        sync.register_host("host-03", "hash-03");
        assert_eq!(sync.host_chain_heads.len(), 3);
        assert_eq!(sync.pull_evidence("host-01").as_deref(), Some("hash-01"));
        assert_eq!(sync.pull_evidence("host-02").as_deref(), Some("hash-02"));
    }

    #[test]
    fn register_overwrites_existing() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.register_host("host-01", "old-hash");
        sync.register_host("host-01", "new-hash");
        assert_eq!(sync.pull_evidence("host-01").as_deref(), Some("new-hash"));
    }

    #[test]
    fn register_unknown_host_returns_none() {
        let sync = CrossMachineEvidenceSync::new();
        assert_eq!(sync.pull_evidence("ghost-host"), None);
    }

    #[test]
    fn push_evidence_updates_head() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.register_host("host-01", "initial");
        let result = sync.push_evidence("host-01", "updated-hash");
        assert!(result.is_ok());
        assert_eq!(
            sync.pull_evidence("host-01").as_deref(),
            Some("updated-hash")
        );
    }

    #[test]
    fn push_evidence_rejects_empty_host_id() {
        let mut sync = CrossMachineEvidenceSync::new();
        let result = sync.push_evidence("", "some-hash");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("host_id must not be empty"));
    }

    #[test]
    fn push_evidence_rejects_empty_hash() {
        let mut sync = CrossMachineEvidenceSync::new();
        let result = sync.push_evidence("host-01", "");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("hash must not be empty"));
    }

    #[test]
    fn push_evidence_auto_registers_host() {
        let mut sync = CrossMachineEvidenceSync::new();
        let result = sync.push_evidence("new-host", "its-hash");
        assert!(result.is_ok());
        assert_eq!(sync.pull_evidence("new-host").as_deref(), Some("its-hash"));
    }

    #[test]
    fn push_evidence_appends_audit_trail() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.push_evidence("host-01", "hash-1").unwrap();
        sync.push_evidence("host-01", "hash-2").unwrap();
        sync.push_evidence("host-02", "hash-3").unwrap();

        let trail = sync.fleet_audit_trail();
        assert_eq!(trail.len(), 3);
        assert_eq!(trail[0].hash, "hash-1");
        assert_eq!(trail[1].hash, "hash-2");
        assert_eq!(trail[2].hash, "hash-3");
    }

    #[test]
    fn sync_report_empty_fleet() {
        let sync = CrossMachineEvidenceSync::new();
        let report = sync.sync_fleet_evidence();
        assert_eq!(report.hosts_synced, 0);
        assert_eq!(report.hosts_failed, 0);
        assert!(!report.divergence_detected);
        assert!(report.divergent_hosts.is_empty());
    }

    #[test]
    fn sync_report_all_in_sync() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.register_host("host-01", "hash-consensus");
        sync.register_host("host-02", "hash-consensus");
        sync.register_host("host-03", "hash-consensus");

        let report = sync.sync_fleet_evidence();
        assert_eq!(report.hosts_synced, 3);
        assert_eq!(report.hosts_failed, 0);
        assert!(!report.divergence_detected);
        assert!(report.divergent_hosts.is_empty());
    }

    #[test]
    fn sync_report_single_host() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.register_host("solo-host", "solo-hash");

        let report = sync.sync_fleet_evidence();
        assert_eq!(report.hosts_synced, 1);
        assert!(!report.divergence_detected);
    }

    #[test]
    fn detect_divergence_returns_divergent_hosts() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.register_host("host-01", "hash-A");
        sync.register_host("host-02", "hash-A");
        sync.register_host("host-03", "hash-B");
        sync.register_host("host-04", "hash-A");

        let diverged = sync.detect_divergence();
        assert_eq!(diverged.len(), 1);
        assert!(diverged.contains(&"host-03".to_string()));
    }

    #[test]
    fn detect_divergence_no_divergence() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.register_host("host-01", "hash-X");
        sync.register_host("host-02", "hash-X");

        let diverged = sync.detect_divergence();
        assert!(diverged.is_empty());
    }

    #[test]
    fn detect_divergence_empty_fleet() {
        let sync = CrossMachineEvidenceSync::new();
        let diverged = sync.detect_divergence();
        assert!(diverged.is_empty());
    }

    #[test]
    fn detect_divergence_majority_tie_returns_diverging_only() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.register_host("host-01", "hash-A");
        sync.register_host("host-02", "hash-B");

        let diverged = sync.detect_divergence();
        assert_eq!(diverged.len(), 1);
    }

    #[test]
    fn audit_trail_starts_empty() {
        let sync = CrossMachineEvidenceSync::new();
        assert_eq!(sync.fleet_audit_trail().len(), 0);
        assert_eq!(sync.evidence_count(), 0);
    }

    #[test]
    fn audit_trail_grows_with_evidence() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.push_evidence("h1", "hash-1").unwrap();
        sync.push_evidence("h2", "hash-2").unwrap();
        assert_eq!(sync.evidence_count(), 2);
    }

    #[test]
    fn sync_report_with_divergence_flags_correctly() {
        let mut sync = CrossMachineEvidenceSync::new();
        sync.register_host("host-01", "hash-A");
        sync.register_host("host-02", "hash-A");
        sync.register_host("host-03", "hash-divergent");

        let report = sync.sync_fleet_evidence();
        assert!(report.divergence_detected);
        assert_eq!(report.divergent_hosts.len(), 1);
        assert_eq!(report.hosts_synced, 3);
    }

    #[test]
    fn default_sync_interval_is_30_seconds() {
        let sync = CrossMachineEvidenceSync::new();
        assert_eq!(sync.sync_interval_secs, 30);
    }

    #[test]
    fn evidence_entry_construction() {
        let entry = EvidenceEntry::new(
            "host-alpha".into(),
            "hash-deadbeef".into(),
            "2026-06-11T12:00:00Z".into(),
        );
        assert_eq!(entry.host_id, "host-alpha");
        assert_eq!(entry.hash, "hash-deadbeef");
        assert_eq!(entry.timestamp, "2026-06-11T12:00:00Z");
    }

    #[test]
    fn sync_report_construction() {
        let report = SyncReport::new(5, 2, true, vec!["h1".into(), "h2".into()]);
        assert_eq!(report.hosts_synced, 5);
        assert_eq!(report.hosts_failed, 2);
        assert!(report.divergence_detected);
        assert_eq!(report.divergent_hosts.len(), 2);
    }

    #[test]
    fn sync_report_no_divergence() {
        let report = SyncReport::new(3, 0, false, vec![]);
        assert!(!report.divergence_detected);
        assert!(report.divergent_hosts.is_empty());
    }
}
