use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::enums::{ContainerAdmissionDecision, ContainerEngine, IsolationLevel, WorkloadImporter};

/// Evidence payload emitted when a container workload is admitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerAdmittedPayload {
    pub passport_id: String,
    pub workload_id: String,
    pub engine: ContainerEngine,
    pub isolation: IsolationLevel,
    pub rootless: bool,
    pub profile: String,
    pub admitted_at: DateTime<Utc>,
}

/// Evidence payload emitted when a container workload is blocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerBlockedPayload {
    pub passport_id: String,
    pub workload_id: String,
    pub reason: String,
    pub source: WorkloadImporter,
    pub blocked_at: DateTime<Utc>,
}

/// Evidence payload emitted when a container workload is quarantined.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerQuarantinedPayload {
    pub passport_id: String,
    pub workload_id: String,
    pub reason: String,
    pub quarantined_at: DateTime<Utc>,
}

impl ContainerAdmittedPayload {
    /// Create a new admission evidence payload.
    pub fn new(
        passport_id: impl Into<String>,
        workload_id: impl Into<String>,
        engine: ContainerEngine,
        isolation: IsolationLevel,
        rootless: bool,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            passport_id: passport_id.into(),
            workload_id: workload_id.into(),
            engine,
            isolation,
            rootless,
            profile: profile.into(),
            admitted_at: Utc::now(),
        }
    }
}

impl ContainerBlockedPayload {
    /// Create a new blocked evidence payload.
    pub fn new(
        passport_id: impl Into<String>,
        workload_id: impl Into<String>,
        reason: impl Into<String>,
        source: WorkloadImporter,
    ) -> Self {
        Self {
            passport_id: passport_id.into(),
            workload_id: workload_id.into(),
            reason: reason.into(),
            source,
            blocked_at: Utc::now(),
        }
    }
}

impl ContainerQuarantinedPayload {
    /// Create a new quarantined evidence payload.
    pub fn new(
        passport_id: impl Into<String>,
        workload_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            passport_id: passport_id.into(),
            workload_id: workload_id.into(),
            reason: reason.into(),
            quarantined_at: Utc::now(),
        }
    }
}

/// Encode an admission decision into the appropriate evidence payload.
#[allow(clippy::too_many_arguments)]
pub fn encode_admission_evidence(
    passport_id: &str,
    workload_id: &str,
    decision: ContainerAdmissionDecision,
    reason: &str,
    engine: ContainerEngine,
    isolation: IsolationLevel,
    rootless: bool,
    profile: &str,
    source: WorkloadImporter,
) -> Result<Vec<u8>, serde_json::Error> {
    match decision {
        ContainerAdmissionDecision::Admitted => {
            let payload = ContainerAdmittedPayload::new(
                passport_id,
                workload_id,
                engine,
                isolation,
                rootless,
                profile,
            );
            serde_json::to_vec(&payload)
        }
        ContainerAdmissionDecision::Blocked => {
            let payload = ContainerBlockedPayload::new(passport_id, workload_id, reason, source);
            serde_json::to_vec(&payload)
        }
        ContainerAdmissionDecision::Quarantined => {
            let payload = ContainerQuarantinedPayload::new(passport_id, workload_id, reason);
            serde_json::to_vec(&payload)
        }
        ContainerAdmissionDecision::RequiresHumanApproval => {
            let payload = ContainerBlockedPayload::new(passport_id, workload_id, reason, source);
            serde_json::to_vec(&payload)
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn admitted_payload_serializes() {
        let payload = ContainerAdmittedPayload::new(
            "cnp_001",
            "wl_001",
            ContainerEngine::PodmanRootless,
            IsolationLevel::Rootless,
            true,
            "DEV_RELAXED",
        );
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("cnp_001"));
        assert!(json.contains("PODMAN_ROOTLESS"));
        assert!(json.contains("ROOTLESS"));
        assert!(json.contains("DEV_RELAXED"));
    }

    #[test]
    fn blocked_payload_serializes() {
        let payload = ContainerBlockedPayload::new(
            "cnp_002",
            "wl_002",
            "unsigned image",
            WorkloadImporter::K8sManifestImporter,
        );
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("cnp_002"));
        assert!(json.contains("unsigned image"));
    }

    #[test]
    fn quarantined_payload_serializes() {
        let payload =
            ContainerQuarantinedPayload::new("cnp_003", "wl_003", "airgap policy violation");
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("cnp_003"));
        assert!(json.contains("airgap policy violation"));
    }

    #[test]
    fn encode_admitted_evidence() {
        let result = encode_admission_evidence(
            "cnp_004",
            "wl_004",
            ContainerAdmissionDecision::Admitted,
            "",
            ContainerEngine::PodmanRootless,
            IsolationLevel::Rootless,
            true,
            "DEV_RELAXED",
            WorkloadImporter::ComposeImporter,
        );
        assert!(result.is_ok());
        let bytes = result.unwrap();
        let json = String::from_utf8(bytes).unwrap();
        assert!(json.contains("cnp_004"));
        assert!(json.contains("PODMAN_ROOTLESS"));
        assert!(json.contains("DEV_RELAXED"));
    }

    #[test]
    fn encode_blocked_evidence() {
        let result = encode_admission_evidence(
            "cnp_005",
            "wl_005",
            ContainerAdmissionDecision::Blocked,
            "policy violation",
            ContainerEngine::PodmanRootless,
            IsolationLevel::Rootless,
            true,
            "STIG_ALIGNED",
            WorkloadImporter::HelmImporter,
        );
        assert!(result.is_ok());
    }
}
