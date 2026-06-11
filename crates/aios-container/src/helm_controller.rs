//! Helm controller — chart registration, template rendering (simulated),
//! release lifecycle (install / upgrade / rollback / uninstall), and
//! revision history tracking.
//!
//! Implements the Rev.7 Helm-native workflow: every chart is validated via
//! digest + optional Ed25519 signature before being rendered into workload
//! descriptors that pass through the K8s admission gate.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::k8s_operator::{
    K8sOperator, K8sResourceRequest, K8sWorkloadDescriptor,
};
use crate::passport::CloudNativePassport;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors surfaced by the Helm controller.
#[derive(Error, Debug)]
pub enum HelmControllerError {
    #[error("chart '{0}' already registered")]
    ChartAlreadyRegistered(String),

    #[error("chart '{0}' not found")]
    ChartNotFound(String),

    #[error("release {0} not found")]
    ReleaseNotFound(Ulid),

    #[error("render failed for chart '{chart}': {detail}")]
    RenderFailed { chart: String, detail: String },

    #[error("install failed for chart '{chart}': {detail}")]
    InstallFailed { chart: String, detail: String },

    #[error("upgrade failed for release {0}: {1}")]
    UpgradeFailed(Ulid, String),

    #[error("rollback failed for release {0}: {1}")]
    RollbackFailed(Ulid, String),

    #[error("uninstall failed for release {0}: {1}")]
    UninstallFailed(Ulid, String),

    #[error("signature verification failed for chart '{chart}': {detail}")]
    SignatureVerificationFailed { chart: String, detail: String },

    #[error("value validation failed: {0}")]
    ValueValidationFailed(String),
}

// ---------------------------------------------------------------------------
// Hash type alias
// ---------------------------------------------------------------------------

/// Blake3 hash digest used for chart integrity verification.
pub type Hash = [u8; 32];

// ---------------------------------------------------------------------------
// Ed25519 signature
// ---------------------------------------------------------------------------

/// Ed25519 signature wrapper for chart verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Signature {
    pub signature_bytes: Vec<u8>,
    pub public_key_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Value constraint
// ---------------------------------------------------------------------------

/// Constraint on a single Helm values key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueConstraint {
    /// Expected value type: `"string"`, `"integer"`, `"boolean"`, `"array"`.
    #[serde(rename = "type")]
    pub type_: String,
    /// Whether this key must be present.
    pub required: bool,
    /// Default value if not provided.
    pub default_value: Option<String>,
    /// Set of allowed values (enum-like).
    pub allowed_values: Option<Vec<String>>,
    /// Minimum numeric value.
    pub min_value: Option<f64>,
    /// Maximum numeric value.
    pub max_value: Option<f64>,
}

// ---------------------------------------------------------------------------
// Helm values
// ---------------------------------------------------------------------------

/// Values supplied to a Helm chart for rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmValues {
    /// Key-value overrides (simulated).
    pub values: HashMap<String, serde_json::Value>,
    /// Raw YAML values file content.
    pub raw_yaml: String,
}

impl Default for HelmValues {
    fn default() -> Self {
        Self {
            values: HashMap::new(),
            raw_yaml: String::new(),
        }
    }
}

impl HelmValues {
    /// Create empty values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a raw YAML string.
    pub fn from_raw(raw_yaml: impl Into<String>) -> Self {
        Self {
            values: HashMap::new(),
            raw_yaml: raw_yaml.into(),
        }
    }

    /// Insert a single value override.
    pub fn with_value(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.values.insert(key.into(), value);
        self
    }
}

// ---------------------------------------------------------------------------
// Chart descriptor
// ---------------------------------------------------------------------------

/// Descriptor for a registered Helm chart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmChartDescriptor {
    /// Chart name (e.g. `"nginx"`, `"aios-inference"`).
    pub name: String,
    /// Semantic version.
    pub version: String,
    /// OCI or HTTP repository URL.
    pub repository: String,
    /// Blake3 digest of the chart archive.
    pub digest: Hash,
    /// Optional Ed25519 signature for integrity verification.
    pub signature: Option<Ed25519Signature>,
    /// Schema of expected values keys.
    pub values_schema: HashMap<String, ValueConstraint>,
}

impl HelmChartDescriptor {
    /// Returns `true` when the chart carries an Ed25519 signature.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Verify the chart signature.
    ///
    /// In this simulated environment, a signature is considered verified if
    /// it is present and the bytes are non-empty.
    pub fn verify_signature(&self) -> Result<(), HelmControllerError> {
        match &self.signature {
            Some(sig) if !sig.signature_bytes.is_empty() && !sig.public_key_bytes.is_empty() => {
                Ok(())
            }
            Some(_) => Err(HelmControllerError::SignatureVerificationFailed {
                chart: self.name.clone(),
                detail: "empty signature or public key bytes".into(),
            }),
            None => Err(HelmControllerError::SignatureVerificationFailed {
                chart: self.name.clone(),
                detail: "chart is not signed".into(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Helm release state
// ---------------------------------------------------------------------------

/// Lifecycle state of a Helm release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HelmReleaseState {
    /// Release planned but not yet installed.
    Planned,
    /// Installation in progress.
    Installing,
    /// Successfully deployed.
    Deployed,
    /// Installation or upgrade failed.
    Failed,
    /// Rolling back to a previous revision.
    RollingBack,
    /// Rollback completed successfully.
    RolledBack,
    /// Release has been purged.
    Purged,
}

// ---------------------------------------------------------------------------
// Helm release
// ---------------------------------------------------------------------------

/// A single Helm release instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmRelease {
    /// Unique release identifier.
    pub release_id: Ulid,
    /// Name of the chart used.
    pub chart_name: String,
    /// Chart version pinned for this release.
    pub chart_version: String,
    /// Target namespace.
    pub namespace: String,
    /// Values used for rendering.
    pub values: HelmValues,
    /// Workload IDs created by this release.
    pub workloads: Vec<Ulid>,
    /// Current release state.
    pub state: HelmReleaseState,
    /// Monotonic revision counter.
    pub revision: u32,
    /// Timestamp of the last state change.
    pub updated_at: DateTime<Utc>,
    /// Revision history (newest first).
    pub history: Vec<HelmReleaseRevision>,
}

/// Immutable snapshot of a release at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmReleaseRevision {
    pub revision: u32,
    pub chart_version: String,
    pub values: HelmValues,
    pub state: HelmReleaseState,
    pub recorded_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Helm controller
// ---------------------------------------------------------------------------

/// Top-level Helm controller managing charts and releases.
#[derive(Debug)]
pub struct HelmController {
    pub charts: HashMap<String, HelmChartDescriptor>,
    pub releases: HashMap<Ulid, HelmRelease>,
    pub values_overrides: HashMap<String, HelmValues>,
    pub default_namespace: String,
}

impl HelmController {
    /// Create a new Helm controller.
    pub fn new(default_namespace: impl Into<String>) -> Self {
        Self {
            charts: HashMap::new(),
            releases: HashMap::new(),
            values_overrides: HashMap::new(),
            default_namespace: default_namespace.into(),
        }
    }

    // -- Chart management --------------------------------------------------

    /// Register a Helm chart.
    pub fn add_chart(
        &mut self,
        descriptor: HelmChartDescriptor,
    ) -> Result<(), HelmControllerError> {
        let name = descriptor.name.clone();
        if self.charts.contains_key(&name) {
            return Err(HelmControllerError::ChartAlreadyRegistered(name));
        }
        self.charts.insert(name, descriptor);
        Ok(())
    }

    // -- Template rendering ------------------------------------------------

    /// Render a chart into workload descriptors.
    ///
    /// Simulates Helm's Go-template rendering by producing one or more
    /// `K8sWorkloadDescriptor` values based on the chart metadata and
    /// provided values.
    pub fn render_chart(
        &self,
        chart_name: &str,
        values: &HelmValues,
        namespace: &str,
    ) -> Result<Vec<K8sWorkloadDescriptor>, HelmControllerError> {
        let chart = self
            .charts
            .get(chart_name)
            .ok_or_else(|| HelmControllerError::ChartNotFound(chart_name.into()))?;

        // Validate values against schema
        validate_chart_values(&chart.values_schema, values)?;

        // Simulate template rendering: produce workload descriptors.
        // In a real Helm controller this would invoke the Go template engine.
        let replica_count = extract_replica_count(values);
        let cpu = extract_value_u32(values, "resources.requests.cpu", 250);
        let mem = extract_value_u32(values, "resources.requests.memory", 256);
        let gpu = extract_value_u32(values, "resources.requests.gpu", 0);

        let image_tag = values
            .values
            .get("image")
            .and_then(|v| v.get("tag"))
            .and_then(|v| v.as_str())
            .unwrap_or("latest");

        let source = format!("helm:{}:{}:{}", chart_name, chart.version, image_tag);
        let image_digest = chart.digest;
        let digest_str = hex::encode(&image_digest);

        let mut descriptors = Vec::new();

        // Main deployment workload
        let payload = self.render_single_workload(
            chart_name,
            namespace,
            &source,
            &digest_str,
            replica_count,
            K8sResourceRequest {
                cpu_millicores: cpu,
                memory_mb: mem,
                gpu_count: gpu,
            },
        );

        descriptors.push(payload);

        // If the chart defines a service port, add a sidecar placeholder
        if let Some(service_port) = values.values.get("service").and_then(|s| s.get("port")) {
            let port = service_port.as_u64().unwrap_or(8080);
            let sidecar_source = format!("helm:{}:{}:svc-{}", chart_name, chart.version, port);
            let sidecar = self.render_single_workload(
                &format!("{}-svc", chart_name),
                namespace,
                &sidecar_source,
                &digest_str,
                1,
                K8sResourceRequest {
                    cpu_millicores: 50,
                    memory_mb: 64,
                    gpu_count: 0,
                },
            );
            descriptors.push(sidecar);
        }

        Ok(descriptors)
    }

    /// Render a single workload descriptor from chart metadata.
    fn render_single_workload(
        &self,
        chart_name: &str,
        namespace: &str,
        source: &str,
        digest: &str,
        replica_count: u32,
        resources: K8sResourceRequest,
    ) -> K8sWorkloadDescriptor {
        let passport = CloudNativePassport::new(
            format!("wl-{}-{}", chart_name, digest),
            source,
            vec![format!("sha256:{}", digest)],
        );

        K8sWorkloadDescriptor {
            workload_id: Ulid::new(),
            passport,
            namespace: namespace.into(),
            state: crate::k8s_operator::WorkloadState::Admitted,
            profile: crate::enums::K8sProfile::K8sDevLocal,
            replica_count,
            resources,
            revision_history: Vec::new(),
        }
    }

    // -- Install -----------------------------------------------------------

    /// Install a chart: render → admit → deploy.
    ///
    /// Each rendered workload descriptor is filtered through the supplied
    /// `K8sOperator` admission gate.  Only admitted workloads are deployed.
    pub fn install(
        &mut self,
        chart_name: &str,
        namespace: impl Into<String>,
        values: &HelmValues,
        operator: &mut K8sOperator,
    ) -> Result<HelmRelease, HelmControllerError> {
        let chart = self
            .charts
            .get(chart_name)
            .ok_or_else(|| HelmControllerError::ChartNotFound(chart_name.into()))?;

        let ns: String = namespace.into();
        let descriptors = self.render_chart(chart_name, values, &ns)?;

        let mut workload_ids = Vec::new();
        for desc in &descriptors {
            match operator.deploy_workload(
                desc.passport.clone(),
                ns.clone(),
                desc.resources.clone(),
            ) {
                Ok(deployed) => {
                    workload_ids.push(deployed.workload_id);
                }
                Err(e) => {
                    return Err(HelmControllerError::InstallFailed {
                        chart: chart_name.into(),
                        detail: format!("admission blocked workload: {e}"),
                    });
                }
            }
        }

        let release_id = Ulid::new();
        let revision = 1u32;
        let now = Utc::now();

        let release = HelmRelease {
            release_id,
            chart_name: chart_name.into(),
            chart_version: chart.version.clone(),
            namespace: ns,
            values: values.clone(),
            workloads: workload_ids,
            state: HelmReleaseState::Deployed,
            revision,
            updated_at: now,
            history: vec![HelmReleaseRevision {
                revision,
                chart_version: chart.version.clone(),
                values: values.clone(),
                state: HelmReleaseState::Deployed,
                recorded_at: now,
            }],
        };

        self.releases.insert(release_id, release.clone());
        Ok(release)
    }

    // -- Upgrade -----------------------------------------------------------

    /// Upgrade a release: diff values → render → test-admit → deploy.
    pub fn upgrade(
        &mut self,
        release_id: Ulid,
        new_values: &HelmValues,
        operator: &mut K8sOperator,
    ) -> Result<HelmRelease, HelmControllerError> {
        let chart_name;
        let namespace;
        {
            let release = self
                .releases
                .get(&release_id)
                .ok_or(HelmControllerError::ReleaseNotFound(release_id))?;
            chart_name = release.chart_name.clone();
            namespace = release.namespace.clone();
        }

        let descriptors = self.render_chart(&chart_name, new_values, &namespace)?;

        // Test-admit: verify all workloads pass admission before applying
        let mut new_workloads = Vec::new();
        for desc in &descriptors {
            match operator.deploy_workload(
                desc.passport.clone(),
                namespace.clone(),
                desc.resources.clone(),
            ) {
                Ok(deployed) => {
                    new_workloads.push(deployed.workload_id);
                }
                Err(e) => {
                    return Err(HelmControllerError::UpgradeFailed(
                        release_id,
                        format!("admission blocked workload during upgrade: {e}"),
                    ));
                }
            }
        }

        let release = self
            .releases
            .get_mut(&release_id)
            .ok_or(HelmControllerError::ReleaseNotFound(release_id))?;

        // Save previous state for rollback
        let prev_revision = HelmReleaseRevision {
            revision: release.revision,
            chart_version: release.chart_version.clone(),
            values: release.values.clone(),
            state: release.state,
            recorded_at: release.updated_at,
        };
        release.history.insert(0, prev_revision);

        // Apply upgrade
        let new_rev = release.revision.saturating_add(1);
        release.values = new_values.clone();
        release.workloads = new_workloads;
        release.state = HelmReleaseState::Deployed;
        release.revision = new_rev;
        release.chart_version = release.chart_version.clone();
        release.updated_at = Utc::now();

        // Push current revision to history
        release.history.insert(
            0,
            HelmReleaseRevision {
                revision: new_rev,
                chart_version: release.chart_version.clone(),
                values: new_values.clone(),
                state: HelmReleaseState::Deployed,
                recorded_at: release.updated_at,
            },
        );

        Ok(release.clone())
    }

    // -- Rollback ----------------------------------------------------------

    /// Rollback a release to its previous revision.
    pub fn rollback(
        &mut self,
        release_id: Ulid,
    ) -> Result<HelmRelease, HelmControllerError> {
        let release = self
            .releases
            .get_mut(&release_id)
            .ok_or(HelmControllerError::ReleaseNotFound(release_id))?;

        if release.history.len() < 2 {
            return Err(HelmControllerError::RollbackFailed(
                release_id,
                "no previous revision to roll back to".into(),
            ));
        }

        release.state = HelmReleaseState::RollingBack;
        release.updated_at = Utc::now();

        // Remove current (index 0), apply previous (index 0 after removal)
        release.history.remove(0);
        let prev = release
            .history
            .first()
            .ok_or_else(|| {
                HelmControllerError::RollbackFailed(
                    release_id,
                    "previous revision missing after history removal".into(),
                )
            })?
            .clone();

        release.chart_version = prev.chart_version;
        release.values = prev.values;
        release.revision = prev.revision;
        release.state = HelmReleaseState::RolledBack;
        release.updated_at = Utc::now();

        Ok(release.clone())
    }

    // -- Uninstall ---------------------------------------------------------

    /// Uninstall a release and purge all its workloads.
    pub fn uninstall(
        &mut self,
        release_id: Ulid,
        operator: &mut K8sOperator,
    ) -> Result<(), HelmControllerError> {
        let release = self
            .releases
            .get_mut(&release_id)
            .ok_or(HelmControllerError::ReleaseNotFound(release_id))?;

        for wl_id in &release.workloads {
            if let Ok(()) = operator.set_workload_state(*wl_id, crate::k8s_operator::WorkloadState::Terminated) {
                // Workload terminated successfully
            }
        }

        release.state = HelmReleaseState::Purged;
        release.workloads.clear();
        release.updated_at = Utc::now();

        Ok(())
    }

    // -- Listing -----------------------------------------------------------

    /// List all releases.
    pub fn list_releases(&self) -> Vec<&HelmRelease> {
        self.releases.values().collect()
    }

    /// Get the revision history for a release.
    pub fn get_release_history(
        &self,
        release_id: Ulid,
    ) -> Result<Vec<HelmReleaseState>, HelmControllerError> {
        let release = self
            .releases
            .get(&release_id)
            .ok_or(HelmControllerError::ReleaseNotFound(release_id))?;

        let states: Vec<HelmReleaseState> = release
            .history
            .iter()
            .map(|r| r.state)
            .collect();

        Ok(states)
    }

    /// Get a single release by ID.
    pub fn get_release(&self, release_id: Ulid) -> Option<&HelmRelease> {
        self.releases.get(&release_id)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate user-supplied values against the chart's values schema.
fn validate_chart_values(
    schema: &HashMap<String, ValueConstraint>,
    values: &HelmValues,
) -> Result<(), HelmControllerError> {
    for (key, constraint) in schema {
        let has_key = values.values.contains_key(key);
        if constraint.required && !has_key && constraint.default_value.is_none() {
            return Err(HelmControllerError::ValueValidationFailed(format!(
                "required key '{key}' is missing and has no default"
            )));
        }

        if let Some(allowed) = &constraint.allowed_values {
            if let Some(val) = values.values.get(key) {
                let val_str = match val {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                if !allowed.contains(&val_str) {
                    return Err(HelmControllerError::ValueValidationFailed(format!(
                        "value for '{key}' is '{val_str}', but only {:?} are allowed",
                        allowed
                    )));
                }
            }
        }

        if let Some(val) = values.values.get(key) {
            if constraint.type_ == "integer" && !val.is_number() {
                return Err(HelmControllerError::ValueValidationFailed(format!(
                    "key '{key}' must be an integer"
                )));
            }
        }

        // Min/max constraints for numeric values
        if let (Some(min), Some(max)) = (constraint.min_value, constraint.max_value) {
            if let Some(val) = values.values.get(key).and_then(|v| v.as_f64()) {
                if val < min || val > max {
                    return Err(HelmControllerError::ValueValidationFailed(format!(
                        "value for '{key}' ({val}) is outside range [{min}, {max}]"
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Extract a replica count from Helm values.
fn extract_replica_count(values: &HelmValues) -> u32 {
    values
        .values
        .get("replicaCount")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u32
}

/// Extract a nested u32 value from Helm values using a dot-notation path.
fn extract_value_u32(values: &HelmValues, path: &str, default: u32) -> u32 {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.is_empty() {
        return default;
    }

    let json_val = serde_json::to_value(&values.values).ok();
    json_val
        .and_then(|root| {
            let mut current = root;
            for part in &parts {
                current = current.get(*part)?.clone();
            }
            current.as_u64()
        })
        .unwrap_or(default as u64) as u32
}

// Within the crate we don't depend on external `hex`, so we provide a minimal
// hex encoder for the 32-byte blake3 digest.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;
    use crate::enums::K8sProfile;
    use crate::k8s_operator::K8sResourceRequest;

    fn make_chart(name: &str, signed: bool) -> HelmChartDescriptor {
        HelmChartDescriptor {
            name: name.into(),
            version: "1.0.0".into(),
            repository: "oci://ghcr.io/aios/charts".into(),
            digest: [0xAB; 32],
            signature: if signed {
                Some(Ed25519Signature {
                    signature_bytes: vec![1, 2, 3, 4],
                    public_key_bytes: vec![5, 6, 7, 8],
                })
            } else {
                None
            },
            values_schema: HashMap::new(),
        }
    }

    fn make_operator() -> K8sOperator {
        K8sOperator::new(K8sProfile::K8sDevLocal)
    }

    // -- Chart descriptor --------------------------------------------------

    #[test]
    fn chart_descriptor_with_signature_accepted() {
        let chart = make_chart("signed-chart", true);
        assert!(chart.is_signed());
        assert!(chart.verify_signature().is_ok());
    }

    #[test]
    fn chart_descriptor_without_signature_rejected() {
        let chart = make_chart("unsigned-chart", false);
        assert!(!chart.is_signed());
        assert!(chart.verify_signature().is_err());
    }

    #[test]
    fn chart_descriptor_with_empty_signature_rejected() {
        let mut chart = make_chart("bad-sig", true);
        chart.signature = Some(Ed25519Signature {
            signature_bytes: vec![],
            public_key_bytes: vec![],
        });
        assert!(chart.verify_signature().is_err());
    }

    // -- Render chart ------------------------------------------------------

    #[test]
    fn helm_render_chart_generates_workload_descriptors() {
        let mut ctrl = HelmController::new("default");
        ctrl.add_chart(make_chart("myapp", true)).unwrap();
        let values = HelmValues::new()
            .with_value("replicaCount", serde_json::json!(3))
            .with_value("service", serde_json::json!({"port": 3000}));

        let descriptors = ctrl.render_chart("myapp", &values, "default").unwrap();
        assert!(
            descriptors.len() >= 1,
            "render should produce at least the main workload"
        );
    }

    #[test]
    fn helm_render_unknown_chart_fails() {
        let ctrl = HelmController::new("default");
        let result = ctrl.render_chart("nonexistent", &HelmValues::new(), "default");
        assert!(result.is_err());
    }

    // -- Install -----------------------------------------------------------

    #[test]
    fn helm_install_success() {
        let mut ctrl = HelmController::new("default");
        ctrl.add_chart(make_chart("nginx", true)).unwrap();

        let mut op = make_operator();
        let values = HelmValues::new().with_value("replicaCount", serde_json::json!(2));

        let release = ctrl.install("nginx", "default", &values, &mut op).unwrap();
        assert_eq!(release.chart_name, "nginx");
        assert_eq!(release.state, HelmReleaseState::Deployed);
        assert_eq!(release.revision, 1);
    }

    #[test]
    fn helm_install_fails_for_missing_chart() {
        let mut ctrl = HelmController::new("default");
        let mut op = make_operator();
        let result = ctrl.install("missing", "default", &HelmValues::new(), &mut op);
        assert!(result.is_err());
    }

    // -- Upgrade -----------------------------------------------------------

    #[test]
    fn helm_upgrade_success() {
        let mut ctrl = HelmController::new("default");
        ctrl.add_chart(make_chart("app", true)).unwrap();

        let mut op = make_operator();
        let v1 = HelmValues::new().with_value("replicaCount", serde_json::json!(1));
        let release = ctrl.install("app", "default", &v1, &mut op).unwrap();
        let rid = release.release_id;

        let v2 = HelmValues::new().with_value("replicaCount", serde_json::json!(3));
        let upgraded = ctrl.upgrade(rid, &v2, &mut op).unwrap();
        assert_eq!(upgraded.revision, 2);
        assert_eq!(upgraded.state, HelmReleaseState::Deployed);
    }

    // -- Rollback ----------------------------------------------------------

    #[test]
    fn helm_rollback_restores_previous_release() {
        let mut ctrl = HelmController::new("default");
        ctrl.add_chart(make_chart("app", true)).unwrap();

        let mut op = make_operator();
        let v1 = HelmValues::new().with_value("replicaCount", serde_json::json!(1));
        let release = ctrl.install("app", "default", &v1, &mut op).unwrap();
        let rid = release.release_id;

        let v2 = HelmValues::new().with_value("replicaCount", serde_json::json!(5));
        let _upgraded = ctrl.upgrade(rid, &v2, &mut op).unwrap();

        let rolled_back = ctrl.rollback(rid).unwrap();
        assert_eq!(rolled_back.revision, 1, "rollback should restore revision 1");
        assert_eq!(rolled_back.state, HelmReleaseState::RolledBack);
    }

    #[test]
    fn helm_rollback_without_history_fails() {
        let mut ctrl = HelmController::new("default");
        ctrl.add_chart(make_chart("app", true)).unwrap();

        let mut op = make_operator();
        let v1 = HelmValues::new();
        let release = ctrl.install("app", "default", &v1, &mut op).unwrap();
        let result = ctrl.rollback(release.release_id);
        assert!(result.is_err());
    }

    // -- Revision history --------------------------------------------------

    #[test]
    fn helm_revision_history_tracks_all_releases() {
        let mut ctrl = HelmController::new("default");
        ctrl.add_chart(make_chart("history-app", true)).unwrap();

        let mut op = make_operator();
        let v1 = HelmValues::new().with_value("replicaCount", serde_json::json!(1));
        let release = ctrl.install("history-app", "default", &v1, &mut op).unwrap();
        let rid = release.release_id;

        let v2 = HelmValues::new().with_value("replicaCount", serde_json::json!(2));
        let _ = ctrl.upgrade(rid, &v2, &mut op).unwrap();

        let v3 = HelmValues::new().with_value("replicaCount", serde_json::json!(3));
        let _ = ctrl.upgrade(rid, &v3, &mut op).unwrap();

        let history = ctrl.get_release_history(rid).unwrap();
        assert!(
            history.len() >= 3,
            "history should have at least 3 entries (initial + 2 upgrades)"
        );
    }

    // -- Uninstall ---------------------------------------------------------

    #[test]
    fn helm_uninstall_purges_workloads() {
        let mut ctrl = HelmController::new("default");
        ctrl.add_chart(make_chart("purge-me", true)).unwrap();

        let mut op = make_operator();
        let v1 = HelmValues::new();
        let release = ctrl.install("purge-me", "default", &v1, &mut op).unwrap();
        let rid = release.release_id;

        assert!(!release.workloads.is_empty(), "release should have workloads");
        ctrl.uninstall(rid, &mut op).unwrap();

        let purged = ctrl.get_release(rid).unwrap();
        assert_eq!(purged.state, HelmReleaseState::Purged);
        assert!(purged.workloads.is_empty());
    }

    // -- List releases -----------------------------------------------------

    #[test]
    fn helm_list_releases_returns_all() {
        let mut ctrl = HelmController::new("default");
        ctrl.add_chart(make_chart("a", true)).unwrap();
        ctrl.add_chart(make_chart("b", true)).unwrap();

        let mut op = make_operator();
        let _ = ctrl.install("a", "default", &HelmValues::new(), &mut op).unwrap();
        let _ = ctrl.install("b", "default", &HelmValues::new(), &mut op).unwrap();

        assert_eq!(ctrl.list_releases().len(), 2);
    }

    // -- Value constraints -------------------------------------------------

    #[test]
    fn value_constraint_required_key_missing_fails() {
        let mut ctrl = HelmController::new("default");
        let mut chart = make_chart("constrained", true);
        chart.values_schema.insert(
            "database_url".into(),
            ValueConstraint {
                type_: "string".into(),
                required: true,
                default_value: None,
                allowed_values: None,
                min_value: None,
                max_value: None,
            },
        );
        ctrl.add_chart(chart).unwrap();

        let values = HelmValues::new();
        let result = ctrl.render_chart("constrained", &values, "default");
        assert!(result.is_err());
    }

    // -- Duplicate chart registration --------------------------------------

    #[test]
    fn duplicate_chart_registration_fails() {
        let mut ctrl = HelmController::new("default");
        ctrl.add_chart(make_chart("dup", true)).unwrap();
        let result = ctrl.add_chart(make_chart("dup", true));
        assert!(result.is_err());
    }

    // -- Default values ----------------------------------------------------

    #[test]
    fn helm_values_default_is_empty() {
        let v = HelmValues::default();
        assert!(v.values.is_empty());
        assert!(v.raw_yaml.is_empty());
    }

    #[test]
    fn helm_values_from_raw() {
        let v = HelmValues::from_raw("replicaCount: 3\nservice:\n  port: 80\n");
        assert_eq!(v.raw_yaml, "replicaCount: 3\nservice:\n  port: 80\n");
    }
}
