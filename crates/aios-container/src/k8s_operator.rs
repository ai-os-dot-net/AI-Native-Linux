//! K8s-native operator — admission control, workload deployment, manifest
//! generation, and health monitoring.
//!
//! Implements the Rev.7 fleet-plane contract (S24 §5): every workload passes
//! through a multi-rule admission gate before landing on a profile-specific
//! namespace.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::enums::{ContainerEngine, IsolationLevel, K8sProfile};
use crate::passport::CloudNativePassport;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors surfaced by the K8s operator.
#[derive(Error, Debug)]
pub enum K8sOperatorError {
    #[error("workload {0} already exists")]
    WorkloadAlreadyExists(Ulid),

    #[error("workload {0} not found")]
    WorkloadNotFound(Ulid),

    #[error("namespace '{0}' not found")]
    NamespaceNotFound(String),

    #[error("admission denied: {0}")]
    AdmissionDenied(String),

    #[error("deployment failed: {0}")]
    DeploymentFailed(String),

    #[error("rollback failed for workload {0}: {1}")]
    RollbackFailed(Ulid, String),

    #[error("health check failed for workload {0}: {1}")]
    HealthCheckFailed(Ulid, String),

    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
}

// ---------------------------------------------------------------------------
// Admission decision
// ---------------------------------------------------------------------------

/// Result of an admission rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionDecision {
    /// Workload is allowed to proceed.
    Allow,
    /// Workload is rejected with a reason.
    Deny { reason: String },
    /// Workload is admitted but generates a warning.
    Warn { reason: String },
}

impl AdmissionDecision {
    /// Returns `true` when the decision permits the workload (Allow or Warn).
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Warn { .. })
    }
}

// ---------------------------------------------------------------------------
// Evidence emitter trait
// ---------------------------------------------------------------------------

/// Emits container-level evidence events (admit, block, quarantine).
///
/// Consumers wire this to `aios-evidence` gRPC or an in-memory ring buffer.
pub trait ContainerEvidenceEmitter: Send + Sync {
    fn emit_admitted(&self, workload_id: Ulid, namespace: &str);
    fn emit_blocked(&self, workload_id: Ulid, namespace: &str, reason: &str);
    fn emit_quarantined(&self, workload_id: Ulid, namespace: &str, reason: &str);
}

// ---------------------------------------------------------------------------
// Resource request
// ---------------------------------------------------------------------------

/// CPU / memory / GPU resource request for a single workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct K8sResourceRequest {
    /// CPU request in millicores (1000m = 1 vCPU).
    pub cpu_millicores: u32,
    /// Memory request in MiB.
    pub memory_mb: u32,
    /// GPU count (0 = no GPU required).
    pub gpu_count: u32,
}

impl Default for K8sResourceRequest {
    fn default() -> Self {
        Self {
            cpu_millicores: 250,
            memory_mb: 256,
            gpu_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Workload state
// ---------------------------------------------------------------------------

/// Lifecycle state of a K8s workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkloadState {
    /// Passed admission, not yet submitted to the scheduler.
    Admitted,
    /// Submitted to the cluster, awaiting node assignment.
    Pending,
    /// At least one replica is healthy.
    Running,
    /// Running but below desired replica count or health threshold.
    Degraded,
    /// Gracefully terminated.
    Terminated,
    /// Admission or policy blocked this workload.
    Blocked,
}

impl WorkloadState {
    /// Returns the set of states this state may transition to.
    pub fn allowed_transitions(&self) -> &[WorkloadState] {
        match self {
            Self::Admitted => &[Self::Pending, Self::Terminated, Self::Blocked],
            Self::Pending => &[Self::Running, Self::Degraded, Self::Terminated, Self::Blocked],
            Self::Running => &[Self::Degraded, Self::Terminated],
            Self::Degraded => &[Self::Running, Self::Terminated],
            Self::Terminated => &[],
            Self::Blocked => &[],
        }
    }

    /// Returns `true` if `target` is a valid transition from `self`.
    pub fn can_transition_to(&self, target: WorkloadState) -> bool {
        self.allowed_transitions().contains(&target)
    }
}

// ---------------------------------------------------------------------------
// Workload descriptor
// ---------------------------------------------------------------------------

/// Full descriptor for a workload admitted into the K8s operator plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sWorkloadDescriptor {
    /// Unique workload identifier.
    pub workload_id: Ulid,
    /// The cloud-native passport used for admission.
    pub passport: CloudNativePassport,
    /// Target namespace.
    pub namespace: String,
    /// Current lifecycle state.
    pub state: WorkloadState,
    /// Deployment profile governing this workload.
    pub profile: K8sProfile,
    /// Desired replica count.
    pub replica_count: u32,
    /// CPU / memory / GPU resource request.
    pub resources: K8sResourceRequest,
    /// Previous revisions for rollback (newest first).
    pub revision_history: Vec<K8sWorkloadRevision>,
}

/// Immutable snapshot of a workload at a point in time (for rollback).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sWorkloadRevision {
    pub passport: CloudNativePassport,
    pub state: WorkloadState,
    pub replica_count: u32,
    pub resources: K8sResourceRequest,
    pub recorded_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Workload health
// ---------------------------------------------------------------------------

/// Health summary for a single workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadHealth {
    pub workload_id: Ulid,
    pub state: WorkloadState,
    pub ready_replicas: u32,
    pub desired_replicas: u32,
    pub restarts: u32,
    pub last_transition: DateTime<Utc>,
    pub conditions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Namespace
// ---------------------------------------------------------------------------

/// K8s namespace managed by the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sNamespace {
    pub name: String,
    pub labels: HashMap<String, String>,
    pub admitted_at: DateTime<Utc>,
    pub policy_bundle_id: Ulid,
}

impl K8sNamespace {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            labels: HashMap::new(),
            admitted_at: Utc::now(),
            policy_bundle_id: Ulid::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Admission rule
// ---------------------------------------------------------------------------

/// A single admission rule evaluated in priority order.
pub struct AdmissionRule {
    /// Human-readable name (e.g. "digest_pin_required").
    pub name: String,
    /// Short description of what the rule enforces.
    pub description: String,
    /// Evaluation function — receives the workload's passport and the active
    /// K8s profile, returns an [`AdmissionDecision`].
    pub evaluate: Box<dyn Fn(&CloudNativePassport, K8sProfile) -> AdmissionDecision + Send + Sync>,
    /// Lower numbers run first.
    pub priority: u8,
}

impl std::fmt::Debug for AdmissionRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionRule")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("priority", &self.priority)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Built-in admission rules
// ---------------------------------------------------------------------------

/// Reject workloads whose images are not digest-pinned when the profile requires it.
pub fn rule_digest_pin_required() -> AdmissionRule {
    AdmissionRule {
        name: "digest_pin_required".into(),
        description: "Reject non-digest-pinned images for profiles that mandate content-addressable references".into(),
        priority: 10,
        evaluate: Box::new(|passport, profile| {
            let requires_pin = crate::profile_gates::requires_digest_pin(&profile_to_security_label(profile));
            if requires_pin && passport.image_digests.is_empty() {
                AdmissionDecision::Deny {
                    reason: "image must be digest-pinned (no tag-only references allowed)".into(),
                }
            } else {
                AdmissionDecision::Allow
            }
        }),
    }
}

/// Reject privileged containers unless human approval is granted.
pub fn rule_privileged_containers_blocked() -> AdmissionRule {
    AdmissionRule {
        name: "privileged_containers_blocked".into(),
        description: "Reject privileged containers unless explicitly approved via the passport decision field".into(),
        priority: 20,
        evaluate: Box::new(|passport, _profile| {
            if passport.privileged {
                match passport.decision {
                    crate::enums::ContainerAdmissionDecision::Admitted => AdmissionDecision::Allow,
                    crate::enums::ContainerAdmissionDecision::RequiresHumanApproval => {
                        AdmissionDecision::Deny {
                            reason: "privileged container requires human approval".into(),
                        }
                    }
                    _ => AdmissionDecision::Deny {
                        reason: "privileged containers are blocked by policy".into(),
                    },
                }
            } else {
                AdmissionDecision::Allow
            }
        }),
    }
}

/// Reject workloads that inject secrets via environment variables.
pub fn rule_secrets_env_spray_blocked() -> AdmissionRule {
    AdmissionRule {
        name: "secrets_env_spray_blocked".into(),
        description: "Block workloads attempting to spray secrets through environment variables".into(),
        priority: 30,
        evaluate: Box::new(|passport, _profile| {
            // Heuristic: if the source contains `envFrom` or `secretKeyRef`,
            // flag as potential env-spray.
            let source_lower = passport.source.to_lowercase();
            let is_spray = source_lower.contains("envfrom")
                || source_lower.contains("secretkeyref")
                || source_lower.contains("secret_ref");

            if is_spray {
                AdmissionDecision::Deny {
                    reason: "secrets via environment variables are blocked — use a secrets manager or CSI driver".into(),
                }
            } else {
                AdmissionDecision::Allow
            }
        }),
    }
}

/// Warn or block unsigned images depending on the profile.
pub fn rule_unsigned_images_warn_or_block() -> AdmissionRule {
    AdmissionRule {
        name: "unsigned_images_warn_or_block".into(),
        description: "Warn (DEV_RELAXED) or block (STIG/AIRGAP) unsigned images".into(),
        priority: 40,
        evaluate: Box::new(|passport, profile| {
            let is_unsigned = passport.image_digests.is_empty();
            if !is_unsigned {
                return AdmissionDecision::Allow;
            }

            match profile {
                K8sProfile::K8sDevLocal => AdmissionDecision::Warn {
                    reason: "unsigned images are allowed in dev but should be signed before production".into(),
                },
                K8sProfile::K8sEdgeNode | K8sProfile::K8sWorkstationNode | K8sProfile::K8sServerCluster => {
                    AdmissionDecision::Deny {
                        reason: "unsigned images not permitted in production profiles".into(),
                    }
                }
                K8sProfile::K8sAirgapCluster => AdmissionDecision::Deny {
                    reason: "unsigned images not permitted in air-gapped environments".into(),
                },
                K8sProfile::K8sGpuAiNode => AdmissionDecision::Warn {
                    reason: "unsigned AI workloads may contain compromised model code".into(),
                },
                K8sProfile::K8sRtEdgeNode => AdmissionDecision::Deny {
                    reason: "unsigned images not permitted on real-time edge nodes".into(),
                },
            }
        }),
    }
}

/// Deny workloads that contain unknown egress targets.
pub fn rule_egress_policy_default_deny() -> AdmissionRule {
    AdmissionRule {
        name: "egress_policy_default_deny".into(),
        description: "Block workloads with unknown egress destinations by default".into(),
        priority: 50,
        evaluate: Box::new(|passport, _profile| {
            // Heuristic: if the workload source references external
            // hostnames that are not in an allow-list, block it.
            let source_lower = passport.source.to_lowercase();
            let suspicious = source_lower.contains("0.0.0.0")
                || source_lower.contains("hostnetwork: true")
                || source_lower.contains("all_traffic");

            if suspicious {
                AdmissionDecision::Deny {
                    reason: "default-deny egress policy — unknown network targets detected".into(),
                }
            } else {
                AdmissionDecision::Allow
            }
        }),
    }
}

/// Require GPU isolation for workloads targeting a GPU AI node.
pub fn rule_gpu_isolation_required() -> AdmissionRule {
    AdmissionRule {
        name: "gpu_isolation_required".into(),
        description: "Require GPU-aware isolation for GpuAiNode profile workloads".into(),
        priority: 60,
        evaluate: Box::new(|passport, profile| {
            if profile != K8sProfile::K8sGpuAiNode {
                return AdmissionDecision::Allow;
            }

            let has_gpu_isolation = matches!(
                passport.isolation_level,
                IsolationLevel::GVisor | IsolationLevel::Kata | IsolationLevel::FullVm
            );

            if has_gpu_isolation {
                AdmissionDecision::Allow
            } else {
                AdmissionDecision::Deny {
                    reason: "GPU workloads require gVisor/Kata/FullVM isolation on GpuAiNode profile".into(),
                }
            }
        }),
    }
}

/// Build the default set of admission rules.
pub fn default_admission_rules() -> Vec<AdmissionRule> {
    vec![
        rule_digest_pin_required(),
        rule_privileged_containers_blocked(),
        rule_secrets_env_spray_blocked(),
        rule_unsigned_images_warn_or_block(),
        rule_egress_policy_default_deny(),
        rule_gpu_isolation_required(),
    ]
}

// ---------------------------------------------------------------------------
// Admission controller
// ---------------------------------------------------------------------------

/// Multi-rule admission controller with an optional webhook endpoint.
#[derive(Debug)]
pub struct K8sAdmissionController {
    pub rules: Vec<AdmissionRule>,
    pub webhook_endpoint: String,
    pub deny_on_failure: bool,
}

impl K8sAdmissionController {
    /// Create a new admission controller with default rules.
    pub fn new(webhook_endpoint: impl Into<String>, deny_on_failure: bool) -> Self {
        let mut rules = default_admission_rules();
        rules.sort_by_key(|r| r.priority);
        Self {
            rules,
            webhook_endpoint: webhook_endpoint.into(),
            deny_on_failure,
        }
    }

    /// Run every rule against the passport and return the aggregate decision.
    ///
    /// Rules are evaluated in priority order. The first `Deny` stops
    /// evaluation and returns immediately.  Warnings are collected and
    /// returned if no denial occurred.
    pub fn evaluate(
        &self,
        passport: &CloudNativePassport,
        profile: K8sProfile,
    ) -> AdmissionDecision {
        let mut warnings: Vec<String> = Vec::new();

        for rule in &self.rules {
            let decision = (rule.evaluate)(passport, profile);
            match decision {
                AdmissionDecision::Deny { reason } => {
                    return AdmissionDecision::Deny { reason };
                }
                AdmissionDecision::Warn { reason } => {
                    warnings.push(format!("[{}] {}", rule.name, reason));
                }
                AdmissionDecision::Allow => {}
            }
        }

        if warnings.is_empty() {
            AdmissionDecision::Allow
        } else {
            AdmissionDecision::Warn {
                reason: warnings.join("; "),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// K8s operator
// ---------------------------------------------------------------------------

/// Top-level K8s-native operator.
///
/// Owns all namespaces and workloads, routes admission through the configured
/// controller, generates manifests, and tracks workload health.
pub struct K8sOperator {
    pub profile: K8sProfile,
    pub namespaces: HashMap<String, K8sNamespace>,
    pub workloads: HashMap<Ulid, K8sWorkloadDescriptor>,
    pub admission_controller: K8sAdmissionController,
    pub evidence_emitter: Option<Arc<dyn ContainerEvidenceEmitter>>,
}

impl K8sOperator {
    /// Create a new operator for the given profile.
    pub fn new(profile: K8sProfile) -> Self {
        let mut namespaces = HashMap::new();
        let default_ns = K8sNamespace::new("default");
        namespaces.insert("default".into(), default_ns);

        Self {
            profile,
            namespaces,
            workloads: HashMap::new(),
            admission_controller: K8sAdmissionController::new("http://localhost:8443/validate", true),
            evidence_emitter: None,
        }
    }

    /// Attach an evidence emitter to the operator.
    pub fn with_evidence_emitter(mut self, emitter: Arc<dyn ContainerEvidenceEmitter>) -> Self {
        self.evidence_emitter = Some(emitter);
        self
    }

    /// Register a namespace with the operator.
    pub fn register_namespace(&mut self, ns: K8sNamespace) -> Result<(), K8sOperatorError> {
        let name = ns.name.clone();
        self.namespaces.insert(name, ns);
        Ok(())
    }

    /// Run all admission rules against a passport.
    ///
    /// Returns the aggregate decision.  If `deny_on_failure` is true in the
    /// controller configuration, any `Deny` is propagated as an error.
    pub fn admit_workload(
        &self,
        passport: &CloudNativePassport,
        namespace: &str,
    ) -> Result<AdmissionDecision, K8sOperatorError> {
        if !self.namespaces.contains_key(namespace) {
            return Err(K8sOperatorError::NamespaceNotFound(namespace.into()));
        }

        let decision = self
            .admission_controller
            .evaluate(passport, self.profile);

        match &decision {
            AdmissionDecision::Deny { reason } => {
                if let Some(ref emitter) = self.evidence_emitter {
                    emitter.emit_blocked(
                        Ulid::from_string(&passport.passport_id.strip_prefix("cnp_").unwrap_or(""))
                            .unwrap_or_else(|_| Ulid::new()),
                        namespace,
                        reason,
                    );
                }
                if self.admission_controller.deny_on_failure {
                    return Err(K8sOperatorError::AdmissionDenied(reason.clone()));
                }
            }
            AdmissionDecision::Allow => {
                if let Some(ref emitter) = self.evidence_emitter {
                    emitter.emit_admitted(
                        Ulid::from_string(&passport.passport_id.strip_prefix("cnp_").unwrap_or(""))
                            .unwrap_or_else(|_| Ulid::new()),
                        namespace,
                    );
                }
            }
            AdmissionDecision::Warn { .. } => {}
        }

        Ok(decision)
    }

    /// Deploy an admitted workload into the operator's workload map.
    ///
    /// Generates a manifest, assigns the workload to a namespace, and records
    /// the initial revision snapshot.
    pub fn deploy_workload(
        &mut self,
        passport: CloudNativePassport,
        namespace: impl Into<String>,
        resources: K8sResourceRequest,
    ) -> Result<K8sWorkloadDescriptor, K8sOperatorError> {
        let ns: String = namespace.into();

        // Admission gate
        let decision = self.admit_workload(&passport, &ns)?;
        if !decision.is_allowed() {
            return Err(K8sOperatorError::AdmissionDenied(format!(
                "workload not admitted: {:?}",
                decision
            )));
        }

        let workload_id = Ulid::new();
        let workload = K8sWorkloadDescriptor {
            workload_id,
            passport: passport.clone(),
            namespace: ns,
            state: WorkloadState::Admitted,
            profile: self.profile,
            replica_count: 1,
            resources,
            revision_history: vec![K8sWorkloadRevision {
                passport,
                state: WorkloadState::Admitted,
                replica_count: 1,
                resources: K8sResourceRequest::default(),
                recorded_at: Utc::now(),
            }],
        };

        self.workloads.insert(workload_id, workload.clone());
        Ok(workload)
    }

    /// Generate a Kubernetes Deployment manifest (YAML) from a workload descriptor.
    pub fn generate_manifest(
        &self,
        workload: &K8sWorkloadDescriptor,
    ) -> Result<String, K8sOperatorError> {
        let passport = &workload.passport;
        let name = sanitize_k8s_name(&passport.workload_id);

        let engine = match self.profile {
            K8sProfile::K8sGpuAiNode => ContainerEngine::Containerd,
            K8sProfile::K8sAirgapCluster => ContainerEngine::PodmanRootful,
            _ => passport.runtime_engine,
        };

        let security_context = if passport.rootless {
            r#"
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        privileged: false
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false"#
        } else {
            r#"
      securityContext:
        privileged: false"#
        };

        // Strip any "sha256:" prefix for the image field
        let image = passport
            .image_digests
            .first()
            .map(|d| d.strip_prefix("sha256:").unwrap_or(d))
            .unwrap_or("scratch");

        // Resolve to string for manifest output
        let engine_str = serde_json::to_string(&engine)
            .map_err(|e| K8sOperatorError::InvalidManifest(e.to_string()))?;

        let gpu_section = if self.profile == K8sProfile::K8sGpuAiNode && workload.resources.gpu_count > 0 {
            format!(
                r#"
        nvidia.com/gpu: "{}""#,
                workload.resources.gpu_count
            )
        } else {
            String::new()
        };

        let manifest = format!(
            r#"---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: {name}
    app.kubernetes.io/managed-by: aios-operator
    aios.io/profile: {profile:?}
    aios.io/engine: {engine_str}
    aios.io/rootless: "{rootless}"
spec:
  replicas: {replicas}
  selector:
    matchLabels:
      app.kubernetes.io/name: {name}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: {name}
        aios.io/profile: {profile:?}
    spec:
      restartPolicy: Always
      runtimeClassName: {runtime_class}{security_context}
      containers:
      - name: {name}
        image: {image}
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
          protocol: TCP
        resources:
          requests:
            cpu: {cpu_m}m
            memory: {mem_m}Mi{gpu_section}
          limits:
            cpu: {cpu_limit_m}m
            memory: {mem_limit_m}Mi
        env:
        - name: AIOS_WORKLOAD_ID
          value: "{wl_id}"
        - name: AIOS_PASSPORT_ID
          value: "{pp_id}"
"#,
            name = name,
            namespace = workload.namespace,
            profile = self.profile,
            engine_str = engine_str,
            rootless = passport.rootless,
            replicas = workload.replica_count,
            runtime_class = match self.profile {
                K8sProfile::K8sGpuAiNode => "nvidia",
                _ => "aios",
            },
            security_context = security_context,
            image = image,
            cpu_m = workload.resources.cpu_millicores,
            mem_m = workload.resources.memory_mb,
            cpu_limit_m = workload.resources.cpu_millicores.saturating_mul(2),
            mem_limit_m = workload.resources.memory_mb.saturating_mul(2),
            gpu_section = gpu_section,
            wl_id = workload.workload_id,
            pp_id = passport.passport_id,
        );

        Ok(manifest)
    }

    /// Rollback a workload to its previous revision.
    pub fn rollback_workload(
        &mut self,
        workload_id: Ulid,
    ) -> Result<K8sWorkloadDescriptor, K8sOperatorError> {
        let workload = self
            .workloads
            .get_mut(&workload_id)
            .ok_or(K8sOperatorError::WorkloadNotFound(workload_id))?;

        if workload.revision_history.len() < 2 {
            return Err(K8sOperatorError::RollbackFailed(
                workload_id,
                "no previous revision to roll back to".into(),
            ));
        }

        // Remove current (newest) and restore previous
        workload.revision_history.remove(0);
        let prev = workload
            .revision_history
            .first()
            .ok_or_else(|| {
                K8sOperatorError::RollbackFailed(
                    workload_id,
                    "previous revision missing".into(),
                )
            })?
            .clone();

        workload.passport = prev.passport;
        workload.state = prev.state;
        workload.replica_count = prev.replica_count;
        workload.resources = prev.resources;

        Ok(workload.clone())
    }

    /// Check the health of a specific workload.
    ///
    /// In a real operator this would query the K8s API; here we synthesize
    /// health based on the workload state.
    pub fn health_check(
        &self,
        workload_id: Ulid,
    ) -> Result<WorkloadHealth, K8sOperatorError> {
        let workload = self
            .workloads
            .get(&workload_id)
            .ok_or(K8sOperatorError::WorkloadNotFound(workload_id))?;

        let (ready_replicas, conditions) = match workload.state {
            WorkloadState::Running => (workload.replica_count, vec!["Ready".into()]),
            WorkloadState::Degraded => {
                let ready = workload.replica_count.saturating_sub(1).max(0);
                (ready, vec!["Degraded: replica count below threshold".into()])
            }
            WorkloadState::Admitted | WorkloadState::Pending => {
                (0, vec!["Progressing".into()])
            }
            WorkloadState::Terminated => (0, vec!["Terminated".into()]),
            WorkloadState::Blocked => (0, vec!["Blocked by admission policy".into()]),
        };

        Ok(WorkloadHealth {
            workload_id,
            state: workload.state,
            ready_replicas,
            desired_replicas: workload.replica_count,
            restarts: 0,
            last_transition: workload
                .revision_history
                .first()
                .map(|r| r.recorded_at)
                .unwrap_or_else(Utc::now),
            conditions,
        })
    }

    /// Transition a workload to a new state.
    pub fn set_workload_state(
        &mut self,
        workload_id: Ulid,
        target: WorkloadState,
    ) -> Result<(), K8sOperatorError> {
        let workload = self
            .workloads
            .get_mut(&workload_id)
            .ok_or(K8sOperatorError::WorkloadNotFound(workload_id))?;

        if !workload.state.can_transition_to(target) {
            return Err(K8sOperatorError::DeploymentFailed(format!(
                "invalid state transition {:?} -> {:?}",
                workload.state, target
            )));
        }

        workload.state = target;
        Ok(())
    }

    /// List all workloads in a given namespace.
    pub fn list_workloads_in_namespace(&self, namespace: &str) -> Vec<&K8sWorkloadDescriptor> {
        self.workloads
            .values()
            .filter(|w| w.namespace == namespace)
            .collect()
    }
}

impl std::fmt::Debug for K8sOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sOperator")
            .field("profile", &self.profile)
            .field("namespaces", &self.namespaces)
            .field("workload_count", &self.workloads.len())
            .field("admission_controller", &self.admission_controller)
            .field("has_evidence_emitter", &self.evidence_emitter.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a [`K8sProfile`] to a security label string compatible with
/// `profile_gates`.
pub fn profile_to_security_label(profile: K8sProfile) -> &'static str {
    match profile {
        K8sProfile::K8sDevLocal => "DEV_RELAXED",
        K8sProfile::K8sEdgeNode
        | K8sProfile::K8sWorkstationNode
        | K8sProfile::K8sServerCluster => "STIG_ALIGNED",
        K8sProfile::K8sAirgapCluster => "AIRGAP_HIGH",
        K8sProfile::K8sGpuAiNode => "STIG_ALIGNED",
        K8sProfile::K8sRtEdgeNode => "AIRGAP_HIGH",
    }
}

/// Sanitize a workload ID into a valid Kubernetes resource name.
fn sanitize_k8s_name(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_lowercase()
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
    use crate::enums::ContainerAdmissionDecision;
    use crate::passport::CloudNativePassport;

    fn make_passport(
        workload_id: &str,
        digests: Vec<&str>,
        privileged: bool,
        decision: ContainerAdmissionDecision,
    ) -> CloudNativePassport {
        CloudNativePassport {
            passport_id: format!("cnp_{}", Ulid::new()),
            workload_id: workload_id.into(),
            source: "docker.io/app:latest".into(),
            image_digests: digests.into_iter().map(String::from).collect(),
            runtime_engine: ContainerEngine::PodmanRootless,
            isolation_level: IsolationLevel::Rootless,
            rootless: true,
            privileged,
            decision,
        }
    }

    // -- Admission rules ---------------------------------------------------

    #[test]
    fn admit_workload_with_digest_pinned_image_accept() {
        let passport = make_passport("wl-001", vec!["sha256:abc123"], false, ContainerAdmissionDecision::Admitted);
        let op = K8sOperator::new(K8sProfile::K8sServerCluster);
        let result = op.admit_workload(&passport, "default");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AdmissionDecision::Allow);
    }

    #[test]
    fn admit_workload_without_digest_reject_stig() {
        let passport = make_passport("wl-002", vec![], false, ContainerAdmissionDecision::Admitted);
        let op = K8sOperator::new(K8sProfile::K8sServerCluster);
        let result = op.admit_workload(&passport, "default");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("digest-pinned"), "expected digest error, got: {err}");
    }

    #[test]
    fn admit_privileged_container_reject() {
        let passport = make_passport(
            "wl-003",
            vec!["sha256:abc123"],
            true,
            ContainerAdmissionDecision::RequiresHumanApproval,
        );
        let op = K8sOperator::new(K8sProfile::K8sServerCluster);
        let result = op.admit_workload(&passport, "default");
        assert!(result.is_err());
    }

    #[test]
    fn admit_privileged_with_human_approval_accept() {
        let passport = make_passport(
            "wl-004",
            vec!["sha256:abc123"],
            true,
            ContainerAdmissionDecision::Admitted,
        );
        let op = K8sOperator::new(K8sProfile::K8sServerCluster);
        let result = op.admit_workload(&passport, "default");
        assert!(result.is_ok());
    }

    #[test]
    fn env_spray_secrets_block() {
        let mut passport = make_passport(
            "wl-005",
            vec!["sha256:abc123"],
            false,
            ContainerAdmissionDecision::Admitted,
        );
        passport.source = "deployment with envFrom and secretKeyRef".into();
        let op = K8sOperator::new(K8sProfile::K8sServerCluster);
        let result = op.admit_workload(&passport, "default");
        assert!(result.is_err());
    }

    // -- GPU isolation -----------------------------------------------------

    #[test]
    fn gpu_isolation_required_reject_weak_isolation() {
        let mut passport = make_passport(
            "wl-gpu",
            vec!["sha256:abc123"],
            false,
            ContainerAdmissionDecision::Admitted,
        );
        passport.isolation_level = IsolationLevel::Rootless;
        let op = K8sOperator::new(K8sProfile::K8sGpuAiNode);
        let result = op.admit_workload(&passport, "default");
        assert!(result.is_err(), "GPU node should reject Rootless isolation");
    }

    #[test]
    fn gpu_isolation_required_accept_gvisor() {
        let mut passport = make_passport(
            "wl-gpu-ok",
            vec!["sha256:abc123"],
            false,
            ContainerAdmissionDecision::Admitted,
        );
        passport.isolation_level = IsolationLevel::GVisor;
        let op = K8sOperator::new(K8sProfile::K8sGpuAiNode);
        let result = op.admit_workload(&passport, "default");
        assert!(result.is_ok(), "GPU node should accept gVisor isolation");
    }

    // -- Workload state FSM ------------------------------------------------

    #[test]
    fn workload_state_fsm_valid_transitions() {
        assert!(WorkloadState::Admitted.can_transition_to(WorkloadState::Pending));
        assert!(WorkloadState::Pending.can_transition_to(WorkloadState::Running));
        assert!(WorkloadState::Running.can_transition_to(WorkloadState::Degraded));
        assert!(WorkloadState::Degraded.can_transition_to(WorkloadState::Running));
        assert!(WorkloadState::Running.can_transition_to(WorkloadState::Terminated));
    }

    #[test]
    fn workload_state_fsm_invalid_transitions() {
        assert!(!WorkloadState::Terminated.can_transition_to(WorkloadState::Running));
        assert!(!WorkloadState::Blocked.can_transition_to(WorkloadState::Admitted));
        assert!(!WorkloadState::Running.can_transition_to(WorkloadState::Admitted));
    }

    // -- Admission rule priority ordering ----------------------------------

    #[test]
    fn admission_rules_sorted_by_priority() {
        let controller = K8sAdmissionController::new("http://localhost", true);
        let priorities: Vec<u8> = controller.rules.iter().map(|r| r.priority).collect();
        let mut sorted = priorities.clone();
        sorted.sort();
        assert_eq!(priorities, sorted, "admission rules must be sorted by priority");
    }

    // -- K8sProfile → security label --------------------------------------

    #[test]
    fn profile_to_security_label_mapping() {
        assert_eq!(profile_to_security_label(K8sProfile::K8sDevLocal), "DEV_RELAXED");
        assert_eq!(profile_to_security_label(K8sProfile::K8sEdgeNode), "STIG_ALIGNED");
        assert_eq!(profile_to_security_label(K8sProfile::K8sWorkstationNode), "STIG_ALIGNED");
        assert_eq!(profile_to_security_label(K8sProfile::K8sServerCluster), "STIG_ALIGNED");
        assert_eq!(profile_to_security_label(K8sProfile::K8sAirgapCluster), "AIRGAP_HIGH");
        assert_eq!(profile_to_security_label(K8sProfile::K8sGpuAiNode), "STIG_ALIGNED");
        assert_eq!(profile_to_security_label(K8sProfile::K8sRtEdgeNode), "AIRGAP_HIGH");
    }

    // -- K8sProfile selection → correct engine -----------------------------

    #[test]
    fn gpu_ai_node_defaults_to_containerd() {
        let op = K8sOperator::new(K8sProfile::K8sGpuAiNode);
        let mut passport = make_passport("wl-eng", vec!["sha256:d1"], false, ContainerAdmissionDecision::Admitted);
        passport.isolation_level = IsolationLevel::GVisor;
        let mut op = op;
        let wl = op.deploy_workload(passport, "default", K8sResourceRequest::default()).unwrap();
        let manifest = op.generate_manifest(&wl).unwrap();
        assert!(manifest.contains("CONTAINERD") || manifest.contains("containerd"));
    }

    #[test]
    fn dev_local_allows_unsigned_as_warn() {
        let passport = make_passport("wl-dev", vec![], false, ContainerAdmissionDecision::Admitted);
        let op = K8sOperator::new(K8sProfile::K8sDevLocal);
        let result = op.admit_workload(&passport, "default");
        // DEV_RELAXED does not require digest pin, and unsigned rule returns Warn
        assert!(result.is_ok());
    }

    // -- Deploy / generate manifest ----------------------------------------

    #[test]
    fn deploy_workload_succeeds_for_admitted_passport() {
        let mut op = K8sOperator::new(K8sProfile::K8sDevLocal);
        let passport = make_passport("wl-deploy", vec!["sha256:d1"], false, ContainerAdmissionDecision::Admitted);
        let wl = op.deploy_workload(passport, "default", K8sResourceRequest::default()).unwrap();
        assert_eq!(wl.state, WorkloadState::Admitted);
        assert!(op.workloads.contains_key(&wl.workload_id));
    }

    #[test]
    fn deploy_workload_fails_for_blocked_passport() {
        let mut op = K8sOperator::new(K8sProfile::K8sAirgapCluster);
        let passport = make_passport("wl-blocked", vec![], false, ContainerAdmissionDecision::Admitted);
        let result = op.deploy_workload(passport, "default", K8sResourceRequest::default());
        assert!(result.is_err());
    }

    #[test]
    fn generate_manifest_produces_valid_yaml_structure() {
        let mut op = K8sOperator::new(K8sProfile::K8sServerCluster);
        let passport = make_passport("wl-manifest", vec!["sha256:d1"], false, ContainerAdmissionDecision::Admitted);
        let wl = op.deploy_workload(passport, "default", K8sResourceRequest::default()).unwrap();
        let manifest = op.generate_manifest(&wl).unwrap();

        assert!(manifest.contains("apiVersion: apps/v1"));
        assert!(manifest.contains("kind: Deployment"));
        assert!(manifest.contains("runAsNonRoot: true"));
        assert!(manifest.contains("readOnlyRootFilesystem: true"));
    }

    #[test]
    fn generate_manifest_for_gpu_profile_includes_gpu_resources() {
        let mut op = K8sOperator::new(K8sProfile::K8sGpuAiNode);
        let mut passport = make_passport("wl-gpu-m", vec!["sha256:d1"], false, ContainerAdmissionDecision::Admitted);
        passport.isolation_level = IsolationLevel::GVisor;
        let resources = K8sResourceRequest {
            cpu_millicores: 1000,
            memory_mb: 4096,
            gpu_count: 1,
        };
        let wl = op.deploy_workload(passport, "default", resources).unwrap();
        let manifest = op.generate_manifest(&wl).unwrap();
        assert!(manifest.contains("nvidia.com/gpu"), "GPU manifest should include nvidia.com/gpu");
    }

    // -- Rollback ----------------------------------------------------------

    #[test]
    fn rollback_workload_restores_previous_version() {
        let mut op = K8sOperator::new(K8sProfile::K8sDevLocal);
        let p1 = make_passport("wl-rb", vec!["sha256:v1"], false, ContainerAdmissionDecision::Admitted);
        let wl = op.deploy_workload(p1, "default", K8sResourceRequest::default()).unwrap();
        let wid = wl.workload_id;

        // Simulate a revision push
        {
            let w = op.workloads.get_mut(&wid).unwrap();
            let p2 = make_passport("wl-rb", vec!["sha256:v2"], false, ContainerAdmissionDecision::Admitted);
            w.revision_history.insert(
                0,
                K8sWorkloadRevision {
                    passport: p2.clone(),
                    state: WorkloadState::Running,
                    replica_count: 2,
                    resources: K8sResourceRequest::default(),
                    recorded_at: Utc::now(),
                },
            );
            w.passport = p2;
            w.replica_count = 2;
            w.state = WorkloadState::Running;
        }

        let restored = op.rollback_workload(wid).unwrap();
        assert_eq!(restored.replica_count, 1, "rollback should restore original replica count");
        assert_eq!(restored.state, WorkloadState::Admitted);
        let digests = &restored.passport.image_digests;
        assert!(digests.iter().any(|d| d.contains("v1")), "rollback should restore v1 image");
    }

    #[test]
    fn rollback_without_history_fails() {
        let mut op = K8sOperator::new(K8sProfile::K8sDevLocal);
        let passport = make_passport("wl-nohist", vec!["sha256:v1"], false, ContainerAdmissionDecision::Admitted);
        let wl = op.deploy_workload(passport, "default", K8sResourceRequest::default()).unwrap();
        let result = op.rollback_workload(wl.workload_id);
        assert!(result.is_err());
    }

    // -- Health check ------------------------------------------------------

    #[test]
    fn health_check_running_workload() {
        let mut op = K8sOperator::new(K8sProfile::K8sDevLocal);
        let passport = make_passport("wl-hc", vec!["sha256:d1"], false, ContainerAdmissionDecision::Admitted);
        let wl = op.deploy_workload(passport, "default", K8sResourceRequest::default()).unwrap();
        let _ = op.set_workload_state(wl.workload_id, WorkloadState::Pending);
        let _ = op.set_workload_state(wl.workload_id, WorkloadState::Running);

        let health = op.health_check(wl.workload_id).unwrap();
        assert_eq!(health.state, WorkloadState::Running);
        assert_eq!(health.ready_replicas, 1);
        assert_eq!(health.desired_replicas, 1);
        assert!(health.conditions.contains(&"Ready".to_string()));
    }

    #[test]
    fn health_check_returns_error_for_unknown_workload() {
        let op = K8sOperator::new(K8sProfile::K8sDevLocal);
        let result = op.health_check(Ulid::new());
        assert!(result.is_err());
    }

    // -- State transitions via operator ------------------------------------

    #[test]
    fn operator_rejects_invalid_state_transition() {
        let mut op = K8sOperator::new(K8sProfile::K8sDevLocal);
        let passport = make_passport("wl-fsm", vec!["sha256:d1"], false, ContainerAdmissionDecision::Admitted);
        let wl = op.deploy_workload(passport, "default", K8sResourceRequest::default()).unwrap();

        // Terminated → Running is invalid
        op.set_workload_state(wl.workload_id, WorkloadState::Terminated).unwrap();
        let result = op.set_workload_state(wl.workload_id, WorkloadState::Running);
        assert!(result.is_err());
    }

    // -- Namespace registration --------------------------------------------

    #[test]
    fn register_and_use_custom_namespace() {
        let mut op = K8sOperator::new(K8sProfile::K8sDevLocal);
        let ns = K8sNamespace::new("production");
        op.register_namespace(ns).unwrap();

        let passport = make_passport("wl-ns", vec!["sha256:d1"], false, ContainerAdmissionDecision::Admitted);
        let wl = op.deploy_workload(passport, "production", K8sResourceRequest::default()).unwrap();
        assert_eq!(wl.namespace, "production");
        assert_eq!(op.list_workloads_in_namespace("production").len(), 1);
    }

    #[test]
    fn admit_to_unknown_namespace_fails() {
        let op = K8sOperator::new(K8sProfile::K8sDevLocal);
        let passport = make_passport("wl-unk", vec!["sha256:d1"], false, ContainerAdmissionDecision::Admitted);
        let result = op.admit_workload(&passport, "nonexistent");
        assert!(result.is_err());
    }

    // -- Airgap profile blocks unsigned ------------------------------------

    #[test]
    fn airgap_cluster_blocks_unsigned() {
        let mut op = K8sOperator::new(K8sProfile::K8sAirgapCluster);
        let passport = make_passport("wl-airgap", vec![], false, ContainerAdmissionDecision::Admitted);
        let result = op.deploy_workload(passport, "default", K8sResourceRequest::default());
        assert!(result.is_err());
    }

    // -- No unsafe / no block_admitted -------------------------------------
}
