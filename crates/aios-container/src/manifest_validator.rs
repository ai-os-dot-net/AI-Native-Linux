//! K8s manifest validator — parse and validate Kubernetes YAML/JSON manifests.
//!
//! Checks structural correctness, detects dangerous security configurations
//! (privileged mode, hostPID, hostNetwork, hostIPC, writable root filesystem),
//! and validates container specifications against the AI-OS container policy.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors surfaced during manifest validation.
#[derive(Error, Debug)]
pub enum ManifestValidationError {
    #[error("YAML parse error: {0}")]
    ParseError(String),

    #[error("manifest structure error: {0}")]
    StructureError(String),

    #[error("invalid resource kind '{kind}': {detail}")]
    InvalidResource { kind: String, detail: String },
}

// ---------------------------------------------------------------------------
// Validation severity
// ---------------------------------------------------------------------------

/// Severity level for a validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationSeverity {
    /// Informational; does not block deployment.
    Warning,
    /// Should be reviewed; may block depending on profile.
    Error,
    /// Hard block — violates a mandatory security control.
    Block,
}

// ---------------------------------------------------------------------------
// Validation error
// ---------------------------------------------------------------------------

/// A single validation finding tied to a specific resource and field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Resource name (e.g. `"my-deployment"`).
    pub resource: String,
    /// Field path (e.g. `"spec.template.spec.containers[0].securityContext"`).
    pub field: String,
    /// Human-readable description of the issue.
    pub message: String,
    /// Severity of the finding.
    pub severity: ValidationSeverity,
}

// ---------------------------------------------------------------------------
// Port spec
// ---------------------------------------------------------------------------

/// A container port definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortSpec {
    pub container_port: u16,
    pub protocol: String,
    pub name: Option<String>,
    pub host_port: Option<u16>,
}

// ---------------------------------------------------------------------------
// Volume spec
// ---------------------------------------------------------------------------

/// A volume mount definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeSpec {
    pub name: String,
    pub mount_path: String,
    pub read_only: bool,
}

// ---------------------------------------------------------------------------
// Env var
// ---------------------------------------------------------------------------

/// A single environment variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: Option<String>,
    #[serde(default)]
    pub value_from_secret: bool,
}

// ---------------------------------------------------------------------------
// Resource spec
// ---------------------------------------------------------------------------

/// Per-container resource specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    pub cpu_request_millicores: u32,
    pub memory_request_mb: u32,
    pub cpu_limit_millicores: u32,
    pub memory_limit_mb: u32,
}

// ---------------------------------------------------------------------------
// Container spec
// ---------------------------------------------------------------------------

/// Parsed container specification from a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub ports: Vec<PortSpec>,
    pub volumes: Vec<VolumeSpec>,
    pub env_vars: Vec<EnvVar>,
    pub resources: ResourceSpec,
    pub privileged: bool,
    pub run_as_root: bool,
    pub read_only_root_filesystem: bool,
}

// ---------------------------------------------------------------------------
// Manifest resource
// ---------------------------------------------------------------------------

/// A single K8s resource extracted from a manifest document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestResource {
    pub kind: String,
    pub api_version: String,
    pub name: String,
    pub namespace: Option<String>,
    pub containers: Vec<ContainerSpec>,
    pub host_pid: bool,
    pub host_network: bool,
    pub host_ipc: bool,
}

// ---------------------------------------------------------------------------
// Validated manifest
// ---------------------------------------------------------------------------

/// Result of manifest validation with resources, warnings, and errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedManifest {
    pub resources: Vec<ManifestResource>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl ValidatedManifest {
    /// Returns `true` when the manifest has no `Block`-severity errors and
    /// no structural errors.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Manifest validator
// ---------------------------------------------------------------------------

/// Validates Kubernetes manifests against the AI-OS container security policy.
#[derive(Debug, Default)]
pub struct K8sManifestValidator {
    /// If true, allow privileged containers (DEV_RELAXED profile).
    pub allow_privileged: bool,
    /// If true, allow host PID namespace sharing.
    pub allow_host_pid: bool,
    /// If true, allow host network.
    pub allow_host_network: bool,
    /// If true, allow host IPC.
    pub allow_host_ipc: bool,
}

impl K8sManifestValidator {
    /// Create a new validator with production-safe defaults.
    pub fn new() -> Self {
        Self {
            allow_privileged: false,
            allow_host_pid: false,
            allow_host_network: false,
            allow_host_ipc: false,
        }
    }

    /// Create a permissive validator for development.
    pub fn dev_relaxed() -> Self {
        Self {
            allow_privileged: true,
            allow_host_pid: true,
            allow_host_network: true,
            allow_host_ipc: false,
        }
    }

    /// Validate a Kubernetes manifest YAML string.
    ///
    /// Parses the YAML into resource objects and runs all security checks.
    /// Returns a `ValidatedManifest` with the parsed resources and any
    /// findings.
    pub fn validate_manifest(
        &self,
        yaml: &str,
    ) -> Result<ValidatedManifest, ManifestValidationError> {
        // Parse multi-document YAML
        let docs = parse_yaml_documents(yaml)?;

        let mut resources: Vec<ManifestResource> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        for (doc_idx, doc) in docs.iter().enumerate() {
            match self.parse_resource(doc, doc_idx) {
                Ok(resource) => {
                    let findings = self.validate_resource(&resource);
                    for finding in &findings {
                        match finding.severity {
                            ValidationSeverity::Warning => {
                                warnings.push(format!(
                                    "[{}] {}: {} (field: {})",
                                    resource.name,
                                    finding.severity_label(),
                                    finding.message,
                                    finding.field
                                ));
                            }
                            ValidationSeverity::Error | ValidationSeverity::Block => {
                                errors.push(format!(
                                    "[{}] {}: {} (field: {})",
                                    resource.name,
                                    finding.severity_label(),
                                    finding.message,
                                    finding.field
                                ));
                            }
                        }
                    }
                    resources.push(resource);
                }
                Err(e) => {
                    errors.push(format!("document {doc_idx}: {e}"));
                }
            }
        }

        if resources.is_empty() && !docs.is_empty() {
            return Err(ManifestValidationError::StructureError(
                "no valid resources found in manifest".into(),
            ));
        }

        Ok(ValidatedManifest {
            resources,
            warnings,
            errors,
        })
    }

    /// Parse a single YAML document into a `ManifestResource`.
    fn parse_resource(
        &self,
        doc: &serde_yaml::Value,
        _doc_idx: usize,
    ) -> Result<ManifestResource, ManifestValidationError> {
        let mapping = doc.as_mapping().ok_or_else(|| {
            ManifestValidationError::StructureError("YAML document is not a mapping".into())
        })?;

        let kind = get_str(mapping, "kind")?;
        let api_version = get_str(mapping, "apiVersion").unwrap_or_else(|_| "v1".into());

        let metadata = mapping
            .get(serde_yaml::Value::String("metadata".into()))
            .and_then(|v| v.as_mapping());

        let name = metadata
            .and_then(|m| m.get(serde_yaml::Value::String("name".into())))
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed")
            .to_string();

        let namespace = metadata.and_then(|m| {
            m.get(serde_yaml::Value::String("namespace".into()))
                .and_then(|v| v.as_str())
                .map(String::from)
        });

        // Extract pod spec (handles Deployment, StatefulSet, DaemonSet, Pod)
        let pod_spec = match kind.as_str() {
            "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "Job" | "CronJob" => {
                mapping
                    .get(serde_yaml::Value::String("spec".into()))
                    .and_then(|s| s.as_mapping())
                    .and_then(|s| s.get(serde_yaml::Value::String("template".into())))
                    .and_then(|t| t.as_mapping())
                    .and_then(|t| t.get(serde_yaml::Value::String("spec".into())))
                    .and_then(|s| s.as_mapping())
            }
            "Pod" => mapping
                .get(serde_yaml::Value::String("spec".into()))
                .and_then(|s| s.as_mapping()),
            _ => None,
        };

        // Extract host-level flags
        let host_pid = pod_spec
            .and_then(|s| s.get(serde_yaml::Value::String("hostPID".into())))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let host_network = pod_spec
            .and_then(|s| s.get(serde_yaml::Value::String("hostNetwork".into())))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let host_ipc = pod_spec
            .and_then(|s| s.get(serde_yaml::Value::String("hostIPC".into())))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Extract containers
        let containers = pod_spec
            .and_then(|s| s.get(serde_yaml::Value::String("containers".into())))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|c| c.as_mapping())
                    .map(|cm| self.parse_container(cm))
                    .collect()
            })
            .unwrap_or_default();

        Ok(ManifestResource {
            kind,
            api_version,
            name,
            namespace,
            containers,
            host_pid,
            host_network,
            host_ipc,
        })
    }

    /// Parse a single container from a YAML mapping.
    fn parse_container(&self, cm: &serde_yaml::Mapping) -> ContainerSpec {
        let name = cm
            .get(serde_yaml::Value::String("name".into()))
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed-container")
            .to_string();

        let image = cm
            .get(serde_yaml::Value::String("image".into()))
            .and_then(|v| v.as_str())
            .unwrap_or("scratch")
            .to_string();

        let ports: Vec<PortSpec> = cm
            .get(serde_yaml::Value::String("ports".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|p| p.as_mapping())
                    .map(|pm| PortSpec {
                        container_port: pm
                            .get(serde_yaml::Value::String("containerPort".into()))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u16,
                        protocol: pm
                            .get(serde_yaml::Value::String("protocol".into()))
                            .and_then(|v| v.as_str())
                            .unwrap_or("TCP")
                            .to_string(),
                        name: pm
                            .get(serde_yaml::Value::String("name".into()))
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        host_port: pm
                            .get(serde_yaml::Value::String("hostPort".into()))
                            .and_then(|v| v.as_u64())
                            .map(|p| p as u16),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let volumes: Vec<VolumeSpec> = cm
            .get(serde_yaml::Value::String("volumeMounts".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|vm| vm.as_mapping())
                    .map(|vmm| VolumeSpec {
                        name: vmm
                            .get(serde_yaml::Value::String("name".into()))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        mount_path: vmm
                            .get(serde_yaml::Value::String("mountPath".into()))
                            .and_then(|v| v.as_str())
                            .unwrap_or("/")
                            .to_string(),
                        read_only: vmm
                            .get(serde_yaml::Value::String("readOnly".into()))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let env_vars: Vec<EnvVar> = cm
            .get(serde_yaml::Value::String("env".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|e| e.as_mapping())
                    .map(|em| {
                        let has_secret = em
                            .get(serde_yaml::Value::String("valueFrom".into()))
                            .and_then(|vf| vf.as_mapping())
                            .and_then(|vfm| {
                                vfm.get(serde_yaml::Value::String("secretKeyRef".into()))
                            })
                            .is_some();

                        EnvVar {
                            name: em
                                .get(serde_yaml::Value::String("name".into()))
                                .and_then(|v| v.as_str())
                                .unwrap_or("UNKNOWN")
                                .to_string(),
                            value: em
                                .get(serde_yaml::Value::String("value".into()))
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            value_from_secret: has_secret,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let resources = cm
            .get(serde_yaml::Value::String("resources".into()))
            .and_then(|v| v.as_mapping());

        let (cpu_req, mem_req) = resources
            .and_then(|r| r.get(serde_yaml::Value::String("requests".into())))
            .and_then(|v| v.as_mapping())
            .map(|req| {
                let cpu = req
                    .get(serde_yaml::Value::String("cpu".into()))
                    .and_then(|v| v.as_str())
                    .and_then(parse_k8s_cpu)
                    .unwrap_or(250);
                let mem = req
                    .get(serde_yaml::Value::String("memory".into()))
                    .and_then(|v| v.as_str())
                    .and_then(parse_k8s_memory_mb)
                    .unwrap_or(256);
                (cpu, mem)
            })
            .unwrap_or((250, 256));

        let (cpu_lim, mem_lim) = resources
            .and_then(|r| r.get(serde_yaml::Value::String("limits".into())))
            .and_then(|v| v.as_mapping())
            .map(|lim| {
                let cpu = lim
                    .get(serde_yaml::Value::String("cpu".into()))
                    .and_then(|v| v.as_str())
                    .and_then(parse_k8s_cpu)
                    .unwrap_or(500);
                let mem = lim
                    .get(serde_yaml::Value::String("memory".into()))
                    .and_then(|v| v.as_str())
                    .and_then(parse_k8s_memory_mb)
                    .unwrap_or(512);
                (cpu, mem)
            })
            .unwrap_or((500, 512));

        let security_ctx = cm
            .get(serde_yaml::Value::String("securityContext".into()))
            .and_then(|v| v.as_mapping());

        let privileged = security_ctx
            .and_then(|sc| sc.get(serde_yaml::Value::String("privileged".into())))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let run_as_root = security_ctx
            .and_then(|sc| sc.get(serde_yaml::Value::String("runAsNonRoot".into())))
            .map(|v| !v.as_bool().unwrap_or(true))
            .unwrap_or(true);

        let read_only_root = security_ctx
            .and_then(|sc| sc.get(serde_yaml::Value::String("readOnlyRootFilesystem".into())))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        ContainerSpec {
            name,
            image,
            ports,
            volumes,
            env_vars,
            resources: ResourceSpec {
                cpu_request_millicores: cpu_req,
                memory_request_mb: mem_req,
                cpu_limit_millicores: cpu_lim,
                memory_limit_mb: mem_lim,
            },
            privileged,
            run_as_root,
            read_only_root_filesystem: read_only_root,
        }
    }

    /// Run security checks against a parsed resource.
    fn validate_resource(&self, resource: &ManifestResource) -> Vec<ValidationError> {
        let mut findings = Vec::new();

        // Host PID check
        if resource.host_pid && !self.allow_host_pid {
            findings.push(ValidationError {
                resource: resource.name.clone(),
                field: "spec.template.spec.hostPID".into(),
                message: "hostPID is enabled — container shares host process namespace".into(),
                severity: ValidationSeverity::Block,
            });
        }

        // Host network check
        if resource.host_network && !self.allow_host_network {
            findings.push(ValidationError {
                resource: resource.name.clone(),
                field: "spec.template.spec.hostNetwork".into(),
                message: "hostNetwork is enabled — container bypasses network isolation".into(),
                severity: ValidationSeverity::Block,
            });
        }

        // Host IPC check
        if resource.host_ipc && !self.allow_host_ipc {
            findings.push(ValidationError {
                resource: resource.name.clone(),
                field: "spec.template.spec.hostIPC".into(),
                message: "hostIPC is enabled — container shares host IPC namespace".into(),
                severity: ValidationSeverity::Block,
            });
        }

        // Per-container checks
        for container in &resource.containers {
            // Privileged mode
            if container.privileged && !self.allow_privileged {
                findings.push(ValidationError {
                    resource: resource.name.clone(),
                    field: format!(
                        "spec.template.spec.containers[{}].securityContext.privileged",
                        container.name
                    ),
                    message: "privileged container detected — grants full host capabilities".into(),
                    severity: ValidationSeverity::Block,
                });
            }

            // Running as root
            if container.run_as_root {
                findings.push(ValidationError {
                    resource: resource.name.clone(),
                    field: format!(
                        "spec.template.spec.containers[{}].securityContext.runAsNonRoot",
                        container.name
                    ),
                    message: "container runs as root — set runAsNonRoot: true".into(),
                    severity: ValidationSeverity::Error,
                });
            }

            // Writable root filesystem
            if !container.read_only_root_filesystem {
                findings.push(ValidationError {
                    resource: resource.name.clone(),
                    field: format!(
                        "spec.template.spec.containers[{}].securityContext.readOnlyRootFilesystem",
                        container.name
                    ),
                    message: "readOnlyRootFilesystem is not set — container can write to root"
                        .into(),
                    severity: ValidationSeverity::Warning,
                });
            }

            // Secrets via environment variables
            for env_var in &container.env_vars {
                if env_var.value_from_secret {
                    findings.push(ValidationError {
                        resource: resource.name.clone(),
                        field: format!(
                            "spec.template.spec.containers[{}].env[{}].valueFrom.secretKeyRef",
                            container.name, env_var.name
                        ),
                        message: "secret exposed as environment variable — use CSI driver or secrets manager".into(),
                        severity: ValidationSeverity::Block,
                    });
                }
            }
        }

        findings
    }
}

impl ValidationError {
    fn severity_label(&self) -> &str {
        match self.severity {
            ValidationSeverity::Warning => "WARNING",
            ValidationSeverity::Error => "ERROR",
            ValidationSeverity::Block => "BLOCK",
        }
    }
}

// ---------------------------------------------------------------------------
// YAML parsing helpers
// ---------------------------------------------------------------------------

/// Parse a YAML string into documents, handling multi-document streams.
fn parse_yaml_documents(yaml: &str) -> Result<Vec<serde_yaml::Value>, ManifestValidationError> {
    let trimmed = yaml.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // Handle multi-document YAML (--- separator)
    let docs: Vec<&str> = if trimmed.contains("\n---") {
        trimmed
            .split("\n---")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        vec![trimmed]
    };

    let mut values = Vec::new();
    for doc in &docs {
        let val: serde_yaml::Value = serde_yaml::from_str(doc)
            .map_err(|e| ManifestValidationError::ParseError(format!("YAML parse failed: {e}")))?;
        values.push(val);
    }

    Ok(values)
}

/// Extract a string value from a YAML mapping.
fn get_str(mapping: &serde_yaml::Mapping, key: &str) -> Result<String, ManifestValidationError> {
    mapping
        .get(serde_yaml::Value::String(key.into()))
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| {
            ManifestValidationError::StructureError(format!("missing required field '{key}'"))
        })
}

/// Parse a Kubernetes CPU quantity string (e.g. "250m", "1") into millicores.
fn parse_k8s_cpu(cpu: &str) -> Option<u32> {
    if let Some(milli) = cpu.strip_suffix('m') {
        milli.parse::<u32>().ok()
    } else {
        cpu.parse::<f64>().ok().map(|v| (v * 1000.0) as u32)
    }
}

/// Parse a Kubernetes memory quantity string (e.g. "256Mi", "1Gi") into MiB.
fn parse_k8s_memory_mb(mem: &str) -> Option<u32> {
    if let Some(mi) = mem.strip_suffix("Mi") {
        mi.parse::<u32>().ok()
    } else if let Some(gi) = mem.strip_suffix("Gi") {
        gi.parse::<u32>().ok().map(|v| v.saturating_mul(1024))
    } else if let Some(ki) = mem.strip_suffix("Ki") {
        ki.parse::<u32>().ok().map(|v| v / 1024)
    } else if let Some(m) = mem.strip_suffix('M') {
        m.parse::<u32>().ok()
    } else if let Some(g) = mem.strip_suffix('G') {
        g.parse::<u32>().ok().map(|v| v.saturating_mul(1024))
    } else if let Some(k) = mem.strip_suffix('K') {
        k.parse::<u32>().ok().map(|v| v / 1024)
    } else {
        // Assume bytes
        mem.parse::<u64>().ok().map(|v| (v / (1024 * 1024)) as u32)
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

    fn valid_deployment_yaml() -> &'static str {
        r#"---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.25
        ports:
        - containerPort: 80
          protocol: TCP
        resources:
          requests:
            cpu: 250m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
"#
    }

    // -- Valid manifest ----------------------------------------------------

    #[test]
    fn valid_manifest_passes() {
        let validator = K8sManifestValidator::new();
        let result = validator.validate_manifest(valid_deployment_yaml());
        assert!(
            result.is_ok(),
            "valid manifest should parse: {:?}",
            result.err()
        );
        let validated = result.unwrap();
        assert!(validated.is_valid(), "valid manifest should have no errors");
        assert_eq!(validated.resources.len(), 1);
        assert_eq!(validated.resources[0].kind, "Deployment");
        assert_eq!(validated.resources[0].name, "nginx-deployment");
    }

    // -- Privileged detection ----------------------------------------------

    #[test]
    fn detect_privileged_container() {
        let yaml = r#"---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-deploy
spec:
  template:
    spec:
      containers:
      - name: bad
        image: bad:latest
        securityContext:
          privileged: true
"#;
        let validator = K8sManifestValidator::new();
        let validated = validator.validate_manifest(yaml).unwrap();
        assert!(!validated.is_valid(), "privileged should be blocked");
        assert!(
            validated.errors.iter().any(|e| e.contains("privileged")),
            "should detect privileged container"
        );
    }

    // -- hostPID detection -------------------------------------------------

    #[test]
    fn detect_host_pid() {
        let yaml = r#"---
apiVersion: v1
kind: Pod
metadata:
  name: hostpid-pod
spec:
  hostPID: true
  containers:
  - name: test
    image: test:latest
"#;
        let validator = K8sManifestValidator::new();
        let validated = validator.validate_manifest(yaml).unwrap();
        assert!(
            validated.errors.iter().any(|e| e.contains("hostPID")),
            "should detect hostPID"
        );
    }

    // -- hostNetwork detection ---------------------------------------------

    #[test]
    fn detect_host_network() {
        let yaml = r#"---
apiVersion: v1
kind: Pod
metadata:
  name: hostnet-pod
spec:
  hostNetwork: true
  containers:
  - name: test
    image: test:latest
"#;
        let validator = K8sManifestValidator::new();
        let validated = validator.validate_manifest(yaml).unwrap();
        assert!(
            validated.errors.iter().any(|e| e.contains("hostNetwork")),
            "should detect hostNetwork"
        );
    }

    // -- Multi-container pod -----------------------------------------------

    #[test]
    fn multi_container_pod_validation() {
        let yaml = r#"---
apiVersion: v1
kind: Pod
metadata:
  name: multi-pod
spec:
  containers:
  - name: app
    image: app:v1
    securityContext:
      runAsNonRoot: true
  - name: sidecar
    image: sidecar:v1
    securityContext:
      privileged: true
"#;
        let validator = K8sManifestValidator::new();
        let validated = validator.validate_manifest(yaml).unwrap();
        assert_eq!(validated.resources[0].containers.len(), 2);
        assert!(!validated.is_valid(), "sidecar is privileged");
    }

    // -- Secrets via env variables -----------------------------------------

    #[test]
    fn detect_secrets_env_spray() {
        let yaml = r#"---
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: app:v1
    env:
    - name: DATABASE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-secret
          key: password
"#;
        let validator = K8sManifestValidator::new();
        let validated = validator.validate_manifest(yaml).unwrap();
        assert!(
            validated.errors.iter().any(|e| e.contains("secret")),
            "should detect secret exposed as env var"
        );
    }

    // -- readOnlyRootFilesystem warning ------------------------------------

    #[test]
    fn warn_missing_read_only_root_filesystem() {
        let yaml = r#"---
apiVersion: v1
kind: Pod
metadata:
  name: rw-pod
spec:
  containers:
  - name: app
    image: app:v1
    securityContext:
      runAsNonRoot: true
"#;
        let validator = K8sManifestValidator::new();
        let validated = validator.validate_manifest(yaml).unwrap();
        assert!(
            validated
                .warnings
                .iter()
                .any(|w| w.contains("readOnlyRootFilesystem")),
            "should warn about missing readOnlyRootFilesystem"
        );
    }

    // -- Empty manifest ----------------------------------------------------

    #[test]
    fn empty_manifest_returns_empty() {
        let validator = K8sManifestValidator::new();
        let result = validator.validate_manifest("");
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert!(validated.resources.is_empty());
    }

    // -- Invalid YAML ------------------------------------------------------

    #[test]
    fn invalid_yaml_returns_error() {
        let validator = K8sManifestValidator::new();
        let result = validator.validate_manifest("this: is: not: valid: [[yaml");
        assert!(result.is_err());
    }

    // -- DEV_RELAXED allows privileged -------------------------------------

    #[test]
    fn dev_relaxed_allows_privileged() {
        let yaml = r#"---
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
spec:
  containers:
  - name: app
    image: app:v1
    securityContext:
      privileged: true
      runAsNonRoot: true
      readOnlyRootFilesystem: true
"#;
        let validator = K8sManifestValidator::dev_relaxed();
        let validated = validator.validate_manifest(yaml).unwrap();
        assert!(
            !validated.errors.iter().any(|e| e.contains("privileged")),
            "DEV_RELAXED should not block privileged"
        );
    }

    // -- Various resource kinds --------------------------------------------

    #[test]
    fn parse_statefulset_correctly() {
        let yaml = r#"---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  template:
    spec:
      containers:
      - name: postgres
        image: postgres:16
"#;
        let validator = K8sManifestValidator::new();
        let validated = validator.validate_manifest(yaml).unwrap();
        assert_eq!(validated.resources[0].kind, "StatefulSet");
        assert_eq!(validated.resources[0].name, "db");
    }

    // -- K8s CPU parsing ---------------------------------------------------

    #[test]
    fn test_parse_k8s_cpu_values() {
        assert_eq!(parse_k8s_cpu("250m"), Some(250));
        assert_eq!(parse_k8s_cpu("1"), Some(1000));
        assert_eq!(parse_k8s_cpu("0.5"), Some(500));
        assert_eq!(parse_k8s_cpu("invalid"), None);
    }

    // -- K8s memory parsing ------------------------------------------------

    #[test]
    fn test_parse_k8s_memory_values() {
        assert_eq!(parse_k8s_memory_mb("256Mi"), Some(256));
        assert_eq!(parse_k8s_memory_mb("1Gi"), Some(1024));
        assert_eq!(parse_k8s_memory_mb("512M"), Some(512));
        assert_eq!(parse_k8s_memory_mb("invalid"), None);
    }

    // -- hostPath volumes are not flagged (not in scope) but volume parsing works

    #[test]
    fn parse_container_volumes() {
        let yaml = r#"---
apiVersion: v1
kind: Pod
metadata:
  name: vol-pod
spec:
  containers:
  - name: app
    image: app:v1
    volumeMounts:
    - name: data
      mountPath: /data
      readOnly: true
"#;
        let validator = K8sManifestValidator::new();
        let validated = validator.validate_manifest(yaml).unwrap();
        let container = &validated.resources[0].containers[0];
        assert_eq!(container.volumes.len(), 1);
        assert_eq!(container.volumes[0].name, "data");
        assert!(container.volumes[0].read_only);
    }
}
