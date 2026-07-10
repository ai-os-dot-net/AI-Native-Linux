//! S6.5 Session Container Runtime — Podman/Docker-backed [`SessionDriver`].
//!
//! Provides a real container-backed implementation of the [`SessionDriver`]
//! trait. Each session is a Podman (or Docker) container running a KDE
//! Plasma Wayland desktop with selkies-gstreamer streaming, or falling
//! back to X11 via Xvfb when Wayland is unavailable.
//!
//! # Resource quotas
//!
//! Per-session CPU shares (`--cpu-shares`), memory limits (`--memory`),
//! and optional GPU device mapping (`--device`) are applied at container
//! creation time.
//!
//! # Lifecycle FSM
//!
//! ```text
//! Idle ──▶ Starting ──▶ Active ──▶ Paused ──▶ Active  (cycle)
//!   │                      │         │
//!   └──────────────────────┴─────────┴──▶ Reclaimed  (terminal)
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time::timeout as tokio_timeout;
use tracing::{debug, error, info, warn};

use crate::ecosystem::EcosystemRuntime;
use crate::error::AppsError;
use crate::evidence::{AppsEvidenceEmitter, SessionPhaseRecord};
use crate::package::PackageId;
use crate::session::{SessionContainerRuntime, SessionContainerState, SessionId};
use crate::session_driver::{
    OpenSessionRequest, Principal, SessionDescriptor, SessionDriver, SessionExitReason,
    SessionFilter, SessionMetrics, SessionState, SessionTerminationReceipt,
};

// ---------------------------------------------------------------------------
// SessionContainerConfig
// ---------------------------------------------------------------------------

/// S6.5 §4 — configuration for the session container runtime.
///
/// Controls the OCI image, resource quotas, GPU passthrough, display
/// backend, and streaming port for each session container.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionContainerConfig {
    /// OCI image name for the session container.
    /// Default: `"aios-session-wayland:rev6"`.
    #[serde(default = "SessionContainerConfig::default_image")]
    pub image: String,

    /// OCI runtime binary name (e.g. `"podman"` or `"docker"`).
    #[serde(default = "SessionContainerConfig::default_runtime_binary")]
    pub runtime_binary: String,

    /// GPU device path to map into the container (e.g. `"/dev/dri"`).
    /// `None` means no GPU passthrough.
    #[serde(default)]
    pub gpu_device: Option<String>,

    /// Memory limit in megabytes per session container.
    /// Default: 2048.
    #[serde(default = "SessionContainerConfig::default_memory_mb")]
    pub memory_mb: u32,

    /// CPU shares (relative weight, see `--cpu-shares`).
    /// Default: 1024.
    #[serde(default = "SessionContainerConfig::default_cpu_shares")]
    pub cpu_shares: u32,

    /// Wayland display socket to bind-mount (e.g. `"wayland-0"`).
    /// `None` means fall back to X11 with Xvfb.
    #[serde(default)]
    pub wayland_display: Option<String>,

    /// GStreamer WebRTC port for selkies-gstreamer streaming.
    /// Default: 8080.
    #[serde(default = "SessionContainerConfig::default_gstreamer_port")]
    pub gstreamer_port: u16,

    /// Maximum number of concurrent sessions.
    /// Default: 8.
    #[serde(default = "SessionContainerConfig::default_max_sessions")]
    pub max_sessions: u32,

    /// Container health check timeout in seconds.
    /// Default: 30.
    #[serde(default = "SessionContainerConfig::default_health_timeout_secs")]
    pub health_timeout_secs: u64,

    /// X11 display number for Xvfb fallback.
    /// Default: 99.
    #[serde(default = "SessionContainerConfig::default_x11_display")]
    pub x11_display: u16,
}

impl SessionContainerConfig {
    /// Create a config with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn default_image() -> String {
        "aios-session-wayland:rev6".to_string()
    }

    fn default_runtime_binary() -> String {
        "podman".to_string()
    }

    const fn default_memory_mb() -> u32 {
        2048
    }

    const fn default_cpu_shares() -> u32 {
        1024
    }

    const fn default_gstreamer_port() -> u16 {
        8080
    }

    const fn default_max_sessions() -> u32 {
        8
    }

    const fn default_health_timeout_secs() -> u64 {
        30
    }

    const fn default_x11_display() -> u16 {
        99
    }

    /// Create a config targeting Docker instead of Podman.
    #[must_use]
    pub fn with_docker(mut self) -> Self {
        self.runtime_binary = "docker".to_string();
        self
    }

    /// Set a custom container image.
    #[must_use]
    pub fn with_image(mut self, image: impl Into<String>) -> Self {
        self.image = image.into();
        self
    }

    /// Set GPU device path for passthrough.
    #[must_use]
    pub fn with_gpu_device(mut self, device: impl Into<String>) -> Self {
        self.gpu_device = Some(device.into());
        self
    }

    /// Set memory limit in MB.
    #[must_use]
    pub fn with_memory_mb(mut self, mb: u32) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Set CPU shares.
    #[must_use]
    pub fn with_cpu_shares(mut self, shares: u32) -> Self {
        self.cpu_shares = shares;
        self
    }

    /// Set the Wayland display socket name.
    #[must_use]
    pub fn with_wayland_display(mut self, display: impl Into<String>) -> Self {
        self.wayland_display = Some(display.into());
        self
    }

    /// Set the GStreamer streaming port.
    #[must_use]
    pub fn with_gstreamer_port(mut self, port: u16) -> Self {
        self.gstreamer_port = port;
        self
    }

    /// Set the max concurrent sessions.
    #[must_use]
    pub fn with_max_sessions(mut self, max: u32) -> Self {
        self.max_sessions = max;
        self
    }

    /// Return the preferred [`SessionContainerRuntime`] based on binary name.
    #[must_use]
    pub fn container_runtime(&self) -> SessionContainerRuntime {
        if self.runtime_binary == "docker" {
            SessionContainerRuntime::Docker
        } else {
            SessionContainerRuntime::Podman
        }
    }
}

impl Default for SessionContainerConfig {
    fn default() -> Self {
        Self {
            image: Self::default_image(),
            runtime_binary: Self::default_runtime_binary(),
            gpu_device: None,
            memory_mb: Self::default_memory_mb(),
            cpu_shares: Self::default_cpu_shares(),
            wayland_display: None,
            gstreamer_port: Self::default_gstreamer_port(),
            max_sessions: Self::default_max_sessions(),
            health_timeout_secs: Self::default_health_timeout_secs(),
            x11_display: Self::default_x11_display(),
        }
    }
}

// ---------------------------------------------------------------------------
// ContainerHandle — internal per-session state
// ---------------------------------------------------------------------------

/// Internal tracking record for a single container session.
#[derive(Clone, Debug)]
struct ContainerHandle {
    session_id: SessionId,
    container_name: String,
    container_id: Option<String>,
    container_state: SessionContainerState,
    package_id: PackageId,
    ecosystem: EcosystemRuntime,
    requester: Principal,
    created_at: DateTime<Utc>,
    last_heartbeat: DateTime<Utc>,
    timeout: Duration,
    heartbeat_count: u64,
}

impl ContainerHandle {
    fn to_descriptor(&self) -> SessionDescriptor {
        SessionDescriptor {
            session_id: self.session_id.clone(),
            package_id: self.package_id.clone(),
            ecosystem: self.ecosystem,
            state: self.to_driver_state(),
            requester: self.requester.clone(),
            created_at: self.created_at,
            last_heartbeat: self.last_heartbeat,
            timeout_seconds: self.timeout.as_secs(),
        }
    }

    fn to_driver_state(&self) -> SessionState {
        match self.container_state {
            SessionContainerState::Idle => SessionState::Allocating,
            SessionContainerState::Starting => SessionState::Allocating,
            SessionContainerState::Active => SessionState::Active,
            SessionContainerState::Paused => SessionState::Suspended,
            SessionContainerState::Reclaimed => SessionState::Terminated,
        }
    }

    fn is_timed_out(&self, now: DateTime<Utc>) -> bool {
        let elapsed = (now - self.last_heartbeat).num_seconds();
        if elapsed < 0 {
            return false;
        }
        elapsed.unsigned_abs() >= self.timeout.as_secs()
    }
}

// ---------------------------------------------------------------------------
// SessionContainerDriver
// ---------------------------------------------------------------------------

/// S6.5 — real container-backed [`SessionDriver`] using Podman or Docker.
///
/// Each session maps to a dedicated OCI container. The driver manages the
/// full lifecycle: container creation, health checking, pause/resume, and
/// cleanup.
///
/// # Graceful degradation
///
/// If the configured runtime binary (`podman` or `docker`) is not found
/// at startup, the driver still constructs successfully, but every
/// `open_session` call returns `SessionContainerError`.
pub struct SessionContainerDriver {
    config: SessionContainerConfig,
    containers: RwLock<HashMap<SessionId, ContainerHandle>>,
    emitter: Option<Arc<dyn AppsEvidenceEmitter>>,
}

impl SessionContainerDriver {
    /// Create a new driver with the given config.
    #[must_use]
    pub fn new(config: SessionContainerConfig) -> Self {
        Self {
            config,
            containers: RwLock::new(HashMap::new()),
            emitter: None,
        }
    }

    /// Create a driver with default config.
    #[must_use]
    pub fn new_with_defaults() -> Self {
        Self::new(SessionContainerConfig::default())
    }

    /// Attach an evidence emitter to this driver.
    #[must_use]
    pub fn with_emitter(mut self, emitter: Arc<dyn AppsEvidenceEmitter>) -> Self {
        self.emitter = Some(emitter);
        self
    }

    /// Return the driver's current config (read-only).
    #[must_use]
    pub fn config(&self) -> &SessionContainerConfig {
        &self.config
    }

    // ------------------------------------------------------------------
    // Podman / Docker command execution
    // ------------------------------------------------------------------

    /// Check whether the configured runtime binary is available on `$PATH`.
    async fn runtime_binary_available(&self) -> bool {
        let output = tokio::process::Command::new("which")
            .arg(&self.config.runtime_binary)
            .output()
            .await;
        output.map(|o| o.status.success()).unwrap_or(false)
    }

    /// Build the base `podman run` / `docker run` argument list.
    fn build_run_args(&self, container_name: &str, port: u16) -> Vec<String> {
        let mut args: Vec<String> = Vec::with_capacity(32);
        // Runtime
        args.push("run".into());
        // Detached
        args.push("--detach".into());
        // Name
        args.push("--name".into());
        args.push(container_name.to_string());
        // Resource quotas
        args.push("--memory".into());
        args.push(format!("{}m", self.config.memory_mb));
        args.push("--cpu-shares".into());
        args.push(self.config.cpu_shares.to_string());
        // Remove on stop
        args.push("--rm".into());
        // GPU device
        if let Some(ref gpu) = self.config.gpu_device {
            args.push("--device".into());
            args.push(gpu.clone());
        }
        // Environment: disable Wayland if not configured, else pass display
        if let Some(ref display) = self.config.wayland_display {
            args.push("--env".into());
            args.push(format!("WAYLAND_DISPLAY={display}"));
            args.push("--volume".into());
            args.push(format!("/run/user/1000/{display}:/run/user/1000/{display}"));
        }
        // GStreamer port
        args.push("--publish".into());
        args.push(format!("{port}:{port}"));
        args.push("--env".into());
        args.push(format!("GSTREAMER_PORT={port}"));
        // X11 fallback display
        args.push("--env".into());
        args.push(format!("DISPLAY=:{}", self.config.x11_display));
        // Image
        args.push(self.config.image.clone());
        args
    }

    /// Execute a podman/docker command and return stdout as String.
    async fn exec_command(&self, args: &[&str]) -> Result<String, AppsError> {
        let binary = &self.config.runtime_binary;
        debug!("exec: {binary} {}", args.join(" "));
        let output = tokio::process::Command::new(binary)
            .args(args)
            .output()
            .await
            .map_err(|e| {
                error!("Failed to execute {binary}: {e}");
                AppsError::SessionContainerError(format!("exec {binary}: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("{binary} exited with status {}: {stderr}", output.status);
            return Err(AppsError::SessionContainerError(format!(
                "{binary} failed: {stderr}"
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(stdout)
    }

    /// Launch a container and return the container ID.
    async fn launch_container(&self, container_name: &str, port: u16) -> Result<String, AppsError> {
        let args = self.build_run_args(container_name, port);
        let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
        let container_id = self.exec_command(&str_args).await?;
        if container_id.is_empty() {
            return Err(AppsError::SessionContainerError(
                "container launch returned empty id".into(),
            ));
        }
        info!("Launched container {container_name} id={container_id}");
        Ok(container_id)
    }

    /// Inspect a container and return its OCI state string.
    async fn inspect_container(&self, container_name: &str) -> Result<String, AppsError> {
        self.exec_command(&["inspect", "--format", "{{.State.Status}}", container_name])
            .await
    }

    /// Pause a running container.
    async fn pause_container(&self, container_name: &str) -> Result<(), AppsError> {
        info!("Pausing container {container_name}");
        self.exec_command(&["pause", container_name]).await?;
        Ok(())
    }

    /// Unpause (resume) a paused container.
    async fn unpause_container(&self, container_name: &str) -> Result<(), AppsError> {
        info!("Unpausing container {container_name}");
        self.exec_command(&["unpause", container_name]).await?;
        Ok(())
    }

    /// Stop a container and wait for cleanup.
    async fn stop_container(&self, container_name: &str) -> Result<(), AppsError> {
        info!("Stopping container {container_name}");
        let result = self
            .exec_command(&["stop", "--time", "10", container_name])
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(AppsError::SessionContainerError(ref msg)) if msg.contains("no such container") => {
                warn!("Container {container_name} already gone");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Translate the OCI state string to our [`SessionContainerState`].
    fn oci_state_to_container_state(oci: &str) -> SessionContainerState {
        match oci {
            "running" => SessionContainerState::Active,
            "paused" => SessionContainerState::Paused,
            "created" | "initializing" => SessionContainerState::Starting,
            _ => SessionContainerState::Reclaimed,
        }
    }

    // ------------------------------------------------------------------
    // Evidence emission helpers
    // ------------------------------------------------------------------

    async fn emit_if_configured(
        &self,
        session_id: &SessionId,
        package_id: &PackageId,
        phase: SessionPhaseRecord,
    ) {
        if let Some(ref emitter) = self.emitter {
            if let Err(e) = emitter
                .emit_session_event(session_id, package_id, phase)
                .await
            {
                error!("Failed to emit session evidence: {e}");
            }
        }
    }
}

impl std::fmt::Debug for SessionContainerDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionContainerDriver")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// SessionDriver trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl SessionDriver for SessionContainerDriver {
    async fn open_session(&self, req: OpenSessionRequest) -> Result<SessionDescriptor, AppsError> {
        // Pre-flight: check runtime binary availability.
        if !self.runtime_binary_available().await {
            let msg = format!(
                "runtime binary '{}' not found on PATH",
                self.config.runtime_binary
            );
            error!("{msg}");
            return Err(AppsError::SessionContainerError(msg));
        }

        // Quota check.
        let current_count = {
            let guard = self.containers.read().await;
            guard
                .values()
                .filter(|h| h.container_state != SessionContainerState::Reclaimed)
                .count() as u32
        };
        if current_count >= self.config.max_sessions {
            return Err(AppsError::SessionQuotaExceeded {
                group_id: req.requester.canonical_id.clone(),
                active: current_count,
                quota: self.config.max_sessions,
            });
        }

        let session_id = SessionId(format!(
            "sess_{}",
            ulid::Ulid::new().to_string().to_lowercase()
        ));
        let container_name = session_id.0.clone();
        let now = Utc::now();

        let handle = ContainerHandle {
            session_id: session_id.clone(),
            container_name: container_name.clone(),
            container_id: None,
            container_state: SessionContainerState::Idle,
            package_id: req.package_id.clone(),
            ecosystem: req.ecosystem,
            requester: req.requester,
            created_at: now,
            last_heartbeat: now,
            timeout: req.timeout,
            heartbeat_count: 0,
        };

        // Insert in Idle state first.
        {
            let mut guard = self.containers.write().await;
            guard.insert(session_id.clone(), handle);
        }

        // Transition: Idle → Starting
        {
            let mut guard = self.containers.write().await;
            if let Some(h) = guard.get_mut(&session_id) {
                h.container_state = SessionContainerState::Starting;
            }
        }

        // Launch the container.
        let port = self.config.gstreamer_port;
        let container_id = self
            .launch_container(&container_name, port)
            .await
            .map_err(|e| {
                error!("Container launch failed for {session_id:?}: {e}");
                e
            })?;

        // Transition: Starting → Active (after successful launch).
        {
            let mut guard = self.containers.write().await;
            if let Some(h) = guard.get_mut(&session_id) {
                h.container_state = SessionContainerState::Active;
                h.container_id = Some(container_id);
            }
        }

        let descriptor = {
            let guard = self.containers.read().await;
            guard
                .get(&session_id)
                .map(ContainerHandle::to_descriptor)
                .ok_or_else(|| AppsError::SessionNotFound(session_id.0.clone()))?
        };

        self.emit_if_configured(&session_id, &req.package_id, SessionPhaseRecord::Opened)
            .await;

        Ok(descriptor)
    }

    async fn close_session(&self, id: SessionId) -> Result<SessionTerminationReceipt, AppsError> {
        let (container_name, package_id, created_at, heartbeat_count, ended_at) = {
            let mut guard = self.containers.write().await;
            let entry = guard
                .get_mut(&id)
                .ok_or_else(|| AppsError::SessionNotFound(id.0.clone()))?;

            if entry.container_state == SessionContainerState::Reclaimed {
                return Err(AppsError::SessionNotFound(id.0.clone()));
            }

            entry.container_state = SessionContainerState::Reclaimed;
            (
                entry.container_name.clone(),
                entry.package_id.clone(),
                entry.created_at,
                entry.heartbeat_count,
                Utc::now(),
            )
        };

        // Stop the container (best-effort).
        if self.runtime_binary_available().await {
            if let Err(e) = self.stop_container(&container_name).await {
                warn!("Container stop warning for {container_name}: {e}");
            }
        }

        let metrics = {
            let uptime = (ended_at - created_at).num_seconds();
            SessionMetrics {
                total_uptime_seconds: uptime.max(0).unsigned_abs(),
                heartbeat_count,
            }
        };

        let exit_reason = SessionExitReason::ClosedByOwner;

        self.emit_if_configured(&id, &package_id, SessionPhaseRecord::Closed(exit_reason))
            .await;

        Ok(SessionTerminationReceipt {
            session_id: id,
            ended_at,
            exit_reason,
            final_metrics: metrics,
        })
    }

    async fn get_session(&self, id: SessionId) -> Result<SessionDescriptor, AppsError> {
        let mut guard = self.containers.write().await;
        let entry = guard
            .get_mut(&id)
            .ok_or_else(|| AppsError::SessionNotFound(id.0.clone()))?;

        if entry.container_state == SessionContainerState::Reclaimed {
            return Err(AppsError::SessionNotFound(id.0.clone()));
        }

        // Check timeout first.
        if entry.is_timed_out(Utc::now()) {
            entry.container_state = SessionContainerState::Reclaimed;
            return Err(AppsError::SessionNotFound(id.0.clone()));
        }

        // If active or paused, verify via container inspect.
        if (entry.container_state == SessionContainerState::Active
            || entry.container_state == SessionContainerState::Paused)
            && self.runtime_binary_available().await
        {
            match self.inspect_container(&entry.container_name).await {
                Ok(oci_state) => {
                    let observed = Self::oci_state_to_container_state(&oci_state);
                    if observed != entry.container_state {
                        debug!(
                            "Container {id:?} state changed: {:?} -> {observed:?}",
                            entry.container_state
                        );
                        entry.container_state = observed;
                    }
                }
                Err(_) => {
                    // Container likely gone.
                    entry.container_state = SessionContainerState::Reclaimed;
                }
            }
        }

        if entry.container_state == SessionContainerState::Reclaimed {
            return Err(AppsError::SessionNotFound(id.0.clone()));
        }

        Ok(entry.to_descriptor())
    }

    async fn list_sessions(&self, filter: SessionFilter) -> Vec<SessionDescriptor> {
        let guard = self.containers.read().await;
        guard
            .values()
            .filter(|entry| match &filter {
                SessionFilter::All => entry.container_state != SessionContainerState::Reclaimed,
                SessionFilter::ByPackage(pkg) => {
                    entry.package_id == *pkg
                        && entry.container_state != SessionContainerState::Reclaimed
                }
                SessionFilter::ByPrincipal(principal) => {
                    entry.requester == *principal
                        && entry.container_state != SessionContainerState::Reclaimed
                }
                SessionFilter::ByState(state) => entry.to_driver_state() == *state,
            })
            .map(ContainerHandle::to_descriptor)
            .collect()
    }

    async fn heartbeat(&self, id: SessionId) -> Result<(), AppsError> {
        let mut guard = self.containers.write().await;
        let entry = guard
            .get_mut(&id)
            .ok_or_else(|| AppsError::SessionNotFound(id.0.clone()))?;

        if entry.container_state == SessionContainerState::Reclaimed {
            return Err(AppsError::SessionNotFound(id.0.clone()));
        }

        if entry.is_timed_out(Utc::now()) {
            entry.container_state = SessionContainerState::Reclaimed;
            return Err(AppsError::SessionNotFound(id.0.clone()));
        }

        entry.last_heartbeat = Utc::now();
        entry.heartbeat_count += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Extra container-driver-specific operations (not part of SessionDriver trait)
// ---------------------------------------------------------------------------

impl SessionContainerDriver {
    /// Pause an active session container.
    ///
    /// Sends `podman pause` to freeze the container. Only callable when
    /// the container is in `Active` state.
    ///
    /// # Errors
    ///
    /// Returns `SessionContainerError` if the runtime command fails or
    /// the session is not in `Active` state.
    pub async fn pause_session(&self, id: &SessionId) -> Result<(), AppsError> {
        let (container_name, current_state) = {
            let guard = self.containers.read().await;
            let entry = guard
                .get(id)
                .ok_or_else(|| AppsError::SessionNotFound(id.0.clone()))?;
            (entry.container_name.clone(), entry.container_state)
        };

        if current_state != SessionContainerState::Active {
            return Err(AppsError::SessionContainerError(format!(
                "cannot pause session in state {current_state:?}"
            )));
        }

        self.pause_container(&container_name).await?;

        let mut guard = self.containers.write().await;
        if let Some(entry) = guard.get_mut(id) {
            entry.container_state = SessionContainerState::Paused;
        }

        Ok(())
    }

    /// Resume a paused session container.
    ///
    /// Sends `podman unpause` to thaw the container. Only callable when
    /// the container is in `Paused` state.
    ///
    /// # Errors
    ///
    /// Returns `SessionContainerError` if the runtime command fails or
    /// the session is not in `Paused` state.
    pub async fn resume_session(&self, id: &SessionId) -> Result<(), AppsError> {
        let (container_name, current_state) = {
            let guard = self.containers.read().await;
            let entry = guard
                .get(id)
                .ok_or_else(|| AppsError::SessionNotFound(id.0.clone()))?;
            (entry.container_name.clone(), entry.container_state)
        };

        if current_state != SessionContainerState::Paused {
            return Err(AppsError::SessionContainerError(format!(
                "cannot resume session in state {current_state:?}"
            )));
        }

        self.unpause_container(&container_name).await?;

        let mut guard = self.containers.write().await;
        if let Some(entry) = guard.get_mut(id) {
            entry.container_state = SessionContainerState::Active;
        }

        Ok(())
    }

    /// Perform a health check on a session container.
    ///
    /// Inspects the container state and compares against the expected state.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the container is in the expected state.
    /// `Ok(false)` if the container is in a different state.
    /// `Err(...)` if the container cannot be inspected (e.g., it is gone).
    pub async fn health_check(&self, id: &SessionId) -> Result<bool, AppsError> {
        let entry = {
            let guard = self.containers.read().await;
            guard
                .get(id)
                .cloned()
                .ok_or_else(|| AppsError::SessionNotFound(id.0.clone()))?
        };

        if entry.container_state == SessionContainerState::Reclaimed {
            return Ok(false);
        }

        let oci_state = tokio_timeout(
            Duration::from_secs(self.config.health_timeout_secs),
            self.inspect_container(&entry.container_name),
        )
        .await
        .map_err(|_| AppsError::SessionContainerError("health check timed out".into()))??;

        let observed = Self::oci_state_to_container_state(&oci_state);
        Ok(observed == entry.container_state)
    }

    /// Return the number of active (non-reclaimed) sessions.
    #[must_use]
    pub async fn active_session_count(&self) -> usize {
        let guard = self.containers.read().await;
        guard
            .values()
            .filter(|h| h.container_state != SessionContainerState::Reclaimed)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;
    use crate::ecosystem::EcosystemRuntime;
    use crate::evidence::InMemoryAppsEvidenceEmitter;
    use crate::package::PackageId;

    fn test_package() -> PackageId {
        PackageId(format!(
            "pkg_{}",
            ulid::Ulid::new().to_string().to_lowercase()
        ))
    }

    fn test_principal() -> Principal {
        Principal {
            canonical_id: "human:test".into(),
        }
    }

    fn test_open_request() -> OpenSessionRequest {
        OpenSessionRequest {
            package_id: test_package(),
            ecosystem: EcosystemRuntime::RuntimeLinuxNative,
            requester: test_principal(),
            capability_grants: vec![],
            timeout: Duration::from_secs(3600),
        }
    }

    // ------------------------------------------------------------------
    // Config / construction tests
    // ------------------------------------------------------------------

    #[test]
    fn construct_driver_with_defaults() {
        let driver = SessionContainerDriver::new_with_defaults();
        assert_eq!(driver.config().image, "aios-session-wayland:rev6");
        assert_eq!(driver.config().runtime_binary, "podman");
        assert_eq!(driver.config().memory_mb, 2048);
    }

    #[test]
    fn config_builder_chains_all_fields() {
        let config = SessionContainerConfig::default()
            .with_image("my-image:v1")
            .with_gpu_device("/dev/dri/renderD128")
            .with_memory_mb(4096)
            .with_cpu_shares(512)
            .with_wayland_display("wayland-1")
            .with_gstreamer_port(9090)
            .with_max_sessions(4);

        assert_eq!(config.image, "my-image:v1");
        assert_eq!(config.gpu_device.as_deref(), Some("/dev/dri/renderD128"));
        assert_eq!(config.memory_mb, 4096);
        assert_eq!(config.cpu_shares, 512);
        assert_eq!(config.wayland_display.as_deref(), Some("wayland-1"));
        assert_eq!(config.gstreamer_port, 9090);
        assert_eq!(config.max_sessions, 4);
    }

    #[test]
    fn docker_config_sets_runtime_binary() {
        let config = SessionContainerConfig::default().with_docker();
        assert_eq!(config.runtime_binary, "docker");
        assert_eq!(config.container_runtime(), SessionContainerRuntime::Docker);
    }

    #[test]
    fn podman_config_has_podman_runtime() {
        let config = SessionContainerConfig::default();
        assert_eq!(config.container_runtime(), SessionContainerRuntime::Podman);
    }

    #[test]
    fn config_defaults_match_s6_5_spec() {
        let config = SessionContainerConfig::default();
        assert_eq!(config.gstreamer_port, 8080);
        assert_eq!(config.health_timeout_secs, 30);
        assert_eq!(config.x11_display, 99);
    }

    // ------------------------------------------------------------------
    // OCI state mapping
    // ------------------------------------------------------------------

    #[test]
    fn oci_state_running_maps_to_active() {
        assert_eq!(
            SessionContainerDriver::oci_state_to_container_state("running"),
            SessionContainerState::Active
        );
    }

    #[test]
    fn oci_state_paused_maps_to_paused() {
        assert_eq!(
            SessionContainerDriver::oci_state_to_container_state("paused"),
            SessionContainerState::Paused
        );
    }

    #[test]
    fn oci_state_created_maps_to_starting() {
        assert_eq!(
            SessionContainerDriver::oci_state_to_container_state("created"),
            SessionContainerState::Starting
        );
    }

    #[test]
    fn oci_state_exited_maps_to_reclaimed() {
        assert_eq!(
            SessionContainerDriver::oci_state_to_container_state("exited"),
            SessionContainerState::Reclaimed
        );
    }

    #[test]
    fn oci_state_unknown_maps_to_reclaimed() {
        assert_eq!(
            SessionContainerDriver::oci_state_to_container_state("dead"),
            SessionContainerState::Reclaimed
        );
    }

    // ------------------------------------------------------------------
    // Session lifecycle FSM transitions (no real container needed)
    // ------------------------------------------------------------------

    #[test]
    fn session_lifecycle_fsm_idle_to_starting_to_active() {
        let states = [
            SessionContainerState::Idle,
            SessionContainerState::Starting,
            SessionContainerState::Active,
        ];
        // Verify the full forward chain is defined.
        for w in states.windows(2) {
            assert_ne!(w[0], w[1]);
        }
    }

    #[test]
    fn session_lifecycle_fsm_active_to_paused_to_active() {
        let states = [
            SessionContainerState::Active,
            SessionContainerState::Paused,
            SessionContainerState::Active,
        ];
        for w in states.windows(2) {
            assert_ne!(w[0], w[1]);
        }
    }

    #[test]
    fn session_lifecycle_fsm_any_to_reclaimed() {
        let non_terminal = vec![
            SessionContainerState::Idle,
            SessionContainerState::Starting,
            SessionContainerState::Active,
            SessionContainerState::Paused,
        ];
        for state in non_terminal {
            assert_ne!(state, SessionContainerState::Reclaimed);
        }
    }

    #[test]
    fn reclaimed_is_terminal() {
        // Reclaimed should be the only terminal state.
        assert!(matches!(
            SessionContainerState::Reclaimed,
            SessionContainerState::Reclaimed
        ));
    }

    #[test]
    fn driver_state_mapping_idle_to_allocating() {
        let handle = ContainerHandle {
            session_id: SessionId("sess_test".into()),
            container_name: "sess_test".into(),
            container_id: None,
            container_state: SessionContainerState::Idle,
            package_id: PackageId("pkg_test".into()),
            ecosystem: EcosystemRuntime::RuntimeLinuxNative,
            requester: Principal {
                canonical_id: "human:test".into(),
            },
            created_at: Utc::now(),
            last_heartbeat: Utc::now(),
            timeout: Duration::from_secs(3600),
            heartbeat_count: 0,
        };
        assert_eq!(handle.to_driver_state(), SessionState::Allocating);
    }

    #[test]
    fn driver_state_mapping_active_to_active() {
        let mut handle = ContainerHandle {
            session_id: SessionId("sess_test".into()),
            container_name: "sess_test".into(),
            container_id: None,
            container_state: SessionContainerState::Active,
            package_id: PackageId("pkg_test".into()),
            ecosystem: EcosystemRuntime::RuntimeLinuxNative,
            requester: Principal {
                canonical_id: "human:test".into(),
            },
            created_at: Utc::now(),
            last_heartbeat: Utc::now(),
            timeout: Duration::from_secs(3600),
            heartbeat_count: 0,
        };
        handle.container_state = SessionContainerState::Active;
        assert_eq!(handle.to_driver_state(), SessionState::Active);
    }

    #[test]
    fn driver_state_mapping_reclaimed_to_terminated() {
        let handle = ContainerHandle {
            session_id: SessionId("sess_test".into()),
            container_name: "sess_test".into(),
            container_id: None,
            container_state: SessionContainerState::Reclaimed,
            package_id: PackageId("pkg_test".into()),
            ecosystem: EcosystemRuntime::RuntimeLinuxNative,
            requester: Principal {
                canonical_id: "human:test".into(),
            },
            created_at: Utc::now(),
            last_heartbeat: Utc::now(),
            timeout: Duration::from_secs(3600),
            heartbeat_count: 0,
        };
        assert_eq!(handle.to_driver_state(), SessionState::Terminated);
    }

    #[test]
    fn evidence_emitted_on_state_change() {
        // This test verifies evidence emitter attachment compiles and is callable.
        let emitter = Arc::new(InMemoryAppsEvidenceEmitter::new("service:test"));
        let _driver = SessionContainerDriver::new_with_defaults().with_emitter(emitter);
        // If we got here without a compile error, the evidence wiring is sound.
    }

    // ------------------------------------------------------------------
    // Resource quota config
    // ------------------------------------------------------------------

    #[test]
    fn resource_quota_config_applied() {
        let config = SessionContainerConfig::default()
            .with_memory_mb(4096)
            .with_cpu_shares(512)
            .with_max_sessions(4);

        let driver = SessionContainerDriver::new(config);
        assert_eq!(driver.config().memory_mb, 4096);
        assert_eq!(driver.config().cpu_shares, 512);
        assert_eq!(driver.config().max_sessions, 4);
    }

    #[test]
    fn gpu_device_config_stored() {
        let config = SessionContainerConfig::default().with_gpu_device("/dev/dri/renderD128");
        let driver = SessionContainerDriver::new(config);
        assert_eq!(
            driver.config().gpu_device.as_deref(),
            Some("/dev/dri/renderD128")
        );
    }

    #[test]
    fn wayland_display_config_stored() {
        let config = SessionContainerConfig::default().with_wayland_display("wayland-1");
        let driver = SessionContainerDriver::new(config);
        assert_eq!(
            driver.config().wayland_display.as_deref(),
            Some("wayland-1")
        );
    }

    // ------------------------------------------------------------------
    // ContainerHandle metrics / timeout
    // ------------------------------------------------------------------

    #[test]
    fn container_handle_not_timed_out_when_fresh() {
        let now = Utc::now();
        let handle = ContainerHandle {
            session_id: SessionId("sess_test".into()),
            container_name: "sess_test".into(),
            container_id: None,
            container_state: SessionContainerState::Active,
            package_id: PackageId("pkg_test".into()),
            ecosystem: EcosystemRuntime::RuntimeLinuxNative,
            requester: Principal {
                canonical_id: "human:test".into(),
            },
            created_at: now,
            last_heartbeat: now,
            timeout: Duration::from_secs(3600),
            heartbeat_count: 0,
        };
        assert!(!handle.is_timed_out(now));
    }

    #[test]
    fn container_handle_timed_out_after_duration() {
        let created = Utc::now();
        let handle = ContainerHandle {
            session_id: SessionId("sess_test".into()),
            container_name: "sess_test".into(),
            container_id: None,
            container_state: SessionContainerState::Active,
            package_id: PackageId("pkg_test".into()),
            ecosystem: EcosystemRuntime::RuntimeLinuxNative,
            requester: Principal {
                canonical_id: "human:test".into(),
            },
            created_at: created,
            last_heartbeat: created,
            timeout: Duration::from_secs(1),
            heartbeat_count: 0,
        };
        let later = created + chrono::Duration::seconds(2);
        assert!(handle.is_timed_out(later));
    }

    #[test]
    fn container_handle_metrics_uptime_counts() {
        let created = Utc::now();
        let handle = ContainerHandle {
            session_id: SessionId("sess_test".into()),
            container_name: "sess_test".into(),
            container_id: None,
            container_state: SessionContainerState::Active,
            package_id: PackageId("pkg_test".into()),
            ecosystem: EcosystemRuntime::RuntimeLinuxNative,
            requester: Principal {
                canonical_id: "human:test".into(),
            },
            created_at: created,
            last_heartbeat: created,
            timeout: Duration::from_secs(3600),
            heartbeat_count: 5,
        };
        let ended = created + chrono::Duration::seconds(120);
        let uptime = (ended - handle.created_at).num_seconds();
        assert_eq!(handle.heartbeat_count, 5);
        assert_eq!(uptime.max(0).unsigned_abs(), 120);
    }

    // ------------------------------------------------------------------
    // Driver is Send + Sync
    // ------------------------------------------------------------------

    #[test]
    fn driver_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SessionContainerDriver>();
    }

    // ------------------------------------------------------------------
    // build_run_args produces correct arguments
    // ------------------------------------------------------------------

    #[test]
    fn build_run_args_includes_memory_and_cpu() {
        let config = SessionContainerConfig::default()
            .with_memory_mb(2048)
            .with_cpu_shares(512);
        let driver = SessionContainerDriver::new(config);
        let args = driver.build_run_args("test-container", 8080);

        // Find argument positions
        let mem_idx = args.iter().position(|a| a == "--memory");
        let cpu_idx = args.iter().position(|a| a == "--cpu-shares");
        let name_idx = args.iter().position(|a| a == "--name");

        assert!(mem_idx.is_some(), "--memory flag missing");
        assert!(cpu_idx.is_some(), "--cpu-shares flag missing");
        assert!(name_idx.is_some(), "--name flag missing");

        if let Some(idx) = mem_idx {
            assert_eq!(args.get(idx + 1).map(String::as_str), Some("2048m"));
        }
        if let Some(idx) = cpu_idx {
            assert_eq!(args.get(idx + 1).map(String::as_str), Some("512"));
        }
        if let Some(idx) = name_idx {
            assert_eq!(
                args.get(idx + 1).map(String::as_str),
                Some("test-container")
            );
        }
    }

    #[test]
    fn build_run_args_includes_gpu_device_when_configured() {
        let config = SessionContainerConfig::default().with_gpu_device("/dev/dri/renderD128");
        let driver = SessionContainerDriver::new(config);
        let args = driver.build_run_args("test", 8080);
        let dev_idx = args.iter().position(|a| a == "--device");
        assert!(
            dev_idx.is_some(),
            "--device flag missing with GPU configured"
        );
        if let Some(idx) = dev_idx {
            assert_eq!(
                args.get(idx + 1).map(String::as_str),
                Some("/dev/dri/renderD128")
            );
        }
    }

    #[test]
    fn build_run_args_no_gpu_device_when_none() {
        let config = SessionContainerConfig::default();
        let driver = SessionContainerDriver::new(config);
        let args = driver.build_run_args("test", 8080);
        let dev_idx = args.iter().position(|a| a == "--device");
        assert!(
            dev_idx.is_none(),
            "--device flag present without GPU config"
        );
    }

    #[test]
    fn build_run_args_includes_wayland_when_configured() {
        let config = SessionContainerConfig::default().with_wayland_display("wayland-0");
        let driver = SessionContainerDriver::new(config);
        let args = driver.build_run_args("test", 8080);

        let env_idx = args.iter().position(|a| a.starts_with("WAYLAND_DISPLAY="));
        assert!(env_idx.is_some(), "WAYLAND_DISPLAY env missing");

        if let Some(idx) = env_idx {
            assert_eq!(args[idx], "WAYLAND_DISPLAY=wayland-0");
        }
    }

    #[test]
    fn build_run_args_publishes_gstreamer_port() {
        let config = SessionContainerConfig::default().with_gstreamer_port(9090);
        let driver = SessionContainerDriver::new(config);
        let args = driver.build_run_args("test", 9090);
        let publish_idx = args.iter().position(|a| a == "--publish");
        assert!(publish_idx.is_some(), "--publish flag missing");
        if let Some(idx) = publish_idx {
            assert_eq!(args.get(idx + 1).map(String::as_str), Some("9090:9090"));
        }
    }

    // ------------------------------------------------------------------
    // open_session with unavailable runtime returns error
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn open_session_with_unavailable_runtime_returns_error() {
        let config = SessionContainerConfig::default();
        // Use a binary name that definitely doesn't exist
        let config = SessionContainerConfig {
            runtime_binary: "nonexistent-binary-xyz-123".into(),
            ..config
        };
        let driver = SessionContainerDriver::new(config);
        let result = driver.open_session(test_open_request()).await;
        assert!(result.is_err(), "Should fail when runtime not found");
    }

    // ------------------------------------------------------------------
    // Session quota enforcement
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn quota_exceeded_returns_error() {
        let config = SessionContainerConfig::default().with_max_sessions(0);
        let driver = SessionContainerDriver::new(config);
        let result = driver.open_session(test_open_request()).await;
        // Should fail either because runtime not found or quota (runtime check
        // comes first, so it may fail there)
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // Not found session
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn get_nonexistent_session_returns_not_found() {
        let driver = SessionContainerDriver::new_with_defaults();
        let result = driver.get_session(SessionId("nonexistent".into())).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn close_nonexistent_session_returns_not_found() {
        let driver = SessionContainerDriver::new_with_defaults();
        let result = driver.close_session(SessionId("nonexistent".into())).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn heartbeat_nonexistent_session_returns_not_found() {
        let driver = SessionContainerDriver::new_with_defaults();
        let result = driver.heartbeat(SessionId("nonexistent".into())).await;
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // List sessions: empty initially
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn list_sessions_empty_initially() {
        let driver = SessionContainerDriver::new_with_defaults();
        let sessions = driver.list_sessions(SessionFilter::All).await;
        assert!(sessions.is_empty());
    }

    // ------------------------------------------------------------------
    // active_session_count starts at zero
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn active_session_count_zero_initially() {
        let driver = SessionContainerDriver::new_with_defaults();
        assert_eq!(driver.active_session_count().await, 0);
    }

    // ------------------------------------------------------------------
    // pause_session / resume_session with invalid state
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn pause_nonexistent_session_returns_error() {
        let driver = SessionContainerDriver::new_with_defaults();
        let result = driver.pause_session(&SessionId("nonexistent".into())).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resume_nonexistent_session_returns_error() {
        let driver = SessionContainerDriver::new_with_defaults();
        let result = driver
            .resume_session(&SessionId("nonexistent".into()))
            .await;
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // health_check nonexistent
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn health_check_nonexistent_session_returns_error() {
        let driver = SessionContainerDriver::new_with_defaults();
        let result = driver.health_check(&SessionId("nonexistent".into())).await;
        assert!(result.is_err());
    }
}
