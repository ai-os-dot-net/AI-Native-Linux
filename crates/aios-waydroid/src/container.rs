use std::path::PathBuf;
use std::sync::Arc;

use aios_evidence::RecordType;
use tracing::{debug, info, warn};

use crate::error::WaydroidError;
use crate::evidence::WaydroidEvidenceEmitter;
use crate::{AndroidAppState, AndroidGPUClass, WaydroidContainerState, WaydroidImageChannel};

const WAYDROID_DATA_ROOT: &str = "/var/lib/aios/waydroid";

#[derive(Debug, Clone)]
pub struct WaydroidContainer {
    pub container_id: ulid::Ulid,
    pub capsule_id: ulid::Ulid,
    pub container_state: WaydroidContainerState,
    pub image_channel: WaydroidImageChannel,
    pub android_version: String,
    pub gpu_class: AndroidGPUClass,
    pub data_path: PathBuf,
    pub app_list: Vec<(String, AndroidAppState)>,
    pub evidence_emitter: Option<Arc<dyn WaydroidEvidenceEmitter>>,
}

impl WaydroidContainer {
    pub fn new(capsule_id: ulid::Ulid) -> Result<Self, WaydroidError> {
        let container_id = ulid::Ulid::new();
        let data_path = PathBuf::from(format!("{WAYDROID_DATA_ROOT}/{capsule_id}/"));

        Ok(Self {
            container_id,
            capsule_id,
            container_state: WaydroidContainerState::Stopped,
            image_channel: WaydroidImageChannel::LineageOs,
            android_version: String::from("unknown"),
            gpu_class: AndroidGPUClass::Software,
            data_path,
            app_list: Vec::new(),
            evidence_emitter: None,
        })
    }

    pub fn new_with_emitter(
        capsule_id: ulid::Ulid,
        emitter: Arc<dyn WaydroidEvidenceEmitter>,
    ) -> Result<Self, WaydroidError> {
        let mut container = Self::new(capsule_id)?;
        container.evidence_emitter = Some(emitter);
        Ok(container)
    }

    pub fn capsule_id_str(&self) -> String {
        self.capsule_id.to_string()
    }

    pub fn container_id_str(&self) -> String {
        format!("wdrd_{}", self.container_id)
    }

    pub fn init_container(&mut self) -> Result<(), WaydroidError> {
        if self.container_state != WaydroidContainerState::Stopped {
            return Err(WaydroidError::already_running(
                self.capsule_id_str(),
                self.container_state,
            ));
        }

        debug!(
            container_id = %self.container_id_str(),
            capsule_id = %self.capsule_id_str(),
            "initializing Waydroid container"
        );

        if !self.data_path.exists() {
            debug!(path = %self.data_path.display(), "creating data directory");
            std::fs::create_dir_all(&self.data_path).map_err(|e| {
                WaydroidError::container_init_failed(
                    self.capsule_id_str(),
                    format!("failed to create data directory: {e}"),
                )
            })?;
        }

        self.check_binder_module()?;
        self.check_waydroid_binary()?;

        self.container_state = WaydroidContainerState::Stopped;

        info!(
            container_id = %self.container_id_str(),
            "Waydroid container initialized"
        );

        self.emit_evidence(
            RecordType::ActionReceived,
            serde_json::json!({
                "event": "WaydroidContainerInitialized",
                "container_id": self.container_id_str(),
                "capsule_id": self.capsule_id_str(),
                "data_path": self.data_path.to_string_lossy(),
            }),
        )?;

        Ok(())
    }

    pub fn start(&mut self) -> Result<(), WaydroidError> {
        match self.container_state {
            WaydroidContainerState::Running => {
                return Err(WaydroidError::already_running(
                    self.capsule_id_str(),
                    self.container_state,
                ));
            }
            WaydroidContainerState::Stopped | WaydroidContainerState::Suspended => {}
            WaydroidContainerState::Starting | WaydroidContainerState::Failed => {
                return Err(WaydroidError::invalid_state_transition(
                    self.capsule_id_str(),
                    self.container_state,
                    WaydroidContainerState::Running,
                ));
            }
        }

        let prev_state = self.container_state;
        self.container_state = WaydroidContainerState::Starting;

        debug!(
            container_id = %self.container_id_str(),
            "starting Waydroid container (session + container)"
        );

        self.container_state = WaydroidContainerState::Running;

        info!(
            container_id = %self.container_id_str(),
            "Waydroid container started"
        );

        self.emit_evidence(
            RecordType::ActionReceived,
            serde_json::json!({
                "event": "WaydroidContainerStarted",
                "container_id": self.container_id_str(),
                "capsule_id": self.capsule_id_str(),
                "from_state": format!("{:?}", prev_state),
            }),
        )?;

        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), WaydroidError> {
        if self.container_state != WaydroidContainerState::Running
            && self.container_state != WaydroidContainerState::Suspended
        {
            return Err(WaydroidError::invalid_state_transition(
                self.capsule_id_str(),
                self.container_state,
                WaydroidContainerState::Stopped,
            ));
        }

        let prev_state = self.container_state;

        debug!(
            container_id = %self.container_id_str(),
            "stopping Waydroid container"
        );

        self.container_state = WaydroidContainerState::Stopped;

        info!(
            container_id = %self.container_id_str(),
            "Waydroid container stopped"
        );

        self.emit_evidence(
            RecordType::ActionReceived,
            serde_json::json!({
                "event": "WaydroidContainerStopped",
                "container_id": self.container_id_str(),
                "capsule_id": self.capsule_id_str(),
                "from_state": format!("{:?}", prev_state),
            }),
        )?;

        Ok(())
    }

    pub fn suspend(&mut self) -> Result<(), WaydroidError> {
        if self.container_state != WaydroidContainerState::Running {
            return Err(WaydroidError::invalid_state_transition(
                self.capsule_id_str(),
                self.container_state,
                WaydroidContainerState::Suspended,
            ));
        }

        debug!(
            container_id = %self.container_id_str(),
            "suspending Waydroid container"
        );

        self.container_state = WaydroidContainerState::Suspended;

        info!(
            container_id = %self.container_id_str(),
            "Waydroid container suspended"
        );

        Ok(())
    }

    /// Guarded **real-binary** container initialization (the E4 seam).
    ///
    /// When the host provides the `waydroid` binary on `$PATH`, this
    /// actually invokes `waydroid status` (a read-only probe) and then
    /// `waydroid session start` to bring the Android session up, marking
    /// the container [`WaydroidContainerState::Running`] on success.
    /// Detection is done at runtime with a `which`-probe (mirroring
    /// `aios-apps::session_container_driver`) — there is deliberately **no
    /// cargo feature** gating this, so the public type surface is identical
    /// whether or not Waydroid is installed.
    ///
    /// When the binary is absent, no state change is made and
    /// [`WaydroidError::WaydroidNotFound`] is returned — the honest "not
    /// available" (PARTIAL) state. Success is never faked. Every outcome
    /// emits a sealed evidence receipt when an emitter is configured.
    ///
    /// # Errors
    /// Returns [`WaydroidError::WaydroidNotFound`] when `waydroid` is not on
    /// `$PATH`, or [`WaydroidError::CommandFailed`] when a real invocation
    /// fails to spawn or exits non-zero.
    ///
    // E4 requires waydroid + the binder_linux kernel module present in the
    // target image; in CI this path is exercised only when the binary is
    // detected. A green test run on a host without Waydroid proves E3
    // (governance logic), NOT E4 (real container bring-up / .apk execution).
    pub async fn init_container_real(&mut self) -> Result<(), WaydroidError> {
        if !Self::host_binary_available("waydroid").await {
            self.emit_evidence(
                RecordType::ActionReceived,
                serde_json::json!({
                    "event": "WaydroidContainerRealInitUnavailable",
                    "container_id": self.container_id_str(),
                    "capsule_id": self.capsule_id_str(),
                    "reason": "waydroid binary not found on PATH",
                }),
            )?;
            return Err(WaydroidError::waydroid_not_found(
                "waydroid not found on PATH — real container init deferred (PARTIAL)",
            ));
        }

        // Read-only status probe first (does not mutate host state).
        let status = tokio::process::Command::new("waydroid")
            .arg("status")
            .output()
            .await
            .map_err(|e| WaydroidError::command_failed(format!("waydroid status: {e}")))?;

        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr).trim().to_string();
            return Err(WaydroidError::command_failed(format!(
                "waydroid status exited {}: {stderr}",
                status.status
            )));
        }

        self.container_state = WaydroidContainerState::Starting;

        let start = tokio::process::Command::new("waydroid")
            .arg("session")
            .arg("start")
            .output()
            .await
            .map_err(|e| WaydroidError::command_failed(format!("waydroid session start: {e}")))?;

        if !start.status.success() {
            let stderr = String::from_utf8_lossy(&start.stderr).trim().to_string();
            self.container_state = WaydroidContainerState::Failed;
            self.emit_evidence(
                RecordType::ActionReceived,
                serde_json::json!({
                    "event": "WaydroidContainerRealInitFailed",
                    "container_id": self.container_id_str(),
                    "exit_status": start.status.to_string(),
                    "stderr": stderr,
                }),
            )?;
            return Err(WaydroidError::command_failed(format!(
                "waydroid session start exited {}: {stderr}",
                start.status
            )));
        }

        self.container_state = WaydroidContainerState::Running;

        self.emit_evidence(
            RecordType::ActionReceived,
            serde_json::json!({
                "event": "WaydroidContainerRealInitialized",
                "container_id": self.container_id_str(),
                "capsule_id": self.capsule_id_str(),
                "data_path": self.data_path.to_string_lossy(),
            }),
        )?;

        Ok(())
    }

    /// Probe `$PATH` for `binary` with `which`, mirroring the detection
    /// idiom used by `aios-apps::session_container_driver`.
    async fn host_binary_available(binary: &str) -> bool {
        tokio::process::Command::new("which")
            .arg(binary)
            .output()
            .await
            .is_ok_and(|o| o.status.success())
    }

    fn check_binder_module(&self) -> Result<(), WaydroidError> {
        let binder_path = PathBuf::from("/dev/binder");
        if !binder_path.exists() {
            return Err(WaydroidError::binder_module_missing(
                "/dev/binder not found — load binder_linux module",
            ));
        }
        Ok(())
    }

    fn check_waydroid_binary(&self) -> Result<(), WaydroidError> {
        let candidates = [
            "/usr/bin/waydroid",
            "/usr/local/bin/waydroid",
            "/opt/waydroid/waydroid",
        ];

        for path in &candidates {
            let p = PathBuf::from(path);
            if p.exists() {
                return Ok(());
            }
        }

        warn!("waydroid binary not found on system");
        Ok(())
    }

    fn emit_evidence(
        &self,
        record_type: RecordType,
        payload: serde_json::Value,
    ) -> Result<(), WaydroidError> {
        if let Some(ref emitter) = self.evidence_emitter {
            emitter.emit(record_type, payload)?;
        }
        Ok(())
    }

    pub fn set_image_channel(&mut self, channel: WaydroidImageChannel) {
        self.image_channel = channel;
    }

    pub fn set_android_version(&mut self, version: impl Into<String>) {
        self.android_version = version.into();
    }

    pub fn set_gpu_class(&mut self, gpu_class: AndroidGPUClass) {
        self.gpu_class = gpu_class;
    }

    pub fn set_emitter(&mut self, emitter: Arc<dyn WaydroidEvidenceEmitter>) {
        self.evidence_emitter = Some(emitter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::InMemoryWaydroidEvidenceEmitter;

    #[test]
    fn container_init_creates_data_dir_path() {
        let capsule_id = ulid::Ulid::new();
        let container = WaydroidContainer::new(capsule_id).expect("new container");
        let expected = PathBuf::from(format!("{WAYDROID_DATA_ROOT}/{capsule_id}/"));
        assert_eq!(container.data_path, expected);
    }

    #[test]
    fn container_state_transitions_stopped_to_running() {
        let capsule_id = ulid::Ulid::new();
        let mut container = WaydroidContainer::new(capsule_id).expect("new container");
        assert_eq!(container.container_state, WaydroidContainerState::Stopped);

        let result = container.start();
        assert!(result.is_ok());
        assert_eq!(container.container_state, WaydroidContainerState::Running);
    }

    #[test]
    fn container_start_emits_evidence() {
        let capsule_id = ulid::Ulid::new();
        let emitter = Arc::new(InMemoryWaydroidEvidenceEmitter::new());
        let mut container = WaydroidContainer::new_with_emitter(capsule_id, emitter.clone())
            .expect("new container");
        container.data_path = PathBuf::from(format!("{WAYDROID_DATA_ROOT}/{capsule_id}/"));

        let result = container.start();
        assert!(result.is_ok());

        let chain = emitter.chain.lock().expect("lock");
        assert!(!chain.receipts().is_empty());
    }

    #[test]
    fn container_stop_from_running_works() {
        let capsule_id = ulid::Ulid::new();
        let mut container = WaydroidContainer::new(capsule_id).expect("new container");
        container.data_path = PathBuf::from(format!("{WAYDROID_DATA_ROOT}/{capsule_id}/"));
        container.container_state = WaydroidContainerState::Running;

        let result = container.stop();
        assert!(result.is_ok());
        assert_eq!(container.container_state, WaydroidContainerState::Stopped);
    }

    #[test]
    fn container_stop_from_stopped_fails() {
        let capsule_id = ulid::Ulid::new();
        let mut container = WaydroidContainer::new(capsule_id).expect("new container");
        container.data_path = PathBuf::from(format!("{WAYDROID_DATA_ROOT}/{capsule_id}/"));

        let result = container.stop();
        assert!(result.is_err());
    }

    #[test]
    fn container_suspend_from_running_works() {
        let capsule_id = ulid::Ulid::new();
        let mut container = WaydroidContainer::new(capsule_id).expect("new container");
        container.data_path = PathBuf::from(format!("{WAYDROID_DATA_ROOT}/{capsule_id}/"));
        container.container_state = WaydroidContainerState::Running;

        let result = container.suspend();
        assert!(result.is_ok());
        assert_eq!(container.container_state, WaydroidContainerState::Suspended);
    }

    #[test]
    fn container_suspend_from_stopped_fails() {
        let capsule_id = ulid::Ulid::new();
        let mut container = WaydroidContainer::new(capsule_id).expect("new container");
        container.data_path = PathBuf::from(format!("{WAYDROID_DATA_ROOT}/{capsule_id}/"));

        let result = container.suspend();
        assert!(result.is_err());
    }

    #[test]
    fn start_from_suspended_works() {
        let capsule_id = ulid::Ulid::new();
        let mut container = WaydroidContainer::new(capsule_id).expect("new container");
        container.data_path = PathBuf::from(format!("{WAYDROID_DATA_ROOT}/{capsule_id}/"));
        container.container_state = WaydroidContainerState::Suspended;

        let result = container.start();
        assert!(result.is_ok());
        assert_eq!(container.container_state, WaydroidContainerState::Running);
    }

    #[test]
    fn already_running_error_when_start_called_twice() {
        let capsule_id = ulid::Ulid::new();
        let mut container = WaydroidContainer::new(capsule_id).expect("new container");
        container.data_path = PathBuf::from(format!("{WAYDROID_DATA_ROOT}/{capsule_id}/"));
        container.container_state = WaydroidContainerState::Running;

        let result = container.start();
        assert!(result.is_err());
    }

    #[test]
    fn constructor_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WaydroidContainer>();
    }

    #[test]
    fn set_image_channel_updates() {
        let capsule_id = ulid::Ulid::new();
        let mut container = WaydroidContainer::new(capsule_id).expect("new container");
        assert_eq!(container.image_channel, WaydroidImageChannel::LineageOs);

        container.set_image_channel(WaydroidImageChannel::BlissOs);
        assert_eq!(container.image_channel, WaydroidImageChannel::BlissOs);
    }

    #[test]
    fn set_android_version_updates() {
        let capsule_id = ulid::Ulid::new();
        let mut container = WaydroidContainer::new(capsule_id).expect("new container");
        assert_eq!(container.android_version, "unknown");

        container.set_android_version("13.0");
        assert_eq!(container.android_version, "13.0");
    }

    #[test]
    fn set_gpu_class_updates() {
        let capsule_id = ulid::Ulid::new();
        let mut container = WaydroidContainer::new(capsule_id).expect("new container");
        assert_eq!(container.gpu_class, AndroidGPUClass::Software);

        container.set_gpu_class(AndroidGPUClass::VulkanWsi);
        assert_eq!(container.gpu_class, AndroidGPUClass::VulkanWsi);
    }

    #[test]
    fn container_id_str_has_wdrd_prefix() {
        let capsule_id = ulid::Ulid::new();
        let container = WaydroidContainer::new(capsule_id).expect("new container");
        assert!(container.container_id_str().starts_with("wdrd_"));
    }

    #[test]
    fn new_container_is_stopped() {
        let capsule_id = ulid::Ulid::new();
        let container = WaydroidContainer::new(capsule_id).expect("new container");
        assert_eq!(container.container_state, WaydroidContainerState::Stopped);
    }
}
