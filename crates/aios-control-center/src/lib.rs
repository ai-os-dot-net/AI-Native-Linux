//! # AIOS Control Center (L7)
//!
//! The Control Center is the AIOS-native web admin panel. Its differentiator
//! versus a classic Linux control panel is a hard architectural law:
//!
//! > **The operator proposes, the system executes.** Every *mutating* operator
//! > action is emitted as a **typed** [`ControlAction`], routed through the
//! > **Policy Kernel** for a decision, and only reflected to the UI **after** a
//! > policy decision + an **evidence** receipt. The panel never shells out and
//! > never calls a system API directly.
//!
//! ## Reuse, not reinvention
//!
//! This crate is an **application on top of the L7 Web renderer transport**
//! ([`aios_renderer_web`]). It does not introduce a new transport. It consumes:
//!
//! * [`aios_renderer_web::GrpcWebClientStub`] / [`aios_renderer_web::GrpcWebBridge`]
//!   — the gRPC-Web bridge to the AIOS backend services (origin allowlist,
//!   service allowlist, message-size ceiling). Every routed request passes the
//!   bridge gate before leaving the panel.
//! * [`aios_renderer_web::ExposureFsm`] / [`aios_renderer_web::ExposureLevel`]
//!   — localhost-only-by-default exposure; any LAN/remote escalation requires a
//!   **policy decision id** (INV I3).
//! * [`aios_renderer_web::InMemoryWebEvidenceEmitter`] /
//!   [`aios_renderer_web::WebEvidenceEmitter`] — append-only evidence receipts.
//!
//! ## Honest taxonomy of this scaffold
//!
//! * The **typed action taxonomy**, the **read-only routing through the real
//!   bridge gate**, and the **LAN-exposure-requires-a-decision-id** path are
//!   `REAL` at `E3` (unit-tested here).
//! * The **transport seam** is now `REAL`: [`ControlCenter`] is generic over a
//!   [`ControlTransport`], and [`RealGrpcTransport`] constructs configured
//!   `tonic` `Endpoint`s (localhost default + connect/request timeouts) and the
//!   **real, importable** backend tonic client stubs
//!   ([`aios_policy::service::PolicyKernelClient`],
//!   [`aios_sgr::service::SgrServiceClient`],
//!   [`aios_evidence::service::EvidenceLogClient`]) over real `Channel`s
//!   (`E3`, unit-tested offline via `connect_lazy`). The default transport is
//!   [`StubTransport`] (the reused echo stub) so the scaffold's behavior is
//!   unchanged.
//! * The **final typed method-dispatch** — turning the abstract
//!   `(service, method, JSON payload)` triple into a concrete typed proto
//!   request and issuing the RPC — is the **only** remaining `CONTRACT`
//!   boundary ([`RealGrpcTransport::send`] returns
//!   [`ControlCenterError::TransportContract`] naming the exact proto path). It
//!   is a genuine deployment task because the SGR/Evidence method names have no
//!   1:1 proto RPC and `PolicyKernel.EvaluatePolicy` needs an
//!   `aios_action::ActionEnvelope` transcode. **No execution is faked**, and the
//!   no-execute law (no `Executed` outcome; mutating actions terminate at
//!   [`ActionOutcome::PolicyPending`]) holds for **any** transport.
//!
//! See `DESIGN.md` for the full architecture and the three-tier product picture.

#![forbid(unsafe_code)]

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use aios_renderer_web::{
    ExposureFsm, ExposureLevel, GrpcWebBridge, GrpcWebClientStub, InMemoryWebEvidenceEmitter,
    WebEvidenceEmitter, WebEvidenceReceipt, WebRendererError,
};

pub mod transport;

pub use transport::{
    BackendClients, BackendEndpoints, ControlTransport, RealGrpcTransport, StubTransport,
};

/// Return the Control Center panel's base stylesheet, built from the AIOS
/// design tokens.
///
/// The panel renders over the shared token system: this composes the light and
/// dark `:root` custom-property blocks emitted by the L7 Web renderer's
/// design-token seam ([`aios_renderer_web::css_compile::aios_default_stylesheet`],
/// which itself emits from `aios_design_tokens::TokenSet::aios_default`). Both
/// themes' `--aios-color-*` (and spacing / radius / typography) custom
/// properties are included so a served panel resolves `var(--aios-color-*)` in
/// either theme.
#[must_use]
pub fn control_center_stylesheet() -> String {
    let light = aios_renderer_web::css_compile::aios_default_stylesheet(false);
    let dark = aios_renderer_web::css_compile::aios_default_stylesheet(true);
    format!("{light}\n{dark}\n")
}

/// Return the Control Center panel's base stylesheet for a single theme
/// (`dark_theme = true` for the dark variant), built from the AIOS design
/// tokens via the L7 Web renderer's design-token seam.
#[must_use]
pub fn control_center_stylesheet_for(dark_theme: bool) -> String {
    aios_renderer_web::css_compile::aios_default_stylesheet(dark_theme)
}

/// Crate version marker used by future closure-invariant tests.
pub const CONTROL_CENTER_CODE_VERSION: &str = "aios-control-center/0.0.1-PARTIAL";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Closed error taxonomy for the Control Center application layer.
///
/// Transport / bridge / exposure failures are surfaced as
/// [`ControlCenterError::Renderer`], wrapping the underlying
/// [`WebRendererError`]. Application-level precondition failures use the
/// dedicated variants below.
#[derive(Debug, thiserror::Error)]
pub enum ControlCenterError {
    /// A failure originating in the reused L7 Web renderer transport (bridge
    /// gate rejection, exposure escalation denial, evidence seal failure, ...).
    #[error(transparent)]
    Renderer(#[from] WebRendererError),

    /// A mutating action was submitted but a required field was empty or
    /// malformed before it could be turned into a typed request.
    #[error("invalid control action: {0}")]
    InvalidAction(String),

    /// A policy decision id was required (e.g. to escalate exposure) but was
    /// missing or empty. The panel refuses to escalate without one — this is
    /// the "operator proposes, system decides" law in code.
    #[error("policy decision id required: {0}")]
    MissingDecisionId(String),

    /// The real gRPC transport ([`RealGrpcTransport`]) could not build or
    /// resolve a backend endpoint (invalid URL, unknown service).
    #[error("transport error: {0}")]
    Transport(String),

    /// The real gRPC transport reached its documented CONTRACT boundary: the
    /// tonic `Channel` and typed client stubs are real, but the final typed
    /// proto method-dispatch (JSON → typed request) is a deployment task. The
    /// message names the exact proto path. **No backend response is fabricated.**
    #[error("transport CONTRACT boundary: {0}")]
    TransportContract(String),
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Control Center configuration.
///
/// Defaults to **localhost-only** exposure ([`ExposureLevel::Localhost`]) with
/// the bridge's default localhost origin. Widening exposure is only possible
/// through the [`ExposureFsm`], which requires a policy decision id (INV I3).
#[derive(Debug, Clone)]
pub struct ControlCenterConfig {
    /// The origin the panel presents to the gRPC-Web bridge. Must be in the
    /// bridge origin allowlist. Defaults to `https://aios.localhost`.
    pub origin: String,
    /// The exposure level the panel starts at. Defaults to
    /// [`ExposureLevel::Localhost`] — bind only to loopback, no evidence
    /// required.
    pub exposure: ExposureLevel,
    /// Canonical subject id stamped on evidence receipts this panel emits.
    pub evidence_subject: String,
}

impl Default for ControlCenterConfig {
    fn default() -> Self {
        Self {
            origin: "https://aios.localhost".to_string(),
            exposure: ExposureLevel::Localhost,
            evidence_subject: "service:aios-control-center".to_string(),
        }
    }
}

impl ControlCenterConfig {
    /// Return `true` iff this config is bound to loopback only (the default).
    #[must_use]
    pub const fn is_localhost_only(&self) -> bool {
        matches!(self.exposure, ExposureLevel::Localhost)
    }
}

// ---------------------------------------------------------------------------
// Action taxonomy
// ---------------------------------------------------------------------------

/// The typed action taxonomy the panel exposes to the operator.
///
/// This is the **whole** surface through which the operator affects the system:
/// there is no free-form command input. Each variant maps to exactly one
/// backend gRPC service + method + typed payload (see [`ControlAction::route`]).
/// Mutating variants ([`ControlAction::is_mutating`]) are routed to the Policy
/// Kernel for a decision before any effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlAction {
    /// Read the desired-state / health of one SGR-managed service (read-only).
    ViewServiceHealth {
        /// The service unit name whose health is requested.
        service: String,
    },
    /// Request a restart of one service. **Mutating** — routed to the Policy
    /// Kernel as a typed action; never executed directly by the panel.
    RequestServiceRestart {
        /// The service unit name to restart.
        service: String,
    },
    /// Read the tail of the append-only evidence log (read-only).
    ViewEvidenceLog {
        /// Maximum number of trailing receipts to return.
        limit: u32,
    },
    /// Request LAN exposure of the panel. **Mutating** — drives the
    /// [`ExposureFsm`] to `LanPending` and requires a policy decision id to
    /// proceed to `LanApproved` (INV I3).
    RequestLanExposure {
        /// Canonical subject id of the approver gate that will authorize this.
        approver_canonical_id: String,
    },
}

impl ControlAction {
    /// Whether this action mutates system state (and therefore must pass
    /// through the Policy Kernel before any effect).
    #[must_use]
    pub const fn is_mutating(&self) -> bool {
        match self {
            Self::ViewServiceHealth { .. } | Self::ViewEvidenceLog { .. } => false,
            Self::RequestServiceRestart { .. } | Self::RequestLanExposure { .. } => true,
        }
    }

    /// The fully-qualified backend gRPC service this action routes to.
    ///
    /// Read-only actions target the owning domain service directly. **Mutating**
    /// actions target [`aios.policy.PolicyKernel`] — the operator *proposes*;
    /// the kernel *decides*; only then does the domain service act.
    #[must_use]
    pub const fn target_service(&self) -> &'static str {
        match self {
            Self::ViewServiceHealth { .. } => "aios.sgr.SgrService",
            Self::ViewEvidenceLog { .. } => "aios.evidence.EvidenceLog",
            // Mutating: the proposal is submitted to the Policy Kernel, not the
            // domain service. The domain effect happens only after a decision.
            Self::RequestServiceRestart { .. } | Self::RequestLanExposure { .. } => {
                "aios.policy.PolicyKernel"
            }
        }
    }

    /// The gRPC method name on [`ControlAction::target_service`] this action
    /// invokes.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::ViewServiceHealth { .. } => "GetServiceHealth",
            Self::ViewEvidenceLog { .. } => "TailReceipts",
            // Both mutating actions are submitted as a typed action envelope for
            // policy evaluation.
            Self::RequestServiceRestart { .. } | Self::RequestLanExposure { .. } => {
                "EvaluatePolicy"
            }
        }
    }

    /// Turn this action into a typed [`RoutedRequest`] (service, method, JSON
    /// payload, mutating flag).
    ///
    /// # Errors
    ///
    /// [`ControlCenterError::InvalidAction`] if a required field is empty.
    pub fn route(&self) -> Result<RoutedRequest, ControlCenterError> {
        let payload = match self {
            Self::ViewServiceHealth { service } => {
                Self::require_non_empty("service", service)?;
                serde_json::json!({ "service": service })
            }
            Self::RequestServiceRestart { service } => {
                Self::require_non_empty("service", service)?;
                // A typed proposed action envelope — NOT a shell command.
                serde_json::json!({
                    "proposed_action": {
                        "verb": "service.restart",
                        "target": service,
                    }
                })
            }
            Self::ViewEvidenceLog { limit } => serde_json::json!({ "limit": limit }),
            Self::RequestLanExposure {
                approver_canonical_id,
            } => {
                Self::require_non_empty("approver_canonical_id", approver_canonical_id)?;
                serde_json::json!({
                    "proposed_action": {
                        "verb": "web.exposure.lan.request",
                        "approver_canonical_id": approver_canonical_id,
                    }
                })
            }
        };

        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| ControlCenterError::InvalidAction(format!("payload encode: {e}")))?;

        Ok(RoutedRequest {
            service_fqn: self.target_service().to_string(),
            method: self.method().to_string(),
            payload: bytes,
            mutating: self.is_mutating(),
        })
    }

    fn require_non_empty(field: &str, value: &str) -> Result<(), ControlCenterError> {
        if value.trim().is_empty() {
            return Err(ControlCenterError::InvalidAction(format!(
                "field `{field}` must not be empty"
            )));
        }
        Ok(())
    }
}

/// A typed request derived from a [`ControlAction`], ready for the gRPC-Web
/// bridge gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedRequest {
    /// Fully-qualified backend service name (must be in the bridge allowlist).
    pub service_fqn: String,
    /// gRPC method name on that service.
    pub method: String,
    /// Canonical JSON payload bytes.
    pub payload: Vec<u8>,
    /// Whether this request mutates state (routed via the Policy Kernel).
    pub mutating: bool,
}

/// The outcome of [`ControlCenter::submit_action`].
///
/// There is deliberately **no** `Executed` variant: the panel never executes.
/// Mutating actions terminate at [`ActionOutcome::PolicyPending`] until a
/// decision arrives out-of-band.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionOutcome {
    /// A read-only action passed the bridge gate; `payload` is the response
    /// (echoed by the stub today — see the `CONTRACT` note on the backend hop).
    Data {
        /// The service that answered.
        service_fqn: String,
        /// The response payload bytes.
        payload: Vec<u8>,
    },
    /// A mutating action was accepted and its typed proposal was routed to the
    /// Policy Kernel. It awaits a decision id before any effect. The panel does
    /// **not** proceed on its own.
    PolicyPending {
        /// The proposal that was routed for a decision.
        routed: RoutedRequest,
    },
}

// ---------------------------------------------------------------------------
// ControlCenter
// ---------------------------------------------------------------------------

/// The L7 Control Center application.
///
/// Composes the reused L7 transport pieces: a gRPC-Web client over the bridge,
/// the exposure FSM, and an evidence emitter. It exposes exactly the typed
/// [`ControlAction`] surface and enforces the propose-decide-execute law.
pub struct ControlCenter<T: ControlTransport = StubTransport> {
    config: ControlCenterConfig,
    transport: T,
    exposure: ExposureFsm,
    evidence: Arc<InMemoryWebEvidenceEmitter>,
}

impl ControlCenter<StubTransport> {
    /// Build a Control Center from a config, wiring the reused L7 transport
    /// (bridge with the default localhost allowlists, wrapped in
    /// [`StubTransport`]) and a fresh evidence chain.
    ///
    /// Use [`ControlCenter::with_transport`] to construct the panel over the
    /// real [`RealGrpcTransport`] instead of the echo stub.
    #[must_use]
    pub fn new(config: ControlCenterConfig) -> Self {
        let bridge = GrpcWebBridge::new(GrpcWebBridge::default_localhost_config());
        let transport = StubTransport::new(GrpcWebClientStub::new(bridge));
        Self::with_transport(config, transport)
    }

    /// Build a Control Center with the default (localhost-only) config over the
    /// echo [`StubTransport`].
    #[must_use]
    pub fn new_localhost() -> Self {
        Self::new(ControlCenterConfig::default())
    }
}

impl<T: ControlTransport + Sync> ControlCenter<T> {
    /// Build a Control Center from a config over an explicit
    /// [`ControlTransport`] (e.g. the real [`RealGrpcTransport`]).
    ///
    /// The no-execute law is transport-independent: whatever the transport,
    /// mutating actions terminate at [`ActionOutcome::PolicyPending`] and there
    /// is no `Executed` outcome.
    #[must_use]
    pub fn with_transport(config: ControlCenterConfig, transport: T) -> Self {
        let evidence = Arc::new(InMemoryWebEvidenceEmitter::new(
            config.evidence_subject.clone(),
        ));
        Self {
            config,
            transport,
            exposure: ExposureFsm::new(),
            evidence,
        }
    }

    /// The active config.
    #[must_use]
    pub const fn config(&self) -> &ControlCenterConfig {
        &self.config
    }

    /// The current exposure level of the panel.
    pub async fn exposure_level(&self) -> ExposureLevel {
        self.exposure.current().await
    }

    /// Number of evidence receipts emitted so far (test/inspection seam).
    pub async fn evidence_count(&self) -> usize {
        self.evidence.receipt_count().await
    }

    /// Submit a typed operator action.
    ///
    /// Read-only actions are routed through the **real** gRPC-Web bridge gate
    /// (origin allowlist + service allowlist + size ceiling) and their response
    /// returned. Mutating actions route their **typed proposal** to the Policy
    /// Kernel and stop at [`ActionOutcome::PolicyPending`] — the panel never
    /// executes. For [`ControlAction::RequestLanExposure`] the exposure FSM is
    /// additionally advanced to `LanPending`.
    ///
    /// # Errors
    ///
    /// * [`ControlCenterError::InvalidAction`] — malformed action.
    /// * [`ControlCenterError::Renderer`] — the bridge gate rejected the request
    ///   (origin/service/size) or an exposure transition was denied.
    pub async fn submit_action(
        &self,
        action: &ControlAction,
    ) -> Result<ActionOutcome, ControlCenterError> {
        let routed = action.route()?;

        // Every request — read-only or mutating proposal — passes the reused
        // bridge gate first. For mutating actions this routes the typed proposal
        // to `aios.policy.PolicyKernel`.
        //
        // CONTRACT: `GrpcWebClientStub::send` validates the gate and echoes the
        // payload; it does NOT yet reach a live backend. A real deployment wires
        // the bridge to a tonic `Channel` so that:
        //   - read-only actions reach SgrService / EvidenceLog and return real
        //     data, and
        //   - mutating proposals reach PolicyKernel.EvaluatePolicy, whose
        //     `PolicyDecision` (Allow / RequireApproval / Deny) gates the domain
        //     effect, which the Capability Runtime then executes and evidences.
        // No execution is simulated here.
        let response = self
            .transport
            .send(
                &self.config.origin,
                &routed.service_fqn,
                &routed.method,
                routed.payload.clone(),
            )
            .await?;

        if !action.is_mutating() {
            return Ok(ActionOutcome::Data {
                service_fqn: routed.service_fqn.clone(),
                payload: response,
            });
        }

        // Mutating: advance any local FSM that models the proposal, then stop.
        if let ControlAction::RequestLanExposure {
            approver_canonical_id,
        } = action
        {
            self.exposure
                .request_lan_escalation(approver_canonical_id)
                .await?;
        }

        Ok(ActionOutcome::PolicyPending { routed })
    }

    /// Apply a Policy Kernel decision authorizing LAN exposure
    /// (`LanPending → LanApproved`) and emit the mandatory
    /// `WEB_EXPOSURE_GRANTED` evidence receipt.
    ///
    /// This is the concrete embodiment of the law: exposure widens **only** with
    /// a policy decision id in hand, and the widening is evidenced.
    ///
    /// # Errors
    ///
    /// * [`ControlCenterError::MissingDecisionId`] — `decision_id` is empty.
    /// * [`ControlCenterError::Renderer`] — the FSM is not in `LanPending`, or
    ///   evidence emission failed.
    pub async fn apply_lan_exposure_decision(
        &self,
        decision_id: &str,
    ) -> Result<WebEvidenceReceipt, ControlCenterError> {
        if decision_id.trim().is_empty() {
            return Err(ControlCenterError::MissingDecisionId(
                "LAN exposure escalation requires a policy decision id".to_string(),
            ));
        }

        self.exposure.apply_policy_decision(decision_id).await?;
        let level = self.exposure.current().await;
        let receipt = self
            .evidence
            .emit_exposure_granted(&level, decision_id)
            .await?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test-double transport that *succeeds* (echoes the payload) without any
    /// network. It stands in for "a real transport that connected", letting us
    /// prove the no-execute guarantee holds for a **successful** transport, not
    /// only for the failing/echo cases — i.e. the guarantee is transport-
    /// independent, a property of [`ControlCenter::submit_action`]'s control
    /// flow, not of any one transport.
    struct RecordingTransport;

    impl ControlTransport for RecordingTransport {
        #[allow(
            clippy::unused_async,
            reason = "implements the async ControlTransport contract; the double \
                      resolves synchronously"
        )]
        async fn send(
            &self,
            _origin: &str,
            _service: &str,
            _method: &str,
            payload: Vec<u8>,
        ) -> Result<Vec<u8>, ControlCenterError> {
            Ok(payload)
        }
    }

    #[tokio::test]
    async fn no_execute_guarantee_holds_for_a_successful_transport(
    ) -> Result<(), ControlCenterError> {
        // Even when the transport SUCCEEDS, a mutating action terminates at
        // PolicyPending — there is no Executed outcome. Transport-independent.
        let cc = ControlCenter::with_transport(ControlCenterConfig::default(), RecordingTransport);
        let outcome = cc
            .submit_action(&ControlAction::RequestServiceRestart {
                service: "aios-fs".to_string(),
            })
            .await?;
        assert!(matches!(outcome, ActionOutcome::PolicyPending { .. }));
        Ok(())
    }

    #[tokio::test]
    async fn real_transport_never_yields_a_data_outcome_for_mutating() {
        // Wired to the REAL transport, a mutating action must never surface as
        // executed/Data — worst case it errors at the named CONTRACT boundary.
        let cc = ControlCenter::with_transport(
            ControlCenterConfig::default(),
            RealGrpcTransport::localhost_default(),
        );
        let result = cc
            .submit_action(&ControlAction::RequestServiceRestart {
                service: "aios-fs".to_string(),
            })
            .await;
        assert!(!matches!(result, Ok(ActionOutcome::Data { .. })));
        assert!(matches!(
            result,
            Err(ControlCenterError::TransportContract(_)) | Ok(ActionOutcome::PolicyPending { .. })
        ));
    }

    #[test]
    fn stylesheet_carries_aios_color_tokens_for_both_themes() {
        let sheet = control_center_stylesheet();
        // Both theme blocks are present.
        assert!(sheet.contains(":root {"));
        assert!(sheet.contains(r#":root[data-theme="dark"]"#));
        // The design-token color custom properties are present.
        assert!(sheet.contains("--aios-color-"));

        // Single-theme variants also carry the color tokens.
        let light = control_center_stylesheet_for(false);
        let dark = control_center_stylesheet_for(true);
        assert!(light.contains("--aios-color-"));
        assert!(dark.contains("--aios-color-"));
        // Light and dark differ (theming is real, not a copy).
        assert_ne!(light, dark);
    }

    #[test]
    fn config_defaults_to_localhost() {
        let cfg = ControlCenterConfig::default();
        assert!(cfg.is_localhost_only());
        assert_eq!(cfg.exposure.label().to_string(), "Localhost");
        assert_eq!(cfg.origin, "https://aios.localhost");
    }

    #[test]
    fn view_service_health_routes_to_sgr_and_is_read_only() -> Result<(), ControlCenterError> {
        let action = ControlAction::ViewServiceHealth {
            service: "aios-fs".to_string(),
        };
        assert!(!action.is_mutating());
        let routed = action.route()?;
        assert_eq!(routed.service_fqn, "aios.sgr.SgrService");
        assert_eq!(routed.method, "GetServiceHealth");
        assert!(!routed.mutating);
        Ok(())
    }

    #[test]
    fn restart_is_mutating_and_targets_policy_kernel() -> Result<(), ControlCenterError> {
        let action = ControlAction::RequestServiceRestart {
            service: "aios-fs".to_string(),
        };
        assert!(action.is_mutating());
        let routed = action.route()?;
        // A mutating action is submitted to the Policy Kernel, never executed.
        assert_eq!(routed.service_fqn, "aios.policy.PolicyKernel");
        assert_eq!(routed.method, "EvaluatePolicy");
        assert!(routed.mutating);
        Ok(())
    }

    #[test]
    fn empty_field_is_rejected() {
        let action = ControlAction::RequestServiceRestart {
            service: "   ".to_string(),
        };
        assert!(matches!(
            action.route(),
            Err(ControlCenterError::InvalidAction(_))
        ));
    }

    #[tokio::test]
    async fn read_only_action_passes_bridge_gate_and_returns_data() -> Result<(), ControlCenterError>
    {
        let cc = ControlCenter::new_localhost();
        let outcome = cc
            .submit_action(&ControlAction::ViewEvidenceLog { limit: 10 })
            .await?;
        assert!(matches!(
            outcome,
            ActionOutcome::Data { ref service_fqn, .. }
                if service_fqn == "aios.evidence.EvidenceLog"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn mutating_action_stops_at_policy_pending_no_execution() -> Result<(), ControlCenterError>
    {
        let cc = ControlCenter::new_localhost();
        let outcome = cc
            .submit_action(&ControlAction::RequestServiceRestart {
                service: "aios-fs".to_string(),
            })
            .await?;
        assert!(matches!(outcome, ActionOutcome::PolicyPending { .. }));
        Ok(())
    }

    #[tokio::test]
    async fn lan_exposure_escalation_requires_a_decision_id() -> Result<(), ControlCenterError> {
        let cc = ControlCenter::new_localhost();

        // Default: localhost only, no evidence yet.
        assert_eq!(cc.exposure_level().await.label().to_string(), "Localhost");
        assert_eq!(cc.evidence_count().await, 0);

        // Propose LAN exposure → FSM advances to LanPending, still no widening.
        cc.submit_action(&ControlAction::RequestLanExposure {
            approver_canonical_id: "subject:operator".to_string(),
        })
        .await?;
        assert_eq!(cc.exposure_level().await.label().to_string(), "LanPending");

        // Escalating WITHOUT a decision id is refused.
        assert!(matches!(
            cc.apply_lan_exposure_decision("").await,
            Err(ControlCenterError::MissingDecisionId(_))
        ));

        // With a decision id: escalation succeeds and is evidenced.
        let receipt = cc
            .apply_lan_exposure_decision("poldec_01TESTDECISION")
            .await?;
        assert!(receipt.record_id.starts_with("evr_"));
        assert_eq!(cc.exposure_level().await.label().to_string(), "LanApproved");
        assert_eq!(cc.evidence_count().await, 1);
        Ok(())
    }
}
