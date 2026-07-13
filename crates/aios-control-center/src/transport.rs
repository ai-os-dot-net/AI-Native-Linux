//! Transport seam for the Control Center.
//!
//! The Control Center submits every typed [`crate::ControlAction`] through a
//! [`ControlTransport`]. Two implementations exist:
//!
//! * [`StubTransport`] — wraps the reused [`aios_renderer_web::GrpcWebClientStub`]
//!   echo stub. It validates the gRPC-Web **bridge gate** (origin allowlist +
//!   service allowlist + size ceiling) and echoes the payload back. This is the
//!   default the panel is constructed with and the one exercised by the
//!   scaffold's unit tests — it needs no live backend.
//! * [`RealGrpcTransport`] — a **real** `tonic::transport::Channel`-backed
//!   client. It constructs configured `tonic` [`Endpoint`]s (localhost default,
//!   connect + request timeouts) and the **real** tonic client stubs exported by
//!   the backend crates:
//!   [`aios_policy::service::PolicyKernelClient`],
//!   [`aios_sgr::service::SgrServiceClient`], and
//!   [`aios_evidence::service::EvidenceLogClient`]. The transport layer
//!   (endpoint build + channel + typed-client construction) is REAL and
//!   unit-tested offline via `connect_lazy`. The **only** remaining seam is the
//!   final typed method-dispatch: turning the abstract
//!   `(service, method, JSON payload)` triple into a concrete typed proto
//!   request. That step is a narrowly-scoped `CONTRACT` (see
//!   [`RealGrpcTransport::send`]) because:
//!     * `aios.sgr.SgrService` exposes **no** `GetServiceHealth` RPC (the health
//!       read maps to `aios.sgr.v1alpha1.SgrService/GetUnit` +
//!       `GetGraphState`), and `aios.evidence.EvidenceLog` exposes **no**
//!       `TailReceipts` RPC (the tail maps to
//!       `aios.evidence.v1alpha1.EvidenceLog/Query`); and
//!     * `aios.policy.v1alpha1.PolicyKernel/EvaluatePolicy` **does** exist, but
//!       its `EvaluatePolicyRequest.envelope_proto` requires an
//!       `aios_action::ActionEnvelope` transcode of the JSON proposal, which is
//!       a deployment-time concern, not this crate's.
//!
//! No execution is ever simulated: the CONTRACT seam returns a typed error, it
//! never fabricates a backend response.

use std::future::Future;
use std::time::Duration;

use tonic::transport::{Channel, Endpoint};

use aios_evidence::service::EvidenceLogClient;
use aios_policy::service::PolicyKernelClient;
use aios_renderer_web::GrpcWebClientStub;
use aios_sgr::service::SgrServiceClient;

use crate::ControlCenterError;

/// The abstract transport a [`crate::ControlCenter`] routes requests through.
///
/// Implementors receive the already-gated `(origin, service, method, payload)`
/// tuple derived from a typed [`crate::ControlAction`] and return the response
/// bytes. The trait is intentionally minimal so the same [`crate::ControlCenter`]
/// control-flow (and its no-execute guarantee) holds regardless of whether the
/// transport is the echo [`StubTransport`] or the [`RealGrpcTransport`].
pub trait ControlTransport {
    /// Send a gated request and return the response payload bytes.
    ///
    /// # Errors
    ///
    /// Implementation-specific: a bridge-gate rejection, an endpoint/connect
    /// failure, or the [`RealGrpcTransport`] CONTRACT boundary.
    fn send(
        &self,
        origin: &str,
        service: &str,
        method: &str,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, ControlCenterError>> + Send;
}

// ---------------------------------------------------------------------------
// StubTransport — the reused echo stub (default)
// ---------------------------------------------------------------------------

/// [`ControlTransport`] over the reused [`GrpcWebClientStub`] echo stub.
///
/// Validates every request through the real gRPC-Web bridge gate and echoes the
/// payload. This is the default transport the panel is constructed with; it
/// requires no live backend and backs the scaffold's unit tests.
#[derive(Debug, Clone)]
pub struct StubTransport {
    stub: GrpcWebClientStub,
}

impl StubTransport {
    /// Wrap a [`GrpcWebClientStub`] as a [`ControlTransport`].
    #[must_use]
    pub const fn new(stub: GrpcWebClientStub) -> Self {
        Self { stub }
    }
}

impl ControlTransport for StubTransport {
    async fn send(
        &self,
        origin: &str,
        service: &str,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, ControlCenterError> {
        self.stub
            .send(origin, service, method, payload)
            .await
            .map_err(ControlCenterError::from)
    }
}

// ---------------------------------------------------------------------------
// RealGrpcTransport — real tonic Channel-backed transport
// ---------------------------------------------------------------------------

/// The backend gRPC endpoints the Control Center's typed actions target.
///
/// Defaults ([`BackendEndpoints::localhost_default`]) mirror the workspace's
/// canonical loopback ports (see `aios-renderer-cli`'s `AiosEndpoints`): policy
/// `50051`, evidence `50055`, sgr `50058`. All three default to the IPv6
/// loopback `[::1]` — the panel is localhost-only by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendEndpoints {
    /// `aios.policy.PolicyKernel` gRPC endpoint.
    pub policy: String,
    /// `aios.sgr.SgrService` gRPC endpoint.
    pub sgr: String,
    /// `aios.evidence.EvidenceLog` gRPC endpoint.
    pub evidence: String,
}

impl BackendEndpoints {
    /// Canonical loopback endpoints (IPv6 `[::1]`), matching the workspace's
    /// `AiosEndpoints::localhost_default` port assignment.
    #[must_use]
    pub fn localhost_default() -> Self {
        Self {
            policy: "http://[::1]:50051".to_owned(),
            sgr: "http://[::1]:50058".to_owned(),
            evidence: "http://[::1]:50055".to_owned(),
        }
    }

    /// Return `true` iff every endpoint binds to loopback (`[::1]`,
    /// `127.0.0.1`, or `localhost`).
    #[must_use]
    pub fn is_localhost_only(&self) -> bool {
        [&self.policy, &self.sgr, &self.evidence]
            .into_iter()
            .all(|url| is_loopback(url))
    }
}

impl Default for BackendEndpoints {
    fn default() -> Self {
        Self::localhost_default()
    }
}

fn is_loopback(url: &str) -> bool {
    url.starts_with("http://[::1]")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
}

/// Real tonic-`Channel`-backed backend clients, constructed from a
/// [`RealGrpcTransport`].
///
/// Holding these proves the backend crates' tonic client stubs are importable
/// and constructible from a real [`Channel`]. The channels are created lazily
/// (`connect_lazy`) so this struct can be built offline; the TCP connection is
/// established on first RPC.
#[derive(Debug, Clone)]
pub struct BackendClients {
    /// Real `aios.policy.v1alpha1.PolicyKernel` client.
    pub policy: PolicyKernelClient<Channel>,
    /// Real `aios.sgr.v1alpha1.SgrService` client.
    pub sgr: SgrServiceClient<Channel>,
    /// Real `aios.evidence.v1alpha1.EvidenceLog` client.
    pub evidence: EvidenceLogClient<Channel>,
}

/// A real `tonic::transport::Channel`-backed [`ControlTransport`].
///
/// The transport layer — endpoint construction (with connect + request
/// timeouts) and typed-client wiring — is REAL. See the module docs for the
/// single remaining CONTRACT: the final typed method-dispatch.
#[derive(Debug, Clone)]
pub struct RealGrpcTransport {
    endpoints: BackendEndpoints,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl RealGrpcTransport {
    /// Default connect timeout applied to every backend endpoint.
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    /// Default per-request timeout applied to every backend endpoint.
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

    /// Build a real transport targeting the loopback backend endpoints with the
    /// default timeouts.
    #[must_use]
    pub fn localhost_default() -> Self {
        Self::new(
            BackendEndpoints::localhost_default(),
            Self::DEFAULT_CONNECT_TIMEOUT,
            Self::DEFAULT_REQUEST_TIMEOUT,
        )
    }

    /// Build a real transport from explicit endpoints and timeouts.
    #[must_use]
    pub const fn new(
        endpoints: BackendEndpoints,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Self {
        Self {
            endpoints,
            connect_timeout,
            request_timeout,
        }
    }

    /// The configured backend endpoints.
    #[must_use]
    pub const fn endpoints(&self) -> &BackendEndpoints {
        &self.endpoints
    }

    /// Build a configured tonic [`Endpoint`] for a URL (connect + request
    /// timeouts applied). This is real tonic transport construction and does
    /// not open a connection.
    ///
    /// # Errors
    ///
    /// [`ControlCenterError::Transport`] if the URL is not a valid tonic
    /// endpoint.
    pub fn endpoint(&self, url: &str) -> Result<Endpoint, ControlCenterError> {
        Endpoint::from_shared(url.to_owned())
            .map(|ep| {
                ep.connect_timeout(self.connect_timeout)
                    .timeout(self.request_timeout)
            })
            .map_err(|e| ControlCenterError::Transport(format!("invalid endpoint `{url}`: {e}")))
    }

    /// Construct the real backend tonic clients over lazily-connected channels.
    ///
    /// Proves the backend crates' client stubs are importable and constructible
    /// from a real [`Channel`]. Buildable offline (`connect_lazy`); the TCP
    /// connection is established on the first RPC.
    ///
    /// # Errors
    ///
    /// [`ControlCenterError::Transport`] if any endpoint URL is invalid.
    pub fn connect_clients(&self) -> Result<BackendClients, ControlCenterError> {
        let policy = self.endpoint(&self.endpoints.policy)?.connect_lazy();
        let sgr = self.endpoint(&self.endpoints.sgr)?.connect_lazy();
        let evidence = self.endpoint(&self.endpoints.evidence)?.connect_lazy();
        Ok(BackendClients {
            policy: PolicyKernelClient::new(policy),
            sgr: SgrServiceClient::new(sgr),
            evidence: EvidenceLogClient::new(evidence),
        })
    }

    /// Resolve a fully-qualified service name to its configured endpoint URL and
    /// the concrete proto path the typed dispatch will target.
    fn resolve(&self, service: &str) -> Result<(&str, &'static str), ControlCenterError> {
        match service {
            "aios.policy.PolicyKernel" => {
                Ok((&self.endpoints.policy, "aios.policy.v1alpha1.PolicyKernel"))
            }
            "aios.sgr.SgrService" => Ok((&self.endpoints.sgr, "aios.sgr.v1alpha1.SgrService")),
            "aios.evidence.EvidenceLog" => Ok((
                &self.endpoints.evidence,
                "aios.evidence.v1alpha1.EvidenceLog",
            )),
            other => Err(ControlCenterError::Transport(format!(
                "no backend endpoint for service `{other}`"
            ))),
        }
    }
}

impl ControlTransport for RealGrpcTransport {
    /// Real transport dispatch.
    ///
    /// Resolves the target endpoint and builds a **real** tonic [`Endpoint`]
    /// (proving the transport layer), then stops at the single documented
    /// CONTRACT boundary: the abstract `method` cannot be dispatched to a
    /// concrete typed proto RPC without a typed-request transcode. The returned
    /// [`ControlCenterError::TransportContract`] names the exact proto path.
    /// **No backend response is fabricated.**
    #[allow(
        clippy::unused_async,
        reason = "the ControlTransport contract is async; this impl reaches its \
                  CONTRACT boundary before the (async) RPC would be issued"
    )]
    async fn send(
        &self,
        _origin: &str,
        service: &str,
        method: &str,
        _payload: Vec<u8>,
    ) -> Result<Vec<u8>, ControlCenterError> {
        let (url, proto_path) = self.resolve(service)?;
        // REAL: build a configured tonic endpoint for the target service.
        // (Errors here are genuine endpoint-construction failures.)
        let _endpoint = self.endpoint(url)?;

        // CONTRACT: the endpoint/channel and the typed client stubs
        // (`PolicyKernelClient` / `SgrServiceClient` / `EvidenceLogClient`, see
        // `connect_clients`) are real and importable. The remaining deployment
        // task is transcoding the abstract JSON payload into the concrete typed
        // proto request for `{proto_path}` and issuing the RPC. In particular:
        //   - `aios.sgr.SgrService` has NO `GetServiceHealth` RPC — the health
        //     read maps to `GetUnit` + `GetGraphState`;
        //   - `aios.evidence.EvidenceLog` has NO `TailReceipts` RPC — the tail
        //     maps to `Query`;
        //   - `aios.policy.v1alpha1.PolicyKernel/EvaluatePolicy` exists but
        //     `EvaluatePolicyRequest.envelope_proto` needs an
        //     `aios_action::ActionEnvelope` transcode.
        // No execution is simulated: we return a typed error, never a faked
        // response.
        Err(ControlCenterError::TransportContract(format!(
            "real endpoint built for `{service}`; typed dispatch of method \
             `{method}` to `{proto_path}` requires a JSON→proto request \
             transcode (deployment task)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_default_to_localhost() {
        let ep = BackendEndpoints::localhost_default();
        assert!(ep.is_localhost_only());
        assert!(ep.policy.starts_with("http://[::1]:"));
        assert!(ep.sgr.starts_with("http://[::1]:"));
        assert!(ep.evidence.starts_with("http://[::1]:"));
    }

    #[test]
    fn non_loopback_endpoints_are_not_localhost_only() {
        let ep = BackendEndpoints {
            policy: "http://192.168.1.180:50051".to_owned(),
            sgr: "http://[::1]:50058".to_owned(),
            evidence: "http://[::1]:50055".to_owned(),
        };
        assert!(!ep.is_localhost_only());
    }

    #[test]
    fn real_transport_builds_valid_endpoints() -> Result<(), ControlCenterError> {
        let t = RealGrpcTransport::localhost_default();
        // Real tonic Endpoint construction for each backend service.
        t.endpoint(&t.endpoints().policy)?;
        t.endpoint(&t.endpoints().sgr)?;
        t.endpoint(&t.endpoints().evidence)?;
        Ok(())
    }

    #[test]
    fn real_transport_rejects_invalid_endpoint() {
        let t = RealGrpcTransport::new(
            BackendEndpoints {
                policy: "not a url".to_owned(),
                sgr: "http://[::1]:50058".to_owned(),
                evidence: "http://[::1]:50055".to_owned(),
            },
            RealGrpcTransport::DEFAULT_CONNECT_TIMEOUT,
            RealGrpcTransport::DEFAULT_REQUEST_TIMEOUT,
        );
        assert!(matches!(
            t.endpoint(&t.endpoints().policy),
            Err(ControlCenterError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn real_transport_constructs_real_backend_clients() -> Result<(), ControlCenterError> {
        // Proves the backend tonic client stubs are importable and constructible
        // from a real Channel (via connect_lazy — needs a Tokio reactor, no
        // server: the TCP connection is deferred to the first RPC).
        let clients = RealGrpcTransport::localhost_default().connect_clients()?;
        // Bind each real client so the types are load-bearing, not just imported.
        let _policy: &PolicyKernelClient<Channel> = &clients.policy;
        let _sgr: &SgrServiceClient<Channel> = &clients.sgr;
        let _evidence: &EvidenceLogClient<Channel> = &clients.evidence;
        Ok(())
    }

    #[tokio::test]
    async fn real_transport_send_stops_at_named_contract_no_fabrication() {
        let t = RealGrpcTransport::localhost_default();
        let result = t
            .send(
                "https://aios.localhost",
                "aios.policy.PolicyKernel",
                "EvaluatePolicy",
                b"{}".to_vec(),
            )
            .await;
        // Real transport must NOT fabricate a backend response: it stops at the
        // named CONTRACT boundary, and the message names the exact proto path.
        assert!(matches!(
            result,
            Err(ControlCenterError::TransportContract(ref msg))
                if msg.contains("aios.policy.v1alpha1.PolicyKernel")
        ));
    }
}
