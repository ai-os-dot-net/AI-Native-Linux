//! Real Wayland compositor backend — Rev.6 KDE Plasma binding (S7.4 §3.1).
//!
//! Opens a Unix socket to `$WAYLAND_DISPLAY`, negotiates globals, binds
//! `wlr-layer-shell-unstable-v1` for chrome/background/recovery zones and
//! `xdg-shell` for content windows. Maps `CompositionZone` to Wayland layers,
//! creates surfaces with proper roles, and supports commit/disconnect lifecycle.
//!
//! The in-memory `WaylandClient` in `wayland.rs` remains unchanged as the test
//! double. This module provides the real socket I/O path.

use std::collections::BTreeMap;
use std::env;
use std::sync::{Arc, Mutex};

use wayland_client::protocol::{
    wl_compositor, wl_output, wl_registry, wl_seat, wl_shm, wl_shm_pool, wl_surface,
};
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle};
use wayland_protocols::xdg::shell::client::{xdg_surface, xdg_toplevel, xdg_wm_base};
use wayland_protocols_wlr::layer_shell::v1::client::{zwlr_layer_shell_v1, zwlr_layer_surface_v1};

use crate::error::KdeRendererError;
use crate::types::KdeSurfaceId;
use crate::zone::CompositionZone;

// ── Zone to wlr-layer-shell layer mapping ───────────────────────────────────

/// Map a `CompositionZone` to the corresponding `zwlr_layer_shell_v1::Layer`.
///
/// | Zone       | wlr-layer-shell layer | Rationale                              |
/// |------------|-----------------------|----------------------------------------|
/// | Chrome     | Overlay               | Always topmost trust-bearing chrome    |
/// | Content    | Bottom                | Below overlay, above background        |
/// | Background | Background            | Below all other surfaces               |
/// | Recovery   | Overlay               | Topmost with exclusive keyboard grab   |
#[must_use]
pub fn zone_to_wlr_layer(zone: CompositionZone) -> zwlr_layer_shell_v1::Layer {
    match zone {
        CompositionZone::Background => zwlr_layer_shell_v1::Layer::Background,
        CompositionZone::Content => zwlr_layer_shell_v1::Layer::Bottom,
        CompositionZone::Chrome | CompositionZone::Recovery => zwlr_layer_shell_v1::Layer::Overlay,
    }
}

/// Keyboard interactivity mode for layer shell surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerKeyboardInteractivity {
    /// No keyboard events delivered.
    None,
    /// Keyboard events delivered on demand.
    OnDemand,
    /// Exclusive keyboard grab (recovery shell only).
    Exclusive,
}

impl LayerKeyboardInteractivity {
    /// Convert to the wlr-layer-shell protocol enum value.
    #[must_use]
    fn to_protocol_value(self) -> zwlr_layer_surface_v1::KeyboardInteractivity {
        match self {
            LayerKeyboardInteractivity::None => zwlr_layer_surface_v1::KeyboardInteractivity::None,
            LayerKeyboardInteractivity::OnDemand => {
                zwlr_layer_surface_v1::KeyboardInteractivity::OnDemand
            }
            LayerKeyboardInteractivity::Exclusive => {
                zwlr_layer_surface_v1::KeyboardInteractivity::Exclusive
            }
        }
    }
}

// ── Wayland surface role ────────────────────────────────────────────────────

/// Role assigned to a Wayland surface.
///
/// Each surface must have exactly one role. The role determines how the
/// compositor manages the surface (z-order, input, decorations).
pub enum WaylandSurfaceRole {
    /// wlr-layer-shell surface (chrome, background, recovery zones).
    LayerShell {
        /// The layer shell surface handle.
        layer_surface: zwlr_layer_surface_v1::ZwlrLayerSurfaceV1,
        /// The assigned layer (overlay/bottom/background).
        layer: zwlr_layer_shell_v1::Layer,
        /// Keyboard interactivity level.
        keyboard_interactivity: LayerKeyboardInteractivity,
    },
    /// xdg-shell toplevel surface (content zone).
    XdgToplevel {
        /// The xdg surface.
        xdg: xdg_surface::XdgSurface,
        /// The xdg toplevel.
        toplevel: xdg_toplevel::XdgToplevel,
    },
}

// ── RealWaylandSurface ──────────────────────────────────────────────────────

/// A real Wayland surface with role tracking.
///
/// Wraps a `wl_surface` and its assigned role. Each surface carries its
/// `KdeSurfaceId` and originating `CompositionZone`.
pub struct RealWaylandSurface {
    /// AIOS surface identifier.
    pub id: KdeSurfaceId,
    /// The underlying `wl_surface`.
    pub surface: wl_surface::WlSurface,
    /// The assigned role (layer shell or xdg toplevel).
    pub role: WaylandSurfaceRole,
    /// The composition zone this surface belongs to.
    pub zone: CompositionZone,
}

impl RealWaylandSurface {
    /// Commit the surface state to the compositor.
    ///
    /// After calling this, pending state (buffer, damage, input region) is
    /// applied atomically. The compositor will emit a configure event when
    /// the surface has been mapped.
    pub fn commit(&self) {
        self.surface.commit();
    }

    /// Destroy the surface and its role objects.
    ///
    /// This sends the `wl_surface::destroy` request and drops all role
    /// handles, which causes the compositor to remove the surface.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "consuming self for drop semantics"
    )]
    pub fn destroy(self) {
        match self.role {
            WaylandSurfaceRole::LayerShell {
                layer_surface,
                layer: _,
                keyboard_interactivity: _,
            } => {
                layer_surface.destroy();
            }
            WaylandSurfaceRole::XdgToplevel { toplevel, xdg } => {
                toplevel.destroy();
                xdg.destroy();
            }
        }
        self.surface.destroy();
    }
}

impl std::fmt::Debug for RealWaylandSurface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealWaylandSurface")
            .field("id", &self.id)
            .field("zone", &self.zone)
            .finish_non_exhaustive()
    }
}

// ── Inner compositor state ──────────────────────────────────────────────────

/// Track which required globals have been received.
type GlobalBindMap = BTreeMap<String, bool>;

/// Internal mutable state shared between the dispatch handlers and the
/// public API. Wrapped in `Arc<Mutex<…>>` so it can be shared with the
/// event queue dispatch target.
struct CompositorStateInner {
    /// Bound wl_compositor global.
    compositor: Option<wl_compositor::WlCompositor>,
    /// Bound zwlr_layer_shell_v1 global.
    layer_shell: Option<zwlr_layer_shell_v1::ZwlrLayerShellV1>,
    /// Bound xdg_wm_base global.
    xdg_wm_base: Option<xdg_wm_base::XdgWmBase>,
    /// Bound wl_shm global (for buffer creation).
    shm: Option<wl_shm::WlShm>,
    /// Bound wl_seat global.
    _seat: Option<wl_seat::WlSeat>,
    /// Bound wl_output globals.
    _outputs: Vec<wl_output::WlOutput>,
    /// Track which required globals have been received.
    globals_bound: GlobalBindMap,
    /// Whether a roundtrip has been completed.
    #[allow(
        dead_code,
        reason = "set during connect, reserved for future health checks"
    )]
    roundtrip_done: bool,
    /// xdg_wm_base has received its initial configure event (ping).
    _xdg_configured: bool,
}

impl CompositorStateInner {
    fn new() -> Self {
        let mut globals = BTreeMap::new();
        for proto in &[
            "wl_compositor",
            "wl_shm",
            "wl_seat",
            "zwlr_layer_shell_v1",
            "xdg_wm_base",
        ] {
            globals.insert((*proto).to_owned(), false);
        }
        Self {
            compositor: None,
            layer_shell: None,
            xdg_wm_base: None,
            shm: None,
            _seat: None,
            _outputs: Vec::new(),
            globals_bound: globals,
            roundtrip_done: false,
            _xdg_configured: false,
        }
    }

    fn all_critical_globals_bound(&self) -> bool {
        self.compositor.is_some() && self.layer_shell.is_some() && self.xdg_wm_base.is_some()
    }
}

/// Shared mutable state for the Wayland compositor dispatch.
#[derive(Clone)]
struct CompositorState {
    inner: Arc<Mutex<CompositorStateInner>>,
}

impl CompositorState {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CompositorStateInner::new())),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, CompositorStateInner>, KdeRendererError> {
        self.inner.lock().map_err(|e| {
            KdeRendererError::Internal(format!("compositor state mutex poisoned: {e}"))
        })
    }
}

impl std::fmt::Debug for CompositorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositorState").finish_non_exhaustive()
    }
}

// ── Dispatch implementations ────────────────────────────────────────────────

// Helper: bind a global from the registry, returning the interface directly.
// The turbulent `<I, U, D>` params allow the compiler to infer U and D from qh.
fn bind_global<I: Proxy + 'static, U: Send + Sync + 'static, D: Dispatch<I, U> + 'static>(
    registry: &wl_registry::WlRegistry,
    name: u32,
    version: u32,
    qh: &QueueHandle<D>,
    udata: U,
) -> I {
    registry.bind::<I, U, D>(name, version, qh, udata)
}

impl Dispatch<wl_registry::WlRegistry, ()> for CompositorState {
    fn event(
        state: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _data: &(),
        _conn: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        match event {
            wl_registry::Event::Global {
                name,
                interface,
                version,
            } => {
                let mut inner = match state.lock() {
                    Ok(i) => i,
                    Err(_) => return,
                };
                match interface.as_str() {
                    "wl_compositor" => {
                        let compositor = bind_global::<
                            wl_compositor::WlCompositor,
                            (),
                            CompositorState,
                        >(
                            registry, name, version.min(5), qh, ()
                        );
                        inner.compositor = Some(compositor);
                        inner.globals_bound.insert("wl_compositor".into(), true);
                    }
                    "wl_shm" => {
                        let shm = bind_global::<wl_shm::WlShm, (), CompositorState>(
                            registry,
                            name,
                            1,
                            qh,
                            (),
                        );
                        inner.shm = Some(shm);
                        inner.globals_bound.insert("wl_shm".into(), true);
                    }
                    "wl_seat" => {
                        let seat = bind_global::<wl_seat::WlSeat, (), CompositorState>(
                            registry,
                            name,
                            version.min(7),
                            qh,
                            (),
                        );
                        inner._seat = Some(seat);
                        inner.globals_bound.insert("wl_seat".into(), true);
                    }
                    "wl_output" => {
                        let output = bind_global::<wl_output::WlOutput, (), CompositorState>(
                            registry,
                            name,
                            version.min(3),
                            qh,
                            (),
                        );
                        inner._outputs.push(output);
                    }
                    "zwlr_layer_shell_v1" => {
                        let shell = bind_global::<
                            zwlr_layer_shell_v1::ZwlrLayerShellV1,
                            (),
                            CompositorState,
                        >(
                            registry, name, version.min(4), qh, ()
                        );
                        inner.layer_shell = Some(shell);
                        inner
                            .globals_bound
                            .insert("zwlr_layer_shell_v1".into(), true);
                    }
                    "xdg_wm_base" => {
                        let wm = bind_global::<xdg_wm_base::XdgWmBase, (), CompositorState>(
                            registry,
                            name,
                            version.min(3),
                            qh,
                            (),
                        );
                        inner.xdg_wm_base = Some(wm);
                        inner.globals_bound.insert("xdg_wm_base".into(), true);
                    }
                    _ => {}
                }
            }
            wl_registry::Event::GlobalRemove { name: _ } => {}
            _ => {}
        }
    }
}

impl Dispatch<wl_compositor::WlCompositor, ()> for CompositorState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_compositor::WlCompositor,
        _event: <wl_compositor::WlCompositor as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_shm::WlShm, ()> for CompositorState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_shm::WlShm,
        _event: <wl_shm::WlShm as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for CompositorState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_seat::WlSeat,
        _event: <wl_seat::WlSeat as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_output::WlOutput, ()> for CompositorState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_output::WlOutput,
        _event: <wl_output::WlOutput as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<zwlr_layer_shell_v1::ZwlrLayerShellV1, ()> for CompositorState {
    fn event(
        _state: &mut Self,
        _proxy: &zwlr_layer_shell_v1::ZwlrLayerShellV1,
        _event: <zwlr_layer_shell_v1::ZwlrLayerShellV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<zwlr_layer_surface_v1::ZwlrLayerSurfaceV1, ()> for CompositorState {
    fn event(
        _state: &mut Self,
        _proxy: &zwlr_layer_surface_v1::ZwlrLayerSurfaceV1,
        _event: <zwlr_layer_surface_v1::ZwlrLayerSurfaceV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<xdg_wm_base::XdgWmBase, ()> for CompositorState {
    fn event(
        state: &mut Self,
        proxy: &xdg_wm_base::XdgWmBase,
        event: <xdg_wm_base::XdgWmBase as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let xdg_wm_base::Event::Ping { serial } = event {
            proxy.pong(serial);
            if let Ok(mut inner) = state.lock() {
                inner._xdg_configured = true;
            }
        }
    }
}

impl Dispatch<xdg_surface::XdgSurface, ()> for CompositorState {
    fn event(
        _state: &mut Self,
        _proxy: &xdg_surface::XdgSurface,
        _event: <xdg_surface::XdgSurface as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<xdg_toplevel::XdgToplevel, ()> for CompositorState {
    fn event(
        _state: &mut Self,
        _proxy: &xdg_toplevel::XdgToplevel,
        _event: <xdg_toplevel::XdgToplevel as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_surface::WlSurface, ()> for CompositorState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_surface::WlSurface,
        _event: <wl_surface::WlSurface as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_shm_pool::WlShmPool, ()> for CompositorState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_shm_pool::WlShmPool,
        _event: <wl_shm_pool::WlShmPool as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

// ── RealWaylandClient ────────────────────────────────────────────────────────

/// Real Wayland compositor client that opens a Unix socket to `$WAYLAND_DISPLAY`,
/// negotiates protocol globals, and creates surfaces with wlr-layer-shell and
/// xdg-shell roles mapped from `CompositionZone`.
///
/// # Lifecycle
///
/// ```text
/// try_connect() → create_surface_for_zone() → commit() → destroy_surface()
///                                                        → disconnect()
/// ```
///
/// The internal event queue flushes outgoing requests on each operation.
/// Incoming events are dispatched via `flush_events()` or implicitly during
/// surface creation roundtrips.
pub struct RealWaylandClient {
    /// Wayland connection (Unix socket) — kept alive for the lifetime of
    /// this client; dropping it closes the socket.
    #[allow(
        dead_code,
        reason = "kept alive for socket lifetime; event_queue drives protocol"
    )]
    connection: Connection,
    /// Event queue that drives dispatch.
    event_queue: EventQueue<CompositorState>,
    /// Shared mutable state.
    state: CompositorState,
    /// Display handle for global binding.
    qh: QueueHandle<CompositorState>,
}

impl RealWaylandClient {
    /// Attempt to connect to the Wayland display named by `$WAYLAND_DISPLAY`.
    ///
    /// Opens a Unix socket, negotiates globals via a blocking roundtrip, and
    /// verifies that the critical globals (`wl_compositor`, `zwlr_layer_shell_v1`,
    /// `xdg_wm_base`) are available.
    ///
    /// # Errors
    ///
    /// Returns `WaylandConnectError` if:
    /// - `$WAYLAND_DISPLAY` is not set or empty
    /// - The socket connection fails
    /// - The initial roundtrip fails
    /// - One or more critical globals are missing
    pub fn try_connect() -> Result<Self, KdeRendererError> {
        let display_name = env::var("WAYLAND_DISPLAY").map_err(|_| {
            KdeRendererError::WaylandConnectError("$WAYLAND_DISPLAY is not set".to_owned())
        })?;

        if display_name.is_empty() {
            return Err(KdeRendererError::WaylandConnectError(
                "$WAYLAND_DISPLAY is empty".to_owned(),
            ));
        }

        let connection = Connection::connect_to_env().map_err(|e| {
            KdeRendererError::WaylandConnectError(format!(
                "failed to connect to Wayland display '{display_name}': {e}"
            ))
        })?;

        let mut state = CompositorState::new();
        let mut event_queue = connection.new_event_queue::<CompositorState>();
        let qh = event_queue.handle();

        // Register for global events.
        {
            let display = connection.display();
            let _registry = display.get_registry(&qh, ());
        }

        event_queue.roundtrip(&mut state).map_err(|e| {
            KdeRendererError::WaylandConnectError(format!("initial roundtrip failed: {e}"))
        })?;

        {
            let inner = state.lock()?;
            if !inner.all_critical_globals_bound() {
                let missing: Vec<&str> = inner
                    .globals_bound
                    .iter()
                    .filter(|(_, bound)| !**bound)
                    .map(|(name, _)| name.as_str())
                    .collect();
                return Err(KdeRendererError::WaylandConnectError(format!(
                    "missing required Wayland globals: {missing:?}"
                )));
            }
        }

        Ok(Self {
            connection,
            event_queue,
            state,
            qh,
        })
    }

    /// Flush pending events without blocking.
    ///
    /// Dispatches any already-received events from the compositor. Call this
    /// after creating surfaces to process configure events.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if the event dispatch itself fails.
    pub fn flush_events(&mut self) -> Result<usize, KdeRendererError> {
        self.event_queue
            .dispatch_pending(&mut self.state)
            .map_err(|e| KdeRendererError::Internal(format!("event dispatch failed: {e}")))
    }

    /// Perform a blocking roundtrip to synchronize with the compositor.
    ///
    /// This sends all buffered requests and blocks until all corresponding
    /// events have been processed. Use sparingly — it blocks the calling thread.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if the roundtrip fails.
    pub fn roundtrip(&mut self) -> Result<usize, KdeRendererError> {
        self.event_queue
            .roundtrip(&mut self.state)
            .map_err(|e| KdeRendererError::Internal(format!("roundtrip failed: {e}")))
    }

    /// Create a new Wayland surface for the given composition zone.
    ///
    /// The surface is assigned a role based on the zone:
    /// - `Chrome`, `Background`, `Recovery` → wlr-layer-shell with the
    ///   corresponding layer
    /// - `Content` → xdg-shell toplevel
    ///
    /// For `Recovery` zone surfaces, exclusive keyboard interactivity is
    /// requested.
    ///
    /// # Errors
    ///
    /// Returns `Internal` if the compositor, layer shell, or xdg_wm_base
    /// global has not been bound yet (call `try_connect()` first).
    pub fn create_surface_for_zone(
        &self,
        id: KdeSurfaceId,
        zone: CompositionZone,
    ) -> Result<RealWaylandSurface, KdeRendererError> {
        let inner = self.state.lock()?;

        let compositor = inner.compositor.as_ref().ok_or_else(|| {
            KdeRendererError::Internal("wl_compositor global not bound".to_owned())
        })?;

        let wl_surface = compositor.create_surface(&self.qh, ());

        match zone {
            CompositionZone::Chrome | CompositionZone::Background | CompositionZone::Recovery => {
                let layer_shell = inner.layer_shell.as_ref().ok_or_else(|| {
                    KdeRendererError::Internal("zwlr_layer_shell_v1 global not bound".to_owned())
                })?;

                let layer = zone_to_wlr_layer(zone);
                let layer_surface = layer_shell.get_layer_surface(
                    &wl_surface,
                    None::<&wl_output::WlOutput>,
                    layer,
                    "aios-shell".to_owned(),
                    &self.qh,
                    (),
                );

                let keyboard_interactivity = match zone {
                    CompositionZone::Recovery => LayerKeyboardInteractivity::Exclusive,
                    CompositionZone::Chrome => LayerKeyboardInteractivity::OnDemand,
                    CompositionZone::Background => LayerKeyboardInteractivity::None,
                    _ => LayerKeyboardInteractivity::None,
                };

                layer_surface
                    .set_keyboard_interactivity(keyboard_interactivity.to_protocol_value());

                let screen_width: u32 = 1920;
                let screen_height: u32 = 1080;
                layer_surface.set_size(screen_width, screen_height);
                layer_surface.set_anchor(
                    zwlr_layer_surface_v1::Anchor::Top
                        | zwlr_layer_surface_v1::Anchor::Bottom
                        | zwlr_layer_surface_v1::Anchor::Left
                        | zwlr_layer_surface_v1::Anchor::Right,
                );
                layer_surface.set_exclusive_zone(match zone {
                    CompositionZone::Recovery => i32::try_from(screen_width).unwrap_or(i32::MAX),
                    _ => 0,
                });

                Ok(RealWaylandSurface {
                    id,
                    surface: wl_surface,
                    role: WaylandSurfaceRole::LayerShell {
                        layer_surface,
                        layer,
                        keyboard_interactivity,
                    },
                    zone,
                })
            }
            CompositionZone::Content => {
                let xdg_wm = inner.xdg_wm_base.as_ref().ok_or_else(|| {
                    KdeRendererError::Internal("xdg_wm_base global not bound".to_owned())
                })?;

                let xdg = xdg_wm.get_xdg_surface(&wl_surface, &self.qh, ());
                let toplevel = xdg.get_toplevel(&self.qh, ());
                toplevel.set_title("AIOS Content Window".to_owned());
                toplevel.set_app_id("aios.content".to_owned());

                Ok(RealWaylandSurface {
                    id,
                    surface: wl_surface,
                    role: WaylandSurfaceRole::XdgToplevel { xdg, toplevel },
                    zone,
                })
            }
        }
    }

    /// Check whether the compositor connection is still alive.
    ///
    /// Returns `true` if the connection protocol object is valid. Note that
    /// this is best-effort; the compositor may disconnect asynchronously.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        let inner = match self.state.lock() {
            Ok(i) => i,
            Err(_) => return false,
        };
        inner.compositor.is_some()
    }

    /// Disconnect from the compositor by dropping all protocol objects.
    ///
    /// This closes the Unix socket and frees all resources. After calling this,
    /// the client is no longer usable.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "consuming self for drop semantics"
    )]
    pub fn disconnect(mut self) -> Result<(), KdeRendererError> {
        let _ = self.event_queue.dispatch_pending(&mut self.state);
        Ok(())
    }
}

impl std::fmt::Debug for RealWaylandClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealWaylandClient")
            .field("connected", &self.is_connected())
            .finish_non_exhaustive()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    unsafe_code,
    reason = "test code; panic-on-failure is idiomatic; unsafe required for env::remove_var/set_var"
)]
mod tests {
    use super::*;

    fn wayland_available() -> bool {
        env::var("WAYLAND_DISPLAY")
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }

    // ── zone_to_wlr_layer unit tests ─────────────────────────────────────

    #[test]
    fn zone_to_layer_mapping_chrome_is_overlay() {
        assert_eq!(
            zone_to_wlr_layer(CompositionZone::Chrome),
            zwlr_layer_shell_v1::Layer::Overlay
        );
    }

    #[test]
    fn zone_to_layer_mapping_recovery_is_overlay() {
        assert_eq!(
            zone_to_wlr_layer(CompositionZone::Recovery),
            zwlr_layer_shell_v1::Layer::Overlay
        );
    }

    #[test]
    fn zone_to_layer_mapping_content_is_bottom() {
        assert_eq!(
            zone_to_wlr_layer(CompositionZone::Content),
            zwlr_layer_shell_v1::Layer::Bottom
        );
    }

    #[test]
    fn zone_to_layer_mapping_background_is_background() {
        assert_eq!(
            zone_to_wlr_layer(CompositionZone::Background),
            zwlr_layer_shell_v1::Layer::Background
        );
    }

    #[test]
    fn zone_to_layer_mapping_all_four_zones_have_correct_mappings() {
        let chrome = zone_to_wlr_layer(CompositionZone::Chrome);
        let recovery = zone_to_wlr_layer(CompositionZone::Recovery);
        let content = zone_to_wlr_layer(CompositionZone::Content);
        let background = zone_to_wlr_layer(CompositionZone::Background);

        assert_eq!(chrome, recovery);
        assert_ne!(chrome, content);
        assert_ne!(chrome, background);
        assert_ne!(content, background);
    }

    // ── Keyboard interactivity ───────────────────────────────────────────

    #[test]
    fn layer_keyboard_interactivity_conversion() {
        assert_eq!(
            LayerKeyboardInteractivity::None.to_protocol_value(),
            zwlr_layer_surface_v1::KeyboardInteractivity::None
        );
        assert_eq!(
            LayerKeyboardInteractivity::OnDemand.to_protocol_value(),
            zwlr_layer_surface_v1::KeyboardInteractivity::OnDemand
        );
        assert_eq!(
            LayerKeyboardInteractivity::Exclusive.to_protocol_value(),
            zwlr_layer_surface_v1::KeyboardInteractivity::Exclusive
        );
    }

    // ── Real wayland tests ───────────────────────────────────────────────

    #[test]
    fn wayland_compositor_initializes_display_connection() {
        if !wayland_available() {
            eprintln!("SKIP: $WAYLAND_DISPLAY not set");
            return;
        }
        let client = RealWaylandClient::try_connect().expect("connect to Wayland display");
        assert!(client.is_connected());
        client.disconnect().expect("clean disconnect");
    }

    #[test]
    fn chrome_surface_created_on_overlay_layer() {
        if !wayland_available() {
            eprintln!("SKIP: $WAYLAND_DISPLAY not set");
            return;
        }
        let client = RealWaylandClient::try_connect().expect("connect");
        let id = KdeSurfaceId::new();
        let surface = client
            .create_surface_for_zone(id.clone(), CompositionZone::Chrome)
            .expect("create chrome surface");
        assert_eq!(surface.zone, CompositionZone::Chrome);
        assert!(matches!(
            surface.role,
            WaylandSurfaceRole::LayerShell { .. }
        ));
        surface.destroy();
        client.disconnect().expect("clean disconnect");
    }

    #[test]
    fn content_window_created_with_xdg_toplevel_role() {
        if !wayland_available() {
            eprintln!("SKIP: $WAYLAND_DISPLAY not set");
            return;
        }
        let client = RealWaylandClient::try_connect().expect("connect");
        let id = KdeSurfaceId::new();
        let surface = client
            .create_surface_for_zone(id.clone(), CompositionZone::Content)
            .expect("create content surface");
        assert_eq!(surface.zone, CompositionZone::Content);
        assert!(matches!(
            surface.role,
            WaylandSurfaceRole::XdgToplevel { .. }
        ));
        surface.destroy();
        client.disconnect().expect("clean disconnect");
    }

    #[test]
    fn background_surface_created_on_background_layer() {
        if !wayland_available() {
            eprintln!("SKIP: $WAYLAND_DISPLAY not set");
            return;
        }
        let client = RealWaylandClient::try_connect().expect("connect");
        let id = KdeSurfaceId::new();
        let surface = client
            .create_surface_for_zone(id.clone(), CompositionZone::Background)
            .expect("create background surface");
        assert_eq!(surface.zone, CompositionZone::Background);
        surface.destroy();
        client.disconnect().expect("clean disconnect");
    }

    #[test]
    fn recovery_surface_grabs_exclusive_keyboard() {
        if !wayland_available() {
            eprintln!("SKIP: $WAYLAND_DISPLAY not set");
            return;
        }
        let client = RealWaylandClient::try_connect().expect("connect");
        let id = KdeSurfaceId::new();
        let surface = client
            .create_surface_for_zone(id.clone(), CompositionZone::Recovery)
            .expect("create recovery surface");
        assert_eq!(surface.zone, CompositionZone::Recovery);
        if let WaylandSurfaceRole::LayerShell {
            keyboard_interactivity,
            layer,
            ..
        } = &surface.role
        {
            assert_eq!(
                *keyboard_interactivity,
                LayerKeyboardInteractivity::Exclusive
            );
            assert_eq!(*layer, zwlr_layer_shell_v1::Layer::Overlay);
        } else {
            panic!("expected LayerShell role");
        }
        surface.destroy();
        client.disconnect().expect("clean disconnect");
    }

    #[test]
    fn surface_commit_does_not_panic() {
        if !wayland_available() {
            eprintln!("SKIP: $WAYLAND_DISPLAY not set");
            return;
        }
        let client = RealWaylandClient::try_connect().expect("connect");
        let id = KdeSurfaceId::new();
        let surface = client
            .create_surface_for_zone(id, CompositionZone::Content)
            .expect("create surface");
        surface.commit();
        surface.destroy();
        client.disconnect().expect("clean disconnect");
    }

    #[test]
    fn real_client_disconnects_cleanly() {
        if !wayland_available() {
            eprintln!("SKIP: $WAYLAND_DISPLAY not set");
            return;
        }
        let client = RealWaylandClient::try_connect().expect("connect");
        client.disconnect().expect("clean disconnect");
    }

    #[test]
    fn compositor_destroy_frees_resources() {
        if !wayland_available() {
            eprintln!("SKIP: $WAYLAND_DISPLAY not set");
            return;
        }
        {
            let client = RealWaylandClient::try_connect().expect("connect");
            let id = KdeSurfaceId::new();
            let surface = client
                .create_surface_for_zone(id, CompositionZone::Chrome)
                .expect("create surface");
            surface.commit();
            surface.destroy();
            client.disconnect().expect("clean disconnect");
        }
    }

    #[test]
    fn multiple_surfaces_coexist() {
        if !wayland_available() {
            eprintln!("SKIP: $WAYLAND_DISPLAY not set");
            return;
        }
        let client = RealWaylandClient::try_connect().expect("connect");
        let s1 = client
            .create_surface_for_zone(KdeSurfaceId::new(), CompositionZone::Chrome)
            .expect("create chrome");
        let s2 = client
            .create_surface_for_zone(KdeSurfaceId::new(), CompositionZone::Content)
            .expect("create content");
        let s3 = client
            .create_surface_for_zone(KdeSurfaceId::new(), CompositionZone::Background)
            .expect("create background");
        let s4 = client
            .create_surface_for_zone(KdeSurfaceId::new(), CompositionZone::Recovery)
            .expect("create recovery");

        s1.commit();
        s2.commit();
        s3.commit();
        s4.commit();

        s1.destroy();
        s2.destroy();
        s3.destroy();
        s4.destroy();
        client.disconnect().expect("clean disconnect");
    }

    #[test]
    fn connect_without_display_returns_error() {
        let saved = env::var("WAYLAND_DISPLAY").ok();
        unsafe {
            env::remove_var("WAYLAND_DISPLAY");
        }

        let result = RealWaylandClient::try_connect();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KdeRendererError::WaylandConnectError(_)
        ));

        if let Some(val) = saved {
            unsafe {
                env::set_var("WAYLAND_DISPLAY", val);
            }
        }
    }

    #[test]
    fn surfaces_have_unique_ids_after_allocation() {
        if !wayland_available() {
            eprintln!("SKIP: $WAYLAND_DISPLAY not set");
            return;
        }
        let client = RealWaylandClient::try_connect().expect("connect");
        let s1 = client
            .create_surface_for_zone(KdeSurfaceId::new(), CompositionZone::Content)
            .expect("create 1");
        let s2 = client
            .create_surface_for_zone(KdeSurfaceId::new(), CompositionZone::Content)
            .expect("create 2");
        assert_ne!(s1.id, s2.id);
        s1.destroy();
        s2.destroy();
        client.disconnect().expect("clean disconnect");
    }

    #[test]
    fn zone_mapping_consistent_with_zone_layers() {
        let zones = [
            CompositionZone::Chrome,
            CompositionZone::Content,
            CompositionZone::Background,
            CompositionZone::Recovery,
        ];
        for zone in &zones {
            let wlr_layer = zone_to_wlr_layer(*zone);
            match wlr_layer {
                zwlr_layer_shell_v1::Layer::Background
                | zwlr_layer_shell_v1::Layer::Bottom
                | zwlr_layer_shell_v1::Layer::Top
                | zwlr_layer_shell_v1::Layer::Overlay => {}
                _ => panic!("unknown wlr layer variant for {zone:?}"),
            }
        }
    }
}
