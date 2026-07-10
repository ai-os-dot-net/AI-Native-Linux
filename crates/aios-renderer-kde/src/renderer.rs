//! KDE renderer service interface — `KdeRenderer` async trait + `InMemoryKdeRenderer`
//! (S7.4 §4).
//!
//! The trait defines 10 async RPCs for surface lifecycle, mode transitions,
//! and visual token application. `InMemoryKdeRenderer` provides the in-memory
//! backing that the rest of M14 composes against, enforcing INV I4 (chrome zone
//! guard), INV I5 (recovery-shell surface allowlist), and INV I7 (degraded-mode
//! GPU-bearing rejection) at allocation time.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::error::KdeRendererError;
use crate::evidence::KdeEvidenceEmitter;
use crate::node_kind::NodeKind;
use crate::recovery_shell::DegradedTrigger;
use crate::types::{KdeSurfaceDescriptor, KdeSurfaceId, RendererMode};
use crate::visual_token::VisualToken;
use crate::wayland_compositor::RealWaylandClient;
use crate::zone::{CompositionZone, ZoneLayer};

// ── Request / receipt DTOs ────────────────────────────────────────────────────

/// Request to allocate a new surface in the KDE renderer.
#[derive(Debug, Clone)]
pub struct AllocateSurfaceRequest {
    /// Composition zone this surface will occupy.
    pub zone: CompositionZone,
    /// Canonical subject id of the client claiming this surface.
    pub claimed_by: String,
    /// The UI node kind the surface will render.
    pub node_kind: NodeKind,
    /// Optional explicit layer override (zone-derived default used when `None`).
    pub requested_layer: Option<ZoneLayer>,
}

/// Receipt confirming a surface was released.
#[derive(Debug, Clone)]
pub struct SurfaceReleaseReceipt {
    /// The released surface identifier.
    pub id: KdeSurfaceId,
    /// Wall-clock timestamp of the release.
    pub released_at: DateTime<Utc>,
    /// Renderer mode at the moment of release.
    pub final_mode: RendererMode,
}

/// Receipt confirming entry into recovery mode.
#[derive(Debug, Clone)]
pub struct RecoveryEntryReceipt {
    /// When recovery mode was entered.
    pub entered_at: DateTime<Utc>,
    /// Always `true` — recovery sessions only admit AIOS-owned surface kinds.
    pub aios_surfaces_only: bool,
    /// Marker string identifying the separate Wayland display.
    pub display_separation: String,
}

/// Receipt confirming visual tokens were applied.
#[derive(Debug, Clone)]
pub struct TokenApplicationReceipt {
    /// Number of tokens applied.
    pub applied_count: usize,
    /// When the tokens were applied.
    pub timestamp: DateTime<Utc>,
}

/// Filter predicate for `list_surfaces`.
#[derive(Debug, Clone)]
pub enum SurfaceFilter {
    /// Return every registered surface.
    All,
    /// Only surfaces in the given composition zone.
    ByZone(CompositionZone),
    /// Only surfaces claimed by the given canonical subject id.
    ByClaimant(String),
    /// Only surfaces of the given node kind.
    ByNodeKind(NodeKind),
    /// Only surfaces whose mode matches the given renderer mode.
    InModeOnly(RendererMode),
}

// ── KdeRenderer async trait ───────────────────────────────────────────────────

/// Service interface for the KDE Plasma renderer (S7.4 §4).
///
/// Ten async RPCs covering surface lifecycle, mode transitions, and visual
/// token management. Implementations must be `Send + Sync` so they can be
/// shared across tokio tasks.
#[async_trait]
pub trait KdeRenderer: Send + Sync {
    /// Allocate a new surface, enforcing INV I4 (chrome zone guard),
    /// INV I5 (recovery-shell allowlist), and INV I7 (degraded-mode
    /// GPU-bearing rejection).
    async fn allocate_surface(
        &self,
        req: AllocateSurfaceRequest,
    ) -> Result<KdeSurfaceDescriptor, KdeRendererError>;

    /// Release a surface, removing it from the renderer's surface set.
    async fn release_surface(
        &self,
        id: KdeSurfaceId,
    ) -> Result<SurfaceReleaseReceipt, KdeRendererError>;

    /// Look up a surface by its identifier.
    async fn get_surface(&self, id: KdeSurfaceId)
        -> Result<KdeSurfaceDescriptor, KdeRendererError>;

    /// List surfaces matching the given filter. Infallible — an empty `Vec`
    /// is returned when no surfaces match.
    async fn list_surfaces(&self, filter: SurfaceFilter) -> Vec<KdeSurfaceDescriptor>;

    /// Enter recovery mode. Allocates are restricted to AIOS-owned surface
    /// kinds (INV I5).
    async fn enter_recovery_mode(&self) -> Result<RecoveryEntryReceipt, KdeRendererError>;

    /// Exit recovery mode and return to normal operation.
    async fn exit_recovery_mode(&self) -> Result<(), KdeRendererError>;

    /// Enter degraded (text-only fallback) mode with the given reason class
    /// (e.g. `"kwin_unreachable"`, `"wgpu_init_failed"`).
    async fn enter_degraded_mode(&self, reason: String) -> Result<(), KdeRendererError>;

    /// Return the current renderer operational mode.
    async fn get_mode(&self) -> RendererMode;

    /// Replace the active visual token set with the given tokens.
    async fn apply_visual_tokens(
        &self,
        tokens: Vec<VisualToken>,
    ) -> Result<TokenApplicationReceipt, KdeRendererError>;

    /// Return a snapshot of the currently active visual tokens.
    async fn get_active_tokens(&self) -> Vec<VisualToken>;
}

// ── In-memory state ───────────────────────────────────────────────────────────

/// Internal renderer state behind a `tokio::sync::RwLock`.
struct KdeRendererState {
    surfaces: HashMap<KdeSurfaceId, KdeSurfaceDescriptor>,
    node_kinds: HashMap<KdeSurfaceId, NodeKind>,
    mode: RendererMode,
    active_tokens: Vec<VisualToken>,
}

// ── InMemoryKdeRenderer ───────────────────────────────────────────────────────

/// In-memory KDE renderer backed by `RwLock<KdeRendererState>`.
///
/// All invariants (I4, I5, I7) are enforced at allocation time. This
/// implementation is intended as the in-process test double and the
/// baseline for the rest of M14 to compose against.
///
/// An optional [`KdeEvidenceEmitter`] emits lifecycle events into the
/// append-only Evidence Log. When `None`, emission is silently skipped.
pub struct InMemoryKdeRenderer {
    state: RwLock<KdeRendererState>,
    emitter: Option<Arc<dyn KdeEvidenceEmitter>>,
    compositor: Option<Arc<std::sync::Mutex<RealWaylandClient>>>,
}

impl InMemoryKdeRenderer {
    /// Create a new renderer in `Normal` mode with no surfaces, no tokens,
    /// and no evidence emitter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(KdeRendererState {
                surfaces: HashMap::new(),
                node_kinds: HashMap::new(),
                mode: RendererMode::Normal,
                active_tokens: Vec::new(),
            }),
            emitter: None,
            compositor: None,
        }
    }

    /// Attach an evidence emitter for lifecycle event recording.
    ///
    /// When set, surface allocate/release, recovery entry/exit, and degraded
    /// mode transitions produce chained BLAKE3 evidence receipts.
    #[must_use]
    pub fn with_emitter(mut self, emitter: Arc<dyn KdeEvidenceEmitter>) -> Self {
        self.emitter = Some(emitter);
        self
    }

    /// Attach a real Wayland compositor client for KDE Plasma surface management.
    ///
    /// When set, every `allocate_surface` call creates a real Wayland
    /// surface (`wl_surface`) with the appropriate role (wlr-layer-shell or
    /// xdg-shell) in addition to the in-memory tracking. When `None`, the
    /// renderer operates as an in-memory test double.
    #[must_use]
    pub fn with_wayland_compositor(mut self, client: RealWaylandClient) -> Self {
        self.compositor = Some(Arc::new(std::sync::Mutex::new(client)));
        self
    }
}

impl Default for InMemoryKdeRenderer {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` when the node kind is an AIOS-owned surface kind allowed
/// during recovery mode (INV I5).
const fn is_aios_surface_kind(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::SecurityIndicator
            | NodeKind::ApprovalPrompt
            | NodeKind::EvidenceLink
            | NodeKind::AgentMessage
    )
}

#[async_trait]
impl KdeRenderer for InMemoryKdeRenderer {
    async fn allocate_surface(
        &self,
        req: AllocateSurfaceRequest,
    ) -> Result<KdeSurfaceDescriptor, KdeRendererError> {
        let mut state = self.state.write().await;

        // INV I5 — recovery mode only admits AIOS-owned surface kinds.
        if state.mode == RendererMode::Recovery && !is_aios_surface_kind(req.node_kind) {
            return Err(KdeRendererError::Internal(
                "recovery shell allows AIOS_SURFACE only".into(),
            ));
        }

        // INV I7 — degraded mode rejects GPU-bearing kinds (text-only fallback).
        if let RendererMode::Degraded(_) = &state.mode {
            if req.node_kind.compilation_hint().is_gpu_bearing {
                return Err(KdeRendererError::Degraded(
                    "gpu-bearing kind disallowed in degraded mode".into(),
                ));
            }
        }

        // INV I4 enforced by KdeSurfaceDescriptor::new (chrome zone requires
        // "aios-chrome" claimant).
        let desc_result = KdeSurfaceDescriptor::new(req.zone, req.claimed_by.clone());
        let mut desc = match desc_result {
            Ok(d) => d,
            Err(e) => {
                // Emit INV I4 rejection before propagating the error.
                if let Some(ref emitter) = self.emitter {
                    let _ = emitter
                        .emit_layer_shell_rejected(&req.claimed_by, req.zone, &e.to_string())
                        .await;
                }
                return Err(e);
            }
        };

        if let Some(layer) = req.requested_layer {
            desc.layer = layer;
        }

        desc.mode = state.mode.clone();

        state.node_kinds.insert(desc.id.clone(), req.node_kind);
        state.surfaces.insert(desc.id.clone(), desc.clone());

        // Create real Wayland surface if a compositor is attached.
        if let Some(ref compositor) = self.compositor {
            let wayland_client = compositor.lock().map_err(|e| {
                KdeRendererError::Internal(format!("wayland compositor mutex poisoned: {e}"))
            })?;
            wayland_client
                .create_surface_for_zone(desc.id.clone(), req.zone)
                .map_err(|e| {
                    KdeRendererError::Internal(format!("wayland surface creation failed: {e}"))
                })?;
        }

        drop(state);

        // Emit surface allocation evidence.
        if let Some(ref emitter) = self.emitter {
            let _ = emitter
                .emit_surface_allocated(&desc, &desc.claimed_by)
                .await;
        }

        Ok(desc)
    }

    async fn release_surface(
        &self,
        id: KdeSurfaceId,
    ) -> Result<SurfaceReleaseReceipt, KdeRendererError> {
        let mut state = self.state.write().await;

        let removed = state.surfaces.remove(&id);
        if removed.is_none() {
            return Err(KdeRendererError::SurfaceNotFound(id));
        }

        state.node_kinds.remove(&id);

        let receipt = SurfaceReleaseReceipt {
            id,
            released_at: Utc::now(),
            final_mode: state.mode.clone(),
        };

        // Drop lock before async emission (clippy: significant_drop_tightening).
        drop(state);

        // Emit surface release evidence.
        if let (Some(ref emitter), Some(ref desc)) = (&self.emitter, &removed) {
            let _ = emitter.emit_surface_released(desc, &desc.claimed_by).await;
        }

        Ok(receipt)
    }

    async fn get_surface(
        &self,
        id: KdeSurfaceId,
    ) -> Result<KdeSurfaceDescriptor, KdeRendererError> {
        let state = self.state.read().await;

        state
            .surfaces
            .get(&id)
            .cloned()
            .ok_or(KdeRendererError::SurfaceNotFound(id))
    }

    async fn list_surfaces(&self, filter: SurfaceFilter) -> Vec<KdeSurfaceDescriptor> {
        let state = self.state.read().await;

        match filter {
            SurfaceFilter::All => state.surfaces.values().cloned().collect(),
            SurfaceFilter::ByZone(zone) => state
                .surfaces
                .values()
                .filter(|d| d.zone == zone)
                .cloned()
                .collect(),
            SurfaceFilter::ByClaimant(ref claimant) => state
                .surfaces
                .values()
                .filter(|d| d.claimed_by == *claimant)
                .cloned()
                .collect(),
            SurfaceFilter::ByNodeKind(kind) => state
                .node_kinds
                .iter()
                .filter(|(_, k)| **k == kind)
                .filter_map(|(id, _)| state.surfaces.get(id).cloned())
                .collect(),
            SurfaceFilter::InModeOnly(ref mode) => state
                .surfaces
                .values()
                .filter(|d| d.mode == *mode)
                .cloned()
                .collect(),
        }
    }

    async fn enter_recovery_mode(&self) -> Result<RecoveryEntryReceipt, KdeRendererError> {
        self.state.write().await.mode = RendererMode::Recovery;

        let receipt = RecoveryEntryReceipt {
            entered_at: Utc::now(),
            aios_surfaces_only: true,
            display_separation: "separate-wayland-display".into(),
        };

        // Emit recovery entered evidence.
        if let Some(ref emitter) = self.emitter {
            let _ = emitter
                .emit_recovery_entered(&receipt, "service:aios-renderer-kde")
                .await;
        }

        Ok(receipt)
    }

    async fn exit_recovery_mode(&self) -> Result<(), KdeRendererError> {
        self.state.write().await.mode = RendererMode::Normal;

        // Emit recovery exited evidence.
        if let Some(ref emitter) = self.emitter {
            let _ = emitter
                .emit_recovery_exited("service:aios-renderer-kde")
                .await;
        }

        Ok(())
    }

    async fn enter_degraded_mode(&self, reason: String) -> Result<(), KdeRendererError> {
        self.state.write().await.mode = RendererMode::Degraded(reason.clone());

        // Emit degraded mode evidence (FOREVER retention).
        if let Some(ref emitter) = self.emitter {
            let _ = emitter
                .emit_renderer_degraded(DegradedTrigger::KwinUnavailable, &reason)
                .await;
        }

        Ok(())
    }

    async fn get_mode(&self) -> RendererMode {
        let state = self.state.read().await;
        state.mode.clone()
    }

    async fn apply_visual_tokens(
        &self,
        tokens: Vec<VisualToken>,
    ) -> Result<TokenApplicationReceipt, KdeRendererError> {
        let count = tokens.len();
        self.state.write().await.active_tokens = tokens;

        Ok(TokenApplicationReceipt {
            applied_count: count,
            timestamp: Utc::now(),
        })
    }

    async fn get_active_tokens(&self) -> Vec<VisualToken> {
        let state = self.state.read().await;
        state.active_tokens.clone()
    }
}
