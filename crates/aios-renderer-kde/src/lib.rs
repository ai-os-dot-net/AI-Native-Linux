//! L7 KDE Plasma renderer for AIOS (S7.4).
//!
//! Typed core skeleton: data model + invariants only. Wayland client,
//! Qt/QML compilation, and `KWin` scripting land in later tasks.

#![deny(unsafe_code)]

#[cfg(feature = "qt-bridge")]
pub mod qt_bridge;

pub mod compilation;
pub mod error;
pub mod evidence;
pub mod integration;
pub mod kwin_script;
pub mod node_kind;
pub mod plasma_theme;
pub mod recovery_shell;
pub mod renderer;
pub mod service;
pub mod token_compile;
pub mod types;
pub mod visual_token;
pub mod wayland;
pub mod wayland_compositor;
pub mod zone;

pub use compilation::{CompilationContext, CompilationRule, NodeSurfaceKind};
pub use error::KdeRendererError;
pub use evidence::{
    InMemoryKdeEvidenceEmitter, KdeEvidenceEmitter, KdeEvidenceReceipt, KdeRecordType,
};
pub use kwin_script::{KwinScript, KwinScriptLoader, KwinScriptRecord, DEFAULT_ALLOWED_ROOT};
pub use node_kind::{NodeKind, NodeKindCompilationHint};
pub use recovery_shell::{
    escalate_to_degraded, ConstitutionalIconBundle, DegradedTrigger, IconEntry, RecoverySession,
    RecoveryShellGuard, SessionIsolationMarker,
};
pub use renderer::{
    AllocateSurfaceRequest, InMemoryKdeRenderer, KdeRenderer, RecoveryEntryReceipt, SurfaceFilter,
    SurfaceReleaseReceipt, TokenApplicationReceipt,
};
pub use token_compile::{
    compile_token, compile_token_with_ctx, IconLookupCtx, QEasingCurve, QFontWeight, QPaletteRole,
    QtRecipe, ShapeKind,
};
pub use types::{KdeSurfaceDescriptor, KdeSurfaceId, RecoveryShellMode, RendererMode};
pub use visual_token::{VisualToken, VisualTokenKind};
pub use wayland::{
    evaluate_surface_request, WaylandClient, WaylandInteractivity, WaylandProtocol,
    WaylandSurfaceGrant, WaylandSurfaceLayer, WaylandSurfaceRequest,
};
pub use wayland_compositor::{
    zone_to_wlr_layer, LayerKeyboardInteractivity, RealWaylandClient, RealWaylandSurface,
    WaylandSurfaceRole,
};
pub use zone::{CompositionZone, ZoneLayer};

// T-137: integration re-exports
pub use integration::{
    apps_package_envelope_to_kde_node_tree, assert_parity_for_apps_domain, AppsBridge,
    DomainTypeParity, DomainTypeParityEntry, KdeNodeTree, KdeNodeTreeEntry,
};

/// Crate version marker used by closure-invariant tests in T-138.
pub const DEFAULT_CODE_VERSION: &str = "aios-renderer-kde/0.1.0-T138";
