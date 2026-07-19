//! L7 Web renderer for AIOS (S7.5).
//!
//! Typed core skeleton: data model + invariants only. HTTPS server,
//! gRPC-Web bridge, exposure FSM, and Next.js front-end land in later
//! tasks.

#![deny(unsafe_code)]

pub mod chrome_integrity;
pub mod compilation;
pub mod css_compile;
pub mod error;
pub mod evidence;
pub mod exposure;
pub mod exposure_fsm;
pub mod grpc_web_bridge;
pub mod https;
pub mod integration;
pub mod origin;
pub mod origin_verifier;
pub mod renderer;
pub mod service;
pub mod token_css;
pub mod types;

pub use chrome_integrity::{
    ChromeIntegrityMonitor, ChromeTreeFragment, IntegrityCheckOutcome, IntegrityCheckRecord,
};
pub use compilation::{
    WebCompilationContext, WebCompilationRule, WebSurfaceZone, WEB_COMPILATION_RULE_CONST_CHECK,
};
pub use css_compile::{
    compile_token_to_css, compile_token_to_css_with_ctx, recipe_to_css_block, CssEasing, CssRecipe,
    WebIconLookupCtx, WebShapeKind,
};
pub use error::WebRendererError;
pub use evidence::{
    InMemoryWebEvidenceEmitter, WebEvidenceEmitter, WebEvidenceReceipt, WebRecordType,
};
pub use exposure::{ExposureLevel, ExposureLevelLabel};
pub use exposure_fsm::{ExposureFsm, ExposureTransition, ExposureTransitionReason};
pub use grpc_web_bridge::{
    default_localhost_config, GrpcWebBridge, GrpcWebBridgeConfig, GrpcWebClientStub,
};
pub use https::{
    generate_self_signed_loopback_cert, lan_bind_addrs, loopback_only_bind_addrs,
    plain_http_rejection_response_body, GeneratedCert, HttpsListener, HttpsServerConfig,
    PLAIN_HTTP_REJECTION_STATUS,
};
pub use origin::{OriginScheme, OriginToken, ParsedOrigin};
pub use origin_verifier::{IframeOriginBinding, OriginVerifier};
pub use renderer::{
    AllocateWebSurfaceRequest, InMemoryWebRenderer, RecoveryEntryReceipt, TokenApplicationReceipt,
    WebRenderer, WebSurfaceFilter, WebSurfaceReleaseReceipt,
};
pub use token_css::{generated_tokens_css, GENERATED_TOKENS_CSS_PATH};
pub use types::{
    ChromeShadowRootMarker, RouteDescriptor, ShadowRootMode, WebRendererMode, WebSurfaceDescriptor,
    WebSurfaceId,
};

/// Re-exported from `aios-renderer-kde` so both L7 renderers share the
/// same closed `NodeKind` vocabulary (S7.2 §3 — 19 declared values).
pub use aios_renderer_kde::{NodeKind, NodeKindCompilationHint, VisualToken, VisualTokenKind};

// T-149: integration re-exports
pub use integration::{
    apps_package_envelope_to_web_render_tree, assert_three_way_parity_for_apps_domain,
    ThreeWayParity, ThreeWayParityEntry, WebAppsBridge, WebRenderTree, WebRenderTreeEntry,
};

/// Crate version marker used by closure-invariant tests in T-150.
pub const DEFAULT_CODE_VERSION: &str = "aios-renderer-web/0.1.0-T150";
