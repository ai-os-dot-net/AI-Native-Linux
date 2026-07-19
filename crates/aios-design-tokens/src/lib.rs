#![forbid(unsafe_code)]
//! # aios-design-tokens — shared visual style vocabulary for AIOS renderers
//!
//! The L7 renderers (KDE, Web, CLI) already share a *structural* vocabulary
//! (the closed 19-variant `NodeKind`, S7.2 §3). This crate adds the missing
//! *style* vocabulary: a closed, typed set of **design tokens** (colors,
//! spacing, radii, typography) defined **once**, per theme (Light/Dark), and
//! emitted identically to Web CSS custom properties and KDE QML properties.
//!
//! ## Why closed vocabularies
//!
//! Every token type is a closed `enum`. A renderer asks for a role
//! (`ColorToken::TextPrimary`), never a literal (`"#1a1d21"`). The resolver
//! ([`TokenSet`]) covers every variant with an **exhaustive** match, so adding
//! a token without theming it fails to compile — drift is caught by the
//! compiler, not by a code review.
//!
//! ## The parity proof
//!
//! [`to_css_custom_properties`] and [`to_qml_properties`] are pure functions
//! over the *same* [`TokenSet`]. The integration test `tests/parity.rs` decodes
//! every color back out of both outputs and asserts byte-equal RGBA. This is
//! what makes "visual parity" a *checked* property rather than a hope.
//!
//! ## Taxonomy honesty
//!
//! Token model + emitters + parity tests are **REAL (E3)**. Pixel-identical
//! rendering in live KDE/Web is **E4-pending** — it requires the renderers'
//! consumption paths (documented as CONTRACT seams in [`emit`]) to be wired and
//! a visual/E2E check. See `DESIGN.md`.

pub mod color;
pub mod component;
pub mod elevation;
pub mod emit;
pub mod motion;
pub mod scale;
pub mod theme;
pub mod typography;

pub use color::{ColorToken, ColorValue};
pub use elevation::{ElevationToken, ShadowValue};
pub use emit::{
    css_var_color, css_var_easing, css_var_elevation, css_var_motion, qml_prop_color,
    qml_prop_easing, qml_prop_elevation, qml_prop_motion, to_css_custom_properties,
    to_qml_properties,
};
pub use motion::{EasingToken, MotionToken};
pub use scale::{RadiusToken, SpacingToken};
pub use theme::{ThemeVariant, TokenSet};
pub use typography::{FontFamily, TypographyToken, TypographyValue};
