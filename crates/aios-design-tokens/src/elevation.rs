//! Closed elevation vocabulary and the typed shadow value it resolves to.
//!
//! `ElevationToken` is a **closed** set of depth roles — NOT a free-form list of
//! box-shadow strings. Adding a role forces a compile error in the exhaustive
//! `match` that resolves it (see `crate::theme::TokenSet::elevation`), which is
//! the same closed-vocabulary guarantee the color and scale tokens rely on.
//!
//! The resolved value is a typed [`ShadowValue`] (offset / blur / spread / RGBA
//! color), not a pre-formatted string. Both emitters serialize the *same*
//! canonical CSS `box-shadow` string, and the parity proof parses that string
//! back into a [`ShadowValue`] from each emitter and asserts equality — exactly
//! the way [`crate::color::ColorValue`] is round-tripped.
//!
//! Elevation is theme-aware: shadows are softer (lower alpha) in `Light` and
//! deeper (higher alpha) in `Dark`, over a neutral black tint. The geometry
//! (offsets/blur/spread) is theme-independent; only the alpha deepens.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

use crate::color::ColorValue;

/// A concrete, typed drop-shadow value — the single source of truth.
///
/// Renderers *format* this into a canonical CSS `box-shadow` string via
/// [`Self::to_css_shadow`]; they never carry a pre-formatted literal as the
/// authoritative value. Storing the components as integers (plus a typed
/// [`ColorValue`]) makes the emitter-equivalence parity proof a structural
/// comparison after a lossless parse, not a fragile string comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShadowValue {
    /// Horizontal offset in logical pixels (positive = rightward).
    pub dx: i8,
    /// Vertical offset in logical pixels (positive = downward).
    pub dy: i8,
    /// Blur radius in logical pixels (never negative, per CSS).
    pub blur: u8,
    /// Spread radius in logical pixels (may be negative).
    pub spread: i8,
    /// Shadow color, including alpha (the alpha is what deepens per theme).
    pub color: ColorValue,
}

impl ShadowValue {
    /// The canonical "no shadow" value: zero geometry over a fully transparent
    /// color. Serializes to the CSS keyword `none` and parses back from it.
    pub const NONE: Self = Self {
        dx: 0,
        dy: 0,
        blur: 0,
        spread: 0,
        color: ColorValue::rgba(0, 0, 0, 0),
    };

    /// Construct a shadow from its components.
    #[must_use]
    pub const fn new(dx: i8, dy: i8, blur: u8, spread: i8, color: ColorValue) -> Self {
        Self {
            dx,
            dy,
            blur,
            spread,
            color,
        }
    }

    /// Whether this value is the canonical "no shadow" (transparent, zero
    /// geometry). Such a value serializes to the CSS keyword `none`.
    #[must_use]
    pub const fn is_none(&self) -> bool {
        self.dx == 0 && self.dy == 0 && self.blur == 0 && self.spread == 0 && self.color.a == 0
    }

    /// Format as a canonical CSS `box-shadow` value, e.g.
    /// `"0px 1px 2px 0px #0000001f"`, or the keyword `"none"` when there is no
    /// shadow. The color is emitted as `#RRGGBBAA` (CSS convention) so both
    /// emitters produce one canonical form; a drifted emitter fails the parity
    /// test.
    #[must_use]
    pub fn to_css_shadow(&self) -> String {
        if self.is_none() {
            return "none".to_string();
        }
        format!(
            "{}px {}px {}px {}px {}",
            self.dx,
            self.dy,
            self.blur,
            self.spread,
            self.color.to_hex_rgba()
        )
    }

    /// Parse a canonical CSS `box-shadow` string (as produced by
    /// [`Self::to_css_shadow`]) back into a `ShadowValue`. Accepts the keyword
    /// `none`. Used by the parity proof to read a shadow back out of each
    /// emitter's output. Returns `None` on any malformed input.
    #[must_use]
    pub fn from_css_shadow(shadow: &str) -> Option<Self> {
        let shadow = shadow.trim();
        if shadow == "none" {
            return Some(Self::NONE);
        }
        let mut parts = shadow.split_whitespace();
        let dx = parse_px_i8(parts.next()?)?;
        let dy = parse_px_i8(parts.next()?)?;
        let blur = parse_px_u8(parts.next()?)?;
        let spread = parse_px_i8(parts.next()?)?;
        let color = ColorValue::from_hex(parts.next()?)?;
        // Reject trailing garbage so the round-trip is exact.
        if parts.next().is_some() {
            return None;
        }
        Some(Self::new(dx, dy, blur, spread, color))
    }
}

/// Parse a `"<int>px"` token into a signed `i8`. Returns `None` on any
/// malformed input.
fn parse_px_i8(token: &str) -> Option<i8> {
    token.strip_suffix("px")?.parse().ok()
}

/// Parse a `"<int>px"` token into an unsigned `u8`. Returns `None` on any
/// malformed input.
fn parse_px_u8(token: &str) -> Option<u8> {
    token.strip_suffix("px")?.parse().ok()
}

/// The closed set of elevation (depth) roles shared by every AIOS renderer.
///
/// Semantic (by depth role), not literal (by shadow string): a renderer asks
/// for `Medium`, never for a raw `box-shadow`. This is the elevation part of the
/// shared STYLE vocabulary that complements color, spacing, radius and
/// typography.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
pub enum ElevationToken {
    /// Flush with the surface — no shadow.
    None,
    /// Low elevation — subtle lift for raised rows and hovered controls.
    Low,
    /// Medium elevation — cards, popovers, menus.
    Medium,
    /// High elevation — dialogs, sheets, floating panels.
    High,
}

impl ElevationToken {
    /// Stable kebab-case slug used to build CSS variable names and QML property
    /// identifiers. Deterministic; part of the public contract.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}
