//! `VisualToken` → Qt recipe compilation (S7.4 §4).
//!
//! `compile_token()` and `compile_token_with_ctx()` turn S7.3 `VisualToken`
//! canonical values into typed `QtRecipe` directives consumed by the Qt/QML
//! compilation pipeline. Each token kind maps to a distinct recipe variant
//! via a parser-style `canonical_value` decoder.
//!
//! INV I6 — icon bundles must be root-signed. `IconLookupCtx.root_signed`
//! enforces this at compile time; an unsigned context yields
//! `IconBundleVerificationFailed`.

use serde::{Deserialize, Serialize};

use crate::error::KdeRendererError;
use crate::visual_token::{VisualToken, VisualTokenKind};

// ── Supporting enums ──────────────────────────────────────────────────────────

/// Qt colour palette role (S7.4 §4 table row "Color").
///
/// Each role maps to a `QPalette::ColorRole` in the Qt C++ API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QPaletteRole {
    /// `QPalette::Window` — general window background.
    WindowBackground,
    /// `QPalette::WindowText` — general foreground text.
    WindowText,
    /// `QPalette::Base` — text entry background.
    Base,
    /// `QPalette::Text` — text entry foreground.
    Text,
    /// `QPalette::Highlight` — selected-item background.
    Highlight,
    /// `QPalette::HighlightedText` — selected-item foreground.
    HighlightText,
    /// `QPalette::Link` — hyperlink colour.
    Link,
    /// `QPalette::Mid` — 3-D midlight.
    Mid,
    /// `QPalette::Shadow` — 3-D shadow.
    Shadow,
    /// `QPalette::BrightText` — contrast text for dark backgrounds.
    BrightText,
    /// `QPalette::ButtonText` — button foreground.
    ButtonText,
    /// `QPalette::Disabled` colour group modifier.
    Disabled,
}

/// Qt font weight enumeration (S7.4 §4 table row "Font").
///
/// Maps to `QFont::Weight` values. Named weights cover the range
/// Thin (100) through Black (900) in standard CSS/OpenType increments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QFontWeight {
    /// Weight 100.
    Thin,
    /// Weight 300.
    Light,
    /// Weight 400.
    Normal,
    /// Weight 500.
    Medium,
    /// Weight 600 (semi-bold / demi-bold).
    DemiBold,
    /// Weight 700.
    Bold,
    /// Weight 900.
    Black,
}

/// Qt animation easing curve (S7.4 §4 table row "Motion").
///
/// The `Bezier` variant carries no control-point payload yet — that is
/// deferred until the cxx-qt bridge (T-136) where `QEasingCurve` can be
/// instantiated with actual `qreal` control points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QEasingCurve {
    /// Linear interpolation.
    Linear,
    /// Quadratic ease-in (`t^2`).
    InQuad,
    /// Quadratic ease-out.
    OutQuad,
    /// Quadratic ease-in-out.
    InOutQuad,
    /// Cubic ease-in (`t^3`).
    InCubic,
    /// Cubic ease-out.
    OutCubic,
    /// Cubic ease-in-out.
    InOutCubic,
    /// Custom cubic-bezier (control points deferred to T-136).
    Bezier,
}

/// Geometric shape kind for `QFrame` / clipping masks (S7.4 §4 table row "Shape").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShapeKind {
    /// Sharp-cornered rectangle.
    Rect,
    /// Rectangle with uniform corner radius.
    RoundedRect,
    /// Perfect circle (width == height).
    Circle,
    /// Pill / capsule shape (border-radius ≫ half the shorter dimension).
    Pill,
}

// ── IconLookupCtx ─────────────────────────────────────────────────────────────

/// Context required for icon token resolution (S7.4 §4 + INV I6).
///
/// INV I6 mandates that icon bundles must be verifiably root-signed.
/// When `root_signed` is `false`, `compile_token_with_ctx` yields
/// `KdeRendererError::IconBundleVerificationFailed` for `Icon` tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconLookupCtx {
    /// Active theme identifier (e.g. `"dark"`, `"breeze-light"`).
    pub theme_id: String,
    /// Whether the theme's icon bundle has been verified as root-signed.
    pub root_signed: bool,
}

// ── QtRecipe ──────────────────────────────────────────────────────────────────

/// A typed Qt rendering directive compiled from a `VisualToken` (S7.4 §4).
///
/// Each variant corresponds to one row in the S7.4 §4 token compilation table
/// and carries enough information for the cxx-qt bridge (T-136) to produce a
/// concrete Qt C++ object without additional parsing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum QtRecipe {
    /// `QPalette` colour assignment.
    Palette {
        /// Target `QPalette::ColorRole`.
        role: QPaletteRole,
        /// The resolved hex colour (e.g. `"#1e1e1e"`).
        color_hex: String,
    },
    /// `QFont` configuration.
    Font {
        /// Font family name (e.g. `"Noto Sans"`).
        family: String,
        /// Point size (logical, not pixel).
        point_size_eq: f32,
        /// Font weight from the Thin–Black scale.
        weight: QFontWeight,
        /// Italic flag.
        italic: bool,
        /// Monospace flag (selects `QFont::Monospace` style hint).
        monospace: bool,
    },
    /// Layout spacing (margins, gaps).
    Spacing {
        /// Pixel count for the spacing directive.
        logical_pixels: u32,
    },
    /// `QPropertyAnimation` duration and easing curve.
    Motion {
        /// Animation duration in milliseconds.
        duration_ms: u32,
        /// Easing curve identifier.
        easing: QEasingCurve,
    },
    /// `KIconLoader` theme icon path.
    Icon {
        /// Path relative to the AIOS-FS mount, e.g.
        /// `/aios/system/themes/dark/icons/COLOR_ACTION_AI.svg`.
        theme_path: String,
        /// Whether to fall back to Breeze icon theme.
        /// INV I6 — always `false`; root-signed bundle contains all icons.
        fallback_to_breeze: bool,
    },
    /// `QFrame` shape + corner radius.
    Shape {
        /// Geometric shape kind.
        kind: ShapeKind,
        /// Corner radius in logical pixels (ignored for `Rect`).
        corner_radius_px: u32,
    },
    /// Surface elevation / shadow layering.
    Elevation {
        /// Z-order for compositor stacking.
        z_order: i32,
        /// Shadow blur radius in logical pixels.
        shadow_blur_px: u32,
        /// Shadow alpha channel (0–255).
        shadow_alpha: u8,
    },
}

// ── Colour role lookup ────────────────────────────────────────────────────────

/// Map a colour token id prefix to its `QPaletteRole`.
fn color_role_from_id(id: &str) -> QPaletteRole {
    if id.starts_with("color.window.background") {
        QPaletteRole::WindowBackground
    } else if id.starts_with("color.window.text") {
        QPaletteRole::WindowText
    } else if id.starts_with("color.base") {
        QPaletteRole::Base
    } else if id.starts_with("color.highlight.text") {
        QPaletteRole::HighlightText
    } else if id.starts_with("color.highlight") {
        QPaletteRole::Highlight
    } else if id.starts_with("color.link") {
        QPaletteRole::Link
    } else if id.starts_with("color.mid") {
        QPaletteRole::Mid
    } else if id.starts_with("color.shadow") {
        QPaletteRole::Shadow
    } else if id.starts_with("color.bright.text") || id.starts_with("color.bright_text") {
        QPaletteRole::BrightText
    } else if id.starts_with("color.button.text") || id.starts_with("color.button_text") {
        QPaletteRole::ButtonText
    } else if id.starts_with("color.disabled") {
        QPaletteRole::Disabled
    } else if id.starts_with("color.text") {
        QPaletteRole::Text
    } else {
        // Fallback per S7.4 §4.
        QPaletteRole::WindowText
    }
}

/// Validate a hex colour string (accepts `#RRGGBB` and `#RRGGBBAA`).
fn validate_hex_color(hex: &str) -> Result<(), KdeRendererError> {
    if hex.len() != 7 && hex.len() != 9 {
        return Err(KdeRendererError::Internal(format!(
            "invalid color hex: expected #RRGGBB or #RRGGBBAA, got '{hex}'"
        )));
    }
    if !hex.starts_with('#') {
        return Err(KdeRendererError::Internal(format!(
            "invalid color hex: must start with '#', got '{hex}'"
        )));
    }
    if !hex[1..].chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KdeRendererError::Internal(format!(
            "invalid color hex: non-hex characters in '{hex}'"
        )));
    }
    Ok(())
}

// ── Font weight parsing ───────────────────────────────────────────────────────

/// Parse a font weight string into `QFontWeight`.
fn parse_font_weight(s: &str) -> Result<QFontWeight, KdeRendererError> {
    match s {
        "thin" => Ok(QFontWeight::Thin),
        "light" => Ok(QFontWeight::Light),
        "normal" => Ok(QFontWeight::Normal),
        "medium" => Ok(QFontWeight::Medium),
        "demibold" => Ok(QFontWeight::DemiBold),
        "bold" => Ok(QFontWeight::Bold),
        "black" => Ok(QFontWeight::Black),
        other => Err(KdeRendererError::Internal(format!(
            "invalid font weight '{other}'; expected one of: thin, light, normal, medium, demibold, bold, black"
        ))),
    }
}

// ── Easing curve parsing ──────────────────────────────────────────────────────

/// Parse an easing curve string into `QEasingCurve`.
fn parse_easing(s: &str) -> Result<QEasingCurve, KdeRendererError> {
    match s {
        "linear" => Ok(QEasingCurve::Linear),
        "in-quad" => Ok(QEasingCurve::InQuad),
        "out-quad" => Ok(QEasingCurve::OutQuad),
        "in-out-quad" => Ok(QEasingCurve::InOutQuad),
        "in-cubic" => Ok(QEasingCurve::InCubic),
        "out-cubic" => Ok(QEasingCurve::OutCubic),
        "in-out-cubic" => Ok(QEasingCurve::InOutCubic),
        "bezier" => Ok(QEasingCurve::Bezier),
        other => Err(KdeRendererError::Internal(format!(
            "invalid easing curve '{other}'; expected one of: linear, in-quad, out-quad, in-out-quad, in-cubic, out-cubic, in-out-cubic, bezier"
        ))),
    }
}

// ── Shape kind parsing ────────────────────────────────────────────────────────

/// Parse a shape kind string into `ShapeKind`.
fn parse_shape_kind(s: &str) -> Result<ShapeKind, KdeRendererError> {
    match s {
        "rect" => Ok(ShapeKind::Rect),
        "rounded-rect" => Ok(ShapeKind::RoundedRect),
        "circle" => Ok(ShapeKind::Circle),
        "pill" => Ok(ShapeKind::Pill),
        other => Err(KdeRendererError::Internal(format!(
            "invalid shape kind '{other}'; expected one of: rect, rounded-rect, circle, pill"
        ))),
    }
}

// ── Compilation ───────────────────────────────────────────────────────────────

/// Compile a `VisualToken` into a typed `QtRecipe` directive.
///
/// Each `VisualTokenKind` variant is parsed from `canonical_value` using a
/// kind-specific schema:
///
/// | Kind       | Schema                              | Example                            |
/// |------------|-------------------------------------|------------------------------------|
/// | Color      | hex string                          | `"#1e1e1e"`                        |
/// | Font       | `family\|pt\|weight\|italic\|mono`   | `"Noto Sans\|10\|bold\|false\|false"` |
/// | Spacing    | pixel count                         | `"16"`                             |
/// | Motion     | `durationMs\|easing`                | `"200\|out-cubic"`                 |
/// | Icon       | deferred to `compile_token_with_ctx`|                                    |
/// | Shape      | `kind\|radius_px`                   | `"rounded-rect\|8"`                |
/// | Elevation  | `z\|blur\|alpha`                    | `"4\|12\|160"`                     |
///
/// # Errors
///
/// Returns `KdeRendererError::Internal` for malformed `canonical_value` strings.
///
/// For `Icon` tokens use `compile_token_with_ctx` — this function returns
/// `Internal("icon tokens require compile_token_with_ctx")` for `Icon` kind.
#[allow(clippy::too_many_lines)]
pub fn compile_token(token: &VisualToken) -> Result<QtRecipe, KdeRendererError> {
    match token.kind {
        VisualTokenKind::Color => {
            validate_hex_color(&token.canonical_value)?;
            let role = color_role_from_id(&token.id);
            Ok(QtRecipe::Palette {
                role,
                color_hex: token.canonical_value.clone(),
            })
        }
        VisualTokenKind::Font => {
            let parts: Vec<&str> = token.canonical_value.split('|').collect();
            if parts.len() != 5 {
                return Err(KdeRendererError::Internal(format!(
                    "invalid font schema: expected 'family|pt|weight|italic|mono', got '{}'",
                    token.canonical_value
                )));
            }
            let family = parts[0].to_string();
            let point_size_eq: f32 = parts[1].parse().map_err(|_| {
                KdeRendererError::Internal(format!("invalid font point size: '{}'", parts[1]))
            })?;
            let weight = parse_font_weight(parts[2])?;
            let italic: bool = parts[3].parse().map_err(|_| {
                KdeRendererError::Internal(format!("invalid font italic flag: '{}'", parts[3]))
            })?;
            let monospace: bool = parts[4].parse().map_err(|_| {
                KdeRendererError::Internal(format!("invalid font monospace flag: '{}'", parts[4]))
            })?;
            Ok(QtRecipe::Font {
                family,
                point_size_eq,
                weight,
                italic,
                monospace,
            })
        }
        VisualTokenKind::Spacing => {
            let logical_pixels: u32 = token.canonical_value.parse().map_err(|_| {
                KdeRendererError::Internal(format!(
                    "invalid spacing value: '{}'",
                    token.canonical_value
                ))
            })?;
            Ok(QtRecipe::Spacing { logical_pixels })
        }
        VisualTokenKind::Motion => {
            let parts: Vec<&str> = token.canonical_value.split('|').collect();
            if parts.len() != 2 {
                return Err(KdeRendererError::Internal(format!(
                    "invalid motion schema: expected 'durationMs|easing', got '{}'",
                    token.canonical_value
                )));
            }
            let duration_ms: u32 = parts[0].parse().map_err(|_| {
                KdeRendererError::Internal(format!("invalid motion duration: '{}'", parts[0]))
            })?;
            let easing = parse_easing(parts[1])?;
            Ok(QtRecipe::Motion {
                duration_ms,
                easing,
            })
        }
        VisualTokenKind::Icon => Err(KdeRendererError::Internal(
            "icon tokens require compile_token_with_ctx".into(),
        )),
        VisualTokenKind::Shape => {
            let parts: Vec<&str> = token.canonical_value.split('|').collect();
            if parts.len() != 2 {
                return Err(KdeRendererError::Internal(format!(
                    "invalid shape schema: expected 'kind|radius_px', got '{}'",
                    token.canonical_value
                )));
            }
            let kind = parse_shape_kind(parts[0])?;
            let corner_radius_px: u32 = parts[1].parse().map_err(|_| {
                KdeRendererError::Internal(format!("invalid shape corner radius: '{}'", parts[1]))
            })?;
            Ok(QtRecipe::Shape {
                kind,
                corner_radius_px,
            })
        }
        VisualTokenKind::Elevation => {
            let parts: Vec<&str> = token.canonical_value.split('|').collect();
            if parts.len() != 3 {
                return Err(KdeRendererError::Internal(format!(
                    "invalid elevation schema: expected 'z|blur|alpha', got '{}'",
                    token.canonical_value
                )));
            }
            let z_order: i32 = parts[0].parse().map_err(|_| {
                KdeRendererError::Internal(format!("invalid elevation z_order: '{}'", parts[0]))
            })?;
            let shadow_blur_px: u32 = parts[1].parse().map_err(|_| {
                KdeRendererError::Internal(format!(
                    "invalid elevation shadow_blur_px: '{}'",
                    parts[1]
                ))
            })?;
            let shadow_alpha: u8 = parts[2].parse().map_err(|_| {
                KdeRendererError::Internal(format!(
                    "invalid elevation shadow_alpha: '{}'",
                    parts[2]
                ))
            })?;
            Ok(QtRecipe::Elevation {
                z_order,
                shadow_blur_px,
                shadow_alpha,
            })
        }
    }
}

/// Compile a `VisualToken` into a typed `QtRecipe` directive with icon context.
///
/// For `Icon` tokens this builds the AIOS-FS theme path and enforces
/// INV I6 (root-signed asset bundle). For all other token kinds this
/// delegates to `compile_token`.
///
/// # Errors
///
/// * `KdeRendererError::IconBundleVerificationFailed` — `ctx.root_signed` is
///   `false` and the token kind is `Icon`.
/// * `KdeRendererError::Internal` — malformed `canonical_value` for non-icon
///   tokens (delegated to `compile_token`).
pub fn compile_token_with_ctx(
    token: &VisualToken,
    ctx: &IconLookupCtx,
) -> Result<QtRecipe, KdeRendererError> {
    if token.kind == VisualTokenKind::Icon {
        if !ctx.root_signed {
            return Err(KdeRendererError::IconBundleVerificationFailed {
                theme_id: ctx.theme_id.clone(),
                reason: "not root-signed".into(),
            });
        }
        let theme_path = format!(
            "/aios/system/themes/{}/icons/{}.svg",
            ctx.theme_id, token.id
        );
        return Ok(QtRecipe::Icon {
            theme_path,
            fallback_to_breeze: false,
        });
    }
    compile_token(token)
}

// ── Shared design-token QML singleton (cross-renderer parity) ──────────────────

/// The AIOS default design tokens rendered as a QML singleton, sourced from the
/// shared `aios-design-tokens` crate.
///
/// This is the KDE renderer's consumption seam for the shared STYLE vocabulary
/// (the counterpart to the Web renderer's `css_compile::aios_default_stylesheet`).
/// Both renderers emit from the same `aios_design_tokens::TokenSet`, so the
/// color / spacing / radius / typography values are identical — parity is proven
/// by `aios-design-tokens/tests/parity.rs`. Write the returned string as a QML
/// singleton (e.g. `AiosTokens.qml`) imported by the Plasma theme.
#[must_use]
pub fn aios_default_qml_tokens(dark_theme: bool) -> String {
    let variant = if dark_theme {
        aios_design_tokens::ThemeVariant::Dark
    } else {
        aios_design_tokens::ThemeVariant::Light
    };
    aios_design_tokens::to_qml_properties(&aios_design_tokens::TokenSet::aios_default(variant))
}

#[cfg(test)]
mod design_token_seam_tests {
    use super::aios_default_qml_tokens;

    #[test]
    fn emits_qml_singleton_with_color_props() {
        let dark = aios_default_qml_tokens(true);
        assert!(dark.contains("pragma Singleton"));
        assert!(dark.contains("readonly property color colorSurface:"));
        // QML colors use #AARRGGBB (alpha first); opaque tokens start "#ff".
        assert!(dark.contains("colorSurface: \"#ff"));
        let light = aios_default_qml_tokens(false);
        assert_ne!(light, dark);
    }
}
