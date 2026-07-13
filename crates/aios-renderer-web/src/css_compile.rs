//! `VisualToken` → CSS custom property mapping (S7.5 §8.2).
//!
//! Mirror of `aios-renderer-kde`'s `QtRecipe` (T-130) but emitting CSS custom
//! properties for injection into `:root {}` blocks served by the Web renderer.
//!
//! Each `VisualToken` family maps to a `CssRecipe` variant; the recipe is then
//! assembled into a CSS custom property block via `recipe_to_css_block`.

use crate::error::WebRendererError;
use aios_renderer_kde::{VisualToken, VisualTokenKind};

// ── CssEasing ─────────────────────────────────────────────────────────────────

/// CSS easing function vocabulary (S7.5 §8.2.1).
///
/// Mirrors the easing vocabulary used in KDE's `QtRecipe` for motion tokens.
/// `CubicBezier` carries four control-point ordinates in CSS order (x1, y1,
/// x2, y2).
#[derive(Debug, Clone, PartialEq)]
pub enum CssEasing {
    /// `linear` — constant speed throughout.
    Linear,
    /// `ease-in` — slow start, accelerates.
    EaseIn,
    /// `ease-out` — fast start, decelerates.
    EaseOut,
    /// `ease-in-out` — slow start and end.
    EaseInOut,
    /// `cubic-bezier(x1, y1, x2, y2)` — custom curve.
    CubicBezier(f32, f32, f32, f32),
}

impl CssEasing {
    /// Render the easing function as a CSS `<easing-function>` value.
    #[must_use]
    pub fn to_css_value(&self) -> String {
        match self {
            Self::Linear => "linear".into(),
            Self::EaseIn => "ease-in".into(),
            Self::EaseOut => "ease-out".into(),
            Self::EaseInOut => "ease-in-out".into(),
            Self::CubicBezier(x1, y1, x2, y2) => {
                format!("cubic-bezier({x1},{y1},{x2},{y2})")
            }
        }
    }
}

// ── WebShapeKind ──────────────────────────────────────────────────────────────

/// Web renderer shape kind vocabulary (S7.5 §8.2.2).
///
/// Mirrors the shape vocabulary used in KDE's `QtRecipe`. Each variant maps to
/// a CSS `border-radius` expression in the compiled custom property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebShapeKind {
    /// Square corners — `border-radius: 0`.
    Rect,
    /// Rounded corners with a given radius in pixels.
    RoundedRect,
    /// Fully circular — `border-radius: 50%`.
    Circle,
    /// Pill shape — `border-radius: 9999px`.
    Pill,
}

impl WebShapeKind {
    /// Render the shape as a CSS `border-radius` value.
    #[must_use]
    pub fn to_css_border_radius(&self, radius_px: u32) -> String {
        match self {
            Self::Rect => "0".into(),
            Self::RoundedRect => format!("{radius_px}px"),
            Self::Circle => "50%".into(),
            Self::Pill => "9999px".into(),
        }
    }
}

// ── WebIconLookupCtx ──────────────────────────────────────────────────────────

/// Context required for icon-token compilation (S7.5 §8.2.3).
///
/// Enforces INV I6: icon tokens require a root-signed asset bundle. When
/// `root_signed` is `false`, icon token compilation fails with
/// `IconBundleVerificationFailed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebIconLookupCtx {
    /// Active theme identifier (e.g. `"aios-dark"`).
    pub theme_id: String,
    /// Whether the served icon bundle carries a root-signed integrity hash.
    pub root_signed: bool,
}

// ── CssRecipe ─────────────────────────────────────────────────────────────────

/// CSS recipe for a single `VisualToken` (S7.5 §8.2 table).
///
/// Seven closed variants — one per `VisualTokenKind` family. Each variant
/// carries enough information for `recipe_to_css_block` to emit one or more
/// CSS custom properties inside a `:root {}` block.
#[derive(Debug, Clone, PartialEq)]
pub enum CssRecipe {
    /// A raw CSS custom property assignment (e.g. `--aios-color-foo: #abc;`).
    Variable {
        /// CSS custom property name (e.g. `--aios-color-foo`).
        property: String,
        /// CSS value (e.g. `#aabbcc`).
        value: String,
    },
    /// Font family, size, weight, italic flag, and monospace flag.
    Font {
        /// Font family name (e.g. `"Inter"`).
        family: String,
        /// Font size in pixels.
        size_px: u32,
        /// Font weight (100–900).
        weight: u32,
        /// Whether italic style is enabled.
        italic: bool,
        /// Whether monospace variant is requested.
        mono: bool,
    },
    /// Spacing token — single pixel value mapped to a custom property.
    Spacing {
        /// CSS custom property name.
        property: String,
        /// Spacing value in pixels.
        value_px: u32,
    },
    /// Motion token — transition duration and easing curve.
    Motion {
        /// CSS custom property base name.
        property: String,
        /// Transition duration in milliseconds.
        duration_ms: u32,
        /// CSS easing function.
        easing: CssEasing,
    },
    /// Icon token — glyph identifier mapped to a custom property.
    Icon {
        /// CSS custom property name.
        property: String,
        /// Icon glyph identifier (e.g. `"xmark"`).
        glyph_id: String,
    },
    /// Shape token — border-radius style and pixel radius.
    Shape {
        /// CSS custom property name.
        property: String,
        /// Shape kind (rect, rounded-rect, circle, pill).
        kind: WebShapeKind,
        /// Border radius in pixels (meaning varies by kind).
        radius_px: u32,
    },
    /// Elevation token — z-index, blur radius, and opacity.
    Elevation {
        /// CSS custom property base name.
        property: String,
        /// Z-index value.
        z: i32,
        /// Box-shadow blur radius in pixels.
        blur_px: u32,
        /// Shadow opacity (0.0–1.0).
        alpha: f32,
    },
}

// ── CSS property name derivation ──────────────────────────────────────────────

/// Convert a `VisualToken::id` (dot-delimited, e.g. `"color.window.background"`)
/// into a CSS custom property name (`"--aios-color-window-background"`).
fn token_id_to_css_property(token_id: &str) -> String {
    format!("--aios-{}", token_id.replace('.', "-"))
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

fn parse_u32(value: &str, label: &str) -> Result<u32, WebRendererError> {
    value
        .parse::<u32>()
        .map_err(|_| WebRendererError::Internal(format!("invalid {label}: {value}")))
}

fn parse_i32(value: &str, label: &str) -> Result<i32, WebRendererError> {
    value
        .parse::<i32>()
        .map_err(|_| WebRendererError::Internal(format!("invalid {label}: {value}")))
}

fn parse_f32(value: &str, label: &str) -> Result<f32, WebRendererError> {
    value
        .parse::<f32>()
        .map_err(|_| WebRendererError::Internal(format!("invalid {label}: {value}")))
}

fn validate_hex_color(value: &str) -> Result<String, WebRendererError> {
    let hex = value.strip_prefix('#').unwrap_or(value);
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(WebRendererError::Internal(format!(
            "invalid hex color: {value}"
        )));
    }
    Ok(format!("#{hex}"))
}

fn parse_easing(value: &str) -> Result<CssEasing, WebRendererError> {
    match value {
        "linear" => Ok(CssEasing::Linear),
        "ease-in" => Ok(CssEasing::EaseIn),
        "ease-out" => Ok(CssEasing::EaseOut),
        "ease-in-out" => Ok(CssEasing::EaseInOut),
        other if other.starts_with("cubic-bezier(") => {
            let inner = other
                .strip_prefix("cubic-bezier(")
                .and_then(|s| s.strip_suffix(')'))
                .ok_or_else(|| WebRendererError::Internal(format!("invalid easing: {value}")))?;
            let parts: Vec<&str> = inner.split(',').collect();
            if parts.len() != 4 {
                return Err(WebRendererError::Internal(format!(
                    "invalid easing: {value}"
                )));
            }
            let x1 = parse_f32(parts[0].trim(), "easing x1")?;
            let y1 = parse_f32(parts[1].trim(), "easing y1")?;
            let x2 = parse_f32(parts[2].trim(), "easing x2")?;
            let y2 = parse_f32(parts[3].trim(), "easing y2")?;
            Ok(CssEasing::CubicBezier(x1, y1, x2, y2))
        }
        _ => Err(WebRendererError::Internal(format!(
            "invalid easing: {value}"
        ))),
    }
}

fn parse_shape_kind(value: &str) -> Result<WebShapeKind, WebRendererError> {
    match value {
        "rect" => Ok(WebShapeKind::Rect),
        "rounded-rect" => Ok(WebShapeKind::RoundedRect),
        "circle" => Ok(WebShapeKind::Circle),
        "pill" => Ok(WebShapeKind::Pill),
        _ => Err(WebRendererError::Internal(format!(
            "invalid shape kind: {value}"
        ))),
    }
}

// ── Token compilation ────────────────────────────────────────────────────────

/// Compile a single `VisualToken` into a `CssRecipe` without icon-context
/// validation.
///
/// Icon tokens compiled through this path always succeed — no INV I6 check is
/// performed. Use [`compile_token_to_css_with_ctx`] when icon bundle integrity
/// verification is required.
///
/// # Errors
///
/// Returns `WebRendererError::Internal` when the `canonical_value` does not
/// conform to the expected parse schema for the token's kind.
pub fn compile_token_to_css(token: &VisualToken) -> Result<CssRecipe, WebRendererError> {
    let property = token_id_to_css_property(&token.id);
    let value = &token.canonical_value;

    match token.kind {
        VisualTokenKind::Color => {
            let hex = validate_hex_color(value)?;
            Ok(CssRecipe::Variable {
                property,
                value: hex,
            })
        }
        VisualTokenKind::Font => {
            // Parse schema: "family|size_px|weight|italic|mono"
            let parts: Vec<&str> = value.split('|').collect();
            if parts.len() != 5 {
                return Err(WebRendererError::Internal(format!(
                    "invalid font value: {value}"
                )));
            }
            let family = parts[0].to_string();
            let size_px = parse_u32(parts[1], "font size_px")?;
            let weight = parse_u32(parts[2], "font weight")?;
            let italic = parts[3] == "true";
            let mono = parts[4] == "true";
            Ok(CssRecipe::Font {
                family,
                size_px,
                weight,
                italic,
                mono,
            })
        }
        VisualTokenKind::Spacing => {
            let value_px = parse_u32(value, "spacing size_px")?;
            Ok(CssRecipe::Spacing { property, value_px })
        }
        VisualTokenKind::Motion => {
            // Parse schema: "durationMs|easing"
            let parts: Vec<&str> = value.split('|').collect();
            if parts.len() != 2 {
                return Err(WebRendererError::Internal(format!(
                    "invalid motion value: {value}"
                )));
            }
            let duration_ms = parse_u32(parts[0], "motion durationMs")?;
            let easing = parse_easing(parts[1])?;
            Ok(CssRecipe::Motion {
                property,
                duration_ms,
                easing,
            })
        }
        VisualTokenKind::Icon => {
            let glyph_id = value.clone();
            Ok(CssRecipe::Icon { property, glyph_id })
        }
        VisualTokenKind::Shape => {
            // Parse schema: "kind|radius_px"
            let parts: Vec<&str> = value.split('|').collect();
            if parts.len() != 2 {
                return Err(WebRendererError::Internal(format!(
                    "invalid shape value: {value}"
                )));
            }
            let kind = parse_shape_kind(parts[0])?;
            let radius_px = parse_u32(parts[1], "shape radius_px")?;
            Ok(CssRecipe::Shape {
                property,
                kind,
                radius_px,
            })
        }
        VisualTokenKind::Elevation => {
            // Parse schema: "z|blur|alpha"
            let parts: Vec<&str> = value.split('|').collect();
            if parts.len() != 3 {
                return Err(WebRendererError::Internal(format!(
                    "invalid elevation value: {value}"
                )));
            }
            let z = parse_i32(parts[0], "elevation z")?;
            let blur_px = parse_u32(parts[1], "elevation blur")?;
            let alpha = parse_f32(parts[2], "elevation alpha")?;
            Ok(CssRecipe::Elevation {
                property,
                z,
                blur_px,
                alpha,
            })
        }
    }
}

/// Compile a single `VisualToken` into a `CssRecipe` with icon-context
/// validation (INV I6, S7.5 §8.2.3).
///
/// When the token kind is `Icon` and `ctx.root_signed` is `false`, this
/// function returns `WebRendererError::IconBundleVerificationFailed`.
///
/// # Errors
///
/// * `WebRendererError::Internal` — parse-schema violation (same as
///   [`compile_token_to_css`]).
/// * `WebRendererError::IconBundleVerificationFailed` — INV I6: the icon bundle
///   is not root-signed and an icon token was presented.
pub fn compile_token_to_css_with_ctx(
    token: &VisualToken,
    ctx: &WebIconLookupCtx,
) -> Result<CssRecipe, WebRendererError> {
    if token.kind == VisualTokenKind::Icon && !ctx.root_signed {
        return Err(WebRendererError::IconBundleVerificationFailed {
            theme_id: ctx.theme_id.clone(),
            reason: "icon bundle not root-signed; INV I6 requires root-signed asset bundle".into(),
        });
    }
    compile_token_to_css(token)
}

// ── CSS block assembly ────────────────────────────────────────────────────────

/// Assemble a `:root { ... }` CSS custom-property block from a slice of
/// `CssRecipe` values.
///
/// Each recipe emits one or more CSS custom property declarations. The result
/// is a single string suitable for injection into a `<style>` element or a
/// standalone `.css` file served by the Web renderer.
///
/// # Example
///
/// ```rust
/// # use aios_renderer_web::css_compile::*;
/// let recipes = vec![
///     CssRecipe::Variable {
///         property: "--aios-color-foo".into(),
///         value: "#aabbcc".into(),
///     },
/// ];
/// let block = recipe_to_css_block(&recipes);
/// assert!(block.contains(":root {"));
/// assert!(block.contains("--aios-color-foo: #aabbcc;"));
/// ```
#[must_use]
pub fn recipe_to_css_block(recipes: &[CssRecipe]) -> String {
    let mut lines = Vec::with_capacity(recipes.len() + 2);
    lines.push(":root {".to_string());

    for recipe in recipes {
        match recipe {
            CssRecipe::Variable { property, value } => {
                lines.push(format!("  {property}: {value};"));
            }
            CssRecipe::Font {
                family,
                size_px,
                weight,
                italic,
                mono,
            } => {
                let base_prop = &family.replace(' ', "-").to_lowercase();
                lines.push(format!("  --aios-font-{base_prop}-family: \"{family}\";"));
                lines.push(format!("  --aios-font-{base_prop}-size: {size_px}px;"));
                lines.push(format!("  --aios-font-{base_prop}-weight: {weight};"));
                lines.push(format!(
                    "  --aios-font-{base_prop}-style: {};",
                    if *italic { "italic" } else { "normal" }
                ));
                lines.push(format!(
                    "  --aios-font-{base_prop}-mono: {};",
                    if *mono { "1" } else { "0" }
                ));
            }
            CssRecipe::Spacing { property, value_px } => {
                lines.push(format!("  {property}: {value_px}px;"));
            }
            CssRecipe::Motion {
                property,
                duration_ms,
                easing,
            } => {
                lines.push(format!("  {property}-duration: {duration_ms}ms;"));
                lines.push(format!("  {property}-easing: {};", easing.to_css_value()));
            }
            CssRecipe::Icon { property, glyph_id } => {
                lines.push(format!("  {property}: \"{glyph_id}\";"));
            }
            CssRecipe::Shape {
                property,
                kind,
                radius_px,
            } => {
                lines.push(format!(
                    "  {property}: {};",
                    kind.to_css_border_radius(*radius_px)
                ));
            }
            CssRecipe::Elevation {
                property,
                z,
                blur_px,
                alpha,
            } => {
                lines.push(format!("  {property}-z: {z};"));
                lines.push(format!("  {property}-blur: {blur_px}px;"));
                lines.push(format!("  {property}-alpha: {alpha};"));
            }
        }
    }

    lines.push("}".to_string());
    lines.join("\n")
}

// ── Shared design-token stylesheet (cross-renderer parity) ─────────────────────

/// The AIOS default design-token stylesheet as CSS custom properties, sourced
/// from the shared `aios-design-tokens` crate.
///
/// This is the Web renderer's consumption seam for the shared STYLE vocabulary
/// (the counterpart to KDE's `token_compile::aios_default_qml_tokens`). Both
/// renderers emit from the same [`aios_design_tokens::TokenSet`], so the color /
/// spacing / radius / typography values are identical — parity is proven by
/// `aios-design-tokens/tests/parity.rs`. Inject the returned block into the
/// document `<head>` (or serve it) so elements resolve `var(--aios-color-*)`.
#[must_use]
pub fn aios_default_stylesheet(dark_theme: bool) -> String {
    let variant = if dark_theme {
        aios_design_tokens::ThemeVariant::Dark
    } else {
        aios_design_tokens::ThemeVariant::Light
    };
    aios_design_tokens::to_css_custom_properties(&aios_design_tokens::TokenSet::aios_default(
        variant,
    ))
}

#[cfg(test)]
mod design_token_seam_tests {
    use super::aios_default_stylesheet;

    #[test]
    fn emits_root_block_with_aios_vars() {
        let light = aios_default_stylesheet(false);
        assert!(light.contains(":root {"));
        assert!(light.contains("--aios-color-surface:"));
        let dark = aios_default_stylesheet(true);
        assert!(dark.contains(r#":root[data-theme="dark"]"#));
        // Light and dark surfaces differ (the point of theming).
        assert_ne!(light, dark);
    }
}
