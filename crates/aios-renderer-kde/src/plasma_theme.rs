//! Concrete KDE Plasma theme artifacts generated from the shared design tokens.
//!
//! This is the *materialisation* half of the KDE consumption seam. The QML
//! singleton emitted by [`crate::token_compile::aios_default_qml_tokens`]
//! (which is [`aios_design_tokens::to_qml_properties`]) gives AIOS *surfaces*
//! their tokens at runtime. This module additionally emits a **Plasma color
//! scheme** (`.colors` INI) so that the *Plasma shell itself* — panels, dialog
//! chrome, window-manager titlebars — looks like AIOS, not stock Breeze.
//!
//! Every value is derived from [`aios_design_tokens::TokenSet::aios_default`];
//! nothing here is a hand-picked hue. The AIOS raspberry accent
//! (`ColorToken::Accent` = `#ce2867`) therefore drives the selection colour and
//! focus decoration in both the light and dark schemes automatically.
//!
//! ## Mapping contract (S7.3 §8.1, S7.4 §5)
//!
//! `ColorToken` → KDE `KColorScheme` roles:
//!
//! | `ColorToken`     | Plasma role(s)                                             |
//! |------------------|------------------------------------------------------------|
//! | `Surface`        | `Colors:View`/`Window` `BackgroundNormal`                  |
//! | `SurfaceVariant` | `BackgroundAlternate`, `Colors:Button` background, `[WM]`  |
//! | `TextPrimary`    | `ForegroundNormal` (≙ `QPalette::WindowText`, per S7.4 §5) |
//! | `TextSecondary`  | `ForegroundInactive`                                       |
//! | `Accent`         | `Colors:Selection` background, `DecorationFocus/Hover`      |
//! | `Success`        | `ForegroundPositive`                                       |
//! | `Warning`        | `ForegroundNeutral`                                        |
//! | `Danger`         | `ForegroundNegative`                                       |
//! | `Border`         | window/inactive titlebar blend; also in the token dump     |
//!
//! Tokens that have no dedicated `KColorScheme` slot (and every additional
//! constitutional token — action provenance / trust / evidence — once
//! `aios-design-tokens` MR !24 lands and grows the `ColorToken` enum) are never
//! silently dropped: the generated file opens with a complete `role=R,G,B` dump
//! of `ColorToken::iter()`, and AIOS surfaces read them via the QML singleton.

use std::fmt::Write as _;

use aios_design_tokens::{ColorToken, ColorValue, ThemeVariant, TokenSet};
use strum::IntoEnumIterator;

/// Format a token colour as Plasma's `R,G,B` decimal triple (alpha dropped —
/// `KColorScheme` base roles are opaque).
fn rgb_decimal(c: ColorValue) -> String {
    format!("{},{},{}", c.r, c.g, c.b)
}

/// WCAG relative luminance of an sRGB colour in `0.0..=1.0`.
fn relative_luminance(c: ColorValue) -> f64 {
    fn linearise(channel: u8) -> f64 {
        let cs = f64::from(channel) / 255.0;
        if cs <= 0.039_28 {
            cs / 12.92
        } else {
            ((cs + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * linearise(c.r) + 0.7152 * linearise(c.g) + 0.0722 * linearise(c.b)
}

/// WCAG contrast ratio between two colours (`1.0..=21.0`).
fn contrast_ratio(a: ColorValue, b: ColorValue) -> f64 {
    let la = relative_luminance(a);
    let lb = relative_luminance(b);
    let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// Pick, from `candidates`, the colour with the greatest contrast against
/// `background`. Deterministic and panic-free; returns `background` only when
/// `candidates` is empty (never, in practice).
fn best_contrast(background: ColorValue, candidates: &[ColorValue]) -> ColorValue {
    candidates
        .iter()
        .copied()
        .max_by(|x, y| contrast_ratio(*x, background).total_cmp(&contrast_ratio(*y, background)))
        .unwrap_or(background)
}

/// The nine standard `KColorScheme` foreground/decoration keys shared by every
/// section, resolved from the semantic tokens. `foreground` and `inactive`
/// vary per section (e.g. the Selection group inverts them for contrast).
fn write_foreground_group(
    out: &mut String,
    foreground: ColorValue,
    inactive: ColorValue,
    set: &TokenSet,
) {
    let accent = set.color(ColorToken::Accent);
    let _ = writeln!(out, "ForegroundNormal={}", rgb_decimal(foreground));
    let _ = writeln!(out, "ForegroundInactive={}", rgb_decimal(inactive));
    let _ = writeln!(out, "ForegroundActive={}", rgb_decimal(accent));
    let _ = writeln!(out, "ForegroundLink={}", rgb_decimal(accent));
    let _ = writeln!(out, "ForegroundVisited={}", rgb_decimal(accent));
    let _ = writeln!(
        out,
        "ForegroundNegative={}",
        rgb_decimal(set.color(ColorToken::Danger))
    );
    let _ = writeln!(
        out,
        "ForegroundNeutral={}",
        rgb_decimal(set.color(ColorToken::Warning))
    );
    let _ = writeln!(
        out,
        "ForegroundPositive={}",
        rgb_decimal(set.color(ColorToken::Success))
    );
    let _ = writeln!(out, "DecorationFocus={}", rgb_decimal(accent));
    let _ = writeln!(out, "DecorationHover={}", rgb_decimal(accent));
}

/// Emit one `[Colors:<name>]` section with the given background pair and the
/// shared semantic foreground group.
fn write_color_section(
    out: &mut String,
    name: &str,
    background: ColorValue,
    alternate: ColorValue,
    foreground: ColorValue,
    inactive: ColorValue,
    set: &TokenSet,
) {
    let _ = writeln!(out, "\n[Colors:{name}]");
    let _ = writeln!(out, "BackgroundNormal={}", rgb_decimal(background));
    let _ = writeln!(out, "BackgroundAlternate={}", rgb_decimal(alternate));
    write_foreground_group(out, foreground, inactive, set);
}

/// The internal `ColorScheme` id (no spaces) for a variant, e.g. `AiosDark`.
#[must_use]
pub fn scheme_id(variant: ThemeVariant) -> &'static str {
    match variant {
        ThemeVariant::Light => "AiosLight",
        ThemeVariant::Dark => "AiosDark",
    }
}

/// The human-facing scheme name for a variant, e.g. `AI-OS.NET Dark`.
#[must_use]
pub fn scheme_display_name(variant: ThemeVariant) -> &'static str {
    match variant {
        ThemeVariant::Light => "AI-OS.NET Light",
        ThemeVariant::Dark => "AI-OS.NET Dark",
    }
}

/// Generate a complete, loadable KDE Plasma color scheme (`.colors` INI) from a
/// resolved [`TokenSet`].
///
/// The output is deterministic (stable section order, stable `ColorToken::iter`
/// order), which is what lets the committed artifacts under `distro/themes/kde/`
/// be diff-guarded against drift by a test. The leading comment block is a full
/// `role=R,G,B` dump of every `ColorToken`, so tokens without a dedicated
/// Plasma slot (and future constitutional tokens) are recorded, not lost.
#[must_use]
pub fn plasma_color_scheme(set: &TokenSet) -> String {
    let variant = set.variant();
    let surface = set.color(ColorToken::Surface);
    let surface_variant = set.color(ColorToken::SurfaceVariant);
    let text_primary = set.color(ColorToken::TextPrimary);
    let text_secondary = set.color(ColorToken::TextSecondary);
    let accent = set.color(ColorToken::Accent);

    let mut out = String::new();

    // ── Provenance / drift-guard header ────────────────────────────────────
    let _ = writeln!(
        out,
        "# AI-OS.NET Plasma color scheme — GENERATED from aios-design-tokens (theme: {}).",
        variant.slug()
    );
    out.push_str(
        "# Do NOT edit by hand. Source of truth: crates/aios-design-tokens (ColorToken).\n",
    );
    out.push_str(
        "# Regenerate: cargo run -p aios-renderer-kde --bin gen-plasma-theme -- distro/themes/kde\n",
    );
    out.push_str("# Full ColorToken dump (role=R,G,B) — includes tokens with no Plasma slot:\n");
    for token in ColorToken::iter() {
        let _ = writeln!(
            out,
            "#   {}={}",
            token.slug(),
            rgb_decimal(set.color(token))
        );
    }

    // ── [General] ──────────────────────────────────────────────────────────
    let _ = writeln!(out, "\n[General]");
    let _ = writeln!(out, "Name={}", scheme_display_name(variant));
    let _ = writeln!(out, "ColorScheme={}", scheme_id(variant));
    out.push_str("shadeSortColumn=true\n");

    // ── Standard colour sections ───────────────────────────────────────────
    // Content surfaces read on the primary Surface; chrome/raised elements on
    // the SurfaceVariant. Foreground is always TextPrimary, inactive is
    // TextSecondary — matching S7.4 §5 (COLOR_TEXT_PRIMARY → WindowText).
    write_color_section(
        &mut out,
        "View",
        surface,
        surface_variant,
        text_primary,
        text_secondary,
        set,
    );
    write_color_section(
        &mut out,
        "Window",
        surface,
        surface_variant,
        text_primary,
        text_secondary,
        set,
    );
    write_color_section(
        &mut out,
        "Button",
        surface_variant,
        surface,
        text_primary,
        text_secondary,
        set,
    );
    write_color_section(
        &mut out,
        "Tooltip",
        surface_variant,
        surface,
        text_primary,
        text_secondary,
        set,
    );
    write_color_section(
        &mut out,
        "Complementary",
        surface,
        surface_variant,
        text_primary,
        text_secondary,
        set,
    );
    write_color_section(
        &mut out,
        "Header",
        surface_variant,
        surface,
        text_primary,
        text_secondary,
        set,
    );

    // Selection: background IS the AIOS accent (raspberry). Foreground is the
    // token with the best WCAG contrast against the accent, so selected text
    // stays legible without hand-picking a colour.
    let selection_fg = best_contrast(accent, &[surface, text_primary]);
    write_color_section(
        &mut out,
        "Selection",
        accent,
        accent,
        selection_fg,
        selection_fg,
        set,
    );

    // ── [WM] — window-manager titlebar colours ─────────────────────────────
    let _ = writeln!(out, "\n[WM]");
    let _ = writeln!(out, "activeBackground={}", rgb_decimal(surface_variant));
    let _ = writeln!(out, "activeForeground={}", rgb_decimal(text_primary));
    let _ = writeln!(out, "activeBlend={}", rgb_decimal(accent));
    let _ = writeln!(out, "inactiveBackground={}", rgb_decimal(surface));
    let _ = writeln!(out, "inactiveForeground={}", rgb_decimal(text_secondary));
    let _ = writeln!(
        out,
        "inactiveBlend={}",
        rgb_decimal(set.color(ColorToken::Border))
    );

    out
}

/// Convenience: the AIOS default Plasma color scheme for the light or dark
/// variant, straight from `TokenSet::aios_default`.
#[must_use]
pub fn aios_default_color_scheme(dark: bool) -> String {
    let variant = if dark {
        ThemeVariant::Dark
    } else {
        ThemeVariant::Light
    };
    plasma_color_scheme(&TokenSet::aios_default(variant))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        aios_default_color_scheme, best_contrast, contrast_ratio, plasma_color_scheme, scheme_id,
    };
    use aios_design_tokens::{ColorToken, ColorValue, ThemeVariant, TokenSet};

    /// The AIOS raspberry accent must drive the selection colour in BOTH
    /// variants — proving the scheme is token-derived, not hand-picked.
    #[test]
    fn accent_maps_to_aios_raspberry_selection() {
        // #ce2867 == 206,40,103 decimal.
        for dark in [false, true] {
            let scheme = aios_default_color_scheme(dark);
            let selection = scheme.split("[Colors:Selection]").nth(1).unwrap_or("");
            assert!(
                selection.contains("BackgroundNormal=206,40,103"),
                "selection background must be the AIOS raspberry accent (dark={dark})"
            );
        }
    }

    /// The header token dump must list every `ColorToken` (forward-compatible
    /// with the constitutional tokens MR !24 adds to the enum).
    #[test]
    fn header_dumps_every_color_token() {
        use strum::IntoEnumIterator;
        let scheme = aios_default_color_scheme(true);
        for token in ColorToken::iter() {
            assert!(
                scheme.contains(&format!("#   {}=", token.slug())),
                "token {} missing from the generated dump",
                token.slug()
            );
        }
    }

    /// Light and dark schemes differ and carry the right scheme id.
    #[test]
    fn variants_are_distinct_and_named() {
        let light = plasma_color_scheme(&TokenSet::aios_default(ThemeVariant::Light));
        let dark = plasma_color_scheme(&TokenSet::aios_default(ThemeVariant::Dark));
        assert_ne!(light, dark);
        assert!(light.contains(&format!("ColorScheme={}", scheme_id(ThemeVariant::Light))));
        assert!(dark.contains(&format!("ColorScheme={}", scheme_id(ThemeVariant::Dark))));
    }

    /// White has maximal contrast against the raspberry accent, so selection
    /// text resolves to a light colour — the contrast helper is real, not a
    /// constant.
    #[test]
    fn best_contrast_picks_the_legible_token() {
        let accent = ColorValue::rgb(0xce, 0x28, 0x67);
        let white = ColorValue::rgb(0xff, 0xff, 0xff);
        let near_black = ColorValue::rgb(0x1a, 0x1d, 0x21);
        assert_eq!(best_contrast(accent, &[near_black, white]), white);
        assert!(contrast_ratio(white, accent) > contrast_ratio(near_black, accent));
    }
}
