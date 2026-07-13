//! The two emitters — pure functions over a single `TokenSet`.
//!
//! [`to_css_custom_properties`] serves the **Web** renderer / Control Center.
//! [`to_qml_properties`] serves the **KDE** renderer's Qt/QML bridge.
//!
//! Both read the *same* resolved values from the *same* `TokenSet`. The parity
//! test (`tests/parity.rs`) proves it: it parses each emitted color back and
//! asserts byte-equal RGBA. Note the two string conventions differ on purpose —
//! CSS 8-digit hex is `#RRGGBBAA`, QML 8-digit hex is `#AARRGGBB` — so the proof
//! is about the *decoded value*, not the literal characters. A drifted emitter
//! (wrong channel order, wrong value, missing token) fails the test.
//!
//! ## CONTRACT — renderer consumption seams
//!
//! These emitters are the shared style source. Each renderer consumes as follows:
//!
//! - **Web** (`aios-renderer-web`): call
//!   [`to_css_custom_properties`] and inject the returned block into the
//!   document `<head>` (or serve it as a stylesheet) so every element resolves
//!   `var(--aios-color-*)`. A thin wrapper `css_compile::aios_default_stylesheet`
//!   exposes this (wired in this change).
//! - **KDE** (`aios-renderer-kde`): call [`to_qml_properties`] and write the
//!   result as a QML singleton (e.g. `AiosTokens.qml`) imported by the Plasma
//!   theme, OR feed the typed `TokenSet` values into the existing
//!   `token_compile::compile_token` pipeline. A thin wrapper
//!   `token_compile::aios_default_qml_tokens` exposes this (wired in this change).

use std::fmt::Write as _;

use strum::IntoEnumIterator;

use crate::color::ColorToken;
use crate::scale::{RadiusToken, SpacingToken};
use crate::theme::{ThemeVariant, TokenSet};
use crate::typography::TypographyToken;

/// CSS variable prefix — namespaced so tokens never collide with app CSS.
const CSS_PREFIX: &str = "--aios";

/// Build the CSS custom-property variable name for a color token,
/// e.g. `--aios-color-surface-variant`. Public so consumers and the parity
/// test reference names symbolically, never by fragile literals.
#[must_use]
pub fn css_var_color(token: ColorToken) -> String {
    format!("{CSS_PREFIX}-color-{}", token.slug())
}

/// Build the QML property identifier for a color token, e.g.
/// `colorSurfaceVariant`.
#[must_use]
pub fn qml_prop_color(token: ColorToken) -> String {
    camel("color", token.slug())
}

/// Emit the token set as a CSS custom-property block for the Web renderer.
///
/// The selector is theme-scoped deterministically: `Light` → `:root`,
/// `Dark` → `:root[data-theme="dark"]`, matching the theme-toggle convention.
#[must_use]
pub fn to_css_custom_properties(set: &TokenSet) -> String {
    let selector = match set.variant() {
        ThemeVariant::Light => ":root",
        ThemeVariant::Dark => r#":root[data-theme="dark"]"#,
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "/* AIOS design tokens — theme: {}. Generated from aios-design-tokens TokenSet. */",
        set.variant().slug()
    );
    let _ = writeln!(out, "{selector} {{");

    for token in ColorToken::iter() {
        let _ = writeln!(
            out,
            "  {}: {};",
            css_var_color(token),
            set.color(token).to_hex_rgba()
        );
    }
    for token in SpacingToken::iter() {
        let _ = writeln!(
            out,
            "  {CSS_PREFIX}-spacing-{}: {}px;",
            token.slug(),
            set.spacing(token)
        );
    }
    for token in RadiusToken::iter() {
        let _ = writeln!(
            out,
            "  {CSS_PREFIX}-radius-{}: {}px;",
            token.slug(),
            set.radius(token)
        );
    }
    for token in TypographyToken::iter() {
        let v = set.typography(token);
        let slug = token.slug();
        let _ = writeln!(
            out,
            "  {CSS_PREFIX}-font-{slug}-family: \"{}\";",
            v.family.face_name()
        );
        let _ = writeln!(out, "  {CSS_PREFIX}-font-{slug}-size: {}px;", v.size_px);
        let _ = writeln!(out, "  {CSS_PREFIX}-font-{slug}-weight: {};", v.weight);
    }

    out.push_str("}\n");
    out
}

/// Emit the token set as a QML singleton for the KDE renderer's Qt/QML bridge.
///
/// Colors are emitted in QML's native `#AARRGGBB` hex convention.
#[must_use]
pub fn to_qml_properties(set: &TokenSet) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "// AIOS design tokens — theme: {}. Generated from aios-design-tokens TokenSet.",
        set.variant().slug()
    );
    out.push_str("pragma Singleton\n");
    out.push_str("import QtQuick\n\n");
    out.push_str("QtObject {\n");

    for token in ColorToken::iter() {
        let _ = writeln!(
            out,
            "    readonly property color {}: \"{}\"",
            qml_prop_color(token),
            set.color(token).to_hex_argb()
        );
    }
    for token in SpacingToken::iter() {
        let _ = writeln!(
            out,
            "    readonly property int {}: {}",
            camel("spacing", token.slug()),
            set.spacing(token)
        );
    }
    for token in RadiusToken::iter() {
        let _ = writeln!(
            out,
            "    readonly property int {}: {}",
            camel("radius", token.slug()),
            set.radius(token)
        );
    }
    for token in TypographyToken::iter() {
        let v = set.typography(token);
        let slug = token.slug();
        let _ = writeln!(
            out,
            "    readonly property string {}: \"{}\"",
            camel("font", &format!("{slug}-family")),
            v.family.face_name()
        );
        let _ = writeln!(
            out,
            "    readonly property int {}: {}",
            camel("font", &format!("{slug}-size")),
            v.size_px
        );
        let _ = writeln!(
            out,
            "    readonly property int {}: {}",
            camel("font", &format!("{slug}-weight")),
            v.weight
        );
    }

    out.push_str("}\n");
    out
}

/// Convert a `prefix` + kebab-case `slug` into a camelCase identifier, e.g.
/// `("color", "surface-variant")` → `"colorSurfaceVariant"`. Deterministic,
/// panic-free.
fn camel(prefix: &str, slug: &str) -> String {
    let mut out = String::from(prefix);
    for part in slug.split('-') {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}
