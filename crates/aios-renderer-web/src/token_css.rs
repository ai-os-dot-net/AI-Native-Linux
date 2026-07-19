//! Deterministic Web-renderer token stylesheet generation (S7.5 §8.2 seam).
//!
//! The Next.js front-end (`web-app/`) cannot depend on the Rust crate at build
//! time, so it consumes a **committed, generated** CSS file. This module is the
//! single generator for that file: it composes the shared
//! [`crate::css_compile::aios_default_stylesheet`] output (which itself emits
//! from the one `aios_design_tokens::TokenSet`) into the exact byte sequence
//! that must live at [`GENERATED_TOKENS_CSS_PATH`].
//!
//! Two consumers call [`generated_tokens_css`] so the file can never drift from
//! the tokens:
//!
//! * `examples/generate-tokens-css.rs` — writes the file.
//! * `tests/token_css_generated.rs` — asserts the committed file is byte-equal
//!   to a fresh generation. If someone edits a token without regenerating, that
//!   test fails.
//!
//! ## Theme selection
//!
//! * `:root` — light values (the default).
//! * `:root[data-theme="dark"]` — dark values, applied by the theme toggle.
//! * `@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) }`
//!   — the **same** generated dark values, applied automatically when the OS
//!   prefers dark and the user has not explicitly chosen a theme. The block is
//!   re-scoped from the generated dark block, not hand-authored, so it cannot
//!   diverge from the tokens.

use crate::css_compile::aios_default_stylesheet;

/// Repository-relative path of the committed generated stylesheet.
pub const GENERATED_TOKENS_CSS_PATH: &str = "web-app/app/aios-tokens.css";

/// Build the complete generated token stylesheet as a single deterministic
/// string.
///
/// The output carries a header note, the light `:root` block, the dark
/// `:root[data-theme="dark"]` block, and a `prefers-color-scheme: dark` block
/// carrying the same dark values for the no-explicit-theme case.
#[must_use]
pub fn generated_tokens_css() -> String {
    let light = aios_default_stylesheet(false);
    let dark = aios_default_stylesheet(true);
    let auto_dark = prefers_dark_block(&dark);

    let mut out = String::new();
    out.push_str(
        "/* GENERATED FILE — do not edit by hand.\n\
         * Source of truth: crate `aios-design-tokens` via\n\
         * `aios_renderer_web::css_compile::aios_default_stylesheet`.\n\
         * Regenerate: `cargo run -p aios-renderer-web --example generate-tokens-css`.\n\
         * Drift is guarded by `tests/token_css_generated.rs`. */\n\n",
    );
    out.push_str(&light);
    out.push('\n');
    out.push_str(&dark);
    out.push('\n');
    out.push_str(&auto_dark);
    out
}

/// Re-scope the generated dark block (`:root[data-theme="dark"] { … }`) into a
/// `prefers-color-scheme: dark` media query that targets roots without an
/// explicit `data-theme`. Reuses the generated declarations verbatim so the
/// automatic-dark values are exactly the toggle-dark values.
fn prefers_dark_block(dark: &str) -> String {
    // The dark block is `…comment…\n:root[data-theme="dark"] {\n  <decls>\n}\n`.
    // Extract the declaration body between the first `{` and the last `}`.
    // `aios_default_stylesheet` always emits both braces; if that ever changes,
    // emit nothing rather than panic (the crate denies `expect()`/`unwrap()`).
    let (Some(open), Some(close)) = (dark.find('{'), dark.rfind('}')) else {
        return String::new();
    };
    let decls = &dark[open + 1..close];

    let mut out = String::new();
    out.push_str(
        "/* AIOS design tokens — prefers-color-scheme: dark (no explicit data-theme). */\n",
    );
    out.push_str("@media (prefers-color-scheme: dark) {\n");
    out.push_str("  :root:not([data-theme=\"light\"]) {");
    out.push_str(decls);
    out.push_str("  }\n}\n");
    out
}
