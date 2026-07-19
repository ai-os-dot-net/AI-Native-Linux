//! Anti-drift guard: the committed `web-app/app/aios-tokens.css` must be
//! byte-equal to a fresh generation from the shared `aios-design-tokens` crate.
//!
//! If a token value changes (or a token is added) without regenerating the
//! stylesheet, this test fails — the Web renderer can never silently diverge
//! from the tokens the KDE renderer emits from.
//!
//! To fix a failure, regenerate:
//! `cargo run -p aios-renderer-web --example generate-tokens-css`

use std::path::Path;

use aios_renderer_web::{generated_tokens_css, GENERATED_TOKENS_CSS_PATH};

#[test]
fn committed_tokens_css_matches_fresh_generation() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(GENERATED_TOKENS_CSS_PATH);
    let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "committed generated stylesheet missing at {}: {e}. \
             Run `cargo run -p aios-renderer-web --example generate-tokens-css`.",
            path.display()
        )
    });
    let fresh = generated_tokens_css();
    assert_eq!(
        on_disk,
        fresh,
        "{} is stale — regenerate with \
         `cargo run -p aios-renderer-web --example generate-tokens-css`",
        path.display()
    );
}

#[test]
fn generated_css_carries_all_three_theme_scopes() {
    let css = generated_tokens_css();
    assert!(css.contains(":root {"), "light :root block missing");
    assert!(
        css.contains(r#":root[data-theme="dark"] {"#),
        "explicit dark toggle block missing"
    );
    assert!(
        css.contains("@media (prefers-color-scheme: dark)"),
        "automatic prefers-color-scheme dark block missing"
    );
    // A known base token role must be present so the stylesheet is non-empty
    // and actually carries the shared vocabulary.
    assert!(
        css.contains("--aios-color-surface:"),
        "expected shared color token --aios-color-surface"
    );
}
