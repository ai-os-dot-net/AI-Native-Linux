//! Write the committed Web-renderer token stylesheet from the shared tokens.
//!
//! Run with:
//! `cargo run -p aios-renderer-web --example generate-tokens-css`
//!
//! It emits [`aios_renderer_web::generated_tokens_css`] to
//! `web-app/app/aios-tokens.css` (relative to this crate). The generated file
//! is committed; `tests/token_css_generated.rs` fails if it drifts from a fresh
//! generation, so this example is the only sanctioned way to update it.

use std::path::Path;

fn main() -> std::io::Result<()> {
    let target =
        Path::new(env!("CARGO_MANIFEST_DIR")).join(aios_renderer_web::GENERATED_TOKENS_CSS_PATH);
    let css = aios_renderer_web::generated_tokens_css();
    std::fs::write(&target, css.as_bytes())?;
    println!("wrote {} ({} bytes)", target.display(), css.len());
    Ok(())
}
