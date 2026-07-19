//! Generator for the committed AIOS KDE Plasma color-scheme artifacts.
//!
//! Writes `aios-light.colors` and `aios-dark.colors` into the target directory
//! (default `distro/themes/kde`) from the single source of truth,
//! `aios_design_tokens::TokenSet::aios_default`. The committed files under
//! `distro/themes/kde/` are the output of this binary; the test
//! `tests/plasma_theme.rs` regenerates in-memory and diffs to guard drift.
//!
//! Usage: `cargo run -p aios-renderer-kde --bin gen-plasma-theme -- [out-dir]`

use std::path::PathBuf;
use std::process::ExitCode;

use aios_renderer_kde::plasma_theme::aios_default_color_scheme;

fn main() -> ExitCode {
    let out_dir: PathBuf = std::env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("distro/themes/kde"), PathBuf::from);

    if let Err(err) = std::fs::create_dir_all(&out_dir) {
        eprintln!("error: cannot create {}: {err}", out_dir.display());
        return ExitCode::FAILURE;
    }

    for (dark, file) in [(false, "aios-light.colors"), (true, "aios-dark.colors")] {
        let path = out_dir.join(file);
        let contents = aios_default_color_scheme(dark);
        if let Err(err) = std::fs::write(&path, contents) {
            eprintln!("error: cannot write {}: {err}", path.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {}", path.display());
    }

    ExitCode::SUCCESS
}
