//! Static tests for the concrete KDE Plasma theme artifacts.
//!
//! Two guarantees:
//!  1. **Drift guard** — the committed `.colors` files under `distro/themes/kde/`
//!     are byte-identical to a fresh regeneration from the tokens. A token edit
//!     that is not regenerated fails here.
//!  2. **GOAL-1 coverage** — the KDE QML singleton (the runtime consumption seam)
//!     carries a property for *every* `ColorToken`, so the constitutional tokens
//!     (action provenance / trust / evidence, MR !24) flow to KDE automatically
//!     the moment the enum grows — no per-token wiring needed.
//!
//! Live-Plasma pixel rendering is NOT covered (no Plasma session here); see
//! `distro/themes/kde/README.md`.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use aios_design_tokens::{qml_prop_color, ColorToken};
use aios_renderer_kde::plasma_theme::aios_default_color_scheme;
use aios_renderer_kde::token_compile::aios_default_qml_tokens;
use strum::IntoEnumIterator;

/// `distro/themes/kde/<file>` resolved from this crate's manifest dir.
fn theme_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../distro/themes/kde")
        .join(file)
}

fn read_committed(file: &str) -> String {
    let path = theme_path(file);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("committed artifact {} unreadable: {e}", path.display()))
}

#[test]
fn dark_scheme_matches_committed_artifact() {
    assert_eq!(
        read_committed("aios-dark.colors"),
        aios_default_color_scheme(true),
        "aios-dark.colors is stale — regenerate: \
         cargo run -p aios-renderer-kde --bin gen-plasma-theme -- distro/themes/kde"
    );
}

#[test]
fn light_scheme_matches_committed_artifact() {
    assert_eq!(
        read_committed("aios-light.colors"),
        aios_default_color_scheme(false),
        "aios-light.colors is stale — regenerate: \
         cargo run -p aios-renderer-kde --bin gen-plasma-theme -- distro/themes/kde"
    );
}

#[test]
fn committed_scheme_carries_the_raspberry_accent() {
    // The AIOS brand accent (#ce2867 = 206,40,103) must be the selection colour.
    for file in ["aios-dark.colors", "aios-light.colors"] {
        let scheme = read_committed(file);
        let selection = scheme.split("[Colors:Selection]").nth(1).unwrap_or("");
        assert!(
            selection.contains("BackgroundNormal=206,40,103"),
            "{file}: selection must use the AIOS raspberry accent"
        );
    }
}

#[test]
fn qml_singleton_covers_every_color_token() {
    // GOAL 1: KDE consumes the FULL shared token vocabulary via to_qml_properties.
    // Every ColorToken — including the constitutional layer once MR !24 grows the
    // enum — must appear as a QML color property in both variants.
    for dark in [true, false] {
        let singleton = aios_default_qml_tokens(dark);
        for token in ColorToken::iter() {
            let prop = qml_prop_color(token);
            assert!(
                singleton.contains(&format!("readonly property color {prop}")),
                "QML singleton (dark={dark}) is missing color token {}",
                token.slug()
            );
        }
    }
}
