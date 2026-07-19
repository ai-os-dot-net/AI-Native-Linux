# AIOS KDE Plasma theme artifacts

Concrete KDE Plasma theme identity for the AIOS desktop, **generated from the
shared design tokens** (`crates/aios-design-tokens`) — not hand-picked. This is
the materialisation of the KDE side of the cross-renderer style vocabulary
(spec `002.AI-OS.NET--SPECREV.2/L7_Interaction_Renderers/03_visual_language.md`
§4/§8.1, `04_kde_renderer.md` §5).

## Contents

| Path                | What it is                                                               |
| ------------------- | ------------------------------------------------------------------------ |
| `aios-light.colors` | Plasma `KColorScheme` INI — light variant (generated)                    |
| `aios-dark.colors`  | Plasma `KColorScheme` INI — dark variant (generated)                     |
| `aios-lookandfeel/` | Plasma `Look-and-Feel` package skeleton that binds the AIOS color scheme |

## How they are generated (do not hand-edit the `.colors` files)

Both `.colors` files are emitted by the generator in `aios-renderer-kde` from
`aios_design_tokens::TokenSet::aios_default(variant)`, the single source of
truth shared with the Web renderer:

```bash
cargo run -p aios-renderer-kde --bin gen-plasma-theme -- distro/themes/kde
```

The mapping (`ColorToken` → `KColorScheme` role) lives in
`crates/aios-renderer-kde/src/plasma_theme.rs`. The AIOS raspberry accent
(`ColorToken::Accent` = `#ce2867` = `206,40,103`) drives the selection colour
and focus decoration in both variants.

Drift is guarded: `crates/aios-renderer-kde/tests/plasma_theme.rs` regenerates
in-memory and byte-diffs against the committed files, so a token change that is
not regenerated fails CI.

Every `ColorToken` — including the constitutional action-provenance / trust /
evidence tokens added by `aios-design-tokens` MR !24 once it lands — is dumped
in the leading comment block of each `.colors` file, so no token is silently
lost. AIOS _surfaces_ additionally consume all tokens through the QML singleton
(`aios_renderer_kde::token_compile::aios_default_qml_tokens`).

## Installation (reference, not run here)

```bash
install -Dm644 aios-dark.colors  ~/.local/share/color-schemes/AiosDark.colors
install -Dm644 aios-light.colors ~/.local/share/color-schemes/AiosLight.colors
cp -r aios-lookandfeel ~/.local/share/plasma/look-and-feel/net.ai-os.lookandfeel.aios
```

## Evidence status

- **Generated + static-tested (E3):** the artifacts are emitted deterministically
  from the tokens and diff-guarded by `tests/plasma_theme.rs`.
- **UNVERIFIED (E4-pending):** pixel-accurate rendering in a **live KDE Plasma
  session** is not proven here (no Plasma session in this environment). Applying
  the scheme/Look-and-Feel on a real desktop and visually confirming the AIOS
  palette remains a deployment task.
