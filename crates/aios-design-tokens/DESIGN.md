# aios-design-tokens — shared visual style vocabulary (L7)

## Why this crate exists

The three L7 renderers (KDE, Web, CLI) already share a **structural** vocabulary:
the closed 19-variant `NodeKind` (S7.2 §3) guarantees every renderer builds the
same tree shape. What was missing was a shared **style** vocabulary. Today a
button's _structure_ is identical across KDE and Web, but its _color, spacing,
radius and typography_ were defined independently in each renderer — so parity
was semantic, never visual.

This crate defines the design tokens **once**, as typed values, per theme, and
gives each renderer a pure emitter. Both emitters read the same resolved values,
so "the AIOS accent blue" has exactly one definition in the whole system.

## Token taxonomy (all closed vocabularies)

Every token type is a closed Rust `enum`. A renderer asks for a **semantic
role**, never a literal value.

| Vocabulary            | Variants                                                                                                        | Resolves to                                   |
| --------------------- | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| `ColorToken` (9)      | `Surface`, `SurfaceVariant`, `TextPrimary`, `TextSecondary`, `Accent`, `Success`, `Warning`, `Danger`, `Border` | `ColorValue { r, g, b, a }` (typed bytes)     |
| `SpacingToken` (5)    | `Xs`, `Sm`, `Md`, `Lg`, `Xl`                                                                                    | `u32` logical pixels (4/8/16/24/40)           |
| `RadiusToken` (5)     | `None`, `Sm`, `Md`, `Lg`, `Full`                                                                                | `u32` logical pixels (0/4/8/16/9999)          |
| `TypographyToken` (5) | `Display`, `Heading`, `Body`, `Caption`, `Code`                                                                 | `TypographyValue { family, size_px, weight }` |
| `ThemeVariant` (2)    | `Light`, `Dark`                                                                                                 | selects which value set resolves              |

`FontFamily` (`Sans` = "Noto Sans", `Mono` = "Noto Sans Mono") is the closed
font-family role set. Concrete face names live here once.

### Why closed vocabularies

- **No drift by construction.** `TokenSet::color` resolves colors with an
  **exhaustive `match` and no wildcard arm**. Add a `ColorToken` variant and the
  crate _fails to compile_ until you give it a Light and a Dark value. The
  compiler, not a reviewer, enforces "every token is themed in every theme".
- **Semantic, not literal.** Renderers reference `TextPrimary`, never
  `"#1a1d21"`. A theme change is one edit in one file.
- **Typed source of truth.** Colors are `{r,g,b,a}` bytes, not CSS strings.
  Strings are an _output format_, produced by the emitters — never the authority.

## The single source of truth

`TokenSet::aios_default(ThemeVariant)` is the one place the AIOS theme is
defined (Light + Dark). It is a deterministic `const` function — no wall-clock,
no randomness, no I/O.

## The two emitters (pure functions over one `TokenSet`)

- `to_css_custom_properties(&TokenSet) -> String` — a `:root { --aios-color-…; … }`
  block for the **Web** renderer / Control Center. Colors as `#RRGGBBAA`.
  Selector is theme-scoped: `:root` (Light) / `:root[data-theme="dark"]` (Dark).
- `to_qml_properties(&TokenSet) -> String` — a QML `pragma Singleton` object of
  `readonly property color colorSurface: "#AARRGGBB"` … for the **KDE** Qt/QML
  bridge. Colors in QML's native alpha-first `#AARRGGBB` convention.

The two string conventions differ deliberately (CSS = `#RRGGBBAA`, QML =
`#AARRGGBB`). That is real: it is how each platform reads hex. The parity proof
is therefore about the **decoded value**, not the literal characters.

## The parity-proof mechanism

`tests/parity.rs` is the reason the crate exists. For **every `ColorToken` ×
`ThemeVariant`** it:

1. resolves the source `ColorValue` from the `TokenSet`;
2. runs both emitters;
3. extracts the color string back out of the CSS output (parsed with
   `ColorValue::from_hex`, RGBA order) and the QML output (parsed with
   `ColorValue::from_hex_argb`, ARGB order);
4. asserts each decoded value equals the source **and** the two decoded values
   equal each other (byte-equal RGBA).

`css_and_qml_colors_decode_to_identical_rgba` is the assertion that CSS↔QML
values match. A drifted emitter — wrong channel order, wrong value, a token
emitted in one output but not the other — fails this test. Supporting tests:

- `every_color_token_is_emitted_in_both_outputs` — exhaustiveness at the emitter
  boundary; iterated count must equal `ColorToken::COUNT` (strum `EnumCount`).
- `light_and_dark_actually_differ` — themes are not accidentally identical.
- `spacing_radius_typography_are_present_and_scale_correctly` — non-color tokens
  emit and the spacing scale is monotonic; closed cardinalities are pinned.
- `hex_roundtrip_is_lossless_in_both_conventions` — the two hex codecs are
  lossless and reject malformed input (no panics).

## Renderer consumption (wired seams)

Both renderers gained a **small additive** consumption function (no existing
behavior changed):

- **Web:** `aios_renderer_web::css_compile::aios_default_stylesheet(dark: bool)
-> String` → `to_css_custom_properties`.
- **KDE:** `aios_renderer_kde::token_compile::aios_default_qml_tokens(dark: bool)
-> String` → `to_qml_properties`.

Each has a unit test asserting the expected block shape. These are the seams a
deployment wires up (inject the stylesheet into the Web `<head>`; write the QML
as a Plasma-imported `AiosTokens.qml`). The KDE renderer can alternatively feed
the typed `TokenSet` values into its existing `token_compile::compile_token`
pipeline.

## Taxonomy grades (honest)

| Capability                                                     | Status       | Grade                                |
| -------------------------------------------------------------- | ------------ | ------------------------------------ |
| Closed typed token model (color/spacing/radius/typography)     | REAL         | E2 (typechecks)                      |
| Default AIOS theme, single source of truth (Light + Dark)      | REAL         | E2                                   |
| Two emitters + emitter-equivalence parity tests                | REAL         | **E3** (unit/integration tests pass) |
| Renderer consumption seams (web + kde helper fns + seam tests) | REAL         | E3                                   |
| **Pixel-identical rendering in a live KDE + live Web session** | **DEFERRED** | **E4-pending**                       |

**What "E4-pending" means, precisely.** This crate proves the two renderers are
_fed byte-identical token values_. It does **not** prove the same pixels land on
screen — that additionally requires: (a) the wired seams actually driving a live
Qt/QML surface and a live browser, and (b) a visual / E2E check (screenshot diff
or DOM/QML computed-style assertion) on a running system. That is a deployment +
E2E task, not a library guarantee, and is not claimed here.
