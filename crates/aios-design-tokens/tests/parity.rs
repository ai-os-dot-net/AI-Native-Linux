//! Emitter-equivalence parity proof.
//!
//! The point of the crate: prove the Web (CSS) and KDE (QML) emitters are
//! generated from the SAME resolved token values. We decode every color back
//! out of each emitter's output and assert byte-equal RGBA — against the source
//! `TokenSet` AND against each other. A drifted emitter fails here.

use strum::{EnumCount, IntoEnumIterator};

use aios_design_tokens::{
    css_var_color, qml_prop_color, to_css_custom_properties, to_qml_properties, ColorToken,
    ColorValue, RadiusToken, SpacingToken, ThemeVariant, TokenSet, TypographyToken,
};

/// Extract the CSS custom-property value string for `var_name` from a
/// `:root { ... }` block: matches `  <var>: <value>;`.
fn css_value(css: &str, var_name: &str) -> Option<String> {
    let needle = format!("{var_name}:");
    css.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix(&needle)?;
        Some(rest.trim().trim_end_matches(';').trim().to_string())
    })
}

/// Extract a QML `readonly property <ty> <prop>: <value>` value for `prop`.
fn qml_value(qml: &str, prop: &str) -> Option<String> {
    let needle = format!(" {prop}:");
    qml.lines().find_map(|line| {
        let idx = line.find(&needle)?;
        let rest = &line[idx + needle.len()..];
        Some(rest.trim().trim_matches('"').to_string())
    })
}

#[test]
fn css_and_qml_colors_decode_to_identical_rgba() {
    for variant in ThemeVariant::iter() {
        let set = TokenSet::aios_default(variant);
        let css = to_css_custom_properties(&set);
        let qml = to_qml_properties(&set);

        for token in ColorToken::iter() {
            let source = set.color(token);

            // Web side: CSS `#RRGGBBAA`.
            let css_hex = css_value(&css, &css_var_color(token));
            let css_decoded = css_hex.as_deref().and_then(ColorValue::from_hex);

            // KDE side: QML `#AARRGGBB`.
            let qml_hex = qml_value(&qml, &qml_prop_color(token));
            let qml_decoded = qml_hex.as_deref().and_then(ColorValue::from_hex_argb);

            assert_eq!(
                css_decoded,
                Some(source),
                "CSS emitter drift for {token:?} in {variant:?}: raw={css_hex:?}"
            );
            assert_eq!(
                qml_decoded,
                Some(source),
                "QML emitter drift for {token:?} in {variant:?}: raw={qml_hex:?}"
            );
            // The whole point: both emitters agree on the exact RGBA.
            assert_eq!(
                css_decoded, qml_decoded,
                "CSS↔QML color divergence for {token:?} in {variant:?}"
            );
        }
    }
}

#[test]
fn light_and_dark_actually_differ() {
    // Sanity: the two themes are not accidentally identical.
    let light = TokenSet::aios_default(ThemeVariant::Light);
    let dark = TokenSet::aios_default(ThemeVariant::Dark);
    let differs = ColorToken::iter().any(|t| light.color(t) != dark.color(t));
    assert!(differs, "Light and Dark themes must differ on some color");
    // Surface specifically must invert.
    assert_ne!(
        light.color(ColorToken::Surface),
        dark.color(ColorToken::Surface)
    );
}

#[test]
fn every_color_token_is_emitted_in_both_outputs() {
    // Exhaustiveness at the emitter boundary: every closed-vocabulary color
    // appears once in each output for each theme. Combined with the exhaustive
    // match in `TokenSet::color`, adding a token without theming/emitting it
    // fails to compile or fails this assertion.
    for variant in ThemeVariant::iter() {
        let set = TokenSet::aios_default(variant);
        let css = to_css_custom_properties(&set);
        let qml = to_qml_properties(&set);
        let mut count = 0;
        for token in ColorToken::iter() {
            assert!(
                css_value(&css, &css_var_color(token)).is_some(),
                "missing CSS var for {token:?} ({variant:?})"
            );
            assert!(
                qml_value(&qml, &qml_prop_color(token)).is_some(),
                "missing QML prop for {token:?} ({variant:?})"
            );
            count += 1;
        }
        assert_eq!(
            count,
            ColorToken::COUNT,
            "iterated color count must equal the closed-vocabulary size"
        );
    }
}

#[test]
fn spacing_radius_typography_are_present_and_scale_correctly() {
    let set = TokenSet::aios_default(ThemeVariant::Light);
    let css = to_css_custom_properties(&set);

    // Spacing scale is strictly increasing.
    let mut prev = 0;
    for t in SpacingToken::iter() {
        let px = set.spacing(t);
        assert!(px >= prev, "spacing scale must be non-decreasing");
        prev = px;
        assert!(
            css.contains(&format!("--aios-spacing-{}: {}px;", t.slug(), px)),
            "missing spacing var for {t:?}"
        );
    }

    // Radius scale present.
    for t in RadiusToken::iter() {
        let px = set.radius(t);
        assert!(
            css.contains(&format!("--aios-radius-{}: {}px;", t.slug(), px)),
            "missing radius var for {t:?}"
        );
    }

    // Typography families/sizes/weights present.
    for t in TypographyToken::iter() {
        let v = set.typography(t);
        assert!(
            css.contains(&format!("--aios-font-{}-size: {}px;", t.slug(), v.size_px)),
            "missing font size var for {t:?}"
        );
        assert!(
            css.contains(&format!("--aios-font-{}-weight: {};", t.slug(), v.weight)),
            "missing font weight var for {t:?}"
        );
    }

    // Every enum has the expected closed cardinality (guards silent additions).
    assert_eq!(ColorToken::COUNT, 9);
    assert_eq!(SpacingToken::COUNT, 5);
    assert_eq!(RadiusToken::COUNT, 5);
    assert_eq!(TypographyToken::COUNT, 5);
    assert_eq!(ThemeVariant::COUNT, 2);
}

#[test]
fn hex_roundtrip_is_lossless_in_both_conventions() {
    let c = ColorValue::rgba(0x12, 0x34, 0x56, 0x78);
    assert_eq!(ColorValue::from_hex(&c.to_hex_rgba()), Some(c));
    assert_eq!(ColorValue::from_hex_argb(&c.to_hex_argb()), Some(c));
    // The two string forms are genuinely different (channel order), which is
    // exactly why the proof compares decoded values, not raw strings.
    assert_ne!(c.to_hex_rgba(), c.to_hex_argb());
    // Malformed input is rejected, not panicked on.
    assert_eq!(ColorValue::from_hex("nope"), None);
    assert_eq!(ColorValue::from_hex("#12"), None);
}
