//! Theme variants and the `TokenSet` that resolves every token to a concrete,
//! typed value.
//!
//! `TokenSet::aios_default(variant)` is the **one source of truth** for the AIOS
//! theme. Both emitters (`crate::emit`) are pure functions over the value this
//! returns, so a color can only be defined in one place.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

use crate::color::{ColorToken, ColorValue};
use crate::scale::{RadiusToken, SpacingToken};
use crate::typography::{FontFamily, TypographyToken, TypographyValue};

/// The two theme variants every AIOS surface must support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
pub enum ThemeVariant {
    /// Light theme.
    Light,
    /// Dark theme.
    Dark,
}

impl ThemeVariant {
    /// Stable slug (`light` / `dark`) used in comments and `data-theme` hooks.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

/// A fully-resolved set of token values for one theme variant.
///
/// The resolver functions use **exhaustive** matches with no wildcard arm:
/// adding a variant to any token enum fails to compile until it is given a
/// value here. That is the compile-time half of "the vocabulary is closed and
/// exhaustively themed"; the parity test is the run-time half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenSet {
    variant: ThemeVariant,
}

impl TokenSet {
    /// The default AIOS theme for a given variant — the single source of truth.
    #[must_use]
    pub const fn aios_default(variant: ThemeVariant) -> Self {
        Self { variant }
    }

    /// Which variant this set resolves.
    #[must_use]
    pub const fn variant(&self) -> ThemeVariant {
        self.variant
    }

    /// Resolve a color role to its concrete RGBA value for this theme.
    ///
    /// Total function (every `ColorToken` in both variants is covered); this is
    /// why a renderer can never ask for an unthemed color.
    #[must_use]
    pub const fn color(&self, token: ColorToken) -> ColorValue {
        match self.variant {
            ThemeVariant::Light => Self::color_light(token),
            ThemeVariant::Dark => Self::color_dark(token),
        }
    }

    const fn color_light(token: ColorToken) -> ColorValue {
        match token {
            ColorToken::Surface => ColorValue::rgb(0xff, 0xff, 0xff),
            ColorToken::SurfaceVariant => ColorValue::rgb(0xf2, 0xf4, 0xf7),
            ColorToken::TextPrimary => ColorValue::rgb(0x1a, 0x1d, 0x21),
            ColorToken::TextSecondary => ColorValue::rgb(0x5a, 0x62, 0x6e),
            ColorToken::Accent => ColorValue::rgb(0x2f, 0x6f, 0xeb),
            ColorToken::Success => ColorValue::rgb(0x1f, 0x9d, 0x55),
            ColorToken::Warning => ColorValue::rgb(0xc4, 0x7f, 0x17),
            ColorToken::Danger => ColorValue::rgb(0xd5, 0x37, 0x2e),
            ColorToken::Border => ColorValue::rgb(0xd7, 0xdc, 0xe2),
        }
    }

    const fn color_dark(token: ColorToken) -> ColorValue {
        match token {
            ColorToken::Surface => ColorValue::rgb(0x16, 0x19, 0x1d),
            ColorToken::SurfaceVariant => ColorValue::rgb(0x21, 0x26, 0x2d),
            ColorToken::TextPrimary => ColorValue::rgb(0xec, 0xef, 0xf3),
            ColorToken::TextSecondary => ColorValue::rgb(0x9a, 0xa4, 0xb1),
            ColorToken::Accent => ColorValue::rgb(0x4f, 0x8b, 0xff),
            ColorToken::Success => ColorValue::rgb(0x3f, 0xb9, 0x68),
            ColorToken::Warning => ColorValue::rgb(0xe0, 0xa3, 0x3a),
            ColorToken::Danger => ColorValue::rgb(0xf0, 0x56, 0x4b),
            ColorToken::Border => ColorValue::rgb(0x2d, 0x33, 0x3b),
        }
    }

    /// Resolve a spacing step to logical pixels (theme-independent).
    #[must_use]
    pub const fn spacing(&self, token: SpacingToken) -> u32 {
        token.pixels()
    }

    /// Resolve a radius step to logical pixels (theme-independent).
    #[must_use]
    pub const fn radius(&self, token: RadiusToken) -> u32 {
        token.pixels()
    }

    /// Resolve a typography role to its concrete value (theme-independent
    /// metrics; contrast is carried by the color tokens, not the type scale).
    #[must_use]
    pub const fn typography(&self, token: TypographyToken) -> TypographyValue {
        match token {
            TypographyToken::Display => TypographyValue {
                family: FontFamily::Sans,
                size_px: 32,
                weight: 700,
            },
            TypographyToken::Heading => TypographyValue {
                family: FontFamily::Sans,
                size_px: 20,
                weight: 600,
            },
            TypographyToken::Body => TypographyValue {
                family: FontFamily::Sans,
                size_px: 14,
                weight: 400,
            },
            TypographyToken::Caption => TypographyValue {
                family: FontFamily::Sans,
                size_px: 12,
                weight: 400,
            },
            TypographyToken::Code => TypographyValue {
                family: FontFamily::Mono,
                size_px: 13,
                weight: 400,
            },
        }
    }
}
