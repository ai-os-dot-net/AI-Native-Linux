//! Closed typography vocabulary.
//!
//! A `TypographyToken` is a semantic text role; it resolves to a typed
//! `TypographyValue` (font-family role + size in px + weight). Renderers format
//! the value: Web into `font-family`/`font-size`/`font-weight` custom
//! properties, KDE into `QFont` family/point-size/weight — both from the same
//! resolved numbers.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// Font-family role. Concrete face names are resolved once, here, so both
/// renderers name the identical family string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FontFamily {
    /// The default proportional (sans-serif) face.
    Sans,
    /// The monospace face (code, terminals, evidence hashes).
    Mono,
}

impl FontFamily {
    /// The concrete face name — one source of truth for both renderers.
    #[must_use]
    pub const fn face_name(self) -> &'static str {
        match self {
            Self::Sans => "Noto Sans",
            Self::Mono => "Noto Sans Mono",
        }
    }
}

/// A concrete, typed typography value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypographyValue {
    /// Font-family role.
    pub family: FontFamily,
    /// Font size in logical pixels.
    pub size_px: u32,
    /// CSS-style numeric weight (100–900); maps directly to `QFont` weight.
    pub weight: u16,
}

/// The closed set of semantic text roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
pub enum TypographyToken {
    /// Display — the largest heading (hero titles).
    Display,
    /// Heading — section titles.
    Heading,
    /// Body — default running text.
    Body,
    /// Caption — small secondary text.
    Caption,
    /// Code — monospace code / hashes / logs.
    Code,
}

impl TypographyToken {
    /// Stable kebab-case slug for variable / property names.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Display => "display",
            Self::Heading => "heading",
            Self::Body => "body",
            Self::Caption => "caption",
            Self::Code => "code",
        }
    }
}
