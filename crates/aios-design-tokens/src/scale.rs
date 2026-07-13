//! Closed spacing and radius scales.
//!
//! Both are fixed, ordered scales resolving to logical pixels. They are
//! theme-independent (a `Dark` theme does not change the spacing rhythm) but
//! are still resolved *through* the `TokenSet` so that renderers have exactly
//! one source of truth and one emission path.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// The closed spacing scale (logical pixels), smallest to largest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
pub enum SpacingToken {
    /// Extra-small — tight inner padding.
    Xs,
    /// Small — control padding, small gaps.
    Sm,
    /// Medium — the default gutter.
    Md,
    /// Large — section spacing.
    Lg,
    /// Extra-large — page-level spacing.
    Xl,
}

impl SpacingToken {
    /// Resolved value in logical pixels.
    #[must_use]
    pub const fn pixels(self) -> u32 {
        match self {
            Self::Xs => 4,
            Self::Sm => 8,
            Self::Md => 16,
            Self::Lg => 24,
            Self::Xl => 40,
        }
    }

    /// Stable kebab-case slug for variable / property names.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Xs => "xs",
            Self::Sm => "sm",
            Self::Md => "md",
            Self::Lg => "lg",
            Self::Xl => "xl",
        }
    }
}

/// The closed corner-radius scale (logical pixels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
pub enum RadiusToken {
    /// Square corners.
    None,
    /// Small radius — inputs, chips.
    Sm,
    /// Medium radius — cards, buttons.
    Md,
    /// Large radius — dialogs, sheets.
    Lg,
    /// Fully rounded — pills, avatars (a large sentinel, clamped by the renderer).
    Full,
}

impl RadiusToken {
    /// Resolved value in logical pixels. `Full` is a large sentinel (`9999`)
    /// matching the KDE `Pill`/Web `9999px` convention already in the renderers.
    #[must_use]
    pub const fn pixels(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Sm => 4,
            Self::Md => 8,
            Self::Lg => 16,
            Self::Full => 9999,
        }
    }

    /// Stable kebab-case slug for variable / property names.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Sm => "sm",
            Self::Md => "md",
            Self::Lg => "lg",
            Self::Full => "full",
        }
    }
}
