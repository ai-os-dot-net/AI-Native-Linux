//! Closed motion vocabulary — durations and easing curves.
//!
//! Both are fixed, closed sets resolving to concrete values: a duration to a
//! count of milliseconds, an easing role to a canonical `cubic-bezier(...)`
//! string. They are theme-independent (a `Dark` theme does not change timing)
//! but are still resolved *through* the [`crate::theme::TokenSet`] so renderers
//! have exactly one source of truth and one emission path — the same discipline
//! the spacing and radius scales follow.
//!
//! Adding a variant to either enum forces a compile error in the exhaustive
//! `match` on the resolver method (no wildcard arm), so motion cannot drift
//! between the Web and KDE renderers.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// The closed motion-duration scale (milliseconds), shortest to longest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
pub enum MotionToken {
    /// No animation — state changes apply immediately (0 ms).
    Instant,
    /// Fast — micro-interactions, hover/press feedback.
    Fast,
    /// Base — the default transition duration.
    Base,
    /// Slow — larger surfaces, dialogs, page-level transitions.
    Slow,
}

impl MotionToken {
    /// Resolved duration in milliseconds.
    #[must_use]
    pub const fn millis(self) -> u32 {
        match self {
            Self::Instant => 0,
            Self::Fast => 120,
            Self::Base => 200,
            Self::Slow => 320,
        }
    }

    /// Stable kebab-case slug for variable / property names.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::Base => "base",
            Self::Slow => "slow",
        }
    }
}

/// The closed set of easing (timing-function) roles shared by every renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
pub enum EasingToken {
    /// Standard curve — the default for most transitions (symmetric-ish ease).
    Standard,
    /// Decelerate — elements entering the screen (fast start, gentle stop).
    Decelerate,
    /// Accelerate — elements leaving the screen (gentle start, fast exit).
    Accelerate,
}

impl EasingToken {
    /// The canonical CSS `cubic-bezier(...)` string for this easing role — one
    /// source of truth for both renderers. QML's `Easing.bezierCurve` consumes
    /// the same four control-point values.
    #[must_use]
    pub const fn cubic_bezier(self) -> &'static str {
        match self {
            Self::Standard => "cubic-bezier(0.2, 0, 0, 1)",
            Self::Decelerate => "cubic-bezier(0, 0, 0, 1)",
            Self::Accelerate => "cubic-bezier(0.3, 0, 1, 1)",
        }
    }

    /// Stable kebab-case slug for variable / property names.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Decelerate => "decelerate",
            Self::Accelerate => "accelerate",
        }
    }
}
