//! Closed color-role vocabulary and the typed RGBA value it resolves to.
//!
//! `ColorToken` is a **closed** set of semantic roles — NOT a free-form palette.
//! Adding a role forces a compile error in every exhaustive `match` that
//! resolves it (see `crate::theme::TokenSet::color`), which is precisely the
//! guarantee that keeps the two renderers from silently diverging.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// A concrete, typed color value — the single source of truth.
///
/// Renderers *format* this (CSS hex, QML color literal); they never carry a
/// pre-formatted string as the authoritative value. Storing `r/g/b/a` as bytes
/// makes the emitter-equivalence parity proof a byte comparison, not a string
/// comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ColorValue {
    /// Red channel, 0–255.
    pub r: u8,
    /// Green channel, 0–255.
    pub g: u8,
    /// Blue channel, 0–255.
    pub b: u8,
    /// Alpha channel, 0–255 (255 = fully opaque).
    pub a: u8,
}

impl ColorValue {
    /// Construct an opaque color from an `#RRGGBB` triple.
    #[must_use]
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 0xff }
    }

    /// Construct a color from an `#RRGGBBAA` quad.
    #[must_use]
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Format as a lowercase `#RRGGBBAA` hex string.
    ///
    /// The alpha channel is always emitted so that both renderers produce a
    /// single canonical form; a drifted emitter that drops or reorders channels
    /// fails the parity test.
    #[must_use]
    pub fn to_hex_rgba(&self) -> String {
        format!("#{:02x}{:02x}{:02x}{:02x}", self.r, self.g, self.b, self.a)
    }

    /// Format as a lowercase `#AARRGGBB` hex string — QML's native color
    /// convention (alpha first). Distinct on purpose from [`Self::to_hex_rgba`]:
    /// the parity proof decodes each convention and compares the *values*.
    #[must_use]
    pub fn to_hex_argb(&self) -> String {
        format!("#{:02x}{:02x}{:02x}{:02x}", self.a, self.r, self.g, self.b)
    }

    /// Parse a `#RRGGBB` or `#RRGGBBAA` hex string back into a `ColorValue`
    /// (CSS convention). Used by the parity proof to read a color back out of
    /// the CSS emitter's output. Returns `None` on any malformed input.
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        let body = hex.strip_prefix('#')?;
        let (r, g, b, a) = match body.len() {
            6 => (&body[0..2], &body[2..4], &body[4..6], "ff"),
            8 => (&body[0..2], &body[2..4], &body[4..6], &body[6..8]),
            _ => return None,
        };
        Some(Self {
            r: u8::from_str_radix(r, 16).ok()?,
            g: u8::from_str_radix(g, 16).ok()?,
            b: u8::from_str_radix(b, 16).ok()?,
            a: u8::from_str_radix(a, 16).ok()?,
        })
    }

    /// Parse a `#AARRGGBB` (or opaque `#RRGGBB`) hex string back into a
    /// `ColorValue` — QML convention (alpha first). Used by the parity proof to
    /// read a color back out of the QML emitter's output. Returns `None` on any
    /// malformed input.
    #[must_use]
    pub fn from_hex_argb(hex: &str) -> Option<Self> {
        let body = hex.strip_prefix('#')?;
        let (a, r, g, b) = match body.len() {
            6 => ("ff", &body[0..2], &body[2..4], &body[4..6]),
            8 => (&body[0..2], &body[2..4], &body[4..6], &body[6..8]),
            _ => return None,
        };
        Some(Self {
            a: u8::from_str_radix(a, 16).ok()?,
            r: u8::from_str_radix(r, 16).ok()?,
            g: u8::from_str_radix(g, 16).ok()?,
            b: u8::from_str_radix(b, 16).ok()?,
        })
    }
}

/// The closed set of semantic color roles shared by every AIOS renderer.
///
/// Semantic (by role), not literal (by hue): a renderer asks for
/// `TextPrimary`, never for "`#1a1d21`". This is the color half of the shared
/// STYLE vocabulary that complements the shared STRUCTURAL vocabulary
/// (`NodeKind`, S7.2 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, EnumCount)]
pub enum ColorToken {
    /// Primary surface / background of a pane.
    Surface,
    /// Secondary surface — cards, raised rows, subtle fills.
    SurfaceVariant,
    /// Primary body text — highest contrast against `Surface`.
    TextPrimary,
    /// Secondary text — captions, hints, disabled-adjacent.
    TextSecondary,
    /// Accent / brand — primary actions, focus, selection.
    Accent,
    /// Success state — confirmations, healthy status.
    Success,
    /// Warning state — cautions, degraded status.
    Warning,
    /// Danger state — destructive actions, failures.
    Danger,
    /// Hairline borders and dividers.
    Border,

    // ── Constitutional layer (S7.3 §4.1) — action provenance (INV-021) ──
    /// Action originated by a human operator.
    ActionHuman,
    /// Action proposed by an AI subject. Never authored by AI themes; paired
    /// with the AI badge / dashed outline / italic axes for multi-axis distinction.
    ActionAi,
    /// Action originated by the system itself (schedulers, health, first-boot).
    ActionSystem,
    /// Recovery namespace (INV-022) — recovery-mode surfaces only.
    Recovery,

    // ── Constitutional layer — trust posture (INV-020) ──
    /// Trust verified — evidence chain intact, signature valid.
    TrustVerified,
    /// Trust not yet established / unproven.
    TrustUnverified,
    /// Trust degraded — partial or expiring assurance.
    TrustDegraded,
    /// Trust denied — policy block or failed verification.
    TrustDenied,

    // ── Constitutional layer — evidence retention class ──
    /// FOREVER retention — visually the most prominent evidence class.
    EvidencePermanent,
    /// Extended retention.
    EvidenceExtended,
    /// Standard retention.
    EvidenceStandard,
}

impl ColorToken {
    /// Stable kebab-case slug used to build CSS variable names and QML property
    /// identifiers. Deterministic; part of the public contract.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Surface => "surface",
            Self::SurfaceVariant => "surface-variant",
            Self::TextPrimary => "text-primary",
            Self::TextSecondary => "text-secondary",
            Self::Accent => "accent",
            Self::Success => "success",
            Self::Warning => "warning",
            Self::Danger => "danger",
            Self::Border => "border",
            Self::ActionHuman => "action-human",
            Self::ActionAi => "action-ai",
            Self::ActionSystem => "action-system",
            Self::Recovery => "recovery",
            Self::TrustVerified => "trust-verified",
            Self::TrustUnverified => "trust-unverified",
            Self::TrustDegraded => "trust-degraded",
            Self::TrustDenied => "trust-denied",
            Self::EvidencePermanent => "evidence-permanent",
            Self::EvidenceExtended => "evidence-extended",
            Self::EvidenceStandard => "evidence-standard",
        }
    }
}
