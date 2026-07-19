//! AIOS component vocabulary (S7.3 §4.6) — the closed set of recognizable
//! component recipes that make "an approval looks like an approval" a contract
//! rather than a per-renderer style accident.
//!
//! A [`ComponentRecipe`] is the *shared* half of a component: it names the
//! component, declares whether its rendering is **constitutional** (themes and
//! AI subjects cannot override it, S7.3 I7), the [`DistinctionAxis`]es its
//! meaning is encoded across (≥2 for every constitutional distinction — the
//! multi-axis rule I4 that keeps AI/human, trust, and recovery legible under
//! colorblindness or monochrome), the S7.2 `NodeKind` its subtree is rooted at,
//! and which semantic [`ColorToken`]s it binds. Each renderer (KDE Qt/QML, Web
//! CSS) materialises the same recipe from the same tokens, so the component
//! reads identically everywhere.
//!
//! Concrete geometry (exact spacing, glyphs) lives in the stage-3 theme; this
//! module is the stage-2 contract: names, constitutionality, axes, and the
//! token roles each component is allowed to speak in.

use std::fmt::Write as _;

use strum::EnumCount as _;
use strum_macros::{EnumCount, EnumIter};

use crate::emit::{css_var_color, css_var_elevation, qml_prop_color, qml_prop_elevation};
use crate::{ColorToken, ElevationToken};

/// The closed axes across which a constitutional distinction is encoded
/// (S7.3 §5). A constitutional distinction (AI/human, trust, recovery) MUST be
/// carried on **at least two** of these so a single-axis failure mode
/// (colorblindness, monochrome, restrictive a11y) can never erase it (I4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, EnumCount)]
pub enum DistinctionAxis {
    /// Colour hue (e.g. AI = violet, human = blue).
    Hue,
    /// Iconography / glyph / hatching differences (badge, chain, tamper mark).
    Pattern,
    /// Font weight, italic, family, size (e.g. the AI-origin italic).
    Typography,
    /// Border style, weight, dash pattern (e.g. AI = dashed, human = solid).
    Outline,
    /// Alpha; used sparingly (e.g. unverified/pending states).
    Opacity,
    /// Location on screen — chrome zone vs content zone.
    Position,
}

/// The closed component vocabulary (S7.3 §4.6). Constitutional components carry
/// meaning the constitution guarantees; recognizable components are AIOS
/// patterns themes may restyle within their axis constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter, EnumCount)]
pub enum ComponentName {
    // ── Constitutional (render rules cannot be overridden; never AI-authored) ──
    /// System-integrity banner in the chrome zone.
    SecurityBanner,
    /// Recovery-mode shield (cognition offline, signed root only).
    RecoveryShield,
    /// Badge marking AI-originated content.
    AiSubjectBadge,
    /// Badge marking human-originated content.
    HumanSubjectBadge,
    /// Trust posture indicator (verified / unverified / degraded / denied).
    TrustIndicator,
    /// Evidence link tile, coloured by retention class.
    EvidenceLinkTile,
    /// Tamper warning (broken evidence chain / hash mismatch).
    TamperWarning,

    // ── Recognizable AIOS components (themes adjust within axis constraints) ──
    /// A message emitted by an AI agent (proposals, explanations).
    AgentMessage,
    /// A prompt requesting a human policy decision on a typed action.
    ApprovalPrompt,
    /// The append-only audit / evidence trail.
    AuditTrail,
    /// A view of a typed action envelope moving through its §13 lifecycle.
    ActionEnvelopeView,
    /// A boundary header grouping related surfaces.
    GroupHeader,
    /// An inbox tile for a pending item requiring attention.
    InboxTile,
}

impl ComponentName {
    /// Stable kebab-case slug (part of the public contract; used by renderers
    /// to key their materialisers).
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::SecurityBanner => "security-banner",
            Self::RecoveryShield => "recovery-shield",
            Self::AiSubjectBadge => "ai-subject-badge",
            Self::HumanSubjectBadge => "human-subject-badge",
            Self::TrustIndicator => "trust-indicator",
            Self::EvidenceLinkTile => "evidence-link-tile",
            Self::TamperWarning => "tamper-warning",
            Self::AgentMessage => "agent-message",
            Self::ApprovalPrompt => "approval-prompt",
            Self::AuditTrail => "audit-trail",
            Self::ActionEnvelopeView => "action-envelope-view",
            Self::GroupHeader => "group-header",
            Self::InboxTile => "inbox-tile",
        }
    }
}

/// The shared recipe for one AIOS component: the stage-2 contract both
/// renderers materialise from the same tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentRecipe {
    /// Which component this recipe defines.
    pub name: ComponentName,
    /// `true` when render rules are constitutional — themes and AI subjects
    /// cannot override them (S7.3 I7).
    pub constitutional: bool,
    /// The S7.2 `NodeKind` name this recipe's subtree is rooted at (the shared
    /// structural vocabulary; kept as the closed spec name so this crate need
    /// not import a renderer's `NodeKind`).
    pub root_node_kind: &'static str,
    /// The axes the component's meaning is encoded across. For a constitutional
    /// component this MUST contain at least two (I4).
    pub required_axes: &'static [DistinctionAxis],
    /// The primary semantic colour role the component speaks in.
    pub primary_color: ColorToken,
    /// Surface elevation — the card-vs-flat signal (S7.4 §5). `None` for flat
    /// chrome/pills, higher for cards that demand a decision or attention.
    pub elevation: ElevationToken,
}

impl ComponentRecipe {
    /// Does this recipe satisfy the multi-axis distinction rule (I4)? Every
    /// constitutional recipe must encode its distinction on ≥2 axes.
    #[must_use]
    pub fn satisfies_multi_axis(&self) -> bool {
        !self.constitutional || self.required_axes.len() >= 2
    }
}

use ColorToken::{
    Accent, ActionAi, ActionHuman, ActionSystem, EvidencePermanent, Recovery, TrustDenied,
    TrustVerified, Warning,
};
use DistinctionAxis::{Hue, Outline, Pattern, Position, Typography};

/// The closed set of AIOS component recipes (S7.3 §4.6). 13 named components;
/// exhaustive and order-stable. Constitutional recipes come first.
pub const AIOS_RECIPES: [ComponentRecipe; ComponentName::COUNT] = [
    ComponentRecipe {
        name: ComponentName::SecurityBanner,
        constitutional: true,
        root_node_kind: "SecurityIndicator",
        required_axes: &[Hue, Pattern, Position],
        primary_color: TrustVerified,
        elevation: ElevationToken::None,
    },
    ComponentRecipe {
        name: ComponentName::RecoveryShield,
        constitutional: true,
        root_node_kind: "SecurityIndicator",
        required_axes: &[Hue, Pattern, Outline, Typography],
        primary_color: Recovery,
        elevation: ElevationToken::High,
    },
    ComponentRecipe {
        name: ComponentName::AiSubjectBadge,
        constitutional: true,
        root_node_kind: "SecurityIndicator",
        required_axes: &[Hue, Pattern, Outline, Typography],
        primary_color: ActionAi,
        elevation: ElevationToken::None,
    },
    ComponentRecipe {
        name: ComponentName::HumanSubjectBadge,
        constitutional: true,
        root_node_kind: "SecurityIndicator",
        required_axes: &[Hue, Pattern, Outline],
        primary_color: ActionHuman,
        elevation: ElevationToken::None,
    },
    ComponentRecipe {
        name: ComponentName::TrustIndicator,
        constitutional: true,
        root_node_kind: "SecurityIndicator",
        required_axes: &[Hue, Pattern],
        primary_color: TrustVerified,
        elevation: ElevationToken::None,
    },
    ComponentRecipe {
        name: ComponentName::EvidenceLinkTile,
        constitutional: true,
        root_node_kind: "EvidenceLink",
        required_axes: &[Hue, Pattern],
        primary_color: EvidencePermanent,
        elevation: ElevationToken::Low,
    },
    ComponentRecipe {
        name: ComponentName::TamperWarning,
        constitutional: true,
        root_node_kind: "SecurityIndicator",
        required_axes: &[Hue, Pattern, Outline],
        primary_color: TrustDenied,
        elevation: ElevationToken::Medium,
    },
    ComponentRecipe {
        name: ComponentName::AgentMessage,
        constitutional: false,
        root_node_kind: "AgentMessage",
        required_axes: &[Hue, Outline, Typography],
        primary_color: ActionAi,
        elevation: ElevationToken::None,
    },
    ComponentRecipe {
        name: ComponentName::ApprovalPrompt,
        constitutional: false,
        root_node_kind: "ApprovalPrompt",
        required_axes: &[Hue, Pattern, Position],
        primary_color: ActionHuman,
        elevation: ElevationToken::Medium,
    },
    ComponentRecipe {
        name: ComponentName::AuditTrail,
        constitutional: false,
        root_node_kind: "Table",
        required_axes: &[Typography, Hue],
        primary_color: ActionSystem,
        elevation: ElevationToken::None,
    },
    ComponentRecipe {
        name: ComponentName::ActionEnvelopeView,
        constitutional: false,
        root_node_kind: "Card",
        required_axes: &[Pattern, Hue],
        primary_color: Accent,
        elevation: ElevationToken::Low,
    },
    ComponentRecipe {
        name: ComponentName::GroupHeader,
        constitutional: false,
        root_node_kind: "Heading",
        required_axes: &[Position, Outline],
        primary_color: Accent,
        elevation: ElevationToken::None,
    },
    ComponentRecipe {
        name: ComponentName::InboxTile,
        constitutional: false,
        root_node_kind: "Card",
        required_axes: &[Hue, Pattern, Position],
        primary_color: Warning,
        elevation: ElevationToken::Low,
    },
];

/// Look up the recipe for a component. Total over the closed vocabulary.
#[must_use]
pub fn recipe_for(name: ComponentName) -> ComponentRecipe {
    // Linear scan over a 13-element const array — trivial and const-data safe.
    let mut i = 0;
    while i < AIOS_RECIPES.len() {
        if matches!((AIOS_RECIPES[i].name, name), (a, b) if a as u8 == b as u8) {
            return AIOS_RECIPES[i];
        }
        i += 1;
    }
    // Unreachable: AIOS_RECIPES covers every ComponentName (proven by
    // `every_component_has_exactly_one_recipe`).
    AIOS_RECIPES[0]
}

/// Emit the shared CSS rule for one component recipe. The class name and every
/// value derive from the recipe + tokens via [`css_var_color`] — the SAME
/// helper the token stylesheet uses, so the colour reference can never drift
/// off-token. The distinction axes drive real CSS: `Outline` → a token-coloured
/// border, `Typography` → italic (the AI-origin axis that separates an AI badge
/// from a human one even under colourblindness), `Opacity` → reduced alpha.
#[must_use]
pub fn recipe_to_css(recipe: &ComponentRecipe) -> String {
    let var = css_var_color(recipe.primary_color);
    let slug = recipe.name.slug();
    let kind = if recipe.constitutional {
        "constitutional"
    } else {
        "recognizable"
    };
    let mut out = String::new();
    let _ = writeln!(out, "/* {slug} — {kind} */");
    let _ = writeln!(out, ".aios-{slug} {{");
    let _ = writeln!(out, "  color: var({var});");
    if recipe.required_axes.contains(&DistinctionAxis::Outline) {
        let _ = writeln!(out, "  border: 1px solid var({var});");
    }
    if recipe.required_axes.contains(&DistinctionAxis::Typography) {
        let _ = writeln!(out, "  font-style: italic;");
    }
    if recipe.required_axes.contains(&DistinctionAxis::Opacity) {
        let _ = writeln!(out, "  opacity: 0.72;");
    }
    let _ = writeln!(out, "  border-radius: var(--aios-radius-md);");
    if recipe.elevation != ElevationToken::None {
        let _ = writeln!(
            out,
            "  box-shadow: var({});",
            css_var_elevation(recipe.elevation)
        );
    }
    out.push_str("}\n");
    out
}

/// Emit the shared QML fragment for one component recipe — the KDE counterpart
/// of [`recipe_to_css`]. Colour binds `AiosTokens.<prop>` via [`qml_prop_color`]
/// (the same helper the QML token singleton uses); the same axes drive the
/// border / italic / opacity properties, so KDE renders the component with the
/// identical token bindings the Web rule uses.
#[must_use]
pub fn recipe_to_qml(recipe: &ComponentRecipe) -> String {
    let prop = qml_prop_color(recipe.primary_color);
    let slug = recipe.name.slug();
    let mut out = String::new();
    let _ = writeln!(out, "// {slug}");
    let _ = writeln!(out, "Item {{");
    let _ = writeln!(out, "  property color aiosColor: AiosTokens.{prop}");
    if recipe.required_axes.contains(&DistinctionAxis::Outline) {
        let _ = writeln!(out, "  property int aiosBorderWidth: 1");
    }
    if recipe.required_axes.contains(&DistinctionAxis::Typography) {
        let _ = writeln!(out, "  property bool aiosItalic: true");
    }
    if recipe.required_axes.contains(&DistinctionAxis::Opacity) {
        let _ = writeln!(out, "  property real aiosOpacity: 0.72");
    }
    if recipe.elevation != ElevationToken::None {
        let _ = writeln!(
            out,
            "  property string aiosElevation: AiosTokens.{}",
            qml_prop_elevation(recipe.elevation)
        );
    }
    out.push_str("}\n");
    out
}

/// Emit the full component stylesheet — every recipe's CSS rule in
/// `AIOS_RECIPES` order. The Web renderer imports this alongside the token
/// custom-properties; the component layer thus comes from one shared source.
#[must_use]
pub fn all_component_css() -> String {
    let mut out = String::from("/* AIOS components — generated from ComponentRecipes. */\n");
    for r in &AIOS_RECIPES {
        out.push_str(&recipe_to_css(r));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn recipe_set_is_closed_and_ordered() {
        assert_eq!(AIOS_RECIPES.len(), ComponentName::COUNT);
        assert_eq!(ComponentName::COUNT, 13);
        // Constitutional recipes come first, contiguously.
        let first_non_const = AIOS_RECIPES
            .iter()
            .position(|r| !r.constitutional)
            .expect("there are recognizable recipes");
        assert!(AIOS_RECIPES[..first_non_const]
            .iter()
            .all(|r| r.constitutional));
        assert!(AIOS_RECIPES[first_non_const..]
            .iter()
            .all(|r| !r.constitutional));
        // Exactly 7 constitutional + 6 recognizable (S7.3 §4.6).
        assert_eq!(AIOS_RECIPES.iter().filter(|r| r.constitutional).count(), 7);
    }

    #[test]
    fn every_component_has_exactly_one_recipe() {
        for name in ComponentName::iter() {
            let matches = AIOS_RECIPES
                .iter()
                .filter(|r| r.name as u8 == name as u8)
                .count();
            assert_eq!(matches, 1, "{name:?} must have exactly one recipe");
            // recipe_for returns the right one.
            assert_eq!(recipe_for(name).name as u8, name as u8);
        }
    }

    #[test]
    fn constitutional_recipes_satisfy_multi_axis_i4() {
        // I4: every constitutional distinction is encoded across ≥2 axes.
        for r in AIOS_RECIPES.iter().filter(|r| r.constitutional) {
            assert!(
                r.satisfies_multi_axis(),
                "{:?} is constitutional but encodes <2 axes",
                r.name
            );
            assert!(r.required_axes.len() >= 2);
        }
    }

    #[test]
    fn ai_and_human_badges_differ_on_at_least_two_axes() {
        // The AI/human distinction (INV-021) must survive the loss of any one
        // axis: different hue AND a second differentiator.
        let ai = recipe_for(ComponentName::AiSubjectBadge);
        let human = recipe_for(ComponentName::HumanSubjectBadge);
        // Different primary hue.
        assert_ne!(ai.primary_color, human.primary_color);
        // AI carries the italic typography axis that human does not — a second,
        // non-colour axis, so colourblind viewers still tell them apart.
        assert!(ai.required_axes.contains(&DistinctionAxis::Typography));
        assert!(!human.required_axes.contains(&DistinctionAxis::Typography));
    }

    #[test]
    fn constitutional_recipes_bind_only_constitutional_color_roles() {
        // I7 mirror: constitutional components speak only in the constitutional
        // colour families (action provenance / trust / evidence / recovery),
        // never a plain brand/base role a user theme could repaint freely.
        let constitutional_roles = [
            ColorToken::ActionHuman,
            ColorToken::ActionAi,
            ColorToken::ActionSystem,
            ColorToken::Recovery,
            ColorToken::TrustVerified,
            ColorToken::TrustUnverified,
            ColorToken::TrustDegraded,
            ColorToken::TrustDenied,
            ColorToken::EvidencePermanent,
            ColorToken::EvidenceExtended,
            ColorToken::EvidenceStandard,
        ];
        for r in AIOS_RECIPES.iter().filter(|r| r.constitutional) {
            assert!(
                constitutional_roles.contains(&r.primary_color),
                "{:?} is constitutional but binds a non-constitutional colour {:?}",
                r.name,
                r.primary_color
            );
        }
    }

    #[test]
    fn slugs_are_unique() {
        let mut slugs: Vec<&str> = ComponentName::iter().map(ComponentName::slug).collect();
        slugs.sort_unstable();
        let n = slugs.len();
        slugs.dedup();
        assert_eq!(slugs.len(), n, "component slugs must be unique");
    }

    #[test]
    fn css_and_qml_reference_the_same_primary_color_by_the_token_name() {
        // The emitters can never drift off-token: both reference the recipe's
        // primary colour by the exact name the token emitters produce.
        for r in &AIOS_RECIPES {
            let css = recipe_to_css(r);
            let qml = recipe_to_qml(r);
            assert!(
                css.contains(&crate::emit::css_var_color(r.primary_color)),
                "{:?} css missing its primary colour var",
                r.name
            );
            assert!(
                qml.contains(&crate::emit::qml_prop_color(r.primary_color)),
                "{:?} qml missing its primary colour prop",
                r.name
            );
        }
    }

    #[test]
    fn typography_axis_drives_italic_and_separates_ai_from_human() {
        // The AI badge carries the Typography axis -> italic; the human badge
        // does not. So even with identical borders they stay distinguishable
        // (INV-021 survives loss of the hue axis).
        let ai = recipe_to_css(&recipe_for(ComponentName::AiSubjectBadge));
        let human = recipe_to_css(&recipe_for(ComponentName::HumanSubjectBadge));
        assert!(ai.contains("font-style: italic"));
        assert!(!human.contains("font-style: italic"));
        assert_ne!(ai, human);
    }

    #[test]
    fn outline_axis_maps_exactly_to_a_border() {
        for r in &AIOS_RECIPES {
            assert_eq!(
                r.required_axes.contains(&DistinctionAxis::Outline),
                recipe_to_css(r).contains("border: 1px solid"),
                "{:?} outline-axis / border mismatch",
                r.name
            );
        }
    }

    #[test]
    fn component_stylesheet_covers_every_recipe() {
        let sheet = all_component_css();
        for name in ComponentName::iter() {
            assert!(
                sheet.contains(&format!(".aios-{}", name.slug())),
                "{name:?} missing from the component stylesheet"
            );
        }
    }

    #[test]
    fn elevation_emits_a_box_shadow_exactly_when_raised() {
        // A raised recipe (card / attention component) emits box-shadow; a flat
        // one (chrome banner, pill badge, table) does not. This is the card-vs-
        // flat identity signal, driven purely from the recipe's elevation token.
        for r in &AIOS_RECIPES {
            let raised = r.elevation != ElevationToken::None;
            assert_eq!(
                raised,
                recipe_to_css(r).contains("box-shadow: var("),
                "{:?} elevation / box-shadow mismatch",
                r.name
            );
            assert_eq!(
                raised,
                recipe_to_qml(r).contains("aiosElevation"),
                "{:?} qml elevation mismatch",
                r.name
            );
        }
        // The decision surfaces are raised; the inline badges are flat.
        assert_ne!(
            recipe_for(ComponentName::ApprovalPrompt).elevation,
            ElevationToken::None
        );
        assert_eq!(
            recipe_for(ComponentName::AiSubjectBadge).elevation,
            ElevationToken::None
        );
    }
}
