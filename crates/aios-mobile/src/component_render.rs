//! Mobile materialisation of the shared ComponentRecipes (S7.3 §8.4).
//!
//! The mobile renderer maps each recipe onto platform-native primitives
//! (Material 3 on Android, UIKit on iOS) within the constitutional constraints:
//! the colour ROLE and the distinction axes are preserved, only the host widget
//! changes. A block recipe becomes a Card/Banner, an inline pill a Chip; the
//! elevation token maps to a Material elevation level (dp); the AI-origin axis
//! stays distinct (emphasised + the AI colour role), so INV-021 holds on a phone
//! exactly as it does on the desktop.

use aios_design_tokens::component::{ComponentRecipe, DistinctionAxis};
use aios_design_tokens::ElevationToken;

/// The native surface a recipe maps onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterialSurface {
    /// Inline pill (Material AssistChip / iOS capsule label).
    Chip,
    /// A raised/bordered card (Material Card).
    Card,
    /// A full-width banner in the chrome zone.
    Banner,
}

/// How a component recipe is presented on a mobile surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobilePresentation {
    /// The native widget kind.
    pub surface: MaterialSurface,
    /// The token colour-role slug the widget tints from (e.g. `action-ai`).
    pub color_role: &'static str,
    /// Material elevation in dp (0 / 1 / 3 / 6), derived from the elevation token.
    pub elevation_dp: u8,
    /// Emphasised styling — carries the AI-origin / attention distinction beyond
    /// colour (bold label + the AI colour), so it survives greyscale / high-contrast.
    pub emphasized: bool,
}

/// Map a recipe to its mobile presentation.
#[must_use]
pub fn render_component_mobile(recipe: &ComponentRecipe) -> MobilePresentation {
    let surface = if !recipe.block {
        MaterialSurface::Chip
    } else if recipe.name == aios_design_tokens::component::ComponentName::SecurityBanner
        || recipe.name == aios_design_tokens::component::ComponentName::RecoveryShield
    {
        MaterialSurface::Banner
    } else {
        MaterialSurface::Card
    };
    let elevation_dp = match recipe.elevation {
        ElevationToken::None => 0,
        ElevationToken::Low => 1,
        ElevationToken::Medium => 3,
        ElevationToken::High => 6,
    };
    // Emphasised when the component is constitutional or carries the AI-origin
    // (Typography) axis — the non-colour distinction a phone must also honour.
    let emphasized =
        recipe.constitutional || recipe.required_axes.contains(&DistinctionAxis::Typography);
    MobilePresentation {
        surface,
        color_role: recipe.primary_color.slug(),
        elevation_dp,
        emphasized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aios_design_tokens::component::{recipe_for, ComponentName, AIOS_RECIPES};

    #[test]
    fn badges_are_chips_and_decisions_are_cards() {
        assert_eq!(
            render_component_mobile(&recipe_for(ComponentName::AiSubjectBadge)).surface,
            MaterialSurface::Chip
        );
        assert_eq!(
            render_component_mobile(&recipe_for(ComponentName::ApprovalPrompt)).surface,
            MaterialSurface::Card
        );
        assert_eq!(
            render_component_mobile(&recipe_for(ComponentName::SecurityBanner)).surface,
            MaterialSurface::Banner
        );
    }

    #[test]
    fn elevation_token_maps_to_material_dp() {
        assert_eq!(
            render_component_mobile(&recipe_for(ComponentName::RecoveryShield)).elevation_dp,
            6
        );
        assert_eq!(
            render_component_mobile(&recipe_for(ComponentName::ApprovalPrompt)).elevation_dp,
            3
        );
        assert_eq!(
            render_component_mobile(&recipe_for(ComponentName::AiSubjectBadge)).elevation_dp,
            0
        );
    }

    #[test]
    fn ai_stays_distinct_from_human_by_colour_role_and_emphasis() {
        let ai = render_component_mobile(&recipe_for(ComponentName::AiSubjectBadge));
        let human = render_component_mobile(&recipe_for(ComponentName::HumanSubjectBadge));
        assert_eq!(ai.color_role, "action-ai");
        assert_eq!(human.color_role, "action-human");
        assert!(ai.emphasized); // AI carries the Typography axis
    }

    #[test]
    fn every_recipe_binds_a_colour_role() {
        for r in &AIOS_RECIPES {
            assert!(
                !render_component_mobile(r).color_role.is_empty(),
                "{:?}",
                r.name
            );
        }
    }
}
