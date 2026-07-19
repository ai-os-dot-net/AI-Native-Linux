//! Voice materialisation of the shared ComponentRecipes (S7.3 §8.4).
//!
//! A voice surface has no colour and no screen, so the constitutional
//! distinctions (AI/human, trust, recovery) are carried on the axes a speaker
//! CAN use: a spoken **prefix word** and a short **earcon** (audio cue). An AI
//! component is announced "A-I" with the `ai` earcon; a human one "operator";
//! recovery and tamper get the urgent earcon. That is ≥2 non-visual axes, so the
//! distinction survives a purely auditory channel — the same INV-021 guarantee
//! the screen renderers meet with hue + glyph.

use aios_design_tokens::component::{ComponentName, ComponentRecipe, DistinctionAxis};

/// A short audio cue that precedes a spoken component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Earcon {
    /// Neutral chime.
    Neutral,
    /// AI-origin cue (binds INV-021 on the audio channel).
    Ai,
    /// Human-origin cue.
    Human,
    /// Positive / verified.
    Positive,
    /// Urgent — recovery, tamper, denial (attention-demanding).
    Urgent,
}

/// How a component recipe is presented on a voice surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoicePresentation {
    /// The spoken prefix announced before the content (e.g. "A I", "operator").
    pub spoken_prefix: &'static str,
    /// The earcon played before the prefix.
    pub earcon: Earcon,
    /// Whether the cadence is deliberate/slowed (used for decisions & alerts).
    pub deliberate: bool,
}

/// Map a recipe to its voice presentation.
#[must_use]
pub fn render_component_voice(recipe: &ComponentRecipe) -> VoicePresentation {
    use ComponentName as N;
    let (spoken_prefix, earcon) = match recipe.name {
        N::SecurityBanner => ("security", Earcon::Positive),
        N::RecoveryShield => ("recovery mode", Earcon::Urgent),
        N::AiSubjectBadge => ("A I", Earcon::Ai),
        N::HumanSubjectBadge => ("operator", Earcon::Human),
        N::TrustIndicator => ("trust", Earcon::Positive),
        N::EvidenceLinkTile => ("evidence", Earcon::Neutral),
        N::TamperWarning => ("tamper warning", Earcon::Urgent),
        N::AgentMessage => ("A I says", Earcon::Ai),
        N::ApprovalPrompt => ("approval required", Earcon::Human),
        N::AuditTrail => ("audit", Earcon::Neutral),
        N::ActionEnvelopeView => ("action", Earcon::Neutral),
        N::GroupHeader => ("group", Earcon::Neutral),
        N::InboxTile => ("inbox", Earcon::Urgent),
    };
    // Decisions and alerts are spoken deliberately (slower) — the audio analogue
    // of the MOTION_DURATION_DELIBERATE / attention treatment on screen.
    let deliberate = matches!(earcon, Earcon::Urgent)
        || matches!(recipe.name, N::ApprovalPrompt)
        || recipe.required_axes.contains(&DistinctionAxis::Position);
    VoicePresentation {
        spoken_prefix,
        earcon,
        deliberate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aios_design_tokens::component::{recipe_for, AIOS_RECIPES};

    #[test]
    fn ai_and_human_have_distinct_prefix_and_earcon() {
        // INV-021 on the audio channel: two axes (prefix word AND earcon) differ.
        let ai = render_component_voice(&recipe_for(ComponentName::AiSubjectBadge));
        let human = render_component_voice(&recipe_for(ComponentName::HumanSubjectBadge));
        assert_ne!(ai.spoken_prefix, human.spoken_prefix);
        assert_ne!(ai.earcon, human.earcon);
        assert_eq!(ai.earcon, Earcon::Ai);
        assert_eq!(human.earcon, Earcon::Human);
    }

    #[test]
    fn recovery_and_tamper_are_urgent_and_deliberate() {
        for n in [ComponentName::RecoveryShield, ComponentName::TamperWarning] {
            let v = render_component_voice(&recipe_for(n));
            assert_eq!(v.earcon, Earcon::Urgent);
            assert!(v.deliberate, "{n:?} must be spoken deliberately");
        }
    }

    #[test]
    fn every_recipe_has_a_non_empty_prefix() {
        for r in &AIOS_RECIPES {
            assert!(
                !render_component_voice(r).spoken_prefix.is_empty(),
                "{:?}",
                r.name
            );
        }
    }
}
