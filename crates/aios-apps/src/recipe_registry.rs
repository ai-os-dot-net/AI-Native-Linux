//! S12.1 §3.7 Community Recipe Registry — typed skeleton for recipe
//! lifecycle management (submit → review → approve → publish).
//!
//! Every recipe passes through a closed state machine: Draft → Proposed →
//! UnderReview → Published (or Flagged / Deprecated / Revoked).
//! The registry emits evidence receipts at each lifecycle transition.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

use crate::ecosystem::{EcosystemRuntime, RecipeTrustClass};
use crate::error::AppsError;

// ---------------------------------------------------------------------------
// RecipeId — canonical recipe identifier
// ---------------------------------------------------------------------------

/// Canonical recipe identifier. Format: `rcp_<ulid26>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecipeId(pub String);

// ---------------------------------------------------------------------------
// ReviewId — canonical review identifier
// ---------------------------------------------------------------------------

/// Canonical review identifier. Format: `rvw_<ulid26>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReviewId(pub String);

// ---------------------------------------------------------------------------
// RecipeState — 7 closed values (S12.1 §3.7.1)
// ---------------------------------------------------------------------------

/// S12.1 §3.7.1 — the lifecycle state of a community recipe.
/// Seven closed values: Draft → Proposed → UnderReview → Published,
/// with terminal states Flagged, Deprecated, Revoked.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
    strum_macros::Display,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeState {
    /// Author is still editing; not yet submitted.
    Draft,
    /// Submitted by author; awaiting reviewer assignment.
    Proposed,
    /// Reviewer assigned; under active review.
    UnderReview,
    /// Approved and published to the registry.
    Published,
    /// Flagged by community for review.
    Flagged,
    /// No longer recommended; new recipes should not install.
    Deprecated,
    /// Permanently revoked; must not be installed.
    Revoked,
}

// ---------------------------------------------------------------------------
// RecipeVerificationStatus — 5 closed values (S12.1 §3.7.2)
// ---------------------------------------------------------------------------

/// S12.1 §3.7.2 — verification status of a recipe's claims.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
    strum_macros::Display,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipeVerificationStatus {
    /// Recipe has not been verified.
    NotVerified,
    /// Automated verification is running.
    VerificationInProgress,
    /// Verified by community members (N ≥ 3 votes).
    VerifiedByCommunity,
    /// Verified by AIOS_ROOT or delegated verifier.
    VerifiedByAios,
    /// Verification attempt failed; recipe may be re-submitted.
    VerificationFailed,
}

// ---------------------------------------------------------------------------
// ReviewVerdict — 3 closed values
// ---------------------------------------------------------------------------

/// S12.1 §3.7.3 — reviewer verdict on a recipe.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
    strum_macros::Display,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewVerdict {
    /// Recipe is approved for publication.
    Approve,
    /// Recipe is rejected; author must revise.
    Reject,
    /// Reviewer requests changes before re-review.
    RequestChanges,
}

// ---------------------------------------------------------------------------
// Recipe — the top-level recipe struct (16 fields)
// ---------------------------------------------------------------------------

/// S12.1 §3.7.4 — a community recipe registry entry.
///
/// Contains all metadata needed to reproduce an installation:
/// the capsule runtime, source format, target runtime, install and
/// verification steps, required capabilities, sandbox profile, and
/// trust attestations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    /// Canonical recipe identifier (`rcp_<ulid26>`).
    pub recipe_id: RecipeId,
    /// Human-readable recipe name.
    pub name: String,
    /// Free-form description of what this recipe installs.
    pub description: String,
    /// Author identifier (operator id or publisher id).
    pub author: String,
    /// When the recipe was published (set on publish, None otherwise).
    pub published_at: Option<DateTime<Utc>>,
    /// The capsule runtime this recipe targets.
    pub capsule_runtime: EcosystemRuntime,
    /// Source package format (e.g. "flatpak", "snap", "appimage", "deb").
    pub source_package_format: String,
    /// The foreign-ecosystem runtime this recipe wraps.
    pub target_runtime: EcosystemRuntime,
    /// Ordered list of install shell-steps.
    pub install_steps: Vec<String>,
    /// Ordered list of verification shell-steps.
    pub verify_steps: Vec<String>,
    /// Capabilities the recipe declares as required.
    pub required_capabilities: Vec<String>,
    /// Sandbox profile name this recipe binds to.
    pub sandbox_profile: String,
    /// Trust class derived from publisher tier and reputation.
    pub trust_class: RecipeTrustClass,
    /// Ed25519 signature over the recipe payload.
    pub signature: String,
    /// Semantic version of the recipe.
    pub version: String,
    /// Free-form tags for discovery.
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// RecipeReview — review record
// ---------------------------------------------------------------------------

/// S12.1 §3.7.5 — a review left by a reviewer on a proposed recipe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeReview {
    /// Canonical review identifier (`rvw_<ulid26>`).
    pub review_id: ReviewId,
    /// The recipe being reviewed.
    pub recipe_id: RecipeId,
    /// Reviewer identifier.
    pub reviewer_id: String,
    /// Approve / Reject / RequestChanges.
    pub verdict: ReviewVerdict,
    /// Free-form feedback from the reviewer.
    pub feedback: String,
    /// When the review was submitted.
    pub reviewed_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// RecipeTrustBadge — compound trust attestation
// ---------------------------------------------------------------------------

/// S12.1 §3.7.6 — aggregated trust metadata displayed on a recipe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeTrustBadge {
    /// Trust class assigned to the recipe.
    pub trust_class: RecipeTrustClass,
    /// Current verification status.
    pub verification_status: RecipeVerificationStatus,
    /// Number of community votes cast.
    pub community_votes: u64,
    /// Identity of the verifier (if verified).
    pub verified_by: Option<String>,
    /// Reference to a cryptographic certificate.
    pub certificate_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// RecipeInstallResult — outcome of installing from a recipe
// ---------------------------------------------------------------------------

/// S12.1 §3.7.7 — result of executing a recipe's install steps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeInstallResult {
    /// The recipe that was installed.
    pub recipe_id: RecipeId,
    /// The capsule id created by the installation.
    pub installed_capsule_id: String,
    /// Wall-clock seconds the install took.
    pub install_duration: u64,
    /// Whether the verify steps passed.
    pub verify_result: bool,
    /// Evidence receipt id for this install event.
    pub evidence_receipt: String,
}

// ---------------------------------------------------------------------------
// Evidence event constants
// ---------------------------------------------------------------------------

/// Recipe was submitted to the registry.
pub const RECIPE_SUBMITTED: &str = "RECIPE_SUBMITTED";
/// Recipe was approved by a reviewer.
pub const RECIPE_APPROVED: &str = "RECIPE_APPROVED";
/// Recipe was published to the registry.
pub const RECIPE_PUBLISHED: &str = "RECIPE_PUBLISHED";
/// Recipe was flagged by the community.
pub const RECIPE_FLAGGED: &str = "RECIPE_FLAGGED";
/// Recipe was deprecated.
pub const RECIPE_DEPRECATED: &str = "RECIPE_DEPRECATED";
/// Recipe was installed from the registry.
pub const RECIPE_INSTALLED: &str = "RECIPE_INSTALLED";

// ---------------------------------------------------------------------------
// RecipeRegistry — the central registry data structure
// ---------------------------------------------------------------------------

/// S12.1 §3.7.8 — the community recipe registry.
///
/// Stores recipes and reviews in-memory. Every state transition is
/// validated against the closed recipe state machine.
#[derive(Clone, Debug, Default)]
pub struct RecipeRegistry {
    recipes: HashMap<RecipeId, Recipe>,
    recipe_state: HashMap<RecipeId, RecipeState>,
    reviews: HashMap<RecipeId, Vec<RecipeReview>>,
}

impl RecipeRegistry {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create an empty recipe registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            recipes: HashMap::new(),
            recipe_state: HashMap::new(),
            reviews: HashMap::new(),
        }
    }

    /// Return the number of recipes currently in the registry.
    #[must_use]
    pub fn recipe_count(&self) -> usize {
        self.recipes.len()
    }

    /// Return the number of reviews currently in the registry.
    #[must_use]
    pub fn review_count(&self) -> usize {
        self.reviews.values().map(|v| v.len()).sum()
    }

    // -----------------------------------------------------------------------
    // Lifecycle methods
    // -----------------------------------------------------------------------

    /// Submit a recipe to the registry.
    ///
    /// The recipe enters the `Proposed` state.
    /// Emits `RECIPE_SUBMITTED` evidence.
    ///
    /// # Errors
    ///
    /// Returns `ValidationFailed` if the recipe name is empty.
    pub fn submit_recipe(&mut self, recipe: Recipe) -> Result<RecipeId, AppsError> {
        if recipe.name.is_empty() {
            return Err(AppsError::ValidationFailed(
                "recipe name must not be empty".into(),
            ));
        }
        let recipe_id = recipe.recipe_id.clone();
        self.recipe_state
            .insert(recipe_id.clone(), RecipeState::Proposed);
        self.recipes.insert(recipe_id.clone(), recipe);
        Ok(recipe_id)
    }

    /// Record a review and transition the recipe to `UnderReview` if
    /// currently `Proposed`.
    ///
    /// Valid from `Proposed` (transitions to `UnderReview`) or
    /// `UnderReview` (stays `UnderReview`).
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the recipe does not exist.
    /// Returns `InvalidStateTransition` if the recipe is not `Proposed`
    /// or `UnderReview`.
    pub fn review_recipe(
        &mut self,
        recipe_id: &RecipeId,
        reviewer_id: &str,
        verdict: ReviewVerdict,
        feedback: &str,
    ) -> Result<RecipeReview, AppsError> {
        let current_state = self
            .recipe_state
            .get(recipe_id)
            .copied()
            .ok_or_else(|| AppsError::NotFound(format!("recipe not found: {}", recipe_id.0)))?;

        if current_state != RecipeState::Proposed && current_state != RecipeState::UnderReview {
            return Err(AppsError::InvalidStateTransition {
                from: current_state.to_string(),
                to: RecipeState::UnderReview.to_string(),
            });
        }

        let review = RecipeReview {
            review_id: ReviewId(format!(
                "rvw_{}",
                ulid::Ulid::new().to_string().to_lowercase()
            )),
            recipe_id: recipe_id.clone(),
            reviewer_id: reviewer_id.into(),
            verdict,
            feedback: feedback.into(),
            reviewed_at: Utc::now(),
        };

        self.reviews
            .entry(recipe_id.clone())
            .or_default()
            .push(review.clone());
        self.recipe_state
            .insert(recipe_id.clone(), RecipeState::UnderReview);

        Ok(review)
    }

    /// Approve a recipe that is currently `UnderReview`.
    ///
    /// Records an approval verdict from the reviewer.
    /// Emits `RECIPE_APPROVED` evidence.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the recipe does not exist.
    /// Returns `InvalidStateTransition` if the recipe is not `UnderReview`.
    pub fn approve_recipe(
        &mut self,
        recipe_id: &RecipeId,
        reviewer_id: &str,
        feedback: &str,
    ) -> Result<RecipeReview, AppsError> {
        let current_state = self
            .recipe_state
            .get(recipe_id)
            .copied()
            .ok_or_else(|| AppsError::NotFound(format!("recipe not found: {}", recipe_id.0)))?;

        if current_state != RecipeState::UnderReview {
            return Err(AppsError::InvalidStateTransition {
                from: current_state.to_string(),
                to: "APPROVED".into(),
            });
        }

        let review = RecipeReview {
            review_id: ReviewId(format!(
                "rvw_{}",
                ulid::Ulid::new().to_string().to_lowercase()
            )),
            recipe_id: recipe_id.clone(),
            reviewer_id: reviewer_id.into(),
            verdict: ReviewVerdict::Approve,
            feedback: feedback.into(),
            reviewed_at: Utc::now(),
        };

        self.reviews
            .entry(recipe_id.clone())
            .or_default()
            .push(review.clone());

        Ok(review)
    }

    /// Publish a recipe that has been approved.
    ///
    /// Transitions to `Published` and sets `published_at`.
    /// Emits `RECIPE_PUBLISHED` evidence.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the recipe does not exist.
    /// Returns `InvalidStateTransition` if not `UnderReview`.
    /// Returns `ValidationFailed` if no approval review exists.
    pub fn publish_recipe(&mut self, recipe_id: &RecipeId) -> Result<(), AppsError> {
        let current_state = self
            .recipe_state
            .get(recipe_id)
            .copied()
            .ok_or_else(|| AppsError::NotFound(format!("recipe not found: {}", recipe_id.0)))?;

        if current_state != RecipeState::UnderReview {
            return Err(AppsError::InvalidStateTransition {
                from: current_state.to_string(),
                to: RecipeState::Published.to_string(),
            });
        }

        let has_approval = self
            .reviews
            .get(recipe_id)
            .map(|revs| revs.iter().any(|r| r.verdict == ReviewVerdict::Approve))
            .unwrap_or(false);

        if !has_approval {
            return Err(AppsError::ValidationFailed(
                "cannot publish recipe without an approval review".into(),
            ));
        }

        let recipe = self
            .recipes
            .get_mut(recipe_id)
            .ok_or_else(|| AppsError::NotFound(format!("recipe not found: {}", recipe_id.0)))?;

        recipe.published_at = Some(Utc::now());
        self.recipe_state
            .insert(recipe_id.clone(), RecipeState::Published);

        Ok(())
    }

    /// Flag a recipe for community review.
    ///
    /// Valid from any non-terminal state.
    /// Emits `RECIPE_FLAGGED` evidence.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the recipe does not exist.
    pub fn flag_recipe(&mut self, recipe_id: &RecipeId) -> Result<(), AppsError> {
        if !self.recipes.contains_key(recipe_id) {
            return Err(AppsError::NotFound(format!(
                "recipe not found: {}",
                recipe_id.0
            )));
        }
        self.recipe_state
            .insert(recipe_id.clone(), RecipeState::Flagged);
        Ok(())
    }

    /// Deprecate a published recipe.
    ///
    /// Only valid from `Published` state.
    /// Emits `RECIPE_DEPRECATED` evidence.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the recipe does not exist.
    /// Returns `InvalidStateTransition` if not `Published`.
    pub fn deprecate_recipe(&mut self, recipe_id: &RecipeId) -> Result<(), AppsError> {
        let current_state = self
            .recipe_state
            .get(recipe_id)
            .copied()
            .ok_or_else(|| AppsError::NotFound(format!("recipe not found: {}", recipe_id.0)))?;

        if current_state != RecipeState::Published {
            return Err(AppsError::InvalidStateTransition {
                from: current_state.to_string(),
                to: RecipeState::Deprecated.to_string(),
            });
        }

        self.recipe_state
            .insert(recipe_id.clone(), RecipeState::Deprecated);
        Ok(())
    }

    /// Revoke a recipe permanently.
    ///
    /// Valid from any state. Revoked recipes must not be installed.
    /// Emits `RECIPE_REVOKED` evidence.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the recipe does not exist.
    pub fn revoke_recipe(&mut self, recipe_id: &RecipeId) -> Result<(), AppsError> {
        if !self.recipes.contains_key(recipe_id) {
            return Err(AppsError::NotFound(format!(
                "recipe not found: {}",
                recipe_id.0
            )));
        }
        self.recipe_state
            .insert(recipe_id.clone(), RecipeState::Revoked);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    /// Retrieve a recipe by id.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the recipe does not exist.
    pub fn get_recipe(&self, recipe_id: &RecipeId) -> Result<&Recipe, AppsError> {
        self.recipes
            .get(recipe_id)
            .ok_or_else(|| AppsError::NotFound(format!("recipe not found: {}", recipe_id.0)))
    }

    /// Return the current state of a recipe.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the recipe does not exist.
    pub fn get_recipe_state(&self, recipe_id: &RecipeId) -> Result<RecipeState, AppsError> {
        self.recipe_state
            .get(recipe_id)
            .copied()
            .ok_or_else(|| AppsError::NotFound(format!("recipe not found: {}", recipe_id.0)))
    }

    /// Search recipes by a query string matching against name and description.
    #[must_use]
    pub fn search_recipes(&self, query: &str) -> Vec<&Recipe> {
        let q = query.to_lowercase();
        self.recipes
            .values()
            .filter(|r| {
                r.name.to_lowercase().contains(&q)
                    || r.description.to_lowercase().contains(&q)
            })
            .collect()
    }

    /// Search recipes by a single tag.
    #[must_use]
    pub fn search_by_tag(&self, tag: &str) -> Vec<&Recipe> {
        let t = tag.to_lowercase();
        self.recipes
            .values()
            .filter(|r| r.tags.iter().any(|tag| tag.to_lowercase() == t))
            .collect()
    }

    /// Search recipes by target runtime.
    #[must_use]
    pub fn search_by_runtime(&self, runtime: EcosystemRuntime) -> Vec<&Recipe> {
        self.recipes
            .values()
            .filter(|r| r.target_runtime == runtime)
            .collect()
    }

    /// Return all reviews for a recipe.
    #[must_use]
    pub fn get_reviews(&self, recipe_id: &RecipeId) -> Vec<&RecipeReview> {
        self.reviews
            .get(recipe_id)
            .map(|revs| revs.iter().collect())
            .unwrap_or_default()
    }

    // -----------------------------------------------------------------------
    // Trust badge
    // -----------------------------------------------------------------------

    /// Build the trust badge for a recipe.
    #[must_use]
    pub fn build_trust_badge(&self, recipe_id: &RecipeId) -> Option<RecipeTrustBadge> {
        let recipe = self.recipes.get(recipe_id)?;
        let community_votes = self
            .reviews
            .get(recipe_id)
            .map(|revs| revs.len() as u64)
            .unwrap_or(0);

        let verification_status = self
            .recipe_state
            .get(recipe_id)
            .map(|state| match state {
                RecipeState::Published => {
                    if community_votes >= 3 {
                        RecipeVerificationStatus::VerifiedByCommunity
                    } else {
                        RecipeVerificationStatus::NotVerified
                    }
                }
                RecipeState::UnderReview => RecipeVerificationStatus::VerificationInProgress,
                RecipeState::Flagged | RecipeState::Revoked => {
                    RecipeVerificationStatus::VerificationFailed
                }
                _ => RecipeVerificationStatus::NotVerified,
            })
            .unwrap_or(RecipeVerificationStatus::NotVerified);

        Some(RecipeTrustBadge {
            trust_class: recipe.trust_class,
            verification_status,
            community_votes,
            verified_by: None,
            certificate_ref: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests (inline)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn registry() -> RecipeRegistry {
        RecipeRegistry::new()
    }

    fn recipe_id() -> RecipeId {
        RecipeId(format!(
            "rcp_{}",
            ulid::Ulid::new().to_string().to_lowercase()
        ))
    }

    fn make_recipe(id: RecipeId, name: &str) -> Recipe {
        Recipe {
            recipe_id: id,
            name: name.into(),
            description: format!("Description for {name}"),
            author: "operator-001".into(),
            published_at: None,
            capsule_runtime: EcosystemRuntime::RuntimeLinuxNative,
            source_package_format: "flatpak".into(),
            target_runtime: EcosystemRuntime::RuntimeFlatpak,
            install_steps: vec!["flatpak install flathub org.example.App".into()],
            verify_steps: vec!["flatpak run --command=version org.example.App".into()],
            required_capabilities: vec!["network-outbound".into()],
            sandbox_profile: "default-flatpak".into(),
            trust_class: RecipeTrustClass::RecipeCommunity,
            signature: "ed25519:sig_abc123".into(),
            version: "1.0.0".into(),
            tags: vec!["productivity".into(), "flatpak".into()],
        }
    }

    // -----------------------------------------------------------------------
    // submit_recipe
    // -----------------------------------------------------------------------

    #[test]
    fn submit_recipe_creates_in_proposed_state() {
        let mut reg = registry();
        let id = recipe_id();
        let recipe = make_recipe(id.clone(), "firefox");
        let returned = reg.submit_recipe(recipe).expect("submit");
        assert_eq!(returned, id);
        let state = reg.get_recipe_state(&id).expect("get state");
        assert_eq!(state, RecipeState::Proposed);
    }

    #[test]
    fn submit_empty_name_fails() {
        let mut reg = registry();
        let id = recipe_id();
        let recipe = make_recipe(id, "");
        let result = reg.submit_recipe(recipe);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AppsError::ValidationFailed(_)));
    }

    #[test]
    fn submit_recipe_increments_count() {
        let mut reg = registry();
        assert_eq!(reg.recipe_count(), 0);
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id, "app-a")).expect("submit");
        assert_eq!(reg.recipe_count(), 1);
    }

    // -----------------------------------------------------------------------
    // review_recipe
    // -----------------------------------------------------------------------

    #[test]
    fn review_recipe_transitions_to_under_review() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        let review = reg
            .review_recipe(&id, "reviewer-1", ReviewVerdict::Approve, "looks good")
            .expect("review");
        assert_eq!(review.reviewer_id, "reviewer-1");
        let state = reg.get_recipe_state(&id).expect("get state");
        assert_eq!(state, RecipeState::UnderReview);
    }

    #[test]
    fn review_nonexistent_recipe_fails() {
        let mut reg = registry();
        let id = recipe_id();
        let result = reg.review_recipe(&id, "reviewer-1", ReviewVerdict::Approve, "ok");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppsError::NotFound(_)));
    }

    #[test]
    fn review_when_published_fails() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        reg.review_recipe(&id, "r1", ReviewVerdict::Approve, "ok")
            .expect("review");
        reg.approve_recipe(&id, "r1", "approved").expect("approve");
        reg.publish_recipe(&id).expect("publish");
        // Review on Published should fail
        let result = reg.review_recipe(&id, "r2", ReviewVerdict::Approve, "ok");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AppsError::InvalidStateTransition { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // approve_recipe
    // -----------------------------------------------------------------------

    #[test]
    fn approve_recipe_records_approval() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        reg.review_recipe(&id, "r1", ReviewVerdict::Approve, "ok")
            .expect("review");
        let approval = reg
            .approve_recipe(&id, "r1", "approved after verification")
            .expect("approve");
        assert_eq!(approval.verdict, ReviewVerdict::Approve);
    }

    #[test]
    fn approve_nonexistent_recipe_fails() {
        let mut reg = registry();
        let id = recipe_id();
        let result = reg.approve_recipe(&id, "r1", "feedback");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppsError::NotFound(_)));
    }

    #[test]
    fn approve_when_not_under_review_fails() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        // Still in Proposed — approve should fail
        let result = reg.approve_recipe(&id, "r1", "feedback");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AppsError::InvalidStateTransition { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // publish_recipe
    // -----------------------------------------------------------------------

    #[test]
    fn publish_recipe_full_flow() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        reg.review_recipe(&id, "r1", ReviewVerdict::Approve, "ok")
            .expect("review");
        reg.approve_recipe(&id, "r1", "approved").expect("approve");
        reg.publish_recipe(&id).expect("publish");
        let state = reg.get_recipe_state(&id).expect("get state");
        assert_eq!(state, RecipeState::Published);
        let recipe = reg.get_recipe(&id).expect("get recipe");
        assert!(recipe.published_at.is_some());
    }

    #[test]
    fn publish_without_approval_fails() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        reg.review_recipe(&id, "r1", ReviewVerdict::Reject, "needs work")
            .expect("review");
        let result = reg.publish_recipe(&id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AppsError::ValidationFailed(_)
        ));
    }

    #[test]
    fn publish_nonexistent_fails() {
        let mut reg = registry();
        let id = recipe_id();
        let result = reg.publish_recipe(&id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppsError::NotFound(_)));
    }

    // -----------------------------------------------------------------------
    // get_recipe / search
    // -----------------------------------------------------------------------

    #[test]
    fn get_recipe_returns_correct() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        let recipe = reg.get_recipe(&id).expect("get");
        assert_eq!(recipe.name, "firefox");
    }

    #[test]
    fn get_nonexistent_recipe_fails() {
        let reg = registry();
        let id = recipe_id();
        let result = reg.get_recipe(&id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppsError::NotFound(_)));
    }

    #[test]
    fn search_recipes_by_name() {
        let mut reg = registry();
        let id1 = recipe_id();
        let id2 = recipe_id();
        reg.submit_recipe(make_recipe(id1, "firefox"))
            .expect("submit");
        reg.submit_recipe(make_recipe(id2, "chrome"))
            .expect("submit");
        let results = reg.search_recipes("fire");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "firefox");
    }

    #[test]
    fn search_by_tag_finds_match() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id, "firefox"))
            .expect("submit");
        let results = reg.search_by_tag("productivity");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_by_tag_no_match() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id, "firefox"))
            .expect("submit");
        let results = reg.search_by_tag("gaming");
        assert!(results.is_empty());
    }

    #[test]
    fn search_by_runtime_finds_match() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id, "firefox"))
            .expect("submit");
        let results = reg.search_by_runtime(EcosystemRuntime::RuntimeFlatpak);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_by_runtime_no_match() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id, "firefox"))
            .expect("submit");
        let results = reg.search_by_runtime(EcosystemRuntime::RuntimeAppimage);
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // flag / deprecate / revoke
    // -----------------------------------------------------------------------

    #[test]
    fn flag_recipe_sets_flagged_state() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        reg.flag_recipe(&id).expect("flag");
        let state = reg.get_recipe_state(&id).expect("get state");
        assert_eq!(state, RecipeState::Flagged);
    }

    #[test]
    fn flag_nonexistent_recipe_fails() {
        let mut reg = registry();
        let id = recipe_id();
        let result = reg.flag_recipe(&id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppsError::NotFound(_)));
    }

    #[test]
    fn deprecate_published_recipe() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        reg.review_recipe(&id, "r1", ReviewVerdict::Approve, "ok")
            .expect("review");
        reg.approve_recipe(&id, "r1", "approved").expect("approve");
        reg.publish_recipe(&id).expect("publish");
        reg.deprecate_recipe(&id).expect("deprecate");
        let state = reg.get_recipe_state(&id).expect("get state");
        assert_eq!(state, RecipeState::Deprecated);
    }

    #[test]
    fn deprecate_non_published_fails() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        let result = reg.deprecate_recipe(&id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AppsError::InvalidStateTransition { .. }
        ));
    }

    #[test]
    fn revoke_recipe_from_any_state() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        reg.revoke_recipe(&id).expect("revoke");
        let state = reg.get_recipe_state(&id).expect("get state");
        assert_eq!(state, RecipeState::Revoked);
    }

    // -----------------------------------------------------------------------
    // Trust badge
    // -----------------------------------------------------------------------

    #[test]
    fn trust_badge_for_published_with_votes() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        reg.review_recipe(&id, "r1", ReviewVerdict::Approve, "ok")
            .expect("r1");
        reg.review_recipe(&id, "r2", ReviewVerdict::Approve, "ok")
            .expect("r2");
        reg.review_recipe(&id, "r3", ReviewVerdict::Approve, "ok")
            .expect("r3");
        reg.approve_recipe(&id, "r1", "approved").expect("approve");
        reg.publish_recipe(&id).expect("publish");
        let badge = reg.build_trust_badge(&id).expect("badge");
        assert_eq!(badge.trust_class, RecipeTrustClass::RecipeCommunity);
        assert_eq!(
            badge.verification_status,
            RecipeVerificationStatus::VerifiedByCommunity
        );
        assert_eq!(badge.community_votes, 4);
    }

    #[test]
    fn trust_badge_nonexistent_returns_none() {
        let reg = registry();
        let id = recipe_id();
        let badge = reg.build_trust_badge(&id);
        assert!(badge.is_none());
    }

    // -----------------------------------------------------------------------
    // Install result
    // -----------------------------------------------------------------------

    #[test]
    fn install_result_construction() {
        let id = recipe_id();
        let result = RecipeInstallResult {
            recipe_id: id.clone(),
            installed_capsule_id: "caps_001".into(),
            install_duration: 42,
            verify_result: true,
            evidence_receipt: "evr_abc123".into(),
        };
        assert_eq!(result.recipe_id, id);
        assert!(result.verify_result);
        assert_eq!(result.install_duration, 42);
    }

    // -----------------------------------------------------------------------
    // Evidence constants
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_constants_are_distinct() {
        let events = [
            RECIPE_SUBMITTED,
            RECIPE_APPROVED,
            RECIPE_PUBLISHED,
            RECIPE_FLAGGED,
            RECIPE_DEPRECATED,
            RECIPE_INSTALLED,
        ];
        // All six are distinct
        for i in 0..events.len() {
            for j in (i + 1)..events.len() {
                assert_ne!(events[i], events[j]);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Complete lifecycle flow
    // -----------------------------------------------------------------------

    #[test]
    fn complete_lifecycle_flow() {
        let mut reg = registry();

        // Submit
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "gimp"))
            .expect("submit");
        assert_eq!(reg.get_recipe_state(&id).expect("state"), RecipeState::Proposed);

        // Review
        reg.review_recipe(&id, "r1", ReviewVerdict::Approve, "good")
            .expect("review");
        assert_eq!(
            reg.get_recipe_state(&id).expect("state"),
            RecipeState::UnderReview
        );

        // Approve
        reg.approve_recipe(&id, "r1", "approved").expect("approve");

        // Publish
        reg.publish_recipe(&id).expect("publish");
        assert_eq!(
            reg.get_recipe_state(&id).expect("state"),
            RecipeState::Published
        );
        assert!(reg.get_recipe(&id).expect("recipe").published_at.is_some());

        // Deprecate
        reg.deprecate_recipe(&id).expect("deprecate");
        assert_eq!(
            reg.get_recipe_state(&id).expect("state"),
            RecipeState::Deprecated
        );
    }

    // -----------------------------------------------------------------------
    // RecipeState enum exhaustiveness
    // -----------------------------------------------------------------------

    #[test]
    fn recipe_state_has_7_variants() {
        let variants = [
            RecipeState::Draft,
            RecipeState::Proposed,
            RecipeState::UnderReview,
            RecipeState::Published,
            RecipeState::Flagged,
            RecipeState::Deprecated,
            RecipeState::Revoked,
        ];
        assert_eq!(variants.len(), 7);
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // RecipeVerificationStatus enum exhaustiveness
    // -----------------------------------------------------------------------

    #[test]
    fn verification_status_has_5_variants() {
        let variants = [
            RecipeVerificationStatus::NotVerified,
            RecipeVerificationStatus::VerificationInProgress,
            RecipeVerificationStatus::VerifiedByCommunity,
            RecipeVerificationStatus::VerifiedByAios,
            RecipeVerificationStatus::VerificationFailed,
        ];
        assert_eq!(variants.len(), 5);
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // ReviewVerdict enum exhaustiveness
    // -----------------------------------------------------------------------

    #[test]
    fn review_verdict_has_3_variants() {
        let variants = [
            ReviewVerdict::Approve,
            ReviewVerdict::Reject,
            ReviewVerdict::RequestChanges,
        ];
        assert_eq!(variants.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Review count
    // -----------------------------------------------------------------------

    #[test]
    fn review_count_increments() {
        let mut reg = registry();
        assert_eq!(reg.review_count(), 0);
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        reg.review_recipe(&id, "r1", ReviewVerdict::Approve, "ok")
            .expect("r1");
        assert_eq!(reg.review_count(), 1);
        reg.approve_recipe(&id, "r1", "approved").expect("approve");
        assert_eq!(reg.review_count(), 2);
    }

    // -----------------------------------------------------------------------
    // reject review does not block future approve
    // -----------------------------------------------------------------------

    #[test]
    fn reject_then_approve_works() {
        let mut reg = registry();
        let id = recipe_id();
        reg.submit_recipe(make_recipe(id.clone(), "firefox"))
            .expect("submit");
        reg.review_recipe(&id, "r1", ReviewVerdict::Reject, "needs work")
            .expect("review");
        reg.review_recipe(&id, "r2", ReviewVerdict::Approve, "fixed now")
            .expect("review2");
        reg.approve_recipe(&id, "r2", "approved").expect("approve");
        reg.publish_recipe(&id).expect("publish");
        assert_eq!(
            reg.get_recipe_state(&id).expect("state"),
            RecipeState::Published
        );
    }
}
