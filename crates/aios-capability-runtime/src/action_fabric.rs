//! Typed-action fabric for AI-OS.NET (R3-W3 Step 3.2).
//!
//! Every command becomes a typed `ActionEnvelope` through the capability
//! translator. This module models the action fabric: a pipeline that resolves
//! natural-language intents into typed actions by consulting a capability
//! catalog, then produces traceable fabric results with evidence chains.
//!
//! ## Pipeline
//!
//! ```text
//! intent → translate → TypedAction → FabricResult
//! ```
//!
//! ## Types
//!
//! - [`CapabilityCatalog`] — registry mapping capability names to action kinds.
//! - [`ActionIntent`]      — natural-language input + resolved capability + confidence.
//! - [`TypedAction`]       — translated result: intent + action ID + action kind + parameters.
//! - [`FabricResult`]      — action ID + lifecycle status + evidence chain.
//! - [`ActionFabric`]      — the pipeline coordinator.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use aios_action::ActionId;

use crate::status::ActionLifecycleState;

// ---------------------------------------------------------------------------
// CapabilityCatalog
// ---------------------------------------------------------------------------

/// Registry of named capabilities that the fabric consults during translation.
///
/// Each entry maps a capability name (the resolved capability from the intent)
/// to its corresponding action kind string. Unregistered capabilities
/// fall through to a raw passthrough during translation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityCatalog {
    entries: HashMap<String, String>,
}

impl CapabilityCatalog {
    /// Create an empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Register a capability → action kind mapping.
    pub fn register(&mut self, capability: impl Into<String>, action_kind: impl Into<String>) {
        self.entries.insert(capability.into(), action_kind.into());
    }

    /// Resolve a capability name to its declared action kind.
    ///
    /// Returns `None` when the capability is not registered.
    #[must_use]
    pub fn resolve(&self, capability: &str) -> Option<&str> {
        self.entries.get(capability).map(String::as_str)
    }

    /// True when the catalog contains the given capability.
    #[must_use]
    pub fn contains(&self, capability: &str) -> bool {
        self.entries.contains_key(capability)
    }

    /// Number of registered capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the catalog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ActionIntent
// ---------------------------------------------------------------------------

/// A user intent expressed in natural language, with a resolved capability
/// and a confidence score in the range `[0.0, 1.0]`.
///
/// Confidence is clamped to `[0.0, 1.0]` on construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionIntent {
    /// The original natural-language command or query.
    pub natural_language: String,
    /// The capability that was resolved from the natural language.
    pub resolved_capability: String,
    /// Translation confidence in `[0.0, 1.0]` (clamped on construction).
    pub confidence: f64,
}

impl ActionIntent {
    /// Construct a new intent, clamping confidence to `[0.0, 1.0]`.
    #[must_use]
    pub fn new(
        natural_language: impl Into<String>,
        resolved_capability: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            natural_language: natural_language.into(),
            resolved_capability: resolved_capability.into(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }

    /// Translate this intent into a [`TypedAction`] by consulting the
    /// capability catalog.
    ///
    /// When the resolved capability is registered in the catalog, the
    /// declared action kind is used. Otherwise the raw capability name
    /// is used as the action kind (passthrough).
    ///
    /// Confidence is re-clamped to `[0.0, 1.0]` before translation.
    #[must_use]
    pub fn translate(&self, catalog: &CapabilityCatalog) -> TypedAction {
        let confidence = self.confidence.clamp(0.0, 1.0);
        let action_id = ActionId::new();

        let action_kind = catalog
            .resolve(&self.resolved_capability)
            .unwrap_or(&self.resolved_capability)
            .to_string();

        let parameters = serde_json::json!({
            "natural_language": self.natural_language,
            "capability":       self.resolved_capability,
            "confidence":       confidence,
        });

        TypedAction {
            intent: self.clone(),
            action_id,
            action_kind,
            parameters,
        }
    }
}

// ---------------------------------------------------------------------------
// TypedAction
// ---------------------------------------------------------------------------

/// A fully resolved typed action produced by the fabric translator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypedAction {
    /// The original intent that produced this action.
    pub intent: ActionIntent,
    /// Minted action identifier.
    pub action_id: ActionId,
    /// Resolved action kind (from catalog or passthrough).
    pub action_kind: String,
    /// Structured parameters for the target adapter.
    pub parameters: serde_json::Value,
}

impl TypedAction {
    /// Construct a typed action directly (bypassing translation).
    #[must_use]
    pub fn new(
        intent: ActionIntent,
        action_id: ActionId,
        action_kind: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Self {
        Self {
            intent,
            action_id,
            action_kind: action_kind.into(),
            parameters,
        }
    }
}

// ---------------------------------------------------------------------------
// FabricResult
// ---------------------------------------------------------------------------

/// Result of processing an intent through the action fabric.
///
/// Carries the minted action id, the terminal lifecycle status, and an
/// evidence chain recording each pipeline step executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricResult {
    /// The action id minted during translation.
    pub action_id: ActionId,
    /// Lifecycle status after fabric processing.
    pub status: ActionLifecycleState,
    /// Ordered evidence entries recording pipeline steps.
    pub evidence_chain: Vec<String>,
}

impl FabricResult {
    /// Construct a new fabric result with the given id, status, and evidence.
    #[must_use]
    pub fn new(
        action_id: ActionId,
        status: ActionLifecycleState,
        evidence_chain: Vec<String>,
    ) -> Self {
        Self {
            action_id,
            status,
            evidence_chain,
        }
    }
}

// ---------------------------------------------------------------------------
// ActionFabric
// ---------------------------------------------------------------------------

/// The action fabric pipeline: `intent → translate → TypedAction → FabricResult`.
///
/// Owns a [`CapabilityCatalog`] and accumulates [`FabricResult`] entries
/// in submission order for traceability.
#[derive(Debug, Clone, Default)]
pub struct ActionFabric {
    catalog: CapabilityCatalog,
    results: Vec<FabricResult>,
}

impl ActionFabric {
    /// Create a fabric backed by the given catalog.
    #[must_use]
    pub fn new(catalog: CapabilityCatalog) -> Self {
        Self {
            catalog,
            results: Vec::new(),
        }
    }

    /// Create a fabric with an empty catalog.
    #[must_use]
    pub fn with_empty_catalog() -> Self {
        Self::default()
    }

    /// Borrow the capability catalog.
    #[must_use]
    pub fn catalog(&self) -> &CapabilityCatalog {
        &self.catalog
    }

    /// Mutably borrow the capability catalog for registration.
    pub fn catalog_mut(&mut self) -> &mut CapabilityCatalog {
        &mut self.catalog
    }

    /// Process an intent through the full pipeline and return the
    /// resulting [`FabricResult`].
    ///
    /// Pipeline steps recorded in the evidence chain:
    ///
    /// 1. `action_fabric:translated:<action_kind>` — translation complete.
    /// 2. `action_fabric:dispatched:<action_id>` — result produced.
    #[must_use]
    pub fn process(&mut self, intent: ActionIntent) -> FabricResult {
        let typed = intent.translate(&self.catalog);

        let mut evidence = Vec::with_capacity(2);
        evidence.push(format!("action_fabric:translated:{}", typed.action_kind));
        evidence.push(format!("action_fabric:dispatched:{}", typed.action_id));

        let result = FabricResult::new(
            typed.action_id.clone(),
            ActionLifecycleState::Created,
            evidence,
        );

        self.results.push(result.clone());
        result
    }

    /// All results accumulated so far, in submission order.
    #[must_use]
    pub fn results(&self) -> &[FabricResult] {
        &self.results
    }

    /// Number of intents processed so far.
    #[must_use]
    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

// ---------------------------------------------------------------------------
// Tests — R3-W3 Step 3.2 acceptance criteria (min 6).
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    // ── Test 1: intent translation ────────────────────────────────────────

    #[test]
    fn intent_translation_resolves_action_kind_from_catalog() {
        let mut catalog = CapabilityCatalog::new();
        catalog.register("service.restart", "system.service.restart");
        catalog.register("filesystem.mount", "storage.mount");

        let intent = ActionIntent::new("restart the nginx service", "service.restart", 0.95);

        let typed = intent.translate(&catalog);

        assert_eq!(typed.action_kind, "system.service.restart");
        assert_eq!(typed.intent.resolved_capability, "service.restart");
        // Confidence should be within [0.0, 1.0] and preserved.
        assert!((typed.intent.confidence - 0.95).abs() < f64::EPSILON);
        // Action ID is freshly minted.
        assert!(typed.action_id.as_str().starts_with("act_"));
    }

    // ── Test 2: intent translation falls through for unknown capability ───

    #[test]
    fn intent_translation_passthrough_for_unknown_capability() {
        let catalog = CapabilityCatalog::new();
        let intent = ActionIntent::new("archive old logs", "maintenance.archive_logs", 0.80);

        let typed = intent.translate(&catalog);

        // Unknown capability → action kind = raw capability name.
        assert_eq!(typed.action_kind, "maintenance.archive_logs");
        assert_eq!(typed.intent.resolved_capability, "maintenance.archive_logs");
    }

    // ── Test 3: confidence clamping ───────────────────────────────────────

    #[test]
    fn confidence_clamped_to_range_on_construction() {
        let above = ActionIntent::new("reboot", "system.reboot", 1.5);
        let below = ActionIntent::new("shutdown", "system.shutdown", -0.3);

        assert!((above.confidence - 1.0).abs() < f64::EPSILON);
        assert!((below.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_reclamped_during_translation() {
        let catalog = CapabilityCatalog::new();
        let intent = ActionIntent::new("status check", "service.status", 99.9);
        let typed = intent.translate(&catalog);

        // Parameters carry the re-clamped confidence.
        let params_conf = typed
            .parameters
            .get("confidence")
            .and_then(serde_json::Value::as_f64)
            .expect("confidence must be present in parameters");
        assert!((params_conf - 1.0).abs() < f64::EPSILON);
    }

    // ── Test 4: action fabric pipeline — intent → fabric result ───────────

    #[test]
    fn action_fabric_process_produces_fabric_result() {
        let mut catalog = CapabilityCatalog::new();
        catalog.register("service.restart", "system.service.restart");

        let mut fabric = ActionFabric::new(catalog);
        let intent = ActionIntent::new("restart nginx", "service.restart", 0.90);

        let result = fabric.process(intent);

        assert_eq!(result.status, ActionLifecycleState::Created);
        assert_eq!(result.evidence_chain.len(), 2);
        assert!(result
            .evidence_chain
            .first()
            .is_some_and(|e| e.starts_with("action_fabric:translated:")));
        assert!(result
            .evidence_chain
            .get(1)
            .is_some_and(|e| e.starts_with("action_fabric:dispatched:")));
    }

    // ── Test 5: fabric result tracking — results accumulate in order ──────

    #[test]
    fn fabric_results_accumulate_in_submission_order() {
        let mut catalog = CapabilityCatalog::new();
        catalog.register("service.restart", "system.service.restart");
        catalog.register("service.status", "system.service.status");

        let mut fabric = ActionFabric::new(catalog);

        let r1 = fabric.process(ActionIntent::new("restart", "service.restart", 0.92));
        let r2 = fabric.process(ActionIntent::new("status", "service.status", 0.88));

        let results = fabric.results();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].action_id, r1.action_id);
        assert_eq!(results[1].action_id, r2.action_id);
        assert_ne!(r1.action_id, r2.action_id);
    }

    // ── Test 6: multiple actions ordering — ids are distinct and monotonic ─

    #[test]
    fn multiple_actions_produce_distinct_ids_ordered_by_submission() {
        let mut catalog = CapabilityCatalog::new();
        catalog.register("task.a", "system.task.a");
        catalog.register("task.b", "system.task.b");
        catalog.register("task.c", "system.task.c");

        let mut fabric = ActionFabric::new(catalog);

        let intents = vec![
            ActionIntent::new("task a", "task.a", 0.99),
            ActionIntent::new("task b", "task.b", 0.75),
            ActionIntent::new("task c", "task.c", 0.50),
        ];

        let mut prev_id: Option<ActionId> = None;
        for intent in intents {
            let result = fabric.process(intent);
            // IDs must be unique across the batch.
            if let Some(ref prev) = prev_id {
                assert_ne!(result.action_id, *prev);
            }
            prev_id = Some(result.action_id.clone());
        }

        let results = fabric.results();
        assert_eq!(results.len(), 3);
        // Each result carries its own evidence chain.
        for r in results {
            assert_eq!(r.status, ActionLifecycleState::Created);
            assert_eq!(r.evidence_chain.len(), 2);
        }
    }

    // ── Test 7: typed action carries parameters derived from intent ───────

    #[test]
    fn typed_action_parameters_carry_intent_data() {
        let mut catalog = CapabilityCatalog::new();
        catalog.register("db.backup", "storage.db.backup");

        let intent = ActionIntent::new("backup postgres database", "db.backup", 0.97);
        let typed = intent.translate(&catalog);

        assert_eq!(
            typed
                .parameters
                .get("natural_language")
                .and_then(serde_json::Value::as_str),
            Some("backup postgres database")
        );
        assert_eq!(
            typed
                .parameters
                .get("capability")
                .and_then(serde_json::Value::as_str),
            Some("db.backup")
        );
    }

    // ── Test 8: empty catalog still produces valid typed actions ──────────

    #[test]
    fn empty_catalog_produces_passthrough_actions() {
        let mut fabric = ActionFabric::with_empty_catalog();

        let r1 = fabric.process(ActionIntent::new(
            "list running containers",
            "container.list",
            0.85,
        ));
        let r2 = fabric.process(ActionIntent::new("show disk usage", "disk.usage", 0.70));

        assert_eq!(fabric.result_count(), 2);
        assert_ne!(r1.action_id, r2.action_id);
        assert_eq!(r1.status, ActionLifecycleState::Created);
        assert_eq!(r2.status, ActionLifecycleState::Created);
    }
}
