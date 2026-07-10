//! Component Registry — MINIX-inspired process table for AIOS.
//!
//! The [`ComponentRegistry`] is the single source of truth for every component
//! in the system: its identity, type, declared dependencies, expected initial
//! state, and isolation level.  This eliminates the "cannot heal unknown
//! component" problem caused by ad-hoc component maps in the driver.

#![allow(
    clippy::module_name_repetitions,
    reason = "Public names mirror the MINIX process-table vocabulary"
)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::self_healing::ComponentHealthState;
pub use crate::self_healing::ComponentIsolationLevel;

// ---------------------------------------------------------------------------
// Registry entry
// ---------------------------------------------------------------------------

/// A single row in the component registry — one AIOS component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RegistryEntry {
    /// Unique component identifier (e.g. `"aios-network-manager"`).
    pub component_id: String,
    /// Human-readable display name (e.g. `"Network Manager"`).
    pub display_name: String,
    /// Optional type tag used for grouping and routing (e.g. `"infrastructure"`).
    #[serde(default)]
    pub component_type: Option<String>,
    /// Component IDs this component depends on (must be healthy first).
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// The component's expected initial health state after boot.
    ///
    /// When the registry is resolved, this is the baseline state that a
    /// freshly-booted component should report.  Deviations from this state
    /// (e.g. `Healthy` expected but `Failed` observed) trigger a graded
    /// escalation through the self-healing policy.
    pub expected_initial_state: ComponentHealthState,
    /// Isolation policy for this component.
    pub isolation_level: ComponentIsolationLevel,
}

impl RegistryEntry {
    /// Create a minimal registry entry with sensible defaults.
    #[must_use]
    pub fn new(component_id: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            component_id: component_id.into(),
            display_name: display_name.into(),
            component_type: None,
            dependencies: Vec::new(),
            expected_initial_state: ComponentHealthState::Healthy,
            isolation_level: ComponentIsolationLevel::default(),
        }
    }

    /// Builder: set the component type tag.
    #[must_use]
    pub fn with_type(mut self, component_type: impl Into<String>) -> Self {
        self.component_type = Some(component_type.into());
        self
    }

    /// Builder: set the dependency list.
    #[must_use]
    pub fn with_dependencies(mut self, deps: Vec<String>) -> Self {
        self.dependencies = deps;
        self
    }

    /// Builder: set the expected initial health state.
    #[must_use]
    pub const fn with_expected_initial_state(mut self, state: ComponentHealthState) -> Self {
        self.expected_initial_state = state;
        self
    }

    /// Builder: set the isolation level.
    #[must_use]
    pub const fn with_isolation_level(mut self, level: ComponentIsolationLevel) -> Self {
        self.isolation_level = level;
        self
    }
}

// ---------------------------------------------------------------------------
// ComponentRegistry
// ---------------------------------------------------------------------------

/// Centralised process table that knows about every AIOS component.
///
/// Replaces the ad-hoc component maps in the self-healing driver so every
/// component is known in advance — no more "cannot heal unknown component"
/// failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentRegistry {
    registry: HashMap<String, RegistryEntry>,
}

impl Default for ComponentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ComponentRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
        }
    }

    /// Create a registry pre-populated from an iterator of entries.
    #[must_use]
    pub fn from_entries(entries: impl IntoIterator<Item = RegistryEntry>) -> Self {
        let mut reg = Self::new();
        for entry in entries {
            reg.register(entry);
        }
        reg
    }

    /// Register a component.  Overwrites any existing entry with the same id.
    pub fn register(&mut self, entry: RegistryEntry) {
        self.registry.insert(entry.component_id.clone(), entry);
    }

    /// Remove a component from the registry.
    ///
    /// Returns the removed entry or `None` if it was not registered.
    pub fn deregister(&mut self, component_id: &str) -> Option<RegistryEntry> {
        self.registry.remove(component_id)
    }

    /// Look up a component by id.
    #[must_use]
    pub fn resolve(&self, component_id: &str) -> Option<&RegistryEntry> {
        self.registry.get(component_id)
    }

    /// Return the ids of all components that `component_id` declares as
    /// dependencies.
    #[must_use]
    pub fn dependencies_of(&self, component_id: &str) -> Vec<String> {
        self.resolve(component_id)
            .map(|e| e.dependencies.clone())
            .unwrap_or_default()
    }

    /// Return the ids of all components that depend on `component_id`.
    #[must_use]
    pub fn dependents_of(&self, component_id: &str) -> Vec<String> {
        self.registry
            .iter()
            .filter_map(|(cid, entry)| {
                if entry.dependencies.contains(&component_id.to_owned()) {
                    Some(cid.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return a snapshot of all registered entries.
    #[must_use]
    pub fn all_entries(&self) -> Vec<&RegistryEntry> {
        self.registry.values().collect()
    }

    /// Return the number of registered components.
    #[must_use]
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// Return `true` when no components are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
    }

    /// Return the isolation level for a component, or the [`ComponentIsolationLevel::default`] if
    /// the component is not registered.
    #[must_use]
    pub fn isolation_level_of(&self, component_id: &str) -> ComponentIsolationLevel {
        self.resolve(component_id)
            .map(|e| e.isolation_level)
            .unwrap_or_default()
    }
}
