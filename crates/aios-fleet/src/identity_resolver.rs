//! Federated identity resolution per S25 §7 / INV-032.
//!
//! The [`FederatedIdentityResolver`] resolves [`FederatedSubjectId`] pairs
//! `(home_realm, local_id)` into fully hydrated [`ResolvedSubject`] records.
//! It enforces the INV-032 loss-free round-trip invariant and the
//! [`CrossOrgTrustDelegation`] ceiling for foreign-realm subjects.
//!
//! # INV-032 Mechanical Invariant
//!
//! The identity system guarantees:
//! ```text
//! (realm:default, old_id) ↔ old_id
//! ```
//! I.e., a legacy identifier round-trips through federated resolution without
//! loss or collision. The [`round_trip_verify`](FederatedIdentityResolver::round_trip_verify)
//! method is the mechanical check for this invariant.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::federated_identity::FederatedSubjectId;
use crate::trust_delegation::CrossOrgTrustDelegation;

// ---------------------------------------------------------------------------
// RealmStatus
// ---------------------------------------------------------------------------

/// The operational status of a registered realm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmStatus {
    /// Realm is active and subjects may be resolved.
    Active,
    /// Realm is temporarily suspended — resolutions return `RealmSuspended`.
    Suspended,
    /// Realm is permanently revoked — resolutions return `RealmRevoked`.
    Revoked,
}

// ---------------------------------------------------------------------------
// RealmDescriptor
// ---------------------------------------------------------------------------

/// Metadata for a registered realm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmDescriptor {
    /// The realm identifier (e.g. `"realm:default"`).
    pub realm: String,
    /// The realm's root Ed25519 verifying key (hex-encoded for JSON compatibility).
    pub root_pubkey: String,
    /// When the realm was first registered.
    pub registered_at: DateTime<Utc>,
    /// Current operational status of the realm.
    pub status: RealmStatus,
}

impl RealmDescriptor {
    /// Creates a new realm descriptor with `Active` status.
    #[must_use]
    pub fn new(realm: String, root_pubkey: String) -> Self {
        Self {
            realm,
            root_pubkey,
            registered_at: Utc::now(),
            status: RealmStatus::Active,
        }
    }

    /// Returns `true` when the realm is in `Active` status.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == RealmStatus::Active
    }

    /// Suspends the realm.
    pub fn suspend(&mut self) {
        self.status = RealmStatus::Suspended;
    }

    /// Revokes the realm permanently.
    pub fn revoke(&mut self) {
        self.status = RealmStatus::Revoked;
    }
}

// ---------------------------------------------------------------------------
// ResolvedSubject
// ---------------------------------------------------------------------------

/// A fully resolved subject from the federated identity system.
///
/// Produced by [`FederatedIdentityResolver::resolve`] and
/// [`FederatedIdentityResolver::resolve_legacy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSubject {
    /// The federated identity id.
    pub federated_id: FederatedSubjectId,
    /// The realm-local identifier.
    pub local_id: String,
    /// `true` when the subject holds admin rights in this realm.
    pub is_admin: bool,
    /// `true` when the subject is an AI agent or application.
    pub is_ai: bool,
    /// The delegation ceiling that caps this subject's authority (foreign-realm only).
    pub delegation_ceiling: Option<CrossOrgTrustDelegation>,
}

impl ResolvedSubject {
    /// Creates a new resolved subject from resolution data.
    #[must_use]
    pub fn new(
        federated_id: FederatedSubjectId,
        is_admin: bool,
        is_ai: bool,
        delegation_ceiling: Option<CrossOrgTrustDelegation>,
    ) -> Self {
        let local_id = federated_id.local_id.clone();
        Self {
            federated_id,
            local_id,
            is_admin,
            is_ai,
            delegation_ceiling,
        }
    }

    /// Returns `true` when the subject belongs to a foreign realm.
    #[must_use]
    pub fn is_foreign(&self) -> bool {
        self.federated_id.is_foreign_realm()
    }

    /// Returns `true` when the subject is subject to a delegation ceiling.
    #[must_use]
    pub fn has_delegation_ceiling(&self) -> bool {
        self.delegation_ceiling.is_some()
    }
}

// ---------------------------------------------------------------------------
// IdentityResolverError
// ---------------------------------------------------------------------------

/// Errors raised by the federated identity resolver.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityResolverError {
    /// The requested realm is not registered.
    #[error("realm not registered: {realm}")]
    RealmNotRegistered {
        /// The realm identifier that could not be found.
        realm: String,
    },

    /// The requested realm is suspended.
    #[error("realm is suspended: {realm}")]
    RealmSuspended {
        /// The suspended realm identifier.
        realm: String,
    },

    /// The requested realm has been permanently revoked.
    #[error("realm is revoked: {realm}")]
    RealmRevoked {
        /// The revoked realm identifier.
        realm: String,
    },

    /// The subject was not found in any registered realm.
    #[error("subject not found: {federated_id}")]
    SubjectNotFound {
        /// The federated subject id that could not be resolved.
        federated_id: FederatedSubjectId,
    },

    /// Legacy id collision detected during resolution.
    #[error("legacy id collision: '{legacy_id}' in realm '{home_realm}' resolves ambiguously")]
    LegacyIdCollision {
        /// The legacy identifier string.
        legacy_id: String,
        /// The realm in which resolution was attempted.
        home_realm: String,
    },

    /// The requested action exceeds the delegation ceiling.
    #[error("action '{action}' exceeds delegation ceiling of '{delegation_id}'")]
    DelegationCeilingExceeded {
        /// The action that was requested.
        action: String,
        /// The delegation id that caps this subject.
        delegation_id: String,
    },

    /// Transitive delegation has an invalid (cyclic) trust path.
    #[error("cyclic delegation path detected at hop {hop_index}: realm '{realm}'")]
    CyclicDelegation {
        /// The hop index where the cycle was detected.
        hop_index: usize,
        /// The realm that created the cycle.
        realm: String,
    },
}

// ---------------------------------------------------------------------------
// FederatedIdentityResolver
// ---------------------------------------------------------------------------

/// The federated identity resolver — resolves subjects across realms.
///
/// Maintains a registry of known realms, their delegation grants, and a local
/// subject cache. Performs INV-032 loss-free round-trip verification.
#[derive(Debug, Clone)]
pub struct FederatedIdentityResolver {
    /// Map of `home_realm → RealmDescriptor`.
    pub realm_registry: HashMap<String, RealmDescriptor>,
    /// Map of `Ulid → CrossOrgTrustDelegation` for fast delegation lookup.
    pub delegations: HashMap<Ulid, CrossOrgTrustDelegation>,
    /// Cache of already-resolved subjects.
    pub subject_cache: HashMap<FederatedSubjectId, ResolvedSubject>,
}

impl FederatedIdentityResolver {
    /// Creates a new empty federated identity resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            realm_registry: HashMap::new(),
            delegations: HashMap::new(),
            subject_cache: HashMap::new(),
        }
    }

    /// Registers a new realm with the given root public key.
    ///
    /// Returns an error if the realm is already registered.
    pub fn register_realm(
        &mut self,
        realm: String,
        root_pubkey: String,
    ) -> Result<RealmDescriptor, IdentityResolverError> {
        if self.realm_registry.contains_key(&realm) {
            return Err(IdentityResolverError::RealmNotRegistered {
                realm: format!(
                    "realm '{}' already registered — use update_realm to modify",
                    realm
                ),
            });
        }

        let descriptor = RealmDescriptor::new(realm.clone(), root_pubkey);
        self.realm_registry.insert(realm, descriptor.clone());
        Ok(descriptor)
    }

    /// Suspends a realm (temporary).
    pub fn suspend_realm(&mut self, realm: &str) -> Result<(), IdentityResolverError> {
        let descriptor = self.realm_registry.get_mut(realm).ok_or_else(|| {
            IdentityResolverError::RealmNotRegistered {
                realm: realm.to_string(),
            }
        })?;
        descriptor.suspend();
        Ok(())
    }

    /// Revokes a realm permanently.
    pub fn revoke_realm(&mut self, realm: &str) -> Result<(), IdentityResolverError> {
        let descriptor = self.realm_registry.get_mut(realm).ok_or_else(|| {
            IdentityResolverError::RealmNotRegistered {
                realm: realm.to_string(),
            }
        })?;
        descriptor.revoke();
        Ok(())
    }

    /// Registers a cross-org trust delegation.
    pub fn register_delegation(&mut self, delegation: CrossOrgTrustDelegation) -> Ulid {
        let id = Ulid::new();
        self.delegations.insert(id, delegation);
        id
    }

    /// Resolves a federated subject id into a fully hydrated [`ResolvedSubject`].
    ///
    /// # INV-032: Loss-free round-trip
    ///
    /// For legacy subjects (`home_realm == "realm:default"`), the resolution
    /// preserves the original local id exactly. Foreign subjects are capped
    /// at their delegation ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityResolverError::RealmNotRegistered`] if the realm is unknown,
    /// [`IdentityResolverError::RealmSuspended`] or [`IdentityResolverError::RealmRevoked`]
    /// if the realm is not active.
    pub fn resolve(
        &mut self,
        federated_id: &FederatedSubjectId,
    ) -> Result<ResolvedSubject, IdentityResolverError> {
        if let Some(cached) = self.subject_cache.get(federated_id) {
            return Ok(cached.clone());
        }

        let descriptor = self
            .realm_registry
            .get(&federated_id.home_realm)
            .ok_or_else(|| IdentityResolverError::RealmNotRegistered {
                realm: federated_id.home_realm.clone(),
            })?;

        match descriptor.status {
            RealmStatus::Active => {}
            RealmStatus::Suspended => {
                return Err(IdentityResolverError::RealmSuspended {
                    realm: federated_id.home_realm.clone(),
                });
            }
            RealmStatus::Revoked => {
                return Err(IdentityResolverError::RealmRevoked {
                    realm: federated_id.home_realm.clone(),
                });
            }
        }

        let delegation_ceiling = self.find_delegation_for_realm(&federated_id.home_realm);

        let is_legacy = federated_id.is_legacy();
        let is_local = !federated_id.is_foreign_realm();

        let resolved = ResolvedSubject::new(
            federated_id.clone(),
            is_legacy || is_local,
            false,
            delegation_ceiling.cloned(),
        );

        self.subject_cache
            .insert(federated_id.clone(), resolved.clone());

        Ok(resolved)
    }

    /// Resolves a legacy (pre-federation) identifier through the backward-compat shim.
    ///
    /// Per S25 §7, legacy ids are wrapped as `(realm:default, legacy_id)`.
    /// The resolved subject inherits local admin status from the default realm.
    pub fn resolve_legacy(
        &mut self,
        legacy_id: &str,
        home_realm: &str,
    ) -> Result<ResolvedSubject, IdentityResolverError> {
        if home_realm == "realm:default" && legacy_id.contains(':') {
            let parts: Vec<&str> = legacy_id.splitn(2, ':').collect();
            if parts.len() == 2 && parts[0] == "realm" {
                return Err(IdentityResolverError::LegacyIdCollision {
                    legacy_id: legacy_id.to_string(),
                    home_realm: home_realm.to_string(),
                });
            }
        }

        let federated_id = FederatedSubjectId {
            home_realm: home_realm.to_string(),
            local_id: legacy_id.to_string(),
        };

        self.resolve(&federated_id)
    }

    /// Checks whether a resolved subject is allowed to perform the given action
    /// within their delegation ceiling.
    ///
    /// Foreign-realm subjects with an active delegation ceiling are checked
    /// against `forbid_admin_actions` and `forbid_ai_subjects`.
    ///
    /// Local-realm subjects always pass this check.
    pub fn check_delegation_ceiling(
        &self,
        subject: &ResolvedSubject,
        requested_action: &str,
    ) -> Result<(), IdentityResolverError> {
        if !subject.is_foreign() {
            return Ok(());
        }

        let ceiling = match &subject.delegation_ceiling {
            Some(c) => c,
            None => return Ok(()),
        };

        let is_admin_action = matches!(
            requested_action,
            "GrantAdmin" | "OverrideHostPolicy" | "ApproveRouting" | "AuthorCheckpoint"
        );

        if is_admin_action && ceiling.forbid_admin_actions {
            return Err(IdentityResolverError::DelegationCeilingExceeded {
                action: requested_action.to_string(),
                delegation_id: ceiling.delegation_id.clone(),
            });
        }

        if subject.is_ai && ceiling.forbid_ai_subjects {
            return Err(IdentityResolverError::DelegationCeilingExceeded {
                action: requested_action.to_string(),
                delegation_id: ceiling.delegation_id.clone(),
            });
        }

        Ok(())
    }

    /// INV-032 mechanical check: verifies that a legacy identifier round-trips
    /// loss-free through federated resolution.
    ///
    /// Returns `true` when `(realm:default, original_local_id) == resolve(original_local_id).local_id`.
    #[must_use]
    pub fn round_trip_verify(&self, id: &FederatedSubjectId) -> bool {
        if !id.is_legacy() {
            return true;
        }

        let re_resolved = FederatedSubjectId::resolve_legacy(&id.local_id);
        re_resolved == *id
    }

    /// Clears the subject cache, forcing fresh resolution on the next lookup.
    pub fn clear_cache(&mut self) {
        self.subject_cache.clear();
    }

    /// Returns the number of cached subject resolutions.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.subject_cache.len()
    }

    /// Finds the delegation that covers the given target realm.
    fn find_delegation_for_realm(&self, target_realm: &str) -> Option<&CrossOrgTrustDelegation> {
        self.delegations
            .values()
            .find(|d| d.to_realm == target_realm || d.from_realm == target_realm)
    }
}

impl Default for FederatedIdentityResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_resolver() -> FederatedIdentityResolver {
        let mut resolver = FederatedIdentityResolver::new();
        resolver
            .register_realm("realm:default".into(), "default_pubkey_hex".into())
            .unwrap();
        resolver
            .register_realm("realm:alpha".into(), "alpha_pubkey_hex".into())
            .unwrap();
        resolver
            .register_realm("realm:beta".into(), "beta_pubkey_hex".into())
            .unwrap();

        let delegation = CrossOrgTrustDelegation::new(
            "del_01".into(),
            "realm:default".into(),
            "realm:alpha".into(),
            crate::enums::TrustDelegationDirection::Bidirectional,
        );
        resolver.register_delegation(delegation);
        resolver
    }

    fn setup_resolver_with_permissive_delegation() -> FederatedIdentityResolver {
        let mut resolver = FederatedIdentityResolver::new();
        resolver
            .register_realm("realm:default".into(), "default_pubkey_hex".into())
            .unwrap();
        resolver
            .register_realm("realm:partner".into(), "partner_pubkey_hex".into())
            .unwrap();

        let mut delegation = CrossOrgTrustDelegation::new(
            "del_permissive".into(),
            "realm:default".into(),
            "realm:partner".into(),
            crate::enums::TrustDelegationDirection::Bidirectional,
        );
        delegation.forbid_admin_actions = false;
        delegation.forbid_ai_subjects = false;
        resolver.register_delegation(delegation);
        resolver
    }

    // --- Realm registration ---

    #[test]
    fn register_realm_creates_descriptor() {
        let mut resolver = FederatedIdentityResolver::new();
        let desc = resolver
            .register_realm("realm:test".into(), "pk_test".into())
            .unwrap();
        assert_eq!(desc.realm, "realm:test");
        assert_eq!(desc.root_pubkey, "pk_test");
        assert_eq!(desc.status, RealmStatus::Active);
        assert!(resolver.realm_registry.contains_key("realm:test"));
    }

    #[test]
    fn register_duplicate_realm_fails() {
        let mut resolver = FederatedIdentityResolver::new();
        resolver
            .register_realm("realm:dup".into(), "pk1".into())
            .unwrap();
        let result = resolver.register_realm("realm:dup".into(), "pk2".into());
        assert!(result.is_err());
    }

    // --- Realm suspension and revocation ---

    #[test]
    fn suspend_realm_prevents_resolution() {
        let mut resolver = FederatedIdentityResolver::new();
        resolver
            .register_realm("realm:tmp".into(), "pk_tmp".into())
            .unwrap();
        resolver.suspend_realm("realm:tmp").unwrap();

        let fid = FederatedSubjectId::new("realm:tmp".into(), "user1".into());
        let result = resolver.resolve(&fid);
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityResolverError::RealmSuspended { realm } => {
                assert_eq!(realm, "realm:tmp");
            }
            other => panic!("expected RealmSuspended, got: {:?}", other),
        }
    }

    #[test]
    fn revoke_realm_prevents_resolution() {
        let mut resolver = FederatedIdentityResolver::new();
        resolver
            .register_realm("realm:gone".into(), "pk_gone".into())
            .unwrap();
        resolver.revoke_realm("realm:gone").unwrap();

        let fid = FederatedSubjectId::new("realm:gone".into(), "user1".into());
        let result = resolver.resolve(&fid);
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityResolverError::RealmRevoked { realm } => {
                assert_eq!(realm, "realm:gone");
            }
            other => panic!("expected RealmRevoked, got: {:?}", other),
        }
    }

    // --- Subject resolution ---

    #[test]
    fn resolve_local_subject_from_active_realm() {
        let mut resolver = setup_resolver();
        let fid = FederatedSubjectId::new("realm:default".into(), "family:alice".into());
        let resolved = resolver.resolve(&fid).unwrap();
        assert_eq!(resolved.local_id, "family:alice");
        assert_eq!(resolved.federated_id, fid);
        assert!(resolved.is_admin);
        assert!(!resolved.is_ai);
    }

    #[test]
    fn resolve_foreign_subject_has_delegation_ceiling() {
        let mut resolver = setup_resolver();
        let fid = FederatedSubjectId::new("realm:alpha".into(), "foreign_user".into());
        let resolved = resolver.resolve(&fid).unwrap();
        assert!(resolved.is_foreign());
        assert!(resolved.has_delegation_ceiling());
    }

    #[test]
    fn resolve_unknown_realm_fails() {
        let mut resolver = setup_resolver();
        let fid = FederatedSubjectId::new("realm:unknown".into(), "ghost".into());
        let result = resolver.resolve(&fid);
        assert!(result.is_err());
        match result.unwrap_err() {
            IdentityResolverError::RealmNotRegistered { realm } => {
                assert_eq!(realm, "realm:unknown");
            }
            other => panic!("expected RealmNotRegistered, got: {:?}", other),
        }
    }

    // --- INV-032 round-trip ---

    #[test]
    fn inv_032_round_trip_verify_passes_for_legacy_id() {
        let resolver = setup_resolver();
        let fid = FederatedSubjectId::resolve_legacy("family:alice");
        assert!(resolver.round_trip_verify(&fid));
    }

    #[test]
    fn inv_032_round_trip_verify_passes_for_non_legacy_id() {
        let resolver = setup_resolver();
        let fid = FederatedSubjectId::new("realm:alpha".into(), "user1".into());
        assert!(resolver.round_trip_verify(&fid));
    }

    // --- Legacy resolution ---

    #[test]
    fn resolve_legacy_shim_returns_correct_subject() {
        let mut resolver = setup_resolver();
        let subject = resolver
            .resolve_legacy("family:alice", "realm:default")
            .unwrap();
        assert_eq!(subject.local_id, "family:alice");
        assert_eq!(subject.federated_id.home_realm, "realm:default");
    }

    #[test]
    fn resolve_legacy_collision_detected() {
        let mut resolver = setup_resolver();
        let result = resolver.resolve_legacy("realm:default:duplicate", "realm:default");
        assert!(result.is_err());
    }

    // --- Delegation ceiling ---

    #[test]
    fn delegation_ceiling_allows_local_subject() {
        let resolver = setup_resolver();
        let subject = ResolvedSubject::new(
            FederatedSubjectId::resolve_legacy("admin1"),
            true,
            false,
            None,
        );
        let result = resolver.check_delegation_ceiling(&subject, "GrantAdmin");
        assert!(result.is_ok());
    }

    #[test]
    fn delegation_ceiling_blocks_admin_action_for_foreign_subject() {
        let resolver = setup_resolver();
        let delegation = CrossOrgTrustDelegation::new(
            "del_01".into(),
            "realm:default".into(),
            "realm:alpha".into(),
            crate::enums::TrustDelegationDirection::InboundAccept,
        );
        let subject = ResolvedSubject::new(
            FederatedSubjectId::new("realm:alpha".into(), "foreigner".into()),
            true,
            false,
            Some(delegation),
        );
        let result = resolver.check_delegation_ceiling(&subject, "GrantAdmin");
        assert!(result.is_err());
    }

    #[test]
    fn delegation_ceiling_allows_permissive_actions() {
        let resolver = setup_resolver_with_permissive_delegation();
        let delegation = resolver
            .delegations
            .values()
            .find(|d| d.delegation_id == "del_permissive")
            .cloned()
            .unwrap();

        let subject = ResolvedSubject::new(
            FederatedSubjectId::new("realm:partner".into(), "partner_user".into()),
            true,
            false,
            Some(delegation),
        );
        let result = resolver.check_delegation_ceiling(&subject, "AuthorCheckpoint");
        assert!(result.is_ok());
    }

    // --- Cache ---

    #[test]
    fn subject_cache_avoids_double_resolution() {
        let mut resolver = setup_resolver();
        let fid = FederatedSubjectId::resolve_legacy("cached_user");
        let _ = resolver.resolve(&fid).unwrap();
        assert_eq!(resolver.cache_size(), 1);
        let _ = resolver.resolve(&fid).unwrap();
        assert_eq!(resolver.cache_size(), 1);
    }

    #[test]
    fn clear_cache_empties_subject_cache() {
        let mut resolver = setup_resolver();
        let fid = FederatedSubjectId::resolve_legacy("temp_user");
        let _ = resolver.resolve(&fid).unwrap();
        assert_eq!(resolver.cache_size(), 1);
        resolver.clear_cache();
        assert_eq!(resolver.cache_size(), 0);
    }

    // --- Default impl ---

    #[test]
    fn default_resolver_is_empty() {
        let resolver = FederatedIdentityResolver::default();
        assert!(resolver.realm_registry.is_empty());
        assert!(resolver.delegations.is_empty());
        assert_eq!(resolver.cache_size(), 0);
    }
}
