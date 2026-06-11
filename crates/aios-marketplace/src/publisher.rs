use ulid::Ulid;
use crate::enums::PublisherTier;
use crate::error::MarketplaceError;

/// A publisher registered in the AIOS marketplace.
#[derive(Debug, Clone)]
pub struct Publisher {
    /// Unique publisher identifier (`pub_` + ULID).
    pub publisher_id: String,
    /// Human-readable publisher name.
    pub name: String,
    /// Trust tier assigned through the onboarding FSM.
    pub tier: PublisherTier,
    /// Reference to the Ed25519 public key used for signing.
    pub signing_key_ref: Option<String>,
    /// Subject ID of the reviewer who verified this publisher.
    pub verified_by: Option<String>,
    /// Evidence receipt from the onboarding flow.
    pub onboarding_receipt: Option<String>,
}

impl Publisher {
    #[must_use]
    pub fn new(name: impl Into<String>, signing_key_ref: Option<String>) -> Self {
        Self {
            publisher_id: format!("pub_{}", Ulid::new()),
            name: name.into(),
            tier: PublisherTier::Unverified,
            signing_key_ref,
            verified_by: None,
            onboarding_receipt: None,
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.tier != PublisherTier::Unverified
    }

    #[must_use]
    pub fn is_aios_core(&self) -> bool {
        self.tier == PublisherTier::AiosCore
    }
}

/// In-memory registry of marketplace publishers.
///
/// Production implementations persist to the AIOS-root-signed publisher catalog
/// (`pubcat_<hex>` per S11.1 §3.1); this implementation provides the type
/// surface and FSM transitions.
#[derive(Debug, Default)]
pub struct PublisherRegistry {
    publishers: Vec<Publisher>,
}

impl PublisherRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, publisher: Publisher) -> Result<&Publisher, MarketplaceError> {
        if self.publishers.iter().any(|p| p.publisher_id == publisher.publisher_id) {
            return Err(MarketplaceError::PublisherAlreadyRegistered(
                publisher.publisher_id,
            ));
        }
        self.publishers.push(publisher);
        Ok(self.publishers.last().unwrap())
    }

    pub fn verify(
        &mut self,
        publisher_id: &str,
        reviewer_id: &str,
    ) -> Result<&Publisher, MarketplaceError> {
        let publisher = self
            .publishers
            .iter_mut()
            .find(|p| p.publisher_id == publisher_id)
            .ok_or_else(|| MarketplaceError::PublisherNotFound(publisher_id.to_string()))?;

        if publisher.tier != PublisherTier::Unverified {
            return Err(MarketplaceError::InvalidStateTransition {
                from: publisher.tier.to_string(),
                to: PublisherTier::CommunityVerified.to_string(),
            });
        }

        publisher.tier = PublisherTier::CommunityVerified;
        publisher.verified_by = Some(reviewer_id.to_string());
        Ok(publisher)
    }

    pub fn promote(
        &mut self,
        publisher_id: &str,
        new_tier: PublisherTier,
        reviewer_id: &str,
    ) -> Result<&Publisher, MarketplaceError> {
        let publisher = self
            .publishers
            .iter_mut()
            .find(|p| p.publisher_id == publisher_id)
            .ok_or_else(|| MarketplaceError::PublisherNotFound(publisher_id.to_string()))?;

        if new_tier == PublisherTier::AiosCore {
            return Err(MarketplaceError::SelfPromotionForbidden(
                publisher_id.to_string(),
                new_tier.to_string(),
            ));
        }

        if new_tier == PublisherTier::Unverified {
            return Err(MarketplaceError::InvalidStateTransition {
                from: publisher.tier.to_string(),
                to: new_tier.to_string(),
            });
        }

        publisher.tier = new_tier;
        publisher.verified_by = Some(reviewer_id.to_string());
        Ok(publisher)
    }

    pub fn suspend(
        &mut self,
        publisher_id: &str,
        _reason: &str,
    ) -> Result<&Publisher, MarketplaceError> {
        let publisher = self
            .publishers
            .iter_mut()
            .find(|p| p.publisher_id == publisher_id)
            .ok_or_else(|| MarketplaceError::PublisherNotFound(publisher_id.to_string()))?;

        publisher.tier = PublisherTier::Unverified;
        Ok(publisher)
    }

    pub fn find(&self, publisher_id: &str) -> Option<&Publisher> {
        self.publishers.iter().find(|p| p.publisher_id == publisher_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.publishers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.publishers.is_empty()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn new_publisher_starts_unverified() {
        let p = Publisher::new("Acme Corp", None);
        assert_eq!(p.tier, PublisherTier::Unverified);
        assert!(!p.is_active());
        assert!(!p.is_aios_core());
    }

    #[test]
    fn registry_register_succeeds() {
        let mut reg = PublisherRegistry::new();
        let p = Publisher::new("Acme", None);
        let result = reg.register(p);
        assert!(result.is_ok());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_duplicate_register_fails() {
        let mut reg = PublisherRegistry::new();
        let p = Publisher::new("Acme", None);
        let _ = reg.register(p.clone());
        let result = reg.register(p);
        assert!(result.is_err());
    }

    #[test]
    fn verify_publisher_transitions_to_community_verified() {
        let mut reg = PublisherRegistry::new();
        let p = Publisher::new("Acme", None);
        let pid = p.publisher_id.clone();
        reg.register(p).ok();
        let result = reg.verify(&pid, "reviewer:alice");
        assert!(result.is_ok());
        let found = reg.find(&pid).unwrap();
        assert_eq!(found.tier, PublisherTier::CommunityVerified);
        assert_eq!(found.verified_by.as_deref(), Some("reviewer:alice"));
    }

    #[test]
    fn promote_works_for_valid_transition() {
        let mut reg = PublisherRegistry::new();
        let p = Publisher::new("Acme", None);
        let pid = p.publisher_id.clone();
        reg.register(p).ok();
        reg.verify(&pid, "reviewer:alice").ok();
        let result = reg.promote(&pid, PublisherTier::AiosPartner, "reviewer:bob");
        assert!(result.is_ok());
        let found = reg.find(&pid).unwrap();
        assert_eq!(found.tier, PublisherTier::AiosPartner);
    }

    #[test]
    fn promote_to_aios_core_is_forbidden() {
        let mut reg = PublisherRegistry::new();
        let p = Publisher::new("Acme", None);
        let pid = p.publisher_id.clone();
        reg.register(p).ok();
        reg.verify(&pid, "reviewer:alice").ok();
        let result = reg.promote(&pid, PublisherTier::AiosCore, "reviewer:bob");
        assert!(result.is_err());
    }

    #[test]
    fn suspend_demotes_publisher() {
        let mut reg = PublisherRegistry::new();
        let p = Publisher::new("Acme", None);
        let pid = p.publisher_id.clone();
        reg.register(p).ok();
        reg.verify(&pid, "r1").ok();
        let result = reg.suspend(&pid, "violation");
        assert!(result.is_ok());
        let found = reg.find(&pid).unwrap();
        assert_eq!(found.tier, PublisherTier::Unverified);
    }

    #[test]
    fn find_nonexistent_returns_none() {
        let reg = PublisherRegistry::new();
        assert!(reg.find("nonexistent").is_none());
    }
}
