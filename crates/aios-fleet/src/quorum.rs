//! Fleet Quorum Manager per S25 §9.
//!
//! Tracks member reachability and determines whether the fleet maintains
//! quorum (k-of-n active members). Quorum is a pre-condition for any
//! cluster-wide mutation including coordinator promotion, policy push,
//! and fleet-wide distribution rollout.
//!
//! ## Quorum threshold
//!
//! The default majority quorum is `floor(total/2) + 1`. A configurable
//! `k_required` override is supported for asymmetric fleets where a
//! higher threshold is warranted.
//!
//! ## Architectural invariants
//!
//! - **Active membership is tracked via an explicit set.** Only explicitly
//!   marked members count toward quorum.
//! - **Quorum is monotonic-lowering.** Once lost, it can only be regained
//!   by explicit member re-add.
//! - **The majority formula is always available** as a static method so
//!   callers can compute the default threshold without instantiating.

use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumManager {
    pub total_members: u32,
    pub k_required: u32,
    pub active_members: HashSet<String>,
}

impl QuorumManager {
    #[must_use]
    pub fn new(total_members: u32, k_required: u32) -> Self {
        Self {
            total_members,
            k_required,
            active_members: HashSet::new(),
        }
    }

    #[must_use]
    pub fn with_majority_quorum(total_members: u32) -> Self {
        let k = Self::majority_quorum(total_members);
        Self::new(total_members, k)
    }

    pub fn add_active(&mut self, member_id: &str) {
        self.active_members.insert(member_id.to_owned());
    }

    pub fn remove_active(&mut self, member_id: &str) {
        self.active_members.remove(member_id);
    }

    #[must_use]
    pub fn is_quorum(&self) -> bool {
        self.quorum_size() >= self.k_required
    }

    #[must_use]
    pub fn quorum_size(&self) -> u32 {
        self.active_members.len() as u32
    }

    #[must_use]
    pub fn remaining_until_quorum(&self) -> u32 {
        self.k_required.saturating_sub(self.quorum_size())
    }

    #[must_use]
    pub fn majority_quorum(total: u32) -> u32 {
        if total == 0 {
            0
        } else {
            (total / 2) + 1
        }
    }

    #[must_use]
    pub fn active_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.active_members.iter().cloned().collect();
        ids.sort();
        ids
    }

    pub fn reset(&mut self) {
        self.active_members.clear();
    }

    pub fn set_total_members(&mut self, total: u32) {
        self.total_members = total;
    }

    pub fn set_k_required(&mut self, k: u32) {
        self.k_required = k;
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::similar_names,
    reason = "unit tests in the same module"
)]
mod tests {
    use super::*;

    #[test]
    fn majority_quorum_formula() {
        assert_eq!(QuorumManager::majority_quorum(1), 1);
        assert_eq!(QuorumManager::majority_quorum(2), 2);
        assert_eq!(QuorumManager::majority_quorum(3), 2);
        assert_eq!(QuorumManager::majority_quorum(4), 3);
        assert_eq!(QuorumManager::majority_quorum(5), 3);
        assert_eq!(QuorumManager::majority_quorum(10), 6);
        assert_eq!(QuorumManager::majority_quorum(0), 0);
    }

    #[test]
    fn new_quorum_empty() {
        let qm = QuorumManager::new(5, 3);
        assert_eq!(qm.quorum_size(), 0);
        assert!(!qm.is_quorum());
        assert_eq!(qm.remaining_until_quorum(), 3);
    }

    #[test]
    fn add_members_reaches_quorum() {
        let mut qm = QuorumManager::new(5, 3);
        qm.add_active("host_01");
        qm.add_active("host_02");
        qm.add_active("host_03");
        assert!(qm.is_quorum());
        assert_eq!(qm.quorum_size(), 3);
        assert_eq!(qm.remaining_until_quorum(), 0);
    }

    #[test]
    fn remove_member_drops_below_quorum() {
        let mut qm = QuorumManager::new(5, 3);
        qm.add_active("A");
        qm.add_active("B");
        qm.add_active("C");
        assert!(qm.is_quorum());
        qm.remove_active("C");
        assert!(!qm.is_quorum());
        assert_eq!(qm.remaining_until_quorum(), 1);
    }

    #[test]
    fn with_majority_quorum_default() {
        let qm = QuorumManager::with_majority_quorum(7);
        assert_eq!(qm.k_required, 4);
    }

    #[test]
    fn active_ids_sorted() {
        let mut qm = QuorumManager::new(5, 3);
        qm.add_active("C");
        qm.add_active("A");
        qm.add_active("B");
        assert_eq!(qm.active_ids(), vec!["A", "B", "C"]);
    }

    #[test]
    fn remaining_until_quorum_saturates_at_zero() {
        let mut qm = QuorumManager::new(3, 2);
        qm.add_active("A");
        qm.add_active("B");
        qm.add_active("C");
        assert_eq!(qm.remaining_until_quorum(), 0);
    }

    #[test]
    fn k_required_override() {
        let mut qm = QuorumManager::new(10, 7);
        qm.add_active("A");
        qm.add_active("B");
        qm.add_active("C");
        qm.add_active("D");
        qm.add_active("E");
        qm.add_active("F");
        assert!(!qm.is_quorum());
        qm.add_active("G");
        assert!(qm.is_quorum());
    }

    #[test]
    fn total_members_update() {
        let mut qm = QuorumManager::new(3, 2);
        qm.set_total_members(10);
        assert_eq!(qm.total_members, 10);
    }

    #[test]
    fn k_required_update() {
        let mut qm = QuorumManager::new(5, 3);
        qm.add_active("A");
        qm.add_active("B");
        qm.add_active("C");
        assert!(qm.is_quorum());
        qm.set_k_required(5);
        assert!(!qm.is_quorum());
    }

    #[test]
    fn reset_clears_active() {
        let mut qm = QuorumManager::new(5, 3);
        qm.add_active("A");
        qm.add_active("B");
        qm.add_active("C");
        qm.reset();
        assert_eq!(qm.quorum_size(), 0);
        assert!(!qm.is_quorum());
    }
}
