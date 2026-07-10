//! Mobile approval request and its finite state machine (FSM).

use crate::enums::ApprovalRiskBand;
use serde::{Deserialize, Serialize};

/// The state of a mobile approval request tracked as a finite state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MobileApprovalState {
    /// Request has been pushed to the mobile surface.
    Pushed,
    /// User has viewed the request on the surface.
    Viewed,
    /// User has signed (tapped approve) on the surface.
    Signed,
    /// Signature has been cryptographically verified by the host.
    Verified,
    /// Approval has been consumed by the bound action (terminal).
    Consumed,
    /// Request expired before any action (terminal).
    Expired,
    /// User explicitly declined (terminal).
    Declined,
    /// Policy rejected the request (terminal).
    Rejected,
    /// Request was revoked by an emergency stop (terminal).
    Revoked,
}

impl MobileApprovalState {
    /// Returns `true` if this state represents a terminal (end-of-life) state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Consumed | Self::Expired | Self::Declined | Self::Rejected | Self::Revoked
        )
    }
}

/// A mobile approval request bound to a specific typed action request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileApprovalRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// The surface this request was pushed to.
    pub surface_id: String,
    /// The typed action request this approval is bound to.
    pub bound_action_request_id: String,
    /// Canonical hash of the bound action request for integrity verification.
    pub bound_action_canonical_hash: String,
    /// Risk band assigned to this approval.
    pub risk_band: ApprovalRiskBand,
    /// Time-to-live in seconds before automatic expiry.
    pub ttl_seconds: u64,
    /// Current FSM state.
    pub state: MobileApprovalState,
}

impl MobileApprovalRequest {
    /// Creates a new approval request in the `Pushed` state.
    #[must_use]
    pub fn new(
        surface_id: String,
        bound_action_request_id: String,
        bound_action_canonical_hash: String,
        risk_band: ApprovalRiskBand,
        ttl_seconds: u64,
    ) -> Self {
        let request_id = format!("marq_{}", ulid::Ulid::new());
        Self {
            request_id,
            surface_id,
            bound_action_request_id,
            bound_action_canonical_hash,
            risk_band,
            ttl_seconds,
            state: MobileApprovalState::Pushed,
        }
    }

    /// Transitions from `Pushed` to `Viewed`. Returns `None` if not in `Pushed`.
    #[must_use]
    pub fn view(self) -> Option<Self> {
        if self.state == MobileApprovalState::Pushed {
            Some(Self {
                state: MobileApprovalState::Viewed,
                ..self
            })
        } else {
            None
        }
    }

    /// Transitions any non-terminal state to `Declined`. Returns `None` if
    /// already terminal.
    #[must_use]
    pub fn decline(self) -> Option<Self> {
        if self.state.is_terminal() {
            None
        } else {
            Some(Self {
                state: MobileApprovalState::Declined,
                ..self
            })
        }
    }

    /// Transitions from `Viewed` or `Signed` to `Verified`. Returns `None`
    /// if the current state is not eligible.
    #[must_use]
    pub fn verify(self) -> Option<Self> {
        if self.state == MobileApprovalState::Viewed || self.state == MobileApprovalState::Signed {
            Some(Self {
                state: MobileApprovalState::Verified,
                ..self
            })
        } else {
            None
        }
    }

    /// Transitions from `Verified` to `Consumed`. Returns `None` if not
    /// currently `Verified`.
    #[must_use]
    pub fn consume(self) -> Option<Self> {
        if self.state == MobileApprovalState::Verified {
            Some(Self {
                state: MobileApprovalState::Consumed,
                ..self
            })
        } else {
            None
        }
    }

    /// Transitions any non-terminal state to `Expired`. Returns `None` if
    /// already terminal.
    #[must_use]
    pub fn expire(self) -> Option<Self> {
        if self.state.is_terminal() {
            None
        } else {
            Some(Self {
                state: MobileApprovalState::Expired,
                ..self
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_request() -> MobileApprovalRequest {
        MobileApprovalRequest::new(
            "msrf_01TEST".to_string(),
            "arq_01TEST".to_string(),
            "abcdef1234567890".to_string(),
            ApprovalRiskBand::Medium,
            300,
        )
    }

    #[test]
    fn new_request_starts_pushed() {
        let req = make_request();
        assert_eq!(req.state, MobileApprovalState::Pushed);
        assert!(req.request_id.starts_with("marq_"));
    }

    #[test]
    fn valid_view_transition() {
        let req = make_request();
        let viewed = req.view();
        assert!(viewed.is_some());
        assert_eq!(viewed.unwrap().state, MobileApprovalState::Viewed);
    }

    #[test]
    fn view_from_non_pushed_returns_none() {
        let req = make_request();
        let viewed = req.view().unwrap();
        let double_view = viewed.view();
        assert!(double_view.is_none());
    }

    #[test]
    fn valid_decline_transition() {
        let req = make_request();
        let declined = req.decline();
        assert!(declined.is_some());
        assert_eq!(declined.unwrap().state, MobileApprovalState::Declined);
    }

    #[test]
    fn decline_from_terminal_returns_none() {
        let req = make_request();
        let declined = req.decline().unwrap();
        let double_decline = declined.decline();
        assert!(double_decline.is_none());
    }

    #[test]
    fn full_happy_path_view_verify_consume() {
        let req = make_request();
        let viewed = req.view().unwrap();
        assert_eq!(viewed.state, MobileApprovalState::Viewed);

        let verified = viewed.verify().unwrap();
        assert_eq!(verified.state, MobileApprovalState::Verified);

        let consumed = verified.consume().unwrap();
        assert_eq!(consumed.state, MobileApprovalState::Consumed);
        assert!(consumed.state.is_terminal());
    }

    #[test]
    fn expire_transitions_to_expired() {
        let req = make_request();
        let expired = req.expire().unwrap();
        assert_eq!(expired.state, MobileApprovalState::Expired);
        assert!(expired.state.is_terminal());
    }

    #[test]
    fn terminal_states_are_terminal() {
        for state in &[
            MobileApprovalState::Consumed,
            MobileApprovalState::Expired,
            MobileApprovalState::Declined,
            MobileApprovalState::Rejected,
            MobileApprovalState::Revoked,
        ] {
            assert!(state.is_terminal(), "{state:?} should be terminal");
        }
    }

    #[test]
    fn non_terminal_states_are_not_terminal() {
        for state in &[
            MobileApprovalState::Pushed,
            MobileApprovalState::Viewed,
            MobileApprovalState::Signed,
            MobileApprovalState::Verified,
        ] {
            assert!(!state.is_terminal(), "{state:?} should NOT be terminal");
        }
    }

    #[test]
    fn verify_from_pushed_returns_none() {
        let req = make_request();
        assert!(req.verify().is_none());
    }

    #[test]
    fn consume_from_pushed_returns_none() {
        let req = make_request();
        assert!(req.consume().is_none());
    }
}
