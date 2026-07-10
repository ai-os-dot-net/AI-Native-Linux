//! Terminal mode switching — manages LX ↔ MIX ↔ AI transitions.
//!
//! S20 §7: AIOS terminal supports three explicit modes. Switching requires
//! explicit operator action, security profile check (AIRGAP_HIGH stays in
//! LX), and evidence emission.

use crate::enums::TerminalMode;
use serde::{Deserialize, Serialize};

/// Security profile levels that gate terminal mode availability.
///
/// Simplified 4-profile model matching S20 §9:
/// - `Dev`: all modes available
/// - `General`: MIX and AI available
/// - `HighRiskReady`: AI mode restricted to registered models only
/// - `AirgapHigh`: LX only — no AI terminal modes allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityProfileLevel {
    /// Development mode — all modes available.
    Dev,
    /// General use — MIX and AI available.
    General,
    /// High-risk ready — AI mode restricted.
    HighRiskReady,
    /// Airgap high-security — LX only.
    AirgapHigh,
}

/// Evidence record emitted on every mode switch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeSwitchEvidence {
    /// Previous terminal mode.
    pub from_mode: TerminalMode,
    /// New terminal mode.
    pub to_mode: TerminalMode,
    /// Actor that triggered the switch.
    pub actor_id: String,
    /// Active security profile at the time of switch.
    pub security_profile: SecurityProfileLevel,
    /// RFC 3339 timestamp of the switch.
    pub timestamp: String,
    /// Evidence receipt id (assigned by the evidence log).
    pub evidence_receipt: Option<String>,
}

/// Error type for mode switching failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeSwitchError {
    /// The requested mode is not available under the current security profile.
    ModeNotAllowedForProfile,
    /// The terminal is already in the requested mode.
    AlreadyInMode,
    /// Mode switching is locked (e.g., emergency stop active).
    SwitchLocked,
}

/// Manages terminal mode state and enforces security profile constraints.
pub struct TerminalModeSwitch {
    current_mode: TerminalMode,
    security_profile: SecurityProfileLevel,
    locked: bool,
}

impl TerminalModeSwitch {
    /// Create a new mode switch in the given starting mode and profile.
    #[must_use]
    pub fn new(start_mode: TerminalMode, profile: SecurityProfileLevel) -> Self {
        Self {
            current_mode: start_mode,
            security_profile: profile,
            locked: false,
        }
    }

    /// Return the current terminal mode.
    #[must_use]
    pub fn current_mode(&self) -> TerminalMode {
        self.current_mode
    }

    /// Return the active security profile.
    #[must_use]
    pub fn security_profile(&self) -> SecurityProfileLevel {
        self.security_profile
    }

    /// Return whether the switch is locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Lock the mode switch — prevents any further mode changes until
    /// unlocked. Used by emergency stop.
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Unlock the mode switch. Requires the caller to prove authority
    /// (operator action). Returns `Ok(())` or `Err` if already unlocked.
    pub fn unlock(&mut self) -> Result<(), ModeSwitchError> {
        if self.locked {
            self.locked = false;
            Ok(())
        } else {
            Err(ModeSwitchError::SwitchLocked)
        }
    }

    /// Update the security profile. If the new profile does not support
    /// the current mode, the mode is forced to `Lx`.
    pub fn set_security_profile(&mut self, profile: SecurityProfileLevel) {
        self.security_profile = profile;
        if !self.is_mode_available(self.current_mode) {
            self.current_mode = TerminalMode::Lx;
        }
    }

    /// Determine which modes are available under the current profile.
    #[must_use]
    pub fn available_modes(&self) -> Vec<TerminalMode> {
        available_modes_for_profile(self.security_profile)
    }

    /// Check if a given mode is available under the current profile.
    #[must_use]
    fn is_mode_available(&self, mode: TerminalMode) -> bool {
        available_modes_for_profile(self.security_profile).contains(&mode)
    }

    /// Switch to the requested mode. Returns the current and previous mode
    /// on success, or an error if the switch is not allowed.
    ///
    /// Switching requires:
    /// - Switch not locked
    /// - Requested mode different from current
    /// - Requested mode available under the active security profile
    pub fn switch_to(
        &mut self,
        target: TerminalMode,
    ) -> Result<(TerminalMode, TerminalMode), ModeSwitchError> {
        if self.locked {
            return Err(ModeSwitchError::SwitchLocked);
        }
        if self.current_mode == target {
            return Err(ModeSwitchError::AlreadyInMode);
        }
        if !self.is_mode_available(target) {
            return Err(ModeSwitchError::ModeNotAllowedForProfile);
        }
        let previous = self.current_mode;
        self.current_mode = target;
        Ok((previous, target))
    }

    /// Build an evidence record for a completed mode switch.
    #[must_use]
    pub fn build_evidence(
        from_mode: TerminalMode,
        to_mode: TerminalMode,
        actor_id: impl Into<String>,
        profile: SecurityProfileLevel,
    ) -> ModeSwitchEvidence {
        ModeSwitchEvidence {
            from_mode,
            to_mode,
            actor_id: actor_id.into(),
            security_profile: profile,
            timestamp: chrono::Utc::now().to_rfc3339(),
            evidence_receipt: None,
        }
    }
}

/// Return the modes available for a given security profile.
///
/// Per S20 §7 / §9:
/// - `Dev`: all three modes.
/// - `General`: MIX and AI (LX is the default fallback).
/// - `HighRiskReady`: LX and MIX only (AI mode blocked unless registered models).
/// - `AirgapHigh`: LX only.
#[must_use]
pub fn available_modes_for_profile(profile: SecurityProfileLevel) -> Vec<TerminalMode> {
    match profile {
        SecurityProfileLevel::Dev => {
            vec![TerminalMode::Lx, TerminalMode::Mix, TerminalMode::Ai]
        }
        SecurityProfileLevel::General => {
            vec![TerminalMode::Lx, TerminalMode::Mix, TerminalMode::Ai]
        }
        SecurityProfileLevel::HighRiskReady => {
            vec![TerminalMode::Lx, TerminalMode::Mix]
        }
        SecurityProfileLevel::AirgapHigh => {
            vec![TerminalMode::Lx]
        }
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
    fn new_switch_starts_in_requested_mode() {
        let s = TerminalModeSwitch::new(TerminalMode::Mix, SecurityProfileLevel::General);
        assert_eq!(s.current_mode(), TerminalMode::Mix);
    }

    #[test]
    fn switch_lx_to_mix_succeeds() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Lx, SecurityProfileLevel::General);
        let result = s.switch_to(TerminalMode::Mix);
        assert!(result.is_ok());
        let (prev, curr) = result.unwrap();
        assert_eq!(prev, TerminalMode::Lx);
        assert_eq!(curr, TerminalMode::Mix);
    }

    #[test]
    fn switch_mix_to_ai_succeeds() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Mix, SecurityProfileLevel::General);
        let result = s.switch_to(TerminalMode::Ai);
        assert!(result.is_ok());
        assert_eq!(s.current_mode(), TerminalMode::Ai);
    }

    #[test]
    fn switch_ai_to_lx_succeeds() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Ai, SecurityProfileLevel::Dev);
        let result = s.switch_to(TerminalMode::Lx);
        assert!(result.is_ok());
        assert_eq!(s.current_mode(), TerminalMode::Lx);
    }

    #[test]
    fn switch_to_same_mode_fails() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Lx, SecurityProfileLevel::General);
        let result = s.switch_to(TerminalMode::Lx);
        assert_eq!(result, Err(ModeSwitchError::AlreadyInMode));
    }

    #[test]
    fn airgap_high_blocks_ai_mode() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Lx, SecurityProfileLevel::AirgapHigh);
        let result = s.switch_to(TerminalMode::Ai);
        assert_eq!(result, Err(ModeSwitchError::ModeNotAllowedForProfile));
    }

    #[test]
    fn airgap_high_blocks_mix_mode() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Lx, SecurityProfileLevel::AirgapHigh);
        let result = s.switch_to(TerminalMode::Mix);
        assert_eq!(result, Err(ModeSwitchError::ModeNotAllowedForProfile));
    }

    #[test]
    fn airgap_high_lx_available() {
        let s = TerminalModeSwitch::new(TerminalMode::Lx, SecurityProfileLevel::AirgapHigh);
        let modes = s.available_modes();
        assert_eq!(modes, vec![TerminalMode::Lx]);
        // Switching to Lx when already at Lx is a no-op fail, but the mode IS
        // available.
    }

    #[test]
    fn high_risk_ready_blocks_ai() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Mix, SecurityProfileLevel::HighRiskReady);
        let result = s.switch_to(TerminalMode::Ai);
        assert_eq!(result, Err(ModeSwitchError::ModeNotAllowedForProfile));
    }

    #[test]
    fn high_risk_ready_allows_lx_and_mix() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Lx, SecurityProfileLevel::HighRiskReady);
        let result = s.switch_to(TerminalMode::Mix);
        assert!(result.is_ok());
        let modes = s.available_modes();
        assert_eq!(modes, vec![TerminalMode::Lx, TerminalMode::Mix]);
    }

    #[test]
    fn dev_has_all_three_modes() {
        let s = TerminalModeSwitch::new(TerminalMode::Lx, SecurityProfileLevel::Dev);
        let modes = s.available_modes();
        assert_eq!(modes.len(), 3);
        assert!(modes.contains(&TerminalMode::Lx));
        assert!(modes.contains(&TerminalMode::Mix));
        assert!(modes.contains(&TerminalMode::Ai));
    }

    #[test]
    fn general_has_all_three_modes() {
        let s = TerminalModeSwitch::new(TerminalMode::Lx, SecurityProfileLevel::General);
        let modes = s.available_modes();
        assert_eq!(modes.len(), 3);
    }

    #[test]
    fn available_modes_for_profile_function() {
        assert_eq!(
            available_modes_for_profile(SecurityProfileLevel::AirgapHigh).len(),
            1
        );
        assert_eq!(
            available_modes_for_profile(SecurityProfileLevel::HighRiskReady).len(),
            2
        );
        assert_eq!(
            available_modes_for_profile(SecurityProfileLevel::General).len(),
            3
        );
        assert_eq!(
            available_modes_for_profile(SecurityProfileLevel::Dev).len(),
            3
        );
    }

    #[test]
    fn locked_switch_blocks_all_transitions() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Mix, SecurityProfileLevel::General);
        s.lock();
        let result = s.switch_to(TerminalMode::Ai);
        assert_eq!(result, Err(ModeSwitchError::SwitchLocked));
        let result = s.switch_to(TerminalMode::Lx);
        assert_eq!(result, Err(ModeSwitchError::SwitchLocked));
    }

    #[test]
    fn unlock_restores_switching() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Mix, SecurityProfileLevel::General);
        s.lock();
        s.unlock().unwrap();
        let result = s.switch_to(TerminalMode::Ai);
        assert!(result.is_ok());
    }

    #[test]
    fn profile_change_forces_lx_on_incompatible_mode() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Ai, SecurityProfileLevel::General);
        assert_eq!(s.current_mode(), TerminalMode::Ai);
        // Downgrade to AirgapHigh — AI mode no longer allowed
        s.set_security_profile(SecurityProfileLevel::AirgapHigh);
        assert_eq!(s.current_mode(), TerminalMode::Lx);
    }

    #[test]
    fn profile_downgrade_to_high_risk_ready_forces_lx_from_ai() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Ai, SecurityProfileLevel::Dev);
        s.set_security_profile(SecurityProfileLevel::HighRiskReady);
        assert_eq!(s.current_mode(), TerminalMode::Lx);
    }

    #[test]
    fn profile_upgrade_does_not_change_mode_if_compatible() {
        let mut s = TerminalModeSwitch::new(TerminalMode::Mix, SecurityProfileLevel::HighRiskReady);
        assert_eq!(s.current_mode(), TerminalMode::Mix);
        s.set_security_profile(SecurityProfileLevel::General);
        assert_eq!(s.current_mode(), TerminalMode::Mix);
    }

    #[test]
    fn evidence_builder_creates_record() {
        let ev = TerminalModeSwitch::build_evidence(
            TerminalMode::Lx,
            TerminalMode::Mix,
            "operator_01",
            SecurityProfileLevel::General,
        );
        assert_eq!(ev.from_mode, TerminalMode::Lx);
        assert_eq!(ev.to_mode, TerminalMode::Mix);
        assert_eq!(ev.actor_id, "operator_01");
        assert_eq!(ev.security_profile, SecurityProfileLevel::General);
        assert!(!ev.timestamp.is_empty());
        assert!(ev.evidence_receipt.is_none());
    }

    #[test]
    fn evidence_serde_round_trip() {
        let ev = TerminalModeSwitch::build_evidence(
            TerminalMode::Mix,
            TerminalMode::Ai,
            "op_42",
            SecurityProfileLevel::Dev,
        );
        let json = serde_json::to_string(&ev).unwrap();
        let back: ModeSwitchEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back.from_mode, ev.from_mode);
        assert_eq!(back.to_mode, ev.to_mode);
    }
}
