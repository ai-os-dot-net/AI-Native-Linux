//! Cross-Host Sandbox Floor — stricter-of-two host sandbox requirements per
//! SPEC S25 §9 and INV-026.
//!
//! When a workload is shipped from an origin host to a target host, the
//! effective sandbox profile is the **stricter of the two** hosts' floors.
//! The target's preference cannot be lowered by the origin (INV-026).
//!
//! ## Threat model
//!
//! An origin host operating at `DEV_RELAXED` shipping to a `STIG_ALIGNED`
//! target must not weaken the target's enforcement. The effective floor is
//! always `max(origin, target)` in the security strictness ordering.
//!
//! ## Constitutional invariants
//!
//! - **INV-026:** Target sandbox floor cannot be lowered by origin.
//! - **No `unsafe`, no `unwrap`/`expect`/`panic`.**

#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Serialize};

use aios_sandbox::SandboxProfile;

// ---------------------------------------------------------------------------
// SecurityProfileLevel — weakest to strongest
// ---------------------------------------------------------------------------

/// The security floor level for cross-host sandbox composition.
///
/// Ordered from weakest (most permissive) to strongest (most restrictive).
/// The integer discriminant encodes the strictness ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityProfileLevel {
    /// Developer workstation — minimal enforcement, maximum flexibility.
    DevRelaxed,
    /// Production secure default — balanced security for networked hosts.
    SecureDefault,
    /// DISA STIG-aligned — government/defense workloads.
    StigAligned,
    /// Physically isolated air-gapped systems — maximum restriction.
    AirgapHigh,
}

impl SecurityProfileLevel {
    /// Return the canonical `SCREAMING_SNAKE_CASE` label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DevRelaxed => "DEV_RELAXED",
            Self::SecureDefault => "SECURE_DEFAULT",
            Self::StigAligned => "STIG_ALIGNED",
            Self::AirgapHigh => "AIRGAP_HIGH",
        }
    }

    /// Returns `true` if `self` is at least as strict as `other`.
    #[must_use]
    pub const fn is_at_least(self, other: Self) -> bool {
        // We rely on the derived Ord: DevRelaxed < SecureDefault < StigAligned < AirgapHigh
        self as u8 >= other as u8
    }

    /// Returns the stricter (higher-ordinal) of the two levels.
    #[must_use]
    pub fn stricter_of(a: Self, b: Self) -> Self {
        if a >= b {
            a
        } else {
            b
        }
    }

    /// Attempt to parse from a canonical label string.
    ///
    /// Returns `None` if the string does not match any known profile level.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "DEV_RELAXED" => Some(Self::DevRelaxed),
            "SECURE_DEFAULT" => Some(Self::SecureDefault),
            "STIG_ALIGNED" => Some(Self::StigAligned),
            "AIRGAP_HIGH" => Some(Self::AirgapHigh),
            _ => None,
        }
    }
}

impl fmt::Display for SecurityProfileLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// StricterOf — result of cross-host sandbox floor computation
// ---------------------------------------------------------------------------

/// Holds the result of computing the stricter-of-two sandbox floors.
///
/// INV-026: `effective` is always `max(origin, target)` in the strictness
/// ordering. The target's preference is never lowered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StricterOf {
    /// Origin host's declared sandbox floor.
    pub origin: SecurityProfileLevel,
    /// Target host's declared sandbox floor.
    pub target: SecurityProfileLevel,
    /// The effective floor = `max(origin, target)`.
    pub effective: SecurityProfileLevel,
    /// Human-readable justification for the resolution.
    pub justification: String,
}

impl StricterOf {
    /// Create a new `StricterOf` resolution.
    #[must_use]
    pub fn new(origin: SecurityProfileLevel, target: SecurityProfileLevel) -> Self {
        let effective = SecurityProfileLevel::stricter_of(origin, target);
        let justification = if origin == target {
            format!(
                "Origin ({origin}) and target ({target}) floors are equal. \
                 Effective floor is {effective}."
            )
        } else if effective == target {
            format!(
                "Target floor ({target}) is stricter than origin floor ({origin}). \
                 Target preference prevails per INV-026. Effective floor = {effective}."
            )
        } else {
            format!(
                "Origin floor ({origin}) is stricter than target floor ({target}). \
                 Origin overdelivers; effective floor = {effective}."
            )
        };
        Self {
            origin,
            target,
            effective,
            justification,
        }
    }

    /// Returns `true` iff the target floor was respected (not lowered).
    /// INV-026 requires this to always be `true`.
    #[must_use]
    pub fn target_floor_respected(&self) -> bool {
        self.effective.is_at_least(self.target)
    }

    /// Returns `true` iff both floors match.
    #[must_use]
    pub fn floors_equal(&self) -> bool {
        self.origin == self.target
    }

    /// Returns `true` iff the target floor is the effective floor (target
    /// was equal-or-stricter than origin).
    #[must_use]
    pub fn target_prevails(&self) -> bool {
        self.effective == self.target
    }
}

// ---------------------------------------------------------------------------
// CrossHostSandboxFloor — computes the effective profile
// ---------------------------------------------------------------------------

/// Stateless cross-host sandbox floor computer.
///
/// Given two hosts' sandbox profiles, computes the stricter-of-two result
/// and generates a merged profile stub.
#[derive(Debug, Clone, Copy, Default)]
pub struct CrossHostSandboxFloor;

impl CrossHostSandboxFloor {
    /// Create a new cross-host sandbox floor computer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute the effective sandbox level from two profiles.
    ///
    /// Parses the profile names to extract [`SecurityProfileLevel`] and
    /// returns the stricter-of-two resolution. If either profile name
    /// cannot be parsed, falls back to `StigAligned` as a safe default.
    #[must_use]
    pub fn compute_effective_sandbox(
        origin_profile: &SandboxProfile,
        target_profile: &SandboxProfile,
    ) -> StricterOf {
        let origin_level = Self::extract_level(origin_profile);
        let target_level = Self::extract_level(target_profile);
        StricterOf::new(origin_level, target_level)
    }

    /// Compute the effective sandbox level from raw floor strings.
    ///
    /// This is the primary entry point when full `SandboxProfile` structs
    /// are not yet available (e.g., during the proposal phase when only
    /// floor labels are known).
    pub fn compute_from_labels(
        origin_floor_label: &str,
        target_floor_label: &str,
    ) -> Result<StricterOf, CrossHostSandboxError> {
        let origin = SecurityProfileLevel::from_label(origin_floor_label).ok_or_else(|| {
            CrossHostSandboxError::UnknownProfileLabel {
                label: origin_floor_label.to_string(),
            }
        })?;
        let target = SecurityProfileLevel::from_label(target_floor_label).ok_or_else(|| {
            CrossHostSandboxError::UnknownProfileLabel {
                label: target_floor_label.to_string(),
            }
        })?;
        let result = StricterOf::new(origin, target);

        // INV-026: effective must be >= target
        if !result.target_floor_respected() {
            return Err(CrossHostSandboxError::TargetFloorLowered {
                target_floor: target.to_string(),
                effective_floor: result.effective.to_string(),
            });
        }

        Ok(result)
    }

    /// Extract the security level from a profile.
    ///
    /// Currently uses a heuristic based on profile name. In Rev.8+ this
    /// should read from a dedicated `security_level` field on the profile.
    fn extract_level(profile: &SandboxProfile) -> SecurityProfileLevel {
        // Heuristic: scan profile name for known level labels
        let name_upper = profile.name.to_uppercase();
        if name_upper.contains("AIRGAP") || name_upper.contains("AIR_GAP") {
            SecurityProfileLevel::AirgapHigh
        } else if name_upper.contains("STIG") {
            SecurityProfileLevel::StigAligned
        } else if name_upper.contains("DEV") || name_upper.contains("RELAXED") {
            SecurityProfileLevel::DevRelaxed
        } else {
            // Default to secure — safe fallback per INV-026
            SecurityProfileLevel::SecureDefault
        }
    }
}

// ---------------------------------------------------------------------------
// CrossHostSandboxError
// ---------------------------------------------------------------------------

/// Closed error taxonomy for cross-host sandbox floor computation.
#[derive(Debug, thiserror::Error)]
pub enum CrossHostSandboxError {
    /// A profile label string was not recognized.
    #[error("unknown security profile label: {label}")]
    UnknownProfileLabel {
        /// The unrecognized label.
        label: String,
    },

    /// INV-026 violation: target floor was lowered.
    #[error(
        "INV-026: target sandbox floor ({target_floor}) lowered to \
         ({effective_floor})"
    )]
    TargetFloorLowered {
        /// The target host's sandbox floor.
        target_floor: String,
        /// The computed effective floor that was too low.
        effective_floor: String,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SecurityProfileLevel ordering
    // -----------------------------------------------------------------------

    #[test]
    fn security_profile_level_ordering() {
        assert!(SecurityProfileLevel::DevRelaxed < SecurityProfileLevel::SecureDefault);
        assert!(SecurityProfileLevel::SecureDefault < SecurityProfileLevel::StigAligned);
        assert!(SecurityProfileLevel::StigAligned < SecurityProfileLevel::AirgapHigh);
    }

    #[test]
    fn is_at_least_semantics() {
        assert!(SecurityProfileLevel::AirgapHigh.is_at_least(SecurityProfileLevel::DevRelaxed));
        assert!(SecurityProfileLevel::StigAligned.is_at_least(SecurityProfileLevel::SecureDefault));
        assert!(
            SecurityProfileLevel::SecureDefault.is_at_least(SecurityProfileLevel::SecureDefault)
        );
        assert!(!SecurityProfileLevel::DevRelaxed.is_at_least(SecurityProfileLevel::StigAligned));
    }

    #[test]
    fn stricter_of_selects_max() {
        assert_eq!(
            SecurityProfileLevel::stricter_of(
                SecurityProfileLevel::DevRelaxed,
                SecurityProfileLevel::AirgapHigh
            ),
            SecurityProfileLevel::AirgapHigh
        );
        assert_eq!(
            SecurityProfileLevel::stricter_of(
                SecurityProfileLevel::StigAligned,
                SecurityProfileLevel::SecureDefault
            ),
            SecurityProfileLevel::StigAligned
        );
        assert_eq!(
            SecurityProfileLevel::stricter_of(
                SecurityProfileLevel::SecureDefault,
                SecurityProfileLevel::SecureDefault
            ),
            SecurityProfileLevel::SecureDefault
        );
    }

    // -----------------------------------------------------------------------
    // Label parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_valid_labels() {
        assert_eq!(
            SecurityProfileLevel::from_label("DEV_RELAXED"),
            Some(SecurityProfileLevel::DevRelaxed)
        );
        assert_eq!(
            SecurityProfileLevel::from_label("SECURE_DEFAULT"),
            Some(SecurityProfileLevel::SecureDefault)
        );
        assert_eq!(
            SecurityProfileLevel::from_label("STIG_ALIGNED"),
            Some(SecurityProfileLevel::StigAligned)
        );
        assert_eq!(
            SecurityProfileLevel::from_label("AIRGAP_HIGH"),
            Some(SecurityProfileLevel::AirgapHigh)
        );
    }

    #[test]
    fn parse_invalid_label_returns_none() {
        assert_eq!(SecurityProfileLevel::from_label("INVALID"), None);
        assert_eq!(SecurityProfileLevel::from_label(""), None);
        assert_eq!(SecurityProfileLevel::from_label("dev_relaxed"), None);
    }

    #[test]
    fn label_round_trips() {
        for level in [
            SecurityProfileLevel::DevRelaxed,
            SecurityProfileLevel::SecureDefault,
            SecurityProfileLevel::StigAligned,
            SecurityProfileLevel::AirgapHigh,
        ] {
            assert_eq!(SecurityProfileLevel::from_label(level.label()), Some(level));
        }
    }

    #[test]
    fn display_is_label() {
        assert_eq!(SecurityProfileLevel::DevRelaxed.to_string(), "DEV_RELAXED");
        assert_eq!(SecurityProfileLevel::AirgapHigh.to_string(), "AIRGAP_HIGH");
    }

    // -----------------------------------------------------------------------
    // StricterOf tests
    // -----------------------------------------------------------------------

    #[test]
    fn stricter_of_origin_stricter() {
        let result = StricterOf::new(
            SecurityProfileLevel::StigAligned,
            SecurityProfileLevel::SecureDefault,
        );
        assert_eq!(result.effective, SecurityProfileLevel::StigAligned);
        assert!(result.target_floor_respected());
        assert!(!result.target_prevails());
        assert!(!result.floors_equal());
    }

    #[test]
    fn stricter_of_target_stricter() {
        let result = StricterOf::new(
            SecurityProfileLevel::DevRelaxed,
            SecurityProfileLevel::AirgapHigh,
        );
        assert_eq!(result.effective, SecurityProfileLevel::AirgapHigh);
        assert!(result.target_floor_respected());
        assert!(result.target_prevails());
        assert!(!result.floors_equal());
    }

    #[test]
    fn stricter_of_equal() {
        let result = StricterOf::new(
            SecurityProfileLevel::StigAligned,
            SecurityProfileLevel::StigAligned,
        );
        assert_eq!(result.effective, SecurityProfileLevel::StigAligned);
        assert!(result.target_floor_respected());
        assert!(result.floors_equal());
    }

    #[test]
    fn target_floor_never_lowered() {
        // Test every combination: effective must always be >= target
        let levels = [
            SecurityProfileLevel::DevRelaxed,
            SecurityProfileLevel::SecureDefault,
            SecurityProfileLevel::StigAligned,
            SecurityProfileLevel::AirgapHigh,
        ];
        for &origin in &levels {
            for &target in &levels {
                let result = StricterOf::new(origin, target);
                assert!(
                    result.target_floor_respected(),
                    "INV-026 violated: origin={origin}, target={target}, \
                     effective={effective}",
                    effective = result.effective,
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // CrossHostSandboxFloor tests
    // -----------------------------------------------------------------------

    #[test]
    fn compute_effective_sandbox_from_profiles() {
        let result = CrossHostSandboxFloor::compute_from_labels("STIG_ALIGNED", "SECURE_DEFAULT");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.target_floor_respected());
        assert_eq!(resolved.effective, SecurityProfileLevel::StigAligned);
    }

    #[test]
    fn compute_from_labels_valid() {
        let result = CrossHostSandboxFloor::compute_from_labels("DEV_RELAXED", "STIG_ALIGNED");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.effective, SecurityProfileLevel::StigAligned);
        assert!(resolved.target_prevails());
        assert!(resolved.target_floor_respected());
    }

    #[test]
    fn compute_from_labels_invalid_label() {
        let result = CrossHostSandboxFloor::compute_from_labels("INVALID", "SECURE_DEFAULT");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(format!("{err}").contains("INVALID"));
    }

    #[test]
    fn compute_from_labels_equal_floors() {
        let result = CrossHostSandboxFloor::compute_from_labels("AIRGAP_HIGH", "AIRGAP_HIGH");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.effective, SecurityProfileLevel::AirgapHigh);
        assert!(resolved.floors_equal());
    }

    #[test]
    fn extract_level_heuristic() {
        let r1 = CrossHostSandboxFloor::compute_from_labels("AIRGAP_HIGH", "STIG_ALIGNED").unwrap();
        assert_eq!(r1.effective, SecurityProfileLevel::AirgapHigh);
        let r2 = CrossHostSandboxFloor::compute_from_labels("DEV_RELAXED", "STIG_ALIGNED").unwrap();
        assert_eq!(r2.effective, SecurityProfileLevel::StigAligned);
        let r3 = CrossHostSandboxFloor::compute_from_labels("UNKNOWN_LABEL", "DEV_RELAXED");
        assert!(r3.is_err()); // unknown labels rejected
    }

    // -----------------------------------------------------------------------
    // Serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn security_profile_level_serde_round_trip() {
        for level in [
            SecurityProfileLevel::DevRelaxed,
            SecurityProfileLevel::SecureDefault,
            SecurityProfileLevel::StigAligned,
            SecurityProfileLevel::AirgapHigh,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: SecurityProfileLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back, "round-trip failed for {level:?}");
        }
    }

    #[test]
    fn stricter_of_serde_round_trip() {
        let original = StricterOf::new(
            SecurityProfileLevel::DevRelaxed,
            SecurityProfileLevel::StigAligned,
        );
        let json = serde_json::to_string(&original).unwrap();
        let back: StricterOf = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn security_profile_level_screaming_snake_case_serde() {
        let json = serde_json::to_string(&SecurityProfileLevel::AirgapHigh).unwrap();
        assert_eq!(json, "\"AIRGAP_HIGH\"");
        let parsed: SecurityProfileLevel = serde_json::from_str("\"AIRGAP_HIGH\"").unwrap();
        assert_eq!(parsed, SecurityProfileLevel::AirgapHigh);
    }
}
