use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustedTimeSource {
    LocalRtc,
    NtpAuthenticated,
    Roughtime,
    TpmTick,
    Gnss,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TimeTrustGrade {
    UntrustedLocal,
    MonotonicOnly,
    AttestedSingle,
    AttestedQuorum,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TimePostureState {
    ColdStart,
    Untrusted,
    Monotonic,
    Attested,
    SkewBlocked,
    Degraded,
    RecoveryRequired,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SkewClassification {
    WithinBudget,
    SoftExceeded,
    HardExceeded,
    MonotonicViolation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::{EnumCount, IntoEnumIterator};

    #[test]
    fn trusted_time_source_variant_count() {
        assert_eq!(TrustedTimeSource::COUNT, 5);
    }

    #[test]
    fn time_trust_grade_ordering() {
        assert!(TimeTrustGrade::AttestedQuorum > TimeTrustGrade::AttestedSingle);
        assert!(TimeTrustGrade::AttestedSingle > TimeTrustGrade::MonotonicOnly);
        assert!(TimeTrustGrade::MonotonicOnly > TimeTrustGrade::UntrustedLocal);
    }

    #[test]
    fn posture_state_iter_all_variants() {
        let states: Vec<_> = TimePostureState::iter().collect();
        assert_eq!(states.len(), TimePostureState::COUNT);
        assert_eq!(TimePostureState::COUNT, 7);
    }

    #[test]
    fn skew_classification_roundtrip_serde() {
        let sc = SkewClassification::HardExceeded;
        let json = serde_json::to_string(&sc).unwrap();
        assert_eq!(json, "\"HARD_EXCEEDED\"");
        let back: SkewClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sc);
    }
}
