use crate::enums::TimePostureState;
use crate::posture::TimePosture;
use crate::skew_budget::SkewBudget;

pub fn is_consequential_action_allowed(posture: &TimePosture, budget: &SkewBudget) -> bool {
    if posture.state == TimePostureState::SkewBlocked {
        return false;
    }
    if posture.active_grade < budget.require_grade_floor {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{TimeTrustGrade, TrustedTimeSource};

    fn attested_posture() -> TimePosture {
        let mut p = TimePosture::new();
        p.transition_to_untrusted();
        p.transition_to_attested(
            TimeTrustGrade::AttestedSingle,
            TrustedTimeSource::NtpAuthenticated,
            100,
        );
        p
    }

    fn attested_quorum_posture() -> TimePosture {
        let mut p = TimePosture::new();
        p.transition_to_untrusted();
        p.transition_to_attested(
            TimeTrustGrade::AttestedQuorum,
            TrustedTimeSource::Roughtime,
            100,
        );
        p
    }

    #[test]
    fn action_allowed_with_sufficient_grade() {
        let posture = attested_posture();
        let budget = SkewBudget::for_profile("SECURE_DEFAULT");
        assert!(is_consequential_action_allowed(&posture, &budget));
    }

    #[test]
    fn action_blocked_by_insufficient_grade() {
        let posture = attested_posture();
        let budget = SkewBudget::for_profile("DEV_RELAXED");
        assert!(is_consequential_action_allowed(&posture, &budget));
        let stricter_budget = SkewBudget::for_profile("SECURE_DEFAULT");
        let mut weak_posture = TimePosture::new();
        weak_posture.transition_to_untrusted();
        assert!(!is_consequential_action_allowed(
            &weak_posture,
            &stricter_budget
        ));
    }

    #[test]
    fn action_blocked_when_skew_blocked() {
        let mut posture = attested_posture();
        posture.observed_skew_ms = 6000;
        posture.transition_to_skew_blocked(5000);
        let budget = SkewBudget::for_profile("SECURE_DEFAULT");
        assert!(!is_consequential_action_allowed(&posture, &budget));
    }

    #[test]
    fn dev_relaxed_allows_coldstart() {
        let posture = TimePosture::new();
        let budget = SkewBudget::for_profile("DEV_RELAXED");
        assert!(is_consequential_action_allowed(&posture, &budget));
    }

    #[test]
    fn attested_quorum_passes_all_profiles() {
        let posture = attested_quorum_posture();
        for profile in &["SECURE_DEFAULT", "STIG_ALIGNED", "AIRGAP_HIGH"] {
            let budget = SkewBudget::for_profile(profile);
            assert!(
                is_consequential_action_allowed(&posture, &budget),
                "failed for profile {profile}"
            );
        }
    }
}
