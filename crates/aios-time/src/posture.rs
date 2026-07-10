use crate::enums::{TimePostureState, TimeTrustGrade, TrustedTimeSource};

#[derive(Debug, Clone)]
pub struct TimePosture {
    pub posture_id: String,
    pub state: TimePostureState,
    pub active_grade: TimeTrustGrade,
    pub selected_source: TrustedTimeSource,
    pub observed_skew_ms: i64,
}

impl TimePosture {
    pub fn new() -> Self {
        Self {
            posture_id: format!("timeposture_{}", ulid::Ulid::new()),
            state: TimePostureState::ColdStart,
            active_grade: TimeTrustGrade::UntrustedLocal,
            selected_source: TrustedTimeSource::LocalRtc,
            observed_skew_ms: 0,
        }
    }

    pub fn transition_to_untrusted(&mut self) {
        assert_eq!(
            self.state,
            TimePostureState::ColdStart,
            "transition_to_untrusted only valid from ColdStart"
        );
        self.state = TimePostureState::Untrusted;
        self.active_grade = TimeTrustGrade::UntrustedLocal;
        self.selected_source = TrustedTimeSource::LocalRtc;
        self.observed_skew_ms = 0;
    }

    pub fn transition_to_attested(
        &mut self,
        grade: TimeTrustGrade,
        source: TrustedTimeSource,
        skew_ms: i64,
    ) {
        assert!(
            matches!(
                self.state,
                TimePostureState::Untrusted
                    | TimePostureState::Monotonic
                    | TimePostureState::SkewBlocked
            ),
            "transition_to_attested only valid from Untrusted, Monotonic, or SkewBlocked"
        );
        assert!(
            grade >= TimeTrustGrade::AttestedSingle,
            "attested grade must be at least AttestedSingle"
        );
        self.state = TimePostureState::Attested;
        self.active_grade = grade;
        self.selected_source = source;
        self.observed_skew_ms = skew_ms;
    }

    pub fn transition_to_monotonic(&mut self) {
        assert_eq!(
            self.state,
            TimePostureState::Untrusted,
            "transition_to_monotonic only valid from Untrusted"
        );
        self.state = TimePostureState::Monotonic;
        self.active_grade = TimeTrustGrade::MonotonicOnly;
        self.selected_source = TrustedTimeSource::TpmTick;
        self.observed_skew_ms = 0;
    }

    pub fn transition_to_skew_blocked(&mut self, hard_skew_ms: i64) {
        assert_eq!(
            self.state,
            TimePostureState::Attested,
            "transition_to_skew_blocked only valid from Attested"
        );
        assert!(
            self.observed_skew_ms.abs() > hard_skew_ms,
            "skew must exceed hard_skew_ms to block"
        );
        self.state = TimePostureState::SkewBlocked;
        self.active_grade = TimeTrustGrade::UntrustedLocal;
    }

    pub fn transition_to_degraded(&mut self) {
        assert_eq!(
            self.state,
            TimePostureState::Attested,
            "transition_to_degraded only valid from Attested"
        );
        self.state = TimePostureState::Degraded;
    }

    pub fn transition_to_recovery_required(&mut self) {
        assert_eq!(
            self.state,
            TimePostureState::Degraded,
            "transition_to_recovery_required only valid from Degraded"
        );
        self.state = TimePostureState::RecoveryRequired;
    }

    pub fn transition_to_cold_start(&mut self) {
        assert_eq!(
            self.state,
            TimePostureState::RecoveryRequired,
            "transition_to_cold_start only valid from RecoveryRequired"
        );
        self.state = TimePostureState::ColdStart;
        self.active_grade = TimeTrustGrade::UntrustedLocal;
        self.selected_source = TrustedTimeSource::LocalRtc;
        self.observed_skew_ms = 0;
    }

    pub fn is_consequential_action_allowed(&self, grade_floor: TimeTrustGrade) -> bool {
        if self.state == TimePostureState::SkewBlocked {
            return false;
        }
        self.active_grade >= grade_floor
    }
}

impl Default for TimePosture {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_start_initial_state() {
        let posture = TimePosture::new();
        assert_eq!(posture.state, TimePostureState::ColdStart);
        assert_eq!(posture.active_grade, TimeTrustGrade::UntrustedLocal);
        assert_eq!(posture.selected_source, TrustedTimeSource::LocalRtc);
        assert_eq!(posture.observed_skew_ms, 0);
        assert!(posture.posture_id.starts_with("timeposture_"));
    }

    #[test]
    fn fsm_coldstart_to_untrusted_to_attested() {
        let mut posture = TimePosture::new();
        posture.transition_to_untrusted();
        assert_eq!(posture.state, TimePostureState::Untrusted);
        posture.transition_to_attested(
            TimeTrustGrade::AttestedSingle,
            TrustedTimeSource::NtpAuthenticated,
            500,
        );
        assert_eq!(posture.state, TimePostureState::Attested);
        assert_eq!(posture.active_grade, TimeTrustGrade::AttestedSingle);
        assert_eq!(posture.observed_skew_ms, 500);
    }

    #[test]
    fn fsm_untrusted_to_monotonic_to_attested() {
        let mut posture = TimePosture::new();
        posture.transition_to_untrusted();
        posture.transition_to_monotonic();
        assert_eq!(posture.state, TimePostureState::Monotonic);
        assert_eq!(posture.active_grade, TimeTrustGrade::MonotonicOnly);
        posture.transition_to_attested(
            TimeTrustGrade::AttestedQuorum,
            TrustedTimeSource::Roughtime,
            200,
        );
        assert_eq!(posture.state, TimePostureState::Attested);
        assert_eq!(posture.active_grade, TimeTrustGrade::AttestedQuorum);
    }

    #[test]
    fn fsm_attested_to_skew_blocked() {
        let mut posture = TimePosture::new();
        posture.transition_to_untrusted();
        posture.transition_to_attested(
            TimeTrustGrade::AttestedSingle,
            TrustedTimeSource::NtpAuthenticated,
            6000,
        );
        posture.transition_to_skew_blocked(5000);
        assert_eq!(posture.state, TimePostureState::SkewBlocked);
        assert_eq!(posture.active_grade, TimeTrustGrade::UntrustedLocal);
    }

    #[test]
    fn fsm_skew_blocked_to_attested_recovery() {
        let mut posture = TimePosture::new();
        posture.transition_to_untrusted();
        posture.transition_to_attested(
            TimeTrustGrade::AttestedSingle,
            TrustedTimeSource::NtpAuthenticated,
            6000,
        );
        posture.transition_to_skew_blocked(5000);
        posture.transition_to_attested(
            TimeTrustGrade::AttestedSingle,
            TrustedTimeSource::Gnss,
            300,
        );
        assert_eq!(posture.state, TimePostureState::Attested);
        assert_eq!(posture.selected_source, TrustedTimeSource::Gnss);
    }

    #[test]
    fn fsm_attested_to_degraded_to_recovery_required_to_coldstart() {
        let mut posture = TimePosture::new();
        posture.transition_to_untrusted();
        posture.transition_to_attested(
            TimeTrustGrade::AttestedSingle,
            TrustedTimeSource::NtpAuthenticated,
            100,
        );
        posture.transition_to_degraded();
        assert_eq!(posture.state, TimePostureState::Degraded);
        posture.transition_to_recovery_required();
        assert_eq!(posture.state, TimePostureState::RecoveryRequired);
        posture.transition_to_cold_start();
        assert_eq!(posture.state, TimePostureState::ColdStart);
    }

    #[test]
    #[should_panic(expected = "transition_to_attested only valid from Untrusted")]
    fn attested_from_coldstart_panics() {
        let mut posture = TimePosture::new();
        posture.transition_to_attested(
            TimeTrustGrade::AttestedSingle,
            TrustedTimeSource::NtpAuthenticated,
            0,
        );
    }

    #[test]
    #[should_panic(expected = "attested grade must be at least AttestedSingle")]
    fn attested_with_low_grade_panics() {
        let mut posture = TimePosture::new();
        posture.transition_to_untrusted();
        posture.transition_to_attested(
            TimeTrustGrade::UntrustedLocal,
            TrustedTimeSource::LocalRtc,
            0,
        );
    }
}
