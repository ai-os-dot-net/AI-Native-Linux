use crate::enums::{SkewClassification, TrustedTimeSource};
use crate::skew_budget::SkewBudget;

#[derive(Debug, Clone)]
pub struct ClockSkewDetector {
    pub detector_id: String,
    pub reference_source: TrustedTimeSource,
    pub cross_check_sources: Vec<TrustedTimeSource>,
    pub monotonic_anchor_present: bool,
    pub observed_skew_ms: i64,
    pub state: SkewClassification,
    pub budget: SkewBudget,
}

impl ClockSkewDetector {
    pub fn new(reference_source: TrustedTimeSource, budget: SkewBudget) -> Self {
        Self {
            detector_id: format!("skew_{}", ulid::Ulid::new()),
            reference_source,
            cross_check_sources: Vec::new(),
            monotonic_anchor_present: false,
            observed_skew_ms: 0,
            state: SkewClassification::WithinBudget,
            budget,
        }
    }

    pub fn classify_skew(&self) -> SkewClassification {
        if self.observed_skew_ms < -(self.budget.backward_jump_tolerance_ms) {
            SkewClassification::MonotonicViolation
        } else {
            let abs_skew = self.observed_skew_ms.unsigned_abs();
            if abs_skew > self.budget.hard_skew_ms as u64 {
                SkewClassification::HardExceeded
            } else if abs_skew > self.budget.soft_skew_ms as u64 {
                SkewClassification::SoftExceeded
            } else {
                SkewClassification::WithinBudget
            }
        }
    }

    pub fn update_skew(&mut self, skew_ms: i64) {
        self.observed_skew_ms = skew_ms;
        self.state = self.classify_skew();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skew_budget::SkewBudget;

    fn secure_budget() -> SkewBudget {
        SkewBudget::for_profile("SECURE_DEFAULT")
    }

    #[test]
    fn within_budget_skew() {
        let budget = secure_budget();
        let mut detector = ClockSkewDetector::new(TrustedTimeSource::NtpAuthenticated, budget);
        detector.update_skew(500);
        assert_eq!(detector.state, SkewClassification::WithinBudget);
    }

    #[test]
    fn soft_exceeded_skew() {
        let budget = secure_budget();
        let mut detector = ClockSkewDetector::new(TrustedTimeSource::NtpAuthenticated, budget);
        detector.update_skew(2000);
        assert_eq!(detector.state, SkewClassification::SoftExceeded);
    }

    #[test]
    fn hard_exceeded_skew() {
        let budget = secure_budget();
        let mut detector = ClockSkewDetector::new(TrustedTimeSource::NtpAuthenticated, budget);
        detector.update_skew(6000);
        assert_eq!(detector.state, SkewClassification::HardExceeded);
    }

    #[test]
    fn monotonic_violation_backward_jump() {
        let budget = secure_budget();
        let mut detector = ClockSkewDetector::new(TrustedTimeSource::NtpAuthenticated, budget);
        detector.update_skew(-10000);
        assert_eq!(detector.state, SkewClassification::MonotonicViolation);
    }

    #[test]
    fn zero_skew_is_within_budget() {
        let budget = secure_budget();
        let detector = ClockSkewDetector::new(TrustedTimeSource::NtpAuthenticated, budget);
        assert_eq!(detector.classify_skew(), SkewClassification::WithinBudget);
    }

    #[test]
    fn negative_skew_within_tolerance() {
        let budget = secure_budget();
        let mut detector = ClockSkewDetector::new(TrustedTimeSource::NtpAuthenticated, budget);
        detector.update_skew(-500);
        assert_eq!(detector.state, SkewClassification::WithinBudget);
    }
}
