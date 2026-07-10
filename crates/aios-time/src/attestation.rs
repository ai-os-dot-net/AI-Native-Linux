use crate::enums::{TimeTrustGrade, TrustedTimeSource};

#[derive(Debug, Clone)]
pub struct TimeAttestation {
    pub attestation_id: String,
    pub source: TrustedTimeSource,
    pub verified_at: chrono::DateTime<chrono::Utc>,
    pub grade_assigned: TimeTrustGrade,
    pub agreeing_sources: Vec<TrustedTimeSource>,
    pub observed_skew_ms: i64,
}

impl TimeAttestation {
    pub fn new(
        source: TrustedTimeSource,
        agreeing_sources: Vec<TrustedTimeSource>,
        observed_skew_ms: i64,
    ) -> Self {
        let agreeing_count = agreeing_sources.len();
        let grade = Self::grade_from_sources(&[source], agreeing_count);
        Self {
            attestation_id: format!("attest_{}", ulid::Ulid::new()),
            source,
            verified_at: chrono::Utc::now(),
            grade_assigned: grade,
            agreeing_sources,
            observed_skew_ms,
        }
    }

    pub fn grade_from_sources(
        sources: &[TrustedTimeSource],
        agreeing_count: usize,
    ) -> TimeTrustGrade {
        if sources.is_empty() {
            TimeTrustGrade::UntrustedLocal
        } else if sources
            .iter()
            .all(|s| matches!(s, TrustedTimeSource::TpmTick))
        {
            TimeTrustGrade::MonotonicOnly
        } else if agreeing_count >= 2 {
            TimeTrustGrade::AttestedQuorum
        } else {
            TimeTrustGrade::AttestedSingle
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sources_yields_untrusted() {
        assert_eq!(
            TimeAttestation::grade_from_sources(&[], 0),
            TimeTrustGrade::UntrustedLocal
        );
    }

    #[test]
    fn tpm_only_yields_monotonic() {
        let sources = vec![TrustedTimeSource::TpmTick, TrustedTimeSource::TpmTick];
        assert_eq!(
            TimeAttestation::grade_from_sources(&sources, 1),
            TimeTrustGrade::MonotonicOnly
        );
    }

    #[test]
    fn single_wall_source_yields_attested_single() {
        let sources = vec![TrustedTimeSource::NtpAuthenticated];
        assert_eq!(
            TimeAttestation::grade_from_sources(&sources, 0),
            TimeTrustGrade::AttestedSingle
        );
    }

    #[test]
    fn multiple_agreeing_yields_attested_quorum() {
        let sources = vec![
            TrustedTimeSource::NtpAuthenticated,
            TrustedTimeSource::Roughtime,
        ];
        assert_eq!(
            TimeAttestation::grade_from_sources(&sources, 2),
            TimeTrustGrade::AttestedQuorum
        );
    }

    #[test]
    fn new_attestation_creates_valid_record() {
        let att = TimeAttestation::new(
            TrustedTimeSource::NtpAuthenticated,
            vec![TrustedTimeSource::Roughtime],
            300,
        );
        assert!(att.attestation_id.starts_with("attest_"));
        assert_eq!(att.grade_assigned, TimeTrustGrade::AttestedSingle);
        assert_eq!(att.observed_skew_ms, 300);
    }
}
