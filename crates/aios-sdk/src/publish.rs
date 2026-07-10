//! Publish pipeline — manifest verification, testing, signing, and registry upload.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

use crate::builder::CapsuleBuilder;
use crate::manifest::ManifestValidationError;
use crate::manifest::ManifestValidator;

type PublishStep = (
    &'static str,
    fn(&mut PublishPipeline) -> Result<(), PublishError>,
);

/// The eight-phase publish state machine.
///
/// Capsules flow through: NotPublished → Building → Testing → Signing →
/// Uploading → Published.  Rejected and Failed are terminal error states.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    EnumCount,
    strum_macros::Display,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublishState {
    /// No publish operation has been initiated.
    NotPublished,
    /// The capsule is being compiled.
    Building,
    /// The test suite is running.
    Testing,
    /// The artifact is being cryptographically signed.
    Signing,
    /// The signed artifact is being uploaded to the registry.
    Uploading,
    /// The capsule was successfully published.
    Published,
    /// The publish was rejected by the registry or policy.
    Rejected,
    /// The publish failed due to a non-recoverable error.
    Failed,
}

/// Target registry endpoint for publishing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEndpoint {
    /// Base URL of the registry (e.g. `"http://registry.aios.local"`).
    pub url: String,
    /// Optional authentication token.
    pub auth_token: Option<String>,
    /// Target namespace on the registry.
    pub namespace: String,
}

/// Errors surfaced by the publish pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// Manifest validation failed.
    ManifestInvalid(ManifestValidationError),
    /// Build step failed.
    BuildFailed(String),
    /// Test step failed.
    TestFailed(String),
    /// Signing step failed.
    SigningFailed(String),
    /// Upload to registry failed.
    UploadFailed(String),
    /// No manifest attached to the builder.
    NoManifest,
    /// Invalid state transition.
    InvalidStateTransition {
        /// Current state.
        from: PublishState,
        /// Attempted target state.
        to: PublishState,
    },
}

/// The publish pipeline orchestrates the full publish lifecycle for a capsule.
///
/// Steps: verify_manifest → run_tests → build_artifact → sign_artifact →
/// upload_to_registry → publish.
#[derive(Clone, Debug)]
pub struct PublishPipeline {
    /// Current state of the pipeline.
    state: PublishState,
    /// The capsule builder holding the manifest.
    builder: CapsuleBuilder,
    /// Target registry endpoint.
    endpoint: RegistryEndpoint,
    /// When the pipeline was created.
    started_at: DateTime<Utc>,
    /// When the pipeline finished (set after Published/Rejected/Failed).
    finished_at: Option<DateTime<Utc>>,
}

impl PublishPipeline {
    /// Create a new publish pipeline.
    #[must_use]
    pub fn new(builder: CapsuleBuilder, endpoint: RegistryEndpoint) -> Self {
        Self {
            state: PublishState::NotPublished,
            builder,
            endpoint,
            started_at: Utc::now(),
            finished_at: None,
        }
    }

    /// Return the current publish state.
    #[must_use]
    pub fn state(&self) -> PublishState {
        self.state
    }

    /// Return a reference to the registry endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &RegistryEndpoint {
        &self.endpoint
    }

    /// Return when the publish pipeline was created.
    #[must_use]
    pub const fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// Return when the publish pipeline finished, if it has reached a terminal state.
    #[must_use]
    pub const fn finished_at(&self) -> Option<DateTime<Utc>> {
        self.finished_at
    }

    /// Verify the manifest attached to the builder.
    ///
    /// Runs [`ManifestValidator::validate`], then [`ManifestValidator::check_completeness`],
    /// then [`ManifestValidator::detect_missing_evidence`]. All three must pass.
    pub fn verify_manifest(&self) -> Result<(), PublishError> {
        let manifest = self.builder.manifest().ok_or(PublishError::NoManifest)?;
        let validator = ManifestValidator::new();

        validator
            .validate(manifest)
            .map_err(PublishError::ManifestInvalid)?;

        let missing = validator.check_completeness(manifest);
        if !missing.is_empty() {
            return Err(PublishError::ManifestInvalid(
                ManifestValidationError::MissingField(format!(
                    "incomplete evidence records: {missing:?}"
                )),
            ));
        }

        let undeclared = validator.detect_missing_evidence(manifest);
        if !undeclared.is_empty() {
            return Err(PublishError::ManifestInvalid(
                ManifestValidationError::EvidenceMismatch {
                    missing: undeclared.clone(),
                    undeclared: Vec::new(),
                },
            ));
        }

        Ok(())
    }

    /// Run the capsule's test suite.
    ///
    /// In this stub, returns `Ok(())` when the manifest is valid.
    pub fn run_tests(&self) -> Result<(), PublishError> {
        if self.builder.manifest().is_none() {
            return Err(PublishError::NoManifest);
        }
        Ok(())
    }

    /// Build the capsule artifact.
    ///
    /// Delegates to [`CapsuleBuilder::build_project`].
    pub fn build_artifact(&self) -> Result<(), PublishError> {
        self.builder
            .build_project()
            .map_err(|e| PublishError::BuildFailed(format!("{e:?}")))?;
        Ok(())
    }

    /// Sign the capsule artifact.
    ///
    /// Delegates to [`CapsuleBuilder::sign_capsule`] (on a mutable borrow).
    pub fn sign_artifact(&mut self) -> Result<(), PublishError> {
        self.builder
            .sign_capsule()
            .map_err(|e| PublishError::SigningFailed(format!("{e:?}")))?;
        Ok(())
    }

    /// Upload the signed artifact to the target registry.
    ///
    /// In this stub, validates that the endpoint URL is non-empty and the
    /// manifest is signed. Returns `Ok(())` when all preconditions are met.
    pub fn upload_to_registry(&self) -> Result<(), PublishError> {
        if self.endpoint.url.is_empty() {
            return Err(PublishError::UploadFailed(
                "registry endpoint URL is empty".into(),
            ));
        }
        let manifest = self.builder.manifest().ok_or(PublishError::NoManifest)?;
        let validator = ManifestValidator::new();
        if !validator.has_signature(manifest) {
            return Err(PublishError::UploadFailed(
                "manifest must be signed before upload".into(),
            ));
        }
        Ok(())
    }

    /// Create a merge request for the published capsule on the target platform.
    ///
    /// In this stub, returns `Ok(())` when the endpoint is configured.
    /// Real implementation would call the GitLab API via `goriko-gitlab-api`.
    pub fn create_merge_request(&self) -> Result<(), PublishError> {
        if self.endpoint.url.is_empty() {
            return Err(PublishError::UploadFailed(
                "cannot create MR with empty registry URL".into(),
            ));
        }
        Ok(())
    }

    /// Run the full publish pipeline: verify → test → build → sign → upload.
    ///
    /// Transitions through each state and returns the final state.
    /// On error, transitions to `Failed` and returns the error.
    pub fn publish(&mut self) -> Result<PublishState, PublishError> {
        let steps: [PublishStep; 5] = [
            ("verify_manifest", |s| s.verify_manifest()),
            ("run_tests", |s| s.run_tests()),
            ("build_artifact", |s| s.build_artifact()),
            ("sign_artifact", |s| s.sign_artifact()),
            ("upload_to_registry", |s| s.upload_to_registry()),
        ];

        for (_step_name, step_fn) in &steps {
            step_fn(self).inspect_err(|_| {
                self.state = PublishState::Failed;
                self.finished_at = Some(Utc::now());
            })?;
        }

        self.state = PublishState::Published;
        self.finished_at = Some(Utc::now());
        Ok(self.state)
    }

    /// Transition the pipeline state explicitly.
    ///
    /// Returns `Ok(new_state)` on success, or `Err(PublishError::InvalidStateTransition)`
    /// when the transition is not allowed.
    pub fn transition_to(&mut self, next: PublishState) -> Result<PublishState, PublishError> {
        let valid = matches!(
            (self.state, next),
            (PublishState::NotPublished, PublishState::Building)
                | (PublishState::Building, PublishState::Testing)
                | (PublishState::Testing, PublishState::Signing)
                | (PublishState::Signing, PublishState::Uploading)
                | (PublishState::Uploading, PublishState::Published)
                | (PublishState::Uploading, PublishState::Rejected)
                | (_, PublishState::Failed)
        );

        if !valid {
            return Err(PublishError::InvalidStateTransition {
                from: self.state,
                to: next,
            });
        }

        self.state = next;
        if matches!(
            self.state,
            PublishState::Published | PublishState::Rejected | PublishState::Failed
        ) {
            self.finished_at = Some(Utc::now());
        }
        Ok(self.state)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use strum::{EnumCount, IntoEnumIterator};

    use crate::{builder::CapsuleBuilder, enums::CapabilityDeclarationFormat, enums::SdkTarget};

    use super::*;

    fn make_builder_with_signed_manifest() -> CapsuleBuilder {
        let mut builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/test-publish".into());
        builder
            .create_manifest(
                "publish-capsule",
                "1.0.0",
                "publisher:test",
                vec!["service.restart".into()],
                vec!["action_completed".into()],
                CapabilityDeclarationFormat::JsonManifest,
            )
            .expect("create manifest");
        builder.sign_capsule().expect("sign");
        builder
    }

    fn make_endpoint() -> RegistryEndpoint {
        RegistryEndpoint {
            url: "http://registry.aios.local".into(),
            auth_token: Some("test-token".into()),
            namespace: "test-ns".into(),
        }
    }

    #[test]
    fn publish_state_variant_count_is_eight() {
        assert_eq!(
            PublishState::COUNT,
            8,
            "PublishState must have exactly 8 variants"
        );
    }

    #[test]
    fn publish_state_iter_yields_all_variants() {
        let all: Vec<PublishState> = PublishState::iter().collect();
        assert_eq!(all.len(), 8);
        assert!(all.contains(&PublishState::NotPublished));
        assert!(all.contains(&PublishState::Published));
        assert!(all.contains(&PublishState::Failed));
    }

    #[test]
    fn publish_state_serde_round_trips() {
        for state in PublishState::iter() {
            let json = serde_json::to_string(&state).expect("serialize");
            let parsed: PublishState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(state, parsed, "round-trip failed for {state:?}");
        }
    }

    #[test]
    fn publish_state_serde_screaming_snake_case() {
        let json = serde_json::to_string(&PublishState::NotPublished).expect("serialize");
        assert!(
            json.contains("NOT_PUBLISHED"),
            "expected SCREAMING_SNAKE_CASE, got {json}"
        );
    }

    #[test]
    fn publish_pipeline_new_starts_not_published() {
        let builder = make_builder_with_signed_manifest();
        let endpoint = make_endpoint();
        let pipeline = PublishPipeline::new(builder, endpoint);
        assert_eq!(pipeline.state(), PublishState::NotPublished);
    }

    #[test]
    fn publish_pipeline_verify_manifest_passes_with_valid_manifest() {
        let builder = make_builder_with_signed_manifest();
        let pipeline = PublishPipeline::new(builder, make_endpoint());
        pipeline
            .verify_manifest()
            .expect("valid manifest should pass verification");
    }

    #[test]
    fn publish_pipeline_verify_manifest_fails_without_manifest() {
        let builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/no-manifest".into());
        let pipeline = PublishPipeline::new(builder, make_endpoint());
        let result = pipeline.verify_manifest();
        assert!(matches!(result, Err(PublishError::NoManifest)));
    }

    #[test]
    fn publish_pipeline_upload_fails_with_empty_url() {
        let builder = make_builder_with_signed_manifest();
        let endpoint = RegistryEndpoint {
            url: String::new(),
            auth_token: None,
            namespace: "test".into(),
        };
        let pipeline = PublishPipeline::new(builder, endpoint);
        let result = pipeline.upload_to_registry();
        assert!(matches!(result, Err(PublishError::UploadFailed(_))));
    }

    #[test]
    fn publish_pipeline_upload_passes_with_valid_config() {
        let builder = make_builder_with_signed_manifest();
        let pipeline = PublishPipeline::new(builder, make_endpoint());
        pipeline
            .upload_to_registry()
            .expect("valid endpoint should upload");
    }

    #[test]
    fn publish_pipeline_create_merge_request_succeeds() {
        let builder = make_builder_with_signed_manifest();
        let pipeline = PublishPipeline::new(builder, make_endpoint());
        pipeline
            .create_merge_request()
            .expect("MR creation should succeed");
    }

    #[test]
    fn publish_pipeline_full_publish_succeeds() {
        let builder = make_builder_with_signed_manifest();
        let mut pipeline = PublishPipeline::new(builder, make_endpoint());
        let state = pipeline.publish().expect("full publish should succeed");
        assert_eq!(state, PublishState::Published);
    }

    #[test]
    fn publish_pipeline_transition_to_valid_sequence() {
        let builder = make_builder_with_signed_manifest();
        let mut pipeline = PublishPipeline::new(builder, make_endpoint());
        let states = vec![
            PublishState::Building,
            PublishState::Testing,
            PublishState::Signing,
            PublishState::Uploading,
            PublishState::Published,
        ];
        for next in states {
            let state = pipeline
                .transition_to(next)
                .expect("valid transition should succeed");
            assert_eq!(state, next);
        }
    }

    #[test]
    fn publish_pipeline_transition_to_invalid_rejected() {
        let builder = make_builder_with_signed_manifest();
        let mut pipeline = PublishPipeline::new(builder, make_endpoint());
        let result = pipeline.transition_to(PublishState::Rejected);
        assert!(matches!(
            result,
            Err(PublishError::InvalidStateTransition { .. })
        ));
    }

    #[test]
    fn publish_pipeline_any_state_can_transition_to_failed() {
        let builder = make_builder_with_signed_manifest();
        let mut pipeline = PublishPipeline::new(builder, make_endpoint());
        pipeline
            .transition_to(PublishState::Building)
            .expect("to building");
        let state = pipeline
            .transition_to(PublishState::Failed)
            .expect("to failed");
        assert_eq!(state, PublishState::Failed);
    }

    #[test]
    fn publish_pipeline_publish_fails_without_manifest() {
        let builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/no-manifest".into());
        let mut pipeline = PublishPipeline::new(builder, make_endpoint());
        let result = pipeline.publish();
        assert!(result.is_err());
        assert_eq!(pipeline.state(), PublishState::Failed);
    }

    #[test]
    fn registry_endpoint_serde_round_trips() {
        let endpoint = RegistryEndpoint {
            url: "http://registry.aios.local".into(),
            auth_token: Some("secret-token".into()),
            namespace: "production".into(),
        };
        let json = serde_json::to_string(&endpoint).expect("serialize");
        let parsed: RegistryEndpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(endpoint, parsed);
    }
}
