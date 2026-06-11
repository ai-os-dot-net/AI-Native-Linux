//! `aios-sdk` — third-party developer SDK for building AIOS capsules and apps.
//!
//! Rev.9 ships the full typed-core skeleton: closed enums for target formats,
//! manifest formats, and CLI commands; the capability manifest with validation
//! and generation; the capsule builder with project scaffolding; the CLI
//! command routing and environment detection; and the publish pipeline with
//! state-machine transitions.
//!
//! ```text
//! aios-sdk
//! ├── enums      (SdkTarget, CapabilityDeclarationFormat, SdkCommand)
//! ├── manifest   (CapabilityManifest, ManifestValidator, ManifestGenerator)
//! ├── builder    (CapsuleBuilder, ProjectTemplate, BoilerplateProjectGenerator)
//! ├── cli        (SdkCommands, SdkConfig, SdkEnvironment)
//! └── publish    (PublishPipeline, PublishState, RegistryEndpoint)
//! ```

#![forbid(unsafe_code)]

pub mod builder;
pub mod cli;
pub mod enums;
pub mod manifest;
pub mod publish;

pub use builder::{
    BoilerplateProjectGenerator, BuilderError, CapsuleBuilder, ProjectTemplate,
};
pub use cli::{SdkCommands, SdkConfig, SdkEnvironment};
pub use enums::{CapabilityDeclarationFormat, SdkCommand, SdkTarget};
pub use manifest::{
    CapabilityManifest, EvidenceRecordDeclaration, ManifestGenerator,
    ManifestValidationError, ManifestValidator, RuntimeRequirement, TypedActionDeclaration,
};
pub use publish::{PublishError, PublishPipeline, PublishState, RegistryEndpoint};
