//! Closed enums for the AIOS SDK — artifact targets, manifest formats, and CLI commands.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

/// Target artifact format produced by the SDK build pipeline.
///
/// Nine closed variants covering the full AIOS Rev.9 distribution matrix.
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
pub enum SdkTarget {
    /// Native Rust dynamic/static library for AIOS-native capsules.
    RustLib,
    /// Python `.whl` wheel for AIOS Python capsules.
    PythonWheel,
    /// npm JavaScript/TypeScript package.
    JavaScriptPackage,
    /// Kotlin JAR for Android capsule targets.
    KotlinJar,
    /// Go module for Go-based capsules.
    GoModule,
    /// OCI container image for portable capsules.
    ContainerImage,
    /// WebAssembly module for sandboxed capsule execution.
    WasmModule,
    /// eBPF probe for kernel-level capsule instrumentation.
    EbpfProgram,
    /// Shell script capsule (single-file executable).
    ShellScript,
}

/// How a capsule declares its capabilities.
///
/// Four closed formats — the SDK can read and write all of them.
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
pub enum CapabilityDeclarationFormat {
    /// Declared in a `capsule.json` manifest file.
    JsonManifest,
    /// Declared in a `capsule.toml` manifest file.
    TomlManifest,
    /// Declared in a `capsule.yaml` manifest file.
    YamlManifest,
    /// Inline annotation within source code (e.g. `#[capability]`).
    InlineAnnotation,
}

/// CLI commands exposed by the SDK toolchain.
///
/// Closed set of eight commands — this is the command type vocabulary;
/// no actual binary is built by this crate.
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
pub enum SdkCommand {
    /// Initialise a new capsule project from a template.
    Init,
    /// Compile the capsule.
    Build,
    /// Run the capsule's test suite.
    Test,
    /// Package the capsule into its target artifact format.
    Package,
    /// Sign the packaged artifact with the publisher's Ed25519 key.
    Sign,
    /// Publish the signed artifact to a registry.
    Publish,
    /// Verify a published capsule's manifest, signature, and evidence.
    Verify,
    /// Remove build artifacts and cached intermediates.
    Clean,
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use strum::{EnumCount, IntoEnumIterator};

    use super::*;

    #[test]
    fn sdk_target_variant_count_is_nine() {
        assert_eq!(SdkTarget::COUNT, 9, "SdkTarget must have exactly 9 variants");
    }

    #[test]
    fn sdk_target_iter_yields_all_variants() {
        let all: Vec<SdkTarget> = SdkTarget::iter().collect();
        assert_eq!(all.len(), 9);
        assert!(all.contains(&SdkTarget::RustLib));
        assert!(all.contains(&SdkTarget::WasmModule));
        assert!(all.contains(&SdkTarget::EbpfProgram));
    }

    #[test]
    fn sdk_target_serde_round_trips() {
        for target in SdkTarget::iter() {
            let json = serde_json::to_string(&target).expect("serialize must succeed");
            let parsed: SdkTarget = serde_json::from_str(&json).expect("deserialize must succeed");
            assert_eq!(target, parsed, "round-trip failed for {target:?}");
        }
    }

    #[test]
    fn sdk_target_serde_screaming_snake_case() {
        let json = serde_json::to_string(&SdkTarget::ContainerImage).expect("serialize");
        assert!(json.contains("CONTAINER_IMAGE"), "expected SCREAMING_SNAKE_CASE, got {json}");
    }

    #[test]
    fn sdk_target_display_produces_human_readable_names() {
        let s = SdkTarget::RustLib.to_string();
        assert_eq!(s, "RustLib");
    }

    #[test]
    fn capability_format_variant_count_is_four() {
        assert_eq!(
            CapabilityDeclarationFormat::COUNT,
            4,
            "CapabilityDeclarationFormat must have exactly 4 variants"
        );
    }

    #[test]
    fn capability_format_iter_yields_all_variants() {
        let all: Vec<CapabilityDeclarationFormat> = CapabilityDeclarationFormat::iter().collect();
        assert_eq!(all.len(), 4);
        assert!(all.contains(&CapabilityDeclarationFormat::JsonManifest));
        assert!(all.contains(&CapabilityDeclarationFormat::InlineAnnotation));
    }

    #[test]
    fn capability_format_serde_round_trips() {
        for fmt in CapabilityDeclarationFormat::iter() {
            let json = serde_json::to_string(&fmt).expect("serialize");
            let parsed: CapabilityDeclarationFormat =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(fmt, parsed, "round-trip failed for {fmt:?}");
        }
    }

    #[test]
    fn capability_format_serde_screaming_snake_case() {
        let json = serde_json::to_string(&CapabilityDeclarationFormat::TomlManifest)
            .expect("serialize");
        assert!(
            json.contains("TOML_MANIFEST"),
            "expected SCREAMING_SNAKE_CASE, got {json}"
        );
    }

    #[test]
    fn sdk_command_variant_count_is_eight() {
        assert_eq!(
            SdkCommand::COUNT,
            8,
            "SdkCommand must have exactly 8 variants"
        );
    }

    #[test]
    fn sdk_command_iter_yields_all_variants() {
        let all: Vec<SdkCommand> = SdkCommand::iter().collect();
        assert_eq!(all.len(), 8);
        assert!(all.contains(&SdkCommand::Init));
        assert!(all.contains(&SdkCommand::Publish));
        assert!(all.contains(&SdkCommand::Clean));
    }

    #[test]
    fn sdk_command_serde_round_trips() {
        for cmd in SdkCommand::iter() {
            let json = serde_json::to_string(&cmd).expect("serialize");
            let parsed: SdkCommand = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(cmd, parsed, "round-trip failed for {cmd:?}");
        }
    }

    #[test]
    fn sdk_command_serde_screaming_snake_case() {
        let json =
            serde_json::to_string(&SdkCommand::Build).expect("serialize");
        assert!(json.contains("BUILD"), "expected SCREAMING_SNAKE_CASE, got {json}");
    }

    #[test]
    fn sdk_command_display_produces_human_readable_names() {
        assert_eq!(SdkCommand::Test.to_string(), "Test");
        assert_eq!(SdkCommand::Clean.to_string(), "Clean");
    }

    #[test]
    fn sdk_target_all_variants_have_distinct_serde_values() {
        let mut seen = std::collections::HashSet::new();
        for target in SdkTarget::iter() {
            let json = serde_json::to_string(&target).expect("serialize");
            assert!(
                seen.insert(json),
                "duplicate serde representation for {target:?}"
            );
        }
    }

    #[test]
    fn sdk_command_all_variants_have_distinct_serde_values() {
        let mut seen = std::collections::HashSet::new();
        for cmd in SdkCommand::iter() {
            let json = serde_json::to_string(&cmd).expect("serialize");
            assert!(
                seen.insert(json),
                "duplicate serde representation for {cmd:?}"
            );
        }
    }
}
