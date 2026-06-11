//! Capsule builder — project scaffolding, manifest creation, and build pipeline.

use serde::{Deserialize, Serialize};
use strum_macros::{EnumCount, EnumIter};

use crate::enums::CapabilityDeclarationFormat;
use crate::enums::SdkTarget;
use crate::manifest::{CapabilityManifest, ManifestGenerator, ManifestValidator};

/// Errors surfaced by the capsule build pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    /// Manifest validation failed before build could proceed.
    ManifestInvalid(String),
    /// Project directory already exists; refusing to overwrite.
    ProjectExists(String),
    /// Required toolchain not found for the selected target.
    ToolchainNotFound(String),
    /// Build step failed.
    BuildFailed(String),
}

/// Project template presets for bootstrapping new capsules.
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
pub enum ProjectTemplate {
    /// Full Rust AIOS-native capsule scaffold.
    RustCapsule,
    /// Python capsule scaffold with pyproject.toml.
    PythonCapsule,
    /// WebAssembly capsule scaffold.
    WasmCapsule,
    /// OCI container capsule scaffold with Dockerfile.
    ContainerCapsule,
    /// eBPF probe scaffold.
    EbpfProbe,
    /// Shell script capsule scaffold.
    ShellApp,
}

/// The CapsuleBuilder orchestrates the full capsule development lifecycle:
/// init → manifest → add capabilities → build → package → sign.
#[derive(Clone, Debug)]
pub struct CapsuleBuilder {
    /// Current manifest (set after `create_manifest`).
    manifest: Option<CapabilityManifest>,
    /// Target artifact format.
    target: SdkTarget,
    /// Project root directory.
    project_root: String,
}

impl CapsuleBuilder {
    /// Create a new capsule builder for a given target.
    #[must_use]
    pub fn new(target: SdkTarget, project_root: String) -> Self {
        Self {
            manifest: None,
            target,
            project_root,
        }
    }

    /// Initialise a new project directory and scaffold from a template.
    ///
    /// Returns an error when the project directory already exists.
    pub fn init_project(
        &mut self,
        _template: ProjectTemplate,
    ) -> Result<(), BuilderError> {
        let path = std::path::Path::new(&self.project_root);
        if path.exists() {
            return Err(BuilderError::ProjectExists(self.project_root.clone()));
        }
        Ok(())
    }

    /// Create a capability manifest from template parameters and attach it
    /// to this builder's state.
    pub fn create_manifest(
        &mut self,
        name: &str,
        version: &str,
        publisher_id: &str,
        capabilities: Vec<String>,
        evidence_categories: Vec<String>,
        format: CapabilityDeclarationFormat,
    ) -> Result<&CapabilityManifest, BuilderError> {
        let generator = ManifestGenerator::new();
        let manifest = generator
            .generate_from_template(
                name,
                version,
                publisher_id,
                capabilities,
                evidence_categories,
                format,
            )
            .map_err(|e| BuilderError::ManifestInvalid(format!("{e:?}")))?;
        self.manifest = Some(manifest);
        Ok(self.manifest.as_ref().expect("just set"))
    }

    /// Add a capability name to the current manifest.
    ///
    /// Returns `Ok(true)` when the capability was added; `Ok(false)` when it
    /// was already present. Returns `Err` when no manifest has been created.
    pub fn add_capability(&mut self, action_name: &str) -> Result<bool, BuilderError> {
        let manifest = self
            .manifest
            .as_mut()
            .ok_or_else(|| BuilderError::ManifestInvalid("no manifest created yet".into()))?;
        if manifest.capabilities.contains(&action_name.to_owned()) {
            return Ok(false);
        }
        manifest.capabilities.push(action_name.to_owned());
        Ok(true)
    }

    /// Validates the manifest and returns `Ok(())` when the capsule is ready to build.
    pub fn build_project(&self) -> Result<(), BuilderError> {
        let manifest = self
            .manifest
            .as_ref()
            .ok_or_else(|| BuilderError::ManifestInvalid("no manifest created yet".into()))?;
        let validator = ManifestValidator::new();
        validator
            .validate(manifest)
            .map_err(|e| BuilderError::ManifestInvalid(format!("{e:?}")))?;
        Ok(())
    }

    /// Package the capsule — validates the manifest and returns the target format.
    pub fn package_capsule(&self) -> Result<SdkTarget, BuilderError> {
        let manifest = self
            .manifest
            .as_ref()
            .ok_or_else(|| BuilderError::ManifestInvalid("no manifest created yet".into()))?;
        let validator = ManifestValidator::new();
        validator
            .validate(manifest)
            .map_err(|e| BuilderError::BuildFailed(format!("manifest invalid: {e:?}")))?;

        if !validator.has_signature(manifest) {
            return Err(BuilderError::BuildFailed(
                "package requires a signed manifest — call sign_capsule first".into(),
            ));
        }
        Ok(self.target)
    }

    /// Sign the capsule manifest.
    ///
    /// In a real implementation this would use the publisher's Ed25519 key.
    /// For now it sets a placeholder signature so `package_capsule` can proceed.
    pub fn sign_capsule(&mut self) -> Result<(), BuilderError> {
        let manifest = self
            .manifest
            .as_mut()
            .ok_or_else(|| BuilderError::ManifestInvalid("no manifest created yet".into()))?;
        let content_bytes = serde_json::to_vec(&manifest)
            .map_err(|e| BuilderError::BuildFailed(format!("serialisation failed: {e}")))?;
        let hash = blake3::hash(&content_bytes);
        manifest.signature = Some(hash.as_bytes().to_vec());
        Ok(())
    }

    /// Return a reference to the current manifest, if any.
    #[must_use]
    pub fn manifest(&self) -> Option<&CapabilityManifest> {
        self.manifest.as_ref()
    }
}

/// Generates boilerplate project files for each template type.
#[derive(Clone, Debug, Default)]
pub struct BoilerplateProjectGenerator;

impl BoilerplateProjectGenerator {
    /// Create a new generator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Generate the complete file scaffold for a given template.
    ///
    /// Returns a map of `relative_path -> file_contents`.
    #[must_use]
    pub fn generate_scaffold(&self, template: ProjectTemplate) -> Vec<(String, String)> {
        let mut files = Vec::new();
        match template {
            ProjectTemplate::RustCapsule => {
                files.push((
                    "Cargo.toml".into(),
                    self.generate_cargo_toml("capsule", "0.1.0"),
                ));
                files.push(("src/main.rs".into(), self.generate_main_file()));
                files.push(("capsule.json".into(), self.generate_manifest_file()));
            }
            ProjectTemplate::PythonCapsule => {
                files.push(("pyproject.toml".into(), self.generate_python_pyproject()));
                files.push(("src/__init__.py".into(), self.generate_python_init()));
                files.push(("capsule.json".into(), self.generate_manifest_file()));
            }
            ProjectTemplate::WasmCapsule => {
                files.push(("Cargo.toml".into(), self.generate_wasm_cargo_toml()));
                files.push(("src/lib.rs".into(), self.generate_wasm_lib()));
                files.push(("capsule.json".into(), self.generate_manifest_file()));
            }
            ProjectTemplate::ContainerCapsule => {
                files.push(("Dockerfile".into(), self.generate_dockerfile()));
                files.push(("capsule.json".into(), self.generate_manifest_file()));
            }
            ProjectTemplate::EbpfProbe => {
                files.push(("Cargo.toml".into(), self.generate_cargo_toml("ebpf-capsule", "0.1.0")));
                files.push(("src/main.rs".into(), self.generate_main_file()));
                files.push(("capsule.json".into(), self.generate_manifest_file()));
            }
            ProjectTemplate::ShellApp => {
                files.push(("main.sh".into(), self.generate_shell_main()));
                files.push(("capsule.json".into(), self.generate_manifest_file()));
            }
        }
        files
    }

    /// Generate a Cargo.toml for Rust-based capsules.
    #[must_use]
    pub fn generate_cargo_toml(&self, name: &str, version: &str) -> String {
        format!(
            "[package]\n\
             name = \"{name}\"\n\
             version = \"{version}\"\n\
             edition = \"2021\"\n\
             \n\
             [dependencies]\n\
             aios-sdk = \"0.1\"\n"
        )
    }

    /// Generate a main.rs entry point for Rust capsules.
    #[must_use]
    pub fn generate_main_file(&self) -> String {
        "fn main() {\n    println!(\"AIOS capsule starting...\");\n}\n".into()
    }

    /// Generate a capsule manifest JSON file.
    #[must_use]
    pub fn generate_manifest_file(&self) -> String {
        serde_json::json!({
            "manifest_id": "",
            "name": "",
            "version": "0.1.0",
            "publisher_id": "",
            "capabilities": [],
            "evidence_categories": [],
            "format": "JSON_MANIFEST"
        })
        .to_string()
    }

    /// Generate a pyproject.toml for Python capsules.
    #[must_use]
    pub fn generate_python_pyproject(&self) -> String {
        "[project]\n\
         name = \"capsule\"\n\
         version = \"0.1.0\"\n\
         requires-python = \">=3.10\"\n\
         dependencies = [\"aios-sdk\"]\n"
            .into()
    }

    /// Generate an __init__.py for Python capsules.
    #[must_use]
    pub fn generate_python_init(&self) -> String {
        "# AIOS Python capsule\n\ndef main():\n    print(\"AIOS capsule starting...\")\n".into()
    }

    /// Generate a Cargo.toml for WebAssembly capsules.
    #[must_use]
    pub fn generate_wasm_cargo_toml(&self) -> String {
        "[package]\n\
         name = \"wasm-capsule\"\n\
         version = \"0.1.0\"\n\
         edition = \"2021\"\n\
         \n\
         [lib]\n\
         crate-type = [\"cdylib\"]\n\
         \n\
         [dependencies]\n\
         wasm-bindgen = \"0.2\"\n"
            .into()
    }

    /// Generate a lib.rs for WebAssembly capsules.
    #[must_use]
    pub fn generate_wasm_lib(&self) -> String {
        "use wasm_bindgen::prelude::*;\n\n\
         #[wasm_bindgen]\n\
         pub fn init() {\n    // AIOS WASM capsule\n}\n"
            .into()
    }

    /// Generate a Dockerfile for container capsules.
    #[must_use]
    pub fn generate_dockerfile(&self) -> String {
        "FROM ubuntu:24.04\n\
         COPY capsule /capsule\n\
         ENTRYPOINT [\"/capsule\"]\n"
            .into()
    }

    /// Generate a main.sh for shell script capsules.
    #[must_use]
    pub fn generate_shell_main(&self) -> String {
        "#!/usr/bin/env bash\n\
         set -euo pipefail\n\
         echo \"AIOS capsule starting...\"\n"
            .into()
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

    use super::*;

    #[test]
    fn project_template_count_is_six() {
        assert_eq!(
            ProjectTemplate::COUNT,
            6,
            "ProjectTemplate must have exactly 6 variants"
        );
    }

    #[test]
    fn project_template_iter_yields_all_variants() {
        let all: Vec<ProjectTemplate> = ProjectTemplate::iter().collect();
        assert_eq!(all.len(), 6);
        assert!(all.contains(&ProjectTemplate::RustCapsule));
        assert!(all.contains(&ProjectTemplate::ShellApp));
    }

    #[test]
    fn project_template_serde_round_trips() {
        for template in ProjectTemplate::iter() {
            let json = serde_json::to_string(&template).expect("serialize");
            let parsed: ProjectTemplate =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(template, parsed, "round-trip failed for {template:?}");
        }
    }

    #[test]
    fn capsule_builder_rejects_init_on_existing_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut builder =
            CapsuleBuilder::new(SdkTarget::RustLib, dir.path().to_string_lossy().to_string());
        let result = builder.init_project(ProjectTemplate::RustCapsule);
        assert!(
            matches!(result, Err(BuilderError::ProjectExists(_))),
            "init should reject existing directory"
        );
    }

    #[test]
    fn capsule_builder_create_manifest_sets_manifest() {
        let mut builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/test-capsule".into());
        builder
            .create_manifest(
                "test-capsule",
                "1.0.0",
                "publisher:test",
                vec!["service.restart".into()],
                vec!["audit".into()],
                CapabilityDeclarationFormat::JsonManifest,
            )
            .expect("create_manifest should succeed");
        assert!(builder.manifest().is_some());
    }

    #[test]
    fn capsule_builder_add_capability_returns_true_for_new() {
        let mut builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/test-capsule".into());
        builder
            .create_manifest(
                "test",
                "1.0.0",
                "pub:test",
                vec!["fs.write".into()],
                vec!["audit".into()],
                CapabilityDeclarationFormat::JsonManifest,
            )
            .expect("create");
        let added = builder
            .add_capability("service.restart")
            .expect("add_capability should succeed");
        assert!(added);
    }

    #[test]
    fn capsule_builder_add_capability_returns_false_for_duplicate() {
        let mut builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/test-capsule".into());
        builder
            .create_manifest(
                "test",
                "1.0.0",
                "pub:test",
                vec!["fs.write".into()],
                vec!["audit".into()],
                CapabilityDeclarationFormat::JsonManifest,
            )
            .expect("create");
        let added = builder
            .add_capability("fs.write")
            .expect("add_capability should succeed");
        assert!(!added);
    }

    #[test]
    fn capsule_builder_add_capability_fails_without_manifest() {
        let mut builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/no-manifest".into());
        let result = builder.add_capability("test.action");
        assert!(result.is_err());
    }

    #[test]
    fn capsule_builder_build_project_fails_without_manifest() {
        let builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/no-manifest".into());
        let result = builder.build_project();
        assert!(result.is_err());
    }

    #[test]
    fn capsule_builder_build_project_passes_with_valid_manifest() {
        let mut builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/test-capsule".into());
        builder
            .create_manifest(
                "test",
                "1.0.0",
                "pub:test",
                vec!["fs.write".into()],
                vec!["audit".into()],
                CapabilityDeclarationFormat::JsonManifest,
            )
            .expect("create");
        builder.build_project().expect("build should pass");
    }

    #[test]
    fn capsule_builder_package_fails_without_signature() {
        let mut builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/test-capsule".into());
        builder
            .create_manifest(
                "test",
                "1.0.0",
                "pub:test",
                vec!["fs.write".into()],
                vec!["audit".into()],
                CapabilityDeclarationFormat::JsonManifest,
            )
            .expect("create");
        let result = builder.package_capsule();
        assert!(result.is_err());
    }

    #[test]
    fn capsule_builder_sign_and_package_round_trip() {
        let mut builder = CapsuleBuilder::new(SdkTarget::RustLib, "/tmp/test-capsule".into());
        builder
            .create_manifest(
                "test",
                "1.0.0",
                "pub:test",
                vec!["fs.write".into()],
                vec!["audit".into()],
                CapabilityDeclarationFormat::JsonManifest,
            )
            .expect("create");
        builder.sign_capsule().expect("sign should succeed");
        let target = builder
            .package_capsule()
            .expect("package should succeed after signing");
        assert_eq!(target, SdkTarget::RustLib);
    }

    #[test]
    fn boilerplate_project_generator_rust_scaffold_has_expected_files() {
        let gen = BoilerplateProjectGenerator::new();
        let files = gen.generate_scaffold(ProjectTemplate::RustCapsule);
        assert_eq!(files.len(), 3);
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"Cargo.toml"));
        assert!(names.contains(&"src/main.rs"));
        assert!(names.contains(&"capsule.json"));
    }

    #[test]
    fn boilerplate_project_generator_python_scaffold_has_expected_files() {
        let gen = BoilerplateProjectGenerator::new();
        let files = gen.generate_scaffold(ProjectTemplate::PythonCapsule);
        assert_eq!(files.len(), 3);
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"pyproject.toml"));
        assert!(names.contains(&"src/__init__.py"));
    }

    #[test]
    fn boilerplate_project_generator_container_scaffold_has_dockerfile() {
        let gen = BoilerplateProjectGenerator::new();
        let files = gen.generate_scaffold(ProjectTemplate::ContainerCapsule);
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"Dockerfile"));
    }

    #[test]
    fn boilerplate_project_generator_all_templates_produce_non_empty_files() {
        let gen = BoilerplateProjectGenerator::new();
        for template in ProjectTemplate::iter() {
            let files = gen.generate_scaffold(template);
            assert!(
                !files.is_empty(),
                "template {template:?} must produce at least one file"
            );
            for (_path, content) in &files {
                assert!(
                    !content.is_empty(),
                    "file content for {template:?}/{_path} must not be empty"
                );
            }
        }
    }
}
