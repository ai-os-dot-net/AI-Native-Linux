//! SDK CLI types — command routing, configuration, and environment detection.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::enums::SdkCommand;
use crate::enums::SdkTarget;

/// Top-level SDK command routing descriptor.
///
/// Maps each [`SdkCommand`] variant to its sub-command configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkCommands {
    /// The command to execute.
    pub command: SdkCommand,
    /// The target format for this invocation.
    pub target: SdkTarget,
    /// Optional extra arguments passed to the command.
    pub args: Vec<String>,
}

/// SDK runtime configuration — loaded from disk or environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkConfig {
    /// Default registry endpoint for publishing.
    pub default_registry: String,
    /// Active publisher profile name.
    pub profile: String,
    /// Project root directory path.
    pub project_root: String,
    /// Override map for per-target toolchain paths.
    pub toolchain_overrides: HashMap<String, String>,
}

impl Default for SdkConfig {
    fn default() -> Self {
        Self {
            default_registry: "http://registry.aios.local".into(),
            profile: "default".into(),
            project_root: ".".into(),
            toolchain_overrides: HashMap::new(),
        }
    }
}

/// SDK environment detection result — what toolchains and capabilities are available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdkEnvironment {
    /// Targets that have working toolchains.
    pub available_targets: Vec<SdkTarget>,
    /// Per-target toolchain directories found.
    pub toolchain_paths: HashMap<SdkTarget, String>,
    /// Warnings about missing dependencies.
    pub warnings: Vec<String>,
}

impl SdkEnvironment {
    /// Create an empty environment snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available_targets: Vec::new(),
            toolchain_paths: HashMap::new(),
            warnings: Vec::new(),
        }
    }

    /// Detect which toolchains are available on the current system.
    ///
    /// Checks for common toolchain binaries by name. Returns a populated
    /// [`SdkEnvironment`] with available targets and any warnings.
    #[must_use]
    pub fn detect_toolchain() -> Self {
        let mut env = Self::new();
        env.check_dependencies();

        if env.available_targets.is_empty() {
            env.warnings
                .push("no AIOS SDK toolchains detected".into());
        }

        env
    }

    /// Check known dependency paths and populate available targets.
    pub fn check_dependencies(&mut self) {
        let checks: Vec<(SdkTarget, &str)> = vec![
            (SdkTarget::RustLib, "cargo"),
            (SdkTarget::RustLib, "rustc"),
            (SdkTarget::PythonWheel, "python3"),
            (SdkTarget::PythonWheel, "pip"),
            (SdkTarget::JavaScriptPackage, "node"),
            (SdkTarget::JavaScriptPackage, "npm"),
            (SdkTarget::KotlinJar, "kotlinc"),
            (SdkTarget::GoModule, "go"),
            (SdkTarget::ContainerImage, "docker"),
            (SdkTarget::WasmModule, "wasm-pack"),
            (SdkTarget::ShellScript, "bash"),
        ];

        let mut seen = std::collections::HashSet::new();
        for (target, binary) in &checks {
            let path = Self::which(binary);
            match path {
                Some(p) => {
                    if seen.insert(target) {
                        self.available_targets.push(*target);
                    }
                    let _ = self.toolchain_paths.entry(*target).or_insert(p);
                }
                None => {
                    if seen.insert(target) {
                        self.warnings.push(format!(
                            "toolchain {binary} not found for target {target:?}"
                        ));
                    }
                }
            }
        }

        self.available_targets.sort_by_key(|t| t.to_string());
        self.available_targets.dedup();
    }

    /// Return the list of targets that have working toolchains.
    #[must_use]
    pub fn list_installed_targets(&self) -> Vec<SdkTarget> {
        self.available_targets.clone()
    }

    /// Try to locate a binary on PATH.
    fn which(binary: &str) -> Option<String> {
        let path_var = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(binary);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
        None
    }
}

impl Default for SdkEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    #[test]
    fn sdk_commands_constructable() {
        let cmd = SdkCommands {
            command: SdkCommand::Init,
            target: SdkTarget::RustLib,
            args: vec!["--name".into(), "my-capsule".into()],
        };
        assert_eq!(cmd.command, SdkCommand::Init);
        assert_eq!(cmd.target, SdkTarget::RustLib);
        assert_eq!(cmd.args.len(), 2);
    }

    #[test]
    fn sdk_commands_serde_round_trips() {
        let cmd = SdkCommands {
            command: SdkCommand::Build,
            target: SdkTarget::WasmModule,
            args: vec!["--release".into()],
        };
        let json = serde_json::to_string(&cmd).expect("serialize");
        let parsed: SdkCommands = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cmd, parsed);
    }

    #[test]
    fn sdk_config_defaults_are_sane() {
        let config = SdkConfig::default();
        assert!(!config.default_registry.is_empty());
        assert_eq!(config.profile, "default");
        assert_eq!(config.project_root, ".");
        assert!(config.toolchain_overrides.is_empty());
    }

    #[test]
    fn sdk_config_serde_round_trips() {
        let config = SdkConfig {
            default_registry: "http://registry.example.com".into(),
            profile: "production".into(),
            project_root: "/home/dev/capsule".into(),
            toolchain_overrides: {
                let mut m = HashMap::new();
                m.insert("rustc".into(), "/usr/local/bin/rustc".into());
                m
            },
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let parsed: SdkConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config.default_registry, parsed.default_registry);
        assert_eq!(config.profile, parsed.profile);
        assert_eq!(
            parsed.toolchain_overrides.get("rustc"),
            Some(&"/usr/local/bin/rustc".to_owned())
        );
    }

    #[test]
    fn sdk_environment_new_is_empty() {
        let env = SdkEnvironment::new();
        assert!(env.available_targets.is_empty());
        assert!(env.toolchain_paths.is_empty());
        assert!(env.warnings.is_empty());
    }

    #[test]
    fn sdk_environment_detect_toolchain_does_not_panic() {
        let env = SdkEnvironment::detect_toolchain();
        assert!(
            !env.warnings.is_empty() || !env.available_targets.is_empty(),
            "environment detection should produce at least targets or warnings"
        );
    }

    #[test]
    fn sdk_environment_list_installed_targets_returns_clone() {
        let mut env = SdkEnvironment::new();
        env.available_targets = vec![SdkTarget::RustLib, SdkTarget::ShellScript];
        let targets = env.list_installed_targets();
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&SdkTarget::RustLib));
    }

    #[test]
    fn sdk_environment_check_dependencies_populates_warnings() {
        let mut env = SdkEnvironment::new();
        env.check_dependencies();
        assert!(
            !env.warnings.is_empty() || !env.available_targets.is_empty(),
            "dependency check should produce notifications"
        );
    }

    #[test]
    fn sdk_commands_all_command_variants_constructable() {
        for command in [
            SdkCommand::Init,
            SdkCommand::Build,
            SdkCommand::Test,
            SdkCommand::Package,
            SdkCommand::Sign,
            SdkCommand::Publish,
            SdkCommand::Verify,
            SdkCommand::Clean,
        ] {
            let cmd = SdkCommands {
                command,
                target: SdkTarget::RustLib,
                args: Vec::new(),
            };
            assert_eq!(cmd.command, command);
        }
    }

    #[test]
    fn sdk_environment_detect_toolchain_sh_binary_found() {
        let mut env = SdkEnvironment::new();
        env.check_dependencies();
        let has_bash = env.available_targets.contains(&SdkTarget::ShellScript);
        if !has_bash {
            assert!(
                env.warnings
                    .iter()
                    .any(|w| w.contains("bash") && w.contains("ShellScript")),
                "missing bash should produce a warning for ShellScript"
            );
        }
    }
}
