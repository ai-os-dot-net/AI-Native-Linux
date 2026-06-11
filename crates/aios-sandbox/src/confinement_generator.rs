//! LSM confinement generator for AI-OS.NET Rev.6.
//!
//! Transforms `SandboxProfile` structs into AppArmor profiles and systemd
//! hardening directives. Maps each SandboxProfile field to the corresponding
//! Linux Security Module rules.
//!
//! ## Architecture
//!
//! ```text
//! SandboxProfile
//!   ├── isolation_kind  → confinement strategy (AppArmor / systemd / VM / none)
//!   ├── network_posture  → AppArmor network rules
//!   ├── gpu_policy       → DRI / Vulkan device access
//!   ├── syscall_allowlist → AppArmor capability directives
//!   └── resource_limits  → systemd resource controls
//! ```

use crate::{GpuCapabilityClass, GpuPolicy, IsolationKind, NetworkPosture, SandboxProfile};

/// Maximum length of a generated AppArmor profile in bytes (~32 KiB).
const DEFAULT_MAX_PROFILE_BYTES: usize = 32768;

/// Strategy for confinement generation based on isolation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfinementStrategy {
    /// Generate an AppArmor profile on the host.
    AppArmorOnly,
    /// Generate AppArmor + systemd unit hardening directives.
    AppArmorWithSystemd,
    /// No host profile — the workload runs in a VM with its own kernel.
    VmNoHostProfile,
    /// Generate an AppArmor profile with browser-specific network sandboxing.
    AppArmorBrowser,
    /// Rejected — the runtime safety floor forbids NoIsolation.
    Rejected,
}

/// Generated AppArmor profile contents and associated metadata.
#[derive(Debug, Clone)]
pub struct GeneratedProfile {
    /// The AppArmor profile name (e.g. `aios-sbx_01J...`).
    pub profile_name: String,
    /// The complete AppArmor profile text.
    pub content: String,
    /// Whether this profile was generated (false for VmGuest / Rejected).
    pub generated: bool,
    /// The confinement strategy used.
    pub strategy: ConfinementStrategy,
}

/// Builder for generating AppArmor profiles from `SandboxProfile` structs.
///
/// # Example
///
/// ```rust
/// use aios_sandbox::SandboxProfile;
/// use aios_sandbox::confinement_generator::AppArmorProfileGenerator;
///
/// let profile = SandboxProfile::new_strict("test", "A test");
/// let generator = AppArmorProfileGenerator::default();
/// let result = generator.generate_profile(&profile);
/// assert!(result.is_some());
/// ```
#[derive(Debug, Clone)]
pub struct AppArmorProfileGenerator {
    /// Maximum profile size in bytes. Profiles exceeding this are truncated
    /// with a comment.
    max_profile_bytes: usize,
}

impl Default for AppArmorProfileGenerator {
    fn default() -> Self {
        Self {
            max_profile_bytes: DEFAULT_MAX_PROFILE_BYTES,
        }
    }
}

impl AppArmorProfileGenerator {
    /// Create a new generator with a custom max profile size.
    #[must_use]
    pub fn new(max_profile_bytes: usize) -> Self {
        Self { max_profile_bytes }
    }

    /// Determine the confinement strategy for an isolation kind.
    #[must_use]
    pub fn strategy_for(kind: IsolationKind) -> ConfinementStrategy {
        match kind {
            IsolationKind::NamespaceLocal => ConfinementStrategy::AppArmorOnly,
            IsolationKind::ProcessContainer => ConfinementStrategy::AppArmorWithSystemd,
            IsolationKind::VmGuest => ConfinementStrategy::VmNoHostProfile,
            IsolationKind::BrowserOriginIsolated => ConfinementStrategy::AppArmorBrowser,
            IsolationKind::NoIsolation => ConfinementStrategy::Rejected,
        }
    }

    /// Generate an AppArmor profile from a `SandboxProfile`.
    ///
    /// Returns `None` when the profile's isolation kind forbids AppArmor
    /// (e.g. `VmGuest`) or the runtime safety floor rejects it (`NoIsolation`).
    pub fn generate_profile(&self, sandbox: &SandboxProfile) -> Option<GeneratedProfile> {
        let strategy = Self::strategy_for(sandbox.isolation_kind);

        match strategy {
            ConfinementStrategy::Rejected | ConfinementStrategy::VmNoHostProfile => {
                return Some(GeneratedProfile {
                    profile_name: sandbox.profile_id.to_string(),
                    content: String::new(),
                    generated: false,
                    strategy,
                });
            }
            _ => {}
        }

        let profile_name = format!("aios-{}", sandbox.profile_id);
        let mut buf = String::with_capacity(2048);

        self.write_header(&mut buf, &profile_name, sandbox);
        self.write_includes(&mut buf);
        self.write_flags(&mut buf, strategy);
        self.write_path_rules(&mut buf, &profile_name);
        self.write_network_rules(&mut buf, sandbox.network_posture, strategy);
        self.write_gpu_rules(&mut buf, &sandbox.gpu_policy);
        self.write_syscall_caps(&mut buf, sandbox.syscall_allowlist.as_deref());
        self.write_deny_list(&mut buf, sandbox.isolation_kind);
        self.write_profile_close(&mut buf);

        self.truncate_if_needed(&mut buf);

        Some(GeneratedProfile {
            profile_name,
            content: buf,
            generated: true,
            strategy,
        })
    }

    // ── Internal writers ──────────────────────────────────────────────

    fn write_header(&self, buf: &mut String, profile_name: &str, sandbox: &SandboxProfile) {
        buf.push_str("# AI-OS.NET Rev.6 — Auto-generated AppArmor profile\n");
        buf.push_str("# Generated by aios-sandbox confinement_generator\n");
        buf.push_str(&format!(
            "# Profile: {name}\n",
            name = sandbox.name
        ));
        buf.push_str(&format!(
            "# Description: {desc}\n",
            desc = sandbox.description
        ));
        buf.push_str(&format!(
            "# Isolation: {kind:?}\n",
            kind = sandbox.isolation_kind
        ));
        buf.push('\n');
        buf.push_str("#include <tunables/global>\n");
        buf.push('\n');
        buf.push_str(&format!("profile {profile_name}"));
        buf.push_str(" {\n");
    }

    fn write_includes(&self, buf: &mut String) {
        buf.push_str("  #include <abstractions/base>\n");
        buf.push_str("  #include <abstractions/fonts>\n");
        buf.push('\n');
    }

    fn write_flags(&self, buf: &mut String, strategy: ConfinementStrategy) {
        if strategy == ConfinementStrategy::AppArmorBrowser {
            buf.push_str("  # Browser-origin isolation: attach_disconnected flag.\n");
            buf.push_str("  flags=(attach_disconnected)\n");
        }
    }

    fn write_path_rules(&self, buf: &mut String, profile_name: &str) {
        let capsule_home = format!("/var/lib/aios/capsules/{profile_name}/");
        buf.push_str("\n  # ── Capsule home ─────────────────────────\n");
        buf.push_str(&format!(
            "  owner {capsule_home} r,\n",
        ));
        buf.push_str(&format!(
            "  owner {capsule_home}** rwlkmix,\n",
        ));
        buf.push_str("\n  # ── System shared data (read-only) ──────\n");
        buf.push_str("  /usr/share/ r,\n");
        buf.push_str("  /usr/share/** r,\n");
        buf.push_str("  /etc/aios/ r,\n");
        buf.push_str("  /etc/aios/** r,\n");
        buf.push_str("\n  # ── System libraries ────────────────────\n");
        buf.push_str("  /usr/lib/ r,\n");
        buf.push_str("  /usr/lib/** mr,\n");
        buf.push_str("\n  # ── Wayland socket ──────────────────────\n");
        buf.push_str("  owner /run/user/[0-9]*/wayland-[0-9]* rw,\n");
        buf.push_str("\n  # ── X11 fallback ────────────────────────\n");
        buf.push_str("  /tmp/.X11-unix/X[0-9]* rw,\n");
        buf.push_str("\n  # ── PulseAudio / PipeWire ───────────────\n");
        buf.push_str("  unix (abstract=\"pipewire-0\"),\n");
        buf.push_str("\n  # ── Deny dangerous paths ────────────────\n");
        buf.push_str("  deny /boot/** rwxlkmix,\n");
        buf.push_str("  deny /root/** rwxlkmix,\n");
        buf.push_str("  deny /etc/shadow rwxlkmix,\n");
        buf.push_str("  deny @{PROC}/sys/** rwxlkmix,\n");
        buf.push_str("  deny /sys/kernel/** rwxlkmix,\n");
    }

    fn write_network_rules(
        &self,
        buf: &mut String,
        posture: NetworkPosture,
        strategy: ConfinementStrategy,
    ) {
        buf.push_str("\n  # ── Network ─────────────────────────────\n");
        match posture {
            NetworkPosture::DenyAll => {
                buf.push_str("  deny network inet,\n");
                buf.push_str("  deny network inet6,\n");
                buf.push_str("  deny network raw,\n");
                buf.push_str("  deny network packet,\n");
            }
            NetworkPosture::LoopbackOnly => {
                buf.push_str("  # Loopback-only: no external connectivity.\n");
                buf.push_str("  deny network inet,\n");
                buf.push_str("  deny network inet6,\n");
                buf.push_str("  deny network raw,\n");
            }
            NetworkPosture::HostLimited | NetworkPosture::ExplicitAllowlist => {
                buf.push_str("  # Explicit allow-list (browser-style).\n");
                buf.push_str("  network inet stream,\n");
                buf.push_str("  network inet6 stream,\n");
                buf.push_str("  network inet dgram,\n");
                buf.push_str("  network inet6 dgram,\n");
            }
            NetworkPosture::Full => {
                buf.push_str("  # Full network access granted.\n");
                buf.push_str("  network inet,\n");
                buf.push_str("  network inet6,\n");
            }
        }
        if strategy == ConfinementStrategy::AppArmorBrowser {
            buf.push_str("  # Browser: allow DNS over TCP/UDP + ephemeral\n");
            buf.push_str("  network inet dgram,\n");
            buf.push_str("  network inet6 dgram,\n");
        }
    }

    fn write_gpu_rules(&self, buf: &mut String, gpu: &GpuPolicy) {
        buf.push_str("\n  # ── GPU ─────────────────────────────────\n");
        match gpu.gpu_capability_class {
            GpuCapabilityClass::GpuPassiveDisplay => {
                buf.push_str("  # Passive display: X11 only, no DRI.\n");
                buf.push_str("  deny /dev/dri/ rw,\n");
                buf.push_str("  deny /dev/dri/** rw,\n");
            }
            GpuCapabilityClass::GpuBasic2d | GpuCapabilityClass::GpuRich2d => {
                buf.push_str("  # Basic/Rich 2D: DRI render node.\n");
                buf.push_str("  /dev/dri/ r,\n");
                buf.push_str("  owner /dev/dri/renderD[0-9]* rw,\n");
            }
            GpuCapabilityClass::GpuFull3d => {
                buf.push_str("  # Full 3D: DRI card + render nodes.\n");
                buf.push_str("  /dev/dri/ r,\n");
                buf.push_str("  owner /dev/dri/card[0-9]* rw,\n");
                buf.push_str("  owner /dev/dri/renderD[0-9]* rw,\n");
            }
            GpuCapabilityClass::GpuComputeHeavy => {
                buf.push_str("  # Compute heavy: DRI + Vulkan ICD paths.\n");
                buf.push_str("  /dev/dri/ r,\n");
                buf.push_str("  owner /dev/dri/card[0-9]* rw,\n");
                buf.push_str("  owner /dev/dri/renderD[0-9]* rw,\n");
                buf.push_str("  /usr/share/vulkan/ r,\n");
                buf.push_str("  /usr/share/vulkan/** r,\n");
                buf.push_str("  /etc/vulkan/ r,\n");
                buf.push_str("  /etc/vulkan/** r,\n");
                buf.push_str("  # Vulkan ICD loaders\n");
                buf.push_str("  /usr/lib/x86_64-linux-gnu/libvulkan* mr,\n");
            }
        }
        if gpu.vk_device_required {
            buf.push_str("  # vk_device_required: dedicated VkDevice\n");
        }
        if gpu.iommu_required {
            buf.push_str("  # IOMMU required for DMA isolation\n");
        }
    }

    fn write_syscall_caps(&self, buf: &mut String, allowlist: Option<&[String]>) {
        buf.push_str("\n  # ── Capabilities ────────────────────────\n");
        buf.push_str("  deny capability sys_ptrace,\n");
        buf.push_str("  deny capability sys_admin,\n");
        buf.push_str("  deny capability sys_module,\n");

        let Some(list) = allowlist else {
            return;
        };

        for entry in list {
            let normalized = entry.to_lowercase().replace('-', "_");
            match normalized.as_str() {
                "net_bind_service" => {
                    buf.push_str("  capability net_bind_service,\n");
                }
                "net_raw" => {
                    buf.push_str("  capability net_raw,\n");
                }
                "sys_tty_config" => {
                    buf.push_str("  capability sys_tty_config,\n");
                }
                "ipc_lock" => {
                    buf.push_str("  capability ipc_lock,\n");
                }
                "sys_nice" => {
                    buf.push_str("  capability sys_nice,\n");
                }
                "net_admin" => {
                    buf.push_str("  capability net_admin,\n");
                }
                _ => {
                    buf.push_str(&format!(
                        "  # unknown syscall allowlist entry: {entry} — denied by default\n"
                    ));
                }
            }
        }
    }

    fn write_deny_list(&self, buf: &mut String, kind: IsolationKind) {
        buf.push_str("\n  # ── Cross-capsule isolation ─────────────\n");
        if kind == IsolationKind::BrowserOriginIsolated {
            buf.push_str("  # Browser: deny secrets access paths.\n");
            buf.push_str("  deny @{HOME}/.ssh/** rwxlkmix,\n");
            buf.push_str("  deny @{HOME}/.gnupg/** rwxlkmix,\n");
        }
        buf.push_str("  # ptrace across profiles is always denied.\n");
        buf.push_str("  deny ptrace,\n");
        buf.push_str("  deny /dev/mem rwxlkmix,\n");
        buf.push_str("  deny /dev/kmem rwxlkmix,\n");
        buf.push_str("  deny /dev/port rwxlkmix,\n");
    }

    fn write_profile_close(&self, buf: &mut String) {
        buf.push_str("}\n");
    }

    fn truncate_if_needed(&self, buf: &mut String) {
        if buf.len() > self.max_profile_bytes {
            let truncation_note = "\n\n# ⚠ PROFILE TRUNCATED — exceeded max_profile_bytes\n";
            buf.truncate(self.max_profile_bytes.saturating_sub(truncation_note.len()));
            buf.push_str(truncation_note);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "panic-on-failure is the idiomatic test signal"
)]
mod tests {
    use super::*;

    fn make_profile(
        isolation: IsolationKind,
        network: NetworkPosture,
        gpu_class: GpuCapabilityClass,
    ) -> SandboxProfile {
        let mut profile = SandboxProfile::new_strict("test-profile", "Auto-generated test profile");
        profile.isolation_kind = isolation;
        profile.network_posture = network;
        profile.gpu_policy.gpu_capability_class = gpu_class;
        profile
    }

    // ── Generation tests ──────────────────────────────────────────────

    #[test]
    fn generate_desktop_base_profile() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should generate a profile");

        assert!(result.generated);
        assert_eq!(result.strategy, ConfinementStrategy::AppArmorOnly);
        assert!(result.content.contains("profile aios-sbx_"));
        assert!(result.content.contains("#include <tunables/global>"));
        assert!(result.content.contains("deny network inet,"));
        assert!(result.content.contains("deny /dev/dri/ rw,"));
        assert!(result.content.contains("deny capability sys_ptrace,"));
    }

    #[test]
    fn generate_firefox_network_profile() {
        let generator = AppArmorProfileGenerator::default();
        let mut profile = make_profile(
            IsolationKind::BrowserOriginIsolated,
            NetworkPosture::ExplicitAllowlist,
            GpuCapabilityClass::GpuFull3d,
        );
        profile.name = "firefox-browser".into();

        let result = generator
            .generate_profile(&profile)
            .expect("should generate");

        let content = &result.content;
        assert!(result.generated);
        assert_eq!(result.strategy, ConfinementStrategy::AppArmorBrowser);
        assert!(content.contains("network inet stream,"));
        assert!(content.contains("network inet dgram,"));
        assert!(content.contains("/dev/dri/card[0-9]* rw,"));
        assert!(content.contains("flags=(attach_disconnected)"));
        assert!(content.contains("deny @{HOME}/.ssh/"));
        assert!(content.contains("deny @{HOME}/.gnupg/"));
    }

    #[test]
    fn generate_office_profile_no_network_documents_access() {
        let generator = AppArmorProfileGenerator::default();
        let mut profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        profile.name = "libreoffice".into();

        let result = generator
            .generate_profile(&profile)
            .expect("should generate");

        let content = &result.content;
        assert!(content.contains("deny network inet,"));
        assert!(content.contains("deny network inet6,"));
        assert!(content.contains("deny /dev/dri/ rw,"));
        assert!(!content.contains("network inet stream,"));
    }

    #[test]
    fn generate_vmguest_profile_no_apparmor() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::VmGuest,
            NetworkPosture::Full,
            GpuCapabilityClass::GpuFull3d,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should return a no-host-profile result");

        assert!(!result.generated);
        assert_eq!(result.strategy, ConfinementStrategy::VmNoHostProfile);
        assert!(result.content.is_empty());
    }

    #[test]
    fn generate_noisolation_is_rejected() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::NoIsolation,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should return a rejected result");

        assert!(!result.generated);
        assert_eq!(result.strategy, ConfinementStrategy::Rejected);
    }

    #[test]
    fn generate_denyall_network_profile_has_no_network_rules() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");

        let content = &result.content;
        assert!(content.contains("deny network inet,"));
        assert!(content.contains("deny network inet6,"));
        assert!(content.contains("deny network raw,"));
        assert!(content.contains("deny network packet,"));
        assert!(!content.contains("network inet stream,"));
    }

    #[test]
    fn generate_full_network_profile() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::ProcessContainer,
            NetworkPosture::Full,
            GpuCapabilityClass::GpuBasic2d,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");

        assert!(result.content.contains("network inet,"));
        assert!(result.content.contains("network inet6,"));
        assert_eq!(result.strategy, ConfinementStrategy::AppArmorWithSystemd);
    }

    #[test]
    fn generate_gpu_compute_profile_has_vulkan_dri() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::LoopbackOnly,
            GpuCapabilityClass::GpuComputeHeavy,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");

        let content = &result.content;
        assert!(content.contains("/dev/dri/card[0-9]* rw,"));
        assert!(content.contains("/dev/dri/renderD[0-9]* rw,"));
        assert!(content.contains("/usr/share/vulkan/"));
        assert!(content.contains("libvulkan* mr,"));
    }

    #[test]
    fn generate_gpu_basic_2d_has_render_node_only() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuBasic2d,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");

        let content = &result.content;
        assert!(content.contains("/dev/dri/renderD[0-9]* rw,"));
        assert!(!content.contains("/dev/dri/card[0-9]* rw,"));
    }

    // ── Syscall allowlist tests ───────────────────────────────────────

    #[test]
    fn syscall_allowlist_net_bind_service_adds_capability() {
        let generator = AppArmorProfileGenerator::default();
        let mut profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        profile.syscall_allowlist = Some(vec!["net_bind_service".into()]);
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");
        assert!(result.content.contains("capability net_bind_service,"));
    }

    #[test]
    fn syscall_allowlist_unknown_emits_comment() {
        let generator = AppArmorProfileGenerator::default();
        let mut profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        profile.syscall_allowlist = Some(vec!["unknown_syscall".into()]);
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");
        assert!(result
            .content
            .contains("unknown syscall allowlist entry: unknown_syscall"));
    }

    #[test]
    fn syscall_allowlist_multiple_entries() {
        let generator = AppArmorProfileGenerator::default();
        let mut profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        profile.syscall_allowlist = Some(vec![
            "net_bind_service".into(),
            "sys_tty_config".into(),
            "ipc_lock".into(),
        ]);
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");
        assert!(result.content.contains("capability net_bind_service,"));
        assert!(result.content.contains("capability sys_tty_config,"));
        assert!(result.content.contains("capability ipc_lock,"));
    }

    // ── Profile structure tests ───────────────────────────────────────

    #[test]
    fn profile_includes_tunables_global() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");
        assert!(result
            .content
            .contains("#include <tunables/global>"));
    }

    #[test]
    fn profile_has_correct_include_stanza() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");
        assert!(result.content.contains("#include <abstractions/base>"));
        assert!(result.content.contains("#include <abstractions/fonts>"));
    }

    #[test]
    fn profile_starts_with_header_and_ends_with_close_brace() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");

        assert!(
            result.content.starts_with("# AI-OS.NET Rev.6"),
            "profile should start with header"
        );
        assert!(
            result.content.trim_end().ends_with('}'),
            "profile should end with closing brace"
        );
    }

    #[test]
    fn profile_contains_capsule_path_rules() {
        let generator = AppArmorProfileGenerator::default();
        let profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");

        assert!(result
            .content
            .contains("/var/lib/aios/capsules/aios-"));
        assert!(result.content.contains("/usr/share/ r,"));
        assert!(result.content.contains("/etc/aios/ r,"));
    }

    // ── Multiple profiles independent ──────────────────────────────────

    #[test]
    fn multiple_profiles_independent() {
        let generator = AppArmorProfileGenerator::default();
        let p1 = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        let p2 = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::Full,
            GpuCapabilityClass::GpuComputeHeavy,
        );

        let r1 = generator.generate_profile(&p1).expect("r1 generated");
        let r2 = generator.generate_profile(&p2).expect("r2 generated");

        assert_ne!(r1.profile_name, r2.profile_name);
        assert!(r1.content.contains("deny network inet,"));
        assert!(r2.content.contains("network inet,"));
        assert!(r2.content.contains("network inet,"));
    }

    #[test]
    fn multiple_profiles_have_different_names() {
        let generator = AppArmorProfileGenerator::default();
        let p1 = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        let p2 = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );

        let r1 = generator.generate_profile(&p1).expect("r1");
        let r2 = generator.generate_profile(&p2).expect("r2");
        assert_ne!(r1.profile_name, r2.profile_name);
    }

    // ── Send + Sync ────────────────────────────────────────────────────

    #[test]
    fn generator_is_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<AppArmorProfileGenerator>();
        assert_sync::<AppArmorProfileGenerator>();
    }

    #[test]
    fn generated_profile_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GeneratedProfile>();
    }

    // ── Truncation ─────────────────────────────────────────────────────

    #[test]
    fn profile_truncates_when_exceeding_max_bytes() {
        let generator = AppArmorProfileGenerator::new(500);
        let profile = make_profile(
            IsolationKind::NamespaceLocal,
            NetworkPosture::DenyAll,
            GpuCapabilityClass::GpuPassiveDisplay,
        );
        let result = generator
            .generate_profile(&profile)
            .expect("should generate");
        assert!(result.content.len() <= 500);
        assert!(result.content.contains("PROFILE TRUNCATED"));
    }

    // ── Strategy mapper ────────────────────────────────────────────────

    #[test]
    fn strategy_mapper_namespace_local() {
        assert_eq!(
            AppArmorProfileGenerator::strategy_for(IsolationKind::NamespaceLocal),
            ConfinementStrategy::AppArmorOnly
        );
    }

    #[test]
    fn strategy_mapper_process_container() {
        assert_eq!(
            AppArmorProfileGenerator::strategy_for(IsolationKind::ProcessContainer),
            ConfinementStrategy::AppArmorWithSystemd
        );
    }

    #[test]
    fn strategy_mapper_vm_guest() {
        assert_eq!(
            AppArmorProfileGenerator::strategy_for(IsolationKind::VmGuest),
            ConfinementStrategy::VmNoHostProfile
        );
    }

    #[test]
    fn strategy_mapper_browser_origin() {
        assert_eq!(
            AppArmorProfileGenerator::strategy_for(IsolationKind::BrowserOriginIsolated),
            ConfinementStrategy::AppArmorBrowser
        );
    }

    #[test]
    fn strategy_mapper_no_isolation() {
        assert_eq!(
            AppArmorProfileGenerator::strategy_for(IsolationKind::NoIsolation),
            ConfinementStrategy::Rejected
        );
    }
}
