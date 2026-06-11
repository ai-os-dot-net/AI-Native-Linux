# AI-OS.NET Rev.6 — Desktop App Confinement Architecture

## Overview

Rev.6 implements **defense-in-depth** desktop application confinement using three
complementary Linux Security Modules (LSMs):

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| 1 | **AppArmor** | Filesystem, network, IPC, and capability MAC |
| 2 | **systemd** | Namespace, seccomp, and privilege hardening |
| 3 | **SELinux** | Renderer type enforcement (X11/Wayland GPU) |

## Directory Layout

```
confine/
├── apparmor/
│   ├── aios-desktop-base        # Base profile (all desktop capsules)
│   ├── aios-browser-firefox     # Firefox capsule (network + DRI)
│   ├── aios-office-libreoffice  # LibreOffice capsule (Documents, no net)
│   ├── aios-media-player        # Media player capsule (audio + GPU)
│   └── aios-terminal            # Terminal capsule (PTY only, most restrictive)
├── systemd/
│   └── aios-app-capsule@.service # Template unit for all desktop capsules
├── selinux/
│   └── aios_renderer.te          # SELinux type enforcement for renderer
└── README.md                     # This file
```

See also: `crates/aios-sandbox/src/confinement_generator.rs` for the Rust
profile generator that produces AppArmor profiles from `SandboxProfile` structs.

## Profile Generation Rules

The confinement generator (`confinement_generator.rs`) applies these rules:

1. **`IsolationKind` → confinement strategy:**
   - `NamespaceLocal` → AppArmor profile on host
   - `ProcessContainer` → AppArmor + systemd unit hardening
   - `VmGuest` → no host profile (VM has its own kernel)
   - `BrowserOriginIsolated` → AppArmor with stricter network sandboxing
   - `NoIsolation` → **rejected** by runtime safety floor

2. **`NetworkPosture` → network rules:**
   - `DenyAll` → `deny network inet, deny network inet6`
   - `LoopbackOnly` → `network inet stream` (loopback only via `@{PROC}`)
   - `HostLimited` / `ExplicitAllowlist` → per-endpoint rules
   - `Full` → `network inet stream, network inet6 stream`

3. **`GpuCapabilityClass` → GPU rules:**
   - `GpuPassiveDisplay` → X11 only, deny DRI
   - `GpuBasic2d` / `GpuRich2d` → DRI render node
   - `GpuFull3d` → DRI card + render nodes
   - `GpuComputeHeavy` → DRI + Vulkan ICD paths

4. **`syscall_allowlist` → AppArmor capability rules:**
   - Maps seccomp filter names to AppArmor `capability` directives
   - Unknown names → default deny

## How to Add a New App Profile

1. Create `apparmor/aios-<app_id>` with `#include <aios-desktop-base>`
2. Define `@{CAPSULE_HOME}=/var/lib/aios/capsules/<app_id>/`
3. Add app-specific binary paths, network rules, and GPU rules
4. Instantiate the systemd unit: `systemctl enable aios-app-capsule@<app_id>.service`
5. Register the profile in `confinement_generator.rs` for automated generation

## Testing Confinement

### AppArmor
```bash
# Validate profile syntax and load
sudo apparmor_parser -r /etc/apparmor.d/aios-desktop-base

# Check profile status
sudo aa-status | grep aios-

# Run a capsule under the profile
aa-exec -p aios-terminal -- /bin/bash -c 'echo $HOME'
```

### systemd
```bash
# Start a capsule
sudo systemctl start aios-app-capsule@terminal.service

# Verify hardening
systemctl show aios-app-capsule@terminal.service |
  grep -E 'NoNewPrivileges|ProtectSystem|PrivateTmp|MemoryDenyWriteExecute'
```

### SELinux
```bash
# Build policy module
make -f /usr/share/selinux/devel/Makefile aios_renderer.pp

# Load module
sudo semodule -i aios_renderer.pp

# Verify context transition
sudo semanage fcontext -a -t aios_renderer_exec_t /usr/lib/aios/bins/aios-renderer
sudo restorecon -v /usr/lib/aios/bins/aios-renderer
```

### Rust Generator Tests
```bash
cargo test -p aios-sandbox -- confinement_generator
```

## Security Properties

- **No cross-capsule IPC**: ptrace denied, PID namespace + `ProtectProc=invisible`
- **No privilege escalation**: `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes`
- **No kernel tampering**: `ProtectKernelTunables=yes`, deny `/proc/sys` write
- **Network-per-capsule**: base denies; only browser profile opens
- **GPU-per-capsule**: DRI access gated by `GpuCapabilityClass`
