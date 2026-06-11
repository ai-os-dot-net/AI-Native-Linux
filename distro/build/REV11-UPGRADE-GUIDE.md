# AI-OS.NET ISO Build System — Rev.4 → Rev.11 Upgrade Guide

## Overview

This document catalogs every change required to upgrade the AI-OS.NET ISO build
system from Revision 4 to Revision 11.  It covers build scripts, systemd units,
filesystem layout, loader configuration, first-boot phases, and CI pipeline.

---

## 1. Build Script Version Bump

| File | Rev.4 | Rev.11 |
|------|-------|--------|
| `distro/build/build-aios-iso.sh:1-29` | `# Revision 4` (header) | `# Revision 11` (header) |
| `distro/build/build-aios-iso.sh:75` | `Revision 4` (banner) | `Revision 11` (banner) |
| `distro/build/build-aios-iso.sh:392` | `# Revision 4` (config) | `# Revision 11` (config) |
| `distro/build/build-aios-iso.sh:811` | `VOLID="AIOS_REV4"` | `VOLID="AIOS_REV11"` |
| `distro/build/Makefile:3,28-29,194` | `Revision 4`, `rev4` | `Revision 11`, `rev11` |
| `distro/build/Dockerfile.ci:3-4` | `aios-ci:rev4` | `aios-ci:rev11` |
| `distro/build/build-deps-check.sh:5,187` | `Revision 4` | `Revision 11` |
| `distro/build/cross-compile.sh:5,89` | `Revision 4` | `Revision 11` |
| `distro/build/ci-build-all.sh:3,12,23` | `Revision 4`, `rev4` | `Revision 11`, `rev11` |

### ISO output naming

```
Rev.4   →  aios-rev4-YYYYMMDD-x86_64.iso
Rev.11  →  aios-rev11-YYYYMMDD-x86_64.iso

Rev.4   →  aios-rev4-YYYYMMDD-aarch64.iso
Rev.11  →  aios-rev11-YYYYMMDD-aarch64.iso
```

---

## 2. New Systemd Unit Files (6 added)

These units are not present in the Rev.4 rootfs-layout.  Each must be placed
under `distro/systemd/` and copied into the rootfs during ISO assembly.

| Unit | Description | Binary |
|------|-------------|--------|
| `aios-fleet.service` | Fleet coordinator for multi-node deployments | `/usr/lib/aios/aios-fleet` |
| `aios-autonomous.service` | Autonomous orchestrator (monitor mode) | `/usr/lib/aios/aios-autonomous` |
| `aios-marketplace.service` | Marketplace indexer with auto-sync | `/usr/lib/aios/aios-marketplace` |
| `aios-container.service` | Container daemon (podman-rootless default) | `/usr/lib/aios/aios-container` |
| `aios-terminal.service` | Terminal daemon (lx mode default) | `/usr/lib/aios/aios-terminal` |
| `aios-cognitive-core.service` | Cognitive model backend core | `/usr/lib/aios/aios-cognitive-core` |

### Rev.4 systemd units (retained)

| Unit | Status |
|------|--------|
| `aios-capability-runtime.service` | Retained |
| `aios-policy-kernel.service` | Retained |
| `aios-evidence-log.service` | Retained |
| `aios-first-boot.service` | Retained |
| `aios-fs-daemon.service` | Retained |
| `aios-sandbox-composer.service` | Retained |
| `aios-hardware-daemon.service` | Retained |
| `aios-network-daemon.service` | Retained |
| `aios-recovery-watchdog.service` | Retained |
| `aios-sgr-daemon.service` | Retained |
| `aios-vault-broker.service` | Retained |
| `aios-vllm.service` | Retained |
| `aios-ollama.service` | Retained |

---

## 3. Rootfs Layout — New Directory Subtrees

The root filesystem layout (`distro/aios-boot/rootfs-layout.txt`) must be updated
from `Revision 4` to `Revision 11` in the header lines (1–10) and the following
new directory subtrees must be added under `/var/lib/aios/` and `/etc/aios/`:

```
var/lib/aios/
  ├── fleet/          [D]  Fleet coordination cache & state
  ├── autonomous/     [D]  Autonomous orchestrator state
  ├── marketplace/    [D]  Marketplace index & metadata
  ├── container/      [D]  Container engine runtime state
  └── terminal/       [D]  Terminal daemon state & history

etc/aios/
  └── autonomous/     [D]  Autonomous policy & configuration
```

Corresponding directories must be created in `build-aios-iso.sh` Step 2
(rootfs directory tree) and Step 5 (configuration).

---

## 4. First-Boot Script — New Phases (11–15)

The first-boot script (`distro/first-boot/aios-first-boot.sh`) currently
implements phases 1–10.  For Revision 11 the following phases must be added:

| Phase | Name | Description |
|-------|------|-------------|
| 11 | Fleet Enrollment | Register host with fleet coordinator |
| 12 | Autonomous Policy | Deploy autonomous orchestration policy |
| 13 | Marketplace Sync | Initial marketplace index pull |
| 14 | Container Engine | Initialize container runtime (podman-rootless) |
| 15 | Terminal Setup | Configure terminal daemon & user defaults |

Variables already declared in the script header (lines 35–38):
```bash
FLEET_DIR="${AIOS_VAR}/fleet"
AUTONOMOUS_DIR="${AIOS_ETC}/autonomous"
MARKETPLACE_DIR="${AIOS_VAR}/marketplace"
CONTAINER_DIR="${AIOS_VAR}/container"
```

---

## 5. Loader Entry

### Required change

The systemd-boot loader entry (`distro/aios-boot/loader-entry.conf`):

```
-title   AI-OS.NET (Revision 4)
+title   AI-OS.NET (Revision 11)
```

Already done: the current file uses `Revision 11` (line 8).

### Build script loader entries

In `distro/build/build-aios-iso.sh` (lines 781 and 807-811):

```
-title   AI-OS.NET Live (Revision 4)
+title   AI-OS.NET Live (Revision 11)

-VOLID="AIOS_REV4"
+VOLID="AIOS_REV11"
```

---

## 6. OS Release

`build-aios-iso.sh` Step 5 (line 455):

```
-VERSION="${AIOS_VERSION} (Revision 4)"
+VERSION="${AIOS_VERSION} (Revision 11)"
```

Already done in the current build script.

---

## 7. CI Pipeline

| File | Change |
|------|--------|
| `ci-build-all.sh:12` | `aios-rev4` → `aios-rev11` |
| `ci-build-all.sh:23` | `Revision 4` → `Revision 11` |
| `Dockerfile.ci:3-4` | `aios-ci:rev4` → `aios-ci:rev11` |
| `Makefile:28-29` | `aios-rev4-*.iso` → `aios-rev11-*.iso` |
| `Makefile:194` | `Revision 4` → `Revision 11` |

---

## 8. Acceptance Criteria Checklist

- [ ] All build scripts reference `Revision 11` (not `Revision 4`)
- [ ] ISO output filename uses `aios-rev11-*`
- [ ] ISO volume label is `AIOS_REV11`
- [ ] All 6 new systemd unit files exist in `distro/systemd/`
- [ ] Rootfs layout document references `Revision 11` and new directories
- [ ] First-boot script implements phases 11–15
- [ ] Loader entry title says `Revision 11`
- [ ] CI Docker image tag uses `rev11`
- [ ] Variable `FLEET_DIR`, `AUTONOMOUS_DIR`, `MARKETPLACE_DIR`, `CONTAINER_DIR` exist in first-boot script
- [ ] Makefile targets produce `rev11`-named ISOs
