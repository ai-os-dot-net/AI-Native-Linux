# AI-OS.NET Distribution Roadmap - Revision 12 and Revision 13

## Purpose

This file records the distribution implementation split after Revision 11.

- Revision 12 turns AI-OS.NET into a bootable, installable, testable Linux
  distribution baseline.
- Revision 13 turns that baseline into an enterprise Linux distribution with
  long-term lifecycle, compliance, hardening, signed supply chain, and support
  gates.

Detailed contracts:

- [Revision 12 distribution specification](REV12-DISTRIBUTION-SPEC.md)
- [Revision 13 enterprise specification](REV13-ENTERPRISE-SPEC.md)

Revision 13 depends on Revision 12. Enterprise work must not be used to hide
missing boot, install, update, or rollback proof in Revision 12.

## Revision 12 - Full Linux Distribution Baseline

Goal: produce a real AI-OS.NET Linux distribution artifact that can boot,
install, update, roll back, and pass automated service health checks.

### R12.1 Bootable live/install ISO

- Produce a real bootable live/install ISO.
- Use `squashfs` for the live root filesystem.
- Use an overlay root for live-session writes.
- Use an AIOS initramfs path that mounts the live media and switches root.
- Add a QEMU boot smoke test for the produced ISO.
- Gate promotion on QEMU proof, not only file-structure checks.

### R12.2 Installer baseline

- Implement and validate disk selection.
- Implement partitioning for EFI, root, recovery, and rollback storage.
- Support LUKS root encryption.
- Support TPM enrollment for sealed secrets where hardware is present.
- Support Secure Boot enrollment or controlled operator handoff.
- Install a recovery partition.
- Install rollback metadata and a previous-deployment fallback path.

### R12.3 Systemd and binary contract

- Ensure every enabled systemd unit points to a binary that is actually
  produced and staged into the rootfs.
- Fail the ISO build if a required `ExecStart` binary is missing.
- Keep optional inference services outside the default `aios.target`.
- Keep service names, binary names, and installed paths in one validated
  contract.

### R12.4 Signed repository, updates, rollback, SBOM, provenance

- Produce a signed package/artifact repository.
- Sign update metadata and package payloads.
- Generate SBOM artifacts for release outputs.
- Generate provenance receipts for build outputs.
- Implement staged update verification before switch.
- Implement rollback to the last known-good deployment.

### R12.5 Kernel, module, and firmware pipeline

- Define supported kernel source modes: host kernel, packaged kernel, custom
  kernel.
- Stage kernel modules and firmware into the image.
- Validate kernel, initramfs, module, and firmware presence during ISO build.
- Prepare signing hooks for kernel, initramfs, and modules.

### R12.6 Linux security baseline

- Add SELinux policy baseline and move toward enforcing mode.
- Add `dm-verity` rootfs verification path.
- Add IMA/EVM policy skeleton for runtime integrity.
- Prepare a signed boot chain from bootloader to kernel, initramfs, and rootfs.

### R12.7 Automated distribution tests

- QEMU live boot test.
- QEMU installer test against an empty virtual disk.
- Service health test after boot.
- Update test.
- Rollback test.
- Negative tests for missing `squashfs`, invalid signatures, missing service
  binaries, and failed rootfs verification.

### Revision 12 exit criteria

- A release ISO boots in QEMU.
- The installer installs to a blank virtual disk.
- The installed system boots in QEMU.
- Core AIOS services reach healthy state.
- An update can be staged and applied.
- A rollback can restore the previous deployment.
- Build output includes signatures, SBOM, and provenance metadata.

## Revision 13 - Enterprise Linux Distribution

Goal: take the Revision 12 distribution baseline and make it enterprise-grade:
stable base, reproducible builds, signed lifecycle, compliance evidence,
security hardening, and operator support model.

### R13.1 Base and lifecycle decision

- Lock the base family: openSUSE Leap 16.x.
- Lock supported architectures: `x86_64` first, `aarch64` after CI proof.
- Define LTS support window: 24 months per minor release.
- Define update cadence and security fix SLA: critical 7 days, high 30 days.
- Define supported upgrade paths between Leap 16.x minors; major upgrades need
  a separate gate.

### R13.2 Hermetic and reproducible build

- Replace host-clone build assumptions with hermetic build inputs.
- Pin all build dependencies.
- Produce reproducible build receipts.
- Make local developer builds and CI builds use the same dependency graph.
- Preserve provenance for every binary, package, kernel, policy bundle, and ISO.

### R13.3 Daemon architecture and systemd finalization

- Choose final daemon model: separate binaries or one `aios-system` supervisor.
- Freeze service names and service responsibilities.
- Apply systemd hardening profiles per service.
- Add service-level health, restart, dependency, and recovery behavior.
- Block release if service hardening score is below the enterprise threshold.

### R13.4 Secure Boot, TPM measured boot, and integrity enforcement

- Sign bootloader, kernel, initramfs, and kernel modules.
- Record TPM PCR measurements for boot chain evidence.
- Enforce SELinux in enterprise profiles.
- Enforce IMA/EVM appraisal where supported.
- Enforce `dm-verity` or equivalent rootfs integrity.
- Record boot integrity state in evidence logs.

### R13.5 Signed repository and atomic update model

- Operate a signed enterprise repository.
- Separate release, security, staging, and recovery channels.
- Require signature and policy verification before installation.
- Support atomic update activation.
- Support automatic rollback on boot or service-health failure.
- Keep retention rules for old deployments and recovery artifacts.

### R13.6 Installer, recovery, and first-boot operator flow

- Provide enterprise installer mode.
- Support unattended install profile with signed answer file.
- Support manual operator install with guarded destructive steps.
- Enroll host identity during first boot.
- Enroll fleet or organization identity where configured.
- Provide recovery flow for rollback, key recovery, policy repair, and update
  channel repair.

### R13.7 CI gates

- QEMU live boot gate.
- QEMU install gate.
- Installed-system boot gate.
- Service health gate.
- Update gate.
- Rollback gate.
- Secure Boot/signature verification gate where CI firmware supports it.
- Compliance baseline gate.

### R13.8 Compliance, audit, and support lifecycle

- Define CIS baseline.
- Define STIG-aligned baseline.
- Map controls to AIOS policy, systemd hardening, SELinux policy, kernel
  config, and evidence records.
- Export audit evidence in operator-readable and machine-readable forms.
- Define CVE intake, triage, patch, release, and advisory process.
- Define support lifecycle and end-of-life policy.

### Revision 13 exit criteria

- Enterprise profile installs and boots with signed artifacts.
- SELinux is enforcing for enterprise profile.
- Update and rollback are atomic and tested.
- SBOM, provenance, signatures, and audit exports are generated for release
  artifacts.
- CI blocks release on boot, install, service health, update, rollback, or
  compliance failure.
- CVE and support lifecycle process is documented and operational.
