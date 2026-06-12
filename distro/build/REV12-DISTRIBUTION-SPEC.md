# AI-OS.NET Revision 12 - Full Linux Distribution Specification

| Field | Value |
|-------|-------|
| Status | `CONTRACT` |
| Scope | Bootable, installable, updateable AI-OS.NET Linux distribution baseline |
| Predecessor | Revision 11 ISO build system |
| Success gate | QEMU-proven live boot, install, service health, update, and rollback |

## 1. Purpose

Revision 12 turns the current AI-OS.NET build output into a real Linux
distribution artifact.

The release is not accepted because an ISO file exists. It is accepted only when
the artifact can boot in QEMU, install to an empty disk, boot after install,
start the required AIOS services, apply an update, and roll back to the previous
deployment.

## 2. Non-goals

- No enterprise LTS promise.
- No formal compliance claim.
- No production support lifecycle.
- No claim of Secure Boot certification unless the signed boot path is actually
  tested.
- No host-specific build assumptions are allowed to count as release evidence.

Enterprise lifecycle, compliance, and support are Revision 13 scope.

## 3. Release artifacts

Every Revision 12 release candidate must produce these artifacts:

| Artifact | Required | Description |
|----------|----------|-------------|
| Live/install ISO | yes | Bootable ISO containing live rootfs, installer, kernel, initramfs, bootloader |
| Rootfs squashfs | yes | Compressed live root filesystem |
| Initramfs | yes | AIOS initramfs that locates live media and switches root |
| Kernel image | yes | Kernel used by the ISO boot path |
| Module tree | yes | Kernel modules matching the staged kernel |
| Firmware tree | yes | Firmware required by the supported hardware profile |
| Manifest | yes | Machine-readable list of release files, hashes, sizes, versions |
| SBOM | yes | SPDX or CycloneDX release SBOM |
| Provenance receipt | yes | Build inputs, git revision, tool versions, builder identity |
| Signature bundle | yes | Detached signatures for release metadata and payloads |

## 4. R12.1 Bootable live/install ISO

### Contract

The ISO must boot through the selected bootloader into the AIOS initramfs. The
initramfs must locate the live media, mount `live/aios.squashfs`, create a
writable overlay, and switch root into the live system.

### Required ISO layout

```text
/boot/
  grub/ or loader/
/live/
  aios.squashfs
  vmlinuz
  initrd.img
/aios/
  manifest.json
  sbom.*
  provenance.*
  signatures/
```

### Required boot evidence

- Serial log from QEMU.
- Positive marker from initramfs start.
- Positive marker from squashfs mount.
- Positive marker from overlay mount.
- Positive marker from switch-root or reached systemd.
- Failure marker scan for kernel panic, missing live media, failed mount, or
  rescue-shell drop.

### Acceptance tests

- `qemu-system-x86_64` live boot smoke test.
- BIOS boot path test.
- UEFI boot path test when OVMF is available.
- Negative test with missing `live/aios.squashfs`.

## 5. R12.2 Installer baseline

### Contract

The installer must install AI-OS.NET from the live ISO onto an empty virtual
disk without relying on manual host-side filesystem copying.

### Required install flow

1. Detect boot mode and target disks.
2. Require explicit target disk selection.
3. Partition the target disk.
4. Format EFI, root, recovery, and rollback storage.
5. Optionally create LUKS root encryption.
6. Copy or deploy the release rootfs.
7. Install bootloader entries.
8. Generate `fstab`, `crypttab`, machine identity seed, and first-boot marker.
9. Install recovery assets.
10. Reboot into the installed system.

### Required disk layout

| Partition | Required | Purpose |
|-----------|----------|---------|
| EFI system partition | yes | UEFI boot artifacts |
| Root filesystem | yes | Installed AIOS root |
| Recovery partition | yes | Recovery kernel/initramfs/tools or recovery image |
| Rollback storage | yes | Previous deployment or snapshot metadata |
| Data partition | optional | Persistent operator/user data |

### Security requirements

- LUKS install mode must never print secrets.
- TPM enrollment must be optional and hardware-gated.
- Secure Boot enrollment must be explicit and operator-visible.
- Destructive partitioning must require a clear confirmation path.

### Acceptance tests

- QEMU install to a blank virtual disk.
- Installed-system boot from that virtual disk.
- LUKS install path in CI where supported.
- Negative test for invalid target disk.
- Negative test for missing rootfs payload.

## 6. R12.3 Systemd and binary contract

### Contract

Enabled systemd units must reference binaries that exist in the produced rootfs.
The build must fail before ISO creation if a required binary is missing.

### Rules

- Required services are enabled through `aios.target`.
- Optional inference services must not block the base boot.
- `ExecStart` paths must be absolute.
- Service names, binary paths, and staged artifacts must be validated together.
- A binary rename is not accepted unless the matching unit contract is updated.

### Acceptance tests

- Parse all staged systemd units.
- Extract every `ExecStart` path.
- Verify required binaries exist in the rootfs.
- Verify optional services are not required by `aios.target`.
- Boot-time service health check after QEMU boot.

## 7. R12.4 Signed repository, updates, rollback, SBOM, provenance

### Contract

Revision 12 must produce signed update metadata and enough release metadata to
prove what was built and what is safe to install.

### Repository requirements

- Release metadata is signed.
- Payload hashes are recorded.
- Packages or artifacts carry version, architecture, channel, and dependency
  metadata.
- Update clients verify metadata before payload download and payload hash before
  staging.
- Unsigned or hash-mismatched updates are rejected.

### Rollback requirements

- The current deployment is not destroyed before the next deployment is proven.
- The previous deployment remains bootable until the new one passes health.
- Failed boot or failed service-health must trigger rollback.
- Rollback must emit evidence.

### SBOM and provenance requirements

- SBOM covers Rust crates, packaged OS dependencies, kernel, modules, firmware,
  and installer scripts where tooling can enumerate them.
- Provenance records source commit, builder, build time, build inputs, tool
  versions, output hashes, and signature identity.

### Acceptance tests

- Signature verification success path.
- Signature verification failure path.
- Update stage and activate path.
- Rollback path after forced health failure.
- SBOM and provenance file existence plus schema sanity.

## 8. R12.5 Kernel, module, and firmware pipeline

### Contract

The ISO and installed system must carry a coherent kernel set: kernel image,
matching module tree, firmware tree, and initramfs.

### Kernel source modes

| Mode | Description | Release use |
|------|-------------|-------------|
| Host kernel | Uses the builder host kernel | developer only unless pinned |
| Packaged kernel | Uses a known package source | preferred Rev12 release mode |
| Custom kernel | Uses AIOS-built kernel config | allowed after CI boot proof |

### Requirements

- Kernel version must match the staged module directory.
- Initramfs must include drivers needed for live media and rootfs mount.
- Firmware staging must be explicit.
- Kernel, initramfs, modules, and firmware must be included in the manifest.
- Signing hooks must exist even if release signing is operator-provided.

### Acceptance tests

- Kernel image exists.
- Initramfs exists.
- Module directory for the kernel exists.
- Firmware directory exists or is explicitly marked empty for the target profile.
- QEMU boot uses the staged kernel/initramfs, not a host fallback.

## 9. R12.6 Linux security baseline

### Contract

Revision 12 establishes the security baseline needed for a real distribution.
Full enterprise enforcement is Revision 13, but Rev12 must create the plumbing.

### Requirements

- SELinux policy baseline exists.
- SELinux mode is recorded in release metadata and runtime evidence.
- `dm-verity` rootfs verification path is defined.
- IMA/EVM policy skeleton exists for runtime integrity.
- Boot chain signing hooks exist for bootloader, kernel, initramfs, modules, and
  rootfs metadata.
- Recovery mode can repair policy and rollback state.

### Acceptance tests

- SELinux policy files are staged.
- Security profile is visible in `/etc/aios`.
- `dm-verity` metadata generation path exists.
- IMA/EVM policy files are staged or explicitly disabled by profile.
- Unsigned boot-chain test is marked failed when signing is required.

## 10. R12.7 Automated distribution tests

### Required gates

| Gate | Blocks release | Description |
|------|----------------|-------------|
| ISO structure | yes | Required files exist in the ISO |
| QEMU live boot | yes | ISO reaches live userspace |
| QEMU install | yes | Installer installs to blank disk |
| Installed boot | yes | Installed disk boots |
| Service health | yes | Required AIOS services are healthy |
| Update | yes | Signed update stages and activates |
| Rollback | yes | Previous deployment is restored after failure |
| Negative tests | yes | Known-bad artifacts are rejected |

### Test output

Each gate must write:

- command line used;
- artifact paths;
- serial or console log where applicable;
- pass/fail result;
- failure reason;
- release candidate identifier.

## 11. Revision 12 exit criteria

Revision 12 is complete only when all of these are true:

- A release ISO boots in QEMU.
- The live environment reaches userspace.
- The installer installs to a blank virtual disk.
- The installed system boots in QEMU.
- Core AIOS services become healthy.
- A signed update can be staged and applied.
- A rollback restores the previous deployment.
- Kernel, initramfs, modules, firmware, rootfs, SBOM, provenance, manifest, and
  signatures are present in the release output.
- CI blocks release on failed boot, install, service health, update, rollback,
  or signature validation.

