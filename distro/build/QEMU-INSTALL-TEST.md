# AI-OS.NET Rev.12 — QEMU Install-and-Boot Gate

Automated harness for spec **R12.2 (installer baseline)** and the **R12.7**
"QEMU install" + "Installed boot" gates in `REV12-DISTRIBUTION-SPEC.md`.

It proves the ISO can install itself onto a blank disk and that the installed
disk boots — the two gates that a mere live-boot smoke test
(`qemu-boot-smoke.sh`) does not cover.

## Files

| File                                            | Role                                                                                     |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `distro/build/qemu-install-test.sh`             | Two-phase harness: install to a blank disk, then boot the installed disk.                |
| `distro/installer/aios-autoinstall.sh`          | Kernel-cmdline → env bridge that drives the non-interactive install in-guest.            |
| `distro/build/tests/test-rev12-install-gate.sh` | Static + dry-run test (matches the other `test-rev12-*` gates), plus an opt-in real run. |

## Non-interactive install mechanism (and why)

The installer's **only genuine non-interactive entrypoint** is the env-var
driven quick installer `distro/installer/aios-quick-install.sh` — it requires no
TTY and takes every parameter from the environment
(`AIOS_TARGET_DISK`, `AIOS_HOSTNAME`, `AIOS_CONFIRM_SKIP=1`; see its header,
lines 41-44, and the guards at lines 97-109). The interactive
`aios-installer.sh` is not scriptable.

There is, however, no existing bridge from the boot environment to that
installer. `aios-autoinstall.sh` is that bridge (new, additive): it reads
`/proc/cmdline`, and when `aios.autoinstall` is present it maps

```
aios.disk=DEV        -> AIOS_TARGET_DISK   (aios-quick-install.sh:97-100)
aios.hostname=NAME   -> AIOS_HOSTNAME      (aios-quick-install.sh:102-105)
(always)             -> AIOS_CONFIRM_SKIP=1(aios-quick-install.sh:107-109)
aios.profile=P       -> AIOS_PROFILE       (aios-quick-install.sh:111)
aios.selinux_mode=M  -> AIOS_SELINUX_MODE  (aios-quick-install.sh:118)
aios.squashfs=PATH   -> AIOS_SQUASHFS      (aios-quick-install.sh:119)
aios.skip_tpm        -> AIOS_SKIP_TPM=1    (aios-quick-install.sh:412)
aios.skip_verity     -> AIOS_SKIP_VERITY=1 (aios-quick-install.sh:451)
aios.skip_selinux    -> AIOS_SKIP_SELINUX=1(aios-quick-install.sh:495)
```

then `exec`s the real installer. It re-implements no installer logic. It emits
serial markers the harness keys on: `AIOS-AUTOINSTALL: START|SKIP|SUCCESS|FAILED`.

The **kernel command line** was chosen over serial "expect" injection because
the installer is already env-driven (no prompt to chat with), and a cmdline flag
is deterministic and CI-friendly. The harness injects the command line with QEMU
**direct kernel boot** (`-kernel`/`-initrd`/`-append`) so no GRUB editing is
needed, while the ISO stays attached as `-cdrom` — the live media source the
AIOS initramfs discovers (`distro/aios-boot/initramfs/init`, `find_live_medium`).

## Required ISO wiring (deployment task)

`aios-autoinstall.sh` must be present in the live rootfs next to
`aios-quick-install.sh`, and run once at live boot when `aios.autoinstall` is on
the command line. A oneshot unit is sufficient (illustrative — add during ISO
build, not part of these files):

```ini
# /etc/systemd/system/aios-autoinstall.service  (enabled in the live rootfs)
[Unit]
Description=AI-OS.NET cmdline autoinstall
After=multi-user.target
ConditionKernelCommandLine=aios.autoinstall

[Service]
Type=oneshot
ExecStart=/usr/lib/aios/installer/aios-autoinstall.sh
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
```

The wrapper powers the guest off when finished (unless `aios.no_poweroff`), so
QEMU exits and the harness proceeds to phase 2.

## Usage

Structure / dry-run only (no QEMU, safe on a busy build host):

```bash
distro/build/qemu-install-test.sh --iso build/out/aios-rev12.iso \
    --kernel /path/live/vmlinuz --initrd /path/live/initrd.img --dry-run

sh distro/build/tests/test-rev12-install-gate.sh
```

Real run (installs to a throwaway qcow2, then boots it):

```bash
distro/build/qemu-install-test.sh \
    --iso   build/out/aios-rev12.iso \
    --kernel live/vmlinuz \
    --initrd live/initrd.img \
    --swtpm \
    --kvm            # optional; TCG is the default fallback

# or via the test wrapper:
AIOS_QEMU_INSTALL_TEST=1 sh distro/build/tests/test-rev12-install-gate.sh \
    --iso build/out/aios-rev12.iso --kernel live/vmlinuz --initrd live/initrd.img
```

`--kernel`/`--initrd` are the ISO's staged `live/vmlinuz` and `live/initrd.img`
(mount the ISO or copy them out of `build/out/staged`). Logs are written to
`distro/build/out/qemu-install-phase1.log` (install) and
`qemu-install-phase2.log` (installed boot).

## Requirements

- `qemu-system-x86_64`, `qemu-img`, `timeout` — always.
- **OVMF** (`OVMF_CODE.fd` + `OVMF_VARS.fd`) — the installed system boots
  `systemd-boot` from the ESP, which is UEFI-only. Auto-discovered; override with
  `--ovmf-code` / `--ovmf-vars`.
- **swtpm** (`--swtpm`) — `aios-quick-install.sh` always creates a LUKS2 root and
  the only unattended unlock path is TPM2 (`crypttab … tpm2-device=auto`). Phase 1
  enrolls the TPM and phase 2 unlocks with it, so **both phases share one swtpm
  state dir**. Without a TPM the installed root cannot auto-unlock and phase 2
  will stall at a passphrase prompt.
- KVM optional (`--kvm`); TCG (`accel=tcg`) is the default, matching
  `qemu-boot-smoke.sh`.

### Caveat (honest)

Under pure TCG the emulated boot measurements (PCRs) can differ between the
enrollment boot (phase 1) and the fresh boot (phase 2). If TPM2 unlock ever
drifts, phase 2 falls through to a passphrase and the gate reports a phase-2
failure with the serial log. Prefer `--kvm` with a stable OVMF for reproducible
PCRs, or extend the installer with a CI-only recovery-passphrase slot before
wiring this gate as release-blocking.

## Exit codes & markers

- `0` — both phases passed.
- non-zero — the failing phase, with the reason and the offending log path.

| Phase          | Success markers                                                              | Failure markers                                                                  |
| -------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Install        | `AIOS-AUTOINSTALL: SUCCESS`, `… installation complete`, `[AIOS-QUICK]  OK …` | `AIOS-AUTOINSTALL: FAILED`, `[AIOS-QUICK]  ERROR`, `Kernel panic`, `AIOS-RESCUE` |
| Installed boot | `AIOS-INIT … Switching to real root`, `Reached target … Multi-User`          | `Kernel panic`, `No bootable device`, `switch_root failed`, `AIOS-RESCUE`        |

## CI wiring suggestion

Add after the ISO build and the live-boot smoke gate (e.g. in `ci-build-all.sh`
/ `Makefile` / `.gitlab-ci.yml`):

```yaml
qemu-install-gate:
  stage: test
  script:
    # always: static + dry-run (no QEMU needed)
    - sh distro/build/tests/test-rev12-install-gate.sh
    # on a KVM-capable runner, promote to a blocking real run:
    - |
      if [ -e /dev/kvm ]; then
        AIOS_QEMU_INSTALL_TEST=1 sh distro/build/tests/test-rev12-install-gate.sh \
          --iso "$ISO" --kernel "$KERNEL" --initrd "$INITRD"
      fi
  artifacts:
    when: always
    paths:
      - distro/build/out/qemu-install-phase1.log
      - distro/build/out/qemu-install-phase2.log
```

Per R12.7, each gate records: command line used, artifact paths, serial logs,
pass/fail, and failure reason — all emitted by the harness to stdout and the two
`out/qemu-install-phase*.log` files.
