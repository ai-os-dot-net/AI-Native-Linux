# Secure Boot enforcement proof (R13.4)

This document records the **real UEFI Secure Boot enforcement proof** for AI-OS.NET
and how to reproduce it. It closes the gap left by the R13.4 _groundwork_ gate
(`distro/build/tests/test-rev13-secureboot.sh`), which proves the key hierarchy,
detached signatures, and tamper detection but explicitly declares the openssl
detached signatures **not** UEFI-consumable (`uefi_enrollment.consumable = false`).

The harness `distro/build/sb-boot-proof.sh` proves the missing link: that with the
AIOS PK/KEK/db hierarchy enrolled and Secure Boot on, a **real UEFI firmware**
(OVMF, SMM build) executes a db-signed kernel and **refuses** a tampered copy of the
same binary before any code runs. This is an end-to-end firmware decision, not a
static `grep`.

## What it proves

1. `generate-sb-keys.sh` builds a self-signed PK/KEK/db hierarchy.
2. The kernel EFI stub (`out/iso-extract/vmlinuz`) is signed with the **db** key
   via `sbsign` — a real PE/Authenticode signature, and `sbverify` confirms it.
3. One body byte of the signed binary is flipped; `sbverify` then **fails** — the
   tamper genuinely breaks the signature.
4. `virt-fw-vars` enrolls PK/KEK/db into a fresh OVMF varstore and turns Secure
   Boot on.
5. QEMU boots each image under an **SMM-enabled** OVMF with a write-protected
   pflash varstore (`-machine q35,smm=on` + `driver=cfi.pflash01,property=secure`),
   which is what makes the firmware actually enforce Secure Boot.

The verdict is the deterministic discriminator **"did the kernel execute?"**: the
EFI stub prints only once the firmware has verified the image and handed control to
it. The signed image must run; the tampered image must never run.

## Deterministic result (recorded 2026-07-18, NUC-15-Pro-Plus, OVMF SMM)

Six consecutive runs, all `SB PROOF: PASS`:

```
signed:   ran=1  reject_lines=0
tampered: ran=0  reject_lines=1
--- tampered rejection line ---
BdsDxe: failed to load Boot0002 "UEFI QEMU HARDDISK ...": Access Denied
        -- rejected probably by Secure Boot
--- signed boot head ---
BdsDxe: loading  Boot0002 "UEFI QEMU HARDDISK ..."
BdsDxe: starting Boot0002 "UEFI QEMU HARDDISK ..."
EFI stub: UEFI Secure Boot is enabled.
```

`ran=1` on the signed boot (the kernel's EFI stub executed and confirmed
"UEFI Secure Boot is enabled"); `ran=0` on the tampered boot (the firmware refused
the image — corroborated by the `Access Denied -- rejected probably by Secure Boot`
line).

## How to reproduce

Prerequisites (all present on the AIOS build host, none in the LXC CI runner —
this is a **local operator gate**, like `qemu-install-test.sh`):

- `sbsign`/`sbverify` (`sbsigntools`), `virt-fw-vars` (repo venv), `qemu-system-x86_64`,
  `sgdisk`, `mtools`, `mkfs.vfat`.
- An **SMM** OVMF firmware pair (`ovmf-x86_64-smm-code.bin` / `-smm-vars.bin`).
  The non-SMM firmware does **not** enforce Secure Boot.
- A kernel EFI stub at `distro/build/out/iso-extract/vmlinuz` (extract `live/vmlinuz`
  from the built ISO), or point `AIOS_KERNEL` at one.
- Root memlock: this QEMU build initializes io_uring at startup and needs a high
  `RLIMIT_MEMLOCK`, so the harness is run under `sudo` (the script raises
  `ulimit -l unlimited`). Non-root users are hard-capped at `DefaultLimitMEMLOCK`
  (8 MiB here), which is insufficient.

Run:

```bash
sudo /usr/bin/bash distro/build/sb-boot-proof.sh run
# exit 0 = PASS, 4 = INCONCLUSIVE (tool/boot problem), 5 = FAIL (tampered executed)
```

Overridable via env: `AIOS_KERNEL`, `AIOS_OVMF_CODE`, `AIOS_OVMF_VARS`,
`AIOS_VIRT_FW_VARS`, `AIOS_SB_BOOT_TIMEOUT`, `AIOS_SB_KEEP=1` (keep the work dir).

## Notes on rigor

- The disk is presented as a **GPT** image with a real ESP partition (a whole-disk
  FAT "superfloppy" and `mtools -i disk@@offset` both proved unreliable — OVMF
  enumeration flaked and mtools silently no-op'd the copy into a GPT image). The
  ESP is built whole-file, then `dd`'d into the ESP partition, and the payload
  presence is asserted before boot, so a silently-empty ESP fails loudly instead
  of flaking.
- The verdict is based on kernel **execution**, not on the rejection message text
  (whose timing in the serial log is flaky when QEMU is killed by the timeout);
  the rejection line is reported as corroboration only.
- QEMU startup errors (io_uring/memlock, missing KVM) are captured separately and
  reported as **INCONCLUSIVE**, never mistaken for a firmware decision — no false
  green.
