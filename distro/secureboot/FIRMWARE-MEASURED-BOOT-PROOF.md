# Firmware measured-boot proof (R13.4)

This records the **real firmware measured-boot proof** for AI-OS.NET and how to
reproduce it. It is the firmware-side complement to the other two R13.4 proofs
already merged to main:

- `sb-boot-proof.sh` — firmware ENFORCES Secure Boot (rejects a tampered kernel);
- `tpm-measured-boot-proof.sh` — the TPM extend model + PCR-bound seal/unseal.

The harness `distro/build/tpm-firmware-measured-boot-proof.sh` proves that a **real
UEFI firmware (OVMF) drives a real TPM 2.0 (swtpm vTPM)** and actually MEASURES
boot state into the TPM's PCRs — and that a security-relevant change in that state
(Secure Boot on vs off) produces a different measurement.

## What it proves

The same db-signed kernel ESP is booted twice under an SMM OVMF with a fresh swtpm
vTPM: once with Secure Boot **enabled** (our PK/KEK/db enrolled), once **disabled**.
swtpm is a persistent daemon, so after QEMU exits it still holds the
firmware-extended PCRs; the harness saves that volatile state, resumes swtpm with
`Startup(STATE)` over TCP, and reads the PCRs with tpm2-tools.

Deterministic assertions (all hold every run):

- **PCR 0 is non-zero** in both boots — firmware measured its own code (SRTM).
- **PCR 7 is non-zero** in both boots — firmware measured the Secure Boot state.
- **PCR 7 (SB on) ≠ PCR 7 (SB off)** — the Secure Boot policy is really folded into
  the TPM by the firmware.
- **PCR 0 (SB on) = PCR 0 (SB off)** — identical firmware code path (consistency).

## Deterministic result (recorded 2026-07-18, NUC-15-Pro-Plus, OVMF SMM + swtpm 0.10.1)

Three consecutive runs, all `FWTPM PROOF: PASS`:

```
SB ON : PCR0=0x9983081c...b6ce8cc4   PCR7=<varies with enrolled key material>
SB OFF: PCR0=0x9983081c...b6ce8cc4   PCR7=0x65caf8dd...34eb3068
```

`PCR 0` is identical across both boots and across runs (the OVMF code path never
changes). `PCR 7 (SB off)` is constant (`0x65caf8dd…`, the "Secure Boot disabled"
state). `PCR 7 (SB on)` **varies across runs by design**: PCR 7 hashes the actual
enrolled PK/KEK/db certificate material, and the harness generates a fresh key
hierarchy each run — so the invariant proven is `PCR7(on) ≠ PCR7(off)`, never a
fixed on-value.

## How to reproduce

Prerequisites: `sbsign`, `virt-fw-vars` (repo venv), `qemu-system-x86_64` with TPM
support, an **SMM** OVMF (`ovmf-x86_64-smm-{code,vars}.bin`), `swtpm` + the swtpm
TCTI (`libtss2-tcti-swtpm0`) + tpm2-tools, `sgdisk`, `mtools`, `mkfs.vfat`. Needs
root for QEMU's locked memory (io_uring), like `sb-boot-proof.sh` — run under sudo.

```bash
sudo /usr/bin/bash distro/build/tpm-firmware-measured-boot-proof.sh run
# exit 0 = PASS, 4 = INCONCLUSIVE (tool/boot problem), 5 = FAIL (no SB-state measurement)
```

Overridable via env: `AIOS_KERNEL`, `AIOS_OVMF_CODE`, `AIOS_OVMF_VARS`,
`AIOS_VIRT_FW_VARS`, `AIOS_TPM_BOOT_TIMEOUT`, `AIOS_TPM_PORT`, `AIOS_TPM_KEEP=1`.

## Notes on rigor

- The vTPM PCR readback uses swtpm's own state persistence: `swtpm_ioctl -v` stores
  the firmware-extended volatile state, then a fresh swtpm resumes it with
  `--flags startup-state` (issues `TPM2_Startup(STATE)`). Plain `not-need-init`
  leaves the TPM without a startup after a real firmware boot and rejects commands
  — that was the initial INCONCLUSIVE cause.
- QEMU startup failures and unreadable PCRs are reported as **INCONCLUSIVE**, never
  a false PASS. swtpm processes and the work dir are cleaned up on exit.
- This proof establishes that firmware measurement is real and reflects the Secure
  Boot policy. Reconciling the exact PCR-4 value against a live TCG event log
  (Authenticode PE hashes, requiring an in-guest event-log reader) remains a
  separate, documented step.
