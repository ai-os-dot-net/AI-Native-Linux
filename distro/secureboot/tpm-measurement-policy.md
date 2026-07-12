# AI-OS.NET R13.4 — TPM Measured-Boot Policy

| Field  | Value                                                                                           |
| ------ | ----------------------------------------------------------------------------------------------- |
| Status | `PARTIAL` (offline expected-PCR computation is `REAL`/E3; live attestation is `DEFERRED`)       |
| Spec   | `distro/build/REV13-ENTERPRISE-SPEC.md` §7 (R13.4)                                              |
| Scope  | Which PCRs AIOS relies on, what extends them, and what is computed vs. what needs real hardware |

## 1. Purpose

R13.4 requires that "the system must know whether it booted through the expected
chain and must record that state" and that "TPM PCR measurements are captured
where TPM is present." This document defines the measured-boot model AIOS
targets and states honestly what is computed at build time versus what requires
a firmware/TPM run.

The compliance map currently records
`STIG-RHEL-08-010030` ("Measured boot / TPM attestation") as `documented`
(`distro/compliance/controls.json`). This policy plus `tpm-expected-pcrs.sh`
turn the _expected-value_ half of that control into a concrete, verifiable
artifact; the _live-quote_ half stays deferred until a QEMU+swtpm gate exists.

## 2. PCR selection (minimum set: 0, 2, 4, 7)

The TPM extends a Platform Configuration Register with
`PCR_new = H(PCR_old || measured_digest)`. AIOS attestation relies on the
following PCRs at minimum. Each entry states what extends it and whether AIOS
can precompute the expected value offline.

| PCR   | What extends it                                                                                                   | Why AIOS cares                                                                                                       | Offline-computable?                                                                                                                                                                                                                         |
| ----- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **0** | Firmware/UEFI code + platform SRTM config (firmware version, embedded drivers)                                    | Detects firmware tampering or an unexpected platform/firmware version under the boot chain                           | **No** — depends on the physical/virtual firmware image; captured only from a live TPM                                                                                                                                                      |
| **2** | Option ROM / externally loaded UEFI driver code                                                                   | Detects injected option ROMs or added UEFI drivers before the OS loader                                              | **No** — depends on attached hardware and loaded drivers at boot                                                                                                                                                                            |
| **4** | Boot manager code + every loaded boot application (shim → GRUB → kernel), and boot-attempt events                 | The core AIOS boot-chain integrity signal: proves the bootloader and kernel that ran match the release               | **Partially** — `tpm-expected-pcrs.sh` models this with a sha256 chain over the staged boot artifacts (a "PCR-4-style" value). The exact firmware value uses Authenticode PE hashes inside TCG events and needs a firmware run to reconcile |
| **7** | Secure Boot policy state — the `SecureBoot` variable plus `PK`/`KEK`/`db`/`dbx` contents used during verification | Proves Secure Boot was ON and which key hierarchy authorised the boot; ties directly to `generate-sb-keys.sh` output | **No** — reflects live firmware variable state at boot time                                                                                                                                                                                 |

### Why these four and not others

- **0 + 2** anchor the hardware/firmware root of trust below the OS. Without
  them, PCR 4 alone can be satisfied by a correct bootloader running on
  compromised firmware.
- **4** is where AIOS's own signed bootloader and kernel are measured, so it is
  the register the release build can most directly predict.
- **7** binds the measurement to Secure Boot being enforced with the operator's
  PK/KEK/db — closing the loop with the Secure Boot signing flow.
- PCRs 8–9 (GRUB command line / loaded files) and 11 (systemd UKI / unified
  kernel) are **future extensions**: valuable once AIOS ships a unified kernel
  image, but out of scope for the R13.4 minimum set.

## 3. What extends the PCRs in the AIOS boot chain

```
firmware/UEFI      -> PCR 0   (SRTM, firmware code + config)
option ROMs        -> PCR 2   (loaded UEFI drivers)
Secure Boot vars   -> PCR 7   (SecureBoot, PK, KEK, db, dbx)   <- generate-sb-keys.sh hierarchy
shim               -> PCR 4   (boot manager code)
GRUB (grubx64.efi) -> PCR 4   (boot application code)          <- sign-boot-artifacts.sh
kernel (vmlinuz)   -> PCR 4   (loaded image code)              <- sign-boot-artifacts.sh
initramfs          -> PCR 4/9 (loaded file, model-dependent)
```

`tpm-expected-pcrs.sh` folds the staged `boot/grub/grub.cfg`, `live/vmlinuz`,
`live/initrd.img`, and `live/aios.squashfs` (in that fixed order, present files
only) into the PCR-4-style expected value.

## 4. Computed vs. requires-hardware — the honest boundary

| Item                                                          | State                               | Produced by                                               |
| ------------------------------------------------------------- | ----------------------------------- | --------------------------------------------------------- |
| Expected PCR-4-style chain over staged boot artifacts         | **Computed offline, deterministic** | `tpm-expected-pcrs.sh` → `aios.tpm_expected_pcrs.v1` JSON |
| Secure Boot key hierarchy that PCR 7 will reflect             | **Computed offline**                | `generate-sb-keys.sh` → `aios.secureboot_keys.v1` JSON    |
| Exact firmware PCR 4 (Authenticode PE hashes + TCG event log) | **Deferred**                        | requires QEMU+swtpm or physical TPM                       |
| PCR 0 / 2 / 7 live values                                     | **Deferred**                        | requires a firmware/TPM run                               |
| Live TPM quote verification against expected JSON             | **Deferred**                        | future attestation verifier + QEMU+swtpm CI gate          |

The expected-PCR JSON is intentionally shaped as the input a future attestation
verifier consumes: it carries the per-artifact event digests and the running PCR
value so a live quote can be diffed field-by-field once a swtpm gate exists.

## 5. Hook points (wiring deferred to a later change)

These are documented, not wired, per the R13.4 groundwork scope. None of the
following files are modified by this change:

- **`distro/build/build-aios-iso.sh`** — after Step 11 emits `aios/boot-chain.json`
  and the boot artifacts, a future step can call
  `tpm-expected-pcrs.sh --staging "${ISO_DIR}" --out "${AIOS_ISO_META_DIR}/tpm-expected-pcrs.json"`
  and append the result to the release manifest (alongside the existing
  `append_manifest_artifact` calls, ~line 2058-2071).
- **`distro/compliance/controls.json`** — once the swtpm gate lands,
  `STIG-RHEL-08-010030` can move `documented` → `partial`/`enforced` with
  `enforcement_ref` pointing at `distro/secureboot/tpm-expected-pcrs.sh`.
- **CI (`.gitlab-ci.yml`)** — a future `verify` stage job can boot the ISO under
  QEMU with swtpm, read the TCG event log, and diff the live PCR 4 against the
  expected JSON. Blocking on mismatch closes the R13.7 "Secure Boot/signature
  verification" gate for firmware-capable runners.
