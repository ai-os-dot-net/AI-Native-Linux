# TPM measured-boot enforcement proof (R13.4)

This records the **real TPM 2.0 measured-boot enforcement proof** for AI-OS.NET
and how to reproduce it. It closes the gap the groundwork script
(`distro/secureboot/tpm-expected-pcrs.sh`) honestly declares: that script computes
an expected PCR-4-style measurement chain offline but _cannot_ prove its math
matches a real TPM, nor that a secret bound to that state is actually gated.

The harness `distro/secureboot/tpm-measured-boot-proof.sh` proves both, against a
real TPM 2.0 implementation (`swtpm`), deterministically, **without root or KVM**.

## What it proves

1. **Extend-model equivalence.** A resettable PCR is reset to zero, then extended
   with the measurement chain (`sha256` of each staged boot artifact, in the fixed
   order) that `tpm-expected-pcrs.sh` emits. Reading the PCR back yields exactly
   the script's precomputed `pcr4_style_expected`. This validates the offline
   groundwork math against a real TPM 2.0 `TPM2_PCR_Extend` implementation.

2. **PCR-bound seal/unseal enforcement** — the property behind
   "release the LUKS key only under the expected measured boot":
   - A secret is sealed under a policy bound to the good PCR state.
   - `tpm2_unseal` **succeeds** while the PCR holds that state.
   - After the PCR is extended with a different (tampered) measurement,
     `tpm2_unseal` **fails**. A secret that unsealed regardless of PCR state
     would be a fake gate; this proves it is not.

## Out of scope (honesty)

This does **not** reconcile the exact firmware PCR-4 value with a live OVMF+vTPM
boot and its TCG event log (real firmware extends PCR 4 with Authenticode PE
hashes inside event-log events, not plain file hashes). That firmware-event-log
reconciliation is the documented next step. This proof establishes the TPM-side
enforcement semantics that protect the sealed secret.

## Deterministic result (recorded 2026-07-18, NUC-15-Pro-Plus, swtpm 0.10.1)

Four consecutive runs, all `TPM PROOF: PASS`:

```
PCR 23 chain (4 artifacts):
  real TPM  = 65eb30d4e6286534a93c8b8a60d046f8d016a5e2c2220fb5fe6aea45e6c6800e
  expected  = 65eb30d4e6286534a93c8b8a60d046f8d016a5e2c2220fb5fe6aea45e6c6800e
seal/unseal:
  good-state  rc=0 released='AIOS-MEASURED-BOOT-SEALED-KEY-9f3c'
  tampered    rc=1 (must be nonzero)
TPM PROOF: PASS
```

`real TPM == expected` (property 1); the sealed secret is released only at the
good measured state and refused after tampering (property 2).

## How to reproduce

Prerequisites: `swtpm`, the **swtpm TCTI** (`libtss2-tcti-swtpm0`), `tpm2-tools`,
`python3`. No root, no KVM — the software TPM runs as an unprivileged socket
server and tpm2-tools talks to it over the swtpm TCTI.

```bash
bash distro/secureboot/tpm-measured-boot-proof.sh
# exit 0 = PASS, 4 = INCONCLUSIVE (a tool is missing), 5 = FAIL (TPM did not enforce)
```

Overridable via env: `AIOS_TPM_PCR` (default 23, must be resettable),
`AIOS_TPM_PORT` (default 42321; control port = +1), `AIOS_TPM_KEEP=1`.

## Notes on rigor

- Uses a **resettable** application PCR (23) so the chain starts from a known zero
  state, matching the offline model exactly — deterministic across runs.
- Drives an **independent** TPM 2.0 implementation (swtpm), not a re-run of the
  groundwork's own Python, so the equivalence check is meaningful.
- Missing tools yield **INCONCLUSIVE** (exit 4), never a false PASS; the swtpm
  process and work dir are always cleaned up on exit.
- Between tpm2-tools calls the harness flushes transient objects
  (`tpm2_flushcontext -t`) because this path runs without a TPM resource manager;
  otherwise `tpm2_load` fails with `out of memory for object contexts`.
