# AI-OS.NET — Defense Readiness Map

**Scope:** how AIOS's shipped, in-repo mechanisms map to the three defense
standards operators ask about — **DISA STIG**, **FIPS 140-3**, and **Common
Criteria (CC)**. This is the engineering-evidence view that backs the objective
_"military-grade BY ENGINEERING (certification-ready)."_

> ## Honest boundary — read this first
>
> **Engineering-ready is not the same as certified.** This document proves the
> _controls_ are built, enforced, and evidenced in code and CI. It does **not**
> claim any formal accreditation. A CMVP certificate (FIPS 140-3), a Common
> Criteria EAL evaluation, or a DISA STIG ATO are issued **only** by an external
> accredited lab / authorizing official against the running artifact. Those
> stamps are explicitly **out of scope** here and are marked `CERT-NEEDED`.
>
> Every row below is grounded in a real file (`path::marker`, the same
> convention the anti-fake gate `validate-controls.py` enforces). No aspirational
> rows.

## Summary — military-grade by engineering

Across the 24 defense-relevant capabilities mapped below:

| Status          | Meaning                                                                    | Count | Share   |
| --------------- | -------------------------------------------------------------------------- | ----- | ------- |
| **REAL**        | Enforced in code/build/CI with resolvable evidence (E2–E4)                 | 19    | **79%** |
| **PARTIAL**     | Partially enforced; a real gap remains (documented per row)                | 3     | **13%** |
| **CERT-NEEDED** | Engineering done; needs an external accredited lab / firmware trust anchor | 2     | **8%**  |

Backing control map (`controls.json`, validated green by `validate-controls.py`):
**39 enforced / 9 partial / 8 documented** of 56 CIS + STIG + EU-AI-Act controls
(70% enforced). Every `enforced`/`partial` control resolves to an in-repo
`enforcement_ref`.

**Bottom line:** the mechanisms a defense integrator would expect — measured/
verified boot, MAC enforcing, a FIPS crypto boundary, air-gap-high, a signed
supply chain, and a tamper-evident audit trail — are **built and enforced**. What
remains is (a) two items that need real hardware/firmware trust anchors and an
external CMVP certificate, and (b) three items partially enforced with a named,
closeable gap.

---

## AIOS differentiators — above typical mil-grade

Standard hardened Linux gives you MAC, secure boot, and an audit log. AIOS adds
three constitutional properties that a conventional STIG/CC target does **not**
have, and which directly matter for an AI-operated system:

1. **Append-only evidence — the AI cannot rewrite its own audit trail.** The
   evidence log is BLAKE3 hash-chained and append-only; agents have no write
   path to it. Grounding: `crates/aios-evidence/src/chain.rs::append-only`,
   tamper detection at `crates/aios-evidence/src/record.rs::TAMPER_DETECTED`.
2. **AI proposes, never executes.** The Cognitive Core emits typed action
   envelopes; nothing runs without a Policy Kernel decision, and the AI cannot
   approve its own privileged action (ALLOW is upgraded to REQUIRE_APPROVAL).
   Grounding: `crates/aios-policy/src/precedence.rs::AiSelfApprovalUpgrade`
   (E3-tested: `crates/aios-policy/tests/ai_self_approval.rs`),
   `crates/aios-action/src/envelope.rs::ActionEnvelope`.
3. **Secrets are capabilities.** Raw secret material read by an AI agent is a
   hard-deny class — the Vault Broker performs operations without revealing
   material. Grounding: `crates/aios-policy/src/hard_deny.rs::hard-deny`.

These are enforced-by-construction, not policy guidance — which is why they read
as `REAL` even before any external certification.

---

## 1. Secure Boot / measured boot

| Capability                                                           | DISA STIG      | FIPS 140-3 | Common Criteria    | Status          | Grounding (`path::marker`)                                                                                                                                                                                                                          |
| -------------------------------------------------------------------- | -------------- | ---------- | ------------------ | --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| UEFI SB key hierarchy (PK/KEK/db) generation                         | RHEL-08-010030 | n/a        | FPT_TST, FCS_CKM   | **REAL**        | `distro/secureboot/generate-sb-keys.sh` (gate: `test-rev13-secureboot.sh`)                                                                                                                                                                          |
| Boot-artifact signing, fail-closed                                   | RHEL-08-010030 | n/a        | FPT_TST.1          | **REAL**        | `distro/build/build-aios-iso.sh::require_boot_signature`; `distro/secureboot/sign-boot-artifacts.sh::sbsign`                                                                                                                                        |
| dm-verity rootfs integrity (verified boot)                           | RHEL-08-010359 | n/a        | FPT_TST.1, FDP_SDI | **REAL**        | `distro/build/build-aios-iso.sh::dm-verity`                                                                                                                                                                                                         |
| Kernel lockdown LSM + signed modules                                 | RHEL-08-010371 | n/a        | FPT_PHP, FMT_MOF   | **REAL**        | `distro/aios-boot/kernel-config::CONFIG_MODULE_SIG_FORCE=y`, `::CONFIG_SECURITY_LOCKDOWN_LSM=y`                                                                                                                                                     |
| TPM measured boot / PCR attestation policy                           | RHEL-08-010030 | n/a        | FPT_TST.1, FCS_COP | **PARTIAL**     | `distro/secureboot/tpm-expected-pcrs.sh`, `distro/secureboot/tpm-measurement-policy.md` — PCR policy + expected values shipped; runtime quote verification and hardware TPM are deployment-bound (`controls.json` STIG-RHEL-08-010030 = documented) |
| UEFI firmware trust-anchor enrollment (real Secure Boot in firmware) | RHEL-08-010030 | n/a        | AGD_PRE, FPT_TST   | **CERT-NEEDED** | Signing pipeline is real, but chaining to a hardware root of trust needs either a Microsoft-UEFI-CA-signed shim or operator-enrolled custom keys on the target firmware — external to this repo                                                     |

## 2. SELinux MAC — enforcing

| Capability                                           | DISA STIG      | FIPS 140-3 | Common Criteria  | Status      | Grounding (`path::marker`)                                                                                                                                                                                                                       |
| ---------------------------------------------------- | -------------- | ---------- | ---------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| SELinux built-in + enforcing state                   | RHEL-08-010450 | n/a        | FDP_ACC, FDP_ACF | **REAL**    | `distro/aios-boot/kernel-config::CONFIG_SECURITY_SELINUX=y`; `distro/aios-boot/aios-config.toml::selinux = "enforcing"`                                                                                                                          |
| Binary targeted policy shipped in base image         | RHEL-08-010450 | n/a        | FMT_MSA          | **REAL**    | `distro/build/build-opensuse-rootfs.sh::selinux-policy-targeted`                                                                                                                                                                                 |
| Per-daemon SELinux security context                  | RHEL-08-040135 | n/a        | FDP_ACF.1        | **REAL**    | `distro/systemd/aios-evidence-log.service::SELinuxContext=-system_u:system_r:aios_evidence_log_t`                                                                                                                                                |
| All services in confined domains (no `unconfined_t`) | RHEL-08-010171 | n/a        | FDP_ACC.2        | **PARTIAL** | `distro/desktop/confine/selinux/aios_renderer.te::aios_renderer_t` — one full custom domain ships; remaining daemons rely on `SELinuxContext=` assignments without a per-daemon `.te` module yet (`controls.json` STIG-RHEL-08-010171 = partial) |

## 3. FIPS crypto boundary

| Capability                                               | DISA STIG      | FIPS 140-3            | Common Criteria  | Status          | Grounding (`path::marker`)                                                                                                                                                                                                                                    |
| -------------------------------------------------------- | -------------- | --------------------- | ---------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FIPS 140-3 strict mode + FIPS-approved algorithm routing | RHEL-08-010020 | 140-3 §Approved SF    | FCS_COP.1        | **REAL**        | `crates/aios-capability-runtime/src/fips.rs::FIPS_STRICT` (mode selection + compliance-sensitive op routing, S16.5)                                                                                                                                           |
| FIPS provider selection at runtime                       | —              | 140-3 §Roles/Services | FCS_CKM, FCS_COP | **REAL**        | `crates/aios-capability-runtime/src/fips.rs::FIPS 140-3`                                                                                                                                                                                                      |
| CMVP-validated module certificate                        | —              | 140-3 CMVP cert       | ALC_CMC          | **CERT-NEEDED** | Code selects a FIPS-approved provider and routes only approved algorithms, but the **certificate** for the underlying crypto module (e.g. OpenSSL FIPS provider) is issued only by an accredited CMVP lab against the deployed binary — external to this repo |

## 4. Air-gap (AIRGAP_HIGH)

| Capability                                         | DISA STIG      | FIPS 140-3 | Common Criteria  | Status      | Grounding (`path::marker`)                                                                                                                                                                                         |
| -------------------------------------------------- | -------------- | ---------- | ---------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Offline-only software intake under AIRGAP_HIGH     | RHEL-08-040200 | n/a        | FDP_IFC, FTP_ITC | **REAL**    | `crates/aios-distribution/src/airgap_store.rs::AIRGAP_HIGH` (live internet fetch constitutionally blocked, S26 §10)                                                                                                |
| Signed air-gap store manifest + verification       | —              | n/a        | FDP_SDI, FCS_COP | **REAL**    | `crates/aios-distribution/src/airgap_store.rs::AIRGAP_STORE_VERIFIED`                                                                                                                                              |
| OS-level network egress lockdown under AIRGAP_HIGH | RHEL-08-040200 | n/a        | FDP_IFF.1        | **PARTIAL** | Policy-plane block is real (above); host firewall egress default-deny is documented-only (`controls.json` CIS-3.5.1.1 = documented, null enforcement) — needs an nftables/firewalld baseline shipped in the rootfs |

## 5. Supply-chain (SBOM / provenance / reproducibility)

| Capability                                | DISA STIG      | FIPS 140-3 | Common Criteria  | Status   | Grounding (`path::marker`)                                                                                            |
| ----------------------------------------- | -------------- | ---------- | ---------------- | -------- | --------------------------------------------------------------------------------------------------------------------- |
| CycloneDX / SPDX SBOM generation          | RHEL-08-010010 | n/a        | ALC_CMS, ALC_CMC | **REAL** | `crates/aios-capability-runtime/src/sbom.rs::SbomFormat`; build emits `distro/build/build-aios-iso.sh::sbom.cdx.json` |
| SLSA provenance model                     | —              | n/a        | ALC_LCD, ALC_TAT | **REAL** | `crates/aios-capability-runtime/src/sbom.rs::SLSA`                                                                    |
| Signed provenance per image (fail-closed) | RHEL-08-010010 | n/a        | ALC_DVS          | **REAL** | `distro/build/build-aios-iso.sh::require_boot_signature` requires `provenance.json.sig` — build hard-fails if absent  |
| Reproducible / hermetic build             | —              | n/a        | ALC_CMC.5        | **REAL** | gate: `distro/build/tests/test-rev13-hermetic.sh`; `distro/build/hermetic/verify-build-lock.sh`                       |

## 6. Audit — append-only evidence

| Capability                                | DISA STIG                  | FIPS 140-3 | Common Criteria    | Status   | Grounding (`path::marker`)                                             |
| ----------------------------------------- | -------------------------- | ---------- | ------------------ | -------- | ---------------------------------------------------------------------- |
| Append-only, hash-chained audit records   | RHEL-08-030010             | n/a        | FAU_STG.1, FAU_GEN | **REAL** | `crates/aios-evidence/src/chain.rs::append-only`                       |
| Audit-log tamper detection + record       | RHEL-08-030181             | n/a        | FAU_STG.4, FPT_TST | **REAL** | `crates/aios-evidence/src/record.rs::TAMPER_DETECTED`                  |
| Boot-time audit/accounting service active | CIS-4.1.1 / RHEL-08-030010 | n/a        | FAU_GEN.1          | **REAL** | `distro/systemd/aios-evidence-log.service::ExecStart`                  |
| AI agents cannot alter the audit trail    | RHEL-08-030010             | n/a        | FAU_STG.1, FDP_ACF | **REAL** | append-only (above) + `crates/aios-policy/src/hard_deny.rs::hard-deny` |

---

## The 3 PARTIAL items — precise gap + how to close

| Item                                       | Why PARTIAL (honest)                                                                                                                                                                                    | Evidence today                                           | To reach REAL                                                                                                                                                                                        |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TPM measured boot / PCR attestation        | PCR policy + expected values are shipped and the secureboot gate signs boot artifacts, but runtime PCR-quote verification against a hardware TPM is deployment-bound; no live attestation loop in-tree. | E2 (`tpm-expected-pcrs.sh`, `tpm-measurement-policy.md`) | Ship a boot-time PCR-quote verifier + evidence record; requires a TPM in the target (or swtpm in CI, already used by `qemu-install-gate`).                                                           |
| All services in confined SELinux domains   | One full `.te` domain ships (`aios_renderer_t`); other daemons use `SELinuxContext=` labels but lack a per-daemon type-enforcement module, so "not `unconfined_t`" is not proven for every service.     | E1–E2 (`aios_renderer.te`, 10× `SELinuxContext=` units)  | Author `.te` modules for the remaining AIOS daemons; add an `seinfo`/`ausearch` gate asserting zero `unconfined_t` transitions. (Rust crates + systemd units are out of this task's edit territory.) |
| OS-level egress lockdown under AIRGAP_HIGH | The policy-plane block on live fetch is REAL; the host-firewall default-deny that would enforce it below the policy plane is documented-only.                                                           | E1 (`controls.json` CIS-3.5.1.1 documented)              | Ship an nftables/firewalld default-deny egress baseline in the rootfs and reference it as an `enforcement_ref`.                                                                                      |

## The 2 CERT-NEEDED items — external lab / firmware only

| Item                                   | What is done (engineering)                                                                            | What only an external body can provide                                                                                                            |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| UEFI firmware Secure Boot trust anchor | Full key hierarchy generation + fail-closed artifact signing pipeline, gate-tested.                   | A hardware root of trust: a Microsoft-UEFI-CA-signed shim, **or** operator-enrolled custom PK/KEK/db in the target firmware. Not a code artifact. |
| FIPS 140-3 CMVP certificate            | FIPS strict mode, approved-algorithm routing, FIPS-provider selection — all in code and type-checked. | A **CMVP validation certificate** for the deployed crypto module, issued by an accredited testing lab against the running binary.                 |

## Controls that remain `documented` (null enforcement) — deployer/organisational

These are honestly not platform-enforced mechanisms and are left `documented` in
`controls.json` (null `enforcement_ref`), not claimed as enforced:

- **STIG-RHEL-08-010550** — no direct root SSH login (sshd config is a deployment baseline).
- **CIS-1.5.3** — restrict core dumps (sysctl/limits baseline, not yet shipped).
- **STIG-RHEL-08-010030b** — LUKS data-at-rest encryption (install-time operator choice).
- **EU-AI-Act Art. 10 / 11-Annex-IV / 26** — data governance, full technical file, and deployer oversight duties are provider/deployer obligations the platform _enables_ but does not discharge. The 7 EU-AI-Act `partial` rows (Art. 9, 11, 13, 13-1, 14, 72, 72-1) reflect that the platform provides the mechanism while the organisational obligation stays with the deployer — this is deliberate honesty, not an implementation gap.

---

## How to reproduce the evidence

```bash
python3 distro/compliance/validate-controls.py         # control map resolves green
bash distro/build/tests/test-rev13-compliance.sh       # anti-fake gate + counts
bash distro/build/tests/test-rev13-secureboot.sh        # signing pipeline (area 1, 5)
bash distro/build/tests/test-rev13-cve-process.sh       # CVE lifecycle
bash distro/build/tests/test-rev13-hermetic.sh          # reproducible build (area 5)
```

See `distro/build/ENTERPRISE-EXIT-GATES.md` for the R13.7 blocking-gate matrix
and `distro/compliance/controls.json` for the full 56-control map.
