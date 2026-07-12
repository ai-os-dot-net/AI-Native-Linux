# AI-OS.NET R13.8 — Compliance baseline (CIS + STIG control map)

This directory is the **distro-level, file-grounded compliance baseline** for
AI-OS.NET enterprise profiles. It answers one auditor question precisely:

> "For each CIS / STIG control you claim, show me the concrete thing in the
> image that enforces it — and prove it is really there."

It is the operator-facing counterpart to the runtime
`ControlMapRegistry` in the Rust workspace (see
[Relationship to the crate registry](#relationship-to-the-crate-controlmapregistry)).

## Files

| File                   | Purpose                                                                                                                                                                                                                      |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `controls.json`        | The control map: an array of CIS/STIG controls, each linked to an AIOS enforcement mechanism and a **resolvable** reference in this repository.                                                                              |
| `validate-controls.py` | The anti-fake gate. Validates schema, vocabularies, unique IDs, and that **every non-null `enforcement_ref` actually resolves** (path exists; any `::marker` is really present in the file). Non-zero exit on any violation. |
| `README.md`            | This document.                                                                                                                                                                                                               |

The release gate test is
`distro/build/tests/test-rev13-compliance.sh`.

## Baselines

Per `REV13-ENTERPRISE-SPEC.md` §11 the enterprise compliance surface covers:

| Baseline         | Scope in this artifact                                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CIS**          | Practical production security baseline. `baseline: "cis"`.                                                                                                    |
| **STIG-aligned** | Government/military-style hardening target. `baseline: "stig"`.                                                                                               |
| **EU AI Act**    | EU Regulation 2024/1688, mapped from the platform/deployer view. `baseline: "eu-ai-act"`. See [EU AI Act baseline](#eu-ai-act-baseline-platform-vs-provider). |
| AIOS native      | AIOS constitutional/evidence invariants — owned by the crate `ControlMapRegistry` (AIOS invariant ↔ NIST family), not duplicated here.                        |
| NIST map         | Control-family mapping — also owned by the crate registry.                                                                                                    |

`controls.json` deliberately scopes itself to the two **externally recognized,
per-control** baselines (CIS, STIG) that an enterprise auditor checks item by
item. The AIOS-native and NIST-family mappings live in the crate registry
because they are invariant-level, not file-level.

> **STIG IDs are alignment references, not a claim of formal DISA STIG
> certification.** They use the `STIG-RHEL-08-0xxxxx` shape to help auditors
> cross-reference; a formal STIG audit is a separate, out-of-tree activity.

## EU AI Act baseline — platform vs. provider

The `eu-ai-act` baseline maps articles of **EU Regulation 2024/1688 (the AI
Act)** to the concrete platform mechanisms AI-OS.NET ships. It exists because a
deployer running AI workloads on this OS must be able to point an auditor at the
technical controls that help them meet the Act's obligations.

> **AI-OS.NET is a compliance-_enabling_ platform, not a "compliant AI
> system."** The OS is neither a high-risk AI system nor a model provider under
> the Act. It cannot _be_ EU AI Act compliant on its own — compliance is a
> property of a specific AI system and the organisation operating it. What this
> baseline claims is narrower and honest: for several of the Act's **technical**
> obligations, the platform provides a real, file-grounded mechanism a deployer
> can rely on. Article/paragraph duties that are inherently organisational (the
> deployer's) or model-level (the provider's) are marked `documented` with a
> `null` `enforcement_ref` — the platform enables them but does not discharge
> them.

### Responsibility split

| Who                      | Owns                                                                                                                        | In this map                                 |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| **Model provider**       | Data governance of training/validation data (Art. 10), model accuracy claims, provider technical file                       | `documented` / out of tree (Art. 10)        |
| **Deployer**             | Assigning human oversight, monitoring operation, retaining logs, completing the Annex IV technical file                     | `documented` (Art. 26, Art. 11 Annex IV)    |
| **Platform (AI-OS.NET)** | Append-only record-keeping, approval-gated execution, self-approval prevention, hardening, signed updates, health reporting | `enforced` / `partial` technical mechanisms |

### Per-article summary

| Article                | Obligation (platform view)                           | Mechanism → `enforcement_ref`                                 | Status       |
| ---------------------- | ---------------------------------------------------- | ------------------------------------------------------------- | ------------ |
| **Art. 9**             | Risk management (continuous hardening scan)          | `distro/systemd/aios-hardening.service::ExecStart`            | `partial`    |
| **Art. 10**            | Data governance (training data)                      | — (model-provider duty)                                       | `documented` |
| **Art. 11**            | Technical documentation (SBOM + provenance)          | `distro/build/build-aios-iso.sh::provenance.json`             | `partial`    |
| **Art. 11 (Annex IV)** | Full technical file                                  | — (deployer/provider duty)                                    | `documented` |
| **Art. 12**            | Record-keeping (automatic event logging)             | `distro/systemd/aios-evidence-log.service::ExecStart`         | `enforced`   |
| **Art. 12(1)**         | Tamper-evident, append-only logs                     | `crates/aios-evidence/src/chain.rs::append-only`              | `enforced`   |
| **Art. 12(2)**         | Log-tampering detection                              | `crates/aios-evidence/src/record.rs::TAMPER_DETECTED`         | `enforced`   |
| **Art. 13**            | Transparency (explainable decisions)                 | `crates/aios-policy/src/explain.rs::DecisionLog`              | `partial`    |
| **Art. 13(1)**         | Typed action envelopes (AI proposes, never executes) | `crates/aios-action/src/envelope.rs::ActionEnvelope`          | `partial`    |
| **Art. 14**            | Human oversight (approval gate)                      | `crates/aios-policy/src/decision.rs::RequireApproval`         | `partial`    |
| **Art. 14(4)**         | AI cannot self-approve                               | `crates/aios-policy/src/precedence.rs::AiSelfApprovalUpgrade` | `enforced`   |
| **Art. 14(4)(e)**      | Stop/override (hard-deny)                            | `crates/aios-policy/src/hard_deny.rs::hard-deny`              | `enforced`   |
| **Art. 15**            | Cybersecurity (kernel ASLR)                          | `distro/aios-boot/kernel-config::CONFIG_RANDOMIZE_BASE=y`     | `enforced`   |
| **Art. 15**            | Integrity (dm-verity)                                | `distro/build/build-aios-iso.sh::dm-verity`                   | `enforced`   |
| **Art. 15**            | Resilience (signed updates)                          | `distro/update/aios-update.sh::verify_signature`              | `enforced`   |
| **Art. 15**            | Robustness (SELinux enforcing)                       | `distro/aios-boot/aios-config.toml::selinux = "enforcing"`    | `enforced`   |
| **Art. 26**            | Deployer obligations (oversight/monitoring)          | — (organisational duty)                                       | `documented` |
| **Art. 72**            | Post-market monitoring (health report)               | `distro/systemd/aios-health-report.service::ExecStart`        | `partial`    |
| **Art. 72**            | Monitoring data retained as evidence receipts        | `crates/aios-evidence/src/receipt.rs::EvidenceReceipt`        | `partial`    |

### Honest coverage statement

Of the 19 `eu-ai-act` entries, the strongest coverage is **Art. 12
(record-keeping)** and the technical half of **Art. 14 (human oversight)** and
**Art. 15 (robustness/cybersecurity)** — these resolve to concrete, in-image
mechanisms and are `enforced`. **Art. 13** transparency and **Art. 9** risk
management are `partial`: the mechanisms exist (explainable policy decisions,
typed action envelopes, a hardening scanner) but full deployer-facing
transparency and a formal risk-management _system_ depend on configuration and
process outside this image. **Art. 10** (training-data governance), the full
**Annex IV** technical file, and **Art. 26** deployer duties are `documented`
with a null reference — they are not, and cannot be, discharged by the OS alone.
No entry claims the operating system itself "is compliant."

## Mechanism vocabulary

Each control maps to exactly one AIOS enforcement mechanism. The vocabulary
covers spec §11's "Control mapping requirements" list:

| `aios_mechanism`    | What it means                                               | Typical `enforcement_ref`                                                   |
| ------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------- |
| `aios-policy`       | Policy Kernel rule (default-deny, hard-deny, approval gate) | `crates/aios-policy/src/*.rs`                                               |
| `systemd-hardening` | systemd unit sandboxing directive                           | `distro/systemd/*.service::<directive>`                                     |
| `selinux`           | SELinux enforcing mode / policy / confined domain           | `distro/aios-boot/aios-config.toml`, `distro/desktop/confine/selinux/*.te`  |
| `kernel-config`     | Kernel build-time hardening flag                            | `distro/aios-boot/kernel-config::CONFIG_*`                                  |
| `evidence-log`      | Append-only, hash-chained evidence record                   | `distro/systemd/aios-evidence-log.service`, `crates/aios-evidence/src/*.rs` |
| `boot-integrity`    | dm-verity / boot-chain / measured boot                      | `distro/build/build-aios-iso.sh`, `distro/aios-boot/aios-config.toml`       |
| `update-signature`  | Signed release / repo / N-of-M operator signatures          | `distro/update/aios-update.sh`, `distro/repo/aios-repo-publish.sh`          |

## Status: enforced vs partial vs documented

`status` states **honestly** how far the control is actually realised in-tree:

- **`enforced`** — a concrete mechanism is present in the image and its
  `enforcement_ref` resolves to the exact directive / flag / code token.
  The gate proves the reference; the mechanism does the work.
- **`partial`** — the mechanism exists but coverage is incomplete (e.g. one
  SELinux domain is confined but not the whole service set; the boot-chain
  manifest is produced but full Secure Boot signing depends on firmware). A
  resolvable `enforcement_ref` is still required.
- **`documented`** — aspirational / roadmap. The control is acknowledged but
  **not yet enforced in-tree**. `enforcement_ref` is `null` and the gate does
  not require a resolving reference. This is the honest label for controls such
  as data-at-rest LUKS encryption, host firewall default-deny, and root-SSH
  lockout, which are not shipped as concrete artifacts in this revision.

`enforced` and `partial` controls **must** carry a non-null, resolving
`enforcement_ref` — the validator rejects them otherwise. This is what stops a
control map from drifting into fiction.

## `enforcement_ref` resolution (the anti-fake gate)

Format: a repo-relative path, optionally suffixed with `::<literal-marker>`:

```
distro/systemd/aios-policy-kernel.service::ProtectSystem=strict
distro/aios-boot/kernel-config::CONFIG_RANDOMIZE_BASE=y
crates/aios-evidence/src/chain.rs::append-only
null            # documented-only control
```

`validate-controls.py` resolves each reference by:

1. splitting off the optional `::marker`;
2. requiring the path to exist as a regular file under the repo root;
3. when a marker is present, requiring that exact substring to appear in the
   file's text.

A control that cites a directive/flag which is later removed from the image
will **fail the gate**, so the map cannot silently rot away from reality.

## Regenerate / audit

```bash
# Validate + print per-baseline / per-status counts:
python3 distro/compliance/validate-controls.py

# Machine-readable use (exit code only, no summary):
python3 distro/compliance/validate-controls.py --quiet

# Full release-gate test (asserts green on real map, red on tampered maps):
TMPDIR="$HOME/.tmp-aios" bash distro/build/tests/test-rev13-compliance.sh
```

Adding or changing a control means editing `controls.json`; the gate then
forces the new `enforcement_ref` to resolve before the change can land.

## Audit evidence export (spec §11 "Audit export requirements")

The two required export forms are:

- **Machine-readable JSON** — `controls.json` itself is the control matrix. It
  is stable, diffable, and consumable by an auditor's tooling.
- **Operator-readable** — the validator's summary (counts per baseline and per
  status) is the human view; the tables in this README describe the model.

For a release candidate, run the gate test and archive both `controls.json` and
the validator's stdout alongside the release artifact manifest, SBOM
(`aios/sbom.cdx.json`), and provenance (`aios/provenance.json`) produced by
`distro/build/build-aios-iso.sh`. The `evidence_record_type` field on a control
links it to the append-only evidence stream (e.g. `POLICY_DECISION`,
`SEGMENT_SEALED`, `CHAIN_CHECKPOINT`, `TAMPER_DETECTED`) defined in
`crates/aios-evidence/src/record.rs`, so a control can be traced from claim →
mechanism → generated runtime evidence.

## Relationship to the crate `ControlMapRegistry`

The Rust workspace already owns the **runtime** compliance surface
(`crates/aios-integration/src/control_map.rs`, M18 closure):

- `ControlMapRegistry` maps AIOS invariants (`INV-001…INV-024`) to external
  control **families** (`ControlFrameworkRef`: NIST 800-53, STIG, CIS, FIPS);
- it produces immutable `ComplianceBaseline` snapshots and computes
  `ControlDriftReport`s (added / removed / modified / unchanged);
- it emits chain-of-custody evidence via the integration emitter.

This directory does **not** re-implement any of that. It is the complementary
**build-artifact** layer:

| Concern     | Crate `ControlMapRegistry`         | `distro/compliance/controls.json`                              |
| ----------- | ---------------------------------- | -------------------------------------------------------------- |
| Granularity | AIOS invariant ↔ control family    | Individual CIS/STIG control ↔ concrete file                    |
| Lives at    | Runtime (in-process registry)      | Build artifact (static JSON)                                   |
| Proves      | Drift vs a prior baseline snapshot | That each enforcement reference physically exists in the image |
| Standards   | NIST / STIG / CIS / FIPS families  | CIS + STIG per-control checks                                  |

Together they satisfy the spec's requirement that "compliance claims must map
to concrete controls, generated evidence, and release gates": the registry
handles families, drift, and evidence emission; this artifact grounds each
concrete control in a file the release actually ships and gates it in CI.
