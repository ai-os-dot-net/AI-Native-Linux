# AI-OS.NET Security — R13.8 CVE Lifecycle

This directory holds the **distro-level operator process and tooling** for the
R13.8 CVE intake / triage / patch / advisory lifecycle
(spec: `distro/build/REV13-ENTERPRISE-SPEC.md` §11, with SLA/EOL numbers from
§4 / R13.1).

It is the **process layer around** the typed CVE model that already lives in
the Rust workspace — it does **not** re-implement it. The CVSS→severity
thresholds and CVE-id grammar used here are deliberately mirrored from the
crates so the operator record and the install gate never disagree:

| Concern                                  | Authoritative crate implementation                                      |
| ---------------------------------------- | ----------------------------------------------------------------------- |
| CVE-id grammar (`CVE-YYYY-NNNN+`)        | `crates/aios-integration/src/cve_feed.rs:94-108` `is_valid_cve_id()`    |
| CVSS range check (`0.0..=10.0`)          | `crates/aios-integration/src/cve_feed.rs:166` `ingest_record()`         |
| CVSS → enforcement level                 | `crates/aios-integration/src/cve_feed.rs:75-85` `cvss_to_enforcement()` |
| CVSS → enforcement (distribution FSM)    | `crates/aios-distribution/src/cve_binding.rs:61-66`                     |
| Severity enum (Low<Medium<High<Critical) | `crates/aios-integration/src/cve.rs:3-14` `CveSeverity`                 |
| Remediation status enum                  | `crates/aios-integration/src/cve.rs:16-29` `CveStatus`                  |

## Tooling

- `aios-cve-triage.sh` — the CVE lifecycle tool (bash + jq).
- `README.md` — this document.
- Gate test: `distro/build/tests/test-rev13-cve-process.sh`.

## Lifecycle state machine (spec §11 steps 1–7)

```
intake ──▶ triaged ──▶ patched ──▶ released ──▶ advisory
```

| State      | Spec step | Meaning                                                                          |
| ---------- | --------- | -------------------------------------------------------------------------------- |
| `intake`   | 1         | Vulnerability feed/advisory ingested.                                            |
| `triaged`  | 2–3       | Affected package assigned, severity + affected releases fixed, SLA deadline set. |
| `patched`  | 4         | Patch or mitigation applied.                                                     |
| `released` | 5–6       | Signed security update built and enterprise gates run.                           |
| `advisory` | 7         | Operator + machine-readable advisory published.                                  |

Transitions are **forward-only, single-step**. The per-CVE event log is
**append-only**: existing events are never rewritten, and re-triaging an
already-triaged CVE is an idempotent no-op. Deployment tracking / rollback
signals (step 8) are emitted by the runtime crates, not by this tool.

## Intake sources

The tool accepts a normalized CVE record from either CLI arguments or a JSON
file (`--json`). Expected upstream feeds (mapped into that normalized shape):

- NVD / NIST CVE feed (`cve_id`, `cvss_v3_score`, affected CPE/purl).
- OSV / GitHub Security Advisories (Rust crates, language deps).
- openSUSE Leap security updates (RPM base packages, kernel, firmware).
- AIOS-native findings (AIOS Rust crates and AIOS code).

Triage must cover **affected packages, kernel, firmware, Rust crates, and AIOS
code** (spec §11 step 2).

## Triage decision table

CVSS v3 base score → severity → enforcement (R12.4 install gate) → remediation SLA:

| CVSS v3 band | Severity | R12.4 install-gate enforcement                  | Remediation SLA | Source                            |
| ------------ | -------- | ----------------------------------------------- | --------------- | --------------------------------- |
| `>= 9.0`     | Critical | `AutoQuarantine` (block/quarantine now)         | **7 days**      | REV13 §4 (spec-mandated)          |
| `7.0 – 8.9`  | High     | `QuarantineCandidate` (propose, await approval) | **30 days**     | REV13 §4 (spec-mandated)          |
| `4.0 – 6.9`  | Medium   | `OperatorNotify` (warn)                         | 90 days         | operational default (NOT in spec) |
| `< 4.0`      | Low      | `MonitorOnly` (notify only)                     | 180 days        | operational default (NOT in spec) |

> **SLA authority:** only the Critical (7d) and High (30d) targets are fixed by
> the spec (`REV13-ENTERPRISE-SPEC.md` §4: _"Security SLA | Critical: 7 days
> target; High: 30 days target"_). The Medium (90d) and Low (180d) deadlines
> are operational defaults chosen here and are **not** spec-mandated — change
> them freely without a spec change.

The SLA **deadline** is computed as `triage-date + SLA-days` (UTC) and stored in
the triage event and rendered into every advisory.

## Patch / release / advisory flow

1. **Intake + triage** — `aios-cve-triage.sh triage ...` (states intake→triaged).
2. **Patch** — apply fix/backport, then `aios-cve-triage.sh advance --to patched`.
3. **Release** — build the **signed** security update and run enterprise gates
   (R12.4 signed repo/update model, REV12 §7; R13.7 CI gates), then
   `advance --to released`.
4. **Advisory** — `aios-cve-triage.sh advisory --id CVE-...` renders:
   - operator-readable **Markdown** advisory, and
   - machine-readable **JSON** advisory (`schema: aios.advisory.v1`),
     satisfying the §11 audit-export requirement (operator-readable + machine-readable).
     Then `advance --to advisory` to record publication in the lifecycle log.

## Tie-in to the R12.4 CVE-aware install pipeline

The severity band chosen at triage maps 1:1 to the enforcement level the
**typed R12.4 pipeline** applies at install/update time. `AutoQuarantine`
(Critical, CVSS ≥ 9.0) blocks the package immediately with FOREVER evidence;
`QuarantineCandidate` (High) proposes quarantine pending operator approval.
That enforcement is implemented and gated in-crate
(`crates/aios-distribution/src/cve_binding.rs` `apply_cve_binding`,
`crates/aios-integration/src/cve_feed.rs`), **not** in this shell tool — the
tool records the human lifecycle and echoes the enforcement band so the
advisory tells the operator exactly how the install gate will behave.

## EOL / support-window policy (spec §4 / R13.1)

| Property             | Value                                                              | Source    |
| -------------------- | ------------------------------------------------------------------ | --------- |
| Base family          | openSUSE Leap 16.x (primary 16.0)                                  | REV13 §4  |
| Supported arch       | `x86_64` (first gate); `aarch64` after CI proof                    | REV13 §4  |
| LTS window           | **24 months** per minor release                                    | REV13 §4  |
| EOL date             | **2027-10-31** (default Leap 16.0 builder metadata)                | REV13 §4  |
| Security SLA         | Critical 7d / High 30d                                             | REV13 §4  |
| Upgrade policy       | Leap 16.x minor upgrades only until a major-upgrade gate exists    | REV13 §4  |
| Emergency patch path | out-of-cadence signed update through the same triage→released flow | REV13 §11 |
| Backport policy      | fixes backported onto the supported Leap 16.x base kernel/packages | REV13 §11 |

## Usage

```sh
# Intake + triage (from args)
./aios-cve-triage.sh triage \
    --id CVE-2026-12345 --cvss 9.8 \
    --package pkg:rpm/openssl@3.1.0 --fixed-version 3.1.4 \
    --summary "heap overflow in TLS record parsing" \
    --state-dir /var/lib/aios/cve

# Intake + triage (from a JSON feed record)
./aios-cve-triage.sh triage --json advisory.json --state-dir /var/lib/aios/cve

# Advance the lifecycle
./aios-cve-triage.sh advance --id CVE-2026-12345 --to patched  --note "backported"
./aios-cve-triage.sh advance --id CVE-2026-12345 --to released

# Render advisory (markdown + JSON) and record publication
./aios-cve-triage.sh advisory --id CVE-2026-12345
./aios-cve-triage.sh advance  --id CVE-2026-12345 --to advisory

# Inspect
./aios-cve-triage.sh show --id CVE-2026-12345
./aios-cve-triage.sh list
```

State dir defaults to `$AIOS_CVE_STATE_DIR` or `./cve-state`. Layout:

```
<state-dir>/records/<CVE-ID>.jsonl     append-only event log (one JSON per line)
<state-dir>/advisories/<CVE-ID>.md     rendered operator advisory
<state-dir>/advisories/<CVE-ID>.json   rendered machine-readable advisory
```
