# AI-OS.NET Daemon Architecture (R13.3 — frozen contract)

Status: **REAL (E3)** for the model choice, the required/optional split, the
dependency graph, and the hardening gate — every claim below is checkable against
the unit files in this directory and enforced by
`distro/build/tests/test-rev13-daemon.sh` + `distro/systemd/aios-security-score.sh`.
Where a criterion is groundwork rather than proven-in-production, it is marked
`PARTIAL` / `CONTRACT` inline.

This document freezes the daemon/service contract required by
`distro/build/REV13-ENTERPRISE-SPEC.md` §6 (R13.3). It is the operator-facing
source of truth for service names, responsibilities, dependencies, restart /
failure behaviour, and per-class hardening.

---

## 1. Chosen model: **Hybrid** (supervisor core + isolated high-risk daemons)

AIOS runs the **Hybrid** model from the R13.3 decision table.

**Justification (grounded in code, not preference).**
`crates/aios-integration/src/bin/aios_system.rs` defines a single
`aios-system` binary with a `run-service <id>` subcommand. Every AIOS-owned
daemon unit invokes exactly that binary — e.g.
`ExecStart=/usr/lib/aios/aios-system run-service aios-policy-kernel …`. The
binary normalises the requested unit name to a canonical service slot
(`normalize_service_id`, `SERVICE_ALIASES`, `EXTRA_SERVICE_IDS`), writes a
readiness state file to `/var/lib/aios/state/<id>.json`
(`run_service_slot` → `write_service_state`), and stays resident. So the 34-crate
workspace ships **one supervisor executable** that presents each layer's daemon
as a systemd-managed slot — that is the _Supervisor_ half of Hybrid.

The **isolated** half: two units do **not** run through the supervisor because
they are third-party inference engines with their own process models and no AIOS
SELinux type — `aios-ollama.service` (`ExecStart=/usr/bin/ollama serve`) and
`aios-vllm.service` (`ExecStart=/usr/bin/python3 -m vllm.entrypoints…`). Three
further units are standalone helpers rather than long-lived slots:
`aios-first-boot.service` (its own `aios-first-boot` binary),
`aios-health-report.service` (a POSIX-sh reporter), and
`aios-update-confirm.service` (an update shell hook).

Pure _Multi-daemon_ is therefore false (one binary backs every AIOS slot); pure
_Supervisor_ is also false (ollama/vllm are deliberately isolated). **Hybrid** is
the honest description.

> Note on the current slot implementation: `run_service_slot` is a resident
> readiness-state scaffold (it writes state then blocks). The _daemon
> architecture, naming, dependency, and hardening contract_ frozen here is REAL;
> the per-slot business logic wired behind each slot is tracked separately in
> `MILESTONES.md` and is not re-litigated by this document.

---

## 2. Required services

"Required" = the L0–L4 cognitive-shell substrate plus the elevated-capability
base daemons that must reach a healthy (active) state after boot for the system
to be functional. These are the units the security gate treats as **gated**
(class `required-core` / `required-high-risk` in `aios-security-score.sh`).
Membership is derived from the `Requires=` graph in the unit files plus the
pre-`capability-runtime` `Before=` core.

All required daemons run as `aios-system run-service <id>`, `Type=simple`, and
carry the full core hardening set (see §5).

| Service                   | Layer | Responsibility                         | Type   | Restart | RestartSec | Requires / After (key)                                        | Failure behaviour                                                                                                                               |
| ------------------------- | ----- | -------------------------------------- | ------ | ------- | ---------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `aios-policy-kernel`      | L4    | Policy decisions (allow/deny/approval) | simple | always  | 3          | `Before=capability-runtime`                                   | Restarts forever; capability-runtime hard-`Requires=` it, so a persistently-failed policy kernel takes capability-runtime down (fail-closed).   |
| `aios-evidence-log`       | L0    | Append-only evidence log               | simple | always  | 3          | `Before=capability-runtime`                                   | Restarts forever; hard dependency of capability-runtime, fs-daemon, sandbox, recovery. Fail-closed.                                             |
| `aios-vault-broker`       | L4    | Secrets-as-capabilities broker         | simple | always  | 3          | `Before=capability-runtime`                                   | Restarts forever; capability-runtime `Wants=` it (soft) so vault flap degrades but does not hard-stop the runtime.                              |
| `aios-capability-runtime` | L4    | Typed-action execution + verification  | simple | always  | 5          | `Requires=policy-kernel,evidence-log`; `After=network.target` | Restarts forever; if policy-kernel or evidence-log are down it refuses to start (fail-closed). High-risk (CAP_NET_BIND_SERVICE, CAP_SYS_ADMIN). |
| `aios-fs-daemon`          | L2    | AIOS-FS semantic object store          | simple | always  | 3          | `Requires=policy-kernel,evidence-log`                         | Restarts forever; fail-closed on missing policy/evidence.                                                                                       |
| `aios-sandbox-composer`   | L6    | Sandbox/runtime composition            | simple | always  | 3          | `Requires=evidence-log`; `Before=capability-runtime`          | Restarts forever; fail-closed on missing evidence log.                                                                                          |
| `aios-sgr-daemon`         | L3    | Service Graph Runtime (desired state)  | simple | always  | 5          | `Requires=capability-runtime,policy-kernel`                   | Restarts forever; fail-closed if runtime/policy absent.                                                                                         |
| `aios-recovery-watchdog`  | L9    | Recovery/self-heal watchdog            | simple | always  | 5          | `Requires=capability-runtime,evidence-log`                    | Restarts forever; core recovery path must not depend on L5 cognition.                                                                           |
| `aios-network-daemon`     | L8    | Network policy enforcement             | simple | always  | 5          | `Requires=capability-runtime,policy-kernel`                   | Restarts forever; high-risk (CAP_NET_ADMIN/RAW/BIND).                                                                                           |
| `aios-hardware-daemon`    | L8    | Hardware graph + device access         | simple | always  | 5          | `Requires=capability-runtime`                                 | Restarts forever; high-risk (CAP_SYS_ADMIN/RAWIO).                                                                                              |

Ten required daemons. `network-daemon` and `hardware-daemon` are included in the
**required** set specifically because they hold elevated capabilities and must
therefore always satisfy the high-risk hardening rule; this is a conservative
policy choice (gating more units, not fewer) and is enforced by the score gate.

---

## 3. Optional services

"Optional" = feature daemons above the core shell (L5/L6/L7/L10), the isolated
inference engines, and the oneshot helpers. **None of these may block boot** — see
§4 for why that is structurally guaranteed. They are reported by the security
scorer but are **not gated** (some legitimately relax directives: third-party
inference binaries have no AIOS SELinux type; oneshot reporters need no
`Restart=`).

| Service               | Layer | Responsibility                    | Type    | Restart    | Enabled at boot?                                   | Non-blocking mechanism                                                                                                                  |
| --------------------- | ----- | --------------------------------- | ------- | ---------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `aios-cognitive-core` | L5    | Intent/planning/model routing     | simple  | always     | via `aios.target` `Wants=`                         | Soft `Wants=` from target; **core invariant: L1 recovery must not depend on L5**, so it is optional by design.                          |
| `aios-fleet`          | L7    | Fleet/cluster coordinator         | simple  | always     | via `Wants=`                                       | Soft `Wants=`; no unit hard-`Requires=` it.                                                                                             |
| `aios-container`      | L6    | Container/app runtime             | simple  | always     | via `Wants=`                                       | Soft `Wants=`; `Requires=sandbox-composer` internally but nothing requires container.                                                   |
| `aios-terminal`       | L7    | Terminal/renderer daemon          | simple  | always     | via `Wants=`                                       | Soft `Wants=`.                                                                                                                          |
| `aios-autonomous`     | L10   | Autonomous orchestrator           | simple  | always     | via `Wants=`                                       | Soft `Wants=fleet` + soft target `Wants=`.                                                                                              |
| `aios-marketplace`    | L10   | Marketplace indexer               | simple  | on-failure | via `Wants=`                                       | Soft `Wants=`; `Restart=on-failure` (not a boot-critical loop).                                                                         |
| `aios-ollama`         | L5    | Local inference (Ollama)          | simple  | on-failure | **no** (not symlinked)                             | Isolated external binary; started on demand, never enabled by the ISO build.                                                            |
| `aios-vllm`           | L5    | High-performance inference (vLLM) | simple  | on-failure | **no** (`ConditionPathExists=/dev/dri/renderD128`) | Isolated; conditional on a GPU render node; `Requires=ollama`.                                                                          |
| `aios-first-boot`     | L1    | First-boot wizard                 | oneshot | —          | via `Wants=`                                       | `ConditionPathExists=/etc/aios/first-boot`; oneshot, `RemainAfterExit=no`.                                                              |
| `aios-hardening`      | L9    | Hardening scanner (one pass)      | oneshot | —          | via `Wants=`                                       | `--once`, `RemainAfterExit=yes`; a scan pass, not a resident service.                                                                   |
| `aios-update-confirm` | L9    | Post-update boot confirmation     | oneshot | —          | via `Wants=`                                       | `ConditionPathExists=/var/lib/aios/update/pending-boot.json`; runs only after an update.                                                |
| `aios-health-report`  | L9    | Boot-time health verdict          | simple  | —          | **yes** (symlinked to `multi-user.target.wants`)   | Emits the `AIOS-HEALTH:` verdict line; `Type=simple` + `RemainAfterExit=yes` (a oneshot here deadlocks boot — see the in-file comment). |

---

## 4. Dependency graph (why optional units cannot block boot)

Only **two** symlinks are created by `distro/build/build-aios-iso.sh` (Step 5):
`multi-user.target.wants/aios.target` and
`multi-user.target.wants/aios-health-report.service`. Everything else is pulled
**only** through `aios.target`'s `Wants=` line — and `Wants=` is a _soft_
dependency: a failed `Wants=` member never fails the depending unit. The internal
`Requires=` edges are between AIOS services and never propagate up to
`multi-user.target`. Therefore any optional (or even required) service can fail
without failing the boot transaction; the boot gate then reports `DEGRADED`
rather than hanging.

```
multi-user.target
├─ (wants) aios-health-report.service   ── emits "AIOS-HEALTH: RUNNING|DEGRADED"
└─ (wants) aios.target
   │  aios.target Wants= (ALL soft):
   │
   ├─ REQUIRED core (Type=simple, Restart=always)
   │   aios-evidence-log ──┐
   │   aios-policy-kernel ─┤ (Before=capability-runtime)
   │   aios-vault-broker ──┘
   │        │  Requires=
   │        ▼
   │   aios-capability-runtime  (Requires=policy-kernel,evidence-log)
   │        │  Requires=
   │        ├─ aios-fs-daemon           (Requires=policy-kernel,evidence-log)
   │        ├─ aios-sandbox-composer    (Requires=evidence-log)
   │        ├─ aios-sgr-daemon          (Requires=capability-runtime,policy-kernel)
   │        ├─ aios-recovery-watchdog   (Requires=capability-runtime,evidence-log)
   │        ├─ aios-network-daemon      (Requires=capability-runtime,policy-kernel) [high-risk]
   │        └─ aios-hardware-daemon     (Requires=capability-runtime)               [high-risk]
   │
   ├─ OPTIONAL feature daemons (soft Wants only)
   │   aios-cognitive-core (L5) ─ aios-fleet (L7) ─ aios-container (L6)
   │   aios-terminal (L7) ─ aios-autonomous (L10) ─ aios-marketplace (L10)
   │
   ├─ OPTIONAL oneshot helpers
   │   aios-first-boot ─ aios-hardening ─ aios-update-confirm
   │
   └─ ISOLATED inference (NOT enabled by the build; on-demand)
       aios-ollama ─ aios-vllm (Requires=ollama, ConditionPathExists=/dev/dri/renderD128)
```

Load-bearing ordering facts that MUST be preserved (hard-won boot fixes):

- `aios-health-report.service` is `Type=simple` (a `oneshot` deadlocks boot).
- `aios-hardening.service` orders `After=aios-evidence-log.service`, **not**
  `After=multi-user.target`, to avoid an ordering cycle that makes systemd skip it.
- Every `run-service` unit lists `/var/lib/aios/state` in `ReadWritePaths=` so the
  readiness-state write is not denied under `ProtectSystem=strict`.
- `SELinuxContext=-system_u:…` keeps the leading `-` (ignore-prefix) so a missing
  SELinux type does not fail the unit on a non-SELinux host.

---

## 5. Per-service-class hardening policy

Enforced by `distro/systemd/aios-security-score.sh` (exposure-point model, 0 = fully
hardened). Directives below are present in the actual unit files today.

| Class                            | Members                                                                                                                   | Required directives (gated)                                                                                                      | Extra directives present                                                                                                                                                                            |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **required-core**                | policy-kernel, evidence-log, vault-broker, capability-runtime, fs-daemon, sandbox-composer, sgr-daemon, recovery-watchdog | `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, `SELinuxContext=-…`, `ReadWritePaths=…/state`, `Restart=always` | `LimitNOFILE=65536`                                                                                                                                                                                 |
| **required-high-risk**           | capability-runtime, network-daemon, hardware-daemon                                                                       | core set **plus** `CapabilityBoundingSet=` (least-privilege cap set)                                                             | `ProtectHome=yes` (capability-runtime); `LimitMEMLOCK=infinity` where model-adjacent                                                                                                                |
| **network / isolated inference** | ollama, vllm                                                                                                              | reported only (not gated)                                                                                                        | `ProtectSystem=strict`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `ReadWritePaths=`, `MemoryMax=`, `CPUQuota=`/`IPAccounting=`. No AIOS `SELinuxContext` (third-party binary) — flagged, not failed. |
| **optional feature daemons**     | cognitive-core, fleet, container, terminal, autonomous, marketplace                                                       | reported only                                                                                                                    | full core set is in fact present; `marketplace` uses `Restart=on-failure`.                                                                                                                          |
| **oneshot helpers**              | first-boot, hardening, update-confirm, health-report                                                                      | reported only                                                                                                                    | oneshots legitimately omit `Restart=`; health-report omits `ProtectSystem` so it can read `systemctl`/`journalctl` and write `/dev/console`.                                                        |

Gate rule: a **required-core** or **required-high-risk** unit whose exposure
exceeds the threshold (default 30 EP) makes `aios-security-score.sh` exit
non-zero, which BLOCKS the enterprise release. Optional/isolated/oneshot units are
reported for visibility only.

`systemd-analyze security` is the spec's named tool; because it is absent from the
CI image and its score is environment-dependent (non-hermetic, contra R13.2), the
**static scorer is the deterministic gate** and `--systemd-analyze` is offered as
an advisory, non-gating cross-check (**PARTIAL** — E1/E2 only when present).

---

## 6. Health-check mechanism

Health is asserted at boot by `aios-health-report.service` →
`/usr/lib/aios/aios-health-report.sh` (source:
`distro/aios-boot/aios-health-report.sh`, POSIX sh). It waits for
`systemctl is-system-running --wait`, collects `systemctl --failed`, and emits
exactly one verdict line to `/dev/console`:

```
AIOS-HEALTH: RUNNING
AIOS-HEALTH: DEGRADED failed=<comma-separated units>
```

plus `AIOS-HEALTH-DETAIL:` / `AIOS-HEALTH-JOURNAL:` diagnostic lines per failed
unit. `distro/build/qemu-boot-smoke.sh --require-health` treats
`AIOS-HEALTH: RUNNING` as the pass signal from the serial log — no guest agent
required. This is the runtime evidence for the acceptance criteria
"required services reach healthy state" and "optional services do not block boot"
(**REAL/E4** via the QEMU boot gate; the per-slot readiness scaffold behind each
service is tracked in `MILESTONES.md`).

Per-slot readiness state is additionally written by the supervisor to
`/var/lib/aios/state/<id>.json` (`write_service_state` in `aios_system.rs`).

---

## 7. Acceptance-criteria traceability (R13.3)

| Criterion                                        | Status                        | Evidence                                                                                                                                                                  |
| ------------------------------------------------ | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Enabled enterprise units match staged binaries   | **REAL (E3)**                 | `build-aios-iso.sh` Step 5 fails the build if any unit's `ExecStart` `/usr/lib/aios/*` binary is missing; `test-rev13-daemon.sh` cross-checks documented ⇄ present units. |
| Required services reach healthy state after boot | **REAL (E4, scaffold slots)** | QEMU boot gate asserts `AIOS-HEALTH: RUNNING`; required units are `Restart=always`. Business logic per slot: see `MILESTONES.md`.                                         |
| Optional services do not block boot              | **REAL (E3)**                 | Structural: only `aios.target`+`health-report` are enabled; all members are soft `Wants=`. Asserted by `test-rev13-daemon.sh`.                                            |
| Hardening score below threshold blocks release   | **REAL (E3)**                 | `aios-security-score.sh` exits non-zero on any over-threshold required unit; proven with a synthetic bad unit in `test-rev13-daemon.sh`.                                  |
| Service restart/failure behaviour is tested      | **REAL (E3)**                 | `test-rev13-daemon.sh` asserts `Restart=`/`RestartSec=` per required unit and the fail-closed `Requires=` edges.                                                          |
