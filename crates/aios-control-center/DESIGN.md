# AIOS Control Center (L7) — Design

**Crate:** `aios-control-center` · **Layer:** L7 (Renderers / Interaction) ·
**Status of this scaffold:** `SHELL` for the transport/backend hop,
`REAL`(E3) for the typed-action taxonomy + exposure-decision path.

---

## 1. What this is (and the three-tier product picture)

AIOS ships **three** distinct operator-facing surfaces. They are complementary,
not competitors:

| Tier               | Surface                              | Role                                                                                                                                               | Owner                             |
| ------------------ | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| Classic admin      | **Cockpit** (or equivalent)          | Traditional per-service Linux admin (logs, resource graphs, raw units). Direct system calls, no cognitive/policy layer.                            | ecosystem tool, out of scope here |
| **Governed admin** | **AIOS Control Center** (this crate) | The differentiator: every _mutating_ operator action is a **typed** action → **PolicyKernel** decision → **evidence** receipt. No free-form shell. | `aios-control-center`             |
| Installer          | **Agama** (R13.6)                    | openSUSE Agama-based first-install / re-provision flow.                                                                                            | `distro/`                         |

**This crate is scoped to the middle tier only.** It is _not_ a new transport,
not an installer, and not a classic control panel. It is an **application on top
of the existing L7 Web renderer** (`aios-renderer-web`).

### The law this crate exists to enforce

> **The operator proposes; the system decides and executes.**
> A mutating action from the panel is emitted as a _typed_ `ControlAction`,
> routed through the **Policy Kernel** (`aios.policy.PolicyKernel`), and only
> reflected in the UI **after** a policy decision plus an **evidence** receipt.
> The panel never shells out and never calls a system API directly.

A normal Linux control panel calls `systemctl restart X` on button click. The
Control Center instead emits a _typed proposal_ that a policy kernel may
`Allow` / `RequireApproval` / `Deny`, and every step is evidence-logged. That
governance chain is the product differentiator.

---

## 2. Reuse map — what we consume from `aios-renderer-web`

This crate adds **no** new transport. It depends only on `aios-renderer-web`
(which itself re-exports `aios-policy`, `aios-evidence`, `aios-action`) and
consumes these concrete modules:

| Reused item (from `aios-renderer-web`)                                       | Source module        | How the Control Center uses it                                                                                                                            |
| ---------------------------------------------------------------------------- | -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GrpcWebBridge`, `GrpcWebBridge::default_localhost_config`                   | `grpc_web_bridge.rs` | The origin allowlist + service allowlist + 4 MiB size ceiling. Every routed request passes this gate.                                                     |
| `GrpcWebClientStub::send`                                                    | `grpc_web_bridge.rs` | The client seam that validates a request through the bridge. **Echo stub today** → the real backend hop is the `CONTRACT` boundary (§5).                  |
| `ExposureLevel` (6-variant FSM marker)                                       | `exposure.rs`        | Config default = `Localhost`; the type carries `policy_decision_id` on every widened variant.                                                             |
| `ExposureFsm` (`request_lan_escalation`, `apply_policy_decision`, `current`) | `exposure_fsm.rs`    | Drives `Localhost → LanPending → LanApproved`. `apply_policy_decision` **requires a decision id** — this is INV I3 in code.                               |
| `InMemoryWebEvidenceEmitter` / `WebEvidenceEmitter::emit_exposure_granted`   | `evidence.rs`        | Emits the `WEB_EXPOSURE_GRANTED` receipt (FOREVER retention) when exposure widens. Backed by `aios_evidence::ReceiptChain`.                               |
| `WebRendererError`                                                           | `error.rs`           | Wrapped by `ControlCenterError::Renderer` — we reuse its `OriginVerificationFailed` / `ExposureEscalationDenied` variants rather than inventing new ones. |
| `WebEvidenceReceipt`                                                         | `evidence.rs`        | The receipt handle returned to the caller after a governed exposure change.                                                                               |

Transitive backend contracts we target by fully-qualified name (already in the
bridge's default service allowlist): `aios.sgr.SgrService`,
`aios.evidence.EvidenceLog`, `aios.policy.PolicyKernel`.

---

## 3. Action taxonomy (`ControlAction`)

The panel exposes **exactly** this closed set — there is no free-form command
input (the adapter-level "no shell as primary input" rule, applied at L7).

| `ControlAction`                                | Mutating? | Target service              | Method             | Action → policy → evidence                                                                                                                                                                                            |
| ---------------------------------------------- | --------- | --------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ViewServiceHealth { service }`                | no        | `aios.sgr.SgrService`       | `GetServiceHealth` | Read-only. Routed through the bridge gate; returns data. No policy decision, no evidence.                                                                                                                             |
| `ViewEvidenceLog { limit }`                    | no        | `aios.evidence.EvidenceLog` | `TailReceipts`     | Read-only tail of the append-only log.                                                                                                                                                                                |
| `RequestServiceRestart { service }`            | **yes**   | `aios.policy.PolicyKernel`  | `EvaluatePolicy`   | Emits a typed proposal `{verb: "service.restart", target}`. Routed to the kernel; stops at `PolicyPending`. Execution + its evidence happen **after** an `Allow` decision, via the Capability Runtime (CONTRACT, §5). |
| `RequestLanExposure { approver_canonical_id }` | **yes**   | `aios.policy.PolicyKernel`  | `EvaluatePolicy`   | Advances `ExposureFsm` to `LanPending`; the widening to `LanApproved` requires `apply_lan_exposure_decision(decision_id)`, which emits `WEB_EXPOSURE_GRANTED`.                                                        |

Each `ControlAction::route()` yields a `RoutedRequest { service_fqn, method,
payload (canonical JSON bytes), mutating }`. Mutating variants **never** target
a domain service directly — they target the Policy Kernel.

### Outcome type

`submit_action` returns `ActionOutcome`, which has **no `Executed` variant** by
construction:

- `Data { service_fqn, payload }` — a read-only response.
- `PolicyPending { routed }` — a mutating proposal was routed to the kernel and
  awaits a decision. The panel does not proceed on its own.

---

## 4. Localhost / exposure model

- `ControlCenterConfig` defaults to `ExposureLevel::Localhost` — bind to
  loopback only, no evidence required. `is_localhost_only()` reflects this.
- Widening is possible **only** through the reused `ExposureFsm`:
  `Localhost → LanPending` (`RequestLanExposure`) → `LanApproved`
  (`apply_lan_exposure_decision`, which **rejects an empty decision id** with
  `ControlCenterError::MissingDecisionId`).
- Every widened `ExposureLevel` variant carries a `policy_decision_id`, and the
  transition emits a `WEB_EXPOSURE_GRANTED` evidence receipt. `Public` exposure
  additionally requires recovery-mode authorization (modeled by the reused FSM;
  not surfaced by the panel in this scaffold).

---

## 5. The `action → policy → evidence` seam — real vs CONTRACT (honest)

**Real today (E3, unit-tested):**

- The typed taxonomy and the read-only / mutating routing split.
- Every `submit_action` passes the **real** `GrpcWebBridge` gate via
  `GrpcWebClientStub::send` (origin allowlist + service allowlist + size ceil).
- The **LAN-exposure-requires-a-decision-id** path runs the real `ExposureFsm`
  and emits a real `aios_evidence`-backed receipt.

**`CONTRACT` boundary (deployment task, marked `// CONTRACT:` at the seam in
`submit_action`):** `GrpcWebClientStub::send` is an **echo stub** — it validates
the gate but does not reach a live backend. A real deployment wires the bridge
to a tonic `Channel` so that:

- read-only actions reach `SgrService` / `EvidenceLog` and return real data, and
- mutating proposals reach `PolicyKernel.EvaluatePolicy`, whose `PolicyDecision`
  (`Allow` / `RequireApproval` / `Deny`, from `aios_policy::decision`) gates the
  domain effect, which the **Capability Runtime** then executes and evidences.

**No execution is simulated.** A mutating action terminates at `PolicyPending`;
nothing in this crate turns a proposal into a system effect.

---

## 6. Taxonomy grade & what E3+ requires next

| Capability                                         | Grade now  | To advance                                                                                  |
| -------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------- |
| Typed action taxonomy + routing                    | `REAL` E3  | — (unit-tested)                                                                             |
| Bridge-gate enforcement on submit                  | `REAL` E3  | — (reuses tested bridge)                                                                    |
| LAN exposure requires decision id + evidence       | `REAL` E3  | — (unit-tested)                                                                             |
| Read-only action → real backend data               | `SHELL`    | Wire `GrpcWebClientStub` to a tonic `Channel` reaching `SgrService`/`EvidenceLog`.          |
| Mutating action → live `PolicyKernel` decision     | `CONTRACT` | Reach `PolicyKernel.EvaluatePolicy` with a real `ActionEnvelope`; consume `PolicyDecision`. |
| Proposal → Capability Runtime execution + evidence | `CONTRACT` | Post-decision execution path (owned by `aios-capability-runtime`, not this crate).          |
| HTTP serving / Next.js front-end                   | `DEFERRED` | Reuse `aios-renderer-web` `https.rs` listener; not in this scaffold's scope.                |

## 7. Dependencies

- `aios-renderer-web` (path) — sole AIOS dependency; re-exports the policy /
  evidence / action crates this crate references.
- `serde` / `serde_json` — typed action payload encoding.
- `thiserror` — `ControlCenterError`.
- `tracing` — structured logging seam.
- `tokio` (dev) — async unit tests.
