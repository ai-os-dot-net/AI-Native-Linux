# AIOS Remote Browser Desktop — Selkies Integration Design (Stream B1)

| Field  | Value                                                                                                               |
| ------ | ------------------------------------------------------------------------------------------------------------------- |
| Status | `CONTRACT` (design + scaffold only — no runtime proof from this environment)                                        |
| Layer  | L7 Interaction Renderers (binds to `002.AI-OS.NET--SPECREV.2/L7_Interaction_Renderers/05_web_renderer.md`, INV-006) |
| Scope  | `distro/remote/selkies/` (this dir) + one gate-test file under `distro/build/tests/`                                |
| Author | Claude Opus 4.8, subagent stream B1, 2026-07-19                                                                     |

## 1. Purpose

Reach the AIOS KDE Plasma (Wayland) desktop from an ordinary browser tab, using
[Selkies](https://selkies-project.github.io/selkies/) as the streaming layer,
without weakening the constitutional invariant that **the Web UI is
localhost-only by default; LAN/remote exposure requires explicit policy
approval** (Rev.2 L0 `INV-006`, restated in
`002.AI-OS.NET--SPECREV.2/L7_Interaction_Renderers/00_overview.md:14` and
implemented as the `WebExposureState` FSM in
`002.AI-OS.NET--SPECREV.2/L7_Interaction_Renderers/05_web_renderer.md` §5).

This document is a design + scaffold deliverable. It does **not** claim the
stream runs on AIOS today. See §7 for the explicit proven/unproven ledger.

## 2. What Selkies actually is, as of July 2026 (grounded, cited)

Research for this design surfaced a real fork in the Selkies ecosystem that
matters for the KDE-Wayland decision. Two lineages exist under the same
project name:

### 2.1 The official `selkies-project` KDE containers (X11/EGL — mature, NVIDIA-locked)

`selkies-project/docker-selkies-egl-desktop` and `docker-selkies-glx-desktop`
are described by their own README as "KDE Plasma Desktop container[s]
designed for Kubernetes, supporting OpenGL EGL and GLX, Vulkan, and
Wine/Proton for NVIDIA GPUs through WebRTC and HTML5"
([GitHub](https://github.com/selkies-project/docker-selkies-egl-desktop)).
Concretely, per their docs:

- KDE Plasma is the **only** supported desktop environment in these images.
- Rendering is **EGL/GLX over an X.Org X11 server** via VirtualGL — **not**
  Wayland. NVIDIA driver ≥450.80.02 + NVIDIA Container Toolkit are required.
- The container serves **both the Selkies WebRTC interface and a bundled
  KasmVNC interface on the same port, 8080** — this is the concrete origin
  of the "KasmVNC fallback" referenced in the task brief.
- TURN is configured via `SELKIES_TURN_HOST` / `SELKIES_TURN_PORT` /
  `SELKIES_TURN_PROTOCOL` / `TURN_MIN_PORT` / `TURN_MAX_PORT`; basic auth via
  `SELKIES_ENABLE_BASIC_AUTH` / `SELKIES_BASIC_AUTH_PASSWORD`.
- The project's own FAQ states explicitly: _"check that you are using X.Org
  instead of Wayland (which is the default in many distributions but not
  supported) when using an existing display"_
  ([Selkies FAQ](https://selkies-project.github.io/selkies/faq/)).

**This lineage cannot drive a Wayland/KWin AIOS desktop.** It requires an
NVIDIA GPU and an X11 session, both incompatible with the AIOS Rev.11/13
KDE Plasma **Wayland** desktop (`distro/desktop/`, SDDM autologin into a
Wayland session per `distro/desktop/session-manager.sh`).

### 2.2 The `selkies-project/selkies` core project + LinuxServer.io Webtop images (Wayland via pixelflux/Smithay — where `PIXELFLUX_WAYLAND` lives)

The core `selkies-project/selkies` repository has moved to a newer,
GPU/CPU-accelerated pipeline (nicknamed "pixelflux") built on
[Smithay](https://github.com/Smithay/smithay), a Rust Wayland-compositor
library. LinuxServer.io's Webtop images consume this stack and, as of their
4.1 release, this is the concrete grounding for `PIXELFLUX_WAYLAND`:

- _"We've now switched our Selkies desktop containers to run in Wayland mode
  by default, if for any reason you want to go back just set
  `-e PIXELFLUX_WAYLAND=false`."_ Requires an x86_64 CPU with AVX2
  (Haswell-class or newer); without AVX2 it falls back to X11.
- _"Complete Wayland KDE integration including clipboard, international
  input, and fractional scaling ... We run Kwin nested in our Smithay
  display socket and Plasma on top of it."_ — i.e. **KWin itself, not a
  wlroots compositor**, is nested inside the Smithay virtual framebuffer,
  which then hosts Plasma. This matches the task brief's requirement
  ("KWin, NOT wlroots").
  ([Webtop 4.1 blog](https://www.linuxserver.io/blog/webtop-4-1-x11-is-dead-and-what-is-selkies-anyway))
- Transport is a **correction to the task brief's assumption**: Selkies is
  _"not"_ WebRTC-first. Per the project's own architecture writeup:
  _"Selkies streams over plain WebSockets by default, with WebRTC available
  as an opt-in transport"_ — WebSockets + the W3C WebCodecs API carry
  encoded frames, driven by Wayland damage-tracking so only changed regions
  are encoded ("Paint-Over" keyframing). WebRTC remains available as an
  opt-in transport for peer-to-peer/NAT-traversal scenarios.
  ([Selkies homepage](https://selkies-project.github.io/selkies/))
- No KasmVNC fallback is documented anywhere in the pixelflux/Wayland
  lineage's own docs (`selkies-project.github.io/selkies`). KasmVNC only
  shows up bundled in the older EGL/GLX X11 images (§2.1). **This design
  treats KasmVNC as unavailable in the Wayland path** unless a later
  packaging step proves otherwise.

### 2.3 Decision

**Use the pixelflux/Smithay Wayland mode (§2.2), not the official
EGL/GLX KDE containers (§2.1).** Only §2.2 supports Wayland + KWin +
Plasma without requiring an NVIDIA-only X11 session, and only §2.2 matches
AIOS's actual desktop (openSUSE Leap 16, KDE Plasma **Wayland**, SDDM
autologin). This also means: no NVIDIA GPU requirement is inherited from
Selkies itself (AVX2 CPU is the hard requirement in software-encode mode;
GPU encode is an optimization, not a gate).

Practical consequence for packaging (deferred, not part of this stream):
AIOS is not itself a container runtime — Selkies here is a **host packaging
target**, not a container. The pixelflux/Smithay/KWin stack must be
packaged as native openSUSE Leap 16 RPM(s) (Smithay + KWin + the Selkies
Python/Rust WebSocket server + WebCodecs encoder), analogous to how
LinuxServer.io's Docker image assembles it from source, rather than by
running the upstream Docker image inside AIOS. That packaging work is
explicitly **out of scope** for this design/scaffold stream (see §7).

## 3. Architecture

```
Browser (client)
   │  HTTPS, loopback only by default (127.0.0.1 / ::1)
   ▼
Selkies WebSocket/WebCodecs server  (SELKIES_BIND_ADDRESS:SELKIES_BIND_PORT)
   │  encoded frame stream + input events
   ▼
Smithay virtual framebuffer (userspace, GPU or CPU)
   │  nests
   ▼
KWin (Wayland compositor, nested)
   │  hosts
   ▼
Plasma Shell  (the SAME desktop session AIOS already boots via
               distro/desktop/session-manager.sh / aios-plasma.desktop —
               NOT a second, parallel desktop)
```

Key architectural commitments:

1. **One desktop, two access paths.** The Selkies session is not a
   separate "cloud desktop" — it streams the operator's existing local
   Plasma Wayland session. This avoids doubling AIOS daemon state
   (Policy Kernel, Evidence Log, Cognitive Core client) across two
   sessions, which would violate the single-session assumptions baked into
   `session-manager.sh`.
2. **Loopback-only bind, by construction.** `SELKIES_BIND_ADDRESS` defaults
   to `127.0.0.1` in `selkies.env` (§5). This is the same posture as
   `EXPOSURE_LOOPBACK` in the L7 Web Renderer FSM (05_web_renderer.md §5.1).
   Nothing in this design binds `0.0.0.0`.
3. **Off by default, policy-gated to turn on.** The systemd unit
   (`aios-selkies.service`, §5) is shipped **not enabled** and additionally
   carries `ConditionPathExists=` on a policy-flag file that only a
   policy-approved operator action is meant to create. This mirrors the
   `WEB_EXPOSURE_GRANTED` gate pattern from `05_web_renderer.md` §5.4,
   without claiming to _be_ that gate — the real Policy Kernel integration
   (S2.3 `EvaluatePolicy` call, `WEB_EXPOSURE_GRANTED` evidence emission)
   does not exist yet and is listed as unproven in §7. The scaffold gate is
   a **file-existence check any operator with root can flip**, which is a
   correct minimum-viable fail-closed default, not a claim of full policy
   enforcement.
4. **TURN is not needed for the default (loopback) posture.** TURN/coturn
   only matters once WebRTC transport or LAN/NAT traversal is in play
   (§2.1/§2.2 sources). For loopback-only WebSocket transport there is no
   NAT to traverse, so TURN is explicitly **not** part of this design's
   default config; it is left commented out in `selkies.env` for a future
   LAN-exposure escalation that would have to go through the L7
   `WEB_EXPOSURE_GRANTED` FSM, not through this file.
5. **Auth.** `SELKIES_ENABLE_BASIC_AUTH=true` with a password file
   (`SELKIES_BASIC_AUTH_PASSWORD_FILE`), not a value in the environment
   file, so the secret is not visible via `systemctl show` or process
   environment dumps. Populating that file is out of scope here (belongs to
   the eventual Vault Broker / L4 secrets integration) and is listed
   unproven in §7.

## 4. Ports

| Port        | Protocol    | Purpose                                                                     | Default bind                                          |
| ----------- | ----------- | --------------------------------------------------------------------------- | ----------------------------------------------------- |
| 8080        | TCP (HTTPS) | Selkies WebSocket/WebCodecs UI + signaling                                  | `127.0.0.1` only                                      |
| 3478        | TCP+UDP     | TURN (coturn), only if a future LAN-exposure grant enables WebRTC transport | not opened by default; commented out in `selkies.env` |
| 65532–65535 | TCP+UDP     | Embedded TURN relay range (upstream default), same conditional as above     | not opened by default                                 |

Port 8080 matches the upstream default documented for both Selkies
lineages (§2.1, §2.2 docker run examples); it is configurable via
`SELKIES_BIND_PORT` in `selkies.env`.

## 5. Scaffold files in this directory

- `aios-selkies.service` — systemd unit. Shipped with **no** `[Install]`
  `WantedBy=` target wired into `aios.target` or `multi-user.target` (so
  `systemctl enable aios-selkies.service` requires an explicit operator
  action, and even then `ConditionPathExists=` on the policy flag file
  blocks start).
- `selkies.env` — configuration, loopback-only defaults, TURN commented
  out, basic auth on with password sourced from a file, not inline.
- `aios-selkies-ctl.sh` — POSIX `sh` control helper with three
  subcommands:
  - `status` — reports whether the policy flag file exists and is well
    formed; no side effects.
  - `preflight` — the actual gate function; called by the unit's
    `ExecStartPre`. Exits non-zero (refuses to proceed) unless the policy
    flag file exists and contains `AIOS_REMOTE_DESKTOP_POLICY_GRANTED=true`.
    This is what the gate-test (§6) exercises.
  - `enable` / `disable` — operator-facing helpers that write/remove the
    policy flag file. `enable` requires an explicit
    `--i-confirm-policy-approval` flag on the command line, and refuses
    silently-scripted invocation (no default "yes"), as a minimal
    anti-footgun measure. This is **not** a substitute for a real L4
    Policy Kernel decision — it is a placeholder control surface, marked
    as such in the script's own header comment, pending the real
    `aios.web.GrantLANExposure`-style typed action + evidence path.

## 6. Gate test

`distro/build/tests/test-remote-selkies-design.sh` (POSIX `sh`, follows the
existing `test-rev13-opensuse-base.sh` conventions: `msg`/`pass`/`fail`
helpers, `set -e`, exit non-zero on any failure) asserts only what is
mechanically true of the files in this repository, right now, without a
running system:

1. All three scaffold files exist.
2. The systemd unit has **no** `WantedBy=` line and **has** a
   `ConditionPathExists=` line pointing at the policy flag path used by
   `aios-selkies-ctl.sh`.
3. `aios-selkies-ctl.sh` passes `sh -n` (syntax check).
4. Running `aios-selkies-ctl.sh preflight` in a clean temp `HOME`/state dir
   (no flag file present) exits non-zero — the fail-closed default is
   real, not asserted.
5. Running `aios-selkies-ctl.sh preflight` after creating a flag file with
   the correct content exits zero — the "happy path" of the gate is
   reachable, proving the test can distinguish granted vs. not-granted
   (this is the regression-detection requirement: a test that always
   passes would not catch a broken gate).
6. `selkies.env` is parseable as `sh`-sourceable key=value pairs
   (`sh -n` on a wrapped `. selkies.env` invocation) and its
   `SELKIES_BIND_ADDRESS` value is `127.0.0.1` (loopback-only default is
   asserted, not assumed).

This is a real, falsifiable test: flip `SELKIES_BIND_ADDRESS` to `0.0.0.0`,
or delete `ConditionPathExists=`, or make `preflight` always exit 0, and the
test fails. It does **not** test that Selkies itself streams a desktop —
that requires the runtime environment described in §7.

## 7. Proven vs. unproven (read this before trusting any "it works" claim)

### Proven from this environment (design worktree, no GPU/no container runtime)

- The three scaffold files exist, are syntactically valid, and encode the
  fail-closed policy gate described above — proven by the gate test in §6,
  executed and shown in the final report.
- The Selkies architecture claims in §2 are grounded in fetched upstream
  documentation (linked and quoted), not invented.
- The port table (§4) reflects upstream documented defaults for the two
  Selkies lineages found during research.

### Explicitly UNPROVEN — requires a GPU host + container/RPM build environment this worktree does not have

- **Whether the pixelflux/Smithay/KWin/Plasma Wayland stack actually
  packages and runs on openSUSE Leap 16** (vs. the Ubuntu/Debian bases the
  upstream Docker images use). No RPM packaging of Smithay, the pixelflux
  encoder, or the Selkies WebSocket server exists in this repository.
- **Whether AVX2-only (no GPU) software encode is fast enough** for a
  usable desktop stream on AIOS's target hardware.
- **Whether the "one desktop, two access paths" model (§3.1) actually
  works** — i.e., whether Smithay/KWin nesting can attach to the _same_
  running Plasma session `session-manager.sh` already started, versus
  needing its own independent Plasma instance. Upstream Selkies images run
  their own self-contained session; AIOS's constraint (attach to the
  existing session) is not validated against upstream behavior.
- **The real L4 Policy Kernel integration** — `aios-selkies-ctl.sh enable`
  is a manual flag-file writer, not a call into
  `S2.3 EvaluatePolicy` / `WEB_EXPOSURE_GRANTED` evidence emission as the
  L7 spec requires for a real exposure grant. Today's scaffold only
  gates the _local_ Selkies process from auto-starting; it does not yet
  implement the constitutional approval chain.
- **Any actual video/input latency, security posture under load, or
  browser-compatibility behavior.** No browser, no Selkies process, and no
  KWin/Smithay binary were run as part of this task.
- **The KasmVNC-availability question for the Wayland lineage (§2.2)**
  — could not confirm or deny from available docs whether the
  pixelflux/Webtop stack also exposes a VNC fallback; treat as absent
  until proven.

## 8. Sources

- [Webtop 4.1: X11 is dead and what is Selkies, anyway? — LinuxServer.io](https://www.linuxserver.io/blog/webtop-4-1-x11-is-dead-and-what-is-selkies-anyway) — `PIXELFLUX_WAYLAND`, KWin-nested-in-Smithay/Plasma, WebSocket+WebCodecs transport, AVX2 requirement, Paint-Over encoding.
- [Selkies project homepage](https://selkies-project.github.io/selkies/) — "streams over plain WebSockets by default, with WebRTC available as an opt-in transport"; basic auth/TLS.
- [Selkies FAQ](https://selkies-project.github.io/selkies/faq/) — explicit statement that Wayland is "not supported" in the classic X.Org-targeted troubleshooting path (applies to the §2.1 lineage, not the pixelflux/Webtop lineage).
- [selkies-project/docker-selkies-egl-desktop — GitHub](https://github.com/selkies-project/docker-selkies-egl-desktop) — official KDE Plasma container description, EGL/GLX/NVIDIA/X11, KasmVNC-on-8080, `SELKIES_TURN_*` / `SELKIES_BASIC_AUTH_*` env vars.
- `002.AI-OS.NET--SPECREV.2/L7_Interaction_Renderers/05_web_renderer.md` (this repo) — `INV-006`, `WebExposureState` FSM, `WEB_EXPOSURE_GRANTED` evidence contract.
- `distro/desktop/session-manager.sh`, `distro/systemd/aios-fs-daemon.service` (this repo) — existing AIOS desktop-session and systemd-unit conventions followed by this scaffold.
