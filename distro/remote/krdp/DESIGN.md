# AIOS Browser Desktop Access — Stream B2: KRDP + Apache Guacamole

| Field                | Value                                                                                                                                                                                                                                                     |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Status               | `CONTRACT` (design + scaffold — no live host to prove runtime from this worktree)                                                                                                                                                                         |
| Stream               | B2 (enterprise, Wayland-native, RDP-over-browser)                                                                                                                                                                                                         |
| Complementary stream | B1 — Selkies (WebRTC screen-capture streaming, see `distro/remote/selkies/` if/when merged)                                                                                                                                                               |
| Layer                | L7 (Interaction / Renderers) with an L4 (Policy Kernel) gate and an L9 (Evidence) obligation                                                                                                                                                              |
| Hard invariant       | Rev.2 `INV-006` — web/remote renderer surfaces are localhost-only by default; LAN/remote exposure requires explicit policy approval + `WEB_EXPOSURE_GRANTED` evidence (`002.AI-OS.NET--SPECREV.2/L0_Governance_Evidence_Safety/04_invariants.md:124-126`) |

This document is the design contract for reaching an AIOS KDE Plasma Wayland
desktop from an ordinary browser tab via RDP, gatewayed by Apache Guacamole.
It is grounded in the current (as of this session, July 2026) upstream state
of KRDP and Guacamole — see **Sources** at the end. Everything under
"Proven vs unproven here" is an honest accounting of what a design/scaffold
deliverable from an isolated git worktree can and cannot demonstrate.

## 1. Why KRDP, and why it is not competing with Selkies (B1)

AIOS ships KDE Plasma 6 on **Wayland** (see `CLAUDE.md` "What this repository
is" and `distro/desktop/`). Two structurally different ways exist to expose
that Wayland session to a browser:

- **B1 — Selkies**: screen-scrapes/encodes the compositor output (GStreamer
  pipeline over WebRTC) and injects input back through a virtual
  input device or the XDG input portal. Selkies does not care what compositor
  produced the pixels; it is a generic "stream whatever is on screen" tool.
  Best for low-latency, browser-native, no-client-install access, and for
  non-KDE payloads (e.g. a single sandboxed app window).
- **B2 — KRDP**: is **KWin's own, first-party RDP server**. It is not a
  screen scraper. KRDP uses the `org.freedesktop.portal.RemoteDesktop` /
  `org.freedesktop.portal.ScreenCast` portals to ask KWin directly for a
  video stream and remote input access, encodes with KPipeWire (H.264), and
  serves that over the RDP protocol via **FreeRDP**'s server-side library
  (`libfreerdp`/`libwinpr`). Because it talks to KWin through the same portal
  API KWin already exposes for screen sharing, it inherits KWin's own
  input/output handling rather than reconstructing it — no extra virtual
  display, no separate input-injection layer, and no compositor-specific
  hacks. It became a shipped System Settings module (`Remote Desktop`, in the
  Networking KCM category) in Plasma 6.1, with an in-tree CLI server example.
  ([KDE/krdp — GitHub](https://github.com/KDE/krdp),
  [KRdp in Plasma 6.1 — KDE Discuss](https://discuss.kde.org/t/krdp-in-plasma-6-1/17857))

KRDP's advantage on AIOS specifically: it is **the same code path KDE itself
maintains for Wayland remote desktop**, so it tracks Plasma/KWin
Wayland-protocol changes for free, needs no extra virtual-framebuffer or
X11-compat shim, and speaks a protocol (RDP) that has universal client
support (`mstsc.exe`, FreeRDP, Remmina) independent of any browser. Guacamole
then removes the "needs an RDP client installed" requirement by acting as a
**clientless HTML5 gateway**: the browser only ever speaks Guacamole's own
lightweight remote-desktop protocol over WebSocket to `guacd`, which is the
component that actually holds the RDP session to KRDP.

Both streams are legitimate access paths for different situations:

|                     | B1 Selkies                                       | B2 KRDP + Guacamole                                                                      |
| ------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| Protocol to browser | WebRTC                                           | Guacamole protocol / WebSocket (HTML5)                                                   |
| What it captures    | Whatever is on the display (compositor-agnostic) | The KWin Wayland session specifically, via the native portal                             |
| Client requirement  | None (WebRTC in-browser)                         | None (Guacamole HTML5 client in-browser); RDP client optional for the non-Guacamole path |
| Session model       | Typically single shared/streamed surface         | Full interactive RDP session incl. clipboard/audio channels FreeRDP supports             |
| Best fit            | Kiosk/low-latency/app-embed streaming            | Enterprise multi-user remote-desktop access, matches "RDP" as an IT-standard protocol    |

They are **not** alternative implementations of the same feature; an
operator may enable neither, one, or both, independently, each behind its
own policy gate.

## 2. Topology

```
Browser (HTTPS)
   │  wss:// (Guacamole protocol over WebSocket)
   ▼
Guacamole web application (Tomcat servlet, guacamole.war)
   │  Guacamole protocol (TCP; TLS when guacd-ssl=true)
   ▼
guacd (Guacamole proxy daemon, localhost:4822 by default)
   │  RDP (TCP 3389; TLS + NLA/username+password)
   ▼
KRDP server (kwin_wayland RDP backend, per-user session, via
org.freedesktop.portal.RemoteDesktop + KPipeWire + FreeRDP server library)
   │  portal calls
   ▼
KWin Wayland compositor (the actual logged-in Plasma session)
```

Key facts, all upstream-documented (see Sources):

- **KRDP listens on port 3389** (the IANA RDP port) and, per current KDE
  documentation, defaults to binding **all interfaces (`0.0.0.0`)** unless
  configured otherwise — this is exactly the exposure Rev.2 `INV-006`
  requires AIOS to gate, so AIOS must **not** ship KRDP bound to `0.0.0.0`
  by default; the AIOS integration constrains it to loopback and only widens
  that with explicit policy approval (§4).
- KRDP self-generates a TLS certificate/key pair by default, or accepts
  operator-supplied `--certificate`/`--certificate-key` files.
- KRDP authenticates a single configured username/password pair (managed via
  the System Settings KCM or CLI flags `-u`/`-p`); credentials for the KCM
  path are stored via KWallet.
- KRDP is a **systemd user service** (`app-org.kde.krdpserver.service`),
  started inside the logged-in Plasma session — it is not a standalone
  system daemon that can run headless without a session. This is the single
  most important architectural constraint for the AIOS integration: our
  system-level systemd unit cannot itself "be" the RDP server; it can only
  **gate and enable** the user-session unit for approved sessions, and
  independently manage `guacd`/the Guacamole web app as system services.
- `guacd` defaults to `localhost:4822`; the Guacamole web app defaults to
  Tomcat's port (commonly fronted by 8080/443 behind a reverse proxy).
- Guacamole's RDP client parameters include a `security` mode
  (`nla`/`tls`/`rdp`/negotiate) and `guacd-ssl`/`GUACD_SSL` to require TLS
  between the web app and `guacd`. `ignore-cert`/`cert-tofu` exist for
  certificate handling but are explicitly a downgrade from real
  verification — AIOS must not default to `ignore-cert=true`.

## 3. Auth / TLS posture (enterprise-grade, matches R13 `SECURE_DEFAULT`)

- **Browser ↔ Guacamole web app**: HTTPS only. Guacamole itself does not
  terminate TLS; this must sit behind AIOS's existing reverse-proxy/TLS
  termination pattern (out of scope of this stream — the scaffold assumes an
  operator-provided or AIOS-managed TLS endpoint in front of Tomcat).
- **Guacamole web app ↔ guacd**: TLS required (`guacd-ssl=true` /
  `GUACD_SSL=true`), backed by a real cert/key pair — never the
  `ignore-cert`/plaintext defaults. The AIOS helper (§5) refuses to enable
  the stack unless a real TLS cert/key pair exists at a defined path.
- **guacd ↔ KRDP (RDP leg)**: `security=nla` where the client and server
  support it (NLA authenticates before a desktop session starts, over TLS);
  `security=tls` as the documented fallback. AIOS's Guacamole connection
  template pins `security=nla` and `ignore-cert=false` — verification is on
  by default; loosening it is an explicit, separately-reviewed operator
  action, not a default.
- **RDP session credentials**: a KRDP username/password pair, provisioned
  through the same identity/secrets path AIOS already uses for other
  operator-facing credentials (Vault Broker, per `002.AI-OS.NET--SPECREV.2/
L4_Policy_Identity_Vault/`) rather than hard-coded in the Guacamole
  connection config. The scaffold template uses placeholder tokens
  (`__AIOS_KRDP_USERNAME__` / `__AIOS_KRDP_PASSWORD_TOKEN__`) to make this
  non-negotiable: the file is not usable until those are substituted by a
  provisioning step that has not been implemented in this stream.

## 4. Policy gate — off by default (Rev.2 `INV-006`)

The whole stack is disabled by default and is enabled only by an explicit,
evidenced policy decision:

1. **`/etc/aios/policy/remote-krdp.enabled`** — the policy flag file. Its
   presence (not its content) is the gate condition, mirroring the existing
   `ConditionPathExists=/etc/aios/first-boot` pattern used by
   `distro/systemd/aios-first-boot.service`. AIOS policy tooling (L4, not
   part of this stream) is the only intended writer of this file; per
   `INV-006` its creation must correspond to a `WEB_EXPOSURE_GRANTED`
   evidence record. This stream does not implement that policy-kernel
   integration — it only defines and consumes the file contract, and says so
   under §6.
2. **TLS material** — `/etc/aios/remote/krdp/guacd-tls.crt` and
   `guacd-tls.key` must both exist and be non-empty before the stack may be
   enabled. No TLS material ⇒ hard refusal, regardless of the policy flag.
3. **`aios-remote-krdp-gate.service`** (`distro/remote/krdp/systemd/`) is a
   `oneshot` system unit, shipped **disabled** (no `[Install]` auto-wanted-by
   linkage into `aios.target`, unlike the always-on daemons in
   `distro/systemd/aios.target`) and additionally guarded by
   `ConditionPathExists=/etc/aios/policy/remote-krdp.enabled`. Even if an
   operator manually runs `systemctl start` on it, the `ConditionPathExists`
   makes systemd itself refuse to execute `ExecStart` without the flag file.
   Its `ExecStart` invokes the control helper (§5) in `enable` mode.
4. **Binding**: because upstream KRDP currently defaults to `0.0.0.0:3389`,
   the AIOS-managed KRDP configuration must explicitly restrict RDP to
   `127.0.0.1` (or a AIOS-managed private bridge reachable only by `guacd`
   on the same host) — Guacamole/`guacd` is the only intended path to KRDP,
   never a directly LAN-reachable RDP port. This is recorded as a design
   requirement in this document; the scaffold's control helper checks the
   Guacamole connection template does not point at a non-loopback host
   (test 8), but does not yet ship the KRDP-side KDE config override itself
   (see §6, unproven items).

## 5. Control helper — `bin/aios-remote-krdp-ctl`

A POSIX `sh` script (style matches `distro/desktop/session-manager.sh`:
`AIOS_CONFIG_DIR`/`AIOS_STATE_DIR`/`AIOS_RUN_DIR` env-overridable paths,
`msg`/`warn`/`err`/`ok`/`die` helpers) with three subcommands:

- `status` — reports policy flag state, TLS material state, and (best
  effort, non-fatal if `systemctl` is unavailable) `guacd`/Guacamole unit
  state.
- `enable` — **fails closed**: exits non-zero with a clear stderr reason if
  the policy flag is absent, or if either TLS file is absent/empty. Only
  when both gates pass does it proceed to the systemd calls that would
  start `guacd`/the Guacamole app and mark the user-session KRDP unit
  approved. Supports `--dry-run` to print the exact actions without
  requiring a live systemd/session (used by the gate test, §7, and safe to
  run in this worktree where no such session exists).
- `disable` — reverses `enable`; always allowed (turning access off is never
  policy-gated).

All paths (`AIOS_CONFIG_DIR`, policy flag name, TLS paths) are overridable
via environment variables, which is what lets the gate test exercise real
refusal logic against a scratch directory instead of mutating `/etc`.

## 6. Proven vs unproven here

This is a design + scaffold deliverable produced in an isolated git
worktree with no live KDE Wayland session, no `guacd`/Guacamole install, and
no network path to either. Per the Production Code Guardian policy, nothing
below is claimed as runtime-verified.

**Proven in this worktree (static/self-contained, see §7 gate test):**

- The systemd gate unit is shipped disabled and is unconditionally blocked
  by `ConditionPathExists` on the policy flag (checked textually, and with
  `systemd-analyze verify` when available on the build host).
- `aios-remote-krdp-ctl enable` refuses (non-zero exit, stderr reason) with
  the policy flag absent.
- `aios-remote-krdp-ctl enable` refuses with the policy flag present but TLS
  cert/key missing.
- `aios-remote-krdp-ctl enable --dry-run` reaches the "would enable" branch
  once both gates are satisfied, without requiring a live systemd.
- The Guacamole `guacamole.properties.template` and `user-mapping.xml.template`
  are syntactically valid (properties parse as `key: value`/`key=value`
  pairs; the XML parses with `xmllint`/Python's `xml.etree`) and encode
  `security=nla`, `ignore-cert=false`, `guacd-ssl=true`, and a loopback
  `hostname`.
- Shell syntax of `aios-remote-krdp-ctl` is valid (`sh -n`).

**Explicitly NOT proven — needs a live KDE Plasma Wayland host + Guacamole
install:**

- That KRDP actually starts under `app-org.kde.krdpserver.service` inside a
  real Plasma Wayland session on AIOS's openSUSE Leap 16 base, and that its
  portal calls succeed against AIOS's KWin build.
- That `guacd` successfully proxies a real RDP handshake to that KRDP
  instance end-to-end (NLA negotiation, H.264 video, input round-trip) —
  i.e. that a browser tab can actually drive the AIOS desktop.
- That the TLS chain (browser↔Tomcat, Tomcat/webapp↔guacd) is correctly
  terminated in AIOS's actual reverse-proxy configuration (no such
  configuration exists yet in this repository).
- That `/etc/aios/policy/remote-krdp.enabled` is ever written by a real L4
  Policy Kernel decision with a `WEB_EXPOSURE_GRANTED` evidence record — the
  policy-kernel-to-evidence-log wiring is out of scope for this stream and
  is a prerequisite before this design can be called `REAL` (Rev.2 evidence
  taxonomy: this stream is `CONTRACT`/`SHELL`, not `REAL`, until that
  runtime proof exists).
- Performance/latency characteristics versus Selkies (B1) under real load.
- openSUSE Leap 16 packaging specifics for `guacamole-server`/`guacd` and
  KRDP (`kde-plasma/krdp` availability was confirmed on Gentoo's package
  index during research; the exact openSUSE Leap 16 package name/version
  was not independently verified in this session and must be checked
  against the R13.1 base-rootfs package set before this ships).

## 7. Gate test

`distro/build/tests/test-remote-krdp.sh` asserts the static contract above:
unit-file disabled-by-default + `ConditionPathExists` wiring, the control
helper's real refusal behavior (no policy flag; policy flag but no TLS;
both present → dry-run "would enable"), shell syntax, and config-template
parseability. It performs no live systemd or network operation and requires
no root.

## Sources

- [KDE/krdp — GitHub](https://github.com/KDE/krdp) — architecture (portal +
  KPipeWire + FreeRDP), CLI usage, systemd user unit name, port 3389 /
  `0.0.0.0` default, certificate handling, single-user credential model.
- [Plasma / KRdp — KDE GitLab (invent.kde.org)](https://invent.kde.org/plasma/krdp) — canonical upstream repository.
- [KRdp in Plasma 6.1 — KDE Discuss](https://discuss.kde.org/t/krdp-in-plasma-6-1/17857) — KCM integration timeline, System Settings location.
- [Remote Desktop using the RDP protocol for Plasma Wayland — KDE Discuss](https://discuss.kde.org/t/remote-desktop-using-the-rdp-protocol-for-plasma-wayland/3616) — original design rationale for KRDP (portal-based, not screen-scraping).
- [Apache Guacamole Manual — Configuring Guacamole (v1.6.0)](https://guacamole.apache.org/doc/gug/configuring-guacamole.html) — `guacd` default port 4822, `user-mapping.xml`, `guacd-ssl`/`GUACD_SSL`, RDP `security`/`ignore-cert`/`cert-tofu` parameters, `enable-environment-properties`.
- `002.AI-OS.NET--SPECREV.2/L0_Governance_Evidence_Safety/04_invariants.md` (`INV-006`) and `L7_Interaction_Renderers/00_overview.md` — the AIOS localhost-only-by-default invariant this design is gated by.
- `distro/systemd/aios-first-boot.service`, `distro/systemd/aios-vllm.service`, `distro/desktop/session-manager.sh` — AIOS conventions this scaffold follows (`ConditionPathExists` gating, `AIOS_CONFIG_DIR`/`AIOS_STATE_DIR` env-overridable paths, POSIX `sh` helper style).
