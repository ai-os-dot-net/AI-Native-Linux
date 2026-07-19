# AI-OS.NET Enterprise Support Lifecycle Policy

Authoritative operator- and auditor-facing statement of the AI-OS.NET enterprise
support lifecycle (REV13-ENTERPRISE-SPEC.md §4 / R13.1 and §11 / R13.8). This is
the single source of truth for support windows, cadence, end-of-life, and upgrade
policy; the compliance audit export and the CVE process reference it.

Values marked **[spec-locked]** are fixed by REV13-ENTERPRISE-SPEC §4/§11 and must
not drift without a spec change. Values marked **[operational]** are AIOS
operational policy that extends — never contradicts — the spec, and may be
ratified into the spec later.

## Base and support window

| Property                     | Value                                                           | Status               |
| ---------------------------- | --------------------------------------------------------------- | -------------------- |
| Base family                  | openSUSE Leap 16.x (primary: Leap 16.0)                         | **[spec-locked]** §4 |
| Supported architectures      | `x86_64` (first enterprise gate); `aarch64` only after CI proof | **[spec-locked]** §4 |
| Major release support window | 24 months per minor release (LTS window)                        | **[spec-locked]** §4 |
| End-of-life (EOL) date       | **2027-10-31** for the default Leap 16.0 builder metadata       | **[spec-locked]** §4 |
| Kernel policy                | Vendor `kernel-default` from openSUSE                           | **[spec-locked]** §4 |
| Package policy               | Hybrid: RPM base + staged AIOS binaries + AIOS signed artifacts | **[spec-locked]** §4 |

The EOL date is emitted into the build metadata (`/etc/aios/base-rootfs.json` →
`/aios/base.json`) and `--enterprise-release` blocks a build with missing EOL
data, so the support window is enforced at build time, not only documented here.

## Release and update cadence

| Cadence                 | Policy                                                                                                   | Status                |
| ----------------------- | -------------------------------------------------------------------------------------------------------- | --------------------- |
| Minor release cadence   | Tracks the upstream openSUSE Leap 16.x minor cadence; an AIOS minor is cut per supported Leap 16.x minor | **[operational]**     |
| Security update cadence | Out-of-cadence signed security updates as advisories are triaged, within the SLA below                   | **[spec-locked]** §11 |
| Security SLA            | Critical: **7 days** target; High: **30 days** target                                                    | **[spec-locked]** §4  |

Security cadence and SLA are enforced operationally through the CVE process
(`distro/security/README.md`, `distro/security/aios-cve-triage.sh`): each advisory
records its severity band and the install-gate enforcement behaviour.

## Emergency patch path

Critical vulnerabilities are shipped as **out-of-cadence signed updates** through
the same `intake → triaged → patched → released → advisory` flow as any other
fix — no separate unsigned fast path. The update is a normal signed release
consumed by `aios-update.sh` (staged, activated atomically, boot-health gated,
auto-rollback on failure), so an emergency patch inherits the full update-integrity
and rollback guarantees. **[spec-locked]** §11.

## Backport policy

Fixes are **backported onto the supported Leap 16.x base** (kernel and packages)
for the life of the support window rather than requiring a major upgrade. Backports
are published to the `security` channel and may be promoted to `release`.
**[spec-locked]** §11 / **[operational]** channel routing.

## Supported upgrade path

- **In-window:** Leap 16.x **minor** upgrades only, until a major-upgrade gate
  exists. Minor upgrades preserve the immutable-root A/B model and the signed
  update/rollback contract. **[spec-locked]** §4.
- **Cross-major (16.x → 17.x):** **not supported** until a dedicated major-upgrade
  CI gate is defined and proven; attempting it is out of policy. **[operational]**
- **Downgrade / rollback:** handled by the atomic update model
  (`aios-update.sh rollback`, `aios-recovery.sh`) to the previous known-good
  deployment, not by package downgrade. **[spec-locked]** §7 (Rev.12 update model).

## Deprecated-feature policy

- A feature slated for removal is **announced at least one minor release ahead**
  of removal, with a migration note in the release notes and, where applicable, a
  runtime deprecation warning. **[operational]**
- Security-driven removals (e.g. a cryptographic primitive withdrawn by policy) may
  be removed within the security SLA without the one-release notice, recorded as a
  CVE-process advisory. **[operational]**
- Removal of a behaviour-defining contract (policy, CI, hooks, branch protection)
  follows the R3 change process — never a silent removal. **[spec-locked]** (change
  control).

## References

- REV13-ENTERPRISE-SPEC.md §4 (R13.1 base and lifecycle decision), §11 (R13.8
  compliance, CVE process, support lifecycle).
- CVE process and enforcement bands: `distro/security/README.md`.
- Update / rollback model: `distro/update/aios-update.sh`; recovery repair:
  `distro/installer/aios-recovery.sh`.
- Build-time EOL enforcement: `distro/build/build-aios-iso.sh` (`--enterprise-release`).
