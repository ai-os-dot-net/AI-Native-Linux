# AI-OS.NET Revision 13 - Enterprise Linux Distribution Specification

| Field | Value |
|-------|-------|
| Status | `CONTRACT` |
| Scope | Enterprise-grade AI-OS.NET Linux distribution lifecycle |
| Predecessor | Revision 12 full distribution baseline |
| Success gate | Signed, supported, compliant, reproducible enterprise release |

## 1. Purpose

Revision 13 turns the Revision 12 distribution baseline into an enterprise Linux
distribution. It adds base selection, lifecycle guarantees, reproducible builds,
signed supply chain, compliance gates, hardened runtime policy, CVE handling,
and support lifecycle.

Revision 13 must not compensate for missing Revision 12 proof. If boot, install,
service health, update, or rollback are unproven, the release is still Revision
12-incomplete.

## 2. Non-goals

- No claim of third-party certification unless that certification is actually
  obtained.
- No hidden manual release steps.
- No unsigned enterprise update channel.
- No enterprise profile that depends on permissive SELinux.
- No support promise without a documented CVE and EOL process.

## 3. Enterprise release profiles

| Profile | Purpose | Enforcement |
|---------|---------|-------------|
| `DEV_RELAXED` | Developer and lab builds | warnings allowed, no enterprise claim |
| `SECURE_DEFAULT` | Normal production baseline | signed updates, service hardening, audit |
| `STIG_ALIGNED` | Government/military-style hardening target | SELinux enforcing, stricter audit, control map |
| `AIRGAP_HIGH` | Disconnected or high-sensitivity deployments | offline repo, restricted networking, signed imports |

Only `SECURE_DEFAULT`, `STIG_ALIGNED`, and `AIRGAP_HIGH` can be called
enterprise profiles.

## 4. R13.1 Base and lifecycle decision

### Contract

Enterprise AI-OS.NET must have a locked base strategy. The base decision defines
package compatibility, security update cadence, kernel policy, supported
architectures, and operator expectations.

### Required decisions

| Decision | Required output |
|----------|-----------------|
| Base family | `openSUSE Leap 16.x` |
| Primary release | `openSUSE Leap 16.0` |
| Supported architectures | `x86_64` for first enterprise gate; `aarch64` only after CI proof |
| LTS window | 24 months per minor release |
| EOL date | `2027-10-31` for the default Leap 16.0 builder metadata |
| Security SLA | Critical: 7 days target; High: 30 days target |
| Upgrade policy | Leap 16.x minor upgrades only until major-upgrade gate exists |
| Kernel policy | Vendor `kernel-default` from openSUSE |
| Package policy | Hybrid: RPM base plus staged AIOS binaries and AIOS signed artifacts |

### Locked R13.1 decision

R13.1 uses openSUSE Leap as the enterprise base. The rootfs builder emits
`/etc/aios/base-rootfs.env` and `/etc/aios/base-rootfs.json`; the ISO builder
then copies that into `/aios/base.json`. `--enterprise-release` blocks scaffold
roots, non-openSUSE base metadata, unsupported architectures, missing EOL data,
and rootfs/ISO architecture mismatch.

### Acceptance criteria

- Base family is recorded in release metadata.
- Supported architectures are listed.
- Unsupported architectures are blocked from enterprise release.
- LTS and EOL dates are recorded.
- Upgrade paths are documented and tested.

## 5. R13.2 Hermetic and reproducible build

### Contract

Enterprise releases must be built from pinned inputs with repeatable build
receipts. A release must be explainable after the fact: what source, what tools,
what dependencies, what builder, and what output hashes.

### Requirements

- Build dependencies are pinned.
- External downloads are locked by hash and source.
- Build scripts do not depend on mutable host state.
- CI and local release builds use the same input manifest.
- Reproducible build receipts are generated.
- Provenance is signed.
- Rebuild drift is detected and reported.

### Acceptance criteria

- Fresh build environment can build the release from declared inputs.
- Build receipt lists source revision, dependency pins, tool versions, builder
  identity, environment profile, and output hashes.
- Rebuild comparison either matches or produces a signed drift explanation.
- Missing dependency pin blocks enterprise release.

## 6. R13.3 Daemon architecture and systemd finalization

### Contract

Enterprise AI-OS.NET must freeze the daemon/service contract. Operators need
stable service names, clear responsibilities, predictable dependencies, and
auditable hardening.

### Required decision

AIOS must choose one of these models before enterprise release:

| Model | Description |
|-------|-------------|
| Multi-daemon | Separate binaries for policy, vault, evidence, fs, SGR, etc. |
| Supervisor | One `aios-system` supervisor with internal service modules |
| Hybrid | Core supervisor plus isolated high-risk daemons |

### Systemd requirements

- Required services are documented.
- Optional services are documented.
- Service dependency graph is stable.
- `Restart`, `TimeoutStartSec`, and failure behavior are defined.
- Hardening directives are set per service class.
- Service health checks exist.
- `systemd-analyze security` or equivalent score gate is enforced.

### Acceptance criteria

- Enabled enterprise units match staged binaries.
- Required services reach healthy state after boot.
- Optional services do not block boot.
- Hardening score below threshold blocks release.
- Service restart/failure behavior is tested.

## 7. R13.4 Secure Boot, TPM measured boot, and integrity enforcement

### Contract

Enterprise boot must be signed, measured, and auditable. The system must know
whether it booted through the expected chain and must record that state.

### Requirements

- Bootloader is signed.
- Kernel is signed.
- Initramfs is signed.
- Kernel modules are signed.
- Rootfs metadata is signed.
- TPM PCR measurements are captured where TPM is present.
- SELinux is enforcing for enterprise profiles.
- IMA/EVM appraisal is enabled where supported.
- `dm-verity` or equivalent rootfs integrity is enabled.
- Boot integrity evidence is emitted.

### Acceptance criteria

- Unsigned kernel is rejected in signed profile.
- Unsigned module is rejected in signed profile.
- SELinux permissive mode blocks `STIG_ALIGNED` and `AIRGAP_HIGH`.
- Boot evidence includes signature state, TPM state, kernel lockdown state,
  SELinux mode, and rootfs integrity state.
- Recovery path can repair keys, policy, or rollback state without weakening
  normal boot policy.

## 8. R13.5 Signed repository and atomic update model

### Contract

Enterprise updates must be signed, policy-checked, staged, activated atomically,
and rollback-capable.

### Repository channels

| Channel | Purpose |
|---------|---------|
| `release` | Stable enterprise updates |
| `security` | Urgent security fixes |
| `staging` | Pre-production validation |
| `recovery` | Recovery-critical packages and boot repair |
| `airgap` | Offline import/export repository |

### Update requirements

- Repository metadata is signed.
- Package payloads are signed or hash-bound by signed metadata.
- Channel policy is enforced.
- Updates are staged before activation.
- Activation is atomic.
- Boot and service health decide success.
- Failed activation rolls back automatically.
- Rollback emits evidence.

### Acceptance criteria

- Valid signed update succeeds.
- Invalid signature fails before installation.
- Wrong channel policy blocks update.
- Forced boot-health failure triggers rollback.
- Previous known-good deployment remains available.

## 9. R13.6 Installer, recovery, and first-boot operator flow

### Contract

Enterprise install must support both guarded manual installation and signed
unattended installation. First boot must enroll host identity and prepare the
machine for fleet or standalone operation.

### Installer modes

| Mode | Description |
|------|-------------|
| Manual enterprise | Operator selects disk, profile, encryption, network, repo |
| Unattended enterprise | Signed answer file drives install |
| Recovery | Repair boot, keys, policy, repo config, rollback state |

### First-boot requirements

- Generate or import host identity.
- Configure security profile.
- Configure update channel.
- Enroll fleet or organization identity where provided.
- Create initial evidence chain.
- Validate required services.
- Mark deployment healthy only after checks pass.

### Acceptance criteria

- Manual enterprise install works in QEMU.
- Signed unattended install works in QEMU.
- Tampered answer file is rejected.
- First boot emits identity and deployment evidence.
- Recovery flow can repair update channel and rollback state.

## 10. R13.7 CI gates

### Contract

Enterprise release cannot be manual-trust based. CI must block release when the
artifact fails boot, install, health, update, rollback, signature, or compliance
checks.

### Required gates

| Gate | Required for |
|------|--------------|
| ISO structure | all profiles |
| QEMU live boot | all profiles |
| QEMU install | all profiles |
| Installed-system boot | all profiles |
| Service health | all profiles |
| Signed update | enterprise profiles |
| Rollback | enterprise profiles |
| Secure Boot/signature verification | enterprise profiles where firmware support exists |
| SELinux enforcing | `STIG_ALIGNED`, `AIRGAP_HIGH` |
| Compliance baseline | enterprise profiles |
| SBOM/provenance/signature presence | enterprise profiles |

### Acceptance criteria

- Failed gate blocks release.
- Gate logs are archived.
- Gate output references the exact release candidate.
- Manual waiver requires a signed exception record.

## 11. R13.8 Compliance, audit, and support lifecycle

### Contract

Enterprise AI-OS.NET must be auditable and supportable. Compliance claims must
map to concrete controls, generated evidence, and release gates.

### Compliance baselines

| Baseline | Purpose |
|----------|---------|
| CIS | Practical production security baseline |
| STIG-aligned | Government/military-style hardening target |
| AIOS native | AIOS constitutional and evidence-specific controls |
| NIST map | Control-family mapping for enterprise auditors |

### Control mapping requirements

Each control must map to at least one of:

- AIOS policy rule;
- systemd hardening rule;
- SELinux domain/type or policy bundle;
- kernel config option;
- boot integrity rule;
- update/signature rule;
- evidence record;
- CI gate.

### Audit export requirements

- Operator-readable Markdown or HTML report.
- Machine-readable JSON report.
- Control matrix export.
- Release artifact manifest.
- SBOM and provenance links.
- Exception register.
- Evidence record references.

### CVE process requirements

1. Intake vulnerability feed or advisory.
2. Triage affected packages, kernel, firmware, Rust crates, and AIOS code.
3. Assign severity and affected releases.
4. Patch or mitigate.
5. Build signed security update.
6. Run enterprise gates.
7. Publish advisory.
8. Track deployment and rollback signals.

### Support lifecycle requirements

- Major release support window.
- Minor release cadence.
- Security update cadence.
- End-of-life date.
- Emergency patch path.
- Backport policy.
- Deprecated feature policy.
- Supported upgrade path.

### Acceptance criteria

- CIS baseline exists and is machine-readable.
- STIG-aligned baseline exists and is machine-readable.
- Control matrix links controls to implementation and evidence.
- Audit export is generated for a release candidate.
- CVE process document exists.
- EOL and support policy exists.
- Release is blocked if mandatory audit artifacts are missing.

## 12. Revision 13 exit criteria

Revision 13 is complete only when all of these are true:

- Base family, architectures, LTS window, update cadence, and EOL policy are
  locked.
- Release builds are hermetic enough to rebuild from declared inputs.
- Enterprise service contract is frozen and tested.
- Secure Boot/signature pipeline exists for boot artifacts.
- TPM measured boot evidence is captured where TPM is available.
- SELinux is enforcing for enterprise profiles.
- Signed repository and atomic rollback update model pass CI.
- Manual and unattended enterprise installer flows pass QEMU tests.
- Compliance baseline, audit export, CVE process, and support lifecycle are
  documented and release-gated.
- CI blocks enterprise release on boot, install, service health, update,
  rollback, signature, SBOM/provenance, or compliance failure.
