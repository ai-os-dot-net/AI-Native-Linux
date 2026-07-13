# R13.7 — Enterprise-Exit Gates

Status: **REAL (partial blocking)** — 7 of 8 gates blocking, 1 pending an
autoinstall fix. Authority: `distro/build/REV13-ENTERPRISE-SPEC.md` §10, §12.
Carrier: `.gitlab-ci.yml`.

## Contract

An enterprise release cannot be manual-trust based. CI **must block** the
release when the release candidate fails boot, install, service health, update,
rollback, signature, SBOM/provenance, or compliance. A blocking gate is one with
`allow_failure: false` (GitLab's default). A gate is flipped to blocking **only
after a proven green run** — never speculatively, so a red pipeline always means
a real regression, not a not-yet-wired gate.

## The 8 gates

| #   | Gate                                 | CI carrier job                                             | Script / mechanism                                                                       | Blocking                                                                                 | Evidence                          |
| --- | ------------------------------------ | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | --------------------------------- |
| 1   | Live boot (QEMU)                     | `assemble-iso` (`--require-health`); `r13-qemu-boot-smoke` | `distro/build/qemu-boot-smoke.sh`                                                        | **YES** for `assemble-iso`; `r13-qemu-boot-smoke` is `when: manual, allow_failure:false` | E4 boot serial log archived       |
| 2   | Install (QEMU install to blank disk) | `qemu-install-gate`                                        | `distro/build/qemu-install-test.sh`                                                      | **NO** — `allow_failure: true`                                                           | pending (see below)               |
| 3   | Signed update + atomic rollback      | `release-update-gate`                                      | `distro/build/tests/test-rev12-release-update-gate.sh` against the real ISO staging tree | **YES** (flipped R13.7)                                                                  | E4 publish→verify→update→rollback |
| 4   | Security / compliance baseline       | `distro-shell-tests`                                       | `test-rev13-compliance.sh` + `validate-controls.py`, `test-rev12-security-baseline.sh`   | **YES** (default)                                                                        | E3 control-map validates green    |
| 5   | CVE process                          | `distro-shell-tests`                                       | `test-rev13-cve-process.sh` (executes `aios-cve-triage.sh`)                              | **YES** (default)                                                                        | E3 intake→advisory state machine  |
| 6   | Reproducible / hermetic build        | `distro-shell-tests`                                       | `test-rev13-hermetic.sh`                                                                 | **YES** (default)                                                                        | E3 build-lock generate/verify     |
| 7   | Signature / Secure Boot              | `distro-shell-tests`                                       | `test-rev13-secureboot.sh` (signs, verifies, tamper-rejects)                             | **YES** (default)                                                                        | E3 fail-closed signing pipeline   |
| 8   | Daemon / service contract            | `distro-shell-tests`                                       | `test-rev13-daemon.sh`                                                                   | **YES** (default)                                                                        | E3 service-unit contract          |

Gates 4–8 all run inside the single `distro-shell-tests` job, which is blocking
by GitLab default (now stated explicitly as `allow_failure: false`). Any one
sub-gate failing red-lines the pipeline.

## Blocking status summary

- **Blocking now (7):** live-boot (`assemble-iso`), update+rollback, compliance,
  CVE, hermetic, secureboot, daemon.
- **Non-blocking (1):** `qemu-install-gate`. The autoinstall trigger is being
  fixed on a parallel branch; the gate is not yet proven green, so flipping it
  blocking now would red-line CI on an unrelated in-flight fix. Marked in
  `.gitlab-ci.yml` with:
  `# TODO(R13.7): flip qemu-install-gate + boot-smoke to blocking once autoinstall fix lands & proven`.

## Why `qemu-install-gate` stays `allow_failure: true`

Anti-fake rule: a gate must be proven green before it is trusted to block. The
install harness (`qemu-install-test.sh` + direct-kernel autoinstall boot) is
under active repair. Flipping it now would either (a) block every unrelated MR on
a known-broken gate, or (b) force a manual-waiver habit that defeats the purpose
of a blocking gate. It stays advisory until one clean run, then the TODO marker
directs the flip.

## Manual-waiver policy

Per §10 acceptance criteria, a manual waiver requires a signed exception record.
`r13-enterprise-iso` and `r13-qemu-boot-smoke` are `when: manual` for the full
openSUSE enterprise ISO chain (heavy, opt-in via `AIOS_R13_ENTERPRISE_BUILD=1`),
but when they run they are `allow_failure: false`.

## Verifying locally

```bash
# gates 4-8 (the distro-shell-tests carriers)
bash distro/build/tests/test-rev13-compliance.sh
bash distro/build/tests/test-rev13-cve-process.sh
bash distro/build/tests/test-rev13-hermetic.sh
bash distro/build/tests/test-rev13-secureboot.sh
bash distro/build/tests/test-rev13-daemon.sh
python3 distro/compliance/validate-controls.py
```
