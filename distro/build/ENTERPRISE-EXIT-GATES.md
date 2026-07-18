# R13.7 — Enterprise-Exit Gates

Status: **REAL — 8 of 8 gates blocking.** The install gate was flipped to
blocking once the autoinstall chain was proven green; no `allow_failure: true`
appears anywhere in `.gitlab-ci.yml`. Authority:
`distro/build/REV13-ENTERPRISE-SPEC.md` §10, §12. Carrier: `.gitlab-ci.yml`.

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
| 2   | Install (QEMU install to blank disk) | `qemu-install-gate`                                        | `distro/build/qemu-install-test.sh`                                                      | **YES** (flipped once proven green)                                                      | E4 install→boot serial log        |
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

**All 8 gates block** — live-boot (`assemble-iso`), install (`qemu-install-gate`),
update+rollback, compliance, CVE, hermetic, secureboot, daemon. No
`allow_failure: true` anywhere in `.gitlab-ci.yml`; a red pipeline always means a
real regression.

The install gate was the last to flip. Per the anti-fake rule below it stayed
advisory only until the autoinstall chain was proven green, then it was flipped
and the `# TODO(R13.7): flip qemu-install-gate ...` marker removed from
`.gitlab-ci.yml`.

## How `qemu-install-gate` earned blocking status

Anti-fake rule: a gate is flipped to blocking only after a proven green run —
never speculatively. The install harness (`qemu-install-test.sh` + direct-kernel
autoinstall boot) was repaired across a forensic sequence, each defect diagnosed
from the phase-1 serial log: autoinstall trigger, squashfs live-media path +
self-mount, 48G disk, installer tool deps, device-mapper modules before LUKS,
IMA module-signature appraisal (#8), ESP mount point shadowed by BOOT_PART (#9),
and `xxd` absent from the live image (#10). Once the chain installed cleanly and
booted to `AIOS-HEALTH: RUNNING`, the gate was flipped to blocking and has since
stayed green (e.g. pipelines 5983, 6049, 6072, 6090 all pass it).

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
