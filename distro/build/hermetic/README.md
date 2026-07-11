# Hermetic & reproducible build (R13.2)

Groundwork for **REV13-ENTERPRISE-SPEC.md §5 — Hermetic and reproducible
build**. This directory adds _input pinning and drift detection_ without
touching the existing build scripts. It captures **what a release is built
from** so a build is explainable after the fact and rebuild drift is caught
before promotion.

The §5 contract: _"Enterprise releases must be built from pinned inputs with
repeatable build receipts. A release must be explainable after the fact: what
source, what tools, what dependencies, what builder, and what output hashes."_

## What is here

| File                     | Role                                                                                                              |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `generate-build-lock.sh` | Snapshots the current tree's build inputs into a deterministic `build-inputs.lock.json`.                          |
| `verify-build-lock.sh`   | Re-derives inputs from the current tree and reports drift vs. an existing lock. `--json` emits a machine verdict. |
| `README.md`              | This document.                                                                                                    |

The generator is the single source of truth; the verifier calls it and compares.

### Usage

```bash
# Pin the current tree's inputs (writes distro/build/build-inputs.lock.json):
distro/build/hermetic/generate-build-lock.sh

# Later / in CI — check the tree still matches the pinned inputs:
distro/build/hermetic/verify-build-lock.sh            # human output, exit 1 on drift
distro/build/hermetic/verify-build-lock.sh --json     # machine verdict
```

## What IS pinned now (input side of §5)

The lockfile (`aios.build-inputs.lock.v1`) captures, deterministically
(sorted keys, preserved array order, **no wall-clock timestamps** — the only
time value is the git-commit-derived epoch):

- **Cargo inputs** — path + **sha256 of `Cargo.lock`**, the workspace crate
  count, and the Rust toolchain (`rust-toolchain.toml` channel if present, else
  `rustc --version`). The `Cargo.lock` sha binds the _entire_ transitive Rust
  dependency graph to exact versions+checksums.
- **rootfs package inputs** — the `BASE_PACKAGES` set and the zypper repository
  URLs, **parsed out of `build-opensuse-rootfs.sh`** (not duplicated), so the
  lock cannot silently disagree with the builder.
- **toolchain inputs** — host versions of `xorriso`, `mksquashfs`,
  `grub2-mkrescue`/`grub-mkrescue`, and `veritysetup` (recorded as `"absent"`
  honestly when a tool is not installed).
- **SOURCE_DATE_EPOCH** — the git HEAD commit timestamp, plus the HEAD revision.

## What is NOT yet hermetic (deferred — honest gaps)

These are the parts of §5 that this groundwork does **not** yet satisfy. They
require changes to the build scripts and are left as documented follow-ups:

- **Network zypper fetch is not hash-locked.** §5 "External downloads are locked
  by hash and source." `build-opensuse-rootfs.sh` resolves package _versions_ at
  build time from live openSUSE mirrors. The lock pins the package _names_ and
  repo _URLs_, but not the exact RPM versions/hashes. A fully hermetic mode needs
  a resolved, hash-bound RPM manifest and an offline package cache.
- **No vendored Cargo registry.** `Cargo.lock` pins versions+checksums, but the
  build still fetches crates from crates.io. Full hermeticity needs
  `cargo vendor` + an offline `.cargo/config.toml`.
- **Host toolchain is not pinned/containerized.** Tool versions are _recorded_
  and drift is _reported_ (as WARN), but the build still uses whatever the host
  provides. §5 "Build scripts do not depend on mutable host state" ultimately
  needs a pinned builder image.
- **No reproducible-rebuild comparison of the final ISO.** §5 "Rebuild
  comparison either matches or produces a signed drift explanation." This
  groundwork detects _input_ drift; comparing two full ISO builds' output hashes
  is a separate step layered on the existing provenance `outputs[]`.

## Documented hook points in the existing build scripts

Because R13.2 groundwork must not rewrite the build scripts, the future
fully-hermetic mode should attach at these existing points:

- **`build-opensuse-rootfs.sh`**
  - Repo add (`add_repo "${REPO_OSS}" ...`) and package install
    (`run_zypper ... install --no-recommends -y "${PACKAGES[@]}"`): a hermetic
    mode would consume a hash-locked RPM manifest here and install from a
    verified local cache (`zypper --pkg-cache-dir`) instead of live mirrors.
  - The `BASE_PACKAGES` array is the canonical package input this lock parses;
    keep it as the single declaration.

- **`build-aios-iso.sh`**
  - The `BUILD_TIMESTAMP` / `GIT_REVISION` / `GIT_DIRTY` block: export
    `SOURCE_DATE_EPOCH` (from this lock's `source.source_date_epoch`) here,
    before `mksquashfs` and `xorriso`, so payload mtimes become reproducible.
  - The `provenance.json` (`aios.provenance.v1`) writer: add a
    `build_inputs_lock_sha256` field referencing this lock, tying the pinned
    inputs to the signed provenance receipt.

## How the lock ties into provenance

`provenance.json` (`aios.provenance.v1`, written by `build-aios-iso.sh`) is the
**output-side receipt**: source revision, builder identity, tool versions, and
output hashes. `build-inputs.lock.json` is the **input-side pin**: the exact
inputs a build must start from. Together they close §5's "explainable after the
fact" loop.

The intended enforcement (a documented follow-up, since it touches CI): run
`verify-build-lock.sh` before an enterprise build; a missing or drifted pin
**blocks the release** — satisfying §5 acceptance criterion _"Missing dependency
pin blocks enterprise release."_ The lock's sha256 should be embedded in the
signed provenance so the receipt names the inputs it was built from.

## Verified by

`distro/build/tests/test-rev13-hermetic.sh` — proves: generate+verify green,
Cargo.lock tamper fails (sha drift), a removed `BASE_PACKAGES` entry fails with
a printed diff, toolchain drift WARNs (does not fail), and two consecutive
generates over an unchanged tree are byte-identical.
