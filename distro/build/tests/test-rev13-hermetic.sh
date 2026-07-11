#!/usr/bin/env bash
#
# AI-OS.NET R13.2 hermetic / reproducible-build gate test.
#
# Proves the build-input lock tooling (distro/build/hermetic/*) is a genuine,
# anti-fake pin+verify gate for REV13-ENTERPRISE-SPEC.md §5:
#
#   1. generate a lock over a controlled tree copy, then verify it GREEN;
#   2. tamper the tree's Cargo.lock  -> verify FAILS (sha256 drift);
#   3. remove a BASE_PACKAGES entry  -> verify FAILS and prints the package diff;
#   4. toolchain version drift       -> verify WARNs, does NOT fail (exit 0);
#   5. determinism — two consecutive generates over an unchanged tree are
#      byte-identical.
#
# Run: bash distro/build/tests/test-rev13-hermetic.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${BUILD_DIR}/../.." && pwd)"

GEN="${BUILD_DIR}/hermetic/generate-build-lock.sh"
VERIFY="${BUILD_DIR}/hermetic/verify-build-lock.sh"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
PASSED=0
FAILED=0

msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

command -v jq >/dev/null 2>&1 || { echo "jq is required for this test" >&2; exit 3; }
[ -f "${GEN}" ]    || { echo "missing generator: ${GEN}" >&2; exit 3; }
[ -f "${VERIFY}" ] || { echo "missing verifier: ${VERIFY}" >&2; exit 3; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-hermetic.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

# Build a self-contained, non-git tree copy carrying just the inputs the tooling
# reads, so we can safely tamper without touching the real repo. A fixed
# SOURCE_DATE_EPOCH stands in for the git-derived epoch on this non-git tree.
TREE="${WORK}/tree"
mkdir -p "${TREE}/distro/build"
cp "${REPO_ROOT}/Cargo.lock"                          "${TREE}/Cargo.lock"
cp "${REPO_ROOT}/distro/build/build-opensuse-rootfs.sh" "${TREE}/distro/build/build-opensuse-rootfs.sh"
export SOURCE_DATE_EPOCH=1700000000

# ── 1. generate + verify green ────────────────────────────────────────────────
msg "generate a lock over the tree copy, verify GREEN"
if bash "${GEN}" --repo-root "${TREE}" --output "${WORK}/lock.json" 2>/dev/null; then
    pass "generate produced a lockfile"
else
    fail "generate failed"
fi
if [ -s "${WORK}/lock.json" ] && jq -e . >/dev/null 2>&1 <"${WORK}/lock.json"; then
    pass "lockfile is valid, non-empty JSON"
else
    fail "lockfile is missing or invalid JSON"
fi
if bash "${VERIFY}" --repo-root "${TREE}" --lock "${WORK}/lock.json" >/dev/null 2>&1; then
    pass "verify GREEN on the pristine tree"
else
    fail "verify should pass on the pristine tree"
fi

# ── 2. tamper Cargo.lock -> verify FAILS ──────────────────────────────────────
msg "tamper the tree's Cargo.lock -> verify must FAIL (sha256 drift)"
printf '\n# tampered by test\n' >> "${TREE}/Cargo.lock"
if bash "${VERIFY}" --repo-root "${TREE}" --lock "${WORK}/lock.json" >/dev/null 2>&1; then
    fail "verify should FAIL after Cargo.lock tamper"
else
    pass "verify FAILED (fail-closed) on Cargo.lock drift"
fi
# JSON verdict must also read 'fail'.
verdict="$(bash "${VERIFY}" --repo-root "${TREE}" --lock "${WORK}/lock.json" --json 2>/dev/null | jq -r '.verdict' || true)"
if [ "${verdict}" = "fail" ]; then
    pass "--json verdict=fail on Cargo.lock drift"
else
    fail "--json verdict should be 'fail' (got '${verdict}')"
fi
# Restore the pristine Cargo.lock for the next case.
cp "${REPO_ROOT}/Cargo.lock" "${TREE}/Cargo.lock"

# ── 3. remove a BASE_PACKAGES entry -> verify FAILS with diff ─────────────────
msg "remove a BASE_PACKAGES entry -> verify must FAIL and show the diff"
# Drop the 'sudo' line from the BASE_PACKAGES block in the tree copy only.
sed -i '/^BASE_PACKAGES=(/,/^)/{/^[[:space:]]*sudo[[:space:]]*$/d}' \
    "${TREE}/distro/build/build-opensuse-rootfs.sh"
pkg_out="$(bash "${VERIFY}" --repo-root "${TREE}" --lock "${WORK}/lock.json" 2>&1 || true)"
if bash "${VERIFY}" --repo-root "${TREE}" --lock "${WORK}/lock.json" >/dev/null 2>&1; then
    fail "verify should FAIL after removing a package"
else
    pass "verify FAILED on BASE_PACKAGES set drift"
fi
if printf '%s\n' "${pkg_out}" | grep -q 'BASE_PACKAGES set' \
   && printf '%s\n' "${pkg_out}" | grep -q 'sudo'; then
    pass "diff of the removed package (sudo) is shown"
else
    fail "expected the package diff to name the removed 'sudo' entry"
fi
# Restore the pristine rootfs script.
cp "${REPO_ROOT}/distro/build/build-opensuse-rootfs.sh" \
    "${TREE}/distro/build/build-opensuse-rootfs.sh"

# ── 4. toolchain drift -> WARN not FAIL ───────────────────────────────────────
msg "toolchain version drift -> verify must WARN, not FAIL"
# Mutate only the STORED lock's toolchain version; the host still reports the
# real version, so verify sees drift on a host-dependent field.
jq '.toolchain.mksquashfs = "mksquashfs version 0.0.0-tampered"' \
    "${WORK}/lock.json" > "${WORK}/lock-drift.json"
drift_out="$(bash "${VERIFY}" --repo-root "${TREE}" --lock "${WORK}/lock-drift.json" 2>&1 || true)"
if bash "${VERIFY}" --repo-root "${TREE}" --lock "${WORK}/lock-drift.json" >/dev/null 2>&1; then
    pass "verify still exits 0 on toolchain drift (WARN, not FAIL)"
else
    fail "toolchain drift must not fail the verify"
fi
if printf '%s\n' "${drift_out}" | grep -q 'WARN'; then
    pass "toolchain drift reported as WARN"
else
    fail "expected a WARN line for toolchain drift"
fi

# ── 5. determinism ────────────────────────────────────────────────────────────
msg "determinism — two consecutive generates are byte-identical"
bash "${GEN}" --repo-root "${TREE}" --output "${WORK}/det-1.json" 2>/dev/null
bash "${GEN}" --repo-root "${TREE}" --output "${WORK}/det-2.json" 2>/dev/null
if cmp -s "${WORK}/det-1.json" "${WORK}/det-2.json"; then
    pass "two generates over an unchanged tree are byte-identical"
else
    fail "generate output is not deterministic"
    diff "${WORK}/det-1.json" "${WORK}/det-2.json" >&2 || true
fi
# Sanity: sorted keys (deterministic key order) — schema key present and JSON sorted.
if jq -e '.schema == "aios.build-inputs.lock.v1"' "${WORK}/det-1.json" >/dev/null 2>&1; then
    pass "lock carries the expected schema tag"
else
    fail "lock schema tag missing/incorrect"
fi

echo
msg "Summary: ${PASSED} passed, ${FAILED} failed"
if [ "${FAILED}" -ne 0 ]; then
    exit 1
fi
exit 0
