#!/usr/bin/env bash
#
# AI-OS.NET R13.7 — ISO build fail-closed regression gate.
#
# Guards against a real false-green that was in build-aios-iso.sh: the final
# verdict block set VERIFY_OK=false whenever a mandatory ISO item (squashfs,
# kernel, SBOM, provenance, signatures, security/boot-chain metadata, verity
# policy, ...) was MISSING — and then `exit 0` anyway with a yellow "COMPLETED
# WITH WARNINGS". The assemble-iso CI gate would pass over a structurally broken
# ISO, in direct violation of the pipeline's own "NO soft gates" policy.
#
# This test extracts the actual verdict block from build-aios-iso.sh and runs it
# both ways: VERIFY_OK=true must exit 0, VERIFY_OK=false must exit NON-ZERO.
#
# Run: bash distro/build/tests/test-rev13-iso-verify-failclosed.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISTRO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD="${DISTRO_DIR}/build/build-aios-iso.sh"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
PASSED=0; FAILED=0
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-failclosed.XXXXXX")"
cleanup() { case "${WORK}" in /tmp/*|"${TMPDIR:-/tmp}"/*) rm -rf "${WORK}" ;; esac; }
trap cleanup EXIT INT TERM

printf '%s[TEST]%s R13.7 ISO build fail-closed verdict\n' "${BLUE}" "${RESET}"

[ -f "${BUILD}" ] && pass "build-aios-iso.sh exists" || { fail "build script missing"; exit 1; }
bash -n "${BUILD}" 2>/dev/null && pass "build script syntax OK" || fail "build script syntax error"

# Extract the final verdict block: from the last `if ${VERIFY_OK}; then` to EOF.
start="$(grep -n 'if ${VERIFY_OK}; then' "${BUILD}" | tail -1 | cut -d: -f1)"
if [ -z "${start}" ]; then
    fail "could not locate the VERIFY_OK verdict block"
    printf '%d passed, %d failed\n' "${PASSED}" "$(( FAILED + 2 ))"; exit 1
fi
VERDICT="${WORK}/verdict.sh"
sed -n "${start},\$p" "${BUILD}" > "${VERDICT}"

# Guard against a lingering false green: the block must not exit 0 in the failure arm.
if grep -A20 'else' "${VERDICT}" | grep -qE '^\s*exit 0'; then
    fail "verdict block still contains 'exit 0' in the failure arm (false green)"
else
    pass "verdict failure arm has no 'exit 0'"
fi

run_verdict() {  # run_verdict <true|false> -> exit code
    # The colour vars + VERIFY_OK are consumed by the sourced verdict block (an
    # opaque source), so the "unused"/"can't follow" lints are false positives.
    # shellcheck disable=SC2034,SC1090
    ( RED='' GREEN='' YELLOW='' BOLD='' RESET='' VERIFY_OK="$1"; . "${VERDICT}" ) >/dev/null 2>&1
    printf '%d' "$?"
}

rc_ok="$(run_verdict true)"
[ "${rc_ok}" -eq 0 ] && pass "VERIFY_OK=true  → exit 0 (healthy build passes)" \
                     || fail "VERIFY_OK=true gave exit ${rc_ok}, expected 0"

rc_bad="$(run_verdict false)"
[ "${rc_bad}" -ne 0 ] && pass "VERIFY_OK=false → exit ${rc_bad} (broken ISO FAILS closed)" \
                      || fail "VERIFY_OK=false gave exit 0 — FALSE GREEN still present"

printf '\n%s[TEST]%s iso-verify-failclosed: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" "${RED}" "${FAILED}" "${RESET}"
[ "${FAILED}" -eq 0 ] || exit 1
