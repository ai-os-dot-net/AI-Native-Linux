#!/usr/bin/env bash
#
# AI-OS.NET R13.8 — support-lifecycle policy gate test.
#
# Proves the acceptance criterion "EOL and support policy exists"
# (REV13-ENTERPRISE-SPEC §11): the authoritative support-lifecycle policy exists,
# documents every one of the eight required lifecycle elements, carries the
# spec-locked values verbatim, and the top-level SUPPORT.md no longer contradicts
# the shipped distribution (the stale "no installable OS yet" claim is gone and it
# points at the policy).
#
# Run: bash distro/build/tests/test-rev13-support-lifecycle.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISTRO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${DISTRO_DIR}/.." && pwd)"
POLICY="${DISTRO_DIR}/SUPPORT-LIFECYCLE.md"
SUPPORT="${REPO_ROOT}/SUPPORT.md"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
PASSED=0; FAILED=0
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

# has PATTERN LABEL — case-insensitive grep -E over the policy doc.
has() { grep -qiE "$1" "${POLICY}" 2>/dev/null && pass "$2" || fail "$2 (missing: $1)"; }

printf '%s[TEST]%s R13.8 support-lifecycle policy\n' "${BLUE}" "${RESET}"

[ -f "${POLICY}" ] && pass "policy doc exists (distro/SUPPORT-LIFECYCLE.md)" \
                   || { fail "policy doc missing"; printf '%d passed, %d failed\n' "${PASSED}" "$(( FAILED + 8 ))"; exit 1; }

# The eight required support-lifecycle elements (§11).
has 'support window'                          "documents the major release support window"
has 'minor release cadence|minor cadence'     "documents the minor release cadence"
has 'security (update )?cadence|security SLA' "documents the security update cadence"
has 'end-of-life|\bEOL\b'                     "documents the end-of-life date"
has 'emergency patch'                         "documents the emergency patch path"
has 'backport'                                "documents the backport policy"
has 'deprecat'                                "documents the deprecated-feature policy"
has 'upgrade path'                            "documents the supported upgrade path"

# Spec-locked values must appear verbatim (no drift).
has '24 months'                               "locked LTS window (24 months) present"
has '2027-10-31'                              "locked EOL date (2027-10-31) present"
has '7 days|7d'                               "locked critical SLA (7 days) present"
has '30 days|30d'                             "locked high SLA (30 days) present"
has 'openSUSE Leap 16'                        "locked base family (openSUSE Leap 16.x) present"

# Top-level SUPPORT.md no longer contradicts the shipped distribution.
if [ -f "${SUPPORT}" ]; then
    if grep -qiE 'no installable operating system' "${SUPPORT}" 2>/dev/null; then
        fail "SUPPORT.md still claims 'no installable operating system' (stale/contradictory)"
    else
        pass "SUPPORT.md stale 'no installable OS' claim removed"
    fi
    grep -q 'SUPPORT-LIFECYCLE.md' "${SUPPORT}" 2>/dev/null \
        && pass "SUPPORT.md points at the lifecycle policy" \
        || fail "SUPPORT.md does not reference the lifecycle policy"
else
    fail "top-level SUPPORT.md missing"
fi

printf '\n%s[TEST]%s support-lifecycle: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" "${RED}" "${FAILED}" "${RESET}"
[ "${FAILED}" -eq 0 ] || exit 1
