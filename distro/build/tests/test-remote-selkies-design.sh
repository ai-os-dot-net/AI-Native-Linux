#!/bin/sh
#
# AI-OS.NET Stream B1 — Selkies browser-desktop remote-access design/scaffold
# gate test.
#
# Verifies only what is mechanically true of distro/remote/selkies/ right
# now, without a running system, GPU, or container runtime:
#   - the scaffold files exist and are syntactically valid
#   - the systemd unit is NOT wired into any auto-start target and gates on
#     an explicit policy flag file
#   - the control script's fail-closed gate actually distinguishes
#     granted vs. not-granted (both directions are exercised, so a broken
#     always-pass or always-fail gate would be caught)
#   - the shipped config defaults to loopback-only binding
#
# Run: sh distro/build/tests/test-remote-selkies-design.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${BUILD_DIR}/../.." && pwd)"

SELKIES_DIR="${REPO_ROOT}/distro/remote/selkies"
UNIT_FILE="${SELKIES_DIR}/aios-selkies.service"
ENV_FILE="${SELKIES_DIR}/selkies.env"
CTL_SCRIPT="${SELKIES_DIR}/aios-selkies-ctl.sh"
DESIGN_DOC="${SELKIES_DIR}/DESIGN.md"

FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

WORK_DIR="${TMPDIR:-/tmp}/aios-remote-selkies-gate-test.$$"
mkdir -p "${WORK_DIR}"
trap 'rm -rf "${WORK_DIR}"' EXIT

check_file() {
    _label="$1"
    _file="$2"
    if [ -f "${_file}" ]; then
        pass "${_label}"
    else
        fail "${_label} missing: ${_file}"
    fi
}

check_grep() {
    _label="$1"
    _file="$2"
    _pattern="$3"
    if grep -E -q -- "${_pattern}" "${_file}" 2>/dev/null; then
        pass "${_label}"
    else
        fail "${_label}"
    fi
}

check_absent() {
    _label="$1"
    _file="$2"
    _pattern="$3"
    if grep -E -q -- "${_pattern}" "${_file}" 2>/dev/null; then
        fail "${_label}"
    else
        pass "${_label}"
    fi
}

msg "1. Scaffold files exist"
check_file "DESIGN.md present" "${DESIGN_DOC}"
check_file "aios-selkies.service present" "${UNIT_FILE}"
check_file "selkies.env present" "${ENV_FILE}"
check_file "aios-selkies-ctl.sh present" "${CTL_SCRIPT}"

msg "2. Systemd unit is not auto-enabled and gates on the policy flag file"
check_absent "unit has no [Install] WantedBy=" "${UNIT_FILE}" "^WantedBy="
check_grep "unit has ConditionPathExists= on the policy gate path" \
    "${UNIT_FILE}" "^ConditionPathExists=/etc/aios/policy/remote-desktop\.enabled$"
check_grep "unit's ExecStartPre runs the ctl script's preflight gate" \
    "${UNIT_FILE}" "ExecStartPre=.*aios-selkies-ctl\.sh preflight"

msg "3. Control script is syntactically valid"
if [ -x "${CTL_SCRIPT}" ]; then
    pass "aios-selkies-ctl.sh is executable"
else
    fail "aios-selkies-ctl.sh is not executable"
fi
if sh -n "${CTL_SCRIPT}" 2>/dev/null; then
    pass "aios-selkies-ctl.sh syntax OK (sh -n)"
else
    fail "aios-selkies-ctl.sh syntax error"
fi

msg "4. Fail-closed gate: preflight refuses when the flag file is absent"
GATE_FILE="${WORK_DIR}/remote-desktop.enabled"
rm -f "${GATE_FILE}"
if AIOS_SELKIES_GATE_FILE="${GATE_FILE}" sh "${CTL_SCRIPT}" preflight \
    >"${WORK_DIR}/preflight-absent.log" 2>&1; then
    fail "preflight exited 0 with no flag file (should refuse)"
else
    pass "preflight exits non-zero with no flag file"
fi

msg "5. Gate is reachable: preflight succeeds once the flag file is correctly granted"
mkdir -p "$(dirname "${GATE_FILE}")"
printf 'AIOS_REMOTE_DESKTOP_POLICY_GRANTED=true\n' > "${GATE_FILE}"
if AIOS_SELKIES_GATE_FILE="${GATE_FILE}" sh "${CTL_SCRIPT}" preflight \
    >"${WORK_DIR}/preflight-granted.log" 2>&1; then
    pass "preflight exits zero once the flag file is granted"
else
    fail "preflight exited non-zero even though the flag file is granted"
fi

msg "5b. Gate stays closed on a malformed flag file (wrong value)"
printf 'AIOS_REMOTE_DESKTOP_POLICY_GRANTED=false\n' > "${GATE_FILE}"
if AIOS_SELKIES_GATE_FILE="${GATE_FILE}" sh "${CTL_SCRIPT}" preflight \
    >"${WORK_DIR}/preflight-malformed.log" 2>&1; then
    fail "preflight exited 0 with a malformed (false) flag value"
else
    pass "preflight exits non-zero with a malformed (false) flag value"
fi

msg "6. Shipped config defaults to loopback-only bind and parses as sh"
check_grep "selkies.env is sh-sourceable (no obvious syntax break)" "${ENV_FILE}" "^SELKIES_BIND_ADDRESS="
if sh -c ". '${ENV_FILE}'" 2>"${WORK_DIR}/env-source.log"; then
    pass "selkies.env sources cleanly under sh"
else
    fail "selkies.env failed to source under sh (see ${WORK_DIR}/env-source.log)"
fi
check_grep "SELKIES_BIND_ADDRESS defaults to loopback 127.0.0.1" \
    "${ENV_FILE}" "^SELKIES_BIND_ADDRESS=127\.0\.0\.1$"
check_absent "no 0.0.0.0 bind address anywhere in shipped config" "${ENV_FILE}" "0\.0\.0\.0"
check_grep "TURN vars are commented out (not active by default)" \
    "${ENV_FILE}" "^# SELKIES_TURN_HOST="

echo
msg "Summary: ${PASSED} passed, ${FAILED} failed"
if [ "${FAILED}" -ne 0 ]; then
    exit 1
fi
exit 0
