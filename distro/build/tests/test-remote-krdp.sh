#!/bin/sh
#
# AI-OS.NET Stream B2 (KRDP + Apache Guacamole) static gate test.
#
# Asserts the CONTRACT documented in distro/remote/krdp/DESIGN.md sec 6-7:
# the remote-desktop stack is off by default and the control helper fails
# closed on both the policy gate and the TLS gate. Performs no live systemd
# operation and requires no root; where a real live-systemd assertion would
# add value (systemd-analyze verify) it SKIPs honestly if the tool is
# unavailable rather than faking a pass.
#
# Run: sh distro/build/tests/test-remote-krdp.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
KRDP_DIR="${DISTRO_DIR}/remote/krdp"

UNIT_FILE="${KRDP_DIR}/systemd/aios-remote-krdp-gate.service"
CTL="${KRDP_DIR}/bin/aios-remote-krdp-ctl"
PROPS_TEMPLATE="${KRDP_DIR}/guacamole/guacamole.properties.template"
XML_TEMPLATE="${KRDP_DIR}/guacamole/user-mapping.xml.template"
DESIGN_DOC="${KRDP_DIR}/DESIGN.md"

FAILED=0
PASSED=0
SKIPPED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }
skip() { SKIPPED=$(( SKIPPED + 1 )); printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; }

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

check_not_grep() {
    _label="$1"
    _file="$2"
    _pattern="$3"
    if grep -E -q -- "${_pattern}" "${_file}" 2>/dev/null; then
        fail "${_label}"
    else
        pass "${_label}"
    fi
}

msg "=== AI-OS.NET Stream B2 (KRDP + Guacamole) Gate Tests ==="

# ── 1. Scaffold files exist ────────────────────────────────────────────────
msg "Scaffold files"
check_file "DESIGN.md exists" "${DESIGN_DOC}"
check_file "systemd gate unit exists" "${UNIT_FILE}"
check_file "control helper exists" "${CTL}"
check_file "Guacamole properties template exists" "${PROPS_TEMPLATE}"
check_file "Guacamole user-mapping template exists" "${XML_TEMPLATE}"

# ── 2. Control helper shell syntax ─────────────────────────────────────────
msg "Control helper syntax"
if sh -n "${CTL}" 2>/dev/null; then
    pass "aios-remote-krdp-ctl: sh -n syntax OK"
else
    fail "aios-remote-krdp-ctl: sh -n syntax error"
fi

# ── 3. systemd unit: disabled by default, gated by ConditionPathExists ────
msg "systemd unit contract (off by default)"
check_grep "unit gated by ConditionPathExists on policy flag" "${UNIT_FILE}" \
    'ConditionPathExists=/etc/aios/policy/remote-krdp\.enabled'
check_not_grep "unit ships with NO [Install] auto-enable section" "${UNIT_FILE}" \
    '^\[Install\]'
check_not_grep "unit is not wanted by aios.target" \
    "${DISTRO_DIR}/systemd/aios.target" 'aios-remote-krdp-gate\.service'

if command -v systemd-analyze >/dev/null 2>&1; then
    # systemd-analyze verify resolves ExecStart against a real filesystem
    # root, so build a scratch --root that stages a stub at the unit's
    # installed ExecStart/ExecStop path (/usr/lib/aios/remote/krdp/...).
    # This checks unit-file correctness (directives, syntax, ordering)
    # without requiring the real AIOS package to be installed on the test
    # host, and without lying about paths that don't exist yet.
    VERIFY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aios-remote-krdp-verify-root.XXXXXX")"
    mkdir -p "${VERIFY_ROOT}/usr/lib/aios/remote/krdp" \
             "${VERIFY_ROOT}/usr/lib/systemd/system"
    printf '#!/bin/sh\nexit 0\n' > "${VERIFY_ROOT}/usr/lib/aios/remote/krdp/aios-remote-krdp-ctl"
    chmod 755 "${VERIFY_ROOT}/usr/lib/aios/remote/krdp/aios-remote-krdp-ctl"
    # Stage the host's real base unit tree so target/dependency resolution
    # (sysinit.target, network.target, etc.) has something to resolve
    # against — otherwise --root's dependency graph fails on units this
    # scaffold never claimed to define, masking real problems in our own
    # unit behind unrelated "target not found" noise.
    if [ -d /usr/lib/systemd/system ]; then
        cp -a /usr/lib/systemd/system/. "${VERIFY_ROOT}/usr/lib/systemd/system/" 2>/dev/null || true
    fi
    cp "${UNIT_FILE}" "${VERIFY_ROOT}/usr/lib/systemd/system/aios-remote-krdp-gate.service"

    _verify_out="$(systemd-analyze verify --root="${VERIFY_ROOT}" \
        "${VERIFY_ROOT}/usr/lib/systemd/system/aios-remote-krdp-gate.service" 2>&1)" || true
    # Ignore pre-existing warnings from unrelated OS-shipped units that
    # --root pulls into the same verify pass; only this unit's own errors
    # (lines mentioning its filename) fail the check.
    _own_errors="$(printf '%s\n' "${_verify_out}" | grep 'aios-remote-krdp-gate\.service:' || true)"
    if [ -z "${_own_errors}" ]; then
        pass "systemd-analyze verify: unit file is syntactically valid (own-unit errors: none)"
    else
        fail "systemd-analyze verify: unit file failed validation: ${_own_errors}"
    fi
    rm -rf "${VERIFY_ROOT}"
else
    skip "systemd-analyze verify (systemd-analyze not on PATH in this environment)"
fi

# ── 4. Control helper: real refusal behavior ───────────────────────────────
msg "Control helper gate logic (real refusal, not constant-success)"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/aios-remote-krdp-test.XXXXXX")"
POLICY_FLAG="${WORKDIR}/policy/remote-krdp.enabled"
TLS_CERT="${WORKDIR}/tls/guacd-tls.crt"
TLS_KEY="${WORKDIR}/tls/guacd-tls.key"
STATE_FILE="${WORKDIR}/state/remote/krdp/enabled"

run_ctl() {
    AIOS_POLICY_FLAG="${POLICY_FLAG}" \
    AIOS_TLS_CERT="${TLS_CERT}" \
    AIOS_TLS_KEY="${TLS_KEY}" \
    AIOS_REMOTE_KRDP_STATE="${STATE_FILE}" \
        sh "${CTL}" "$@"
}

# 4a. No policy flag, no TLS -> enable must refuse (policy gate wins first)
_out="$(run_ctl enable --dry-run 2>&1)" && _rc=0 || _rc=$?
if [ "${_rc}" -ne 0 ]; then
    pass "enable refuses with policy flag absent (exit=${_rc})"
else
    fail "enable did NOT refuse with policy flag absent (exit=${_rc})"
fi
case "${_out}" in
    *"policy flag"*"absent"*) pass "refusal message names the missing policy flag" ;;
    *) fail "refusal message did not name the missing policy flag (got: ${_out})" ;;
esac

# 4b. Policy flag present, TLS absent -> enable must still refuse
mkdir -p "$(dirname "${POLICY_FLAG}")"
: > "${POLICY_FLAG}"
_out="$(run_ctl enable --dry-run 2>&1)" && _rc=0 || _rc=$?
if [ "${_rc}" -ne 0 ]; then
    pass "enable refuses with policy flag present but TLS material absent (exit=${_rc})"
else
    fail "enable did NOT refuse with TLS material absent (exit=${_rc})"
fi
case "${_out}" in
    *"TLS material"*) pass "refusal message names the missing TLS material" ;;
    *) fail "refusal message did not name the missing TLS material (got: ${_out})" ;;
esac

# 4c. Policy flag present, TLS present but EMPTY -> enable must still refuse
mkdir -p "$(dirname "${TLS_CERT}")"
: > "${TLS_CERT}"
: > "${TLS_KEY}"
_out="$(run_ctl enable --dry-run 2>&1)" && _rc=0 || _rc=$?
if [ "${_rc}" -ne 0 ]; then
    pass "enable refuses when TLS files exist but are empty (exit=${_rc})"
else
    fail "enable did NOT refuse for empty TLS files (exit=${_rc})"
fi

# 4d. Policy flag present, TLS present and non-empty -> dry-run reaches
#     the "would enable" branch (no live systemd required).
printf 'FAKE-CERT-FOR-TEST\n' > "${TLS_CERT}"
printf 'FAKE-KEY-FOR-TEST\n' > "${TLS_KEY}"
_out="$(run_ctl enable --dry-run 2>&1)" && _rc=0 || _rc=$?
if [ "${_rc}" -eq 0 ]; then
    pass "enable --dry-run succeeds once both gates are satisfied (exit=0)"
else
    fail "enable --dry-run unexpectedly failed with both gates satisfied (exit=${_rc}, out: ${_out})"
fi
case "${_out}" in
    *"would enable"*) pass "dry-run output reaches the would-enable branch" ;;
    *) fail "dry-run output did not reach the would-enable branch (got: ${_out})" ;;
esac
# The real (non-dry-run) systemd calls must NOT have been made.
if [ -e "${STATE_FILE}" ]; then
    fail "dry-run must not write the state marker (${STATE_FILE} exists)"
else
    pass "dry-run did not write the state marker (no live side effect)"
fi

# 4e. status subcommand runs without error and reports both gates open
_out="$(run_ctl status 2>&1)" && _rc=0 || _rc=$?
if [ "${_rc}" -eq 0 ]; then
    pass "status subcommand exits 0"
else
    fail "status subcommand exited non-zero (${_rc})"
fi
case "${_out}" in
    *"policy gate OPEN"*) pass "status reports policy gate OPEN with flag present" ;;
    *) fail "status did not report policy gate OPEN (got: ${_out})" ;;
esac
case "${_out}" in
    *"TLS gate OPEN"*) pass "status reports TLS gate OPEN with material present" ;;
    *) fail "status did not report TLS gate OPEN (got: ${_out})" ;;
esac

# 4f. disable --dry-run is always permitted (never policy-gated)
rm -f "${POLICY_FLAG}"
_out="$(run_ctl disable --dry-run 2>&1)" && _rc=0 || _rc=$?
if [ "${_rc}" -eq 0 ]; then
    pass "disable --dry-run succeeds even with policy flag absent (turning off is never gated)"
else
    fail "disable --dry-run unexpectedly failed (exit=${_rc})"
fi

rm -rf "${WORKDIR}"

# ── 5. Guacamole config templates parse ─────────────────────────────────────
msg "Guacamole config template validity"

# properties file: every non-comment, non-blank line looks like key: value
if awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    !/^[A-Za-z0-9_-]+:[[:space:]]*.+$/ { bad = 1 }
    END { exit bad ? 1 : 0 }
' "${PROPS_TEMPLATE}"; then
    pass "guacamole.properties.template: all lines are valid key: value pairs"
else
    fail "guacamole.properties.template: contains a malformed (non key: value) line"
fi

check_grep "guacamole.properties.template requires guacd-ssl" "${PROPS_TEMPLATE}" 'guacd-ssl:[[:space:]]*true'
check_grep "guacamole.properties.template points guacd at loopback" "${PROPS_TEMPLATE}" 'guacd-hostname:[[:space:]]*127\.0\.0\.1'

# XML: parse with xmllint if present, else Python's xml.etree, else SKIP.
if command -v xmllint >/dev/null 2>&1; then
    if xmllint --noout "${XML_TEMPLATE}" 2>/dev/null; then
        pass "user-mapping.xml.template: well-formed XML (xmllint)"
    else
        fail "user-mapping.xml.template: xmllint reports malformed XML"
    fi
elif command -v python3 >/dev/null 2>&1; then
    # Prefer defusedxml (guards against XXE / billion-laughs) when available;
    # fall back to stdlib xml.etree only to check well-formedness of this
    # repo-controlled template (not untrusted input).
    if python3 -c "
import sys
try:
    from defusedxml import ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
ET.parse(sys.argv[1])
" "${XML_TEMPLATE}" 2>/dev/null; then
        pass "user-mapping.xml.template: well-formed XML (python3)"
    else
        fail "user-mapping.xml.template: python3 xml parse reports malformed XML"
    fi
else
    skip "XML well-formedness check (neither xmllint nor python3 on PATH)"
fi

check_grep "user-mapping.xml.template pins security=nla" "${XML_TEMPLATE}" '<param name="security">nla</param>'
check_grep "user-mapping.xml.template pins ignore-cert=false" "${XML_TEMPLATE}" '<param name="ignore-cert">false</param>'
check_grep "user-mapping.xml.template points RDP hostname at loopback" "${XML_TEMPLATE}" '<param name="hostname">127\.0\.0\.1</param>'
check_grep "user-mapping.xml.template uses unresolved credential placeholders (not real secrets)" "${XML_TEMPLATE}" '__AIOS_KRDP_PASSWORD_TOKEN__'
check_not_grep "user-mapping.xml.template does not default ignore-cert to true" "${XML_TEMPLATE}" '<param name="ignore-cert">true</param>'

printf '\n'
msg "=== Test Summary ==="
printf '  Passed:  %d\n' "${PASSED}"
printf '  Failed:  %d\n' "${FAILED}"
printf '  Skipped: %d\n' "${SKIPPED}"

if [ "${FAILED}" -eq 0 ]; then
    printf '  \033[1;32mALL TESTS PASSED\033[0m\n'
    exit 0
fi

printf '  \033[1;31mSOME TESTS FAILED\033[0m\n'
exit 1
