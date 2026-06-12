#!/bin/sh
#
# AI-OS.NET Rev.12 installer sanity test.
#
# Run: sh distro/build/tests/test-rev12-installer.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"
QUICK_INSTALL="${DISTRO_DIR}/installer/aios-quick-install.sh"
INTERACTIVE_INSTALL="${DISTRO_DIR}/installer/aios-installer.sh"
FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

msg "=== AI-OS.NET Rev.12 Installer Tests ==="

for _script in "${QUICK_INSTALL}" "${INTERACTIVE_INSTALL}"; do
    if [ -f "${_script}" ]; then
        pass "Installer script exists: ${_script#"${DISTRO_DIR}"/}"
    else
        fail "Installer script missing: ${_script#"${DISTRO_DIR}"/}"
    fi

    if bash -n "${_script}" 2>/dev/null; then
        pass "Installer syntax OK: ${_script#"${DISTRO_DIR}"/}"
    else
        fail "Installer syntax error: ${_script#"${DISTRO_DIR}"/}"
    fi
done

for _needle in \
    'AIOS_RECOVERY_SIZE_MB' \
    'AIOS_ROLLBACK_SIZE_MB' \
    'AIOS_RECOVERY' \
    'AIOS_ROLLBACK' \
    'RECOVERY_PART' \
    'ROLLBACK_PART' \
    '/recovery' \
    '/var/lib/aios/rollback' \
    'aios.install_layout.v1' \
    'aios.rollback_state.v1'; do
    if grep -q -- "${_needle}" "${QUICK_INSTALL}" 2>/dev/null \
       && grep -q -- "${_needle}" "${INTERACTIVE_INSTALL}" 2>/dev/null; then
        pass "Installers contain Rev.12 marker: ${_needle}"
    else
        fail "Installer missing Rev.12 marker: ${_needle}"
    fi
done

if grep -q 'aios-installer.sh' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q 'aios-quick-install.sh' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q '/usr/lib/aios/install' "${BUILD_SCRIPT}" 2>/dev/null; then
    pass "Build script stages live installer tools"
else
    fail "Build script does not stage live installer tools"
fi

printf '\n'
msg "=== Test Summary ==="
printf '  Passed: %d\n' "${PASSED}"
printf '  Failed: %d\n' "${FAILED}"

if [ "${FAILED}" -eq 0 ]; then
    printf '  \033[1;32mALL TESTS PASSED\033[0m\n'
    exit 0
fi

printf '  \033[1;31mSOME TESTS FAILED\033[0m\n'
exit 1
