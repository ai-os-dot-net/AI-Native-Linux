#!/bin/sh
#
# AI-OS.NET Rev.12 boot gate sanity test.
#
# Run: sh distro/build/tests/test-rev12-boot-gate.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
QEMU_SMOKE="${BUILD_DIR}/qemu-boot-smoke.sh"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"
FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

msg "=== AI-OS.NET Rev.12 Boot Gate Tests ==="

if [ -f "${QEMU_SMOKE}" ]; then
    pass "QEMU boot smoke script exists"
else
    fail "QEMU boot smoke script missing"
fi

if [ -x "${QEMU_SMOKE}" ]; then
    pass "QEMU boot smoke script is executable"
else
    fail "QEMU boot smoke script is not executable"
fi

if bash -n "${QEMU_SMOKE}" 2>/dev/null; then
    pass "QEMU boot smoke script syntax OK"
else
    fail "QEMU boot smoke script syntax error"
fi

for _needle in \
    'qemu-system-x86_64' \
    'timeout' \
    '--dry-run' \
    'Kernel panic' \
    'AIOS-RESCUE' \
    'AIOS-INIT.*Mounting live squashfs' \
    'AIOS-INIT.*Live overlay mounted'; do
    if grep -q -- "${_needle}" "${QEMU_SMOKE}" 2>/dev/null; then
        pass "QEMU smoke script contains: ${_needle}"
    else
        fail "QEMU smoke script missing: ${_needle}"
    fi
done

if grep -q 'console=ttyS0,115200n8' "${BUILD_SCRIPT}" 2>/dev/null; then
    pass "GRUB live entries enable serial console for QEMU evidence"
else
    fail "GRUB live entries do not enable serial console"
fi

if grep -q 'live/aios.squashfs' "${DISTRO_DIR}/aios-boot/initramfs/init" 2>/dev/null \
   && grep -q 'Live overlay mounted' "${DISTRO_DIR}/aios-boot/initramfs/init" 2>/dev/null; then
    pass "Initramfs emits live squashfs and overlay boot markers"
else
    fail "Initramfs live boot markers missing"
fi

if grep -q 'Kernel command line loaded' "${DISTRO_DIR}/aios-boot/initramfs/init" 2>/dev/null \
   && grep -q 'load_live_media_modules' "${DISTRO_DIR}/aios-boot/initramfs/init" 2>/dev/null \
   && grep -q 'sr_mod' "${DISTRO_DIR}/aios-boot/initramfs/init" 2>/dev/null; then
    pass "Initramfs loads cmdline and live media modules before ISO discovery"
else
    fail "Initramfs missing cmdline/live media module boot guards"
fi

# ── Boot-time service health gate (spec §6 acceptance, §10 "Service health") ──

HEALTH_UNIT="${DISTRO_DIR}/systemd/aios-health-report.service"
HEALTH_SCRIPT="${DISTRO_DIR}/aios-boot/aios-health-report.sh"

if [ -f "${HEALTH_UNIT}" ]; then
    pass "Health report systemd unit exists"
else
    fail "Health report systemd unit missing"
fi

if [ -f "${HEALTH_SCRIPT}" ]; then
    pass "Health report script exists"
else
    fail "Health report script missing"
fi

if [ -x "${HEALTH_SCRIPT}" ]; then
    pass "Health report script is executable"
else
    fail "Health report script is not executable"
fi

if sh -n "${HEALTH_SCRIPT}" 2>/dev/null; then
    pass "Health report script syntax OK"
else
    fail "Health report script syntax error"
fi

# The unit must run after the AIOS + multi-user targets and point ExecStart at
# the staged script path (the ExecStart-validation gate keys off this path).
for _needle in \
    'After=aios.target multi-user.target' \
    'ExecStart=/usr/lib/aios/aios-health-report.sh'; do
    if grep -q -- "${_needle}" "${HEALTH_UNIT}" 2>/dev/null; then
        pass "Health unit contains: ${_needle}"
    else
        fail "Health unit missing: ${_needle}"
    fi
done

# The script must emit exactly the two console verdict markers the gate matches.
for _needle in \
    'AIOS-HEALTH: RUNNING' \
    'AIOS-HEALTH: DEGRADED failed=' \
    'is-system-running --wait' \
    'systemctl --failed'; do
    if grep -q -- "${_needle}" "${HEALTH_SCRIPT}" 2>/dev/null; then
        pass "Health script contains: ${_needle}"
    else
        fail "Health script missing: ${_needle}"
    fi
done

# The build must stage the script and enable the unit.
for _needle in \
    'aios-health-report.sh' \
    'aios-health-report.service'; do
    if grep -q -- "${_needle}" "${BUILD_SCRIPT}" 2>/dev/null; then
        pass "Build script references: ${_needle}"
    else
        fail "Build script missing reference: ${_needle}"
    fi
done

# The smoke script must expose --require-health and match the health markers.
for _needle in \
    '--require-health' \
    'AIOS-HEALTH: RUNNING' \
    'AIOS-HEALTH: DEGRADED'; do
    if grep -q -- "${_needle}" "${QEMU_SMOKE}" 2>/dev/null; then
        pass "QEMU smoke script contains: ${_needle}"
    else
        fail "QEMU smoke script missing: ${_needle}"
    fi
done

_fake_iso="$(mktemp "${TMPDIR:-/tmp}/aios-rev12-fake-iso.XXXXXX")"
trap 'rm -f "${_fake_iso}"' EXIT
printf 'AIOS fake ISO for dry-run only\n' > "${_fake_iso}"

if "${QEMU_SMOKE}" --iso "${_fake_iso}" --dry-run --serial-log "${TMPDIR:-/tmp}/aios-qemu-smoke-test.log" \
   | grep -q -- 'qemu-system-x86_64'; then
    pass "QEMU smoke dry-run prints qemu command"
else
    fail "QEMU smoke dry-run did not print qemu command"
fi

if "${QEMU_SMOKE}" --iso "${_fake_iso}" --require-health --dry-run \
   --serial-log "${TMPDIR:-/tmp}/aios-qemu-smoke-health-test.log" \
   | grep -q -- 'qemu-system-x86_64'; then
    pass "QEMU smoke dry-run accepts --require-health"
else
    fail "QEMU smoke dry-run rejects --require-health"
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
