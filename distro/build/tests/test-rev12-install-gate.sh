#!/bin/sh
#
# AI-OS.NET Rev.12 install gate sanity test (spec R12.2 / R12.7).
#
# Static + dry-run checks for the QEMU install-and-boot harness
# (distro/build/qemu-install-test.sh) and its autoinstall wrapper
# (distro/installer/aios-autoinstall.sh). No QEMU is launched unless the
# optional real-run section is explicitly enabled:
#
#   AIOS_QEMU_INSTALL_TEST=1 sh test-rev12-install-gate.sh --iso /path/to.iso \
#       --kernel live/vmlinuz --initrd live/initrd.img
#
# Run (static/dry-run only): sh distro/build/tests/test-rev12-install-gate.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
HARNESS="${BUILD_DIR}/qemu-install-test.sh"
AUTOINSTALL="${DISTRO_DIR}/installer/aios-autoinstall.sh"
QUICK_INSTALLER="${DISTRO_DIR}/installer/aios-quick-install.sh"
FAILED=0
PASSED=0

# Parse optional real-run args.
REAL_ISO=""
REAL_KERNEL=""
REAL_INITRD=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --iso)    REAL_ISO="$2"; shift 2 ;;
        --kernel) REAL_KERNEL="$2"; shift 2 ;;
        --initrd) REAL_INITRD="$2"; shift 2 ;;
        *) shift ;;
    esac
done

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

msg "=== AI-OS.NET Rev.12 Install Gate Tests ==="

# ── Existence + executable + syntax ───────────────────────────────────────────

for _f in "${HARNESS}" "${AUTOINSTALL}"; do
    if [ -f "${_f}" ]; then
        pass "exists: $(basename "${_f}")"
    else
        fail "missing: ${_f}"
    fi
    if [ -x "${_f}" ]; then
        pass "executable: $(basename "${_f}")"
    else
        fail "not executable: ${_f}"
    fi
    if bash -n "${_f}" 2>/dev/null; then
        pass "syntax OK: $(basename "${_f}")"
    else
        fail "syntax error: ${_f}"
    fi
done

# ── Harness contains required conventions + markers ───────────────────────────

for _needle in \
    'qemu-img create' \
    'qemu-system-x86_64' \
    'timeout' \
    '--dry-run' \
    '--kvm' \
    'accel=tcg' \
    'aios.autoinstall' \
    'AIOS-AUTOINSTALL: SUCCESS' \
    'installation complete' \
    'Kernel panic' \
    'AIOS-RESCUE' \
    'Switching to real root' \
    'if=pflash'; do
    if grep -q -- "${_needle}" "${HARNESS}" 2>/dev/null; then
        pass "harness contains: ${_needle}"
    else
        fail "harness missing: ${_needle}"
    fi
done

# ── Autoinstall wrapper maps cmdline -> quick installer env ───────────────────

for _needle in \
    'aios.autoinstall' \
    'AIOS_TARGET_DISK' \
    'AIOS_HOSTNAME' \
    'AIOS_CONFIRM_SKIP=1' \
    'aios-quick-install.sh' \
    'AIOS-AUTOINSTALL: SUCCESS' \
    'AIOS-AUTOINSTALL: FAILED'; do
    if grep -q -- "${_needle}" "${AUTOINSTALL}" 2>/dev/null; then
        pass "autoinstall contains: ${_needle}"
    else
        fail "autoinstall missing: ${_needle}"
    fi
done

# The wrapper must build on the real installer interface, not reimplement it.
if [ -f "${QUICK_INSTALLER}" ] \
   && grep -q 'AIOS_CONFIRM_SKIP' "${QUICK_INSTALLER}" 2>/dev/null; then
    pass "quick installer non-interactive interface present"
else
    fail "quick installer non-interactive interface missing"
fi

# ── Dry-run structure checks (no QEMU) ────────────────────────────────────────

_dry_out="$("${HARNESS}" --iso /nonexistent.iso --dry-run 2>/dev/null || true)"

if printf '%s' "${_dry_out}" | grep -q 'qemu-img:'; then
    pass "dry-run prints qemu-img create command"
else
    fail "dry-run did not print qemu-img create command"
fi

if printf '%s' "${_dry_out}" | grep -q 'phase1-install:'; then
    pass "dry-run prints phase 1 install command"
else
    fail "dry-run did not print phase 1 install command"
fi

if printf '%s' "${_dry_out}" | grep -q 'phase2-boot:'; then
    pass "dry-run prints phase 2 boot command"
else
    fail "dry-run did not print phase 2 boot command"
fi

if printf '%s' "${_dry_out}" | grep -q 'aios.autoinstall'; then
    pass "dry-run phase 1 injects aios.autoinstall cmdline"
else
    fail "dry-run phase 1 missing aios.autoinstall cmdline"
fi

if "${HARNESS}" --dry-run 2>/dev/null; then
    fail "harness accepted missing --iso"
else
    pass "harness rejects missing --iso"
fi

if printf '%s' "$("${HARNESS}" --iso /x.iso --swtpm --dry-run 2>/dev/null || true)" \
   | grep -q 'swtpm:'; then
    pass "dry-run with --swtpm prints swtpm command"
else
    fail "dry-run with --swtpm did not print swtpm command"
fi

# ── Optional: real QEMU install run ───────────────────────────────────────────

if [ "${AIOS_QEMU_INSTALL_TEST:-0}" = "1" ]; then
    msg "=== Real QEMU install run (AIOS_QEMU_INSTALL_TEST=1) ==="
    if [ -z "${REAL_ISO}" ]; then
        fail "AIOS_QEMU_INSTALL_TEST=1 but no --iso provided"
    elif [ ! -f "${REAL_ISO}" ]; then
        fail "ISO not found: ${REAL_ISO}"
    else
        _args="--iso ${REAL_ISO}"
        [ -n "${REAL_KERNEL}" ] && _args="${_args} --kernel ${REAL_KERNEL}"
        [ -n "${REAL_INITRD}" ] && _args="${_args} --initrd ${REAL_INITRD}"
        # shellcheck disable=SC2086
        if "${HARNESS}" ${_args} --swtpm; then
            pass "real install gate passed"
        else
            fail "real install gate failed (see out/qemu-install-phase*.log)"
        fi
    fi
else
    msg "Real run skipped (set AIOS_QEMU_INSTALL_TEST=1 --iso ... to enable)"
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
