#!/bin/sh
#
# AI-OS.NET Rev.12 kernel/module/firmware pipeline sanity test.
#
# Run: sh distro/build/tests/test-rev12-kernel-pipeline.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"
FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

msg "=== AI-OS.NET Rev.12 Kernel Pipeline Tests ==="

if [ -f "${BUILD_SCRIPT}" ]; then
    pass "Build script exists"
else
    fail "Build script missing"
fi

if bash -n "${BUILD_SCRIPT}" 2>/dev/null; then
    pass "Build script syntax OK"
else
    fail "Build script syntax error"
fi

# shellcheck disable=SC2016
for _needle in \
    'KERNEL_VERSION' \
    'KERNEL_MODULES_SOURCE' \
    'KERNEL_FIRMWARE_SOURCE' \
    'infer_kernel_version_from_path' \
    'Step 8b: Staging kernel modules and firmware' \
    'stage_kernel_modules' \
    'stage_kernel_firmware' \
    'modules.dep' \
    'AIOS_MODULES_EMPTY' \
    'AIOS_FIRMWARE_EMPTY' \
    '/usr/lib/modules/${STAGED_KERNEL_VERSION}' \
    '/usr/lib/firmware' \
    'aios.kernel_pipeline.v1' \
    'kernel.json' \
    'signing_hooks' \
    'usr-lib-modules-' \
    'usr-lib-firmware.sig'; do
    if grep -q -- "${_needle}" "${BUILD_SCRIPT}" 2>/dev/null; then
        pass "Kernel pipeline marker present: ${_needle}"
    else
        fail "Kernel pipeline marker missing: ${_needle}"
    fi
done

if grep -q 'aios/kernel.json' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q 'Rev.12 kernel metadata' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q 'Kernel module tree' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q 'Kernel firmware tree' "${BUILD_SCRIPT}" 2>/dev/null; then
    pass "Release verification includes kernel metadata/modules/firmware"
else
    fail "Release verification does not include kernel metadata/modules/firmware"
fi

# shellcheck disable=SC2016
if grep -q 'ROOTFS_DIR}/usr/lib/modules/${STAGED_KERNEL_VERSION}' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q 'INITRAMFS_DIR}/lib/modules/${STAGED_KERNEL_VERSION}' "${BUILD_SCRIPT}" 2>/dev/null; then
    pass "Initramfs copies staged matching module tree"
else
    fail "Initramfs does not copy staged matching module tree"
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
