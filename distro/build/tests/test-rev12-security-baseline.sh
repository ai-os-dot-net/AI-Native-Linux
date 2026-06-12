#!/bin/sh
#
# AI-OS.NET Rev.12 security baseline sanity test.
#
# Run: sh distro/build/tests/test-rev12-security-baseline.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"
INITRAMFS_INIT="${DISTRO_DIR}/aios-boot/initramfs/init"
PREINIT="${DISTRO_DIR}/aios-boot/initramfs/aios-preinit"
RESCUE="${DISTRO_DIR}/aios-boot/initramfs/rescue.sh"
QUICK_INSTALL="${DISTRO_DIR}/installer/aios-quick-install.sh"
INTERACTIVE_INSTALL="${DISTRO_DIR}/installer/aios-installer.sh"
FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

check_file() {
    _label="$1"
    _file="$2"
    if [ -f "${_file}" ]; then
        pass "${_label}"
    else
        fail "${_label} missing: ${_file}"
    fi
}

check_bash_syntax() {
    _label="$1"
    _file="$2"
    if bash -n "${_file}" 2>/dev/null; then
        pass "${_label} syntax OK"
    else
        fail "${_label} syntax error"
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

msg "=== AI-OS.NET Rev.12 Security Baseline Tests ==="

for _entry in \
    "Build script:${BUILD_SCRIPT}" \
    "Initramfs init:${INITRAMFS_INIT}" \
    "Preinit config:${PREINIT}" \
    "Rescue shell:${RESCUE}" \
    "Quick installer:${QUICK_INSTALL}" \
    "Interactive installer:${INTERACTIVE_INSTALL}"; do
    check_file "${_entry%%:*} exists" "${_entry#*:}"
done

for _entry in \
    "Build script:${BUILD_SCRIPT}" \
    "Initramfs init:${INITRAMFS_INIT}" \
    "Rescue shell:${RESCUE}" \
    "Quick installer:${QUICK_INSTALL}" \
    "Interactive installer:${INTERACTIVE_INSTALL}"; do
    check_bash_syntax "${_entry%%:*}" "${_entry#*:}"
done

msg "Build metadata and rootfs policy markers"
for _needle in \
    'AIOS_SECURITY_PROFILE' \
    'AIOS_SELINUX_MODE' \
    'AIOS_SELINUX_POLICY_SOURCE' \
    'AIOS_REQUIRE_BOOT_SIGNATURES' \
    'AIOS_SIGNATURE_SOURCE_DIR' \
    'aios.security_baseline.v1' \
    'aios.boot_chain_signing.v1' \
    'security.json' \
    'boot-chain.json' \
    '/etc/ima/ima-policy' \
    '/etc/evm/evm-policy' \
    'rootfs-policy.json' \
    'dm_verity.roothash' \
    'Boot-chain signature required but missing' \
    'Rev.12 security metadata' \
    'Rev.12 boot chain metadata'; do
    check_grep "Build script marker: ${_needle}" "${BUILD_SCRIPT}" "${_needle}"
done

check_grep "Build blocks enforcing without a binary policy" "${BUILD_SCRIPT}" 'SELinux enforcing requires --selinux-policy-source'
check_grep "Build stages IMA policy into initramfs" "${BUILD_SCRIPT}" 'INITRAMFS_DIR}/etc/ima/ima-policy'
check_grep "Build stages EVM policy into initramfs" "${BUILD_SCRIPT}" 'INITRAMFS_DIR}/etc/evm/evm-policy'

msg "Initramfs security enforcement markers"
for _needle in \
    'AIOS_IMA_POLICY' \
    'AIOS_EVM_POLICY' \
    'Loading IMA policy' \
    'dm_verity.roothash' \
    'dm-verity required but root hash is missing' \
    'dm-verity required but data/hash device is missing' \
    'dm-verity verification failed'; do
    check_grep "Initramfs marker: ${_needle}" "${INITRAMFS_INIT}" "${_needle}"
done
check_not_grep "Initramfs no longer ignores dm-verity corruption" "${INITRAMFS_INIT}" '--ignore-corruption'
check_grep "Preinit defines IMA policy path" "${PREINIT}" 'AIOS_IMA_POLICY=/etc/ima/ima-policy'
check_grep "Preinit defines EVM policy path" "${PREINIT}" 'AIOS_EVM_POLICY=/etc/evm/evm-policy'

msg "Installer consistency markers"
# shellcheck disable=SC2016
for _needle in \
    'AIOS_HASH' \
    'ROOT_HASH_PART' \
    'ROOT_HASH_DEV' \
    'AIOS_HASH_SIZE_MB' \
    'roothash.sig' \
    'dm_verity.roothash' \
    'AIOS_SELINUX_MODE' \
    'SELINUX=\${SELINUX_MODE}' \
    'Placeholder/no policy|placeholder/no policy'; do
    check_grep "Interactive installer marker: ${_needle}" "${INTERACTIVE_INSTALL}" "${_needle}"
done

# shellcheck disable=SC2016
for _needle in \
    'AIOS_HASH' \
    'ROOT_HASH_PART' \
    'ROOT_HASH_DEV' \
    'AIOS_HASH_SIZE_MB' \
    'roothash.sig' \
    'dm_verity.roothash' \
    'AIOS_SELINUX_MODE' \
    'SELINUX=\${SELINUX_MODE}'; do
    check_grep "Quick installer marker: ${_needle}" "${QUICK_INSTALL}" "${_needle}"
done

msg "Recovery repair markers"
check_grep "Rescue provides security policy repair command" "${RESCUE}" 'aios-repair-security-policy'
check_grep "Rescue provides rollback state repair command" "${RESCUE}" 'aios-repair-rollback-state'
check_grep "Rescue repair touches autorelabel" "${RESCUE}" '\.autorelabel'

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
