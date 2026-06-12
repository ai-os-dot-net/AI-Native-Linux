#!/bin/sh
#
# AI-OS.NET R12.7 automated distribution gate sanity test.
#
# Run: sh distro/build/tests/test-rev12-distribution-gates.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"

BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"
QEMU_SMOKE="${BUILD_DIR}/qemu-boot-smoke.sh"
BOOT_GATE="${SCRIPT_DIR}/test-rev12-boot-gate.sh"
INSTALLER_GATE="${SCRIPT_DIR}/test-rev12-installer.sh"
UPDATE_GATE="${SCRIPT_DIR}/test-rev12-repo-update.sh"
RELEASE_GATE="${SCRIPT_DIR}/test-rev12-release-metadata.sh"
SECURITY_GATE="${SCRIPT_DIR}/test-rev12-security-baseline.sh"
INITRAMFS_INIT="${DISTRO_DIR}/aios-boot/initramfs/init"
INTERACTIVE_INSTALL="${DISTRO_DIR}/installer/aios-installer.sh"
QUICK_INSTALL="${DISTRO_DIR}/installer/aios-quick-install.sh"
REPO_PUBLISH="${DISTRO_DIR}/repo/aios-repo-publish.sh"
UPDATE_CLIENT="${DISTRO_DIR}/update/aios-update.sh"

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

    if ! command -v bash >/dev/null 2>&1; then
        fail "bash missing for syntax check: ${_label}"
        return
    fi

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

msg "=== AI-OS.NET R12.7 Automated Distribution Gates ==="

msg "Required files"
check_file "QEMU live boot smoke script exists" "${QEMU_SMOKE}"
check_file "QEMU boot gate test exists" "${BOOT_GATE}"
check_file "Installer gate test exists" "${INSTALLER_GATE}"
check_file "Update/rollback gate test exists" "${UPDATE_GATE}"
check_file "Release metadata gate test exists" "${RELEASE_GATE}"
check_file "Security baseline gate test exists" "${SECURITY_GATE}"
check_file "ISO build script exists" "${BUILD_SCRIPT}"
check_file "Initramfs init exists" "${INITRAMFS_INIT}"
check_file "Interactive installer exists" "${INTERACTIVE_INSTALL}"
check_file "Quick installer exists" "${QUICK_INSTALL}"
check_file "Repo publish script exists" "${REPO_PUBLISH}"
check_file "Update client exists" "${UPDATE_CLIENT}"

msg "Syntax checks"
check_bash_syntax "QEMU live boot smoke script" "${QEMU_SMOKE}"
check_bash_syntax "QEMU boot gate test" "${BOOT_GATE}"
check_bash_syntax "Installer gate test" "${INSTALLER_GATE}"
check_bash_syntax "Update/rollback gate test" "${UPDATE_GATE}"
check_bash_syntax "Release metadata gate test" "${RELEASE_GATE}"
check_bash_syntax "Security baseline gate test" "${SECURITY_GATE}"
check_bash_syntax "ISO build script" "${BUILD_SCRIPT}"
check_bash_syntax "Initramfs init" "${INITRAMFS_INIT}"
check_bash_syntax "Interactive installer" "${INTERACTIVE_INSTALL}"
check_bash_syntax "Quick installer" "${QUICK_INSTALL}"
check_bash_syntax "Repo publish script" "${REPO_PUBLISH}"
check_bash_syntax "Update client" "${UPDATE_CLIENT}"

msg "QEMU live boot smoke markers"
check_grep "Boot gate is wired to qemu-boot-smoke.sh" "${BOOT_GATE}" 'qemu-boot-smoke\.sh'
check_grep "Boot gate uses QEMU dry-run evidence" "${BOOT_GATE}" '--dry-run'
check_grep "QEMU smoke uses qemu-system-x86_64" "${QEMU_SMOKE}" 'qemu-system-x86_64'
check_grep "QEMU smoke requires timeout for bounded boots" "${QEMU_SMOKE}" 'timeout command not found'
check_grep "QEMU smoke detects rescue failure marker" "${QEMU_SMOKE}" 'AIOS-RESCUE'
check_grep "QEMU smoke detects live squashfs boot marker" "${QEMU_SMOKE}" 'AIOS-INIT\.\*Mounting live squashfs'
check_grep "QEMU smoke detects live overlay boot marker" "${QEMU_SMOKE}" 'AIOS-INIT\.\*Live overlay mounted'
check_grep "Initramfs reads kernel cmdline after proc mount" "${INITRAMFS_INIT}" 'Kernel command line loaded'
check_grep "Initramfs loads live media modules before ISO discovery" "${INITRAMFS_INIT}" 'load_live_media_modules'

msg "Installer markers"
check_grep "Installer gate checks interactive installer" "${INSTALLER_GATE}" 'aios-installer\.sh'
check_grep "Installer gate checks quick installer" "${INSTALLER_GATE}" 'aios-quick-install\.sh'
check_grep "Installer gate requires install layout marker" "${INSTALLER_GATE}" 'aios\.install_layout\.v1'
check_grep "Installer gate requires rollback state marker" "${INSTALLER_GATE}" 'aios\.rollback_state\.v1'
check_grep "Interactive installer emits install layout marker" "${INTERACTIVE_INSTALL}" 'aios\.install_layout\.v1'
check_grep "Interactive installer emits rollback state marker" "${INTERACTIVE_INSTALL}" 'aios\.rollback_state\.v1'
check_grep "Quick installer emits install layout marker" "${QUICK_INSTALL}" 'aios\.install_layout\.v1'
check_grep "Quick installer emits rollback state marker" "${QUICK_INSTALL}" 'aios\.rollback_state\.v1'

msg "Update, rollback, and service-health markers"
check_grep "Update gate verifies signed release" "${UPDATE_GATE}" 'Update verify accepts valid signed release'
check_grep "Update gate stages signed release" "${UPDATE_GATE}" 'Update stage succeeds'
check_grep "Update gate activates on passing health" "${UPDATE_GATE}" 'Update activate succeeds when health passes'
check_grep "Update gate forces failed service-health" "${UPDATE_GATE}" '--health-command false'
check_grep "Update gate checks rollback evidence" "${UPDATE_GATE}" '"action":"rollback"'
check_grep "Update client exposes health command option" "${UPDATE_CLIENT}" '--health-command'
check_grep "Update client records service-health pass" "${UPDATE_CLIENT}" 'health check passed'
check_grep "Update client rolls back on service-health failure" "${UPDATE_CLIENT}" 'health check failed; previous deployment restored'
check_grep "Update client has manual rollback command" "${UPDATE_CLIENT}" 'rollback\)[[:space:]]+rollback_previous'

msg "Security baseline markers"
check_grep "Security gate checks Rev.12 security metadata" "${SECURITY_GATE}" 'aios\.security_baseline\.v1'
check_grep "Security gate checks boot-chain metadata" "${SECURITY_GATE}" 'aios\.boot_chain_signing\.v1'
check_grep "Build emits security metadata" "${BUILD_SCRIPT}" 'aios\.security_baseline\.v1'
check_grep "Build emits boot-chain metadata" "${BUILD_SCRIPT}" 'aios\.boot_chain_signing\.v1'
check_grep "Build has signed boot-chain fail gate" "${BUILD_SCRIPT}" 'Boot-chain signature required but missing'
check_grep "Initramfs consumes dm_verity.roothash" "${INITRAMFS_INIT}" 'dm_verity\.roothash'
check_grep "Initramfs stages IMA policy" "${INITRAMFS_INIT}" 'AIOS_IMA_POLICY'

msg "Negative-path markers"
check_grep "Negative: missing live squashfs reaches rescue path" "${INITRAMFS_INIT}" 'AIOS live media with live/aios\.squashfs not found'
check_grep "Negative: missing live squashfs is a QEMU failure marker" "${QEMU_SMOKE}" 'AIOS live media with live/aios\\\.squashfs not found'
check_grep "Negative: interactive installer rejects missing squashfs" "${INTERACTIVE_INSTALL}" 'Squashfs root not found'
check_grep "Negative: quick installer rejects missing squashfs" "${QUICK_INSTALL}" 'Squashfs not found at'
check_grep "Negative: update rejects missing signatures" "${UPDATE_CLIENT}" 'require_file "signature"'
check_grep "Negative: update rejects bad signatures" "${UPDATE_CLIENT}" 'signature verification failed'
check_grep "Negative: update requires SHA256SUMS" "${UPDATE_CLIENT}" 'require_file "release SHA256SUMS"'
check_grep "Negative: update rejects payload hash mismatch" "${UPDATE_CLIENT}" 'release payload hash verification failed'
check_grep "Negative: update test corrupts signed metadata" "${UPDATE_GATE}" 'Corrupt signed metadata is rejected'
check_grep "Negative: update test corrupts artifact hash" "${UPDATE_GATE}" 'Hash-mismatched artifact is rejected'
check_grep "Negative: build catches missing service binaries" "${BUILD_SCRIPT}" 'ExecStart binary missing from rootfs'
check_grep "Negative: build fails on missing service binaries" "${BUILD_SCRIPT}" 'One or more AIOS systemd units reference missing staged binaries'
check_grep "Negative: initramfs detects rootfs verification failure" "${INITRAMFS_INIT}" 'dm-verity: verification FAILED'
check_grep "Negative: initramfs routes rootfs verification failure to rescue" "${INITRAMFS_INIT}" 'dm-verity verification failed'
check_grep "Negative: installer handles missing verity tool" "${INTERACTIVE_INSTALL}" 'veritysetup not found'

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
