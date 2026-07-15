#!/bin/sh
#
# AI-OS.NET R13.1 openSUSE base and lifecycle sanity test.
#
# Run: sh distro/build/tests/test-rev13-opensuse-base.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${BUILD_DIR}/../.." && pwd)"

OPENSUSE_BUILDER="${BUILD_DIR}/build-opensuse-rootfs.sh"
ISO_BUILDER="${BUILD_DIR}/build-aios-iso.sh"
CI_FILE="${REPO_ROOT}/.gitlab-ci.yml"
MAKEFILE="${BUILD_DIR}/Makefile"
SPEC="${BUILD_DIR}/REV13-ENTERPRISE-SPEC.md"
PLAN="${BUILD_DIR}/REV12-REV13-IMPLEMENTATION-PLAN.md"
DRY_LOG="${TMPDIR:-/tmp}/aios-r13-opensuse-dry-run.$$"
NO_BASE_LOG="${TMPDIR:-/tmp}/aios-r13-enterprise-no-base.$$"
MISMATCH_LOG="${TMPDIR:-/tmp}/aios-r13-enterprise-mismatch.$$"
MISMATCH_ROOT="${TMPDIR:-/tmp}/aios-r13-rootfs-mismatch-$$"

FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

trap 'rm -f "${DRY_LOG}" "${NO_BASE_LOG}" "${MISMATCH_LOG}" "${MISMATCH_ROOT}/etc/aios/base-rootfs.env"; rmdir "${MISMATCH_ROOT}/etc/aios" "${MISMATCH_ROOT}/etc" "${MISMATCH_ROOT}" 2>/dev/null || true' EXIT

check_file() {
    _label="$1"
    _file="$2"

    if [ -f "${_file}" ]; then
        pass "${_label}"
    else
        fail "${_label} missing: ${_file}"
    fi
}

check_exec() {
    _label="$1"
    _file="$2"

    if [ -x "${_file}" ]; then
        pass "${_label}"
    else
        fail "${_label} not executable: ${_file}"
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

msg "=== AI-OS.NET R13.1 openSUSE Base Gate ==="

msg "Required files"
check_file "openSUSE rootfs builder exists" "${OPENSUSE_BUILDER}"
check_exec "openSUSE rootfs builder is executable" "${OPENSUSE_BUILDER}"
check_file "ISO builder exists" "${ISO_BUILDER}"
check_file "R13 enterprise spec exists" "${SPEC}"
check_file "R12/R13 implementation plan exists" "${PLAN}"

msg "Syntax checks"
check_bash_syntax "openSUSE rootfs builder" "${OPENSUSE_BUILDER}"
check_bash_syntax "ISO builder" "${ISO_BUILDER}"

msg "openSUSE builder contract"
check_grep "Builder locks openSUSE family metadata" "${OPENSUSE_BUILDER}" 'AIOS_BASE_FAMILY=opensuse'
check_grep "Builder defaults to Leap 16.0" "${OPENSUSE_BUILDER}" 'AIOS_OPENSUSE_RELEASE:-16\.0'
check_grep "Builder records Leap 16.x series" "${OPENSUSE_BUILDER}" 'AIOS_OPENSUSE_SERIES:-16\.x'
check_grep "Builder records 24-month support" "${OPENSUSE_BUILDER}" 'AIOS_OPENSUSE_SUPPORT_MONTHS:-24'
check_grep "Builder records default EOL date" "${OPENSUSE_BUILDER}" 'AIOS_OPENSUSE_EOL_DATE:-2027-10-31'
check_grep "Builder supports partial rootfs resume" "${OPENSUSE_BUILDER}" '--resume'
check_grep "Builder requires root for real zypper install" "${OPENSUSE_BUILDER}" 'real openSUSE rootfs build requires root'
check_grep "Builder emits base-rootfs env" "${OPENSUSE_BUILDER}" 'base-rootfs\.env'
check_grep "Builder emits base-rootfs JSON" "${OPENSUSE_BUILDER}" 'aios\.base_rootfs\.v1'
check_grep "Builder uses zypper root install" "${OPENSUSE_BUILDER}" 'zypper'
check_grep "Builder preinitializes RPM GPG target dir" "${OPENSUSE_BUILDER}" 'usr/lib/rpm/gnupg/keys'
check_grep "Builder settles before first zypper target init" "${OPENSUSE_BUILDER}" 'AIOS_ZYPPER_SETTLE_SECONDS'
check_grep "Builder retries zypper target init failures" "${OPENSUSE_BUILDER}" 'Retrying zypper command after target initialization failure'
check_grep "Builder detects zypper false success output" "${OPENSUSE_BUILDER}" 'Target initialization failed'
check_grep "Builder verifies repo file after addrepo" "${OPENSUSE_BUILDER}" 'zypper did not create repository file'
check_grep "Builder skips invalid Leap 16 update repo" "${OPENSUSE_BUILDER}" 'has no dedicated update repo'
check_grep "Builder includes vendor kernel" "${OPENSUSE_BUILDER}" 'kernel-default'
check_grep "Builder includes Leap 16 firmware package" "${OPENSUSE_BUILDER}" 'kernel-firmware-all'
check_absent "Builder does not require removed systemd-sysvinit package" "${OPENSUSE_BUILDER}" 'systemd-sysvinit'
check_grep "Builder includes secure boot tooling" "${OPENSUSE_BUILDER}" 'shim'
check_grep "Builder includes TPM tooling" "${OPENSUSE_BUILDER}" 'tpm2\.0-tools'
# R13.4: tpm2.0-tools brings the tss2 stack but no TCTI *driver*. Without one,
# every TPM call fails with "TPM TCTI driver not available" despite /dev/tpm0
# existing, so systemd-cryptenroll never enrols a TPM2 token. Measured in a
# local QEMU+swtpm install run, not inferred.
check_grep "Builder includes a TPM2 TCTI device driver (not just the tss2 stack)" \
    "${OPENSUSE_BUILDER}" '^\s*libtss2-tcti-device0\s'
# Defect #12a (pipeline 5309): the systemd package ships bootctl but NOT the
# loader payload. Without the separate systemd-boot package the installed ESP
# held zero .efi files and the firmware dropped to the EFI shell, while bootctl
# had already "succeeded". A bootctl-only package set is the regression.
check_grep "Builder includes the systemd-boot loader payload package" \
    "${OPENSUSE_BUILDER}" '^\s*systemd-boot\s*$'
# dracut must be present: zypper --root runs no kernel hooks, so the rootfs
# ships no initramfs and the installer has to build one (defect #12b).
check_grep "Builder includes dracut for installer-side initramfs generation" \
    "${OPENSUSE_BUILDER}" '^\s*dracut\s*$'

msg "ISO enterprise gate"
check_grep "ISO builder has enterprise flag" "${ISO_BUILDER}" '--enterprise-release'
check_grep "ISO builder blocks non-openSUSE enterprise rootfs" "${ISO_BUILDER}" 'Enterprise release requires openSUSE base metadata'
check_grep "ISO builder blocks rootfs/ISO arch mismatch" "${ISO_BUILDER}" 'Enterprise rootfs arch mismatch'
check_grep "ISO builder emits R13 base metadata" "${ISO_BUILDER}" 'aios/base\.json'
check_grep "ISO builder emits boolean enterprise metadata" "${ISO_BUILDER}" 'ENTERPRISE_RELEASE_JSON'
check_grep "ISO builder includes base metadata in provenance" "${ISO_BUILDER}" '"base_rootfs"'
check_grep "ISO builder verifies base metadata" "${ISO_BUILDER}" 'Rev\.13 base metadata'

msg "Build integration"
check_grep "Makefile exposes openSUSE rootfs target" "${MAKEFILE}" '^opensuse-rootfs:'
check_grep "Makefile exposes enterprise ISO target" "${MAKEFILE}" '^enterprise-iso:'
check_grep "CI shellchecks openSUSE builder" "${CI_FILE}" 'build-opensuse-rootfs\.sh'
check_grep "CI runs R13 openSUSE test" "${CI_FILE}" 'test-rev13-opensuse-base\.sh'
check_grep "CI can build optional openSUSE rootfs" "${CI_FILE}" 'AIOS_BUILD_OPENSUSE_ROOTFS'
check_grep "CI passes enterprise release flag" "${CI_FILE}" '--enterprise-release'
check_grep "ci-build-all can build optional openSUSE rootfs" "${BUILD_DIR}/ci-build-all.sh" 'AIOS_BUILD_OPENSUSE_ROOTFS'
check_grep "ci-build-all passes enterprise release flag" "${BUILD_DIR}/ci-build-all.sh" '--enterprise-release'

msg "Enterprise negative gates"
if "${ISO_BUILDER}" --enterprise-release --output "${TMPDIR:-/tmp}/aios-r13-no-base.iso" >"${NO_BASE_LOG}" 2>&1; then
    fail "Enterprise ISO unexpectedly accepted missing base rootfs"
else
    pass "Enterprise ISO rejects missing base rootfs"
fi
check_grep "Missing base rootfs error is explicit" "${NO_BASE_LOG}" 'Enterprise release requires --base-rootfs'

mkdir -p "${MISMATCH_ROOT}/etc/aios"
cat > "${MISMATCH_ROOT}/etc/aios/base-rootfs.env" <<'EOF'
AIOS_BASE_FAMILY=opensuse
AIOS_BASE_VARIANT=leap
AIOS_BASE_VERSION=16.0
AIOS_BASE_SERIES=16.x
AIOS_BASE_ARCH=aarch64
AIOS_BASE_SUPPORT_MONTHS=24
AIOS_BASE_EOL_DATE=2027-10-31
AIOS_BASE_KERNEL_POLICY=vendor-kernel
AIOS_BASE_PACKAGE_POLICY=hybrid-rpm-aios
AIOS_BASE_REPO_OSS=https://download.opensuse.org/distribution/leap/16.0/repo/oss/
AIOS_BASE_REPO_UPDATE=https://download.opensuse.org/update/leap/16.0/oss/
AIOS_BASE_BUILDER=build-opensuse-rootfs.sh
EOF

if "${ISO_BUILDER}" \
    --enterprise-release \
    --base-rootfs "${MISMATCH_ROOT}" \
    --arch x86_64 \
    --output "${TMPDIR:-/tmp}/aios-r13-mismatch.iso" >"${MISMATCH_LOG}" 2>&1; then
    fail "Enterprise ISO unexpectedly accepted rootfs/ISO arch mismatch"
else
    pass "Enterprise ISO rejects rootfs/ISO arch mismatch"
fi
check_grep "Architecture mismatch error is explicit" "${MISMATCH_LOG}" 'Enterprise rootfs arch mismatch'

msg "Specification lock"
check_grep "Spec locks openSUSE Leap 16.x" "${SPEC}" 'openSUSE Leap 16\.x'
check_grep "Spec locks Leap 16.0 primary release" "${SPEC}" 'openSUSE Leap 16\.0'
check_grep "Spec locks x86_64 first" "${SPEC}" 'x86_64.*first enterprise gate'
check_grep "Spec gates aarch64 on CI proof" "${SPEC}" 'aarch64.*CI proof'
check_grep "Spec records 24-month support" "${SPEC}" '24 months per minor release'
check_grep "Spec records default EOL" "${SPEC}" '2027-10-31'
check_grep "Plan records openSUSE base" "${PLAN}" 'openSUSE Leap 16\.x'

msg "Dry-run rootfs command"
if "${OPENSUSE_BUILDER}" \
    --dry-run \
    --output "${TMPDIR:-/tmp}/aios-r13-opensuse-rootfs-$$" \
    --release 16.0 \
    --arch x86_64 \
    --package-set minimal >"${DRY_LOG}" 2>&1; then
    pass "openSUSE builder dry-run succeeds"
else
    fail "openSUSE builder dry-run failed"
fi

check_grep "Dry-run prints Leap 16.0" "${DRY_LOG}" 'openSUSE Leap 16\.0'
check_grep "Dry-run prints zypper commands" "${DRY_LOG}" 'zypper'
check_grep "Dry-run uses openSUSE OSS repo" "${DRY_LOG}" 'download\.opensuse\.org/distribution/leap/16\.0/repo/oss'
check_grep "Dry-run would write env metadata" "${DRY_LOG}" 'would write .*/base-rootfs\.env'
check_grep "Dry-run would write JSON metadata" "${DRY_LOG}" 'would write .*/base-rootfs\.json'

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
