#!/bin/bash
#
# AI-OS.NET Rev.12 kernel/module/firmware pipeline gate.
#
# Validates the kernel pipeline acceptance tests from
# distro/build/REV12-DISTRIBUTION-SPEC.md section 8 in two layers:
#
#   1. STATIC checks — build script exists, parses, and still contains the
#      Step 8/8b/9 kernel-staging code paths and the kernel.json emission.
#      Fast, no build dependencies. Weak evidence by itself — source-text
#      greps prove nothing about what actually gets written to disk — kept
#      only as an early smoke signal.
#
#   2. DYNAMIC checks (run by default) — actually invoke build-aios-iso.sh
#      far enough to stage a REAL kernel image, a REAL (small) module tree
#      copied from the host, an explicitly-empty firmware tree, and build
#      the real initramfs cpio.xz — then validate the produced
#      live/vmlinuz, live/initrd.img, rootfs/usr/lib/modules/<version>,
#      rootfs/usr/lib/firmware, and aios/kernel.json against each other
#      with validate-rev12-kernel-pipeline.py, plus inline checks that the
#      initramfs actually decompresses and contains an init script.
#
# Why a *custom* --kernel-modules-source directory instead of plain
# --kernel-modules-source auto (which stages the full host module tree):
# copying the full host /usr/lib/modules/<version> tree (hundreds of MB)
# into the initramfs and xz -9 compressing it took over 2 minutes and
# exceeded the interactive verification budget for this gate. Instead this
# test builds a small scratch module source directory containing the
# REAL host modules.dep plus a few of the smallest REAL *.ko(.zst) files
# for the exact kernel version build-aios-iso.sh will select (mirroring its
# own host-kernel-selection logic) — real files, small archive, ~4s build.
# Firmware uses --kernel-firmware-source none (explicit-empty), matching
# the proven-cheap pattern from test-rev12-release-metadata.sh; the
# validator still asserts kernel.json truthfully reports that empty state.
#
# The dynamic layer SKIPs (not PASSes) if mksquashfs, xorriso, python3, or
# cargo are not on PATH, or if the host has no /usr/lib/modules/*/vmlinuz
# kernel layout to stage real module content from — there is no cheaper
# way to reach a REAL kernel/module/firmware build without them.
#
# Run: bash distro/build/tests/test-rev12-kernel-pipeline.sh
#
# Env overrides:
#   AIOS_BUILD_WORKDIR   Reuse an existing build workdir instead of a
#                        fresh mktemp scratch dir (skips cleanup too).
#   AIOS_TEST_KEEP_WORKDIR=1
#                        Keep the scratch workdir after the test for
#                        inspection instead of deleting it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"
VALIDATOR="${SCRIPT_DIR}/validate-rev12-kernel-pipeline.py"
FAILED=0
PASSED=0
SKIPPED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }
skip() { SKIPPED=$(( SKIPPED + 1 )); printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; }

msg "=== AI-OS.NET Rev.12 Kernel Pipeline Tests ==="

# ─────────────────────────────────────────────────────────────────────────
# Layer 1: STATIC smoke checks (no build dependencies)
# ─────────────────────────────────────────────────────────────────────────

msg "--- Layer 1: static smoke checks ---"

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

if [ -f "${VALIDATOR}" ]; then
    pass "Kernel pipeline validator helper exists (validate-rev12-kernel-pipeline.py)"
else
    fail "Kernel pipeline validator helper missing: ${VALIDATOR}"
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

# ─────────────────────────────────────────────────────────────────────────
# Layer 2: DYNAMIC checks — actually stage real kernel/module/firmware
# output and validate it against kernel.json. This is the authoritative
# layer; Layer 1 only proves the source text still mentions the right
# staging functions and filenames.
# ─────────────────────────────────────────────────────────────────────────

msg "--- Layer 2: dynamic kernel pipeline checks ---"

DYNAMIC_PREREQS_OK=true

if ! command -v mksquashfs >/dev/null 2>&1; then
    skip "Dynamic kernel pipeline build (mksquashfs not on PATH — required by build-aios-iso.sh preflight)"
    DYNAMIC_PREREQS_OK=false
fi

if ! command -v xorriso >/dev/null 2>&1; then
    skip "Dynamic kernel pipeline build (xorriso not on PATH — required by build-aios-iso.sh preflight)"
    DYNAMIC_PREREQS_OK=false
fi

if ! command -v python3 >/dev/null 2>&1; then
    skip "Dynamic kernel pipeline validation (python3 not on PATH)"
    DYNAMIC_PREREQS_OK=false
fi

if ! command -v cargo >/dev/null 2>&1; then
    skip "Dynamic kernel pipeline build (cargo not on PATH)"
    DYNAMIC_PREREQS_OK=false
fi

for _tool in xz cpio; do
    if ! command -v "${_tool}" >/dev/null 2>&1; then
        skip "Dynamic kernel pipeline validation (${_tool} not on PATH)"
        DYNAMIC_PREREQS_OK=false
    fi
done

# Mirror build-aios-iso.sh's own host-kernel-selection logic (Step 8,
# KERNEL_SOURCE=host default): first /usr/lib/modules/<version>/vmlinuz
# found in glob order. If the host has no such kernel layout there is no
# cheap way to stage a REAL module tree that matches a REAL staged kernel.
HOST_KERNEL_VMLINUZ=""
HOST_KERNEL_VERSION=""
if [ "${DYNAMIC_PREREQS_OK}" = true ]; then
    if [ -d /usr/lib/modules ]; then
        for _kdir in /usr/lib/modules/*/; do
            _candidate="${_kdir}vmlinuz"
            if [ -f "${_candidate}" ]; then
                HOST_KERNEL_VMLINUZ="${_candidate}"
                HOST_KERNEL_VERSION="$(basename "${_kdir%/}")"
                break
            fi
        done
    fi

    if [ -z "${HOST_KERNEL_VMLINUZ}" ]; then
        skip "Dynamic kernel pipeline build (no /usr/lib/modules/*/vmlinuz on host — build-aios-iso.sh's default KERNEL_SOURCE=host has nothing to stage)"
        DYNAMIC_PREREQS_OK=false
    elif [ ! -f "/usr/lib/modules/${HOST_KERNEL_VERSION}/modules.dep" ]; then
        skip "Dynamic kernel pipeline build (host kernel ${HOST_KERNEL_VERSION} has no modules.dep — cannot stage a REAL matching module tree)"
        DYNAMIC_PREREQS_OK=false
    fi
fi

if [ "${DYNAMIC_PREREQS_OK}" = true ]; then
    CREATED_WORKDIR=false
    if [ -z "${AIOS_BUILD_WORKDIR:-}" ]; then
        WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/aios-rev12-kernel-test.XXXXXX")"
        CREATED_WORKDIR=true
    else
        WORKDIR="${AIOS_BUILD_WORKDIR}"
        mkdir -p "${WORKDIR}"
    fi

    cleanup() {
        if [ "${CREATED_WORKDIR}" = true ] && [ "${AIOS_TEST_KEEP_WORKDIR:-0}" != "1" ]; then
            rm -rf "${WORKDIR}"
        fi
    }
    trap cleanup EXIT

    BUILD_LOG="${WORKDIR}/build.log"
    ISO_STAGING_DIR="${WORKDIR}/iso"
    HOST_MODULES_DIR="/usr/lib/modules/${HOST_KERNEL_VERSION}"
    MODULES_SRC_DIR="${WORKDIR}/kmods-src"

    msg "Staging a small REAL module source for kernel ${HOST_KERNEL_VERSION} in ${MODULES_SRC_DIR}"

    mkdir -p "${MODULES_SRC_DIR}/${HOST_KERNEL_VERSION}"
    cp "${HOST_MODULES_DIR}/modules.dep" "${MODULES_SRC_DIR}/${HOST_KERNEL_VERSION}/modules.dep"

    # Copy up to 3 of the smallest REAL *.ko(.zst|.xz|.gz) module files so
    # the staged tree carries actual module payloads, not just the index.
    COPIED_KO_COUNT=0
    while IFS= read -r _ko; do
        [ -n "${_ko}" ] || continue
        _rel="${_ko#"${HOST_MODULES_DIR}"/}"
        mkdir -p "${MODULES_SRC_DIR}/${HOST_KERNEL_VERSION}/$(dirname "${_rel}")"
        cp "${_ko}" "${MODULES_SRC_DIR}/${HOST_KERNEL_VERSION}/${_rel}"
        COPIED_KO_COUNT=$(( COPIED_KO_COUNT + 1 ))
    done < <(find "${HOST_MODULES_DIR}" -name '*.ko*' -type f -printf '%s %p\n' 2>/dev/null \
                | sort -n | head -n 3 | awk '{ $1=""; sub(/^ /, ""); print }')

    info_ko_count="${COPIED_KO_COUNT}"
    msg "Staged modules.dep + ${info_ko_count} real .ko module file(s) for kernel ${HOST_KERNEL_VERSION}"

    msg "Running kernel-pipeline build in ${WORKDIR} (log: ${BUILD_LOG})"

    BUILD_EXIT=0
    AIOS_BUILD_WORKDIR="${WORKDIR}" \
        "${BUILD_SCRIPT}" \
            --debug \
            --allow-scaffold-rootfs \
            --kernel-modules-source "${MODULES_SRC_DIR}" \
            --kernel-firmware-source none \
            --output "${WORKDIR}/aios-kernel-pipeline-test.iso" \
            --jobs "$(nproc 2>/dev/null || echo 2)" \
            > "${BUILD_LOG}" 2>&1 || BUILD_EXIT=$?

    if [ -d "${ISO_STAGING_DIR}/aios" ] && [ -f "${ISO_STAGING_DIR}/live/vmlinuz" ]; then
        pass "Build staged a real kernel and reached Step 11 (build exit=${BUILD_EXIT})"
    else
        fail "Build did NOT stage a real kernel / reach Step 11 — ${ISO_STAGING_DIR}/live/vmlinuz or aios/ missing (build exit=${BUILD_EXIT})"
        printf '  --- last 40 lines of build log (%s) ---\n' "${BUILD_LOG}" >&2
        tail -n 40 "${BUILD_LOG}" >&2 || true
    fi

    if [ -d "${ISO_STAGING_DIR}/aios" ]; then
        msg "Validating staged kernel/module/firmware output against kernel.json with validate-rev12-kernel-pipeline.py"
        VALIDATOR_OUT="$(python3 "${VALIDATOR}" "${WORKDIR}")"
        if [ -z "${VALIDATOR_OUT}" ]; then
            fail "Kernel pipeline validator produced no output — validator or workdir contract broken"
        else
            while IFS=$'\t' read -r _status _message; do
                [ -n "${_status}" ] || continue
                case "${_status}" in
                    PASS) pass "${_message}" ;;
                    FAIL) fail "${_message}" ;;
                    *)    fail "Validator emitted unrecognized status '${_status}': ${_message}" ;;
                esac
            done <<< "${VALIDATOR_OUT}"
        fi

        # Inline check: the initramfs must actually decompress and contain
        # an init script — spec sec.8 requires a real, bootable initramfs,
        # not merely a file that happens to exist at live/initrd.img.
        INITRD="${ISO_STAGING_DIR}/live/initrd.img"
        if [ -f "${INITRD}" ]; then
            if xz -t "${INITRD}" 2>/dev/null; then
                pass "live/initrd.img: xz -t confirms valid xz compression"

                CPIO_LISTING="$(xz -dc "${INITRD}" 2>/dev/null | cpio -t 2>/dev/null || true)"
                if printf '%s\n' "${CPIO_LISTING}" | grep -qx 'init'; then
                    pass "live/initrd.img: decompressed cpio archive contains the init script"
                else
                    fail "live/initrd.img: decompressed cpio archive does NOT contain an 'init' entry"
                fi
            else
                fail "live/initrd.img: xz -t reports invalid/corrupt xz stream"
            fi
        else
            fail "live/initrd.img: missing, cannot verify cpio contents"
        fi
    fi
else
    skip "Dynamic kernel pipeline validation skipped entirely — missing prerequisite(s) above"
fi

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
