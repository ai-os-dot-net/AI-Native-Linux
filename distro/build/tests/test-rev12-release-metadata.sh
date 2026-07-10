#!/bin/bash
#
# AI-OS.NET Rev.12 release metadata gate.
#
# Validates the release metadata contract from
# distro/build/REV12-DISTRIBUTION-SPEC.md section 7 ("SBOM and provenance
# requirements" + "Acceptance tests") in two layers:
#
#   1. STATIC checks — build script exists, parses, and still contains the
#      Step 11 metadata-emission code paths. Fast, no build dependencies.
#      Weak evidence by itself (source-text greps prove nothing about what
#      actually gets written to disk) — kept only as an early smoke signal.
#
#   2. DYNAMIC checks (run by default) — actually invoke build-aios-iso.sh
#      far enough to emit the real manifest.json, sbom.cdx.json,
#      provenance.json, security.json, boot-chain.json, kernel.json files
#      into a scratch ISO staging directory, then validate each one with
#      validate-rev12-metadata.py: JSON parses, required schema/fields are
#      present, artifact sha256/size_bytes entries are cross-checked
#      against the actual staged files on disk.
#
# The dynamic layer uses:
#   --debug --allow-scaffold-rootfs --kernel-modules-source none \
#   --kernel-firmware-source none
# This is the cheapest invocation that still reaches Step 11 (metadata
# generation happens after Step 10 squashfs assembly, so kernel/module/
# firmware staging and mksquashfs must run — but a full bootable
# --base-rootfs and --release compile are not required to reach it).
#
# The dynamic layer SKIPs (not PASSes) if mksquashfs or xorriso are not
# on PATH — those are hard preflight requirements in build-aios-iso.sh
# and there is no cheaper way to reach Step 11 without them.
#
# Run: bash distro/build/tests/test-rev12-release-metadata.sh
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
VALIDATOR="${SCRIPT_DIR}/validate-rev12-metadata.py"
FAILED=0
PASSED=0
SKIPPED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }
skip() { SKIPPED=$(( SKIPPED + 1 )); printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; }

msg "=== AI-OS.NET Rev.12 Release Metadata Tests ==="

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
    pass "JSON validator helper exists (validate-rev12-metadata.py)"
else
    fail "JSON validator helper missing: ${VALIDATOR}"
fi

for _needle in \
    'Step 11: Generating Rev.12 release metadata' \
    'aios.release_manifest.v1' \
    'manifest.json' \
    'sbom.cdx.json' \
    'CycloneDX' \
    'provenance.json' \
    'aios.provenance.v1' \
    'SHA256SUMS' \
    'signatures/README' \
    'sha256sum' \
    'live/aios.squashfs' \
    'live/initrd.img' \
    'live/vmlinuz'; do
    if grep -q -- "${_needle}" "${BUILD_SCRIPT}" 2>/dev/null; then
        pass "Build script contains metadata marker: ${_needle}"
    else
        fail "Build script missing metadata marker: ${_needle}"
    fi
done

# ─────────────────────────────────────────────────────────────────────────
# Layer 2: DYNAMIC checks — actually build the metadata and validate the
# generated JSON artifacts. This is the authoritative layer; Layer 1 only
# proves the source text still mentions the right filenames.
# ─────────────────────────────────────────────────────────────────────────

msg "--- Layer 2: dynamic artifact checks ---"

DYNAMIC_PREREQS_OK=true

if ! command -v mksquashfs >/dev/null 2>&1; then
    skip "Dynamic metadata build (mksquashfs not on PATH — required by build-aios-iso.sh preflight)"
    DYNAMIC_PREREQS_OK=false
fi

if ! command -v xorriso >/dev/null 2>&1; then
    skip "Dynamic metadata build (xorriso not on PATH — required by build-aios-iso.sh preflight)"
    DYNAMIC_PREREQS_OK=false
fi

if ! command -v python3 >/dev/null 2>&1; then
    skip "Dynamic metadata validation (python3 not on PATH)"
    DYNAMIC_PREREQS_OK=false
fi

if ! command -v cargo >/dev/null 2>&1; then
    skip "Dynamic metadata build (cargo not on PATH)"
    DYNAMIC_PREREQS_OK=false
fi

if [ "${DYNAMIC_PREREQS_OK}" = true ]; then
    CREATED_WORKDIR=false
    if [ -z "${AIOS_BUILD_WORKDIR:-}" ]; then
        WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/aios-rev12-metadata-test.XXXXXX")"
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

    msg "Running scaffold metadata build in ${WORKDIR} (log: ${BUILD_LOG})"

    BUILD_EXIT=0
    AIOS_BUILD_WORKDIR="${WORKDIR}" \
        "${BUILD_SCRIPT}" \
            --debug \
            --allow-scaffold-rootfs \
            --kernel-modules-source none \
            --kernel-firmware-source none \
            --output "${WORKDIR}/aios-metadata-test.iso" \
            --jobs "$(nproc 2>/dev/null || echo 2)" \
            > "${BUILD_LOG}" 2>&1 || BUILD_EXIT=$?

    if [ -d "${ISO_STAGING_DIR}/aios" ]; then
        pass "Build reached Step 11: ${ISO_STAGING_DIR}/aios metadata directory exists (build exit=${BUILD_EXIT})"
    else
        fail "Build did NOT reach Step 11 — ${ISO_STAGING_DIR}/aios missing (build exit=${BUILD_EXIT})"
        printf '  --- last 40 lines of build log (%s) ---\n' "${BUILD_LOG}" >&2
        tail -n 40 "${BUILD_LOG}" >&2 || true
    fi

    if [ -d "${ISO_STAGING_DIR}/aios" ]; then
        msg "Validating generated JSON artifacts with validate-rev12-metadata.py"
        VALIDATOR_OUT="$(python3 "${VALIDATOR}" "${ISO_STAGING_DIR}")"
        if [ -z "${VALIDATOR_OUT}" ]; then
            fail "JSON validator produced no output — validator or staging dir contract broken"
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
    fi
else
    skip "Dynamic artifact validation skipped entirely — missing prerequisite tool(s) above"
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
