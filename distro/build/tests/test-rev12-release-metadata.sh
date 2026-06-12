#!/bin/sh
#
# AI-OS.NET Rev.12 release metadata sanity test.
#
# Run: sh distro/build/tests/test-rev12-release-metadata.sh
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

msg "=== AI-OS.NET Rev.12 Release Metadata Tests ==="

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

for _verify in \
    'Rev.12 manifest' \
    'Rev.12 SBOM' \
    'Rev.12 provenance' \
    'Rev.12 SHA256SUMS' \
    'Rev.12 signatures dir'; do
    if grep -q -- "${_verify}" "${BUILD_SCRIPT}" 2>/dev/null; then
        pass "Verification checks: ${_verify}"
    else
        fail "Verification missing: ${_verify}"
    fi
done

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
