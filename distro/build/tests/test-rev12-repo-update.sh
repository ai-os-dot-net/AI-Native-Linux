#!/bin/sh
#
# AI-OS.NET Rev.12 signed repository and update/rollback sanity test.
#
# Run: sh distro/build/tests/test-rev12-repo-update.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"
PUBLISH_SCRIPT="${DISTRO_DIR}/repo/aios-repo-publish.sh"
UPDATE_SCRIPT="${DISTRO_DIR}/update/aios-update.sh"
TMP_ROOT=""
FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

# shellcheck disable=SC2317,SC2329
cleanup() {
    if [ -n "${TMP_ROOT}" ] && [ -d "${TMP_ROOT}" ]; then
        case "${TMP_ROOT}" in
            /tmp/aios-repo-update.*) rm -rf "${TMP_ROOT}" ;;
        esac
    fi
}
trap cleanup EXIT INT TERM

msg "=== AI-OS.NET Rev.12 Signed Repo/Update Tests ==="

for _script in "${PUBLISH_SCRIPT}" "${UPDATE_SCRIPT}"; do
    if [ -f "${_script}" ]; then
        pass "Script exists: ${_script#"${DISTRO_DIR}"/}"
    else
        fail "Script missing: ${_script#"${DISTRO_DIR}"/}"
    fi

    if [ -x "${_script}" ]; then
        pass "Script is executable: ${_script#"${DISTRO_DIR}"/}"
    else
        fail "Script is not executable: ${_script#"${DISTRO_DIR}"/}"
    fi

    if bash -n "${_script}" 2>/dev/null; then
        pass "Syntax OK: ${_script#"${DISTRO_DIR}"/}"
    else
        fail "Syntax error: ${_script#"${DISTRO_DIR}"/}"
    fi
done

for _cmd in openssl jq sha256sum; do
    if command -v "${_cmd}" >/dev/null 2>&1; then
        pass "Required command present: ${_cmd}"
    else
        fail "Required command missing: ${_cmd}"
    fi
done

if grep -q '/usr/lib/aios/update/aios-update.sh' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q '/etc/aios/update.d/update.toml' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q '/var/lib/aios/update' "${BUILD_SCRIPT}" 2>/dev/null; then
    pass "Build script stages update client and config"
else
    fail "Build script does not stage update client and config"
fi

TMP_ROOT="$(mktemp -d /tmp/aios-repo-update.XXXXXX)"
REPO_DIR="${TMP_ROOT}/repo"
STATE_DIR="${TMP_ROOT}/state"
ROLLBACK_DIR="${TMP_ROOT}/rollback"
KEY_FILE="${TMP_ROOT}/release-key.pem"
PUB_FILE="${TMP_ROOT}/release-pub.pem"
MANIFEST="${TMP_ROOT}/manifest.json"
SBOM="${TMP_ROOT}/sbom.cdx.json"
PROVENANCE="${TMP_ROOT}/provenance.json"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${KEY_FILE}" >/dev/null 2>&1
openssl pkey -in "${KEY_FILE}" -pubout -out "${PUB_FILE}" >/dev/null 2>&1

cat > "${MANIFEST}" <<'EOF'
{"schema":"aios.release_manifest.v1","revision":12,"artifacts":[]}
EOF
cat > "${SBOM}" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}
EOF
cat > "${PROVENANCE}" <<'EOF'
{"schema":"aios.provenance.v1","builder":"rev12-test"}
EOF

ARTIFACT_V1="${TMP_ROOT}/aios-v1.iso"
ARTIFACT_V2="${TMP_ROOT}/aios-v2.iso"
printf 'AIOS release payload v1\n' > "${ARTIFACT_V1}"
printf 'AIOS release payload v2\n' > "${ARTIFACT_V2}"

if "${PUBLISH_SCRIPT}" \
    --repo-dir "${REPO_DIR}" \
    --release-id rev12-v1 \
    --version 0.1.0 \
    --arch x86_64 \
    --artifact "${ARTIFACT_V1}" \
    --manifest "${MANIFEST}" \
    --sbom "${SBOM}" \
    --provenance "${PROVENANCE}" \
    --signing-key "${KEY_FILE}" \
    --signing-key-id test-key >/dev/null; then
    pass "Signed repository publish succeeds"
else
    fail "Signed repository publish failed"
fi

if "${UPDATE_SCRIPT}" verify --repo "${REPO_DIR}" --trusted-key "${PUB_FILE}" >/dev/null; then
    pass "Update verify accepts valid signed release"
else
    fail "Update verify rejected valid signed release"
fi

if "${UPDATE_SCRIPT}" stage \
    --repo "${REPO_DIR}" \
    --trusted-key "${PUB_FILE}" \
    --state-dir "${STATE_DIR}" \
    --rollback-dir "${ROLLBACK_DIR}" >/dev/null; then
    pass "Update stage succeeds"
else
    fail "Update stage failed"
fi

if "${UPDATE_SCRIPT}" activate \
    --state-dir "${STATE_DIR}" \
    --rollback-dir "${ROLLBACK_DIR}" \
    --health-command true >/dev/null; then
    pass "Update activate succeeds when health passes"
else
    fail "Update activate failed despite passing health"
fi

CURRENT_RELEASE="$(jq -r '.release_id' "${STATE_DIR}/current.json")"
if [ "${CURRENT_RELEASE}" = "rev12-v1" ]; then
    pass "Current deployment records rev12-v1"
else
    fail "Current deployment is not rev12-v1"
fi

if "${PUBLISH_SCRIPT}" \
    --repo-dir "${REPO_DIR}" \
    --release-id rev12-v2 \
    --version 0.1.1 \
    --arch x86_64 \
    --artifact "${ARTIFACT_V2}" \
    --manifest "${MANIFEST}" \
    --sbom "${SBOM}" \
    --provenance "${PROVENANCE}" \
    --signing-key "${KEY_FILE}" \
    --signing-key-id test-key >/dev/null; then
    pass "Second signed repository publish succeeds"
else
    fail "Second signed repository publish failed"
fi

if "${UPDATE_SCRIPT}" stage \
    --repo "${REPO_DIR}" \
    --trusted-key "${PUB_FILE}" \
    --state-dir "${STATE_DIR}" \
    --rollback-dir "${ROLLBACK_DIR}" >/dev/null; then
    pass "Second update stage succeeds"
else
    fail "Second update stage failed"
fi

if "${UPDATE_SCRIPT}" activate \
    --state-dir "${STATE_DIR}" \
    --rollback-dir "${ROLLBACK_DIR}" \
    --health-command false >/dev/null 2>&1; then
    fail "Failed health activation unexpectedly succeeded"
else
    pass "Failed health activation triggers rollback failure path"
fi

CURRENT_RELEASE="$(jq -r '.release_id' "${STATE_DIR}/current.json")"
if [ "${CURRENT_RELEASE}" = "rev12-v1" ]; then
    pass "Rollback restored previous deployment rev12-v1"
else
    fail "Rollback did not restore previous deployment"
fi

if grep -q '"action":"rollback"' "${ROLLBACK_DIR}/evidence.jsonl" 2>/dev/null; then
    pass "Rollback emits evidence"
else
    fail "Rollback evidence missing"
fi

BAD_SIG_REPO="${TMP_ROOT}/bad-signature-repo"
cp -a "${REPO_DIR}" "${BAD_SIG_REPO}"
printf '\ncorrupt metadata\n' >> "${BAD_SIG_REPO}/releases/rev12-v2/metadata.json"
if "${UPDATE_SCRIPT}" verify --repo "${BAD_SIG_REPO}" --trusted-key "${PUB_FILE}" >/dev/null 2>&1; then
    fail "Corrupt signed metadata was accepted"
else
    pass "Corrupt signed metadata is rejected"
fi

BAD_HASH_REPO="${TMP_ROOT}/bad-hash-repo"
cp -a "${REPO_DIR}" "${BAD_HASH_REPO}"
printf '\ncorrupt artifact\n' >> "${BAD_HASH_REPO}/releases/rev12-v2/artifacts/aios-v2.iso"
if "${UPDATE_SCRIPT}" verify --repo "${BAD_HASH_REPO}" --trusted-key "${PUB_FILE}" >/dev/null 2>&1; then
    fail "Hash-mismatched artifact was accepted"
else
    pass "Hash-mismatched artifact is rejected"
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
