#!/bin/bash
#
# AI-OS.NET Rev.12 (R12.4) signed release update/rollback gate — REAL artifacts.
#
# Validates the R12.4 contract from distro/build/REV12-DISTRIBUTION-SPEC.md
# section 7 ("Signed repository, updates, rollback, SBOM, provenance") against
# the artifacts the REAL build produces, not synthetic /tmp fixtures.
#
# The existing test-rev12-repo-update.sh proves aios-repo-publish.sh +
# aios-update.sh work on hand-written /tmp payloads. It never touches the ISO
# build output. This gate closes that evidence gap: it drives the real build
# far enough to emit the genuine manifest.json / sbom.cdx.json / provenance.json
# and the real squashfs + ISO payload, then runs the full signed
# publish -> verify -> stage -> activate -> rollback flow over THOSE files.
#
# Two layers:
#
#   1. STATIC checks — scripts exist, are executable, parse; required tooling
#      present. Fast, no build dependencies. Weak on its own (source-text and
#      existence greps prove nothing about a real signed update flow) — kept as
#      an early smoke signal only.
#
#   2. REAL checks (run by default) — build a real release tree with the cheap
#      scaffold invocation, publish the real ISO/squashfs + real metadata JSONs
#      as a signed release, verify the metadata signature with the public key,
#      stage+activate (health true), assert payload hash equals the real
#      artifact sha256, publish a v2, activate with health false to force a
#      rollback to v1 (asserting evidence), and finally corrupt the real signed
#      payload to prove staging fails closed.
#
# The REAL layer reuses the same cheapest-that-still-emits-metadata build
# invocation as test-rev12-release-metadata.sh:
#   --debug --allow-scaffold-rootfs --kernel-modules-source none \
#   --kernel-firmware-source none
#
# It SKIPs (not FAILs) the whole real layer when a hard build prerequisite
# (mksquashfs, xorriso, grub2-mkrescue, cargo, python3) is missing, or when
# AIOS_RELEASE_UPDATE_GATE=0 is set to skip the expensive build.
#
# Run: bash distro/build/tests/test-rev12-release-update-gate.sh
#
# Env / arg overrides:
#   AIOS_RELEASE_UPDATE_GATE=0   Skip the expensive real build+update section.
#   AIOS_BUILD_WORKDIR DIR       Reuse an existing build workdir instead of a
#                                fresh mktemp scratch dir.
#   --release-dir DIR            Skip the build; treat DIR as an already-built
#   AIOS_RELEASE_DIR DIR         ISO staging tree (must contain aios/ + live/).
#                                An optional built ISO at DIR/../*.iso or
#                                AIOS_RELEASE_ISO is used as the payload if set.
#   AIOS_RELEASE_ISO FILE        Explicit path to a built ISO to use as payload.
#   AIOS_TEST_KEEP_WORKDIR=1     Keep the scratch workdir for inspection.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"
PUBLISH_SCRIPT="${DISTRO_DIR}/repo/aios-repo-publish.sh"
UPDATE_SCRIPT="${DISTRO_DIR}/update/aios-update.sh"

RELEASE_DIR_ARG="${AIOS_RELEASE_DIR:-}"
FAILED=0
PASSED=0
SKIPPED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }
skip() { SKIPPED=$(( SKIPPED + 1 )); printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --release-dir) RELEASE_DIR_ARG="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,60p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

msg "=== AI-OS.NET Rev.12 (R12.4) Signed Release Update Gate ==="

# ─────────────────────────────────────────────────────────────────────────
# Layer 1: STATIC smoke checks (no build dependencies)
# ─────────────────────────────────────────────────────────────────────────

msg "--- Layer 1: static smoke checks ---"

for _script in "${PUBLISH_SCRIPT}" "${UPDATE_SCRIPT}" "${BUILD_SCRIPT}"; do
    _rel="${_script#"${DISTRO_DIR}"/}"
    if [ -f "${_script}" ]; then
        pass "Script exists: ${_rel}"
    else
        fail "Script missing: ${_rel}"
        continue
    fi
    if [ -x "${_script}" ]; then
        pass "Script is executable: ${_rel}"
    else
        fail "Script is not executable: ${_rel}"
    fi
    if bash -n "${_script}" 2>/dev/null; then
        pass "Syntax OK: ${_rel}"
    else
        fail "Syntax error: ${_rel}"
    fi
done

# ─────────────────────────────────────────────────────────────────────────
# Layer 2: REAL build + signed update/rollback flow
# ─────────────────────────────────────────────────────────────────────────

msg "--- Layer 2: real signed publish -> stage -> activate -> rollback ---"

if [ "${AIOS_RELEASE_UPDATE_GATE:-1}" = "0" ]; then
    skip "Real layer disabled via AIOS_RELEASE_UPDATE_GATE=0"
    printf '\n'
    msg "=== Test Summary ==="
    printf '  Passed:  %d\n' "${PASSED}"
    printf '  Failed:  %d\n' "${FAILED}"
    printf '  Skipped: %d\n' "${SKIPPED}"
    [ "${FAILED}" -eq 0 ] && { printf '  \033[1;32mALL TESTS PASSED\033[0m\n'; exit 0; }
    printf '  \033[1;31mSOME TESTS FAILED\033[0m\n'; exit 1
fi

REAL_PREREQS_OK=true
for _cmd in openssl jq sha256sum; do
    if ! command -v "${_cmd}" >/dev/null 2>&1; then
        skip "Real update flow (required command missing: ${_cmd})"
        REAL_PREREQS_OK=false
    fi
done

# Build prerequisites are only needed when we actually build (no --release-dir).
NEED_BUILD=true
[ -n "${RELEASE_DIR_ARG}" ] && NEED_BUILD=false

if [ "${NEED_BUILD}" = true ]; then
    for _cmd in mksquashfs xorriso grub2-mkrescue cargo python3; do
        if ! command -v "${_cmd}" >/dev/null 2>&1; then
            skip "Real build (build prerequisite missing: ${_cmd} — required by build-aios-iso.sh)"
            REAL_PREREQS_OK=false
        fi
    done
fi

if [ "${REAL_PREREQS_OK}" != true ]; then
    skip "Real layer skipped entirely — missing prerequisite(s) above"
    printf '\n'
    msg "=== Test Summary ==="
    printf '  Passed:  %d\n' "${PASSED}"
    printf '  Failed:  %d\n' "${FAILED}"
    printf '  Skipped: %d\n' "${SKIPPED}"
    [ "${FAILED}" -eq 0 ] && { printf '  \033[1;32mALL TESTS PASSED\033[0m\n'; exit 0; }
    printf '  \033[1;31mSOME TESTS FAILED\033[0m\n'; exit 1
fi

# ---- Scratch workdir --------------------------------------------------------

CREATED_WORKDIR=false
if [ -n "${AIOS_BUILD_WORKDIR:-}" ]; then
    WORKDIR="${AIOS_BUILD_WORKDIR}"
    mkdir -p "${WORKDIR}"
else
    WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/aios-rev12-update-gate.XXXXXX")"
    CREATED_WORKDIR=true
fi

# shellcheck disable=SC2317,SC2329
cleanup() {
    if [ "${CREATED_WORKDIR}" = true ] && [ "${AIOS_TEST_KEEP_WORKDIR:-0}" != "1" ]; then
        rm -rf "${WORKDIR}"
    fi
}
trap cleanup EXIT INT TERM

# ---- Obtain a real release tree (build or reuse) ----------------------------

BUILT_ISO=""
if [ "${NEED_BUILD}" = true ]; then
    ISO_STAGING_DIR="${WORKDIR}/iso"
    BUILT_ISO="${WORKDIR}/aios-release-update-gate.iso"
    BUILD_LOG="${WORKDIR}/build.log"

    msg "Running scaffold build in ${WORKDIR} (log: ${BUILD_LOG})"
    BUILD_EXIT=0
    AIOS_BUILD_WORKDIR="${WORKDIR}" \
        "${BUILD_SCRIPT}" \
            --debug \
            --allow-scaffold-rootfs \
            --kernel-modules-source none \
            --kernel-firmware-source none \
            --output "${BUILT_ISO}" \
            --jobs "$(nproc 2>/dev/null || echo 2)" \
            > "${BUILD_LOG}" 2>&1 || BUILD_EXIT=$?

    if [ -d "${ISO_STAGING_DIR}/aios" ]; then
        pass "Build reached Step 11: real metadata tree exists (build exit=${BUILD_EXIT})"
    else
        fail "Build did NOT produce real metadata tree ${ISO_STAGING_DIR}/aios (build exit=${BUILD_EXIT})"
        printf '  --- last 40 lines of build log ---\n' >&2
        tail -n 40 "${BUILD_LOG}" >&2 || true
    fi
else
    ISO_STAGING_DIR="${RELEASE_DIR_ARG%/}"
    BUILT_ISO="${AIOS_RELEASE_ISO:-}"
    if [ -d "${ISO_STAGING_DIR}/aios" ]; then
        pass "Reusing supplied release dir: ${ISO_STAGING_DIR}"
    else
        fail "Supplied --release-dir has no aios/ metadata tree: ${ISO_STAGING_DIR}"
    fi
    # Auto-discover a sibling ISO if the caller did not name one.
    if [ -z "${BUILT_ISO}" ]; then
        BUILT_ISO="$(find "$(dirname "${ISO_STAGING_DIR}")" -maxdepth 1 -name '*.iso' 2>/dev/null | head -1 || true)"
    fi
fi

# If we could not even get the metadata tree, stop the real layer here.
if [ ! -d "${ISO_STAGING_DIR}/aios" ]; then
    skip "Real update flow skipped — no release tree available"
    printf '\n'
    msg "=== Test Summary ==="
    printf '  Passed:  %d\n' "${PASSED}"
    printf '  Failed:  %d\n' "${FAILED}"
    printf '  Skipped: %d\n' "${SKIPPED}"
    printf '  \033[1;31mSOME TESTS FAILED\033[0m\n'; exit 1
fi

# ---- Locate the real artifacts ---------------------------------------------

REAL_MANIFEST="${ISO_STAGING_DIR}/aios/manifest.json"
REAL_SBOM="${ISO_STAGING_DIR}/aios/sbom.cdx.json"
REAL_PROVENANCE="${ISO_STAGING_DIR}/aios/provenance.json"
REAL_SQUASHFS="${ISO_STAGING_DIR}/live/aios.squashfs"

for _pair in \
    "manifest.json:${REAL_MANIFEST}" \
    "sbom.cdx.json:${REAL_SBOM}" \
    "provenance.json:${REAL_PROVENANCE}" \
    "live/aios.squashfs:${REAL_SQUASHFS}"; do
    _label="${_pair%%:*}"
    _path="${_pair#*:}"
    if [ -s "${_path}" ]; then
        pass "Real build artifact present and non-empty: ${_label}"
    else
        fail "Real build artifact missing or empty: ${_label} (${_path})"
    fi
done

# Metadata JSONs must be genuine (parse + carry their contract schema).
if jq -e '.schema == "aios.release_manifest.v1"' "${REAL_MANIFEST}" >/dev/null 2>&1; then
    pass "Real manifest.json parses and carries aios.release_manifest.v1"
else
    fail "Real manifest.json missing schema aios.release_manifest.v1"
fi
if jq -e '.bomFormat == "CycloneDX"' "${REAL_SBOM}" >/dev/null 2>&1; then
    pass "Real sbom.cdx.json parses and is CycloneDX"
else
    fail "Real sbom.cdx.json is not CycloneDX"
fi
if jq -e '.schema == "aios.provenance.v1" and (.source.git_revision | length > 0)' \
        "${REAL_PROVENANCE}" >/dev/null 2>&1; then
    pass "Real provenance.json parses and records source git revision"
else
    fail "Real provenance.json missing schema/git revision"
fi

# Choose the release payload: prefer the real ISO, fall back to the squashfs.
if [ -s "${BUILT_ISO}" ]; then
    REAL_PAYLOAD="${BUILT_ISO}"
    pass "Release payload = real ISO ($(basename "${BUILT_ISO}"))"
elif [ -s "${REAL_SQUASHFS}" ]; then
    REAL_PAYLOAD="${REAL_SQUASHFS}"
    pass "Release payload = real squashfs (ISO not built; using live/aios.squashfs)"
else
    fail "No usable real payload (neither ISO nor squashfs present)"
    REAL_PAYLOAD=""
fi

# Without a payload or the metadata JSONs there is nothing to publish; bail out
# of the real layer but still print the summary.
if [ -z "${REAL_PAYLOAD}" ] || [ ! -s "${REAL_MANIFEST}" ] \
   || [ ! -s "${REAL_SBOM}" ] || [ ! -s "${REAL_PROVENANCE}" ]; then
    fail "Cannot run signed update flow — real payload or metadata missing"
    printf '\n'
    msg "=== Test Summary ==="
    printf '  Passed:  %d\n' "${PASSED}"
    printf '  Failed:  %d\n' "${FAILED}"
    printf '  Skipped: %d\n' "${SKIPPED}"
    printf '  \033[1;31mSOME TESTS FAILED\033[0m\n'; exit 1
fi

PAYLOAD_BASENAME="$(basename "${REAL_PAYLOAD}")"
REAL_PAYLOAD_SHA="$(sha256_of "${REAL_PAYLOAD}")"
msg "Real payload: ${PAYLOAD_BASENAME} sha256=${REAL_PAYLOAD_SHA}"

# ---- Signing key + repo/state dirs -----------------------------------------

REPO_DIR="${WORKDIR}/repo"
STATE_DIR="${WORKDIR}/state"
ROLLBACK_DIR="${WORKDIR}/rollback"
KEY_FILE="${WORKDIR}/release-key.pem"
PUB_FILE="${WORKDIR}/release-pub.pem"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${KEY_FILE}" >/dev/null 2>&1
openssl pkey -in "${KEY_FILE}" -pubout -out "${PUB_FILE}" >/dev/null 2>&1

# ---- 1) Publish v1 with the REAL payload + REAL metadata JSONs --------------

REL_V1="rev12-real-v1"
if "${PUBLISH_SCRIPT}" \
    --repo-dir "${REPO_DIR}" \
    --release-id "${REL_V1}" \
    --version 0.1.0 \
    --arch x86_64 \
    --artifact "${REAL_PAYLOAD}" \
    --manifest "${REAL_MANIFEST}" \
    --sbom "${REAL_SBOM}" \
    --provenance "${REAL_PROVENANCE}" \
    --signing-key "${KEY_FILE}" \
    --signing-key-id release-gate >/dev/null; then
    pass "Signed publish of real release ${REL_V1} succeeds"
else
    fail "Signed publish of real release ${REL_V1} failed"
fi

V1_DIR="${REPO_DIR}/releases/${REL_V1}"
CURRENT_JSON="${REPO_DIR}/channels/release/current.json"

# metadata signature verifies with the PUBLIC key (task step 2)
if openssl dgst -sha256 -verify "${PUB_FILE}" \
        -signature "${V1_DIR}/signatures/metadata.json.sig" \
        "${V1_DIR}/metadata.json" >/dev/null 2>&1; then
    pass "Release metadata.json signature verifies with public key"
else
    fail "Release metadata.json signature did NOT verify with public key"
fi
if openssl dgst -sha256 -verify "${PUB_FILE}" \
        -signature "${CURRENT_JSON}.sig" "${CURRENT_JSON}" >/dev/null 2>&1; then
    pass "Channel current.json signature verifies with public key"
else
    fail "Channel current.json signature did NOT verify with public key"
fi

# The published payload hash inside real metadata equals the real artifact sha.
PUBLISHED_PAYLOAD_SHA="$(jq -r --arg p "artifacts/${PAYLOAD_BASENAME}" \
    '.artifacts[] | select(.path == $p) | .sha256' "${V1_DIR}/metadata.json")"
if [ "${PUBLISHED_PAYLOAD_SHA}" = "${REAL_PAYLOAD_SHA}" ]; then
    pass "Published metadata records the real payload sha256"
else
    fail "Published payload sha mismatch (meta=${PUBLISHED_PAYLOAD_SHA} real=${REAL_PAYLOAD_SHA})"
fi

# ---- 2) Verify + stage + activate v1 (health true) -------------------------

if "${UPDATE_SCRIPT}" verify --repo "${REPO_DIR}" --trusted-key "${PUB_FILE}" >/dev/null; then
    pass "Update verify accepts the real signed release"
else
    fail "Update verify rejected the real signed release"
fi

if "${UPDATE_SCRIPT}" stage \
    --repo "${REPO_DIR}" --trusted-key "${PUB_FILE}" \
    --state-dir "${STATE_DIR}" --rollback-dir "${ROLLBACK_DIR}" >/dev/null; then
    pass "Stage of real release ${REL_V1} succeeds"
else
    fail "Stage of real release ${REL_V1} failed"
fi

if "${UPDATE_SCRIPT}" activate \
    --state-dir "${STATE_DIR}" --rollback-dir "${ROLLBACK_DIR}" \
    --health-command true >/dev/null; then
    pass "Activate of real release ${REL_V1} succeeds (health true)"
else
    fail "Activate of real release ${REL_V1} failed despite passing health"
fi

CURRENT_RELEASE="$(jq -r '.release_id' "${STATE_DIR}/current.json")"
if [ "${CURRENT_RELEASE}" = "${REL_V1}" ]; then
    pass "Current deployment points to ${REL_V1}"
else
    fail "Current deployment is '${CURRENT_RELEASE}', expected ${REL_V1}"
fi

# Payload hash on the ACTIVATED (staged) tree equals the real artifact sha256.
STAGED_DIR="$(jq -r '.release_dir' "${STATE_DIR}/current.json")"
STAGED_PAYLOAD="${STAGED_DIR}/artifacts/${PAYLOAD_BASENAME}"
if [ -f "${STAGED_PAYLOAD}" ] && [ "$(sha256_of "${STAGED_PAYLOAD}")" = "${REAL_PAYLOAD_SHA}" ]; then
    pass "Activated deployment payload hash equals the real build artifact sha256"
else
    fail "Activated deployment payload hash does not match the real artifact"
fi

# ---- 3) Publish v2 (real-derived, distinct hash), force rollback -----------

# v2 payload: a real-artifact-derived variant with a genuinely different hash
# (byte-appended copy of the real payload). Single expensive build; the update
# machinery only needs two distinct signed payloads to exercise rollback.
V2_PAYLOAD_DIR="${WORKDIR}/v2-payload"
mkdir -p "${V2_PAYLOAD_DIR}"
V2_PAYLOAD="${V2_PAYLOAD_DIR}/${PAYLOAD_BASENAME}"
cp "${REAL_PAYLOAD}" "${V2_PAYLOAD}"
printf 'aios-rev12-update-gate-v2-variant\n' >> "${V2_PAYLOAD}"
V2_PAYLOAD_SHA="$(sha256_of "${V2_PAYLOAD}")"
if [ "${V2_PAYLOAD_SHA}" != "${REAL_PAYLOAD_SHA}" ]; then
    pass "v2 payload derived from real artifact has a distinct sha256"
else
    fail "v2 payload sha256 unexpectedly equals v1"
fi

REL_V2="rev12-real-v2"
if "${PUBLISH_SCRIPT}" \
    --repo-dir "${REPO_DIR}" \
    --release-id "${REL_V2}" \
    --version 0.1.1 \
    --arch x86_64 \
    --artifact "${V2_PAYLOAD}" \
    --manifest "${REAL_MANIFEST}" \
    --sbom "${REAL_SBOM}" \
    --provenance "${REAL_PROVENANCE}" \
    --signing-key "${KEY_FILE}" \
    --signing-key-id release-gate >/dev/null; then
    pass "Signed publish of real release ${REL_V2} succeeds"
else
    fail "Signed publish of real release ${REL_V2} failed"
fi

if "${UPDATE_SCRIPT}" stage \
    --repo "${REPO_DIR}" --trusted-key "${PUB_FILE}" \
    --state-dir "${STATE_DIR}" --rollback-dir "${ROLLBACK_DIR}" >/dev/null; then
    pass "Stage of real release ${REL_V2} succeeds"
else
    fail "Stage of real release ${REL_V2} failed"
fi

if "${UPDATE_SCRIPT}" activate \
    --state-dir "${STATE_DIR}" --rollback-dir "${ROLLBACK_DIR}" \
    --health-command false >/dev/null 2>&1; then
    fail "Activate with failing health unexpectedly succeeded"
else
    pass "Activate with failing health fails closed and triggers rollback"
fi

CURRENT_RELEASE="$(jq -r '.release_id' "${STATE_DIR}/current.json")"
if [ "${CURRENT_RELEASE}" = "${REL_V1}" ]; then
    pass "Rollback restored the previous real deployment ${REL_V1}"
else
    fail "Rollback did not restore ${REL_V1} (current='${CURRENT_RELEASE}')"
fi

# Rolled-back deployment must still point at the v1 payload (previous deployment
# remained intact / bootable through the failed activation).
STAGED_DIR="$(jq -r '.release_dir' "${STATE_DIR}/current.json")"
STAGED_PAYLOAD="${STAGED_DIR}/artifacts/${PAYLOAD_BASENAME}"
if [ -f "${STAGED_PAYLOAD}" ] && [ "$(sha256_of "${STAGED_PAYLOAD}")" = "${REAL_PAYLOAD_SHA}" ]; then
    pass "Post-rollback deployment payload is the intact v1 real artifact"
else
    fail "Post-rollback deployment payload is not the intact v1 real artifact"
fi

if grep -q '"action":"rollback"' "${ROLLBACK_DIR}/evidence.jsonl" 2>/dev/null; then
    pass "Rollback recorded in append-only evidence.jsonl"
else
    fail "Rollback evidence missing from evidence.jsonl"
fi

# ---- 4) Negative: corrupt the real signed payload -> fail closed -----------

CORRUPT_REPO="${WORKDIR}/corrupt-repo"
cp -a "${REPO_DIR}" "${CORRUPT_REPO}"
# Corrupt the already-signed real payload of v1 (hash no longer matches the
# signed SHA256SUMS / metadata) — staging must reject it.
printf '\naios-corruption\n' >> "${CORRUPT_REPO}/releases/${REL_V1}/artifacts/${PAYLOAD_BASENAME}"
CORRUPT_STATE="${WORKDIR}/corrupt-state"
CORRUPT_ROLLBACK="${WORKDIR}/corrupt-rollback"

# The active channel currently points at v2; repoint it at the corrupted v1
# release (re-signed current.json) so verify/stage targets the tampered payload.
CORRUPT_CURRENT="${CORRUPT_REPO}/channels/release/current.json"
V1_META_SHA="$(sha256_of "${CORRUPT_REPO}/releases/${REL_V1}/metadata.json")"
cat > "${CORRUPT_CURRENT}" <<EOF
{
  "schema": "aios.repository.current.v1",
  "channel": "release",
  "release_id": "${REL_V1}",
  "version": "0.1.0",
  "architecture": "x86_64",
  "metadata_path": "releases/${REL_V1}/metadata.json",
  "metadata_sha256": "${V1_META_SHA}",
  "generated_at": "1970-01-01T00:00:00Z"
}
EOF
openssl dgst -sha256 -sign "${KEY_FILE}" -out "${CORRUPT_CURRENT}.sig" "${CORRUPT_CURRENT}" 2>/dev/null

if "${UPDATE_SCRIPT}" stage \
    --repo "${CORRUPT_REPO}" --trusted-key "${PUB_FILE}" \
    --state-dir "${CORRUPT_STATE}" --rollback-dir "${CORRUPT_ROLLBACK}" >/dev/null 2>&1; then
    fail "Staging a corrupted real signed payload unexpectedly succeeded"
else
    pass "Staging a corrupted real signed payload fails closed"
fi

# ---- Summary ---------------------------------------------------------------

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
