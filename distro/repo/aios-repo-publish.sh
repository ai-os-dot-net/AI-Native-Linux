#!/bin/bash
set -euo pipefail

# Publish an AI-OS.NET release into a signed local artifact repository.

REPO_DIR="${AIOS_REPO_DIR:-}"
CHANNEL="${AIOS_REPO_CHANNEL:-release}"
RELEASE_ID="${AIOS_RELEASE_ID:-}"
VERSION="${AIOS_VERSION:-0.1.0}"
ARCH="${AIOS_ARCH:-x86_64}"
SIGNING_KEY="${AIOS_SIGNING_KEY:-}"
SIGNING_KEY_ID="${AIOS_SIGNING_KEY_ID:-operator}"
ALLOW_UNSIGNED="${AIOS_ALLOW_UNSIGNED_REPO:-0}"
MANIFEST=""
SBOM=""
PROVENANCE=""
ARTIFACTS=()
TMP_DIR=""

usage() {
    cat <<'EOF'
Usage: aios-repo-publish.sh --repo-dir DIR --release-id ID --artifact FILE \
    --manifest FILE --sbom FILE --provenance FILE --signing-key KEY [OPTIONS]

Options:
  --channel NAME          Repository channel (default: release)
  --version VERSION      Release version (default: 0.1.0)
  --arch ARCH            Target architecture (default: x86_64)
  --artifact FILE        Release payload; may be passed more than once
  --signing-key KEY      Private key used for detached OpenSSL signatures
  --signing-key-id ID    Human-readable signing identity
  --allow-unsigned       Lab-only mode; do not use for promoted releases
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '  -> %s\n' "$*"
}

cleanup() {
    if [ -n "${TMP_DIR}" ] && [ -d "${TMP_DIR}" ]; then
        case "${TMP_DIR}" in
            /tmp/aios-repo-publish.*|*/.tmp.*) rm -rf "${TMP_DIR}" ;;
        esac
    fi
}
trap cleanup EXIT

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g'
}

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

file_size_bytes() {
    stat -c '%s' "$1"
}

require_file() {
    local label="$1"
    local path="$2"

    [ -n "${path}" ] || die "${label} is required"
    [ -f "${path}" ] || die "${label} not found: ${path}"
}

copy_required_file() {
    local src="$1"
    local dst="$2"

    cp "${src}" "${dst}"
    chmod 644 "${dst}"
}

sign_file() {
    local input="$1"
    local sig_dir="$2"
    local sig_name

    if [ "${ALLOW_UNSIGNED}" = "1" ]; then
        return 0
    fi

    [ -n "${SIGNING_KEY}" ] || die "signing key is required unless --allow-unsigned is set"
    [ -f "${SIGNING_KEY}" ] || die "signing key not found: ${SIGNING_KEY}"
    command -v openssl >/dev/null 2>&1 || die "openssl is required for signing"

    sig_name="$(basename "${input}").sig"
    openssl dgst -sha256 -sign "${SIGNING_KEY}" -out "${sig_dir}/${sig_name}" "${input}"
    chmod 644 "${sig_dir}/${sig_name}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --repo-dir)       REPO_DIR="$2"; shift 2 ;;
        --channel)        CHANNEL="$2"; shift 2 ;;
        --release-id)     RELEASE_ID="$2"; shift 2 ;;
        --version)        VERSION="$2"; shift 2 ;;
        --arch)           ARCH="$2"; shift 2 ;;
        --manifest)       MANIFEST="$2"; shift 2 ;;
        --sbom)           SBOM="$2"; shift 2 ;;
        --provenance)     PROVENANCE="$2"; shift 2 ;;
        --artifact)       ARTIFACTS+=("$2"); shift 2 ;;
        --signing-key)    SIGNING_KEY="$2"; shift 2 ;;
        --signing-key-id) SIGNING_KEY_ID="$2"; shift 2 ;;
        --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
        --help|-h)        usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "${REPO_DIR}" ] || die "--repo-dir is required"
[ -n "${RELEASE_ID}" ] || die "--release-id is required"
[ ${#ARTIFACTS[@]} -gt 0 ] || die "at least one --artifact is required"
require_file "manifest" "${MANIFEST}"
require_file "SBOM" "${SBOM}"
require_file "provenance" "${PROVENANCE}"

if [ "${ALLOW_UNSIGNED}" != "1" ]; then
    require_file "signing key" "${SIGNING_KEY}"
fi

command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
command -v stat >/dev/null 2>&1 || die "stat is required"

RELEASE_DIR="${REPO_DIR}/releases/${RELEASE_ID}"
CHANNEL_DIR="${REPO_DIR}/channels/${CHANNEL}"
[ ! -e "${RELEASE_DIR}" ] || die "release already exists: ${RELEASE_DIR}"

mkdir -p "${REPO_DIR}/releases" "${CHANNEL_DIR}"
TMP_DIR="$(mktemp -d "${REPO_DIR}/.tmp.${RELEASE_ID}.XXXXXX")"
mkdir -p "${TMP_DIR}/artifacts" "${TMP_DIR}/signatures"

copy_required_file "${MANIFEST}" "${TMP_DIR}/manifest.json"
copy_required_file "${SBOM}" "${TMP_DIR}/sbom.cdx.json"
copy_required_file "${PROVENANCE}" "${TMP_DIR}/provenance.json"

declare -A ARTIFACT_BASENAMES=()
for artifact in "${ARTIFACTS[@]}"; do
    require_file "artifact" "${artifact}"
    base_name="$(basename "${artifact}")"
    [ -z "${ARTIFACT_BASENAMES[${base_name}]+x}" ] || die "duplicate artifact basename: ${base_name}"
    ARTIFACT_BASENAMES["${base_name}"]=1
    cp "${artifact}" "${TMP_DIR}/artifacts/${base_name}"
    chmod 644 "${TMP_DIR}/artifacts/${base_name}"
done

CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
METADATA_JSON="${TMP_DIR}/metadata.json"

{
    printf '{\n'
    printf '  "schema": "aios.release_repository_metadata.v1",\n'
    printf '  "release_id": "%s",\n' "$(json_escape "${RELEASE_ID}")"
    printf '  "channel": "%s",\n' "$(json_escape "${CHANNEL}")"
    printf '  "version": "%s",\n' "$(json_escape "${VERSION}")"
    printf '  "architecture": "%s",\n' "$(json_escape "${ARCH}")"
    printf '  "created_at": "%s",\n' "${CREATED_AT}"
    printf '  "signing_key_id": "%s",\n' "$(json_escape "${SIGNING_KEY_ID}")"
    printf '  "artifacts": [\n'

    artifact_count=${#ARTIFACTS[@]}
    artifact_index=0
    for artifact in "${ARTIFACTS[@]}"; do
        artifact_index=$((artifact_index + 1))
        base_name="$(basename "${artifact}")"
        rel_path="artifacts/${base_name}"
        comma=","
        [ "${artifact_index}" -eq "${artifact_count}" ] && comma=""
        printf '    {"path": "%s", "sha256": "%s", "size_bytes": %s, "dependencies": []}%s\n' \
            "$(json_escape "${rel_path}")" \
            "$(file_sha256 "${TMP_DIR}/${rel_path}")" \
            "$(file_size_bytes "${TMP_DIR}/${rel_path}")" \
            "${comma}"
    done

    printf '  ],\n'
    printf '  "metadata": {\n'
    printf '    "manifest": {"path": "manifest.json", "sha256": "%s"},\n' "$(file_sha256 "${TMP_DIR}/manifest.json")"
    printf '    "sbom": {"path": "sbom.cdx.json", "sha256": "%s"},\n' "$(file_sha256 "${TMP_DIR}/sbom.cdx.json")"
    printf '    "provenance": {"path": "provenance.json", "sha256": "%s"}\n' "$(file_sha256 "${TMP_DIR}/provenance.json")"
    printf '  }\n'
    printf '}\n'
} > "${METADATA_JSON}"
chmod 644 "${METADATA_JSON}"

(
    cd "${TMP_DIR}"
    {
        sha256sum metadata.json manifest.json sbom.cdx.json provenance.json
        for artifact in artifacts/*; do
            [ -f "${artifact}" ] || continue
            sha256sum "${artifact}"
        done
    } > SHA256SUMS
)
chmod 644 "${TMP_DIR}/SHA256SUMS"

sign_file "${TMP_DIR}/metadata.json" "${TMP_DIR}/signatures"
sign_file "${TMP_DIR}/SHA256SUMS" "${TMP_DIR}/signatures"
sign_file "${TMP_DIR}/manifest.json" "${TMP_DIR}/signatures"
sign_file "${TMP_DIR}/sbom.cdx.json" "${TMP_DIR}/signatures"
sign_file "${TMP_DIR}/provenance.json" "${TMP_DIR}/signatures"
for artifact_file in "${TMP_DIR}/artifacts/"*; do
    [ -f "${artifact_file}" ] || continue
    sign_file "${artifact_file}" "${TMP_DIR}/signatures"
done

if [ "${ALLOW_UNSIGNED}" = "1" ]; then
    cat > "${TMP_DIR}/signatures/UNSIGNED" <<'EOF'
This release was published with --allow-unsigned.
It must not be promoted to a Rev.12 release channel.
EOF
fi

mv "${TMP_DIR}" "${RELEASE_DIR}"
TMP_DIR=""

CURRENT_JSON="${CHANNEL_DIR}/current.json"
cat > "${CURRENT_JSON}" <<EOF
{
  "schema": "aios.repository.current.v1",
  "channel": "$(json_escape "${CHANNEL}")",
  "release_id": "$(json_escape "${RELEASE_ID}")",
  "version": "$(json_escape "${VERSION}")",
  "architecture": "$(json_escape "${ARCH}")",
  "metadata_path": "releases/$(json_escape "${RELEASE_ID}")/metadata.json",
  "metadata_sha256": "$(file_sha256 "${RELEASE_DIR}/metadata.json")",
  "generated_at": "${CREATED_AT}"
}
EOF
chmod 644 "${CURRENT_JSON}"

if [ "${ALLOW_UNSIGNED}" != "1" ]; then
    openssl dgst -sha256 -sign "${SIGNING_KEY}" -out "${CURRENT_JSON}.sig" "${CURRENT_JSON}"
    chmod 644 "${CURRENT_JSON}.sig"
fi

info "Published ${RELEASE_ID} to ${CHANNEL}"
info "Repository: ${REPO_DIR}"
