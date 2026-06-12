#!/bin/bash
set -euo pipefail

# Verify, stage, activate, and roll back AI-OS.NET signed release updates.

COMMAND="${1:-}"
if [ $# -gt 0 ]; then
    shift
fi

REPO="${AIOS_UPDATE_REPO:-}"
CHANNEL="${AIOS_UPDATE_CHANNEL:-release}"
TRUSTED_KEY="${AIOS_TRUSTED_KEY:-/etc/aios/update.d/trusted-release-key.pem}"
STATE_DIR="${AIOS_UPDATE_STATE_DIR:-/var/lib/aios/update}"
ROLLBACK_DIR="${AIOS_ROLLBACK_DIR:-/var/lib/aios/rollback}"
REQUIRE_SIGNATURE="${AIOS_UPDATE_REQUIRE_SIGNATURE:-1}"
HEALTH_COMMAND="${AIOS_UPDATE_HEALTH_COMMAND:-true}"

VERIFIED_RELEASE_DIR=""
VERIFIED_METADATA_JSON=""
VERIFIED_RELEASE_ID=""
VERIFIED_VERSION=""
VERIFIED_ARCH=""

usage() {
    cat <<'EOF'
Usage: aios-update.sh <command> [OPTIONS]

Commands:
  verify      Verify signed channel metadata, release metadata, signatures, hashes
  stage       Verify and copy the release into the local staged update area
  activate    Activate the staged release; rollback automatically on health failure
  rollback    Restore the previous known-good deployment metadata
  status      Print current/staged/previous deployment state

Options:
  --repo DIR|file://DIR       Local repository root for verify/stage
  --channel NAME             Channel name (default: release)
  --trusted-key FILE         OpenSSL public key for detached signature checks
  --state-dir DIR            Update state directory (default: /var/lib/aios/update)
  --rollback-dir DIR         Rollback directory (default: /var/lib/aios/rollback)
  --health-command COMMAND   Command run after activation (default: true)
  --no-signature             Lab-only mode; do not use for promoted releases
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '  -> %s\n' "$*"
}

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g'
}

now_utc() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

require_file() {
    local label="$1"
    local path="$2"

    [ -f "${path}" ] || die "${label} not found: ${path}"
}

repo_root() {
    local root="${REPO}"

    [ -n "${root}" ] || die "--repo is required for ${COMMAND}"
    case "${root}" in
        file://*) root="${root#file://}" ;;
        http://*|https://*) die "network repository fetch is not implemented in Rev.12 client; mount or mirror the repo locally" ;;
    esac
    [ -d "${root}" ] || die "repository directory not found: ${root}"
    printf '%s\n' "${root}"
}

verify_signature() {
    local input="$1"
    local signature="$2"

    if [ "${REQUIRE_SIGNATURE}" != "1" ]; then
        info "Signature bypass enabled for lab mode: ${input}"
        return 0
    fi

    require_file "trusted key" "${TRUSTED_KEY}"
    require_file "signature" "${signature}"
    openssl dgst -sha256 -verify "${TRUSTED_KEY}" -signature "${signature}" "${input}" >/dev/null \
        || die "signature verification failed: ${input}"
}

metadata_sig_path() {
    local release_dir="$1"
    local file_name="$2"
    printf '%s/signatures/%s.sig\n' "${release_dir}" "${file_name}"
}

verify_release() {
    local root
    local channel_dir
    local current_json
    local current_sig
    local metadata_path
    local metadata_sha_expected
    local metadata_sha_actual
    local sha_file

    require_cmd jq
    require_cmd openssl
    require_cmd sha256sum

    root="$(repo_root)"
    channel_dir="${root}/channels/${CHANNEL}"
    current_json="${channel_dir}/current.json"
    current_sig="${current_json}.sig"
    require_file "channel current metadata" "${current_json}"
    verify_signature "${current_json}" "${current_sig}"

    jq -e --arg channel "${CHANNEL}" \
        '.schema == "aios.repository.current.v1" and .channel == $channel' \
        "${current_json}" >/dev/null || die "invalid current metadata schema or channel"

    metadata_path="$(jq -r '.metadata_path' "${current_json}")"
    metadata_sha_expected="$(jq -r '.metadata_sha256' "${current_json}")"
    if [ -z "${metadata_path}" ] || [ "${metadata_path}" = "null" ]; then
        die "current metadata has no metadata_path"
    fi
    if [ -z "${metadata_sha_expected}" ] || [ "${metadata_sha_expected}" = "null" ]; then
        die "current metadata has no metadata_sha256"
    fi

    VERIFIED_METADATA_JSON="${root}/${metadata_path}"
    VERIFIED_RELEASE_DIR="$(dirname "${VERIFIED_METADATA_JSON}")"

    require_file "release metadata" "${VERIFIED_METADATA_JSON}"
    verify_signature "${VERIFIED_METADATA_JSON}" "$(metadata_sig_path "${VERIFIED_RELEASE_DIR}" metadata.json)"

    metadata_sha_actual="$(file_sha256 "${VERIFIED_METADATA_JSON}")"
    [ "${metadata_sha_actual}" = "${metadata_sha_expected}" ] \
        || die "release metadata hash mismatch"

    jq -e --arg channel "${CHANNEL}" \
        '.schema == "aios.release_repository_metadata.v1" and .channel == $channel and (.artifacts | length > 0)' \
        "${VERIFIED_METADATA_JSON}" >/dev/null || die "invalid release metadata schema"

    VERIFIED_RELEASE_ID="$(jq -r '.release_id' "${VERIFIED_METADATA_JSON}")"
    VERIFIED_VERSION="$(jq -r '.version' "${VERIFIED_METADATA_JSON}")"
    VERIFIED_ARCH="$(jq -r '.architecture' "${VERIFIED_METADATA_JSON}")"
    if [ -z "${VERIFIED_RELEASE_ID}" ] || [ "${VERIFIED_RELEASE_ID}" = "null" ]; then
        die "release_id missing"
    fi

    sha_file="${VERIFIED_RELEASE_DIR}/SHA256SUMS"
    require_file "release SHA256SUMS" "${sha_file}"
    verify_signature "${sha_file}" "$(metadata_sig_path "${VERIFIED_RELEASE_DIR}" SHA256SUMS)"
    verify_signature "${VERIFIED_RELEASE_DIR}/manifest.json" "$(metadata_sig_path "${VERIFIED_RELEASE_DIR}" manifest.json)"
    verify_signature "${VERIFIED_RELEASE_DIR}/sbom.cdx.json" "$(metadata_sig_path "${VERIFIED_RELEASE_DIR}" sbom.cdx.json)"
    verify_signature "${VERIFIED_RELEASE_DIR}/provenance.json" "$(metadata_sig_path "${VERIFIED_RELEASE_DIR}" provenance.json)"

    while IFS= read -r artifact_path; do
        [ -n "${artifact_path}" ] || continue
        require_file "artifact" "${VERIFIED_RELEASE_DIR}/${artifact_path}"
        verify_signature \
            "${VERIFIED_RELEASE_DIR}/${artifact_path}" \
            "$(metadata_sig_path "${VERIFIED_RELEASE_DIR}" "$(basename "${artifact_path}")")"
    done < <(jq -r '.artifacts[].path' "${VERIFIED_METADATA_JSON}")

    (
        cd "${VERIFIED_RELEASE_DIR}"
        sha256sum -c SHA256SUMS >/dev/null
    ) || die "release payload hash verification failed"

    info "Verified release ${VERIFIED_RELEASE_ID} (${CHANNEL}/${VERIFIED_ARCH})"
}

emit_evidence() {
    local action="$1"
    local release_id="$2"
    local result="$3"
    local detail="$4"

    mkdir -p "${ROLLBACK_DIR}"
    cat >> "${ROLLBACK_DIR}/evidence.jsonl" <<EOF
{"schema":"aios.update_evidence.v1","time":"$(now_utc)","action":"$(json_escape "${action}")","release_id":"$(json_escape "${release_id}")","result":"$(json_escape "${result}")","detail":"$(json_escape "${detail}")"}
EOF
}

stage_release() {
    local stage_release_dir
    local staged_json

    verify_release
    mkdir -p "${STATE_DIR}/staged" "${ROLLBACK_DIR}"
    stage_release_dir="${STATE_DIR}/staged/${VERIFIED_RELEASE_ID}"

    case "${stage_release_dir}" in
        "${STATE_DIR}"/staged/*)
            if [ -d "${stage_release_dir}" ]; then
                rm -rf "${stage_release_dir}"
            fi
            ;;
        *) die "refusing unsafe staged path: ${stage_release_dir}" ;;
    esac

    mkdir -p "${stage_release_dir}"
    cp -a "${VERIFIED_RELEASE_DIR}/." "${stage_release_dir}/"
    staged_json="${STATE_DIR}/staged.json"
    cat > "${staged_json}" <<EOF
{
  "schema": "aios.update_staged.v1",
  "release_id": "$(json_escape "${VERIFIED_RELEASE_ID}")",
  "version": "$(json_escape "${VERIFIED_VERSION}")",
  "architecture": "$(json_escape "${VERIFIED_ARCH}")",
  "channel": "$(json_escape "${CHANNEL}")",
  "staged_release_dir": "$(json_escape "${stage_release_dir}")",
  "staged_at": "$(now_utc)"
}
EOF
    chmod 600 "${staged_json}"
    emit_evidence "stage" "${VERIFIED_RELEASE_ID}" "OK" "release staged"
    info "Staged release ${VERIFIED_RELEASE_ID}"
}

write_current_state() {
    local source_json="$1"
    local status="$2"
    local current_json="${STATE_DIR}/current.json"
    local release_id
    local version
    local arch
    local channel
    local staged_dir

    release_id="$(jq -r '.release_id' "${source_json}")"
    version="$(jq -r '.version' "${source_json}")"
    arch="$(jq -r '.architecture' "${source_json}")"
    channel="$(jq -r '.channel' "${source_json}")"
    staged_dir="$(jq -r '.staged_release_dir // ""' "${source_json}")"

    cat > "${current_json}" <<EOF
{
  "schema": "aios.deployment_current.v1",
  "release_id": "$(json_escape "${release_id}")",
  "version": "$(json_escape "${version}")",
  "architecture": "$(json_escape "${arch}")",
  "channel": "$(json_escape "${channel}")",
  "release_dir": "$(json_escape "${staged_dir}")",
  "status": "$(json_escape "${status}")",
  "updated_at": "$(now_utc)"
}
EOF
    chmod 600 "${current_json}"
}

activate_staged() {
    local staged_json="${STATE_DIR}/staged.json"
    local current_json="${STATE_DIR}/current.json"
    local release_id

    require_cmd jq
    require_file "staged update" "${staged_json}"
    release_id="$(jq -r '.release_id' "${staged_json}")"
    if [ -z "${release_id}" ] || [ "${release_id}" = "null" ]; then
        die "staged release_id missing"
    fi

    mkdir -p "${ROLLBACK_DIR}"
    if [ -f "${current_json}" ]; then
        cp "${current_json}" "${ROLLBACK_DIR}/previous.json"
        chmod 600 "${ROLLBACK_DIR}/previous.json"
    fi

    write_current_state "${staged_json}" "activating"

    if bash -c "${HEALTH_COMMAND}"; then
        write_current_state "${staged_json}" "active"
        cp "${STATE_DIR}/current.json" "${ROLLBACK_DIR}/current.json"
        chmod 600 "${ROLLBACK_DIR}/current.json"
        emit_evidence "activate" "${release_id}" "OK" "health check passed"
        info "Activated release ${release_id}"
        return 0
    fi

    if [ -f "${ROLLBACK_DIR}/previous.json" ]; then
        cp "${ROLLBACK_DIR}/previous.json" "${current_json}"
        chmod 600 "${current_json}"
        emit_evidence "rollback" "${release_id}" "OK" "health check failed; previous deployment restored"
        die "health check failed; rolled back to previous deployment"
    fi

    emit_evidence "activate" "${release_id}" "FAILED" "health check failed and no previous deployment exists"
    die "health check failed and no previous deployment exists"
}

rollback_previous() {
    local previous_json="${ROLLBACK_DIR}/previous.json"
    local release_id

    require_cmd jq
    require_file "previous deployment" "${previous_json}"
    mkdir -p "${STATE_DIR}"
    cp "${previous_json}" "${STATE_DIR}/current.json"
    chmod 600 "${STATE_DIR}/current.json"
    release_id="$(jq -r '.release_id' "${previous_json}")"
    emit_evidence "rollback" "${release_id}" "OK" "manual rollback"
    info "Rolled back to ${release_id}"
}

show_status() {
    printf 'state_dir=%s\n' "${STATE_DIR}"
    printf 'rollback_dir=%s\n' "${ROLLBACK_DIR}"
    if [ -f "${STATE_DIR}/current.json" ]; then
        printf 'current='
        jq -c '.' "${STATE_DIR}/current.json"
    else
        printf 'current=null\n'
    fi
    if [ -f "${STATE_DIR}/staged.json" ]; then
        printf 'staged='
        jq -c '.' "${STATE_DIR}/staged.json"
    else
        printf 'staged=null\n'
    fi
    if [ -f "${ROLLBACK_DIR}/previous.json" ]; then
        printf 'previous='
        jq -c '.' "${ROLLBACK_DIR}/previous.json"
    else
        printf 'previous=null\n'
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)           REPO="$2"; shift 2 ;;
        --channel)        CHANNEL="$2"; shift 2 ;;
        --trusted-key)    TRUSTED_KEY="$2"; shift 2 ;;
        --state-dir)      STATE_DIR="$2"; shift 2 ;;
        --rollback-dir)   ROLLBACK_DIR="$2"; shift 2 ;;
        --health-command) HEALTH_COMMAND="$2"; shift 2 ;;
        --no-signature)   REQUIRE_SIGNATURE=0; shift ;;
        --help|-h)        usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "${COMMAND}" in
    verify)   verify_release ;;
    stage)    stage_release ;;
    activate) activate_staged ;;
    rollback) rollback_previous ;;
    status)   show_status ;;
    ""|--help|-h) usage ;;
    *) die "unknown command: ${COMMAND}" ;;
esac
