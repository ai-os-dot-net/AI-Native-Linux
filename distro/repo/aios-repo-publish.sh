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
SKIP_LINKAGE_CHECK="${AIOS_SKIP_LINKAGE_CHECK:-0}"
MANIFEST=""
SBOM=""
PROVENANCE=""
ARTIFACTS=()
TMP_DIR=""

# R13.5 enterprise channels + promotion + retention.
COMMAND=""                     # publish (default) | promote | prune
PROMOTE_FROM="${AIOS_PROMOTE_FROM:-}"   # source channel for `promote`
RETAIN="${AIOS_RETAIN:-}"      # keep newest N releases in a channel (empty = keep all)
UPDATE_STATE_FILE="${AIOS_UPDATE_STATE_FILE:-}"   # client current.json (active release)
ROLLBACK_STATE_FILE="${AIOS_ROLLBACK_STATE_FILE:-}"  # client previous.json (rollback target)

# The closed set of valid enterprise channels (REV13-ENTERPRISE-SPEC.md §8).
# `airgap` (offline import/export) is specified but out of scope for R13.5 and is
# intentionally NOT accepted here; publishing to it must be added deliberately.
CHANNEL_SET="release security staging recovery"

usage() {
    cat <<'EOF'
Usage:
  aios-repo-publish.sh [publish] --repo-dir DIR --release-id ID --artifact FILE \
      --manifest FILE --sbom FILE --provenance FILE --signing-key KEY [OPTIONS]
  aios-repo-publish.sh promote --repo-dir DIR --promote-from SRC --channel DST \
      --signing-key KEY [--release-id NEW_ID] [OPTIONS]
  aios-repo-publish.sh prune --repo-dir DIR --channel NAME --retain N [OPTIONS]

Commands:
  publish (default)      Publish a freshly built release into a signed channel.
  promote                Copy an EXISTING published release from --promote-from
                         into --channel WITHOUT rebuilding. Artifact payload bytes
                         are identical; a new signed channel head is written.
  prune                  Apply --retain N retention to a channel, deleting the
                         oldest superseded releases. Never prunes the active or
                         previous (rollback-target) release.

Channels (closed set): release, security, staging, recovery

Options:
  --channel NAME          Repository channel (default: release)
  --version VERSION       Release version (default: 0.1.0)
  --arch ARCH             Target architecture (default: x86_64)
  --artifact FILE         Release payload; may be passed more than once
  --promote-from SRC      Source channel to promote an existing release from
  --release-id NEW_ID     (promote) id for the promoted copy; default SRC_ID-DST
  --retain N              Keep only the newest N releases in the channel; prune
                          older superseded ones (default: keep all). Never below 2.
  --update-state-file F   Client current.json; its release_id is protected
  --rollback-state-file F Client previous.json; its release_id is protected
  --signing-key KEY       Private key used for detached OpenSSL signatures
  --signing-key-id ID     Human-readable signing identity
  --allow-unsigned        Lab-only mode; do not use for promoted releases
  --skip-linkage-check    Do NOT cross-check manifest artifact hashes against the
                          resolvable payload files (lab-only; prints a warning)
EOF
}

validate_channel_name() {
    local channel="$1"
    local valid
    for valid in ${CHANNEL_SET}; do
        [ "${channel}" = "${valid}" ] && return 0
    done
    die "unknown channel: ${channel} (valid: ${CHANNEL_SET// /, })"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

# json_get FILE KEY -> prints the string value of a top-level object KEY ("" if absent).
json_get() {
    require_cmd python3
    python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1])).get(sys.argv[2], "") or "")
except Exception:
    sys.exit(1)' "$1" "$2"
}

# Append a one-line evidence record to REPO_DIR/evidence.jsonl (same JSONL
# convention as the update-side aios.update_evidence.v1 log).
append_repo_evidence() {
    local action="$1"
    local channel="$2"
    local release_id="$3"
    local result="$4"
    local detail="$5"

    mkdir -p "${REPO_DIR}"
    cat >> "${REPO_DIR}/evidence.jsonl" <<EOF
{"schema":"aios.repo_evidence.v1","time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","action":"$(json_escape "${action}")","channel":"$(json_escape "${channel}")","release_id":"$(json_escape "${release_id}")","result":"$(json_escape "${result}")","detail":"$(json_escape "${detail}")"}
EOF
    chmod 644 "${REPO_DIR}/evidence.jsonl" 2>/dev/null || true
}

# Append a channel-history record so retention can order releases per channel.
append_channel_history() {
    local channel="$1"
    local release_id="$2"
    local version="$3"
    local hist="${REPO_DIR}/channels/${channel}/history.jsonl"

    mkdir -p "${REPO_DIR}/channels/${channel}"
    cat >> "${hist}" <<EOF
{"schema":"aios.channel_history.v1","time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","channel":"$(json_escape "${channel}")","release_id":"$(json_escape "${release_id}")","version":"$(json_escape "${version}")"}
EOF
    chmod 644 "${hist}"
}

# Write (and sign) the channel head at channels/<channel>/current.json, keeping
# the superseded head as channels/<channel>/previous.json for rollback awareness.
write_channel_head() {
    local release_dir="$1"
    local release_id="$2"
    local version="$3"
    local arch="$4"
    local channel="$5"
    local channel_dir="${REPO_DIR}/channels/${channel}"
    local current_json="${channel_dir}/current.json"

    mkdir -p "${channel_dir}"
    if [ -f "${current_json}" ]; then
        cp "${current_json}" "${channel_dir}/previous.json"
        chmod 644 "${channel_dir}/previous.json"
    fi

    cat > "${current_json}" <<EOF
{
  "schema": "aios.repository.current.v1",
  "channel": "$(json_escape "${channel}")",
  "release_id": "$(json_escape "${release_id}")",
  "version": "$(json_escape "${version}")",
  "architecture": "$(json_escape "${arch}")",
  "metadata_path": "releases/$(json_escape "${release_id}")/metadata.json",
  "metadata_sha256": "$(file_sha256 "${release_dir}/metadata.json")",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    chmod 644 "${current_json}"

    if [ "${ALLOW_UNSIGNED}" != "1" ]; then
        openssl dgst -sha256 -sign "${SIGNING_KEY}" -out "${current_json}.sig" "${current_json}"
        chmod 644 "${current_json}.sig"
    fi
}

# Generate metadata.json + SHA256SUMS from a populated TMP_DIR (manifest.json,
# sbom.cdx.json, provenance.json and artifacts/* already present), sign every
# file, move it into place as releases/<release_id>, then publish the channel
# head, history and evidence. Shared by publish and promote.
finalize_release() {
    local release_id="$1"
    local version="$2"
    local arch="$3"
    local channel="$4"
    local origin="$5"     # human note for evidence detail
    local release_dir="${REPO_DIR}/releases/${release_id}"
    local created_at
    local metadata_json="${TMP_DIR}/metadata.json"

    [ ! -e "${release_dir}" ] || die "release already exists: ${release_dir}"
    created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    {
        printf '{\n'
        printf '  "schema": "aios.release_repository_metadata.v1",\n'
        printf '  "release_id": "%s",\n' "$(json_escape "${release_id}")"
        printf '  "channel": "%s",\n' "$(json_escape "${channel}")"
        printf '  "version": "%s",\n' "$(json_escape "${version}")"
        printf '  "architecture": "%s",\n' "$(json_escape "${arch}")"
        printf '  "created_at": "%s",\n' "${created_at}"
        printf '  "signing_key_id": "%s",\n' "$(json_escape "${SIGNING_KEY_ID}")"
        printf '  "artifacts": [\n'

        local files=()
        local f
        for f in "${TMP_DIR}/artifacts/"*; do
            [ -f "${f}" ] || continue
            files+=("${f}")
        done
        local total=${#files[@]}
        local idx=0
        for f in "${files[@]}"; do
            idx=$((idx + 1))
            local base_name rel_path comma
            base_name="$(basename "${f}")"
            rel_path="artifacts/${base_name}"
            comma=","
            [ "${idx}" -eq "${total}" ] && comma=""
            printf '    {"path": "%s", "sha256": "%s", "size_bytes": %s, "dependencies": []}%s\n' \
                "$(json_escape "${rel_path}")" \
                "$(file_sha256 "${f}")" \
                "$(file_size_bytes "${f}")" \
                "${comma}"
        done

        printf '  ],\n'
        printf '  "metadata": {\n'
        printf '    "manifest": {"path": "manifest.json", "sha256": "%s"},\n' "$(file_sha256 "${TMP_DIR}/manifest.json")"
        printf '    "sbom": {"path": "sbom.cdx.json", "sha256": "%s"},\n' "$(file_sha256 "${TMP_DIR}/sbom.cdx.json")"
        printf '    "provenance": {"path": "provenance.json", "sha256": "%s"}\n' "$(file_sha256 "${TMP_DIR}/provenance.json")"
        printf '  }\n'
        printf '}\n'
    } > "${metadata_json}"
    chmod 644 "${metadata_json}"

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

    mv "${TMP_DIR}" "${release_dir}"
    TMP_DIR=""

    write_channel_head "${release_dir}" "${release_id}" "${version}" "${arch}" "${channel}"
    append_channel_history "${channel}" "${release_id}" "${version}"
    append_repo_evidence "${COMMAND}" "${channel}" "${release_id}" "OK" "${origin}"
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

# Cross-check payload <-> metadata linkage: the release manifest must be valid
# JSON, and every artifacts[] entry that carries a sha256 must match the actual
# hash of the payload file it names when that file is resolvable. Publish fails
# closed on any mismatch. Non-resolvable entries are skipped (cannot be checked).
verify_manifest_linkage() {
    local manifest="$1"
    shift

    command -v python3 >/dev/null 2>&1 || die "python3 is required for manifest linkage verification (use --skip-linkage-check for lab-only publishes)"

    python3 - "${manifest}" "$@" <<'PYEOF'
import hashlib
import json
import os
import sys

manifest = sys.argv[1]
artifact_files = sys.argv[2:]
mdir = os.path.dirname(os.path.abspath(manifest))

try:
    with open(manifest) as fh:
        data = json.load(fh)
except Exception as exc:  # noqa: BLE001 - any parse failure is fail-closed
    sys.stderr.write("manifest is not internally consistent JSON: %s\n" % exc)
    sys.exit(2)

by_base = {}
for path in artifact_files:
    by_base.setdefault(os.path.basename(path), path)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


artifacts = data.get("artifacts")
checked = 0
if isinstance(artifacts, list):
    for entry in artifacts:
        if not isinstance(entry, dict):
            continue
        expected = entry.get("sha256")
        if not expected:
            continue
        rel = entry.get("path") or entry.get("name") or ""
        candidates = []
        if rel:
            candidates.append(os.path.join(mdir, rel))
            candidates.append(os.path.normpath(os.path.join(mdir, "..", rel)))
            base = os.path.basename(rel)
            if base in by_base:
                candidates.append(by_base[base])
        resolved = next((c for c in candidates if os.path.isfile(c)), None)
        if resolved is None:
            continue
        actual = sha256(resolved)
        if actual.lower() != str(expected).lower():
            sys.stderr.write(
                "manifest linkage mismatch for %s: manifest sha256=%s actual=%s (%s)\n"
                % (rel, expected, actual, resolved)
            )
            sys.exit(3)
        checked += 1

sys.stderr.write("manifest linkage OK: %d artifact hash(es) cross-checked\n" % checked)
PYEOF
}

# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

do_publish() {
    [ -n "${REPO_DIR}" ] || die "--repo-dir is required"
    [ -n "${RELEASE_ID}" ] || die "--release-id is required"
    validate_channel_name "${CHANNEL}"
    [ ${#ARTIFACTS[@]} -gt 0 ] || die "at least one --artifact is required"
    require_file "manifest" "${MANIFEST}"
    require_file "SBOM" "${SBOM}"
    require_file "provenance" "${PROVENANCE}"

    if [ "${SKIP_LINKAGE_CHECK}" = "1" ]; then
        printf 'WARNING: ============================================================\n' >&2
        printf 'WARNING: --skip-linkage-check set: manifest artifact hashes are NOT\n' >&2
        printf 'WARNING: cross-checked against payload files. Payload/metadata drift\n' >&2
        printf 'WARNING: will NOT be caught. Do not use for promoted releases.\n' >&2
        printf 'WARNING: ============================================================\n' >&2
    else
        verify_manifest_linkage "${MANIFEST}" "${ARTIFACTS[@]}"
    fi

    if [ "${ALLOW_UNSIGNED}" != "1" ]; then
        require_file "signing key" "${SIGNING_KEY}"
    fi

    require_cmd sha256sum
    require_cmd stat

    [ ! -e "${REPO_DIR}/releases/${RELEASE_ID}" ] || die "release already exists: ${REPO_DIR}/releases/${RELEASE_ID}"

    mkdir -p "${REPO_DIR}/releases" "${REPO_DIR}/channels/${CHANNEL}"
    TMP_DIR="$(mktemp -d "${REPO_DIR}/.tmp.${RELEASE_ID}.XXXXXX")"
    mkdir -p "${TMP_DIR}/artifacts" "${TMP_DIR}/signatures"

    copy_required_file "${MANIFEST}" "${TMP_DIR}/manifest.json"
    copy_required_file "${SBOM}" "${TMP_DIR}/sbom.cdx.json"
    copy_required_file "${PROVENANCE}" "${TMP_DIR}/provenance.json"

    declare -A ARTIFACT_BASENAMES=()
    local artifact base_name
    for artifact in "${ARTIFACTS[@]}"; do
        require_file "artifact" "${artifact}"
        base_name="$(basename "${artifact}")"
        [ -z "${ARTIFACT_BASENAMES[${base_name}]+x}" ] || die "duplicate artifact basename: ${base_name}"
        ARTIFACT_BASENAMES["${base_name}"]=1
        cp "${artifact}" "${TMP_DIR}/artifacts/${base_name}"
        chmod 644 "${TMP_DIR}/artifacts/${base_name}"
    done

    finalize_release "${RELEASE_ID}" "${VERSION}" "${ARCH}" "${CHANNEL}" "published new release"

    info "Published ${RELEASE_ID} to ${CHANNEL}"
    info "Repository: ${REPO_DIR}"

    if [ -n "${RETAIN}" ]; then
        prune_channel "${CHANNEL}" "${RETAIN}"
    fi
}

do_promote() {
    [ -n "${REPO_DIR}" ] || die "--repo-dir is required"
    [ -n "${PROMOTE_FROM}" ] || die "--promote-from SRC is required for promote"
    validate_channel_name "${PROMOTE_FROM}"
    validate_channel_name "${CHANNEL}"
    [ "${PROMOTE_FROM}" != "${CHANNEL}" ] || die "--promote-from and --channel must differ"

    if [ "${ALLOW_UNSIGNED}" != "1" ]; then
        require_file "signing key" "${SIGNING_KEY}"
    fi
    require_cmd sha256sum
    require_cmd stat

    local src_current="${REPO_DIR}/channels/${PROMOTE_FROM}/current.json"
    require_file "source channel head" "${src_current}"

    local src_release_id src_version src_arch src_dir new_id
    src_release_id="$(json_get "${src_current}" release_id)" || die "cannot read source channel head"
    [ -n "${src_release_id}" ] || die "source channel head has no release_id"
    src_dir="${REPO_DIR}/releases/${src_release_id}"
    require_file "source release metadata" "${src_dir}/metadata.json"

    # Refuse to promote an --allow-unsigned lab release into a real channel.
    [ ! -e "${src_dir}/signatures/UNSIGNED" ] || die "refusing to promote an unsigned lab release: ${src_release_id}"

    src_version="$(json_get "${src_dir}/metadata.json" version)"
    src_arch="$(json_get "${src_dir}/metadata.json" architecture)"
    [ -n "${VERSION_SET}" ] && src_version="${VERSION}"
    [ -n "${ARCH_SET}" ] && src_arch="${ARCH}"

    new_id="${RELEASE_ID}"
    [ -n "${new_id}" ] || new_id="${src_release_id}-${CHANNEL}"
    [ ! -e "${REPO_DIR}/releases/${new_id}" ] || die "promoted release already exists: ${REPO_DIR}/releases/${new_id}"

    mkdir -p "${REPO_DIR}/releases" "${REPO_DIR}/channels/${CHANNEL}"
    TMP_DIR="$(mktemp -d "${REPO_DIR}/.tmp.${new_id}.XXXXXX")"
    mkdir -p "${TMP_DIR}/artifacts" "${TMP_DIR}/signatures"

    # Copy metadata inputs and artifact payloads BYTE-IDENTICAL from the source.
    copy_required_file "${src_dir}/manifest.json" "${TMP_DIR}/manifest.json"
    copy_required_file "${src_dir}/sbom.cdx.json" "${TMP_DIR}/sbom.cdx.json"
    copy_required_file "${src_dir}/provenance.json" "${TMP_DIR}/provenance.json"
    local f
    for f in "${src_dir}/artifacts/"*; do
        [ -f "${f}" ] || continue
        cp "${f}" "${TMP_DIR}/artifacts/$(basename "${f}")"
        chmod 644 "${TMP_DIR}/artifacts/$(basename "${f}")"
    done

    finalize_release "${new_id}" "${src_version}" "${src_arch}" "${CHANNEL}" \
        "promoted from ${PROMOTE_FROM} release ${src_release_id}"

    info "Promoted ${src_release_id} (${PROMOTE_FROM}) -> ${new_id} (${CHANNEL})"
    info "Repository: ${REPO_DIR}"

    if [ -n "${RETAIN}" ]; then
        prune_channel "${CHANNEL}" "${RETAIN}"
    fi
}

# prune_channel CHANNEL RETAIN_N
# Keep the newest N releases recorded in the channel history; delete older
# superseded release directories. NEVER prunes: the active release (this
# channel's head), any other channel's head, the repo-side previous head, or
# any release named by --update-state-file / --rollback-state-file. When update
# state is unknown it still refuses to prune below 2 kept releases.
prune_channel() {
    local channel="$1"
    local retain="$2"
    validate_channel_name "${channel}"

    case "${retain}" in
        ''|*[!0-9]*) die "--retain must be a non-negative integer, got: ${retain}" ;;
    esac
    if [ "${retain}" -lt 2 ]; then
        info "Retention floor is 2 (active + rollback target); clamping --retain ${retain} to 2"
        retain=2
    fi

    local hist="${REPO_DIR}/channels/${channel}/history.jsonl"
    if [ ! -f "${hist}" ]; then
        info "No channel history for ${channel}; nothing to prune"
        return 0
    fi

    require_cmd python3

    # Build the protected set: this channel head, every channel head, repo-side
    # previous head, and any release_id from supplied client update state.
    local protected=()
    local ch head prev
    for ch in ${CHANNEL_SET}; do
        head="${REPO_DIR}/channels/${ch}/current.json"
        if [ -f "${head}" ]; then
            protected+=("$(json_get "${head}" release_id)")
        fi
        prev="${REPO_DIR}/channels/${ch}/previous.json"
        if [ -f "${prev}" ]; then
            protected+=("$(json_get "${prev}" release_id)")
        fi
    done
    if [ -n "${UPDATE_STATE_FILE}" ] && [ -f "${UPDATE_STATE_FILE}" ]; then
        protected+=("$(json_get "${UPDATE_STATE_FILE}" release_id)")
    fi
    if [ -n "${ROLLBACK_STATE_FILE}" ] && [ -f "${ROLLBACK_STATE_FILE}" ]; then
        protected+=("$(json_get "${ROLLBACK_STATE_FILE}" release_id)")
    fi

    # Compute the ordered, de-duplicated release list for this channel (oldest
    # first) and the newest-N keep window; python emits the prunable ids.
    local prunable
    prunable="$(PRUNE_PROTECTED="${protected[*]}" python3 - "${hist}" "${retain}" <<'PYEOF'
import json, os, sys

hist_path = sys.argv[1]
retain = int(sys.argv[2])
protected = set(os.environ.get("PRUNE_PROTECTED", "").split())

order = []
seen = set()
with open(hist_path) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        rid = rec.get("release_id")
        if not rid:
            continue
        # keep the LATEST position for a repeated id
        if rid in seen:
            order.remove(rid)
        order.append(rid)
        seen.add(rid)

# newest-N are kept; the rest are prune candidates (but never protected ones).
keep = set(order[-retain:]) if retain > 0 else set()
for rid in order[:-retain] if retain > 0 else order:
    if rid in keep or rid in protected:
        continue
    print(rid)
PYEOF
)"

    if [ -z "${prunable}" ]; then
        info "Retention: nothing to prune in ${channel} (retain=${retain})"
        return 0
    fi

    local rid rel_dir
    while IFS= read -r rid; do
        [ -n "${rid}" ] || continue
        rel_dir="${REPO_DIR}/releases/${rid}"
        case "${rel_dir}" in
            "${REPO_DIR}/releases/"*)
                if [ -d "${rel_dir}" ]; then
                    rm -rf "${rel_dir}"
                    info "Retention: pruned superseded release ${rid} from ${channel}"
                    append_repo_evidence "prune" "${channel}" "${rid}" "OK" "retention pruned superseded release (retain=${retain})"
                fi
                ;;
            *) die "refusing unsafe prune path: ${rel_dir}" ;;
        esac
    done <<EOF
${prunable}
EOF
}

do_prune() {
    [ -n "${REPO_DIR}" ] || die "--repo-dir is required"
    [ -n "${RETAIN}" ] || die "--retain N is required for prune"
    prune_channel "${CHANNEL}" "${RETAIN}"
    info "Retention applied to ${CHANNEL} in ${REPO_DIR}"
}

# ---------------------------------------------------------------------------
# Argument parsing (optional leading subcommand: publish | promote | prune)
# ---------------------------------------------------------------------------

VERSION_SET=""
ARCH_SET=""

case "${1:-}" in
    publish|promote|prune) COMMAND="$1"; shift ;;
    ""|--*|-h) COMMAND="publish" ;;
    *) COMMAND="publish" ;;
esac

while [ $# -gt 0 ]; do
    case "$1" in
        --repo-dir)           REPO_DIR="$2"; shift 2 ;;
        --channel)            CHANNEL="$2"; shift 2 ;;
        --release-id)         RELEASE_ID="$2"; shift 2 ;;
        --version)            VERSION="$2"; VERSION_SET=1; shift 2 ;;
        --arch)               ARCH="$2"; ARCH_SET=1; shift 2 ;;
        --manifest)           MANIFEST="$2"; shift 2 ;;
        --sbom)               SBOM="$2"; shift 2 ;;
        --provenance)         PROVENANCE="$2"; shift 2 ;;
        --artifact)           ARTIFACTS+=("$2"); shift 2 ;;
        --promote-from)       PROMOTE_FROM="$2"; COMMAND="promote"; shift 2 ;;
        --retain)             RETAIN="$2"; shift 2 ;;
        --update-state-file)  UPDATE_STATE_FILE="$2"; shift 2 ;;
        --rollback-state-file) ROLLBACK_STATE_FILE="$2"; shift 2 ;;
        --signing-key)        SIGNING_KEY="$2"; shift 2 ;;
        --signing-key-id)     SIGNING_KEY_ID="$2"; shift 2 ;;
        --allow-unsigned)     ALLOW_UNSIGNED=1; shift ;;
        --skip-linkage-check) SKIP_LINKAGE_CHECK=1; shift ;;
        --help|-h)            usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "${COMMAND}" in
    publish) do_publish ;;
    promote) do_promote ;;
    prune)   do_prune ;;
    *) die "unknown command: ${COMMAND}" ;;
esac
