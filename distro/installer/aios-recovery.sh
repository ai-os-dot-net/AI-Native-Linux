#!/bin/bash
set -euo pipefail

# =============================================================================
# AI-OS.NET Recovery-mode operator flow — Revision 13 (R13.6)
# =============================================================================
# The "Recovery" installer mode from REV13-ENTERPRISE-SPEC §9. It repairs a
# machine whose update configuration or deployment state has drifted, WITHOUT a
# reinstall, satisfying the acceptance criterion "Recovery flow can repair update
# channel and rollback state." It orchestrates primitives that already exist:
#   * the update client config /etc/aios/update.d/update.toml (channel + paths), and
#   * aios-update.sh rollback (restore the previous known-good deployment).
#
# Commands:
#   repair-channel   Ensure a VALID update.toml exists. A missing or corrupt file
#                    (unparasable, or naming a channel outside the closed set) is
#                    backed up and rewritten with known-good defaults. --set-channel
#                    NAME forces a specific (validated) channel. A valid file is left
#                    unchanged (idempotent).
#   rollback         Restore the previous known-good deployment via aios-update.sh,
#                    reading state/rollback dirs from the (repaired) config.
#   repair           repair-channel, then a best-effort rollback (no previous
#                    deployment is not an error for the combined repair).
#   status           Print the config + current update deployment state.
#
# Everything is file/state based; no daemons. Recovery actions are appended to
# <rollback_dir>/evidence.jsonl (schema aios.recovery_evidence.v1). Fails closed:
# an invalid --set-channel, or a rollback with no previous deployment, is a hard
# error (non-zero) rather than a silent success.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${AIOS_UPDATE_CONFIG:-/etc/aios/update.d/update.toml}"
SET_CHANNEL=""
DEFAULT_CHANNEL="release"
# Defaults for a restored config; overridable for tests / alternate layouts.
DEFAULT_STATE_DIR="${AIOS_DEFAULT_STATE_DIR:-/var/lib/aios/update}"
DEFAULT_ROLLBACK_DIR="${AIOS_DEFAULT_ROLLBACK_DIR:-/var/lib/aios/rollback}"
DEFAULT_TRUSTED_KEY="${AIOS_DEFAULT_TRUSTED_KEY:-/etc/aios/update.d/trusted-release-key.pem}"

# Closed channel set (must match aios-update.sh / aios-repo-publish.sh).
VALID_CHANNELS="release security staging recovery airgap"

# Resolve the update client (installed layout first, then repo layout).
UPDATE_SCRIPT="${AIOS_UPDATE_SCRIPT:-}"
if [ -z "${UPDATE_SCRIPT}" ]; then
    for _c in "/usr/lib/aios/update/aios-update.sh" "${SCRIPT_DIR}/../update/aios-update.sh"; do
        if [ -f "${_c}" ]; then UPDATE_SCRIPT="${_c}"; break; fi
    done
fi

die()  { printf 'AIOS-RECOVERY: FAILED reason=%s\n' "$*" >&2; exit 1; }
log()  { printf 'AIOS-RECOVERY: %s\n' "$*"; }

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g'; }

channel_valid() {
    local c="$1" v
    for v in ${VALID_CHANNELS}; do [ "${c}" = "${v}" ] && return 0; done
    return 1
}

# toml_get FILE KEY -> bare value (strips quotes, inline comments, whitespace).
toml_get() {
    [ -f "$1" ] || return 1
    sed -n "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*//p" "$1" 2>/dev/null | head -1 \
        | sed 's/[[:space:]]*#.*$//; s/^"//; s/"[[:space:]]*$//; s/[[:space:]]*$//'
}

resolved_dir() {  # KEY DEFAULT — value from config or the default
    local v; v="$(toml_get "${CONFIG}" "$1" || true)"
    [ -n "${v}" ] && printf '%s' "${v}" || printf '%s' "$2"
}

emit_recovery_evidence() {
    local action="$1" result="$2" detail="$3"
    local rb; rb="$(resolved_dir rollback_dir "${DEFAULT_ROLLBACK_DIR}")"
    mkdir -p "${rb}" 2>/dev/null || return 0
    cat >> "${rb}/evidence.jsonl" <<EOF
{"schema":"aios.recovery_evidence.v1","time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","action":"$(json_escape "${action}")","result":"$(json_escape "${result}")","detail":"$(json_escape "${detail}")"}
EOF
    chmod 644 "${rb}/evidence.jsonl" 2>/dev/null || true
}

write_default_config() {  # CHANNEL
    local channel="$1"
    mkdir -p "$(dirname "${CONFIG}")"
    cat > "${CONFIG}" <<EOF
# AI-OS.NET update client configuration (restored by aios-recovery.sh)
[updates]
channel = "${channel}"
state_dir = "${DEFAULT_STATE_DIR}"
rollback_dir = "${DEFAULT_ROLLBACK_DIR}"
trusted_key = "${DEFAULT_TRUSTED_KEY}"
require_signature = true
EOF
    chmod 644 "${CONFIG}"
}

config_is_valid() {
    local ch
    ch="$(toml_get "${CONFIG}" channel || true)"
    [ -n "${ch}" ] || return 1
    channel_valid "${ch}" || return 1
    [ -n "$(toml_get "${CONFIG}" state_dir || true)" ] || return 1
    [ -n "$(toml_get "${CONFIG}" rollback_dir || true)" ] || return 1
    [ -n "$(toml_get "${CONFIG}" trusted_key || true)" ] || return 1
    return 0
}

do_repair_channel() {
    # An explicit --set-channel must be valid before touching anything.
    if [ -n "${SET_CHANNEL}" ] && ! channel_valid "${SET_CHANNEL}"; then
        emit_recovery_evidence "repair-channel" "FAILED" "invalid --set-channel ${SET_CHANNEL}"
        die "invalid-channel=${SET_CHANNEL} (valid: ${VALID_CHANNELS// /, })"
    fi

    if [ -n "${SET_CHANNEL}" ]; then
        # Preserve a corrupt file for forensics before overwriting.
        if [ -f "${CONFIG}" ] && ! config_is_valid; then
            cp "${CONFIG}" "${CONFIG}.corrupt.bak"
        fi
        write_default_config "${SET_CHANNEL}"
        emit_recovery_evidence "repair-channel" "OK" "channel set to ${SET_CHANNEL}"
        log "repaired update channel -> ${SET_CHANNEL} (${CONFIG})"
        return 0
    fi

    if config_is_valid; then
        log "update config already valid (channel=$(toml_get "${CONFIG}" channel)); no change"
        emit_recovery_evidence "repair-channel" "OK" "config already valid; no change"
        return 0
    fi

    if [ -f "${CONFIG}" ]; then
        cp "${CONFIG}" "${CONFIG}.corrupt.bak"
        log "backed up corrupt config -> ${CONFIG}.corrupt.bak"
    fi
    write_default_config "${DEFAULT_CHANNEL}"
    emit_recovery_evidence "repair-channel" "OK" "restored defaults (channel=${DEFAULT_CHANNEL})"
    log "restored update config with defaults (channel=${DEFAULT_CHANNEL})"
}

do_rollback() {
    [ -n "${UPDATE_SCRIPT}" ] && [ -f "${UPDATE_SCRIPT}" ] || die "update-client-not-found"
    local state rb
    state="$(resolved_dir state_dir "${DEFAULT_STATE_DIR}")"
    rb="$(resolved_dir rollback_dir "${DEFAULT_ROLLBACK_DIR}")"
    if [ ! -f "${rb}/previous.json" ]; then
        emit_recovery_evidence "rollback" "FAILED" "no previous deployment to restore"
        die "no-previous-deployment"
    fi
    if bash "${UPDATE_SCRIPT}" rollback --state-dir "${state}" --rollback-dir "${rb}"; then
        emit_recovery_evidence "rollback" "OK" "previous deployment restored via aios-update.sh"
        log "rolled back to the previous known-good deployment"
    else
        emit_recovery_evidence "rollback" "FAILED" "aios-update.sh rollback returned non-zero"
        die "rollback-failed"
    fi
}

do_status() {
    printf 'AIOS-RECOVERY: config=%s\n' "${CONFIG}"
    if [ -f "${CONFIG}" ]; then
        printf '  channel=%s state_dir=%s rollback_dir=%s valid=%s\n' \
            "$(toml_get "${CONFIG}" channel || printf '?')" \
            "$(toml_get "${CONFIG}" state_dir || printf '?')" \
            "$(toml_get "${CONFIG}" rollback_dir || printf '?')" \
            "$(config_is_valid && printf 'yes' || printf 'no')"
    else
        printf '  (config missing)\n'
    fi
    if [ -n "${UPDATE_SCRIPT}" ] && [ -f "${UPDATE_SCRIPT}" ]; then
        local state rb
        state="$(resolved_dir state_dir "${DEFAULT_STATE_DIR}")"
        rb="$(resolved_dir rollback_dir "${DEFAULT_ROLLBACK_DIR}")"
        bash "${UPDATE_SCRIPT}" status --state-dir "${state}" --rollback-dir "${rb}" 2>/dev/null || true
    fi
}

usage() {
    cat <<'EOF'
Usage: aios-recovery.sh <command> [OPTIONS]

Commands:
  repair-channel   Ensure a valid update.toml (repair/restore if missing/corrupt)
  rollback         Restore the previous known-good deployment
  repair           repair-channel then a best-effort rollback
  status           Print update config + deployment state

Options:
  --config PATH        update.toml path (default: /etc/aios/update.d/update.toml)
  --set-channel NAME   Force channel to NAME (release|security|staging|recovery|airgap)
  --update-script PATH Path to aios-update.sh (auto-detected otherwise)
EOF
}

COMMAND="${1:-}"
[ $# -gt 0 ] && shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --config)        CONFIG="$2"; shift 2 ;;
        --set-channel)   SET_CHANNEL="$2"; shift 2 ;;
        --update-script) UPDATE_SCRIPT="$2"; shift 2 ;;
        --help|-h)       usage; exit 0 ;;
        *) die "unknown-argument=$1" ;;
    esac
done

case "${COMMAND}" in
    repair-channel) do_repair_channel ;;
    rollback)       do_rollback ;;
    repair)         do_repair_channel; do_rollback || true ;;
    status)         do_status ;;
    ""|--help|-h)   usage ;;
    *) die "unknown-command=${COMMAND}" ;;
esac
