#!/bin/sh
#
# AI-OS.NET Session Manager — Revision 6
#
# Called by SDDM via /usr/share/xsessions/aios-plasma.desktop Exec= line.
# Orchestrates the complete AIOS desktop session lifecycle:
#
#   1. Read system posture from /etc/aios/time-posture
#   2. Start AIOS Policy Kernel daemon
#   3. Start AIOS Evidence Log daemon
#   4. Verify TPM2 attestation (if available)
#   5. Set up D-Bus session bus for AIOS services
#   6. Launch KDE Plasma Wayland session
#   7. On session exit: graceful teardown of all AIOS daemons
#   8. Log session start/end to evidence via aios CLI
#
# POSIX-compatible — no bashisms.

set -e

# ── Paths ────────────────────────────────────────────────────────────────────

AIOS_BIN="${AIOS_BIN:-/usr/bin/aios}"
AIOS_LIB_DIR="${AIOS_LIB_DIR:-/usr/lib/aios}"
AIOS_CONFIG_DIR="${AIOS_CONFIG_DIR:-/etc/aios}"
AIOS_STATE_DIR="${AIOS_STATE_DIR:-/var/lib/aios}"
AIOS_RUN_DIR="${AIOS_RUN_DIR:-/run/aios}"
AIOS_LOG_DIR="${AIOS_LOG_DIR:-/var/log/aios}"

POSTURE_FILE="${AIOS_CONFIG_DIR}/time-posture"
AIOS_PID_DIR="${AIOS_RUN_DIR}/pids"
SESSION_ID_FILE="${AIOS_RUN_DIR}/session-id"

# ── Message helpers ──────────────────────────────────────────────────────────

msg()  { printf '\033[1;34m[AIOS-SESSION]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[AIOS-SESSION]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[AIOS-SESSION]\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[1;32m[AIOS-SESSION]\033[0m %s\n' "$*"; }

# ── Die with message ─────────────────────────────────────────────────────────

die() {
    err "$*"
    exit 1
}

# ── Generate session ID ──────────────────────────────────────────────────────

generate_session_id() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    elif [ -r /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    else
        printf 'aios-%s-%s' "$(date +%s)" "$$"
    fi
}

# ── Read posture ─────────────────────────────────────────────────────────────

read_posture() {
    if [ -r "${POSTURE_FILE}" ]; then
        head -n1 "${POSTURE_FILE}" 2>/dev/null | tr -d '[:space:]'
    else
        printf 'SECURE_DEFAULT'
    fi
}

# ── Start daemon helper ──────────────────────────────────────────────────────

start_daemon() {
    _name="$1"
    _cmd="$2"
    _pidfile="${AIOS_PID_DIR}/${_name}.pid"
    _logfile="${AIOS_LOG_DIR}/${_name}.log"

    if [ ! -x "$(printf '%s' "${_cmd}" | awk '{print $1}')" ]; then
        warn "Cannot start ${_name}: binary not found (${_cmd})"
        return 1
    fi

    msg "Starting ${_name}..."
    mkdir -p "${AIOS_LOG_DIR}" "${AIOS_PID_DIR}"

    # shellcheck disable=SC2086
    ${_cmd} > "${_logfile}" 2>&1 &
    _pid=$!
    printf '%d' "${_pid}" > "${_pidfile}"
    ok "${_name} started (pid ${_pid})"
    return 0
}

# ── Stop daemon helper ───────────────────────────────────────────────────────

stop_daemon() {
    _name="$1"
    _pidfile="${AIOS_PID_DIR}/${_name}.pid"

    if [ ! -f "${_pidfile}" ]; then
        return 0
    fi

    _pid=$(cat "${_pidfile}" 2>/dev/null || true)
    if [ -z "${_pid}" ]; then
        return 0
    fi

    msg "Stopping ${_name} (pid ${_pid})..."
    kill "${_pid}" 2>/dev/null || true

    _waited=0
    while kill -0 "${_pid}" 2>/dev/null; do
        sleep 1
        _waited=$(( _waited + 1 ))
        if [ "${_waited}" -ge 10 ]; then
            warn "${_name} not responding, force killing..."
            kill -9 "${_pid}" 2>/dev/null || true
            break
        fi
    done

    rm -f "${_pidfile}"
    ok "${_name} stopped."
}

# ── Log evidence entry ───────────────────────────────────────────────────────

log_evidence() {
    _event="$1"
    _details="${2:-}"
    _timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    if [ -x "${AIOS_BIN}" ]; then
        "${AIOS_BIN}" evidence log \
            --event "${_event}" \
            --session "${SESSION_ID}" \
            --timestamp "${_timestamp}" \
            --details "${_details}" 2>/dev/null || true
    else
        _evidence_file="${AIOS_STATE_DIR}/evidence/session.log"
        mkdir -p "$(dirname "${_evidence_file}")"
        printf '%s | %s | %s | %s\n' \
            "${_timestamp}" "${SESSION_ID}" "${_event}" "${_details}" \
            >> "${_evidence_file}"
    fi
}

# ── Verify TPM2 attestation ──────────────────────────────────────────────────

verify_tpm2_attestation() {
    _posture="$1"

    if ! command -v tpm2_pcrread >/dev/null 2>&1; then
        warn "tpm2_pcrread not found — skipping TPM2 attestation."
        return 0
    fi

    msg "Verifying TPM2 PCR state..."
    _pcr_output="${AIOS_RUN_DIR}/pcr-state.txt"
    if tpm2_pcrread sha256:0,1,2,3,4,5,6,7 > "${_pcr_output}" 2>/dev/null; then
        ok "TPM2 PCR banks read successfully."
        case "${_posture}" in
            AIRGAP_HIGH)
                if grep -q '0000000000000000000000000000000000000000000000000000000000000000' "${_pcr_output}"; then
                    warn "TPM2 PCRs show zero values — possible attestation bypass."
                fi
                ;;
        esac
    else
        warn "TPM2 PCR read failed — system may not have TPM."
        if [ "${_posture}" = "AIRGAP_HIGH" ]; then
            err "AIRGAP_HIGH posture requires TPM2 attestation."
            return 1
        fi
    fi
    rm -f "${_pcr_output}"
    return 0
}

# ── Set up D-Bus session bus ─────────────────────────────────────────────────

setup_dbus_session() {
    msg "Setting up D-Bus session bus..."

    if [ -z "${DBUS_SESSION_BUS_ADDRESS}" ]; then
        if command -v dbus-launch >/dev/null 2>&1; then
            eval "$(dbus-launch --sh-syntax --exit-with-session)" || true
            ok "D-Bus session launched: ${DBUS_SESSION_BUS_ADDRESS}"
        else
            warn "dbus-launch not found — AIOS D-Bus services may not work."
        fi
    else
        ok "D-Bus session already active: ${DBUS_SESSION_BUS_ADDRESS}"
    fi

    export DBUS_SESSION_BUS_ADDRESS
}

# ── Set up Wayland environment ────────────────────────────────────────────────

setup_wayland_env() {
    if [ -z "${WAYLAND_DISPLAY}" ]; then
        WAYLAND_DISPLAY="wayland-0"
    fi

    AIOS_WAYLAND_DISPLAY="${WAYLAND_DISPLAY}"
    export AIOS_WAYLAND_DISPLAY WAYLAND_DISPLAY

    msg "Wayland display: ${WAYLAND_DISPLAY}"
}

# ── Start policy kernel daemon ────────────────────────────────────────────────

start_policy_kernel() {
    _policy_bin="${AIOS_LIB_DIR}/aios-policy-kernel"
    if [ ! -x "${_policy_bin}" ]; then
        _policy_bin="${AIOS_BIN}"
        _policy_cmd="${AIOS_BIN} policy serve"
    else
        _policy_cmd="${_policy_bin}"
    fi

    start_daemon "aios-policy-kernel" "${_policy_cmd}"
}

# ── Start evidence log daemon ─────────────────────────────────────────────────

start_evidence_daemon() {
    _evidence_bin="${AIOS_LIB_DIR}/aios-evidence-log"
    if [ ! -x "${_evidence_bin}" ]; then
        _evidence_bin="${AIOS_BIN}"
        _evidence_cmd="${AIOS_BIN} evidence serve"
    else
        _evidence_cmd="${_evidence_bin}"
    fi

    start_daemon "aios-evidence-log" "${_evidence_cmd}"
}

# ── Start KDE Plasma session ─────────────────────────────────────────────────

start_plasma_session() {
    msg "Launching KDE Plasma Wayland session..."

    _plasma_cmd=""
    for _candidate in \
        /usr/bin/startplasma-wayland \
        /usr/bin/startplasmacompositor \
        /usr/bin/startkde; do
        if [ -x "${_candidate}" ]; then
            _plasma_cmd="${_candidate}"
            break
        fi
    done

    if [ -z "${_plasma_cmd}" ]; then
        die "No KDE Plasma launcher found. Tried: startplasma-wayland, startplasmacompositor, startkde"
    fi

    msg "Plasma launcher: ${_plasma_cmd}"
    "${_plasma_cmd}"
    _exit_code=$?

    msg "Plasma session exited with code ${_exit_code}."
    return "${_exit_code}"
}

# ── Teardown all AIOS daemons ─────────────────────────────────────────────────

teardown_all() {
    msg "=== Session teardown ==="

    for _daemon in \
        aios-evidence-log \
        aios-policy-kernel; do
        stop_daemon "${_daemon}"
    done

    rm -f "${SESSION_ID_FILE}"
    msg "Teardown complete."
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    msg "========================================"
    msg "AI-OS.NET Session Manager — Revision 6"
    msg "========================================"

    # Generate session ID
    SESSION_ID=$(generate_session_id)
    printf '%s' "${SESSION_ID}" > "${SESSION_ID_FILE}"
    ok "Session ID: ${SESSION_ID}"

    # Read posture
    POSTURE=$(read_posture)
    ok "System posture: ${POSTURE}"

    # Verify TPM2 attestation
    if ! verify_tpm2_attestation "${POSTURE}"; then
        err "TPM2 attestation failed for posture ${POSTURE}."
        exit 1
    fi

    # Set up environment
    setup_wayland_env
    setup_dbus_session

    # Start AIOS daemons
    start_policy_kernel
    start_evidence_daemon

    # Log session start
    log_evidence "SESSION_START" "posture=${POSTURE} wayland=${WAYLAND_DISPLAY}"

    # Run Plasma session
    set +e
    start_plasma_session
    PLASMA_EXIT=$?
    set -e

    # Log session end
    log_evidence "SESSION_END" "exit_code=${PLASMA_EXIT}"

    # Teardown
    teardown_all

    msg "Session complete. Exit code: ${PLASMA_EXIT}"
    exit "${PLASMA_EXIT}"
}

# ── Trap cleanup ─────────────────────────────────────────────────────────────

trap 'log_evidence "SESSION_ABORT" "signal"; teardown_all; exit 1' INT TERM HUP

main "$@"
