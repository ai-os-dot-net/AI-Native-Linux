#!/bin/sh
#
# aios-selkies-ctl.sh — AIOS Selkies remote-desktop-stream control helper
# (Stream B1 scaffold — see distro/remote/selkies/DESIGN.md)
#
# Manages the fail-closed policy gate for aios-selkies.service. This script
# does NOT launch the actual Selkies/Smithay/KWin media pipeline — that is
# not packaged for AIOS yet (DESIGN.md §2.3 / §7 "unproven"). `start`
# performs the same gate check the systemd unit's ExecStartPre performs and
# then reports NOT_PACKAGED rather than fabricating a running stream.
#
# `enable` is a manual, root-only, explicitly-confirmed flag-file writer. It
# is a placeholder control surface, NOT the real L4 Policy Kernel
# WEB_EXPOSURE_GRANTED evidence chain (DESIGN.md §5, §7).
#
# POSIX-compatible — no bashisms.

set -e

GATE_FILE="${AIOS_SELKIES_GATE_FILE:-/etc/aios/policy/remote-desktop.enabled}"
GATE_KEY="AIOS_REMOTE_DESKTOP_POLICY_GRANTED"
GATE_VALUE="true"

msg()  { printf '[aios-selkies-ctl] %s\n' "$*"; }
err()  { printf '[aios-selkies-ctl] ERROR: %s\n' "$*" >&2; }

usage() {
    printf 'usage: %s {status|preflight|start|stop|enable --i-confirm-policy-approval|disable}\n' "$0" >&2
}

gate_granted() {
    # Returns 0 (true) only if the gate file exists and contains the exact
    # key=value line. Any other content (missing file, wrong value, empty
    # file, malformed line) is treated as NOT granted — fail closed.
    [ -f "${GATE_FILE}" ] || return 1
    grep -qx "${GATE_KEY}=${GATE_VALUE}" "${GATE_FILE}" 2>/dev/null
}

cmd_status() {
    if gate_granted; then
        msg "policy gate: GRANTED (${GATE_FILE})"
    else
        msg "policy gate: NOT GRANTED (${GATE_FILE} missing or malformed)"
    fi
}

cmd_preflight() {
    if gate_granted; then
        msg "preflight: gate GRANTED, proceeding"
        return 0
    fi
    err "preflight: gate NOT GRANTED — refusing to start aios-selkies.service"
    err "run: aios-selkies-ctl.sh enable --i-confirm-policy-approval  (root only)"
    return 1
}

cmd_start() {
    cmd_preflight
    err "start: gate is granted, but the Selkies/Smithay/KWin media pipeline"
    err "is not packaged for AIOS yet (DESIGN.md section 7, unproven/deferred)."
    err "NOT_PACKAGED — refusing to report a fake running stream."
    return 1
}

cmd_stop() {
    msg "stop: no packaged Selkies process is managed by this scaffold; nothing to stop."
    return 0
}

cmd_enable() {
    if [ "$1" != "--i-confirm-policy-approval" ]; then
        err "enable requires explicit confirmation: --i-confirm-policy-approval"
        err "this flag file is a placeholder control surface, not a real policy"
        err "decision (DESIGN.md section 5/7) — you are asserting you obtained one out of band."
        return 1
    fi
    if [ "$(id -u 2>/dev/null || echo 1)" != "0" ]; then
        err "enable must run as root (writes ${GATE_FILE})"
        return 1
    fi
    _dir=$(dirname "${GATE_FILE}")
    mkdir -p "${_dir}"
    printf '%s=%s\n' "${GATE_KEY}" "${GATE_VALUE}" > "${GATE_FILE}"
    chmod 0644 "${GATE_FILE}"
    msg "enabled: wrote ${GATE_FILE}"
}

cmd_disable() {
    if [ -f "${GATE_FILE}" ]; then
        rm -f "${GATE_FILE}"
        msg "disabled: removed ${GATE_FILE}"
    else
        msg "disable: ${GATE_FILE} did not exist; already disabled"
    fi
}

case "$1" in
    status)    cmd_status ;;
    preflight) cmd_preflight ;;
    start)     cmd_start ;;
    stop)      cmd_stop ;;
    enable)    shift; cmd_enable "$1" ;;
    disable)   cmd_disable ;;
    *)         usage; exit 2 ;;
esac
