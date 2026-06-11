#!/bin/sh
#
# AI-OS.NET Evidence Tray Autostart
#
# Starts the evidence tray icon showing live posture state
# in the KDE system tray. Displays current posture color
# and provides quick access to evidence logs.
#
# POSIX-compatible

set -e

msg()  { printf '[AIOS-EVIDENCE-TRAY] %s\n' "$*"; }
warn() { printf '[AIOS-EVIDENCE-TRAY] %s\n' "$*" >&2; }

AIOS_BIN="${AIOS_BIN:-/usr/bin/aios}"
POSTURE_FILE="${POSTURE_FILE:-/etc/aios/time-posture}"
POSTURE_UPDATE_INTERVAL="${POSTURE_UPDATE_INTERVAL:-30}"

msg "Starting AIOS evidence tray..."

start_tray_process() {
    if [ -x "${AIOS_BIN}" ]; then
        "${AIOS_BIN}" evidence tray --daemon \
            --interval "${POSTURE_UPDATE_INTERVAL}" \
            >/dev/null 2>&1 &
        _tray_pid=$!
        msg "Evidence tray daemon started (pid ${_tray_pid})."
        return 0
    fi

    warn "aios CLI not found — starting minimal posture watcher."
    (
        while true; do
            if [ -r "${POSTURE_FILE}" ]; then
                _posture=$(head -n1 "${POSTURE_FILE}" 2>/dev/null | tr -d '[:space:]')
                notify-send "AIOS Posture" "System posture: ${_posture}" \
                    --icon=security-high \
                    --category=security \
                    2>/dev/null || true
            fi
            sleep "${POSTURE_UPDATE_INTERVAL}"
        done
    ) &
    _tray_pid=$!
    msg "Minimal posture watcher started (pid ${_tray_pid})."
}

start_tray_process
