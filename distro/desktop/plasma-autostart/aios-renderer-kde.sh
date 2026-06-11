#!/bin/sh
#
# AI-OS.NET KDE Renderer Autostart
#
# Launches the KDE renderer service as a systemd --user service.
# Placed in ~/.config/autostart/ or plasma-autostart/ directory.
# Runs after the Plasma session is fully initialized.
#
# POSIX-compatible

set -e

msg()  { printf '[AIOS-RENDERER] %s\n' "$*"; }
warn() { printf '[AIOS-RENDERER] %s\n' "$*" >&2; }

SERVICE_NAME="aios-renderer-kde"

msg "Starting AIOS KDE renderer service..."

if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user is-enabled "${SERVICE_NAME}.service" >/dev/null 2>&1; then
        systemctl --user start "${SERVICE_NAME}.service" || warn "Failed to start ${SERVICE_NAME}"
        msg "${SERVICE_NAME} started via systemd --user."
    else
        warn "${SERVICE_NAME}.service not enabled for user."
        warn "Enable with: systemctl --user enable aios-renderer-kde.service"
    fi
else
    warn "systemctl not found — cannot start renderer service."
fi
