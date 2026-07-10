#!/bin/bash
set -euo pipefail

# =============================================================================
# AI-OS.NET Kernel-Cmdline Autoinstall Entrypoint — Revision 12
# =============================================================================
# Non-interactive bridge between the kernel command line and the env-var driven
# quick installer (aios-quick-install.sh). This is the mechanism the automated
# QEMU install gate (distro/build/qemu-install-test.sh) relies on: the live ISO
# boots with `aios.autoinstall` on the kernel command line, a live-system unit
# runs THIS script, and it maps the `aios.*` cmdline keys onto the exact
# AIOS_* environment variables that aios-quick-install.sh already consumes.
#
# It does NOT re-implement any installer logic. Every value it sets is traceable
# to aios-quick-install.sh's documented interface:
#   AIOS_TARGET_DISK    -> aios-quick-install.sh:97-100   (required)
#   AIOS_HOSTNAME       -> aios-quick-install.sh:102-105  (required)
#   AIOS_CONFIRM_SKIP=1 -> aios-quick-install.sh:107-109  (required guard)
#   AIOS_PROFILE        -> aios-quick-install.sh:111
#   AIOS_SELINUX_MODE   -> aios-quick-install.sh:118
#   AIOS_SQUASHFS       -> aios-quick-install.sh:119
#   AIOS_SKIP_TPM       -> aios-quick-install.sh:412
#   AIOS_SKIP_VERITY    -> aios-quick-install.sh:451
#   AIOS_SKIP_SELINUX   -> aios-quick-install.sh:495
#
# KERNEL COMMAND LINE KEYS (parsed from /proc/cmdline):
#   aios.autoinstall            Activate autoinstall (no value). Absent => no-op.
#   aios.disk=DEV               Target disk (default: /dev/vda)
#   aios.hostname=NAME          Hostname   (default: aios-autoinstall)
#   aios.profile=PROFILE        -> AIOS_PROFILE
#   aios.selinux_mode=MODE      -> AIOS_SELINUX_MODE
#   aios.squashfs=PATH          -> AIOS_SQUASHFS
#   aios.skip_tpm               -> AIOS_SKIP_TPM=1
#   aios.skip_verity            -> AIOS_SKIP_VERITY=1
#   aios.skip_selinux           -> AIOS_SKIP_SELINUX=1
#   aios.no_poweroff            Do not power the guest off when finished
#
# MARKERS (scanned by qemu-install-test.sh on the serial log):
#   AIOS-AUTOINSTALL: START     autoinstall activated
#   AIOS-AUTOINSTALL: SKIP      aios.autoinstall not present
#   AIOS-AUTOINSTALL: SUCCESS   installer exited 0
#   AIOS-AUTOINSTALL: FAILED    installer exited non-zero (reason + code)
#
# EXIT CODES:
#   0   success (or clean skip)
#   >0  installer exit code (propagated from aios-quick-install.sh)
#
# DEPLOYMENT (wiring into the live ISO — NOT done by this script):
#   Install this file alongside aios-quick-install.sh in the live rootfs and
#   run it from a oneshot systemd unit (or live-init hook) gated on the
#   `aios.autoinstall` cmdline flag. A sample unit is documented in
#   distro/build/QEMU-INSTALL-TEST.md.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QUICK_INSTALLER="${AIOS_QUICK_INSTALLER:-${SCRIPT_DIR}/aios-quick-install.sh}"
CMDLINE_FILE="${AIOS_CMDLINE_FILE:-/proc/cmdline}"

log() { printf 'AIOS-AUTOINSTALL: %s\n' "$*"; }

# ── Kernel command line helpers ───────────────────────────────────────────────

read_cmdline() {
    if [ -r "${CMDLINE_FILE}" ]; then
        cat "${CMDLINE_FILE}"
    else
        printf '%s' "${AIOS_CMDLINE:-}"
    fi
}

KCL="$(read_cmdline)"

cmdline_bool() {
    # Return 0 if the bare flag is present on the kernel command line.
    local _tok
    for _tok in ${KCL}; do
        [ "${_tok}" = "$1" ] && return 0
    done
    return 1
}

cmdline_value() {
    # Print the value of key=val from the kernel command line (empty if unset).
    local _tok
    for _tok in ${KCL}; do
        case "${_tok}" in
            "${1}="*) printf '%s' "${_tok#"${1}"=}"; return 0 ;;
        esac
    done
    return 1
}

# ── Activation guard ──────────────────────────────────────────────────────────

do_poweroff() {
    # Best-effort power off so the QEMU harness's guest exits cleanly.
    if cmdline_bool aios.no_poweroff; then
        return 0
    fi
    sync 2>/dev/null || true
    if command -v systemctl >/dev/null 2>&1; then
        systemctl poweroff --no-block 2>/dev/null && return 0
    fi
    if command -v poweroff >/dev/null 2>&1; then
        poweroff -f 2>/dev/null && return 0
    fi
    # Fallback: trigger a kernel power-off directly.
    if [ -w /proc/sysrq-trigger ]; then
        echo o > /proc/sysrq-trigger 2>/dev/null || true
    fi
}

if ! cmdline_bool aios.autoinstall; then
    log "SKIP (aios.autoinstall not present on kernel command line)"
    exit 0
fi

log "START"

if [ ! -f "${QUICK_INSTALLER}" ]; then
    log "FAILED reason=quick-installer-not-found path=${QUICK_INSTALLER} code=2"
    do_poweroff
    exit 2
fi

# ── Map aios.* cmdline keys onto AIOS_* environment ───────────────────────────

TARGET_DISK="$(cmdline_value aios.disk || printf '/dev/vda')"
HOST_NAME="$(cmdline_value aios.hostname || printf 'aios-autoinstall')"

export AIOS_TARGET_DISK="${TARGET_DISK}"
export AIOS_HOSTNAME="${HOST_NAME}"
export AIOS_CONFIRM_SKIP=1

if _v="$(cmdline_value aios.profile)"; then
    export AIOS_PROFILE="${_v}"
fi
if _v="$(cmdline_value aios.selinux_mode)"; then
    export AIOS_SELINUX_MODE="${_v}"
fi
if _v="$(cmdline_value aios.squashfs)"; then
    export AIOS_SQUASHFS="${_v}"
fi
if cmdline_bool aios.skip_tpm; then
    export AIOS_SKIP_TPM=1
fi
if cmdline_bool aios.skip_verity; then
    export AIOS_SKIP_VERITY=1
fi
if cmdline_bool aios.skip_selinux; then
    export AIOS_SKIP_SELINUX=1
fi

log "target-disk=${AIOS_TARGET_DISK} hostname=${AIOS_HOSTNAME} profile=${AIOS_PROFILE:-CI_BARE}"

# ── Run the real installer ────────────────────────────────────────────────────

set +e
bash "${QUICK_INSTALLER}"
INSTALL_STATUS=$?
set -e

if [ "${INSTALL_STATUS}" -eq 0 ]; then
    log "SUCCESS"
else
    log "FAILED reason=quick-installer-error code=${INSTALL_STATUS}"
fi

do_poweroff
exit "${INSTALL_STATUS}"
