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
#   aios.answer_file=PATH       SIGNED unattended answer file. When present it is
#                               the ONLY config source: its detached signature
#                               (PATH.sig) must verify against the ISO trust anchor
#                               (/etc/aios/answer-file-signing.pub) BEFORE anything
#                               is exported; a tampered/unsigned file is rejected
#                               fail-closed (exit 3) and the installer never runs.
#                               Individual unsigned aios.* keys below are ignored in
#                               this mode. Answer-file keys: disk, hostname, profile,
#                               selinux_mode, squashfs, skip_tpm, skip_verity,
#                               skip_selinux, no_poweroff (key = value, # comments).
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
#   2   quick installer not found
#   3   signed answer file rejected (missing/invalid signature, bad key/parse) —
#       fails closed BEFORE any disk-mutating installer call
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
# Trust anchor for signed answer files (baked into the enterprise ISO). Overridable
# for tests. A signed answer file's detached signature must verify against this key.
ANSWER_TRUST_KEY="${AIOS_ANSWER_TRUST_KEY:-/etc/aios/answer-file-signing.pub}"
ANSWER_NO_POWEROFF=0

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

# ── Signed answer file (unattended enterprise install) ────────────────────────
# An answer file is a small `key = value` file (comments with `#`). It is trusted
# ONLY when its detached signature (FILE.sig) verifies against the ISO's baked-in
# trust anchor. Values are parsed through a strict whitelist (no eval, unknown keys
# are a hard error), so a tampered file cannot inject unexpected behaviour. On ANY
# verification or parse failure the function fails closed and NO AIOS_* variable is
# exported and the installer is never run.

# Map one whitelisted answer-file key onto the AIOS_* environment. Returns non-zero
# on an unknown key so the whole file is rejected fail-closed.
map_answer_key() {
    local key="$1" val="$2"
    case "${key}" in
        disk)         export AIOS_TARGET_DISK="${val}" ;;
        hostname)     export AIOS_HOSTNAME="${val}" ;;
        profile)      export AIOS_PROFILE="${val}" ;;
        selinux_mode) export AIOS_SELINUX_MODE="${val}" ;;
        squashfs)     export AIOS_SQUASHFS="${val}" ;;
        skip_tpm)     if [ "${val}" = "1" ]; then export AIOS_SKIP_TPM=1; fi ;;
        skip_verity)  if [ "${val}" = "1" ]; then export AIOS_SKIP_VERITY=1; fi ;;
        skip_selinux) if [ "${val}" = "1" ]; then export AIOS_SKIP_SELINUX=1; fi ;;
        no_poweroff)  if [ "${val}" = "1" ]; then ANSWER_NO_POWEROFF=1; fi ;;
        *) return 1 ;;
    esac
    return 0
}

parse_answer_file() {
    local file="$1" line key val
    while IFS= read -r line || [ -n "${line}" ]; do
        line="${line%%#*}"
        line="$(printf '%s' "${line}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -n "${line}" ] || continue
        case "${line}" in
            *=*) : ;;
            *) log "FAILED reason=answer-file-malformed-line"; return 1 ;;
        esac
        key="$(printf '%s' "${line%%=*}" | sed 's/[[:space:]]*$//')"
        val="$(printf '%s' "${line#*=}" | sed 's/^[[:space:]]*//')"
        if ! map_answer_key "${key}" "${val}"; then
            log "FAILED reason=answer-file-unknown-key key=${key}"
            return 1
        fi
    done < "${file}"
    export AIOS_CONFIRM_SKIP=1
}

# Verify a signed answer file end to end, then load it. Fails closed (non-zero,
# nothing exported) on missing file/sig/key or an invalid signature.
verify_and_load_answer_file() {
    local file="$1"
    local sig="${file}.sig"
    command -v openssl >/dev/null 2>&1 || { log "FAILED reason=openssl-missing code=3"; return 1; }
    [ -f "${file}" ] || { log "FAILED reason=answer-file-missing path=${file} code=3"; return 1; }
    [ -f "${sig}" ]  || { log "FAILED reason=answer-file-signature-missing path=${sig} code=3"; return 1; }
    [ -f "${ANSWER_TRUST_KEY}" ] || { log "FAILED reason=answer-file-trust-key-missing path=${ANSWER_TRUST_KEY} code=3"; return 1; }
    if ! openssl dgst -sha256 -verify "${ANSWER_TRUST_KEY}" -signature "${sig}" "${file}" >/dev/null 2>&1; then
        log "FAILED reason=answer-file-signature-invalid path=${file} code=3"
        return 1
    fi
    log "answer-file-verified path=${file}"
    parse_answer_file "${file}" || return 1
    return 0
}

# ── Activation guard ──────────────────────────────────────────────────────────

do_poweroff() {
    # Best-effort power off so the QEMU harness's guest exits cleanly.
    if cmdline_bool aios.no_poweroff || [ "${ANSWER_NO_POWEROFF}" = "1" ]; then
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

# ── Resolve the install configuration ─────────────────────────────────────────
# Two sources, mutually exclusive. When `aios.answer_file=PATH` is present the
# SIGNED answer file is the ONLY source of truth: it must verify against the trust
# anchor before anything is exported, and the individual unsigned aios.* keys are
# ignored (so a signed file cannot be silently mixed with untrusted cmdline args).
# Without it, the legacy unsigned cmdline mapping applies (lab / CI-bare use).

if ANSWER_FILE="$(cmdline_value aios.answer_file)"; then
    log "answer-file-mode path=${ANSWER_FILE}"
    if ! verify_and_load_answer_file "${ANSWER_FILE}"; then
        # verify_and_load_answer_file already logged the exact FAILED reason.
        do_poweroff
        exit 3
    fi
else
    _disk="$(cmdline_value aios.disk || printf '/dev/vda')"
    _host="$(cmdline_value aios.hostname || printf 'aios-autoinstall')"
    export AIOS_TARGET_DISK="${_disk}"
    export AIOS_HOSTNAME="${_host}"
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
    log "unsigned-cmdline-mode (no aios.answer_file)"
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
