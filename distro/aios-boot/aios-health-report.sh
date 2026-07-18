#!/bin/sh
#
# AI-OS.NET Rev.12 boot-time service health reporter.
#
# Emits EXACTLY ONE line to /dev/console so an external QEMU serial-log gate can
# assert boot-time service health without a guest agent:
#
#   AIOS-HEALTH: RUNNING
#   AIOS-HEALTH: DEGRADED failed=<comma-separated unit names>
#
# It also emits the runtime SELinux enforcement mode (always, before the verdict):
#
#   AIOS-HEALTH-SELINUX: enforcing | permissive | disabled | unavailable
#
# Staged to /usr/lib/aios/aios-health-report.sh and driven by
# aios-health-report.service (oneshot, after aios.target + multi-user.target).
#
# POSIX sh only. Never fails the boot: always prints a single verdict line and
# exits 0, even when systemctl is unavailable (e.g. scaffold rootfs).

set -u

CONSOLE="/dev/console"

# Prefer the real console; fall back to stdout when it is not writable so the
# line still lands in the journal / serial capture during testing.
emit() {
    if [ -w "${CONSOLE}" ] 2>/dev/null; then
        printf '%s\n' "$*" > "${CONSOLE}" 2>/dev/null || printf '%s\n' "$*"
    else
        printf '%s\n' "$*"
    fi
}

# Report the SELinux enforcement mode so a serial-log-only gate (QEMU CI) can
# assert enforcing for enterprise profiles (STIG_ALIGNED / AIRGAP_HIGH) at RUNTIME
# — not just by grepping the build scripts. Always emitted, never fails the boot:
# "enforcing" / "permissive" / "disabled" from getenforce, or "unavailable".
if command -v getenforce >/dev/null 2>&1; then
    _selinux_mode="$(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    [ -n "${_selinux_mode}" ] || _selinux_mode="unknown"
    emit "AIOS-HEALTH-SELINUX: ${_selinux_mode}"
else
    emit "AIOS-HEALTH-SELINUX: unavailable"
fi

# No systemctl (scaffold / minimal rootfs): report degraded with an explicit
# reason rather than pretending the system is healthy.
if ! command -v systemctl >/dev/null 2>&1; then
    emit "AIOS-HEALTH: DEGRADED failed=no-systemctl"
    exit 0
fi

# Let systemd finish bringing the system up. is-system-running --wait blocks
# until the manager leaves the 'starting' state, then exits non-zero for any
# non-'running' final state (e.g. 'degraded'). We deliberately IGNORE that exit
# code and instead inspect the actual failed-unit set below.
systemctl is-system-running --wait >/dev/null 2>&1 || true

# Collect the failed units. --no-legend drops the header/footer; each remaining
# line starts with the unit name in column 1.
failed_units="$(
    systemctl --failed --no-legend --plain --no-pager 2>/dev/null \
        | awk '{ print $1 }' \
        | grep -v '^$' \
        | paste -sd ',' -
)"

if [ -n "${failed_units}" ]; then
    emit "AIOS-HEALTH: DEGRADED failed=${failed_units}"
    # Per-unit failure detail so a serial-log-only gate (QEMU CI) can diagnose
    # without guest access: unit result, exec status, and last journal lines.
    for _unit in $(printf '%s' "${failed_units}" | tr ',' ' '); do
        _detail="$(systemctl show -p Result,ExecMainStatus,StatusText --value "${_unit}" 2>/dev/null | paste -sd '/' -)"
        emit "AIOS-HEALTH-DETAIL: ${_unit} result/exec/status=${_detail}"
        journalctl -u "${_unit}" -n 8 --no-pager -o cat 2>/dev/null | while IFS= read -r _line; do
            emit "AIOS-HEALTH-JOURNAL: ${_unit}: ${_line}"
        done
    done
else
    emit "AIOS-HEALTH: RUNNING"
fi

exit 0
