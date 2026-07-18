#!/usr/bin/env bash
#
# AI-OS.NET R13.6/R12.7 — update boot-outcome contract wiring gate.
#
# The update rollback contract (REV12-DISTRIBUTION-SPEC §7: "failed boot / failed
# service-health must trigger rollback") has two boot-time halves:
#   * aios-update-confirm.service   — success path, marks pending healthy at multi-user
#   * aios-update-boot-check.service — recovery path, rolls back an unconfirmed,
#     past-deadline deployment early on the next boot
# Both existed only as CLI subcommands / (for confirm) an un-enabled unit; the
# boot-check trigger had NO unit and neither was enabled at boot, so the rollback
# contract could only be proven by direct CLI invocation. This gate asserts both
# units exist, are correctly wired, and are enabled by the ISO builder.
#
# Run: bash distro/build/tests/test-rev13-boot-outcome-wiring.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISTRO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SYSTEMD_DIR="${DISTRO_DIR}/systemd"
BUILD="${DISTRO_DIR}/build/build-aios-iso.sh"
BOOT_CHECK="${SYSTEMD_DIR}/aios-update-boot-check.service"
CONFIRM="${SYSTEMD_DIR}/aios-update-confirm.service"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
PASSED=0; FAILED=0
msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

# has FILE PATTERN LABEL
has() { grep -qE "$2" "$1" 2>/dev/null && pass "$3" || fail "$3"; }

msg "1. boot-check unit exists and is correctly wired"
if [ -f "${BOOT_CHECK}" ]; then
    pass "aios-update-boot-check.service exists"
    has "${BOOT_CHECK}" 'ExecStart=.*/aios-update\.sh boot-check' "boot-check runs 'aios-update.sh boot-check'"
    has "${BOOT_CHECK}" 'ExecStart=/usr/lib/aios/update/aios-update\.sh' "boot-check ExecStart uses the staged client path"
    has "${BOOT_CHECK}" 'ConditionPathExists=/var/lib/aios/update/pending-boot\.json' "boot-check gated on the pending marker (no-op otherwise)"
    has "${BOOT_CHECK}" 'Before=.*multi-user\.target' "boot-check ordered BEFORE multi-user (runs early)"
    has "${BOOT_CHECK}" 'WantedBy=multi-user\.target' "boot-check installable (WantedBy multi-user)"
    has "${BOOT_CHECK}" 'Type=oneshot' "boot-check is a oneshot"
else
    fail "aios-update-boot-check.service MISSING"
fi

msg "2. confirm-boot unit (success path) is present"
if [ -f "${CONFIRM}" ]; then
    pass "aios-update-confirm.service exists"
    has "${CONFIRM}" 'ExecStart=.*/aios-update\.sh confirm-boot' "confirm runs 'aios-update.sh confirm-boot'"
    has "${CONFIRM}" 'ConditionPathExists=/var/lib/aios/update/pending-boot\.json' "confirm gated on the pending marker"
else
    fail "aios-update-confirm.service MISSING"
fi

msg "3. the ISO builder ENABLES both units at boot"
# The builder copies every distro/systemd/*.service, but only explicitly-enabled
# units get a multi-user.target.wants symlink. Both boot-outcome units must be in
# that enable set.
has "${BUILD}" 'aios-update-boot-check\.service' "build enables aios-update-boot-check.service"
has "${BUILD}" 'aios-update-confirm\.service' "build enables aios-update-confirm.service"
# Assert they are in a wants-symlink context, not just mentioned.
if awk '/multi-user\.target\.wants/{w=1} /aios-update-boot-check\.service/{if(w)b=1} /aios-update-confirm\.service/{if(w)c=1} END{exit (b&&c)?0:1}' "${BUILD}"; then
    pass "both units enabled via multi-user.target.wants symlinks"
else
    fail "boot-outcome units not both wired into multi-user.target.wants"
fi

# ── optional: systemd-analyze verify if available (deeper unit validation) ────
if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze verify "${BOOT_CHECK}" >/dev/null 2>&1; then
        pass "systemd-analyze verify accepts the boot-check unit"
    else
        # verify can warn about ExecStart path not existing on the test host; only
        # fail on a genuine parse error.
        if systemd-analyze verify "${BOOT_CHECK}" 2>&1 | grep -qiE 'Failed to (parse|load)|Invalid'; then
            fail "systemd-analyze found a parse/load error in the boot-check unit"
        else
            pass "boot-check unit parses (systemd-analyze path warnings ignored)"
        fi
    fi
fi

printf '\n%s[TEST]%s boot-outcome wiring: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" "${RED}" "${FAILED}" "${RESET}"
[ "${FAILED}" -eq 0 ] || exit 1
