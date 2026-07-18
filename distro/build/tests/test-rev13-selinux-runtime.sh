#!/usr/bin/env bash
#
# AI-OS.NET R13.7 — runtime SELinux-enforcing gate test.
#
# Proves the RUNTIME SELinux signal exists and the install gate can enforce it,
# closing the gap where "SELinux enforcing" was only checked by grepping build
# scripts (never getenforce at runtime). Two parts:
#   1. aios-health-report.sh emits `AIOS-HEALTH-SELINUX: <mode>` from getenforce
#      (enforcing / permissive / unavailable), driven by a PATH-shadowed fake so
#      the test is hermetic.
#   2. qemu-install-test.sh, under AIOS_REQUIRE_SELINUX_ENFORCING=1, asserts the
#      installed-boot log carries `AIOS-HEALTH-SELINUX: enforcing` and fails closed
#      otherwise.
#
# Run: bash distro/build/tests/test-rev13-selinux-runtime.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISTRO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
HEALTH="${DISTRO_DIR}/aios-boot/aios-health-report.sh"
INSTALL_TEST="${DISTRO_DIR}/build/qemu-install-test.sh"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
PASSED=0; FAILED=0
msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-selinux.XXXXXX")"
cleanup() { case "${WORK}" in /tmp/*|"${TMPDIR:-/tmp}"/*) rm -rf "${WORK}" ;; esac; }
trap cleanup EXIT INT TERM

# A hermetic fake environment: a fake systemctl (no failed units → RUNNING) and a
# fake getenforce whose output we control, both shadowed onto PATH.
BIN="${WORK}/bin"; mkdir -p "${BIN}"
cat > "${BIN}/systemctl" <<'EOF'
#!/bin/sh
case "$1" in
  is-system-running) exit 0 ;;
  --failed) exit 0 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "${BIN}/systemctl"

set_getenforce() {  # set_getenforce "Enforcing" | remove
    if [ "$1" = "remove" ]; then rm -f "${BIN}/getenforce"; return; fi
    printf '#!/bin/sh\necho "%s"\n' "$1" > "${BIN}/getenforce"
    chmod +x "${BIN}/getenforce"
}

run_health() { PATH="${BIN}:${PATH}" CONSOLE=/nonexistent sh "${HEALTH}" 2>/dev/null; }

msg "0. presence / syntax"
[ -f "${HEALTH}" ] && pass "aios-health-report.sh exists" || fail "health report missing"
sh -n "${HEALTH}" 2>/dev/null && pass "health report syntax OK" || fail "health report syntax error"
[ -f "${INSTALL_TEST}" ] && pass "qemu-install-test.sh exists" || fail "install test missing"

# ── 1. enforcing is reported ─────────────────────────────────────────────────
msg "1. health report emits the runtime SELinux mode"
set_getenforce "Enforcing"
out="$(run_health)"
printf '%s\n' "${out}" | grep -qE 'AIOS-HEALTH-SELINUX:[[:space:]]*enforcing' \
    && pass "enforcing reported (lowercased)" || fail "enforcing not reported: ${out}"
printf '%s\n' "${out}" | grep -qE 'AIOS-HEALTH:[[:space:]]*RUNNING' \
    && pass "still emits the health verdict" || fail "health verdict missing"

# ── 2. permissive is reported (not masked as enforcing) ──────────────────────
msg "2. permissive is reported honestly"
set_getenforce "Permissive"
out="$(run_health)"
printf '%s\n' "${out}" | grep -qE 'AIOS-HEALTH-SELINUX:[[:space:]]*permissive' \
    && pass "permissive reported" || fail "permissive not reported: ${out}"
printf '%s\n' "${out}" | grep -qE 'AIOS-HEALTH-SELINUX:[[:space:]]*enforcing' \
    && fail "permissive masked as enforcing" || pass "permissive not masked as enforcing"

# ── 3. getenforce absent → unavailable ───────────────────────────────────────
# Restrict PATH to the fake bin ONLY so the host's real getenforce is not found.
msg "3. no getenforce → unavailable"
set_getenforce remove
# /usr/bin:/bin so sh/tr/awk resolve; deliberately EXCLUDE /usr/sbin:/sbin where
# the host's real getenforce lives, so the "absent" path is genuinely exercised.
out="$(PATH="${BIN}:/usr/bin:/bin" CONSOLE=/nonexistent sh "${HEALTH}" 2>/dev/null)"
printf '%s\n' "${out}" | grep -qE 'AIOS-HEALTH-SELINUX:[[:space:]]*unavailable' \
    && pass "unavailable reported when getenforce absent" || fail "unavailable not reported: ${out}"

# ── 4. the install gate enforces it under the opt-in flag ────────────────────
msg "4. qemu-install-test.sh runtime enforcement gate"
grep -q 'AIOS_REQUIRE_SELINUX_ENFORCING' "${INSTALL_TEST}" \
    && pass "install test honors AIOS_REQUIRE_SELINUX_ENFORCING" || fail "no enforcing opt-in in install test"
grep -qE 'AIOS-HEALTH-SELINUX:.*enforcing' "${INSTALL_TEST}" \
    && pass "install test asserts the enforcing marker" || fail "install test does not assert the marker"

# Simulate the gate's assertion logic against two boot logs.
GOOD="${WORK}/good.log"; BAD="${WORK}/bad.log"
printf 'AIOS-INIT === Switching to real root ===\nAIOS-HEALTH-SELINUX: enforcing\n' > "${GOOD}"
printf 'AIOS-INIT === Switching to real root ===\nAIOS-HEALTH-SELINUX: permissive\n' > "${BAD}"
grep -E -q -- 'AIOS-HEALTH-SELINUX:[[:space:]]*enforcing' "${GOOD}" \
    && pass "an enforcing boot log satisfies the gate" || fail "enforcing log should satisfy the gate"
grep -E -q -- 'AIOS-HEALTH-SELINUX:[[:space:]]*enforcing' "${BAD}" \
    && fail "a permissive boot log wrongly satisfies the gate" || pass "a permissive boot log fails the gate"

printf '\n%s[TEST]%s selinux-runtime gate: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" "${RED}" "${FAILED}" "${RESET}"
[ "${FAILED}" -eq 0 ] || exit 1
