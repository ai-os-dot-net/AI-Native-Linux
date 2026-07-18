#!/usr/bin/env bash
#
# AI-OS.NET R13.6 — recovery-mode gate test.
#
# Proves the acceptance criterion "Recovery flow can repair update channel and
# rollback state" (REV13-ENTERPRISE-SPEC §9): aios-recovery.sh restores a missing
# or corrupt update-channel config to a valid known-good state, forces a specific
# channel on request (rejecting an invalid one fail-closed), and rolls the
# deployment back to the previous known-good release via aios-update.sh — failing
# closed when there is no previous deployment to restore.
#
# Run: bash distro/build/tests/test-rev13-recovery.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISTRO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RECOVERY="${DISTRO_DIR}/installer/aios-recovery.sh"
UPDATE="${DISTRO_DIR}/update/aios-update.sh"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
PASSED=0; FAILED=0
msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-recovery.XXXXXX")"
cleanup() { case "${WORK}" in /tmp/*|"${TMPDIR:-/tmp}"/*) rm -rf "${WORK}" ;; esac; }
trap cleanup EXIT INT TERM

# Point restored-config defaults + the update client at the sandbox.
STATE="${WORK}/state"; RB="${WORK}/rollback"
export AIOS_DEFAULT_STATE_DIR="${STATE}"
export AIOS_DEFAULT_ROLLBACK_DIR="${RB}"
export AIOS_DEFAULT_TRUSTED_KEY="${WORK}/trusted.pem"
CFG="${WORK}/update.toml"

rec() { bash "${RECOVERY}" "$@" --config "${CFG}" --update-script "${UPDATE}"; }

msg "0. presence / syntax"
[ -f "${RECOVERY}" ] && pass "aios-recovery.sh exists" || fail "recovery missing"
[ -x "${RECOVERY}" ] && pass "recovery executable" || fail "recovery not executable"
bash -n "${RECOVERY}" 2>/dev/null && pass "recovery syntax OK" || fail "recovery syntax error"
command -v jq >/dev/null 2>&1 && pass "jq present" || fail "jq missing"

# ── 1. repair-channel restores a MISSING config ──────────────────────────────
msg "1. repair a missing update config"
rm -f "${CFG}"
rec repair-channel >/dev/null 2>&1 && pass "repair-channel exit 0 on missing config" || fail "repair-channel failed"
[ -f "${CFG}" ] && pass "config created" || fail "config not created"
grep -q 'channel = "release"' "${CFG}" 2>/dev/null && pass "default channel = release" || fail "wrong default channel"

# ── 2. repair-channel fixes a CORRUPT config (invalid channel) ───────────────
msg "2. repair a corrupt config (invalid channel)"
printf '[updates]\nchannel = "bogus"\n' > "${CFG}"
rec repair-channel >/dev/null 2>&1 && pass "repair-channel exit 0 on corrupt config" || fail "repair-channel failed on corrupt"
grep -q 'channel = "release"' "${CFG}" 2>/dev/null && pass "corrupt channel reset to release" || fail "corrupt channel not reset"
[ -f "${CFG}.corrupt.bak" ] && pass "corrupt config backed up" || fail "no .corrupt.bak backup"

# ── 3. valid config is left unchanged (idempotent) ───────────────────────────
msg "3. a valid config is left unchanged"
rm -f "${CFG}.corrupt.bak"
cksum_before="$(cksum "${CFG}")"
rec repair-channel >/dev/null 2>&1
[ "$(cksum "${CFG}")" = "${cksum_before}" ] && pass "valid config unchanged (idempotent)" || fail "valid config was rewritten"
[ ! -f "${CFG}.corrupt.bak" ] && pass "no spurious backup for a valid config" || fail "spurious backup created"

# ── 4. --set-channel forces a specific valid channel ─────────────────────────
msg "4. --set-channel"
rec repair-channel --set-channel security >/dev/null 2>&1 && pass "exit 0 for --set-channel security" || fail "--set-channel security failed"
grep -q 'channel = "security"' "${CFG}" 2>/dev/null && pass "channel set to security" || fail "channel not set to security"

# ── 5. invalid --set-channel fails closed ────────────────────────────────────
msg "5. invalid --set-channel is rejected"
cp "${CFG}" "${WORK}/cfg-before-bad"
if rec repair-channel --set-channel bogus >/dev/null 2>&1; then
    fail "invalid --set-channel was accepted"
else
    pass "invalid --set-channel rejected fail-closed"
fi
diff -q "${CFG}" "${WORK}/cfg-before-bad" >/dev/null 2>&1 && pass "config untouched after rejected channel" || fail "config changed despite rejection"

# ── 6. rollback restores the previous known-good deployment ──────────────────
msg "6. rollback restores previous deployment"
rec repair-channel --set-channel release >/dev/null 2>&1
mkdir -p "${STATE}" "${RB}"
printf '{"schema":"aios.update_current.v1","release_id":"r-v2","status":"confirmed"}\n' > "${STATE}/current.json"
printf '{"schema":"aios.update_current.v1","release_id":"r-v1","status":"confirmed"}\n' > "${RB}/previous.json"
if rec rollback >/dev/null 2>&1; then
    pass "rollback exit 0 with a previous deployment"
else
    fail "rollback failed despite a previous deployment"
fi
if jq -e '.release_id == "r-v1"' "${STATE}/current.json" >/dev/null 2>&1; then
    pass "current deployment restored to previous (r-v1)"
else
    fail "current deployment not rolled back"
fi

# ── 7. rollback with no previous deployment fails closed ─────────────────────
msg "7. rollback with no previous deployment fails closed"
rm -f "${RB}/previous.json"
if rec rollback >"${WORK}/r7.log" 2>&1; then
    fail "rollback succeeded with no previous deployment"
else
    pass "rollback fails closed when there is nothing to restore"
fi
grep -q 'no-previous-deployment' "${WORK}/r7.log" 2>/dev/null && pass "clear no-previous diagnostic" || fail "missing no-previous diagnostic"

# ── 8. combined `repair` repairs channel + rolls back ────────────────────────
msg "8. combined repair (channel + rollback)"
printf '[updates]\nchannel = "bogus"\n' > "${CFG}"
printf '{"release_id":"r-v2"}\n' > "${STATE}/current.json"
printf '{"release_id":"r-v1"}\n' > "${RB}/previous.json"
rec repair >/dev/null 2>&1
grep -q 'channel = "release"' "${CFG}" 2>/dev/null && pass "repair fixed the channel" || fail "repair did not fix channel"
jq -e '.release_id == "r-v1"' "${STATE}/current.json" >/dev/null 2>&1 && pass "repair rolled back deployment" || fail "repair did not roll back"

# ── 9. recovery evidence is emitted ──────────────────────────────────────────
msg "9. recovery evidence"
grep -q '"schema":"aios.recovery_evidence.v1"' "${RB}/evidence.jsonl" 2>/dev/null && pass "recovery evidence schema present" || fail "no recovery evidence"
grep -q '"action":"repair-channel"' "${RB}/evidence.jsonl" 2>/dev/null && pass "repair-channel evidence" || fail "no repair-channel evidence"
grep -q '"action":"rollback"' "${RB}/evidence.jsonl" 2>/dev/null && pass "rollback evidence" || fail "no rollback evidence"

# ── 10. status runs cleanly ──────────────────────────────────────────────────
msg "10. status"
rec status >/dev/null 2>&1 && pass "status exits 0" || fail "status failed"

printf '\n%s[TEST]%s recovery-mode gate: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" "${RED}" "${FAILED}" "${RESET}"
[ "${FAILED}" -eq 0 ] || exit 1
