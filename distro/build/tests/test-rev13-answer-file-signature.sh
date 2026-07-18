#!/usr/bin/env bash
#
# AI-OS.NET R13.6 — signed unattended answer-file gate test.
#
# Proves the acceptance criterion "Tampered answer file is rejected"
# (REV13-ENTERPRISE-SPEC.md §9): the unattended installer entrypoint
# (aios-autoinstall.sh) accepts a correctly-signed answer file and maps its fields,
# and FAILS CLOSED — exit 3, installer never invoked — on a tampered file, a
# missing/foreign signature, or an unknown key.
#
# The real installer is replaced by a TRIPWIRE stub: if it ever runs it records
# that fact, so every negative case can assert nothing disk-mutating was reached.
#
# Run: bash distro/build/tests/test-rev13-answer-file-signature.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISTRO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
AUTOINSTALL="${DISTRO_DIR}/installer/aios-autoinstall.sh"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
PASSED=0; FAILED=0
msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-answerfile.XXXXXX")"
cleanup() { case "${WORK}" in /tmp/*|"${TMPDIR:-/tmp}"/*) rm -rf "${WORK}" ;; esac; }
trap cleanup EXIT INT TERM

msg "0. presence / syntax"
[ -f "${AUTOINSTALL}" ] && pass "aios-autoinstall.sh exists" || fail "autoinstall missing"
bash -n "${AUTOINSTALL}" 2>/dev/null && pass "autoinstall syntax OK" || fail "autoinstall syntax error"
command -v openssl >/dev/null 2>&1 && pass "openssl present" || fail "openssl missing"

# ── trust anchor + a tripwire installer stub ─────────────────────────────────
KEY="${WORK}/trust.key"; PUB="${WORK}/trust.pub"
FOREIGN="${WORK}/foreign.key"; FOREIGN_PUB="${WORK}/foreign.pub"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${KEY}"     >/dev/null 2>&1
openssl pkey -in "${KEY}"     -pubout -out "${PUB}"        >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${FOREIGN}" >/dev/null 2>&1
openssl pkey -in "${FOREIGN}" -pubout -out "${FOREIGN_PUB}" >/dev/null 2>&1

TRIPWIRE="${WORK}/installer-ran"
ENVDUMP="${WORK}/env-dump"
STUB="${WORK}/fake-installer.sh"
cat > "${STUB}" <<STUBEOF
#!/usr/bin/env bash
touch "${TRIPWIRE}"
{
  echo "AIOS_TARGET_DISK=\${AIOS_TARGET_DISK:-}"
  echo "AIOS_HOSTNAME=\${AIOS_HOSTNAME:-}"
  echo "AIOS_PROFILE=\${AIOS_PROFILE:-}"
  echo "AIOS_SKIP_TPM=\${AIOS_SKIP_TPM:-}"
} > "${ENVDUMP}"
exit 0
STUBEOF
chmod +x "${STUB}"

# Helper: run autoinstall in answer-file mode. aios.no_poweroff is ALWAYS present
# so no code path can power off the test host (do_poweroff runs even on reject).
run_autoinstall() {
    local answer="$1" trust="$2"
    rm -f "${TRIPWIRE}" "${ENVDUMP}"
    AIOS_CMDLINE="aios.autoinstall aios.answer_file=${answer} aios.no_poweroff" \
    AIOS_ANSWER_TRUST_KEY="${trust}" \
    AIOS_QUICK_INSTALLER="${STUB}" \
    AIOS_CMDLINE_FILE="/nonexistent-cmdline-file" \
        bash "${AUTOINSTALL}" > "${WORK}/out.log" 2>&1
    return $?
}

write_answer() {  # write_answer FILE
    cat > "$1" <<'EOF'
# AIOS unattended answer file
disk = /dev/vda
hostname = aios-ent-01
profile = STIG_ALIGNED
selinux_mode = enforcing
skip_tpm = 1
no_poweroff = 1
EOF
}
sign_answer() { openssl dgst -sha256 -sign "${KEY}" -out "$1.sig" "$1"; }

# ── 1. valid signed answer file is accepted + mapped ─────────────────────────
msg "1. valid signed answer file"
A="${WORK}/answer.conf"; write_answer "${A}"; sign_answer "${A}"
if run_autoinstall "${A}" "${PUB}"; then
    pass "exit 0 on a validly signed answer file"
else
    fail "valid signed answer file was rejected (rc=$?)"
fi
[ -f "${TRIPWIRE}" ] && pass "installer WAS invoked for the valid file" || fail "installer not invoked for valid file"
grep -q '^AIOS_TARGET_DISK=/dev/vda$'   "${ENVDUMP}" 2>/dev/null && pass "disk mapped to AIOS_TARGET_DISK"   || fail "disk not mapped"
grep -q '^AIOS_HOSTNAME=aios-ent-01$'   "${ENVDUMP}" 2>/dev/null && pass "hostname mapped"                  || fail "hostname not mapped"
grep -q '^AIOS_PROFILE=STIG_ALIGNED$'   "${ENVDUMP}" 2>/dev/null && pass "profile mapped"                   || fail "profile not mapped"
grep -q '^AIOS_SKIP_TPM=1$'             "${ENVDUMP}" 2>/dev/null && pass "skip_tpm mapped"                   || fail "skip_tpm not mapped"
grep -q 'answer-file-verified'          "${WORK}/out.log" 2>/dev/null && pass "logged answer-file-verified" || fail "no verified log line"

# ── 2. TAMPERED answer file is rejected fail-closed ──────────────────────────
msg "2. tampered answer file (the headline acceptance criterion)"
A2="${WORK}/answer2.conf"; write_answer "${A2}"; sign_answer "${A2}"
# flip a real config byte AFTER signing (change the target disk)
sed -i 's|/dev/vda|/dev/sda|' "${A2}"
run_autoinstall "${A2}" "${PUB}"; rc=$?
[ "${rc}" -eq 3 ] && pass "exit 3 on a tampered answer file" || fail "expected exit 3, got ${rc}"
[ ! -f "${TRIPWIRE}" ] && pass "installer NOT invoked on tamper (nothing disk-mutating ran)" || fail "installer ran despite tamper"
grep -q 'reason=answer-file-signature-invalid' "${WORK}/out.log" 2>/dev/null \
    && pass "diagnostic: signature-invalid" || fail "missing signature-invalid diagnostic"

# ── 3. missing signature ─────────────────────────────────────────────────────
msg "3. missing signature"
A3="${WORK}/answer3.conf"; write_answer "${A3}"; sign_answer "${A3}"; rm -f "${A3}.sig"
run_autoinstall "${A3}" "${PUB}"; rc=$?
[ "${rc}" -eq 3 ] && pass "exit 3 when signature file is absent" || fail "expected exit 3, got ${rc}"
[ ! -f "${TRIPWIRE}" ] && pass "installer NOT invoked (missing signature)" || fail "installer ran without a signature"
grep -q 'reason=answer-file-signature-missing' "${WORK}/out.log" 2>/dev/null \
    && pass "diagnostic: signature-missing" || fail "missing signature-missing diagnostic"

# ── 4. foreign (untrusted) key ───────────────────────────────────────────────
msg "4. answer file signed by an untrusted key"
A4="${WORK}/answer4.conf"; write_answer "${A4}"
openssl dgst -sha256 -sign "${FOREIGN}" -out "${A4}.sig" "${A4}"   # signed by foreign key
run_autoinstall "${A4}" "${PUB}"; rc=$?                            # verified against trust anchor
[ "${rc}" -eq 3 ] && pass "exit 3 for an untrusted-key signature" || fail "expected exit 3, got ${rc}"
[ ! -f "${TRIPWIRE}" ] && pass "installer NOT invoked (untrusted key)" || fail "installer ran with untrusted signature"

# ── 5. unknown key in an otherwise-signed file ───────────────────────────────
msg "5. unknown key is rejected even when correctly signed"
A5="${WORK}/answer5.conf"
printf 'disk = /dev/vda\nhostname = h\nrootpw = hunter2\n' > "${A5}"   # rootpw is not whitelisted
sign_answer "${A5}"
run_autoinstall "${A5}" "${PUB}"; rc=$?
[ "${rc}" -eq 3 ] && pass "exit 3 on an unknown answer-file key" || fail "expected exit 3, got ${rc}"
[ ! -f "${TRIPWIRE}" ] && pass "installer NOT invoked (unknown key)" || fail "installer ran with unknown key"
grep -q 'reason=answer-file-unknown-key' "${WORK}/out.log" 2>/dev/null \
    && pass "diagnostic: unknown-key" || fail "missing unknown-key diagnostic"

# ── 6. regression: unsigned cmdline mode still works ─────────────────────────
msg "6. legacy unsigned cmdline mode unaffected"
rm -f "${TRIPWIRE}" "${ENVDUMP}"
AIOS_CMDLINE="aios.autoinstall aios.disk=/dev/vdb aios.hostname=legacy aios.no_poweroff" \
AIOS_QUICK_INSTALLER="${STUB}" AIOS_CMDLINE_FILE="/nonexistent" \
    bash "${AUTOINSTALL}" > "${WORK}/out6.log" 2>&1
rc=$?
[ "${rc}" -eq 0 ] && pass "unsigned cmdline mode exits 0" || fail "unsigned mode rc=${rc}"
grep -q '^AIOS_TARGET_DISK=/dev/vdb$' "${ENVDUMP}" 2>/dev/null && pass "unsigned cmdline disk still mapped" || fail "unsigned cmdline disk not mapped"

printf '\n%s[TEST]%s answer-file signature gate: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" "${RED}" "${FAILED}" "${RESET}"
[ "${FAILED}" -eq 0 ] || exit 1
