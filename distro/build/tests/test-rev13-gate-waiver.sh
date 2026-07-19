#!/usr/bin/env bash
#
# AI-OS.NET R13.7 — signed gate-waiver gate test.
#
# Proves "A manual waiver requires a signed exception record" (§10): a correctly
# signed, in-scope, unexpired waiver is accepted, and every failure mode — tampered
# record, foreign key, missing signature, wrong gate, wrong target, expired, bad
# schema — is REJECTED fail-closed. Uses only openssl + a real record; fabricates
# nothing.
#
# Run: bash distro/build/tests/test-rev13-gate-waiver.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISTRO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VERIFY="${DISTRO_DIR}/compliance/aios-waiver-verify.sh"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
PASSED=0; FAILED=0
msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-waiver.XXXXXX")"
cleanup() { case "${WORK}" in /tmp/*|"${TMPDIR:-/tmp}"/*) rm -rf "${WORK}" ;; esac; }
trap cleanup EXIT INT TERM

KEY="${WORK}/waiver.key"; PUB="${WORK}/waiver.pub"
FKEY="${WORK}/foreign.key"; FPUB="${WORK}/foreign.pub"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${KEY}"  >/dev/null 2>&1
openssl pkey -in "${KEY}"  -pubout -out "${PUB}"  >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${FKEY}" >/dev/null 2>&1
openssl pkey -in "${FKEY}" -pubout -out "${FPUB}" >/dev/null 2>&1

GATE="qemu-install-gate"
TARGET="a1b2c3d4"
ISSUED=1700000000
EXPIRES=1900000000            # far future
NOW_OK=1750000000            # between issued and expires
NOW_LATE=1900000001          # past expiry

mk_waiver() {  # mk_waiver FILE GATE TARGET EXPIRES
    cat > "$1" <<EOF
{"schema":"aios.gate_waiver.v1","gate":"$2","target":"$3","reason":"install chain not yet complete","approver":"operator","issued_at":${ISSUED},"expires_at":$4}
EOF
}
sign() { openssl dgst -sha256 -sign "${KEY}" -out "$1.sig" "$1"; }

msg "0. presence / syntax"
[ -f "${VERIFY}" ] && pass "aios-waiver-verify.sh exists" || fail "verifier missing"
[ -x "${VERIFY}" ] && pass "verifier executable" || fail "verifier not executable"
bash -n "${VERIFY}" 2>/dev/null && pass "verifier syntax OK" || fail "verifier syntax error"

# ── 1. valid waiver accepted ─────────────────────────────────────────────────
msg "1. a correctly signed, in-scope, unexpired waiver is accepted"
W="${WORK}/w.json"; mk_waiver "${W}" "${GATE}" "${TARGET}" "${EXPIRES}"; sign "${W}"
if bash "${VERIFY}" --waiver "${W}" --key "${PUB}" --gate "${GATE}" --target "${TARGET}" --now "${NOW_OK}" >/dev/null 2>&1; then
    pass "valid waiver accepted (exit 0)"
else
    fail "valid waiver rejected"
fi
# gate-only (no --target) also accepted
bash "${VERIFY}" --waiver "${W}" --key "${PUB}" --gate "${GATE}" --now "${NOW_OK}" >/dev/null 2>&1 \
    && pass "valid waiver accepted without --target" || fail "gate-only check rejected a valid waiver"

# ── 2. tampered record ───────────────────────────────────────────────────────
msg "2. tampered / forged / missing signature"
Wt="${WORK}/wt.json"; mk_waiver "${Wt}" "${GATE}" "${TARGET}" "${EXPIRES}"; sign "${Wt}"
sed -i 's/install chain not yet complete/EVIL OVERRIDE/' "${Wt}"   # change after signing
bash "${VERIFY}" --waiver "${Wt}" --key "${PUB}" --gate "${GATE}" --now "${NOW_OK}" >/dev/null 2>&1 \
    && fail "tampered waiver accepted" || pass "tampered waiver rejected"

# foreign key
Wf="${WORK}/wf.json"; mk_waiver "${Wf}" "${GATE}" "${TARGET}" "${EXPIRES}"
openssl dgst -sha256 -sign "${FKEY}" -out "${Wf}.sig" "${Wf}"
bash "${VERIFY}" --waiver "${Wf}" --key "${PUB}" --gate "${GATE}" --now "${NOW_OK}" >/dev/null 2>&1 \
    && fail "foreign-key waiver accepted" || pass "foreign-key waiver rejected"

# missing signature
Wm="${WORK}/wm.json"; mk_waiver "${Wm}" "${GATE}" "${TARGET}" "${EXPIRES}"
bash "${VERIFY}" --waiver "${Wm}" --key "${PUB}" --gate "${GATE}" --now "${NOW_OK}" >/dev/null 2>&1 \
    && fail "unsigned waiver accepted" || pass "unsigned waiver rejected"

# ── 3. wrong scope ───────────────────────────────────────────────────────────
msg "3. wrong gate / wrong target"
out="$(bash "${VERIFY}" --waiver "${W}" --key "${PUB}" --gate "some-other-gate" --now "${NOW_OK}" 2>&1)" && rc=0 || rc=1
[ "${rc}" -ne 0 ] && pass "waiver for a different gate rejected" || fail "wrong-gate waiver accepted"
printf '%s' "${out}" | grep -q 'gate-mismatch' && pass "diagnostic: gate-mismatch" || fail "no gate-mismatch diagnostic"

out="$(bash "${VERIFY}" --waiver "${W}" --key "${PUB}" --gate "${GATE}" --target "deadbeef" --now "${NOW_OK}" 2>&1)" && rc=0 || rc=1
[ "${rc}" -ne 0 ] && pass "waiver for a different target rejected" || fail "wrong-target waiver accepted"
printf '%s' "${out}" | grep -q 'target-mismatch' && pass "diagnostic: target-mismatch" || fail "no target-mismatch diagnostic"

# ── 4. expiry ────────────────────────────────────────────────────────────────
msg "4. expired waiver"
We="${WORK}/we.json"; mk_waiver "${We}" "${GATE}" "${TARGET}" "1750000000"; sign "${We}"   # expires_at in the past vs NOW_LATE
out="$(bash "${VERIFY}" --waiver "${We}" --key "${PUB}" --gate "${GATE}" --now "${NOW_LATE}" 2>&1)" && rc=0 || rc=1
[ "${rc}" -ne 0 ] && pass "expired waiver rejected" || fail "expired waiver accepted"
printf '%s' "${out}" | grep -q 'expired' && pass "diagnostic: expired" || fail "no expired diagnostic"

# ── 5. bad schema ────────────────────────────────────────────────────────────
msg "5. wrong schema is rejected even when signed"
Ws="${WORK}/ws.json"
printf '{"schema":"totally.wrong.v9","gate":"%s","expires_at":%s}\n' "${GATE}" "${EXPIRES}" > "${Ws}"
sign "${Ws}"
out="$(bash "${VERIFY}" --waiver "${Ws}" --key "${PUB}" --gate "${GATE}" --now "${NOW_OK}" 2>&1)" && rc=0 || rc=1
[ "${rc}" -ne 0 ] && pass "wrong-schema waiver rejected" || fail "wrong-schema waiver accepted"
printf '%s' "${out}" | grep -q 'bad-schema' && pass "diagnostic: bad-schema" || fail "no bad-schema diagnostic"

printf '\n%s[TEST]%s gate-waiver: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" "${RED}" "${FAILED}" "${RESET}"
[ "${FAILED}" -eq 0 ] || exit 1
