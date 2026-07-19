#!/usr/bin/env bash
#
# AI-OS.NET R13.7 — signed gate-waiver (exception record) verifier.
#
# Enforces the acceptance line "A manual waiver requires a signed exception record"
# (REV13-ENTERPRISE-SPEC §10). A gate may be manually overridden ONLY by a waiver
# that:
#   * carries a valid detached signature from a trusted waiver-signing key,
#   * is an aios.gate_waiver.v1 record for the EXACT gate being overridden,
#   * (optionally) names the exact release target (SHA / MR / release id), and
#   * has not expired.
# Any failure exits non-zero with a precise reason — so a broken, forged, stale, or
# wrong-scope waiver can never silently unblock a gate. Fabricates no data; it only
# checks a record a human authored and signed out of band.
#
# Waiver record (JSON): {"schema":"aios.gate_waiver.v1","gate":"<gate>","target":
#   "<sha|mr|release>","reason":"...","approver":"...","issued_at":<epoch>,
#   "expires_at":<epoch>}   with a detached <file>.sig alongside it.
#
# Usage:
#   aios-waiver-verify.sh --waiver FILE --key PUBKEY --gate NAME [--target T] [--now EPOCH]
# Exit: 0 valid, 1 rejected (with reason on stderr), 2 usage error.
set -u

WAIVER=""; KEY=""; GATE=""; TARGET=""; NOW=""

reject() { printf 'AIOS-WAIVER: REJECTED reason=%s\n' "$*" >&2; exit 1; }
die()    { printf 'AIOS-WAIVER: ERROR %s\n' "$*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --waiver) WAIVER="${2:-}"; shift 2 ;;
        --key)    KEY="${2:-}"; shift 2 ;;
        --gate)   GATE="${2:-}"; shift 2 ;;
        --target) TARGET="${2:-}"; shift 2 ;;
        --now)    NOW="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "${WAIVER}" ] || die "--waiver FILE is required"
[ -n "${KEY}" ]    || die "--key PUBKEY is required"
[ -n "${GATE}" ]   || die "--gate NAME is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[ -f "${WAIVER}" ] || reject "waiver-missing:${WAIVER}"
[ -f "${WAIVER}.sig" ] || reject "signature-missing:${WAIVER}.sig"
[ -f "${KEY}" ] || reject "trust-key-missing:${KEY}"

# 1. signature must verify against the trusted waiver-signing key.
if ! openssl dgst -sha256 -verify "${KEY}" -signature "${WAIVER}.sig" "${WAIVER}" >/dev/null 2>&1; then
    reject "signature-invalid"
fi

# 2. content checks (schema / gate / target / expiry) in one python pass.
NOW="${NOW:-$(date -u +%s)}"
_reason="$(GATE="${GATE}" TARGET="${TARGET}" NOW="${NOW}" python3 - "${WAIVER}" <<'PY'
import json, os, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("malformed-json"); sys.exit(0)
if d.get("schema") != "aios.gate_waiver.v1":
    print("bad-schema"); sys.exit(0)
gate = os.environ["GATE"]
if d.get("gate") != gate:
    print("gate-mismatch"); sys.exit(0)
target = os.environ.get("TARGET", "")
if target and d.get("target") != target:
    print("target-mismatch"); sys.exit(0)
try:
    exp = int(d.get("expires_at"))
    now = int(os.environ["NOW"])
except (TypeError, ValueError):
    print("bad-expires_at"); sys.exit(0)
if now >= exp:
    print("expired"); sys.exit(0)
print("OK")
PY
)"

case "${_reason}" in
    OK) : ;;
    "") die "waiver content check produced no result" ;;
    *) reject "${_reason}" ;;
esac

printf 'AIOS-WAIVER: VALID gate=%s%s\n' "${GATE}" "${TARGET:+ target=${TARGET}}"
exit 0
