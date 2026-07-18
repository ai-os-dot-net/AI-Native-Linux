#!/usr/bin/env bash
#
# AI-OS.NET R13.5 — airgap channel (offline import/export) gate test.
#
# Proves the `airgap` channel closes the last R13.5 gap: a signed release can be
# EXPORTED from a publishable channel into a single self-contained bundle,
# transported offline, and IMPORTED into a separate repository's airgap channel
# with full end-to-end signature/hash verification — and that every tamper or
# missing-authorization path FAILS CLOSED before any repository state is written.
#
# Covers:
#   1. export produces a bundle whose manifest signature verifies with the pubkey.
#   2. import of a valid bundle populates a signed channels/airgap/current.json and
#      the client can verify + stage off it.
#   3. import of a tampered artifact fails closed (no dest repo state written).
#   4. import with a corrupted bundle-manifest binding fails closed.
#   5. import with the WRONG verify key fails closed.
#   6. client refuses --channel airgap without --allow-airgap-channel, accepts with.
#   7. closed-set enforcement: airgap is valid (via import), bogus still rejected,
#      and export REFUSES airgap as a source (airgap is not publishable).
#   8. import/export emit repo evidence records.
#
# Run: bash distro/build/tests/test-rev13-airgap-channel.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISTRO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PUBLISH="${DISTRO_DIR}/repo/aios-repo-publish.sh"
UPDATE="${DISTRO_DIR}/update/aios-update.sh"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
PASSED=0; FAILED=0
msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-airgap.XXXXXX")"
cleanup() { case "${WORK}" in /tmp/*|"${TMPDIR:-/tmp}"/*) rm -rf "${WORK}" ;; esac; }
trap cleanup EXIT INT TERM

for s in "${PUBLISH}" "${UPDATE}"; do
    [ -f "${s}" ]  && pass "exists: ${s#"${DISTRO_DIR}"/}"        || fail "missing: ${s}"
    [ -x "${s}" ]  && pass "executable: ${s#"${DISTRO_DIR}"/}"    || fail "not executable: ${s}"
    bash -n "${s}" 2>/dev/null && pass "syntax OK: ${s#"${DISTRO_DIR}"/}" || fail "syntax error: ${s}"
done
for c in openssl jq sha256sum tar; do
    command -v "${c}" >/dev/null 2>&1 && pass "cmd present: ${c}" || fail "cmd missing: ${c}"
done

# ── fixtures ──────────────────────────────────────────────────────────────────
KEY="${WORK}/key.pem"; PUB="${WORK}/pub.pem"
KEY2="${WORK}/key2.pem"; PUB2="${WORK}/pub2.pem"   # a DIFFERENT (untrusted) key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${KEY}"  >/dev/null 2>&1
openssl pkey -in "${KEY}"  -pubout -out "${PUB}"  >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${KEY2}" >/dev/null 2>&1
openssl pkey -in "${KEY2}" -pubout -out "${PUB2}" >/dev/null 2>&1

MANIFEST="${WORK}/manifest.json"; SBOM="${WORK}/sbom.cdx.json"; PROV="${WORK}/provenance.json"
printf '{"schema":"aios.release_manifest.v1","revision":13,"artifacts":[]}\n' > "${MANIFEST}"
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}\n'      > "${SBOM}"
printf '{"schema":"aios.provenance.v1","builder":"r13-airgap-test"}\n'        > "${PROV}"
ART="${WORK}/aios.squashfs"; printf 'AIOS airgap payload\n' > "${ART}"

SRC="${WORK}/srcrepo"; DST="${WORK}/dstrepo"; BUNDLE="${WORK}/aios-airgap.tar.gz"

# ── publish a real signed release to the `release` channel of SRC ─────────────
msg "1. publish + export"
if "${PUBLISH}" publish --repo-dir "${SRC}" --release-id air-001 --channel release \
     --artifact "${ART}" --manifest "${MANIFEST}" --sbom "${SBOM}" --provenance "${PROV}" \
     --signing-key "${KEY}" >/dev/null 2>&1; then
    pass "published air-001 to release"
else
    fail "publish failed"
fi

if "${PUBLISH}" export --repo-dir "${SRC}" --channel release --out "${BUNDLE}" \
     --signing-key "${KEY}" >/dev/null 2>&1 && [ -f "${BUNDLE}" ]; then
    pass "export produced a bundle"
else
    fail "export failed"
fi

# bundle manifest signature must verify with the pubkey
_x="${WORK}/x"; mkdir -p "${_x}"; tar -C "${_x}" -xzf "${BUNDLE}" 2>/dev/null
if openssl dgst -sha256 -verify "${PUB}" -signature "${_x}/airgap-bundle.json.sig" \
     "${_x}/airgap-bundle.json" >/dev/null 2>&1; then
    pass "bundle manifest signature verifies with the public key"
else
    fail "bundle manifest signature does not verify"
fi

# ── export must REFUSE airgap as a source channel (not publishable) ───────────
if "${PUBLISH}" export --repo-dir "${SRC}" --channel airgap --out "${WORK}/nope.tar.gz" \
     --signing-key "${KEY}" >/dev/null 2>&1; then
    fail "export accepted airgap as a source channel (should be rejected)"
else
    pass "export refuses airgap as a source channel (not publishable)"
fi

# ── import happy path ─────────────────────────────────────────────────────────
msg "2. import + client consume"
if "${PUBLISH}" import --repo-dir "${DST}" --bundle "${BUNDLE}" \
     --verify-key "${PUB}" --signing-key "${KEY}" >/dev/null 2>&1; then
    pass "import materialized the bundle into dst"
else
    fail "import of a valid bundle failed"
fi

if [ -f "${DST}/channels/airgap/current.json" ] && [ -f "${DST}/channels/airgap/current.json.sig" ]; then
    pass "airgap channel head written and signed"
else
    fail "airgap channel head missing or unsigned"
fi
if [ -f "${DST}/releases/air-001/metadata.json" ]; then
    pass "release materialized under dst releases/"
else
    fail "release not materialized in dst"
fi

ST="${WORK}/state"; RB="${WORK}/rollback"
if "${UPDATE}" verify --repo "file://${DST}" --channel airgap --allow-airgap-channel \
     --trusted-key "${PUB}" >/dev/null 2>&1; then
    pass "client verifies release off the airgap channel"
else
    fail "client verify off airgap failed"
fi
if "${UPDATE}" stage --repo "file://${DST}" --channel airgap --allow-airgap-channel \
     --trusted-key "${PUB}" --state-dir "${ST}" --rollback-dir "${RB}" >/dev/null 2>&1; then
    pass "client stages the airgap release"
else
    fail "client stage off airgap failed"
fi

# ── fail-closed opt-in gating ─────────────────────────────────────────────────
msg "3. fail-closed policy"
if "${UPDATE}" verify --repo "file://${DST}" --channel airgap \
     --trusted-key "${PUB}" >/dev/null 2>&1; then
    fail "airgap consumed WITHOUT --allow-airgap-channel (should fail closed)"
else
    pass "airgap refused without --allow-airgap-channel (fail closed)"
fi
if "${UPDATE}" verify --repo "file://${DST}" --channel bogus --allow-airgap-channel \
     --trusted-key "${PUB}" >/dev/null 2>&1; then
    fail "unknown channel 'bogus' accepted (closed set broken)"
else
    pass "unknown channel 'bogus' still rejected (closed set holds)"
fi

# ── tamper: corrupted artifact inside the bundle ─────────────────────────────
msg "4. tamper detection (all must fail closed)"
DST_T1="${WORK}/dst_t1"; TDIR="${WORK}/tam1"; mkdir -p "${TDIR}"
tar -C "${TDIR}" -xzf "${BUNDLE}" 2>/dev/null
printf 'EVIL' >> "${TDIR}/release/artifacts/aios.squashfs"
tar -C "${TDIR}" -czf "${WORK}/bad-artifact.tar.gz" . 2>/dev/null
if "${PUBLISH}" import --repo-dir "${DST_T1}" --bundle "${WORK}/bad-artifact.tar.gz" \
     --verify-key "${PUB}" --signing-key "${KEY}" >/dev/null 2>&1; then
    fail "import accepted a tampered artifact"
else
    pass "import rejects a tampered artifact"
fi
[ ! -e "${DST_T1}/releases" ] && pass "no dst state written on tampered-artifact import" \
                              || fail "dst repo state written despite tamper"

# ── tamper: corrupted bundle-manifest binding ────────────────────────────────
DST_T2="${WORK}/dst_t2"; TDIR2="${WORK}/tam2"; mkdir -p "${TDIR2}"
tar -C "${TDIR2}" -xzf "${BUNDLE}" 2>/dev/null
python3 -c 'import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["release_sha256sums_sha256"]="0"*64; json.dump(d,open(p,"w"))' \
    "${TDIR2}/airgap-bundle.json"
tar -C "${TDIR2}" -czf "${WORK}/bad-manifest.tar.gz" . 2>/dev/null
if "${PUBLISH}" import --repo-dir "${DST_T2}" --bundle "${WORK}/bad-manifest.tar.gz" \
     --verify-key "${PUB}" --signing-key "${KEY}" >/dev/null 2>&1; then
    fail "import accepted a corrupted bundle manifest"
else
    pass "import rejects a corrupted bundle manifest"
fi

# ── tamper: wrong verify key ─────────────────────────────────────────────────
DST_T3="${WORK}/dst_t3"
if "${PUBLISH}" import --repo-dir "${DST_T3}" --bundle "${BUNDLE}" \
     --verify-key "${PUB2}" --signing-key "${KEY}" >/dev/null 2>&1; then
    fail "import accepted a bundle under the WRONG verify key"
else
    pass "import rejects a bundle signed by an untrusted key"
fi

# ── evidence ──────────────────────────────────────────────────────────────────
msg "5. evidence"
if grep -q '"action":"export"' "${SRC}/evidence.jsonl" 2>/dev/null \
   && grep -q '"channel":"airgap"' "${SRC}/evidence.jsonl" 2>/dev/null; then
    pass "export emitted an airgap evidence record"
else
    fail "no export evidence record"
fi
if grep -q '"action":"import"' "${DST}/evidence.jsonl" 2>/dev/null; then
    pass "import emitted an evidence record"
else
    fail "no import evidence record"
fi

printf '\n%s[TEST]%s airgap channel: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" "${RED}" "${FAILED}" "${RESET}"
[ "${FAILED}" -eq 0 ] || exit 1
