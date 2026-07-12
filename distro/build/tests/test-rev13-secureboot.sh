#!/usr/bin/env bash
#
# AI-OS.NET R13.4 Secure Boot + TPM measured-boot groundwork gate test.
#
# Proves the distro/secureboot/ tooling produces real, verifiable artifacts:
#   1. generate-sb-keys.sh builds a PK/KEK/db hierarchy (keys, PEM, DER, manifest)
#      and REFUSES to overwrite without --force.
#   2. sign-boot-artifacts.sh signs a fake staging tree with the EXACT .sig names
#      build-aios-iso.sh's require_boot_signature() consumes.
#   3. Each detached signature verifies with openssl, and tampering the signed
#      artifact makes verification FAIL (anti-fake).
#   4. The emitted signature-manifest layout matches the build script's contract.
#   5. tpm-expected-pcrs.sh emits schema-valid JSON and is deterministic
#      (two runs are byte-identical).
#
# Run: TMPDIR=$HOME/.tmp-aios bash distro/build/tests/test-rev13-secureboot.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${BUILD_DIR}/../.." && pwd)"

SB_DIR="${REPO_ROOT}/distro/secureboot"
GEN_KEYS="${SB_DIR}/generate-sb-keys.sh"
SIGN_BOOT="${SB_DIR}/sign-boot-artifacts.sh"
TPM_PCRS="${SB_DIR}/tpm-expected-pcrs.sh"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
BLUE=$'\033[1;34m'
RESET=$'\033[0m'

PASSED=0
FAILED=0

msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

# Deterministic epoch so the run never touches the wall clock.
EPOCH=1700000000

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-secureboot.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

KEYS_DIR="${WORK}/keys"
STAGING="${WORK}/staging"
SIGS_OUT="${WORK}/sigs"
PCR_OUT="${WORK}/pcr"

# ── 1. Key hierarchy generation ───────────────────────────────────────────────
msg "1. Secure Boot key hierarchy generation"

if bash "${GEN_KEYS}" --out "${KEYS_DIR}" --epoch "${EPOCH}" >/dev/null 2>&1; then
    pass "generate-sb-keys.sh succeeded"
else
    fail "generate-sb-keys.sh failed"
fi

for f in PK.key PK.crt PK.der KEK.key KEK.crt KEK.der db.key db.crt db.der \
         sb-keys-manifest.json; do
    if [ -f "${KEYS_DIR}/${f}" ]; then
        pass "hierarchy artifact present: ${f}"
    else
        fail "missing hierarchy artifact: ${f}"
    fi
done

# Manifest is valid JSON with the expected schema + three roles.
if python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d["schema"] == "aios.secureboot_keys.v1", d.get("schema")
roles = {e["role"] for e in d["hierarchy"]}
assert roles == {"platform-key", "key-exchange-key", "signature-db-leaf"}, roles
assert d["created_epoch"] == '"${EPOCH}"', d["created_epoch"]
assert d["uefi_enrollment"]["consumable"] is False
' "${KEYS_DIR}/sb-keys-manifest.json" 2>/dev/null; then
    pass "key manifest schema + roles + epoch valid"
else
    fail "key manifest schema/roles/epoch invalid"
fi

# db cert must carry the codeSigning EKU (it signs boot binaries).
if openssl x509 -in "${KEYS_DIR}/db.crt" -noout -ext extendedKeyUsage 2>/dev/null \
    | grep -q "Code Signing"; then
    pass "db cert has codeSigning extendedKeyUsage"
else
    fail "db cert missing codeSigning extendedKeyUsage"
fi

# ── 2. Refuse-overwrite contract ──────────────────────────────────────────────
msg "2. Refuse-overwrite protection"

if bash "${GEN_KEYS}" --out "${KEYS_DIR}" --epoch "${EPOCH}" >/dev/null 2>&1; then
    fail "second run without --force should have refused but succeeded"
else
    pass "second run without --force refused (fail closed)"
fi

if bash "${GEN_KEYS}" --out "${KEYS_DIR}" --epoch "${EPOCH}" --force >/dev/null 2>&1; then
    pass "second run with --force overwrote hierarchy"
else
    fail "run with --force should have succeeded"
fi

# ── 3. Sign a fake staging tree ───────────────────────────────────────────────
msg "3. Boot-artifact signing"

mkdir -p "${STAGING}/live" "${STAGING}/boot/grub"
printf 'FAKE-VMLINUZ-%s' "${EPOCH}" > "${STAGING}/live/vmlinuz"
printf 'FAKE-INITRD-%s'  "${EPOCH}" > "${STAGING}/live/initrd.img"
printf 'FAKE-SQUASHFS-%s' "${EPOCH}" > "${STAGING}/live/aios.squashfs"
printf 'set default=0\nlinux /live/vmlinuz\n' > "${STAGING}/boot/grub/grub.cfg"

# This host has no sbsign; use the documented CI-only detached fallback.
FALLBACK_FLAG=""
if ! command -v sbsign >/dev/null 2>&1; then
    FALLBACK_FLAG="--detached-fallback"
fi

if bash "${SIGN_BOOT}" --staging "${STAGING}" \
        --db-key "${KEYS_DIR}/db.key" --db-cert "${KEYS_DIR}/db.crt" \
        --out "${SIGS_OUT}" --epoch "${EPOCH}" ${FALLBACK_FLAG} >/dev/null 2>&1; then
    pass "sign-boot-artifacts.sh succeeded"
else
    fail "sign-boot-artifacts.sh failed"
fi

# Fail-closed check: without --detached-fallback and no sbsign, it must refuse.
if ! command -v sbsign >/dev/null 2>&1; then
    if bash "${SIGN_BOOT}" --staging "${STAGING}" \
            --db-key "${KEYS_DIR}/db.key" --db-cert "${KEYS_DIR}/db.crt" \
            --out "${WORK}/sigs-noforce" --epoch "${EPOCH}" >/dev/null 2>&1; then
        fail "signing without --detached-fallback should fail closed (no sbsign)"
    else
        pass "signing without --detached-fallback fails closed (no sbsign)"
    fi
fi

# ── 4. Signature names match build-aios-iso.sh's require_boot_signature() ─────
msg "4. Signature-manifest layout matches build-aios-iso.sh"

# Extract the exact names build-aios-iso.sh hard-requires for boot artifacts.
REQUIRED_BOOT_SIGS="$(grep -oE 'require_boot_signature "[a-zA-Z0-9._-]+\.sig"' \
    "${BUILD_SCRIPT}" | sed -E 's/.*"([^"]+)".*/\1/' | sort -u)"

if [ -z "${REQUIRED_BOOT_SIGS}" ]; then
    fail "could not parse require_boot_signature names from build-aios-iso.sh"
fi

# Every boot-file signature we produced (from staging paths) must be a name the
# build script knows about, AND the four boot-chain names must be produced.
for expected in boot-grub-grub.cfg.sig live-vmlinuz.sig \
                live-initrd.img.sig live-aios.squashfs.sig; do
    if [ -f "${SIGS_OUT}/${expected}" ]; then
        pass "produced signature: ${expected}"
    else
        fail "missing expected signature: ${expected}"
    fi
    if printf '%s\n' "${REQUIRED_BOOT_SIGS}" | grep -qx "${expected}"; then
        pass "build-aios-iso.sh requires ${expected} (contract match)"
    else
        fail "build-aios-iso.sh does not require ${expected} (contract drift)"
    fi
done

# Signature manifest is schema-valid and lists all four boot artifacts.
if python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d["schema"] == "aios.boot_signature_manifest.v1", d.get("schema")
sigs = {e["signature"] for e in d["signatures"]}
need = {"boot-grub-grub.cfg.sig", "live-vmlinuz.sig",
        "live-initrd.img.sig", "live-aios.squashfs.sig"}
assert need <= sigs, sigs
# Fallback openssl sigs must honestly declare non-UEFI-consumable.
for e in d["signatures"]:
    if e["method"] == "openssl-detached":
        assert e["uefi_consumable"] is False, e
' "${SIGS_OUT}/sb-signature-manifest.json" 2>/dev/null; then
    pass "signature manifest schema + coverage + honesty valid"
else
    fail "signature manifest invalid"
fi

# ── 5. openssl verification + tamper detection ────────────────────────────────
msg "5. Signature verification and tamper detection"

openssl x509 -in "${KEYS_DIR}/db.crt" -pubkey -noout > "${WORK}/db-pub.pem" 2>/dev/null

verify_sig() {
    _art="$1"; _sig="$2"
    openssl dgst -sha256 -verify "${WORK}/db-pub.pem" \
        -signature "${_sig}" "${_art}" >/dev/null 2>&1
}

if verify_sig "${STAGING}/live/vmlinuz" "${SIGS_OUT}/live-vmlinuz.sig"; then
    pass "openssl verifies live-vmlinuz.sig"
else
    fail "openssl failed to verify live-vmlinuz.sig"
fi

if verify_sig "${STAGING}/boot/grub/grub.cfg" "${SIGS_OUT}/boot-grub-grub.cfg.sig"; then
    pass "openssl verifies boot-grub-grub.cfg.sig"
else
    fail "openssl failed to verify boot-grub-grub.cfg.sig"
fi

# Tamper: flip the signed artifact and expect verification to FAIL.
cp "${STAGING}/live/vmlinuz" "${WORK}/vmlinuz.tampered"
printf 'X' >> "${WORK}/vmlinuz.tampered"
if verify_sig "${WORK}/vmlinuz.tampered" "${SIGS_OUT}/live-vmlinuz.sig"; then
    fail "tampered artifact still verified (anti-fake broken)"
else
    pass "tampered artifact fails verification (anti-fake holds)"
fi

# ── 6. TPM expected-PCR computation: schema + determinism ─────────────────────
msg "6. TPM expected-PCR computation"

if bash "${TPM_PCRS}" --staging "${STAGING}" --out "${PCR_OUT}/pcr-a.json" >/dev/null 2>&1; then
    pass "tpm-expected-pcrs.sh run 1 succeeded"
else
    fail "tpm-expected-pcrs.sh run 1 failed"
fi

if bash "${TPM_PCRS}" --staging "${STAGING}" --out "${PCR_OUT}/pcr-b.json" >/dev/null 2>&1; then
    pass "tpm-expected-pcrs.sh run 2 succeeded"
else
    fail "tpm-expected-pcrs.sh run 2 failed"
fi

if python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d["schema"] == "aios.tpm_expected_pcrs.v1", d.get("schema")
assert d["hash_alg"] == "sha256"
c = d["computed"]
val = c["pcr4_style_expected"]
assert isinstance(val, str) and len(val) == 64, val
chain = c["measurement_chain"]
assert len(chain) == 4, len(chain)
assert chain[-1]["pcr_after_extend"] == val
for k in ("pcr0", "pcr2", "pcr7"):
    assert k in d["requires_hardware_or_swtpm"], k
' "${PCR_OUT}/pcr-a.json" 2>/dev/null; then
    pass "expected-PCR JSON schema + PCR-4 chain valid"
else
    fail "expected-PCR JSON schema invalid"
fi

if diff -q "${PCR_OUT}/pcr-a.json" "${PCR_OUT}/pcr-b.json" >/dev/null 2>&1; then
    pass "expected-PCR output is deterministic (two runs identical)"
else
    fail "expected-PCR output is non-deterministic"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n%s[TEST]%s Secure Boot gate: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" \
    "${RED}" "${FAILED}" "${RESET}"

[ "${FAILED}" -eq 0 ] || exit 1
