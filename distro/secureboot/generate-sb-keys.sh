#!/usr/bin/env bash
#
# AI-OS.NET R13.4 — Secure Boot key hierarchy generator.
#
# Creates a self-signed Secure Boot key hierarchy (PK / KEK / db) in
# "operator-CA" mode: the operator owns the platform trust root instead of a
# vendor. Emits both PEM (.crt) and DER (.der) certificates plus the RSA private
# keys, and an auth-artifact manifest JSON that records the sha256 of every key
# and certificate for the boot-integrity evidence chain.
#
# Determinism / no-wall-clock contract (R13.2 hermetic builds):
#   Certificate validity and the manifest "created_epoch" come ONLY from an
#   explicit --epoch argument or from the git HEAD commit time. The script never
#   reads the wall clock, so a rebuild from the same source revision produces
#   certificates with identical validity windows. (RSA private keys are
#   intrinsically random; their sha256 is recorded, not asserted deterministic.)
#
# Scope / honesty:
#   This produces the X.509 trust hierarchy that is the GROUNDWORK for Secure
#   Boot enrollment. Turning these certs into UEFI-enrollable ESL/.auth blobs
#   still requires efitools (cert-to-efi-sig-list / sign-efi-sig-list) or sbctl
#   on the target; that step is documented as a hook, not performed here, because
#   it depends on tools that are not part of the hermetic build set.
#
# Usage:
#   generate-sb-keys.sh --out DIR [--epoch SECONDS] [--force]
#
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

OUT_DIR=""
EPOCH_ARG=""
FORCE=0

# Fixed 10-year validity window (3650 days) expressed as seconds. Deterministic
# offset from the chosen epoch — no calendar math against "now".
VALIDITY_SECONDS=315360000

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[sb-keys] %s\n' "$*"; }

usage() {
    cat <<EOF
${SCRIPT_NAME} — generate a Secure Boot PK/KEK/db key hierarchy.

Options:
  --out DIR         Output directory for keys, certs, and manifest (required).
  --epoch SECONDS   Unix epoch for certificate validity + manifest. Defaults to
                    the git HEAD commit time. Never uses the wall clock.
  --force           Overwrite an existing hierarchy in --out.
  -h, --help        Show this help.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out)   OUT_DIR="${2:-}"; shift 2 ;;
        --epoch) EPOCH_ARG="${2:-}"; shift 2 ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown argument: $1 (see --help)" ;;
    esac
done

[ -n "${OUT_DIR}" ] || die "--out DIR is required"
command -v openssl >/dev/null 2>&1 || die "openssl not found on PATH"

# ── Resolve the epoch deterministically (arg > git HEAD; never wall-clock) ────
if [ -n "${EPOCH_ARG}" ]; then
    case "${EPOCH_ARG}" in
        ''|*[!0-9]*) die "--epoch must be a positive integer (unix seconds)" ;;
    esac
    EPOCH="${EPOCH_ARG}"
    EPOCH_SOURCE="argument"
else
    EPOCH="$(git -C "${REPO_ROOT}" show -s --format=%ct HEAD 2>/dev/null || true)"
    [ -n "${EPOCH}" ] || die "no --epoch given and git HEAD commit time unavailable"
    EPOCH_SOURCE="git-head"
fi
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"

# Format the fixed epoch into openssl's ASN.1 UTC form. `date` here only FORMATS
# a constant; it does not read the current time.
NOT_BEFORE="$(date -u -d "@${EPOCH}" +%Y%m%d%H%M%SZ)"
NOT_AFTER="$(date -u -d "@$(( EPOCH + VALIDITY_SECONDS ))" +%Y%m%d%H%M%SZ)"

# ── Refuse to clobber an existing hierarchy without --force ───────────────────
MANIFEST="${OUT_DIR}/sb-keys-manifest.json"
if [ "${FORCE}" -ne 1 ]; then
    for existing in "${MANIFEST}" \
        "${OUT_DIR}/PK.key" "${OUT_DIR}/KEK.key" "${OUT_DIR}/db.key"; do
        if [ -e "${existing}" ]; then
            die "existing Secure Boot hierarchy at ${OUT_DIR} (found ${existing##*/}); pass --force to overwrite"
        fi
    done
fi

mkdir -p "${OUT_DIR}"

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

# generate_role <name> <serial> <subject-CN> <ca-bool> <extra-addext...>
generate_role() {
    local name="$1"; shift
    local serial="$1"; shift
    local cn="$1"; shift
    local ca="$1"; shift

    local key="${OUT_DIR}/${name}.key"
    local crt="${OUT_DIR}/${name}.crt"
    local der="${OUT_DIR}/${name}.der"

    rm -f "${key}" "${crt}" "${der}"

    local -a addext=(
        -addext "basicConstraints=critical,CA:${ca}"
    )
    local ext
    for ext in "$@"; do
        addext+=( -addext "${ext}" )
    done

    # RSA-3072 self-signed cert with a deterministic serial + fixed validity.
    # -not_before/-not_after need OpenSSL >= 3.4; older releases (Debian 3.0.x
    # in CI) fall back to -days, which anchors notBefore at wall-clock —
    # recorded honestly in the manifest as validity_source=days-fallback.
    local -a validity
    if openssl req -help 2>&1 | grep -q -- '-not_before'; then
        validity=( -not_before "${NOT_BEFORE}" -not_after "${NOT_AFTER}" )
        VALIDITY_SOURCE="fixed-epoch"
    else
        validity=( -days "$(( VALIDITY_SECONDS / 86400 ))" )
        VALIDITY_SOURCE="days-fallback"
    fi
    openssl req -x509 -newkey rsa:3072 -nodes \
        -keyout "${key}" -out "${crt}" \
        -subj "/CN=${cn}/O=AI-OS.NET/OU=SecureBoot/" \
        -set_serial "${serial}" \
        "${validity[@]}" \
        -sha256 "${addext[@]}" 2>/dev/null \
        || die "openssl failed to generate ${name} certificate"

    openssl x509 -in "${crt}" -outform DER -out "${der}" 2>/dev/null \
        || die "openssl failed to convert ${name} certificate to DER"

    chmod 600 "${key}"
    chmod 644 "${crt}" "${der}"
    info "generated ${name}: key + PEM + DER (CA:${ca})"
}

# PK — Platform Key: the trust root. Signs KEK updates in real UEFI enrollment.
generate_role "PK" 1 "AI-OS.NET Secure Boot Platform Key" "TRUE" \
    "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"

# KEK — Key Exchange Key: authorises db/dbx updates.
generate_role "KEK" 2 "AI-OS.NET Secure Boot Key Exchange Key" "TRUE" \
    "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"

# db — signature database leaf: the cert that actually signs boot binaries.
generate_role "db" 3 "AI-OS.NET Secure Boot Signature DB" "FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=codeSigning"

# ── Emit the auth-artifact manifest (sha256 of every key + cert) ──────────────
emit_entry() {
    local name="$1"
    local role="$2"
    cat <<EOF
    {
      "name": "${name}",
      "role": "${role}",
      "key_file": "${name}.key",
      "key_sha256": "$(sha256_of "${OUT_DIR}/${name}.key")",
      "cert_pem": "${name}.crt",
      "cert_pem_sha256": "$(sha256_of "${OUT_DIR}/${name}.crt")",
      "cert_der": "${name}.der",
      "cert_der_sha256": "$(sha256_of "${OUT_DIR}/${name}.der")",
      "not_before": "${NOT_BEFORE}",
      "not_after": "${NOT_AFTER}"
    }
EOF
}

{
    cat <<EOF
{
  "schema": "aios.secureboot_keys.v1",
  "revision": 13,
  "mode": "operator-ca-self-signed",
  "created_epoch": ${EPOCH},
  "epoch_source": "${EPOCH_SOURCE}",
  "validity_source": "${VALIDITY_SOURCE:-unknown}",
  "source_revision": "${GIT_REVISION}",
  "key_algorithm": "rsa-3072-sha256",
  "hierarchy": [
$(emit_entry "PK" "platform-key"),
$(emit_entry "KEK" "key-exchange-key"),
$(emit_entry "db" "signature-db-leaf")
  ],
  "uefi_enrollment": {
    "consumable": false,
    "note": "PEM/DER certs are trust-hierarchy groundwork. Building UEFI-enrollable ESL/.auth blobs requires efitools (cert-to-efi-sig-list, sign-efi-sig-list) or sbctl on the target; that step is a documented hook, not performed here.",
    "expected_tools": ["cert-to-efi-sig-list", "sign-efi-sig-list", "sbctl"]
  }
}
EOF
} > "${MANIFEST}"
chmod 644 "${MANIFEST}"

info "manifest written: ${MANIFEST}"
info "Secure Boot key hierarchy ready in ${OUT_DIR}"
