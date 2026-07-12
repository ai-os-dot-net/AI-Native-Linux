#!/usr/bin/env bash
#
# AI-OS.NET R13.4 — Secure Boot boot-artifact signer.
#
# Signs the ISO's staged boot artifacts (bootloader config, kernel, initramfs,
# rootfs payload, and any *.efi binaries) with the Secure Boot `db` key. It emits
# detached signatures whose file names match EXACTLY what build-aios-iso.sh
# consumes via AIOS_SIGNATURE_SOURCE_DIR, so the output directory can be handed
# straight to `--signature-source-dir`.
#
# Naming contract (verified against distro/build/build-aios-iso.sh):
#   * build-aios-iso.sh stages signatures with:
#         cp -a "${AIOS_SIGNATURE_SOURCE_DIR}/." "${AIOS_SIGNATURE_DIR}/"   (line 1697)
#     into ${ISO_DIR}/aios/signatures, then hard-requires (lines 2101-2104):
#         require_boot_signature "boot-grub-grub.cfg.sig"
#         require_boot_signature "live-vmlinuz.sig"
#         require_boot_signature "live-initrd.img.sig"
#         require_boot_signature "live-aios.squashfs.sig"
#   * The boot-chain.json signature_hooks (lines 1848-1857) map each artifact to
#         aios/signatures/<relpath-with-slashes-as-dashes>.sig
#     e.g. boot/grub/grub.cfg -> boot-grub-grub.cfg.sig, live/vmlinuz ->
#     live-vmlinuz.sig. This script reproduces that exact transform.
#
# sbsign vs. fallback (R13.4 fail-closed contract):
#   * When `sbsign` is present, PE/COFF binaries (vmlinuz EFI stub, *.efi) are
#     signed with `sbsign --detached`, producing UEFI-consumable detached sigs.
#     Non-PE artifacts (initrd, squashfs, grub.cfg) are not PE-signable by UEFI;
#     they get openssl detached sigs (integrity/measured-boot use, CI-verifiable).
#   * When `sbsign` is ABSENT the script FAILS CLOSED, unless --detached-fallback
#     is passed, in which case ALL artifacts get openssl detached signatures.
#     Those are explicitly NOT UEFI-consumable — CI-verification-only — and the
#     signature manifest records that honestly.
#
# Usage:
#   sign-boot-artifacts.sh --staging DIR --db-key FILE --db-cert FILE --out DIR \
#       [--detached-fallback] [--epoch SECONDS]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

STAGING_DIR=""
DB_KEY=""
DB_CERT=""
OUT_DIR=""
DETACHED_FALLBACK=0
EPOCH_ARG=""

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[sign-boot] %s\n' "$*"; }
warn() { printf '[sign-boot] WARN: %s\n' "$*" >&2; }

usage() {
    cat <<'EOF'
sign-boot-artifacts.sh — sign staged boot artifacts for Secure Boot.

Options:
  --staging DIR        Directory holding staged boot files (required).
  --db-key FILE        Secure Boot db private key (required).
  --db-cert FILE       Secure Boot db certificate PEM (required).
  --out DIR            Output dir for detached sigs + manifest (required).
  --detached-fallback  Allow openssl detached sigs when sbsign is absent.
  --epoch SECONDS      Epoch for the manifest (default: git HEAD commit time).
  -h, --help           Show this help.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --staging) STAGING_DIR="${2:-}"; shift 2 ;;
        --db-key)  DB_KEY="${2:-}"; shift 2 ;;
        --db-cert) DB_CERT="${2:-}"; shift 2 ;;
        --out)     OUT_DIR="${2:-}"; shift 2 ;;
        --detached-fallback) DETACHED_FALLBACK=1; shift ;;
        --epoch)   EPOCH_ARG="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown argument: $1 (see --help)" ;;
    esac
done

[ -n "${STAGING_DIR}" ] || die "--staging DIR is required"
[ -n "${DB_KEY}" ]      || die "--db-key FILE is required"
[ -n "${DB_CERT}" ]     || die "--db-cert FILE is required"
[ -n "${OUT_DIR}" ]     || die "--out DIR is required"
[ -d "${STAGING_DIR}" ] || die "staging dir not found: ${STAGING_DIR}"
[ -f "${DB_KEY}" ]      || die "db key not found: ${DB_KEY}"
[ -f "${DB_CERT}" ]     || die "db cert not found: ${DB_CERT}"
command -v openssl >/dev/null 2>&1 || die "openssl not found on PATH"

# ── sbsign availability + fail-closed gate ────────────────────────────────────
HAVE_SBSIGN=0
if command -v sbsign >/dev/null 2>&1; then
    HAVE_SBSIGN=1
elif [ "${DETACHED_FALLBACK}" -ne 1 ]; then
    die "sbsign not found and --detached-fallback not set: refusing to produce non-UEFI signatures silently (fail closed)"
fi

# ── Epoch for the manifest (no wall-clock) ────────────────────────────────────
if [ -n "${EPOCH_ARG}" ]; then
    case "${EPOCH_ARG}" in
        ''|*[!0-9]*) die "--epoch must be a positive integer" ;;
    esac
    EPOCH="${EPOCH_ARG}"
else
    EPOCH="$(git -C "${REPO_ROOT}" show -s --format=%ct HEAD 2>/dev/null || printf '0')"
fi
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}"

# Public key extracted once for openssl detached verification bookkeeping.
DB_PUBKEY="${OUT_DIR}/.db-pubkey.pem"
openssl x509 -in "${DB_CERT}" -pubkey -noout > "${DB_PUBKEY}" 2>/dev/null \
    || die "failed to extract public key from ${DB_CERT}"

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

# Map a staging-relative path to the .sig name build-aios-iso.sh expects:
# replace every '/' with '-' and append '.sig'.
sig_name_for() { printf '%s.sig' "${1//\//-}"; }

# Detect PE/COFF (EFI-signable) files by the 'MZ' magic.
is_pe_binary() {
    local f="$1"
    [ "$(head -c2 "${f}" 2>/dev/null)" = "MZ" ]
}

# Candidate boot-chain artifacts (staging-relative). Only those present are
# signed; missing ones are skipped (a live/ build may not stage every file).
CANDIDATES=(
    "boot/grub/grub.cfg"
    "live/vmlinuz"
    "live/initrd.img"
    "live/aios.squashfs"
)
# Plus any EFI binaries anywhere under the staging tree (shim, grubx64, etc.).
while IFS= read -r efi; do
    CANDIDATES+=( "${efi#"${STAGING_DIR}"/}" )
done < <(find "${STAGING_DIR}" -type f -name '*.efi' 2>/dev/null | sort)

MANIFEST="${OUT_DIR}/sb-signature-manifest.json"
ENTRIES=""
SIGNED_COUNT=0

append_entry() {
    [ -z "${ENTRIES}" ] || ENTRIES="${ENTRIES},"
    ENTRIES="${ENTRIES}
    {
      \"artifact\": \"$1\",
      \"signature\": \"$2\",
      \"method\": \"$3\",
      \"uefi_consumable\": $4,
      \"artifact_sha256\": \"$5\",
      \"signature_sha256\": \"$6\"
    }"
}

for rel in "${CANDIDATES[@]}"; do
    src="${STAGING_DIR}/${rel}"
    [ -f "${src}" ] || continue

    signame="$(sig_name_for "${rel}")"
    sig="${OUT_DIR}/${signame}"
    method=""
    uefi="false"

    if [ "${HAVE_SBSIGN}" -eq 1 ] && is_pe_binary "${src}"; then
        sbsign --key "${DB_KEY}" --cert "${DB_CERT}" \
            --detached --output "${sig}" "${src}" >/dev/null 2>&1 \
            || die "sbsign failed on ${rel}"
        method="sbsign-detached"
        uefi="true"
    else
        if [ "${HAVE_SBSIGN}" -eq 1 ]; then
            warn "${rel} is not a PE binary; using openssl detached sig (not UEFI-consumable)"
        fi
        openssl dgst -sha256 -sign "${DB_KEY}" -out "${sig}" "${src}" \
            || die "openssl detached sign failed on ${rel}"
        method="openssl-detached"
        uefi="false"
    fi

    append_entry "${rel}" "${signame}" "${method}" "${uefi}" \
        "$(sha256_of "${src}")" "$(sha256_of "${sig}")"
    SIGNED_COUNT=$(( SIGNED_COUNT + 1 ))
    info "signed ${rel} -> ${signame} (${method})"
done

[ "${SIGNED_COUNT}" -gt 0 ] || die "no boot artifacts found to sign under ${STAGING_DIR}"

{
    cat <<EOF
{
  "schema": "aios.boot_signature_manifest.v1",
  "revision": 13,
  "created_epoch": ${EPOCH},
  "source_revision": "${GIT_REVISION}",
  "signer_cert_sha256": "$(sha256_of "${DB_CERT}")",
  "sbsign_available": $( [ "${HAVE_SBSIGN}" -eq 1 ] && echo true || echo false ),
  "detached_fallback": $( [ "${DETACHED_FALLBACK}" -eq 1 ] && echo true || echo false ),
  "consumes_via": "build-aios-iso.sh --signature-source-dir (staged into /aios/signatures)",
  "note": "openssl-detached signatures are NOT UEFI-consumable; they exist for CI verification and measured-boot integrity checks only.",
  "signatures": [${ENTRIES}
  ]
}
EOF
} > "${MANIFEST}"
chmod 644 "${MANIFEST}"

rm -f "${DB_PUBKEY}"
info "signature manifest written: ${MANIFEST}"
info "signed ${SIGNED_COUNT} boot artifact(s) into ${OUT_DIR}"
