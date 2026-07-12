#!/usr/bin/env bash
#
# AI-OS.NET R13.4 — Expected TPM PCR precomputation (measured-boot groundwork).
#
# Computes a DETERMINISTIC, PCR-4-style expected measurement chain over the
# staged boot artifacts and emits it as machine-readable JSON for a future
# attestation verifier to compare against a live TPM quote.
#
# What this DOES compute (offline, no hardware):
#   * A sha256 measurement chain in the TPM extend model:
#         PCR_0    = 32 zero bytes
#         PCR_n    = sha256( PCR_{n-1} || sha256(artifact_n) )
#     folded over the boot artifacts in a fixed, documented order. This is a
#     "PCR-4-style" value: it models how PCR 4 (boot manager + loaded images)
#     grows as the bootloader and kernel are measured.
#
# What this does NOT and CANNOT compute here (honesty, see tpm-measurement-policy.md):
#   * The EXACT firmware measurement. Real UEFI extends PCR 4 with the
#     Authenticode PE hash of each loaded image inside TCG event-log events, not
#     a plain sha256 of the on-disk file. Matching the real quote requires a
#     firmware run (QEMU + swtpm, or physical TPM) and the TCG event log.
#   * PCR 0 / 2 / 7 values, which depend on firmware code, option ROMs, and the
#     live Secure Boot variable state — none of which exist at build time.
#
# Determinism: output depends only on the artifact bytes and the fixed order.
# No wall-clock, no randomness -> two runs on the same inputs are byte-identical.
#
# Usage:
#   tpm-expected-pcrs.sh --staging DIR --out FILE
#
set -euo pipefail

STAGING_DIR=""
OUT_FILE=""

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[tpm-pcr] %s\n' "$*"; }

usage() {
    cat <<'EOF'
tpm-expected-pcrs.sh — precompute expected PCR-4-style boot measurements.

Options:
  --staging DIR   Directory holding staged boot files (required).
  --out FILE      Output JSON path (required).
  -h, --help      Show this help.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --staging) STAGING_DIR="${2:-}"; shift 2 ;;
        --out)     OUT_FILE="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown argument: $1 (see --help)" ;;
    esac
done

[ -n "${STAGING_DIR}" ] || die "--staging DIR is required"
[ -n "${OUT_FILE}" ]    || die "--out FILE is required"
[ -d "${STAGING_DIR}" ] || die "staging dir not found: ${STAGING_DIR}"
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"

# Fixed measurement order for the PCR-4-style chain. Mirrors the real boot
# sequence: boot manager config -> bootloader-launched kernel -> initramfs ->
# rootfs payload. Only present files are measured; order is preserved.
ORDER=(
    "boot/grub/grub.cfg"
    "live/vmlinuz"
    "live/initrd.img"
    "live/aios.squashfs"
)

MEASURED=()
for rel in "${ORDER[@]}"; do
    [ -f "${STAGING_DIR}/${rel}" ] && MEASURED+=( "${rel}" )
done
[ "${#MEASURED[@]}" -gt 0 ] || die "no measurable boot artifacts under ${STAGING_DIR}"

mkdir -p "$(dirname "${OUT_FILE}")"

# The whole computation + JSON emission runs in python for exact byte control
# over the TPM extend folding. Deterministic by construction.
STAGING_DIR="${STAGING_DIR}" OUT_FILE="${OUT_FILE}" \
    python3 - "${MEASURED[@]}" <<'PY'
import hashlib
import json
import os
import sys

staging = os.environ["STAGING_DIR"]
out = os.environ["OUT_FILE"]
measured = sys.argv[1:]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.digest()

# TPM PCR extend model in the sha256 bank.
pcr = b"\x00" * 32
chain = []
for rel in measured:
    digest = sha256_file(os.path.join(staging, rel))
    pcr = hashlib.sha256(pcr + digest).digest()
    chain.append({
        "artifact": rel,
        "event_digest_sha256": digest.hex(),
        "pcr_after_extend": pcr.hex(),
    })

doc = {
    "schema": "aios.tpm_expected_pcrs.v1",
    "revision": 13,
    "hash_alg": "sha256",
    "model": "pcr-extend: PCR_n = sha256(PCR_{n-1} || sha256(artifact_n))",
    "computed": {
        # PCR 4 is the one we can model offline from staged boot images.
        "pcr4_style_expected": chain[-1]["pcr_after_extend"],
        "measurement_chain": chain,
    },
    "requires_hardware_or_swtpm": {
        "pcr0": "firmware/platform code + config (SRTM) — not computable offline",
        "pcr2": "option ROM / loaded UEFI driver code — not computable offline",
        "pcr7": "Secure Boot variable state (PK/KEK/db/dbx) — not computable offline",
        "note": "Real PCR 4 uses Authenticode PE hashes inside TCG event-log "
                "events; the value above is a sha256-of-file stand-in. A live "
                "QEMU+swtpm or physical-TPM run plus the TCG event log is "
                "required to reconcile with a real quote.",
    },
}

with open(out, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

info "expected PCR JSON written: ${OUT_FILE}"
