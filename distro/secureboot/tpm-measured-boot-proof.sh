#!/usr/bin/env bash
#
# AI-OS.NET R13.4 — TPM measured-boot enforcement proof.
#
# Proves — against a REAL TPM 2.0 implementation (swtpm), not an offline sha256
# re-implementation — the two security properties AIOS relies on for measured
# boot, closing the gap the groundwork script (tpm-expected-pcrs.sh) honestly
# declares it cannot: that its PCR-extend math matches a real TPM, and that a
# secret bound to a measured-boot PCR state is released ONLY in that state.
#
#   1. EXTEND-MODEL EQUIVALENCE.
#      Reset a resettable PCR, extend it with the measurement chain
#      (sha256 of each staged boot artifact, in the fixed order) that
#      tpm-expected-pcrs.sh emits, read the PCR back, and assert it equals the
#      script's precomputed `pcr4_style_expected`. This validates the offline
#      groundwork against a real TPM 2.0 extend implementation.
#
#   2. PCR-BOUND SEAL/UNSEAL ENFORCEMENT (the LUKS-key-to-measured-boot property).
#      Seal a secret under a policy bound to that PCR state; prove tpm2_unseal
#      SUCCEEDS at the expected measured state and FAILS after the PCR is
#      extended with a different (tampered) measurement. A secret that unseals
#      regardless of PCR state would be a fake gate — this proves it does not.
#
# What this does NOT claim (honesty, see tpm-measurement-policy.md): it does not
# reconcile the EXACT firmware PCR-4 value with a live OVMF+vTPM boot and its TCG
# event log (Authenticode PE hashes) — that firmware-event-log reconciliation is
# the documented next step. This proves the TPM-side enforcement semantics that
# protect the sealed secret, deterministically and without root or KVM.
#
# Requires: swtpm, the swtpm TCTI (libtss2-tcti-swtpm), tpm2-tools, python3.
# No root, no KVM. Fails closed (INCONCLUSIVE) if a tool is missing; FAIL if the
# TPM does not enforce.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SB_DIR="${REPO_ROOT}/distro/secureboot"
EXPECTED_PCRS="${SB_DIR}/tpm-expected-pcrs.sh"

# Resettable application PCR (TPM 2.0): reset to zeros from locality 0 so the
# measurement chain starts from a known state, exactly like the offline model.
PCR_INDEX="${AIOS_TPM_PCR:-23}"
SECRET="AIOS-MEASURED-BOOT-SEALED-KEY-9f3c"
SRV_PORT="${AIOS_TPM_PORT:-42321}"
CTRL_PORT="$(( SRV_PORT + 1 ))"
WORK="${AIOS_TPM_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/aios-tpm-proof.XXXXXX")}"
SWTPM_PID=""

log()  { printf '[tpm-proof] %s\n' "$*"; }
die()  { printf '[tpm-proof] FATAL: %s\n' "$*" >&2; _cleanup; exit 3; }

_cleanup() {
  [ -n "${SWTPM_PID}" ] && kill "${SWTPM_PID}" 2>/dev/null
  [ -n "${AIOS_TPM_KEEP:-}" ] || rm -rf "${WORK}"
}
trap _cleanup EXIT

for t in swtpm tpm2_pcrreset tpm2_pcrextend tpm2_pcrread tpm2_startauthsession \
         tpm2_policypcr tpm2_createprimary tpm2_create tpm2_load tpm2_unseal \
         tpm2_flushcontext python3 sha256sum; do
  command -v "$t" >/dev/null 2>&1 || { printf '[tpm-proof] INCONCLUSIVE: missing tool %s\n' "$t"; exit 4; }
done
[ -f "${EXPECTED_PCRS}" ] || die "groundwork script missing: ${EXPECTED_PCRS}"

mkdir -p "${WORK}/state"
log "work dir: ${WORK}"

# ── start swtpm and wait until it answers ─────────────────────────────────────
swtpm socket --tpm2 --tpmstate dir="${WORK}/state" \
  --ctrl type=tcp,port="${CTRL_PORT}" --server type=tcp,port="${SRV_PORT}" \
  --flags startup-clear --daemon --pid file="${WORK}/swtpm.pid" 2>"${WORK}/swtpm.err" \
  || { printf '[tpm-proof] INCONCLUSIVE: swtpm failed to start\n'; cat "${WORK}/swtpm.err" >&2; exit 4; }
SWTPM_PID="$(cat "${WORK}/swtpm.pid" 2>/dev/null)"
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=${SRV_PORT}"

_ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if tpm2_pcrread "sha256:${PCR_INDEX}" >/dev/null 2>&1; then _ready=1; break; fi
  sleep 0.3
done
[ "${_ready}" -eq 1 ] || { printf '[tpm-proof] INCONCLUSIVE: swtpm/TCTI not responding\n'; cat "${WORK}/swtpm.err" >&2; exit 4; }
log "swtpm live; TCTI=${TPM2TOOLS_TCTI}"

# ── deterministic staging tree + offline expected PCRs ────────────────────────
STAGING="${WORK}/staging"
mkdir -p "${STAGING}/live" "${STAGING}/boot/grub"
printf 'AIOS-VMLINUZ-DETERMINISTIC'  > "${STAGING}/live/vmlinuz"
printf 'AIOS-INITRD-DETERMINISTIC'   > "${STAGING}/live/initrd.img"
printf 'AIOS-SQUASHFS-DETERMINISTIC' > "${STAGING}/live/aios.squashfs"
printf 'set default=0\nlinux /live/vmlinuz\n' > "${STAGING}/boot/grub/grub.cfg"

bash "${EXPECTED_PCRS}" --staging "${STAGING}" --out "${WORK}/expected.json" >/dev/null 2>&1 \
  || die "tpm-expected-pcrs.sh failed"

# Pull the precomputed final PCR and the ordered per-artifact event digests.
EXPECT_PCR="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["computed"]["pcr4_style_expected"])' "${WORK}/expected.json")"
mapfile -t EVENT_DIGESTS < <(python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
for e in d["computed"]["measurement_chain"]:
    print(e["event_digest_sha256"])
' "${WORK}/expected.json")
[ "${#EVENT_DIGESTS[@]}" -ge 1 ] || die "no measurement-chain digests parsed"

# ── property 1: real TPM extend reproduces the offline expected PCR ────────────
log "property 1: replay the measurement chain into PCR ${PCR_INDEX} on a real TPM"
tpm2_pcrreset "${PCR_INDEX}" 2>/dev/null || die "pcrreset ${PCR_INDEX} failed (is it resettable?)"
for d in "${EVENT_DIGESTS[@]}"; do
  tpm2_pcrextend "${PCR_INDEX}:sha256=${d}" 2>/dev/null || die "pcrextend failed for ${d}"
done
GOT_PCR="$(tpm2_pcrread "sha256:${PCR_INDEX}" 2>/dev/null | grep -oiE '0x[0-9A-Fa-f]{64}' | head -1 | sed 's/0x//' | tr 'A-F' 'a-f')"

# ── property 2: seal to this PCR state, prove release only in this state ───────
log "property 2: seal a secret to PCR ${PCR_INDEX} and test release under good vs tampered state"
# Build the authorization policy for the CURRENT (good) PCR state.
tpm2_startauthsession -S "${WORK}/trial.ctx" >/dev/null 2>&1 || die "trial session failed"
tpm2_policypcr -S "${WORK}/trial.ctx" -l "sha256:${PCR_INDEX}" -L "${WORK}/policy.dig" >/dev/null 2>&1 \
  || die "trial policypcr failed"
tpm2_flushcontext "${WORK}/trial.ctx" 2>/dev/null

tpm2_createprimary -C o -g sha256 -G ecc -c "${WORK}/prim.ctx" >/dev/null 2>&1 || die "createprimary failed"
printf '%s' "${SECRET}" | tpm2_create -C "${WORK}/prim.ctx" -L "${WORK}/policy.dig" \
  -i - -u "${WORK}/seal.pub" -r "${WORK}/seal.priv" >/dev/null 2>&1 || die "tpm2_create (seal) failed"
# Free leaked transient objects before loading (no resource manager in this path).
tpm2_flushcontext -t 2>/dev/null
tpm2_load -C "${WORK}/prim.ctx" -u "${WORK}/seal.pub" -r "${WORK}/seal.priv" \
  -c "${WORK}/seal.ctx" >/dev/null 2>&1 || die "tpm2_load (sealed object) failed"

# Good-state unseal: PCR still holds the sealed measured state → must succeed.
tpm2_flushcontext -t 2>/dev/null
tpm2_startauthsession --policy-session -S "${WORK}/s_good.ctx" >/dev/null 2>&1
tpm2_policypcr -S "${WORK}/s_good.ctx" -l "sha256:${PCR_INDEX}" >/dev/null 2>&1
GOOD_OUT="$(tpm2_unseal -c "${WORK}/seal.ctx" -p session:"${WORK}/s_good.ctx" 2>/dev/null)"; GOOD_RC=$?
tpm2_flushcontext "${WORK}/s_good.ctx" 2>/dev/null

# Tampered-state unseal: extend the PCR with a different measurement → must fail.
tpm2_pcrreset "${PCR_INDEX}" 2>/dev/null
TAMPER_DIGEST="$(printf 'TAMPERED-BOOT-COMPONENT' | sha256sum | cut -d' ' -f1)"
tpm2_pcrextend "${PCR_INDEX}:sha256=${TAMPER_DIGEST}" 2>/dev/null
tpm2_flushcontext -t 2>/dev/null
tpm2_startauthsession --policy-session -S "${WORK}/s_bad.ctx" >/dev/null 2>&1
tpm2_policypcr -S "${WORK}/s_bad.ctx" -l "sha256:${PCR_INDEX}" >/dev/null 2>&1
BAD_OUT="$(tpm2_unseal -c "${WORK}/seal.ctx" -p session:"${WORK}/s_bad.ctx" 2>&1)"; BAD_RC=$?
tpm2_flushcontext "${WORK}/s_bad.ctx" 2>/dev/null

# ── verdict ───────────────────────────────────────────────────────────────────
echo "===== TPM MEASURED-BOOT PROOF ====="
echo "PCR ${PCR_INDEX} chain (${#EVENT_DIGESTS[@]} artifacts):"
echo "  real TPM  = ${GOT_PCR}"
echo "  expected  = ${EXPECT_PCR}"
echo "seal/unseal:"
echo "  good-state  rc=${GOOD_RC} released='${GOOD_OUT}'"
echo "  tampered    rc=${BAD_RC} (must be nonzero)"

p1=0; [ -n "${GOT_PCR}" ] && [ "${GOT_PCR}" = "${EXPECT_PCR}" ] && p1=1
p2=0; [ "${GOOD_RC}" -eq 0 ] && [ "${GOOD_OUT}" = "${SECRET}" ] && [ "${BAD_RC}" -ne 0 ] && p2=1

RC=0
if [ "${p1}" -eq 1 ] && [ "${p2}" -eq 1 ]; then
  echo "TPM PROOF: PASS — real TPM extend matches the groundwork model AND the sealed"
  echo "           secret is released only under the expected measured-boot state."
else
  [ "${p1}" -eq 1 ] || echo "  property 1 FAILED: real TPM PCR != offline expected"
  [ "${p2}" -eq 1 ] || echo "  property 2 FAILED: seal/unseal did not enforce the PCR policy"
  echo "TPM PROOF: FAIL"
  RC=5
fi
echo "===== END TPM MEASURED-BOOT PROOF ====="
exit "${RC}"
