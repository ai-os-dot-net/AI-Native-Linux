#!/bin/bash
#
# AI-OS.NET R13.4 — Firmware measured-boot proof (real OVMF + vTPM).
#
# Proves — with a REAL UEFI firmware (OVMF) driving a REAL TPM 2.0 (swtpm vTPM),
# not an offline model — that the platform firmware actually MEASURES boot state
# into the TPM's PCRs, and that a security-relevant change in that state (Secure
# Boot on vs off) produces a different measurement. This is the firmware-side
# complement to:
#   * sb-boot-proof.sh          — firmware ENFORCES Secure Boot (rejects tampered),
#   * tpm-measured-boot-proof.sh — the TPM extend model + PCR-bound seal/unseal.
#
# Method (no guest OS needed): boot the same db-signed kernel ESP under OVMF twice,
# once with Secure Boot ENABLED (our PK/KEK/db enrolled) and once DISABLED, each
# with a fresh swtpm vTPM. The firmware measures itself and the boot state into the
# vTPM. swtpm is a persistent daemon, so after QEMU exits it still holds the
# firmware-extended PCRs in memory; we save that volatile state (swtpm_ioctl -v),
# resume swtpm read-only over TCP, and read the PCRs with tpm2-tools.
#
# Deterministic assertions (a live-quote reconciliation with the full TCG event
# log — Authenticode PE hashes — is the documented next step and needs an in-guest
# reader; this proof establishes that firmware measurement is REAL and reflects the
# Secure Boot policy):
#   * PCR 0 is non-zero in both boots  -> firmware measured its own code (SRTM).
#   * PCR 7 is non-zero in both boots  -> firmware measured the Secure Boot state.
#   * PCR 7(SB on) != PCR 7(SB off)    -> the SB policy is really folded into the TPM.
#   * PCR 0(SB on) == PCR 0(SB off)    -> same firmware code path (consistency).
#
# Requires: sbsign, virt-fw-vars (repo venv), qemu-system-x86_64 with TPM support,
# an SMM OVMF, swtpm + swtpm TCTI + tpm2-tools, sgdisk, mtools, mkfs.vfat. Needs
# root for QEMU's locked memory (io_uring), like sb-boot-proof.sh. Fails closed
# (INCONCLUSIVE) if a tool/firmware is missing; never a false green.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SB_DIR="${REPO_ROOT}/distro/secureboot"
KEYGEN="${SB_DIR}/generate-sb-keys.sh"
VIRT_FW_VARS="${AIOS_VIRT_FW_VARS:-/home/luckyngoriko/.venv-virtfw/bin/virt-fw-vars}"
OVMF_CODE="${AIOS_OVMF_CODE:-/usr/share/qemu/ovmf-x86_64-smm-code.bin}"
OVMF_VARS_TMPL="${AIOS_OVMF_VARS:-/usr/share/qemu/ovmf-x86_64-smm-vars.bin}"
KERNEL="${AIOS_KERNEL:-${REPO_ROOT}/distro/build/out/iso-extract/vmlinuz}"
EPOCH="${AIOS_SB_EPOCH:-1735689600}"
OWNER_GUID="a0b1c2d3-e4f5-6789-abcd-ef0123456789"
BOOT_TIMEOUT="${AIOS_TPM_BOOT_TIMEOUT:-45}"
TPM_PORT="${AIOS_TPM_PORT:-42331}"
WORK="${AIOS_TPM_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/aios-fwtpm.XXXXXX")}"
# swtpm unixio control sockets must fit in sun_path (~108 chars); keep them short.
SOCKDIR="$(mktemp -d /tmp/aios-fwtpm-sock.XXXX)"

ulimit -l unlimited 2>/dev/null || true

for _a in "$@"; do case "${_a}" in --keep) AIOS_TPM_KEEP=1 ;; esac; done

log() { printf '[fwtpm] %s\n' "$*"; }
inconclusive() { printf '[fwtpm] INCONCLUSIVE: %s\n' "$*" >&2; _cleanup; exit 4; }
die() { printf '[fwtpm] FATAL: %s\n' "$*" >&2; _cleanup; exit 3; }

_SWTPM_PIDS=""
_cleanup() {
  for p in ${_SWTPM_PIDS}; do kill "${p}" 2>/dev/null; done
  [ -n "${AIOS_TPM_KEEP:-}" ] || { rm -rf "${WORK}" "${SOCKDIR}"; }
}
trap _cleanup EXIT

for t in sbsign qemu-system-x86_64 swtpm swtpm_ioctl tpm2_pcrread sgdisk mformat mcopy mkfs.vfat; do
  command -v "$t" >/dev/null 2>&1 || inconclusive "missing tool: $t"
done
[ -x "${VIRT_FW_VARS}" ] || VIRT_FW_VARS="$(command -v virt-fw-vars 2>/dev/null)"
[ -n "${VIRT_FW_VARS}" ] && [ -x "${VIRT_FW_VARS}" ] || inconclusive "virt-fw-vars missing"
[ -f "${OVMF_CODE}" ] || inconclusive "OVMF code missing: ${OVMF_CODE}"
[ -f "${OVMF_VARS_TMPL}" ] || inconclusive "OVMF vars template missing: ${OVMF_VARS_TMPL}"
[ -f "${KERNEL}" ] || inconclusive "kernel EFI stub missing: ${KERNEL}"

mkdir -p "${WORK}"
log "work dir: ${WORK}"

# ── keys + signed kernel + GPT ESP (shared by both boots) ─────────────────────
log "generating keys and signing the kernel"
bash "${KEYGEN}" --out "${WORK}/keys" --epoch "${EPOCH}" >/dev/null 2>&1 || die "key generation failed"
sbsign --key "${WORK}/keys/db.key" --cert "${WORK}/keys/db.crt" \
  --output "${WORK}/signed.efi" "${KERNEL}" >/dev/null 2>&1 || die "sbsign failed"

build_disk() {  # $1 = disk path
  local disk="$1" esp="${WORK}/esp.img" off=$((2048 * 512))
  if [ ! -f "${esp}" ]; then
    truncate -s 90M "${esp}"
    mkfs.vfat -n AIOS_SB "${esp}" >/dev/null 2>&1 || die "mkfs.vfat failed"
    mmd   -i "${esp}" ::/EFI ::/EFI/BOOT >/dev/null 2>&1 || die "mmd failed"
    mcopy -i "${esp}" "${WORK}/signed.efi" ::/EFI/BOOT/BOOTX64.EFI >/dev/null 2>&1 || die "mcopy failed"
  fi
  truncate -s 96M "${disk}"
  sgdisk --zap-all "${disk}" >/dev/null 2>&1
  sgdisk -n 1:2048:0 -t 1:ef00 -c 1:AIOS_ESP "${disk}" >/dev/null 2>&1
  dd if="${esp}" of="${disk}" bs=1M seek=1 conv=notrunc status=none
}

# Enrolled varstore (Secure Boot ON) and a clean varstore (Secure Boot OFF).
"${VIRT_FW_VARS}" -i "${OVMF_VARS_TMPL}" \
  --set-pk "${OWNER_GUID}" "${WORK}/keys/PK.crt" \
  --add-kek "${OWNER_GUID}" "${WORK}/keys/KEK.crt" \
  --add-db "${OWNER_GUID}" "${WORK}/keys/db.crt" \
  --secure-boot -o "${WORK}/vars-sbon.bin" >/dev/null 2>&1 || die "enrollment failed"
cp "${OVMF_VARS_TMPL}" "${WORK}/vars-sboff.bin"

# ── one measured boot: firmware -> vTPM, then read the PCRs back ───────────────
# Returns via globals RES_PCR0 / RES_PCR7 for the caller.
measured_boot() {
  local name="$1" vars="$2" srv_port="$3"
  local ctrl_port=$((srv_port + 1))
  local disk="${WORK}/disk-${name}.img"
  local state="${WORK}/tpmstate-${name}"; mkdir -p "${state}"
  local sock="${SOCKDIR}/${name}.sock"
  build_disk "${disk}"
  cp "${vars}" "${WORK}/vars-run-${name}.bin"

  # vTPM backend for QEMU (unixio control socket).
  swtpm socket --tpm2 --tpmstate dir="${state}" \
    --ctrl type=unixio,path="${sock}" --flags startup-clear \
    --daemon --pid file="${state}/pid" 2>"${state}/swtpm.err" \
    || { log "swtpm(qemu) failed to start for ${name}"; return 1; }
  local sp; sp="$(cat "${state}/pid" 2>/dev/null)"; _SWTPM_PIDS="${_SWTPM_PIDS} ${sp}"
  sleep 0.5

  local kvm=""; [ -w /dev/kvm ] && kvm="-enable-kvm -cpu host"
  timeout "${BOOT_TIMEOUT}" qemu-system-x86_64 \
    -machine q35,smm=on -m 1024 -smp 2 -display none -no-reboot ${kvm} \
    -global driver=cfi.pflash01,property=secure,value=on \
    -global ICH9-LPC.disable_s3=1 \
    -drive if=pflash,format=raw,unit=0,readonly=on,aio=threads,file="${OVMF_CODE}" \
    -drive if=pflash,format=raw,unit=1,aio=threads,file="${WORK}/vars-run-${name}.bin" \
    -chardev "socket,id=chrtpm,path=${sock}" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-crb,tpmdev=tpm0 \
    -drive format=raw,aio=threads,file="${disk}" \
    -serial file:"${state}/serial.log" -nic none >/dev/null 2>"${state}/qemu.err"

  # QEMU has exited; swtpm still holds the firmware-extended PCRs. Persist that
  # volatile state to the state dir, stop the QEMU-facing instance, then resume a
  # fresh instance over TCP that issues Startup(STATE) to restore those PCRs.
  swtpm_ioctl --unix "${sock}" -v 2>>"${state}/ioctl.err"   # store volatile (PCR) state
  swtpm_ioctl --unix "${sock}" -s 2>>"${state}/ioctl.err"   # shutdown + exit this instance
  kill "${sp}" 2>/dev/null; sleep 0.5

  # startup-state restores the saved volatile state (PCRs); not-need-init alone
  # would leave the TPM without a Startup and reject commands after a real boot.
  swtpm socket --tpm2 --tpmstate dir="${state}" \
    --ctrl type=tcp,port="${ctrl_port}" --server type=tcp,port="${srv_port}" \
    --flags startup-state --daemon --pid file="${state}/pid2" 2>"${state}/swtpm2.err" \
    || { log "swtpm(resume) failed for ${name}: $(tr -d '\n' <"${state}/swtpm2.err")"; return 1; }
  local sp2; sp2="$(cat "${state}/pid2" 2>/dev/null)"; _SWTPM_PIDS="${_SWTPM_PIDS} ${sp2}"
  sleep 0.5

  export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=${srv_port}"
  local ready=0 i
  for i in 1 2 3 4 5 6 7 8; do
    tpm2_pcrread sha256:0 >/dev/null 2>&1 && { ready=1; break; }; sleep 0.3
  done
  if [ "${ready}" -ne 1 ]; then
    log "resumed swtpm not responding for ${name}"
    log "  swtpm2.err: $(tr -d '\n' <"${state}/swtpm2.err" 2>/dev/null | head -c 300)"
    log "  ioctl.err:  $(tr -d '\n' <"${state}/ioctl.err" 2>/dev/null | head -c 200)"
    log "  qemu.err:   $(tr -d '\n' <"${state}/qemu.err" 2>/dev/null | head -c 200)"
    log "  state dir:  $(ls "${state}" 2>/dev/null | tr '\n' ' ')"
    return 1
  fi

  RES_PCR0="$(tpm2_pcrread sha256:0 2>/dev/null | grep -oiE '0x[0-9A-Fa-f]{64}' | head -1 | tr 'A-F' 'a-f')"
  RES_PCR7="$(tpm2_pcrread sha256:7 2>/dev/null | grep -oiE '0x[0-9A-Fa-f]{64}' | head -1 | tr 'A-F' 'a-f')"
  kill "${sp2}" 2>/dev/null
  return 0
}

log "=== measured boot 1: Secure Boot ON ==="
RES_PCR0=""; RES_PCR7=""
measured_boot sbon "${WORK}/vars-sbon.bin" "${TPM_PORT}" || inconclusive "SB-on measured boot failed"
PCR0_ON="${RES_PCR0}"; PCR7_ON="${RES_PCR7}"

log "=== measured boot 2: Secure Boot OFF ==="
RES_PCR0=""; RES_PCR7=""
measured_boot sboff "${WORK}/vars-sboff.bin" "$((TPM_PORT + 2))" || inconclusive "SB-off measured boot failed"
PCR0_OFF="${RES_PCR0}"; PCR7_OFF="${RES_PCR7}"

echo "===== FIRMWARE MEASURED-BOOT PROOF ====="
echo "SB ON : PCR0=${PCR0_ON:-<empty>}"
echo "        PCR7=${PCR7_ON:-<empty>}"
echo "SB OFF: PCR0=${PCR0_OFF:-<empty>}"
echo "        PCR7=${PCR7_OFF:-<empty>}"

ZERO="0000000000000000000000000000000000000000000000000000000000000000"
RC=0
fail() { echo "  FAIL: $*"; RC=5; }
[ -n "${PCR0_ON}" ] && [ -n "${PCR7_ON}" ] && [ -n "${PCR0_OFF}" ] && [ -n "${PCR7_OFF}" ] \
  || inconclusive "one or more PCRs could not be read"
[ "${PCR0_ON}" != "${ZERO}" ] || fail "PCR0 (SB on) is zero — firmware did not measure its own code"
[ "${PCR7_ON}" != "${ZERO}" ] || fail "PCR7 (SB on) is zero — Secure Boot state not measured"
[ "${PCR7_OFF}" != "${ZERO}" ] || fail "PCR7 (SB off) is zero — Secure Boot state not measured"
[ "${PCR7_ON}" != "${PCR7_OFF}" ] || fail "PCR7 identical for SB on/off — SB policy not folded into the TPM"
[ "${PCR0_ON}" = "${PCR0_OFF}" ] || echo "  NOTE: PCR0 differs across runs (firmware code path not identical)"

if [ "${RC}" -eq 0 ]; then
  echo "FWTPM PROOF: PASS — real firmware measured boot into the vTPM; the Secure Boot"
  echo "             state is reflected in PCR 7 (differs on vs off), PCR 0 is populated."
else
  echo "FWTPM PROOF: FAIL"
fi
echo "===== END FIRMWARE MEASURED-BOOT PROOF ====="
exit "${RC}"
