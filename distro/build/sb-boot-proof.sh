#!/bin/bash
#
# Secure Boot enforcement proof (R13.4).
#
# Proves — with a real UEFI firmware, not a static grep — that the AIOS Secure
# Boot key hierarchy actually gates boot: with our PK/KEK/db enrolled and Secure
# Boot on, a db-signed kernel EFI binary is executed by the firmware, and a
# tampered (signature-broken) copy of the same binary is REFUSED by the firmware
# before any code runs.
#
# Flow:
#   1. generate-sb-keys.sh -> PK/KEK/db (self-signed hierarchy).
#   2. sbsign the kernel EFI stub with the db key           -> signed BOOTX64.EFI.
#   3. corrupt one body byte of the signed binary            -> tampered BOOTX64.EFI.
#   4. virt-fw-vars enrolls PK/KEK/db into an OVMF varstore + turns Secure Boot on.
#   5. QEMU boots each ESP under that SB-enabled OVMF and the serial log decides:
#        signed   -> firmware hands off (NO rejection line);
#        tampered -> firmware prints a Secure Boot rejection and runs nothing.
#
# Requires: sbsign, virt-fw-vars (the repo's helper venv), mkfs.vfat, mtools,
# qemu-system-x86_64, an SB-capable OVMF. Fails closed (non-zero) if a tool or
# the OVMF firmware is missing, and is INCONCLUSIVE (non-zero) if the firmware
# does not enforce — never a false green.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SB_DIR="${REPO_ROOT}/distro/secureboot"
KEYGEN="${SB_DIR}/generate-sb-keys.sh"
VIRT_FW_VARS="${AIOS_VIRT_FW_VARS:-/home/luckyngoriko/.venv-virtfw/bin/virt-fw-vars}"
# Secure Boot is only securely enforced by an SMM-enabled OVMF with a
# write-protected varstore; the non-SMM firmware does NOT enforce. Pair the SMM
# code/vars with `-machine q35,smm=on` + secure pflash in boot_case().
OVMF_CODE="${AIOS_OVMF_CODE:-/usr/share/qemu/ovmf-x86_64-smm-code.bin}"
OVMF_VARS_TMPL="${AIOS_OVMF_VARS:-/usr/share/qemu/ovmf-x86_64-smm-vars.bin}"

# QEMU's io_uring rings need locked memory; a low RLIMIT_MEMLOCK makes qemu die
# at startup with "Failed to initialize io_uring: Cannot allocate memory". Raise
# it when we can (root); harmless otherwise.
ulimit -l unlimited 2>/dev/null || true
KERNEL="${AIOS_KERNEL:-${REPO_ROOT}/distro/build/out/iso-extract/vmlinuz}"
EPOCH="${AIOS_SB_EPOCH:-1735689600}"
OWNER_GUID="a0b1c2d3-e4f5-6789-abcd-ef0123456789"
# The very first QEMU launch is cold (KVM init, TSC calibration, OVMF first-boot
# NVRAM processing) and can take noticeably longer to reach the UEFI Boot Manager
# than the second; too short a cap kills the SIGNED boot (always boot 1) before it
# runs, producing false INCONCLUSIVE. 70s leaves ample headroom — a boot that
# succeeds exits immediately (-no-reboot), so the cap only bites a genuine hang.
BOOT_TIMEOUT="${AIOS_SB_BOOT_TIMEOUT:-70}"
WORK="${AIOS_SB_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/aios-sb-proof.XXXXXX")}"

for _a in "$@"; do
  case "${_a}" in
    --keep) AIOS_SB_KEEP=1 ;;
  esac
done

log() { printf '[sb-proof] %s\n' "$*"; }
die() { printf '[sb-proof] FATAL: %s\n' "$*" >&2; exit 3; }

for t in sbsign mkfs.vfat mcopy qemu-system-x86_64; do
  command -v "$t" >/dev/null 2>&1 || die "required tool missing: $t"
done
[ -x "${VIRT_FW_VARS}" ] || command -v virt-fw-vars >/dev/null 2>&1 || die "virt-fw-vars missing (${VIRT_FW_VARS})"
[ -x "${VIRT_FW_VARS}" ] || VIRT_FW_VARS="$(command -v virt-fw-vars)"
[ -f "${OVMF_CODE}" ] || die "OVMF code firmware missing: ${OVMF_CODE}"
[ -f "${OVMF_VARS_TMPL}" ] || die "OVMF vars template missing: ${OVMF_VARS_TMPL}"
[ -f "${KERNEL}" ] || die "kernel EFI stub missing: ${KERNEL} (extract live/vmlinuz from the ISO first)"

mkdir -p "${WORK}"
log "work dir: ${WORK}"

# 1. keys
log "generating Secure Boot key hierarchy"
bash "${KEYGEN}" --out "${WORK}/keys" --epoch "${EPOCH}" >/dev/null 2>&1 \
  || die "generate-sb-keys.sh failed"

# 2. sign the kernel with db
log "signing the kernel EFI stub with the db key"
sbsign --key "${WORK}/keys/db.key" --cert "${WORK}/keys/db.crt" \
  --output "${WORK}/signed.efi" "${KERNEL}" >/dev/null 2>&1 \
  || die "sbsign failed"
sbverify --cert "${WORK}/keys/db.crt" "${WORK}/signed.efi" >/dev/null 2>&1 \
  || die "our own signature does not verify — signing is broken"

# 3. tamper: flip a byte deep in the body so the signature no longer covers it.
cp "${WORK}/signed.efi" "${WORK}/tampered.efi"
_sz=$(stat -c%s "${WORK}/tampered.efi")
_off=$(( _sz / 2 ))
printf '\xff' | dd of="${WORK}/tampered.efi" bs=1 seek="${_off}" count=1 conv=notrunc 2>/dev/null
if sbverify --cert "${WORK}/keys/db.crt" "${WORK}/tampered.efi" >/dev/null 2>&1; then
  die "tampered binary still verifies — tamper did not take"
fi
log "tampered copy no longer verifies (as expected)"

# 4. enroll PK/KEK/db + enable Secure Boot in a fresh varstore
log "enrolling PK/KEK/db into OVMF varstore + enabling Secure Boot"
"${VIRT_FW_VARS}" -i "${OVMF_VARS_TMPL}" \
  --set-pk  "${OWNER_GUID}" "${WORK}/keys/PK.crt" \
  --add-kek "${OWNER_GUID}" "${WORK}/keys/KEK.crt" \
  --add-db  "${OWNER_GUID}" "${WORK}/keys/db.crt" \
  --secure-boot -o "${WORK}/sb-vars.bin" >/dev/null 2>&1 \
  || die "virt-fw-vars enrollment failed"

# helper: build a proper GPT disk with an EFI System Partition holding
# \EFI\BOOT\BOOTX64.EFI, then boot it once under the SB-enabled OVMF.
#
# A whole-disk raw FAT "superfloppy" is enumerated by OVMF inconsistently
# (observed: same input booting, "Access Denied", or "Not Found" across runs).
# A GPT disk with a real ESP is discovered deterministically via the UEFI
# default removable-media path, so the ONLY variable left is Secure Boot.
boot_case() {
  local name="$1" efi="$2" log_file="$3"
  local disk="${WORK}/disk-${name}.img" vars="${WORK}/vars-${name}.bin"
  local esp="${WORK}/esp-${name}.img"
  # Build the FAT ESP as a STANDALONE image first (whole-file mtools is reliable),
  # then dd it into the ESP partition of a GPT disk. Writing directly into a GPT
  # disk with `mtools -i disk@@offset` silently no-ops here (mtools' GPT
  # auto-detection fights the byte offset — mcopy returns 0 but the file never
  # lands), which was the real source of the "signed didn't run" flakiness.
  truncate -s 90M "${esp}"
  mkfs.vfat -n AIOS_SB "${esp}" >/dev/null 2>&1 || die "mkfs.vfat failed (${name})"
  mmd   -i "${esp}" ::/EFI ::/EFI/BOOT >/dev/null 2>&1 || die "mmd failed (${name})"
  mcopy -i "${esp}" "${efi}" ::/EFI/BOOT/BOOTX64.EFI >/dev/null 2>&1 || die "mcopy failed (${name})"
  # Verify the payload actually landed — a silent empty ESP would boot-flake, not fail.
  mdir -i "${esp}" ::/EFI/BOOT 2>/dev/null | grep -qi 'BOOTX64' \
    || die "BOOTX64.EFI missing from ${name} ESP after mcopy"
  local off=$((2048 * 512))   # ESP partition starts at LBA 2048 (1 MiB), conventional
  truncate -s 96M "${disk}"
  sgdisk --zap-all "${disk}" >/dev/null 2>&1
  sgdisk -n 1:2048:0 -t 1:ef00 -c 1:"AIOS_ESP" "${disk}" >/dev/null 2>&1
  dd if="${esp}" of="${disk}" bs=1M seek=1 conv=notrunc status=none
  cp "${WORK}/sb-vars.bin" "${vars}"
  local kvm=""
  [ -w /dev/kvm ] && kvm="-enable-kvm -cpu host"
  # SMM + a write-protected pflash varstore is what makes the firmware actually
  # enforce Secure Boot (without it OVMF admits anything). q35 is required for smm.
  # QEMU's own stderr is captured separately so a startup failure (io_uring,
  # missing kvm, bad pflash) is never mistaken for a firmware boot decision.
  timeout "${BOOT_TIMEOUT}" qemu-system-x86_64 \
    -machine q35,smm=on -m 1024 -smp 2 -display none -no-reboot ${kvm} \
    -global driver=cfi.pflash01,property=secure,value=on \
    -global ICH9-LPC.disable_s3=1 \
    -drive if=pflash,format=raw,unit=0,readonly=on,aio=threads,file="${OVMF_CODE}" \
    -drive if=pflash,format=raw,unit=1,aio=threads,file="${vars}" \
    -drive format=raw,aio=threads,file="${disk}" \
    -serial file:"${log_file}" -nic none >/dev/null 2>"${WORK}/qemu-${name}.err"
  return 0
}

REJECT_RE='Security Violation|Access Denied|not.*sign|verification failed|image.*fail|Image failed|hash.*not.*allowed|SB violation'

log "=== boot 1: SIGNED kernel (must be allowed) ==="
boot_case signed "${WORK}/signed.efi" "${WORK}/signed.log"
log "=== boot 2: TAMPERED kernel (must be refused) ==="
boot_case tampered "${WORK}/tampered.efi" "${WORK}/tampered.log"

echo "===== SB PROOF ====="
# The deterministic discriminator is whether the KERNEL ITSELF EXECUTED: the EFI
# stub only prints once the firmware has verified the image and handed control to
# it. A signed image must run; a tampered image must never run. The textual
# "Access Denied / Security Violation" line is nice corroboration but its timing
# in the serial log is flaky (QEMU may be killed by the timeout mid-flush), so it
# is reported but NOT the basis of the verdict.
#
# grep -c already prints a count (0 on no match); do NOT add `|| echo 0` — that
# appends a second line and breaks the integer test below.
RAN_RE='EFI stub|Linux version|Booting the kernel|Decompressing Linux'
signed_ran=$(grep -icE "${RAN_RE}" "${WORK}/signed.log" 2>/dev/null);     signed_ran=${signed_ran:-0}
tampered_ran=$(grep -icE "${RAN_RE}" "${WORK}/tampered.log" 2>/dev/null); tampered_ran=${tampered_ran:-0}
signed_reject=$(grep -icE "${REJECT_RE}" "${WORK}/signed.log" 2>/dev/null);     signed_reject=${signed_reject:-0}
tampered_reject=$(grep -icE "${REJECT_RE}" "${WORK}/tampered.log" 2>/dev/null); tampered_reject=${tampered_reject:-0}
# QEMU must have started cleanly for either log to mean anything.
qemu_err=""
for n in signed tampered; do
  if grep -qiE 'io_uring|could not|failed to|cannot|error' "${WORK}/qemu-${n}.err" 2>/dev/null; then
    qemu_err="${qemu_err} ${n}:$(tr -d '\n' < "${WORK}/qemu-${n}.err" | head -c 160)"
  fi
done

echo "signed:   ran=${signed_ran}  reject_lines=${signed_reject}"
echo "tampered: ran=${tampered_ran}  reject_lines=${tampered_reject}"
[ -n "${qemu_err}" ] && echo "qemu-startup-errors:${qemu_err}"
echo "--- tampered rejection lines ---"
grep -iaE "${REJECT_RE}" "${WORK}/tampered.log" 2>/dev/null | tr -d '\000' | head -3
echo "--- signed boot head ---"
head -c 500 "${WORK}/signed.log" 2>/dev/null | tr -d '\000' | tr -dc '[:print:]\n'
echo ""

RC=0
if [ -n "${qemu_err}" ]; then
  echo "SB PROOF: INCONCLUSIVE — QEMU failed to start; not a firmware decision."
  RC=4
elif [ "${signed_ran}" -eq 0 ]; then
  echo "SB PROOF: INCONCLUSIVE — the SIGNED image did not run (boot/disk problem, not Secure Boot)."
  RC=4
elif [ "${signed_ran}" -ge 1 ] && [ "${tampered_ran}" -eq 0 ]; then
  echo "SB PROOF: PASS — firmware executed the db-signed kernel and refused the tampered copy."
else
  echo "SB PROOF: FAIL — the tampered kernel executed; Secure Boot did NOT enforce."
  RC=5
fi
echo "===== END SB PROOF ====="
[ -n "${AIOS_SB_KEEP:-}" ] || rm -rf "${WORK}"
exit "${RC}"
