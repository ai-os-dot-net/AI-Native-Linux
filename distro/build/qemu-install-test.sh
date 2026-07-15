#!/bin/bash
set -euo pipefail

# AI-OS.NET Rev.12 QEMU install-and-boot gate (spec R12.2 / R12.7).
#
# Two phases, both driven over the serial console with no display:
#   Phase 1 (install): create a blank virtual disk, boot the ISO, and drive a
#                      NON-INTERACTIVE install onto that disk via the kernel
#                      command line flag `aios.autoinstall` (handled in-guest by
#                      distro/installer/aios-autoinstall.sh, which wraps the
#                      env-var driven aios-quick-install.sh). Wait for the
#                      install-success marker, then the guest powers off.
#   Phase 2 (boot):    boot QEMU again FROM THE INSTALLED DISK (no ISO) and
#                      assert the same boot success markers as qemu-boot-smoke.sh.
#
# Both serial logs are written under distro/build/out/. Conventions (arg style,
# markers, KVM detection, TCG fallback, OVMF discovery) mirror qemu-boot-smoke.sh.
#
# The autoinstall mechanism is the kernel command line because the installer's
# only genuine non-interactive entrypoint is the env-var driven
# aios-quick-install.sh (see its header, lines 41-44). aios-autoinstall.sh maps
# `aios.disk=` / `aios.hostname=` cmdline keys onto AIOS_TARGET_DISK /
# AIOS_HOSTNAME / AIOS_CONFIRM_SKIP. Phase 1 injects that command line with
# QEMU direct kernel boot (-kernel/-initrd/-append) so no GRUB editing is needed
# while the ISO stays attached as the live-media source.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
DEFAULT_INSTALL_LOG="${OUT_DIR}/qemu-install-phase1.log"
DEFAULT_BOOT_LOG="${OUT_DIR}/qemu-install-phase2.log"
DEFAULT_DISK="${OUT_DIR}/aios-install-test.qcow2"

ISO_PATH=""
KERNEL_PATH=""
INITRD_PATH=""
DISK_PATH="${AIOS_QEMU_INSTALL_DISK:-${DEFAULT_DISK}}"
# 48G (sparse qcow2, ~a few GB actually written): must clear the installer's
# own AIOS_MIN_DISK_GB=40 production guard — a harness that provisions a disk
# the installer legitimately rejects is a harness bug, not an installer bug.
# Pipeline 4731 proved the install now reaches this check (squashfs found, disk
# too small at the old 20G). Do NOT lower the installer minimum to pass CI.
DISK_SIZE="${AIOS_QEMU_INSTALL_DISK_SIZE:-48G}"
TARGET_DEV="${AIOS_QEMU_TARGET_DEV:-/dev/vda}"
GUEST_HOSTNAME="${AIOS_QEMU_INSTALL_HOSTNAME:-aios-ci}"
CDLABEL="${AIOS_QEMU_CDLABEL:-AIOS_REV12}"
INSTALL_LOG="${AIOS_QEMU_INSTALL_LOG:-${DEFAULT_INSTALL_LOG}}"
BOOT_LOG="${AIOS_QEMU_INSTALL_BOOT_LOG:-${DEFAULT_BOOT_LOG}}"
INSTALL_TIMEOUT="${AIOS_QEMU_INSTALL_TIMEOUT:-900}"
BOOT_TIMEOUT="${AIOS_QEMU_INSTALL_BOOT_TIMEOUT:-240}"
MEMORY_MB="${AIOS_QEMU_MEMORY_MB:-4096}"
CPUS="${AIOS_QEMU_CPUS:-2}"
QEMU_BINARY="${AIOS_QEMU_BINARY:-}"
OVMF_CODE="${AIOS_OVMF_CODE:-}"
OVMF_VARS_SRC="${AIOS_OVMF_VARS:-}"
EXTRA_APPEND="${AIOS_QEMU_EXTRA_APPEND:-}"
SWTPM_STATE="${AIOS_QEMU_SWTPM_STATE:-${OUT_DIR}/aios-install-swtpm}"
DRY_RUN=false
USE_KVM=false
USE_SWTPM=false
KEEP_DISK=false

usage() {
    cat <<'EOF'
Usage: qemu-install-test.sh --iso PATH [options]

Runs the Rev.12 install gate: install to a blank disk (phase 1), then boot the
installed disk (phase 2). Requires the ISO to carry aios-autoinstall.sh wired to
the `aios.autoinstall` kernel flag (see QEMU-INSTALL-TEST.md).

Required:
  --iso PATH             AI-OS.NET live/install ISO

Phase 1 autoinstall inputs:
  --kernel PATH          Kernel image for direct-boot autoinstall (live/vmlinuz)
  --initrd PATH          Initramfs for direct-boot autoinstall (live/initrd.img)
  --target-dev DEV       In-guest install target, default: /dev/vda
  --hostname NAME        Installed hostname, default: aios-ci
  --cdlabel LABEL        Live media volume label, default: AIOS_REV12
  --extra-append STR     Extra kernel cmdline appended in phase 1

Disk:
  --disk PATH            Blank virtual disk path, default: out/aios-install-test.qcow2
  --disk-size SIZE       qemu-img size, default: 48G (> installer 40G minimum)
  --keep-disk            Keep the disk image after a successful run

Firmware / TPM (installed boot usually needs both — see QEMU-INSTALL-TEST.md):
  --uefi                 (implied for phase 2) boot installed disk via OVMF
  --ovmf-code PATH       OVMF_CODE.fd path
  --ovmf-vars PATH       OVMF_VARS.fd template path (copied per run)
  --swtpm                Attach a swtpm software TPM2 (shared across phases)
  --swtpm-state DIR      swtpm state dir, default: out/aios-install-swtpm

QEMU:
  --memory MB            Guest memory, default: 4096
  --cpus N               Guest vCPUs, default: 2
  --qemu-binary PATH     qemu-system-x86_64 override
  --kvm                  Use KVM acceleration when /dev/kvm is available

Logs / control:
  --install-log PATH     Phase 1 serial log, default: out/qemu-install-phase1.log
  --boot-log PATH        Phase 2 serial log, default: out/qemu-install-phase2.log
  --install-timeout SEC  Phase 1 timeout, default: 900
  --boot-timeout SEC     Phase 2 timeout, default: 240
  --dry-run              Print the qemu-img / QEMU commands only, do not run
  -h, --help             Show this help
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '[qemu-install-test] %s\n' "$*"
}

require_int() {
    case "$2" in
        ''|*[!0-9]*) die "$1 must be a positive integer" ;;
    esac
    [ "$2" -gt 0 ] || die "$1 must be greater than zero"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --iso)           [ "$#" -ge 2 ] || die "--iso requires a path"; ISO_PATH="$2"; shift 2 ;;
        --kernel)        [ "$#" -ge 2 ] || die "--kernel requires a path"; KERNEL_PATH="$2"; shift 2 ;;
        --initrd)        [ "$#" -ge 2 ] || die "--initrd requires a path"; INITRD_PATH="$2"; shift 2 ;;
        --target-dev)    [ "$#" -ge 2 ] || die "--target-dev requires a device"; TARGET_DEV="$2"; shift 2 ;;
        --hostname)      [ "$#" -ge 2 ] || die "--hostname requires a name"; GUEST_HOSTNAME="$2"; shift 2 ;;
        --cdlabel)       [ "$#" -ge 2 ] || die "--cdlabel requires a label"; CDLABEL="$2"; shift 2 ;;
        --extra-append)  [ "$#" -ge 2 ] || die "--extra-append requires a string"; EXTRA_APPEND="$2"; shift 2 ;;
        --disk)          [ "$#" -ge 2 ] || die "--disk requires a path"; DISK_PATH="$2"; shift 2 ;;
        --disk-size)     [ "$#" -ge 2 ] || die "--disk-size requires a size"; DISK_SIZE="$2"; shift 2 ;;
        --keep-disk)     KEEP_DISK=true; shift ;;
        --uefi)          shift ;; # phase 2 is always UEFI; accepted for clarity
        --ovmf-code)     [ "$#" -ge 2 ] || die "--ovmf-code requires a path"; OVMF_CODE="$2"; shift 2 ;;
        --ovmf-vars)     [ "$#" -ge 2 ] || die "--ovmf-vars requires a path"; OVMF_VARS_SRC="$2"; shift 2 ;;
        --swtpm)         USE_SWTPM=true; shift ;;
        --swtpm-state)   [ "$#" -ge 2 ] || die "--swtpm-state requires a dir"; SWTPM_STATE="$2"; USE_SWTPM=true; shift 2 ;;
        --memory)        [ "$#" -ge 2 ] || die "--memory requires MB"; MEMORY_MB="$2"; shift 2 ;;
        --cpus)          [ "$#" -ge 2 ] || die "--cpus requires a count"; CPUS="$2"; shift 2 ;;
        --qemu-binary)   [ "$#" -ge 2 ] || die "--qemu-binary requires a path"; QEMU_BINARY="$2"; shift 2 ;;
        --kvm)           USE_KVM=true; shift ;;
        --install-log)   [ "$#" -ge 2 ] || die "--install-log requires a path"; INSTALL_LOG="$2"; shift 2 ;;
        --boot-log)      [ "$#" -ge 2 ] || die "--boot-log requires a path"; BOOT_LOG="$2"; shift 2 ;;
        --install-timeout) [ "$#" -ge 2 ] || die "--install-timeout requires seconds"; INSTALL_TIMEOUT="$2"; shift 2 ;;
        --boot-timeout)  [ "$#" -ge 2 ] || die "--boot-timeout requires seconds"; BOOT_TIMEOUT="$2"; shift 2 ;;
        --dry-run)       DRY_RUN=true; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               die "unknown argument: $1" ;;
    esac
done

[ -n "${ISO_PATH}" ] || die "--iso PATH is required"

require_int "--install-timeout" "${INSTALL_TIMEOUT}"
require_int "--boot-timeout" "${BOOT_TIMEOUT}"
require_int "--memory" "${MEMORY_MB}"
require_int "--cpus" "${CPUS}"

if [ -z "${QEMU_BINARY}" ]; then
    QEMU_BINARY="$(command -v qemu-system-x86_64 2>/dev/null || printf 'qemu-system-x86_64')"
fi

# ── OVMF discovery (installed systemd-boot requires UEFI firmware) ─────────────

find_ovmf() {
    # $1 = CODE|VARS
    local kind="$1"
    local candidate
    local code_list vars_list
    code_list="/usr/share/OVMF/OVMF_CODE.fd /usr/share/ovmf/OVMF_CODE.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
        /usr/share/qemu/OVMF_CODE.fd"
    vars_list="/usr/share/OVMF/OVMF_VARS.fd /usr/share/ovmf/OVMF_VARS.fd \
        /usr/share/edk2/ovmf/OVMF_VARS.fd /usr/share/edk2-ovmf/x64/OVMF_VARS.fd \
        /usr/share/qemu/OVMF_VARS.fd"
    if [ "${kind}" = "VARS" ]; then
        for candidate in ${vars_list}; do
            [ -f "${candidate}" ] && { printf '%s\n' "${candidate}"; return 0; }
        done
    else
        for candidate in ${code_list}; do
            [ -f "${candidate}" ] && { printf '%s\n' "${candidate}"; return 0; }
        done
    fi
    return 1
}

# ── Accel selection (shared by both phases) ───────────────────────────────────

accel_args() {
    if ${USE_KVM}; then
        if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
            printf '%s\n' "-enable-kvm" "-cpu" "host"
            return 0
        fi
        die "--kvm requested but /dev/kvm is not readable and writable"
    fi
    printf '%s\n' "-machine" "accel=tcg" "-cpu" "qemu64"
}

# ── swtpm helpers ─────────────────────────────────────────────────────────────

SWTPM_SOCK="${SWTPM_STATE}/swtpm-sock"
SWTPM_PID=""

start_swtpm() {
    ${USE_SWTPM} || return 0
    command -v swtpm >/dev/null 2>&1 || die "--swtpm requested but swtpm not found"
    mkdir -p "${SWTPM_STATE}"
    swtpm socket --tpmstate "dir=${SWTPM_STATE}" \
        --ctrl "type=unixio,path=${SWTPM_SOCK}" \
        --tpm2 --daemon --pid "file=${SWTPM_STATE}/swtpm.pid" \
        || die "failed to start swtpm"
    SWTPM_PID="$(cat "${SWTPM_STATE}/swtpm.pid" 2>/dev/null || printf '')"
    info "swtpm started (state=${SWTPM_STATE})"
}

# swtpm goes away once its QEMU client disconnects, so by the time phase 2 runs
# the control socket from the phase-1 start is gone and QEMU fails to launch at
# all ("Failed to connect to ...swtpm-sock", phase-2 log stays empty — defect
# #11). Re-start it per phase; the state dir is reused, so TPM state carries
# across phases as intended.
ensure_swtpm() {
    ${USE_SWTPM} || return 0
    if [ -n "${SWTPM_PID}" ] && kill -0 "${SWTPM_PID}" 2>/dev/null && [ -S "${SWTPM_SOCK}" ]; then
        return 0
    fi
    start_swtpm
}

# shellcheck disable=SC2329  # invoked indirectly via the EXIT trap (cleanup)
stop_swtpm() {
    [ -n "${SWTPM_PID}" ] || return 0
    kill "${SWTPM_PID}" 2>/dev/null || true
    SWTPM_PID=""
}

swtpm_qemu_args() {
    ${USE_SWTPM} || return 0
    printf '%s\n' \
        "-chardev" "socket,id=chrtpm,path=${SWTPM_SOCK}" \
        "-tpmdev" "emulator,id=tpm0,chardev=chrtpm" \
        "-device" "tpm-tis,tpmdev=tpm0"
}

# ── Command builders ──────────────────────────────────────────────────────────

QEMU_CMD=()

print_command() {
    local label="$1"; shift
    local arg
    printf '%s:' "${label}"
    for arg in "$@"; do
        printf ' %q' "${arg}"
    done
    printf '\n'
}

build_qemu_img_cmd() {
    QEMU_IMG_CMD=("${QEMU_IMG_BINARY}" create -f qcow2 "${DISK_PATH}" "${DISK_SIZE}")
}

build_phase1_cmd() {
    local append
    append="root=live:CDLABEL=${CDLABEL} rd.live.image rd.live.overlay=tmpfs"
    append="${append} console=tty0 console=ttyS0,115200n8 loglevel=4"
    append="${append} aios.autoinstall aios.disk=${TARGET_DEV} aios.hostname=${GUEST_HOSTNAME}"
    [ -n "${EXTRA_APPEND}" ] && append="${append} ${EXTRA_APPEND}"

    QEMU_CMD=(
        "${QEMU_BINARY}"
        -m "${MEMORY_MB}"
        -smp "${CPUS}"
        -display none
        -monitor none
        -no-reboot
        -drive "file=${DISK_PATH},if=virtio,format=qcow2,cache=unsafe"
        -cdrom "${ISO_PATH}"
        -serial "file:${INSTALL_LOG}"
        -nic none
        -kernel "${KERNEL_PATH}"
        -initrd "${INITRD_PATH}"
        -append "${append}"
    )
    local a
    while IFS= read -r a; do QEMU_CMD+=("${a}"); done < <(accel_args)
    while IFS= read -r a; do QEMU_CMD+=("${a}"); done < <(swtpm_qemu_args)
}

build_phase2_cmd() {
    QEMU_CMD=(
        "${QEMU_BINARY}"
        -m "${MEMORY_MB}"
        -smp "${CPUS}"
        -display none
        -monitor none
        -no-reboot
        -boot c
        -drive "file=${DISK_PATH},if=virtio,format=qcow2,cache=unsafe"
        -serial "file:${BOOT_LOG}"
        -nic none
    )
    local a
    while IFS= read -r a; do QEMU_CMD+=("${a}"); done < <(accel_args)
    # Installed system boots systemd-boot from the ESP: UEFI firmware required.
    QEMU_CMD+=(
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
        -drive "if=pflash,format=raw,file=${OVMF_VARS_RUN}"
    )
    while IFS= read -r a; do QEMU_CMD+=("${a}"); done < <(swtpm_qemu_args)
}

# ── Log marker scanning (shared) ──────────────────────────────────────────────

MATCHED_MARKER=""
log_contains_any() {
    local log="$1"; shift
    local pattern
    for pattern in "$@"; do
        if grep -E -q -- "${pattern}" "${log}" 2>/dev/null; then
            MATCHED_MARKER="${pattern}"
            return 0
        fi
    done
    return 1
}

INSTALL_SUCCESS_MARKERS=(
    'AIOS-AUTOINSTALL: SUCCESS'
    'AI-OS\.NET .* installation complete'
    '\[AIOS-QUICK\]  OK   AI-OS.NET'
)
INSTALL_FAILURE_MARKERS=(
    'AIOS-AUTOINSTALL: FAILED'
    '\[AIOS-QUICK\]  ERROR'
    'Kernel panic'
    'not syncing'
    'AIOS-RESCUE'
    'Dropping to rescue shell'
)
BOOT_SUCCESS_MARKERS=(
    'AIOS-INIT.*=== Switching to real root ==='
    'AIOS-INIT.*Root filesystem mounted'
    'Reached target.*Multi-User'
    'AI-OS\.NET'
)
BOOT_FAILURE_MARKERS=(
    'Kernel panic'
    'not syncing'
    'No bootable device'
    'AIOS-RESCUE'
    'Dropping to rescue shell'
    'switch_root failed'
    'Missing init on new root'
)

# ── Preflight ─────────────────────────────────────────────────────────────────

QEMU_IMG_BINARY="$(command -v qemu-img 2>/dev/null || printf 'qemu-img')"

if [ -z "${OVMF_CODE}" ]; then
    OVMF_CODE="$(find_ovmf CODE || true)"
fi
if [ -z "${OVMF_VARS_SRC}" ]; then
    OVMF_VARS_SRC="$(find_ovmf VARS || true)"
fi
OVMF_VARS_RUN="${AIOS_QEMU_OVMF_VARS_RUN:-${OUT_DIR}/aios-install-OVMF_VARS.fd}"

if ! ${DRY_RUN}; then
    [ -f "${ISO_PATH}" ] || die "ISO not found: ${ISO_PATH}"
    [ -s "${ISO_PATH}" ] || die "ISO is empty: ${ISO_PATH}"
    command -v "${QEMU_BINARY}" >/dev/null 2>&1 || [ -x "${QEMU_BINARY}" ] \
        || die "qemu-system-x86_64 not found"
    command -v "${QEMU_IMG_BINARY}" >/dev/null 2>&1 || die "qemu-img not found"
    command -v timeout >/dev/null 2>&1 || die "timeout command not found"
    [ -n "${KERNEL_PATH}" ] || die "--kernel is required for a real run (autoinstall direct boot)"
    [ -n "${INITRD_PATH}" ] || die "--initrd is required for a real run (autoinstall direct boot)"
    [ -f "${KERNEL_PATH}" ] || die "kernel not found: ${KERNEL_PATH}"
    [ -f "${INITRD_PATH}" ] || die "initrd not found: ${INITRD_PATH}"
    [ -n "${OVMF_CODE}" ] || die "OVMF_CODE.fd not found; pass --ovmf-code PATH (installed boot needs UEFI)"
    [ -f "${OVMF_CODE}" ] || die "OVMF_CODE.fd not found: ${OVMF_CODE}"
    [ -n "${OVMF_VARS_SRC}" ] || die "OVMF_VARS.fd not found; pass --ovmf-vars PATH"
    [ -f "${OVMF_VARS_SRC}" ] || die "OVMF_VARS.fd not found: ${OVMF_VARS_SRC}"
fi

mkdir -p "${OUT_DIR}"
build_qemu_img_cmd

# ── Dry run: print every command and exit ─────────────────────────────────────

if ${DRY_RUN}; then
    print_command "qemu-img" "${QEMU_IMG_CMD[@]}"
    KERNEL_PATH="${KERNEL_PATH:-<KERNEL>}"
    INITRD_PATH="${INITRD_PATH:-<INITRD>}"
    OVMF_CODE="${OVMF_CODE:-<OVMF_CODE.fd>}"
    build_phase1_cmd
    print_command "phase1-install" "${QEMU_CMD[@]}"
    build_phase2_cmd
    print_command "phase2-boot" "${QEMU_CMD[@]}"
    if ${USE_SWTPM}; then
        printf 'swtpm: swtpm socket --tpmstate dir=%q --ctrl type=unixio,path=%q --tpm2 --daemon\n' \
            "${SWTPM_STATE}" "${SWTPM_SOCK}"
    fi
    exit 0
fi

# ── Real run ──────────────────────────────────────────────────────────────────

# shellcheck disable=SC2329  # invoked indirectly via the EXIT trap
cleanup() {
    stop_swtpm
    if ! ${KEEP_DISK} && [ "${RUN_OK:-0}" -eq 1 ] && [ -f "${DISK_PATH}" ]; then
        rm -f "${DISK_PATH}"
    fi
}
trap cleanup EXIT

: > "${INSTALL_LOG}"
: > "${BOOT_LOG}"

info "Creating blank disk: ${DISK_PATH} (${DISK_SIZE})"
print_command "qemu-img" "${QEMU_IMG_CMD[@]}"
"${QEMU_IMG_CMD[@]}" || die "qemu-img create failed"

cp "${OVMF_VARS_SRC}" "${OVMF_VARS_RUN}" || die "failed to stage OVMF_VARS"

ensure_swtpm

# --- Phase 1: install ---------------------------------------------------------
info "=== Phase 1: install to ${DISK_PATH} (target ${TARGET_DEV}) ==="
build_phase1_cmd
print_command "phase1-install" "${QEMU_CMD[@]}"
set +e
timeout "${INSTALL_TIMEOUT}" "${QEMU_CMD[@]}"
PHASE1_STATUS=$?
set -e

if log_contains_any "${INSTALL_LOG}" "${INSTALL_FAILURE_MARKERS[@]}"; then
    die "install failure marker in ${INSTALL_LOG}: ${MATCHED_MARKER}"
fi
if ! log_contains_any "${INSTALL_LOG}" "${INSTALL_SUCCESS_MARKERS[@]}"; then
    case "${PHASE1_STATUS}" in
        124) die "install phase timed out before success marker (${INSTALL_LOG})" ;;
        *)   die "install phase produced no success marker (status ${PHASE1_STATUS}, ${INSTALL_LOG})" ;;
    esac
fi
info "PASS phase 1: install marker found: ${MATCHED_MARKER}"

# --- Phase 2: boot installed disk ---------------------------------------------
info "=== Phase 2: boot installed disk ${DISK_PATH} ==="
ensure_swtpm
build_phase2_cmd
print_command "phase2-boot" "${QEMU_CMD[@]}"
set +e
timeout "${BOOT_TIMEOUT}" "${QEMU_CMD[@]}"
PHASE2_STATUS=$?
set -e

if log_contains_any "${BOOT_LOG}" "${BOOT_FAILURE_MARKERS[@]}"; then
    die "installed-boot failure marker in ${BOOT_LOG}: ${MATCHED_MARKER}"
fi
if ! log_contains_any "${BOOT_LOG}" "${BOOT_SUCCESS_MARKERS[@]}"; then
    case "${PHASE2_STATUS}" in
        124) die "installed-boot timed out before success marker (${BOOT_LOG})" ;;
        *)   die "installed-boot produced no success marker (status ${PHASE2_STATUS}, ${BOOT_LOG})" ;;
    esac
fi
info "PASS phase 2: installed-boot marker found: ${MATCHED_MARKER}"

RUN_OK=1
info "SUCCESS: install gate passed (logs: ${INSTALL_LOG}, ${BOOT_LOG})"
exit 0
