#!/bin/bash
set -euo pipefail

# AI-OS.NET Rev.12 QEMU live ISO boot smoke test.
# Proves the ISO reaches the AIOS initramfs live-root path and does not drop
# into rescue before a positive boot marker appears.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_SERIAL_LOG="${SCRIPT_DIR}/out/qemu-boot-smoke.log"

ISO_PATH=""
SERIAL_LOG="${AIOS_QEMU_SERIAL_LOG:-${DEFAULT_SERIAL_LOG}}"
TIMEOUT_SECONDS="${AIOS_QEMU_BOOT_TIMEOUT:-120}"
MEMORY_MB="${AIOS_QEMU_MEMORY_MB:-2048}"
CPUS="${AIOS_QEMU_CPUS:-2}"
QEMU_BINARY="${AIOS_QEMU_BINARY:-}"
UEFI=false
OVMF_CODE="${AIOS_OVMF_CODE:-}"
DRY_RUN=false
USE_KVM=false

usage() {
    cat <<'EOF'
Usage: qemu-boot-smoke.sh --iso PATH [options]

Required:
  --iso PATH              AI-OS.NET live/install ISO to boot

Options:
  --timeout SECONDS       Boot timeout, default: 120
  --memory MB             Guest memory, default: 2048
  --cpus N                Guest vCPU count, default: 2
  --serial-log PATH       Serial console log path
  --qemu-binary PATH      qemu-system-x86_64 binary override
  --uefi                  Boot with OVMF UEFI firmware
  --ovmf-code PATH        OVMF_CODE.fd path for --uefi
  --kvm                   Use KVM acceleration when /dev/kvm is available
  --dry-run               Print the QEMU command and exit without booting
  -h, --help              Show this help
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '[qemu-boot-smoke] %s\n' "$*"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --iso)
            [ "$#" -ge 2 ] || die "--iso requires a path"
            ISO_PATH="$2"
            shift 2
            ;;
        --timeout)
            [ "$#" -ge 2 ] || die "--timeout requires seconds"
            TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        --memory)
            [ "$#" -ge 2 ] || die "--memory requires MB"
            MEMORY_MB="$2"
            shift 2
            ;;
        --cpus)
            [ "$#" -ge 2 ] || die "--cpus requires a count"
            CPUS="$2"
            shift 2
            ;;
        --serial-log)
            [ "$#" -ge 2 ] || die "--serial-log requires a path"
            SERIAL_LOG="$2"
            shift 2
            ;;
        --qemu-binary)
            [ "$#" -ge 2 ] || die "--qemu-binary requires a path"
            QEMU_BINARY="$2"
            shift 2
            ;;
        --uefi)
            UEFI=true
            shift
            ;;
        --ovmf-code)
            [ "$#" -ge 2 ] || die "--ovmf-code requires a path"
            OVMF_CODE="$2"
            shift 2
            ;;
        --kvm)
            USE_KVM=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[ -n "${ISO_PATH}" ] || die "--iso PATH is required"
[ -f "${ISO_PATH}" ] || die "ISO not found: ${ISO_PATH}"

case "${TIMEOUT_SECONDS}" in
    ''|*[!0-9]*) die "--timeout must be a positive integer" ;;
esac
case "${MEMORY_MB}" in
    ''|*[!0-9]*) die "--memory must be a positive integer" ;;
esac
case "${CPUS}" in
    ''|*[!0-9]*) die "--cpus must be a positive integer" ;;
esac

[ "${TIMEOUT_SECONDS}" -gt 0 ] || die "--timeout must be greater than zero"
[ "${MEMORY_MB}" -gt 0 ] || die "--memory must be greater than zero"
[ "${CPUS}" -gt 0 ] || die "--cpus must be greater than zero"

if [ -z "${QEMU_BINARY}" ]; then
    QEMU_BINARY="$(command -v qemu-system-x86_64 2>/dev/null || printf 'qemu-system-x86_64')"
fi

if ! ${DRY_RUN}; then
    [ -x "${QEMU_BINARY}" ] || command -v "${QEMU_BINARY}" >/dev/null 2>&1 \
        || die "qemu-system-x86_64 not found"
    [ -s "${ISO_PATH}" ] || die "ISO is empty: ${ISO_PATH}"
    command -v timeout >/dev/null 2>&1 || die "timeout command not found"
fi

find_ovmf_code() {
    local candidate
    for candidate in \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/ovmf/OVMF_CODE.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd \
        /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
        /usr/share/qemu/OVMF_CODE.fd \
        /usr/share/qemu/ovmf-x86_64-4m-code.bin \
        /usr/share/qemu/ovmf-x86_64-code.bin; do
        if [ -f "${candidate}" ]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    return 1
}

QEMU_CMD=(
    "${QEMU_BINARY}"
    -m "${MEMORY_MB}"
    -smp "${CPUS}"
    -display none
    -monitor none
    -no-reboot
    -boot d
    -cdrom "${ISO_PATH}"
    -serial "file:${SERIAL_LOG}"
    -nic none
)

if ${USE_KVM}; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        QEMU_CMD+=(-enable-kvm -cpu host)
    else
        die "--kvm requested but /dev/kvm is not readable and writable"
    fi
else
    QEMU_CMD+=(-machine accel=tcg -cpu qemu64)
fi

if ${UEFI}; then
    if [ -z "${OVMF_CODE}" ]; then
        OVMF_CODE="$(find_ovmf_code || true)"
    fi
    [ -n "${OVMF_CODE}" ] || die "OVMF_CODE.fd not found; pass --ovmf-code PATH"
    [ -f "${OVMF_CODE}" ] || die "OVMF_CODE.fd not found: ${OVMF_CODE}"
    QEMU_CMD+=(-drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}")
fi

print_command() {
    local arg
    printf 'Command:'
    for arg in "${QEMU_CMD[@]}"; do
        printf ' %q' "${arg}"
    done
    printf '\n'
}

if ${DRY_RUN}; then
    print_command
    exit 0
fi

mkdir -p "$(dirname "${SERIAL_LOG}")"
: > "${SERIAL_LOG}"

info "Booting ISO: ${ISO_PATH}"
info "Serial log: ${SERIAL_LOG}"
info "Timeout: ${TIMEOUT_SECONDS}s"
print_command

set +e
timeout "${TIMEOUT_SECONDS}" "${QEMU_CMD[@]}"
QEMU_STATUS=$?
set -e

MATCHED_MARKER=""
log_contains_any() {
    local pattern
    for pattern in "$@"; do
        if grep -E -q -- "${pattern}" "${SERIAL_LOG}" 2>/dev/null; then
            MATCHED_MARKER="${pattern}"
            return 0
        fi
    done
    return 1
}

FAILURE_MARKERS=(
    'Kernel panic'
    'not syncing'
    'No bootable device'
    'AIOS-RESCUE'
    'Dropping to rescue shell'
    'AIOS live media with live/aios\.squashfs not found'
    'Mount of live squashfs failed'
    'Mount of live overlay tmpfs failed'
    'Missing init on new root'
    'switch_root failed'
)

SUCCESS_MARKERS=(
    'AIOS-INIT.*Live media mounted'
    'AIOS-INIT.*Mounting live squashfs'
    'AIOS-INIT.*Live overlay mounted'
    'AIOS-INIT.*=== Switching to real root ==='
    'Reached target.*Multi-User'
    'AI-OS\.NET'
)

if log_contains_any "${FAILURE_MARKERS[@]}"; then
    die "boot failure marker found in serial log: ${MATCHED_MARKER}"
fi

if log_contains_any "${SUCCESS_MARKERS[@]}"; then
    info "PASS: boot success marker found: ${MATCHED_MARKER}"
    exit 0
fi

case "${QEMU_STATUS}" in
    124)
        die "QEMU timed out before a boot success marker appeared"
        ;;
    0)
        die "QEMU exited cleanly but no boot success marker appeared"
        ;;
    *)
        die "QEMU exited with status ${QEMU_STATUS} before a boot success marker appeared"
        ;;
esac
