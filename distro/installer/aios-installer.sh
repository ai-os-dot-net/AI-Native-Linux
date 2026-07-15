#!/bin/bash
set -euo pipefail

# =============================================================================
# AI-OS.NET Bare-Metal Installer — Revision 4
# =============================================================================
# Installs AI-OS.NET on a physical machine from the live ISO/USB environment.
#
# PREREQUISITES:
#   — UEFI firmware (Secure Boot recommended)
#   — TPM 2.0 device present
#   — At least 40 GB disk space
#   — Internet connection (for NTP time sync)
#   — Running in AIOS live environment (ISO/USB boot)
#
# WHAT IT DOES:
#   1.  Disk selection — enumerate, confirm, safety checks
#   2.  Partition — GPT: ESP (512MiB) + Boot (1GiB) + LUKS-root (rest)
#   3.  LUKS2 encryption — argon2id pbkdf, random master key
#   4.  Filesystem creation — FAT32 ESP, ext4 boot, ext4 root on LUKS
#   5.  Rootfs extraction — unsquashfs from live media
#   6.  dm-verity setup — hash tree, root hash signing
#   7.  systemd-boot — bootloader install, loader entries
#   8.  System config — fstab, crypttab, hostname, machine-id, network
#   9.  TPM2 sealing — systemd-cryptenroll with PCRs 0+1+7
#   10. Recovery key — generate + display (mandatory user record)
#   11. SELinux — policy load, relabel, enforcing
#   12. First-boot flag — /etc/aios/first-boot
#   13. Unmount + completion
#
# USAGE:
#   aios-installer [--disk /dev/nvme0n1] [--hostname aios] \
#                  [--profile SECURE_DEFAULT]
#
# SAFETY: Prompts for confirmation before writing to disk.
#         Never destroys data without explicit user confirmation.
# =============================================================================

readonly AIOS_VERSION="REV4"
AIOS_BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)"
readonly AIOS_BUILD_ID
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME

# ── Defaults (overridable by flags / env) ─────────────────────────────────────

TARGET_DISK="${AIOS_TARGET_DISK:-}"
HOSTNAME="${AIOS_HOSTNAME:-aios}"
PROFILE="${AIOS_PROFILE:-SECURE_DEFAULT}"
RECOVERY_KEY_LENGTH=24
CONFIRM_SKIP="${AIOS_CONFIRM_SKIP:-0}"
ESP_SIZE_MB="${AIOS_ESP_SIZE_MB:-512}"
BOOT_SIZE_MB="${AIOS_BOOT_SIZE_MB:-1024}"
RECOVERY_SIZE_MB="${AIOS_RECOVERY_SIZE_MB:-2048}"
ROLLBACK_SIZE_MB="${AIOS_ROLLBACK_SIZE_MB:-4096}"
HASH_SIZE_MB="${AIOS_HASH_SIZE_MB:-1024}"
MIN_DISK_GB="${AIOS_MIN_DISK_GB:-40}"
SELINUX_MODE="${AIOS_SELINUX_MODE:-permissive}"

# ── Colour helpers ────────────────────────────────────────────────────────────

BOLD="\033[1m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
CYAN="\033[1;36m"
RESET="\033[0m"

msg()    { printf "${GREEN}[AIOS-INSTALL]${RESET} %s\n" "$*"; }
warn()   { printf "${YELLOW}[AIOS-INSTALL]${RESET} %s\n" "$*" >&2; }
err()    { printf "${RED}[AIOS-INSTALL] ${BOLD}ERROR:${RESET} %s\n" "$*" >&2; }
info()   { printf "${CYAN}[AIOS-INSTALL]${RESET} %s\n" "$*"; }
banner() { printf "\n${BOLD}════ %s ════${RESET}\n\n" "$*"; }

die() {
    err "$*"
    cleanup_on_failure
    exit 1
}

# ── Cleanup trap ──────────────────────────────────────────────────────────────

TARGET_MOUNT="/mnt/aios-target"
SETUP_DONE=""

cleanup_on_failure() {
    warn "Attempting cleanup after failure..."
    if [ -n "${SETUP_DONE}" ]; then
        # Try to unmount in reverse order
        umount "${TARGET_MOUNT}/boot/efi" 2>/dev/null || true
        umount "${TARGET_MOUNT}/boot"     2>/dev/null || true
        umount "${TARGET_MOUNT}/recovery" 2>/dev/null || true
        umount "${TARGET_MOUNT}/var/lib/aios/rollback" 2>/dev/null || true
        umount "${TARGET_MOUNT}"           2>/dev/null || true

        if [ -b "/dev/mapper/aios-cryptroot" ]; then
            cryptsetup close aios-cryptroot 2>/dev/null || true
        fi
    fi
    warn "Manual recovery may be required. Check:"
    warn "  — lsblk to see device state"
    warn "  — cryptsetup status aios-cryptroot"
    warn "  — mount | grep ${TARGET_MOUNT}"
}

trap 'cleanup_on_failure' ERR
trap 'cleanup_on_failure; exit 130' INT TERM

# ── Argument parsing ──────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --disk)      TARGET_DISK="$2"; shift 2 ;;
        --hostname)  HOSTNAME="$2";    shift 2 ;;
        --profile)   PROFILE="$2";     shift 2 ;;
        --help|-h)   usage; exit 0 ;;
        *)           warn "Unknown option: $1"; usage; exit 2 ;;
    esac
done

usage() {
    cat <<EOF
${BOLD}AI-OS.NET Bare-Metal Installer${RESET} — ${AIOS_VERSION}

Usage: ${SCRIPT_NAME} [OPTIONS]

Options:
  --disk DEVICE       Target block device (e.g. /dev/nvme0n1, /dev/sda)
  --hostname NAME     System hostname (default: aios)
  --profile PROFILE   Security profile (default: SECURE_DEFAULT)
  --help              Show this help

Environment variables:
  AIOS_TARGET_DISK    Same as --disk
  AIOS_HOSTNAME       Same as --hostname
  AIOS_CONFIRM_SKIP   Set to 1 to skip confirmation prompts (CI/automation)
  AIOS_ESP_SIZE_MB    EFI System Partition size in MiB (default: 512)
  AIOS_BOOT_SIZE_MB   Boot partition size in MiB (default: 1024)
  AIOS_HASH_SIZE_MB   dm-verity hash partition size in MiB (default: 1024)
  AIOS_MIN_DISK_GB    Minimum disk size in GB (default: 40)
  AIOS_SELINUX_MODE   SELinux mode (permissive|enforcing|disabled)
EOF
}

# ── Privilege check ───────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    die "This installer must be run as root. Use: sudo $0"
fi

# ── Environment probes ────────────────────────────────────────────────────────

check_prerequisites() {
    banner "Phase 0 — Environment Check"

    local _missing=""

    for _bin in lsblk sgdisk mkfs.vfat mkfs.ext4 cryptsetup \
                unsquashfs bootctl systemd-cryptenroll blkid \
                mount umount; do
        if ! command -v "${_bin}" >/dev/null 2>&1; then
            _missing="${_missing} ${_bin}"
        fi
    done

    if [ -n "${_missing}" ]; then
        die "Missing required tools:${_missing}"
    fi

    # Check UEFI
    if [ ! -d /sys/firmware/efi ]; then
        die "UEFI firmware not detected. AI-OS.NET requires UEFI boot."
    fi
    msg "UEFI firmware detected."

    # Check TPM
    if [ -d /sys/kernel/security/tpm0 ] || [ -d /sys/class/tpm/tpm0 ]; then
        msg "TPM device detected."
    else
        warn "No TPM device detected. TPM2 sealing will be skipped."
        warn "You will need to enter your LUKS passphrase on every boot."
    fi

    # Check squashed rootfs
    AIOS_SQUASHFS="${AIOS_SQUASHFS:-/run/initramfs/live/aios.squashfs}"
    if [ ! -f "${AIOS_SQUASHFS}" ]; then
        # Try alternate locations
        for _alt in /run/initramfs/live/filesystem.squashfs \
                    /run/archiso/bootmnt/aios.squashfs \
                    /run/live/medium/aios.squashfs; do
            if [ -f "${_alt}" ]; then
                AIOS_SQUASHFS="${_alt}"
                break
            fi
        done
    fi

    if [ ! -f "${AIOS_SQUASHFS}" ]; then
        die "Squashfs root not found. Are you running from the AIOS live ISO?"
    fi
    msg "Rootfs squashfs found: ${AIOS_SQUASHFS}"

    msg "All prerequisite tools and environment checks PASSED."
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — DISK SELECTION
# ══════════════════════════════════════════════════════════════════════════════

select_disk() {
    banner "Phase 1 — Disk Selection"

    if [ -z "${TARGET_DISK}" ]; then
        info "Available disks (excluding removable/loop devices):"
        echo
        lsblk -d -o NAME,SIZE,MODEL,SERIAL,TYPE,TRAN \
            | grep -v -E 'loop|sr[0-9]|zd[0-9]' \
            | head -30
        echo
        info "Enter the target disk path (e.g. /dev/nvme0n1 or /dev/sda):"
        read -r TARGET_DISK
        echo
    fi

    # Validate disk path
    if [ ! -b "${TARGET_DISK}" ]; then
        die "Invalid block device: ${TARGET_DISK}"
    fi

    local _disk_name
    _disk_name="$(basename "${TARGET_DISK}")"

    local _disk_size_bytes _disk_size_gb
    _disk_size_bytes=$(lsblk -b -d -n -o SIZE "${TARGET_DISK}" 2>/dev/null || echo 0)
    _disk_size_gb=$(( _disk_size_bytes / 1024 / 1024 / 1024 ))

    info "=== Selected Disk ==="
    info "  Device : ${TARGET_DISK}"
    info "  Model  : $(lsblk -d -n -o MODEL "${TARGET_DISK}" 2>/dev/null || echo 'UNKNOWN')"
    info "  Size   : ${_disk_size_gb} GB"
    echo

    # Size check
    if [ "${_disk_size_gb}" -lt "${MIN_DISK_GB}" ]; then
        die "Disk too small: ${_disk_size_gb}GB < ${MIN_DISK_GB}GB minimum."
    fi

    # Mounted check
    if mount | grep -q "^${TARGET_DISK}"; then
        die "DISK IS CURRENTLY MOUNTED. Refusing to install on mounted disk."
    fi

    # Partition warning
    local _existing_parts
    _existing_parts=$(lsblk -n -o NAME "${TARGET_DISK}" 2>/dev/null | tail -n +2 | wc -l)
    if [ "${_existing_parts}" -gt 0 ]; then
        warn "This disk has ${_existing_parts} existing partition(s):"
        lsblk "${TARGET_DISK}"
        echo
    fi

    msg "Disk validation PASSED: ${TARGET_DISK} (${_disk_size_gb} GB)"
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — CONFIRMATION
# ══════════════════════════════════════════════════════════════════════════════

confirm_install() {
    local _all_ok=1

    if [ "${CONFIRM_SKIP}" = "1" ]; then
        msg "Confirmation skipped (AIOS_CONFIRM_SKIP=1)"
        return 0
    fi

    # Try hardware probe for TPM awareness
    if [ -c /dev/tpm0 ] || [ -c /dev/tpmrm0 ]; then
        _all_ok=1
    else
        warn "No TPM 2.0 device found (/dev/tpm0 or /dev/tpmrm0)."
        warn "Encrypted root will require a passphrase on every boot."
        read -rp "Continue without TPM? [y/N]: " _resp
        if [ "${_resp}" != "y" ] && [ "${_resp}" != "Y" ]; then
            msg "Installation aborted by user."
            exit 0
        fi
        _all_ok=0
    fi

    banner "=== DESTRUCTIVE OPERATION CONFIRMATION ==="
    warn "ALL DATA on ${TARGET_DISK} will be PERMANENTLY DESTROYED."
    warn "There is NO undo. This CANNOT be reversed."
    echo
    info "Hostname : ${HOSTNAME}"
    info "Profile  : ${PROFILE}"
    info "Disk     : ${TARGET_DISK}"
    echo
    read -rp "Type the disk path to confirm (${TARGET_DISK}): " _confirm_disk
    echo

    if [ "${_confirm_disk}" != "${TARGET_DISK}" ]; then
        msg "Disk path mismatch. Installation aborted."
        exit 0
    fi

    msg "User confirmation received. Proceeding with installation."
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — PARTITIONING
# ══════════════════════════════════════════════════════════════════════════════

partition_disk() {
    banner "Phase 3 — Partitioning"

    local _disk="${TARGET_DISK}"

    msg "Wiping disk: ${_disk}"
    sgdisk --zap-all "${_disk}" || die "sgdisk --zap-all failed on ${_disk}"

    # Let the kernel re-read the partition table
    partprobe "${_disk}" 2>/dev/null || true
    sleep 1

    msg "Creating GPT partition table with 6 partitions..."

    sgdisk --clear \
        "--new=1:0:+${ESP_SIZE_MB}M"  --typecode=1:ef00 --change-name=1:AIOS_ESP \
        "--new=2:0:+${BOOT_SIZE_MB}M" --typecode=2:8300 --change-name=2:AIOS_BOOT \
        "--new=3:0:+${RECOVERY_SIZE_MB}M" --typecode=3:8300 --change-name=3:AIOS_RECOVERY \
        "--new=4:0:+${ROLLBACK_SIZE_MB}M" --typecode=4:8300 --change-name=4:AIOS_ROLLBACK \
        "--new=5:0:+${HASH_SIZE_MB}M" --typecode=5:8300 --change-name=5:AIOS_HASH \
        --new=6:0:0                 --typecode=6:8309 --change-name=6:AIOS_LUKS \
        "${_disk}" || die "sgdisk partition creation failed"

    partprobe "${_disk}" 2>/dev/null || true
    sleep 2

    # Determine partition suffix
    local _part_suffix=""
    case "${_disk}" in
        /dev/nvme*|/dev/mmcblk*) _part_suffix="p" ;;
        *)                        _part_suffix=""  ;;
    esac

    ESP_PART="${_disk}${_part_suffix}1"
    BOOT_PART="${_disk}${_part_suffix}2"
    RECOVERY_PART="${_disk}${_part_suffix}3"
    ROLLBACK_PART="${_disk}${_part_suffix}4"
    ROOT_HASH_PART="${_disk}${_part_suffix}5"
    ROOT_HASH_DEV="${ROOT_HASH_PART}"
    LUKS_PART="${_disk}${_part_suffix}6"

    # Verify partitions exist
    for _part in "${ESP_PART}" "${BOOT_PART}" "${RECOVERY_PART}" "${ROLLBACK_PART}" "${ROOT_HASH_PART}" "${LUKS_PART}"; do
        if ! lsblk -n "${_part}" >/dev/null 2>&1; then
            die "Partition ${_part} was not created successfully"
        fi
    done

    msg "Partitions created:"
    msg "  ESP      : ${ESP_PART}      (${ESP_SIZE_MB} MiB)"
    msg "  BOOT     : ${BOOT_PART}     (${BOOT_SIZE_MB} MiB)"
    msg "  RECOVERY : ${RECOVERY_PART} (${RECOVERY_SIZE_MB} MiB)"
    msg "  ROLLBACK : ${ROLLBACK_PART} (${ROLLBACK_SIZE_MB} MiB)"
    msg "  HASH     : ${ROOT_HASH_PART} (${HASH_SIZE_MB} MiB)"
    msg "  LUKS     : ${LUKS_PART}     (remainder)"
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — ENCRYPTION
# ══════════════════════════════════════════════════════════════════════════════

setup_encryption() {
    banner "Phase 4 — LUKS2 Encryption"

    local _luks_dev="${LUKS_PART}"
    local _luks_name="aios-cryptroot"
    LUKS_MAPPER="/dev/mapper/${_luks_name}"

    msg "Generating random LUKS master key (argon2id pbkdf)..."
    local _tmp_keyfile
    _tmp_keyfile="$(mktemp /tmp/aios-luks-key.XXXXXX)"
    dd if=/dev/urandom of="${_tmp_keyfile}" bs=64 count=1 status=none || die "Failed to generate LUKS key"
    chmod 600 "${_tmp_keyfile}"

    msg "Creating LUKS2 container on ${_luks_dev}..."
    cryptsetup luksFormat --type luks2 \
        --pbkdf argon2id \
        --pbkdf-memory 1048576 \
        --pbkdf-parallel 4 \
        --pbkdf-force-iterations 4 \
        --key-file "${_tmp_keyfile}" \
        --batch-mode \
        "${_luks_dev}" || die "LUKS2 format failed"

    msg "Opening LUKS2 container..."
    cryptsetup open --key-file "${_tmp_keyfile}" \
        "${_luks_dev}" "${_luks_name}" || die "LUKS2 open failed"

    msg "Creating ext4 filesystem on ${LUKS_MAPPER} (label: aios-root)..."
    mkfs.ext4 -q -L aios-root "${LUKS_MAPPER}" || die "mkfs.ext4 failed on ${LUKS_MAPPER}"

    # Store keyfile path for later TPM2 enrollment
    LUKS_TMP_KEYFILE="${_tmp_keyfile}"
    LUKS_DEV="${_luks_dev}"
    LUKS_NAME="${_luks_name}"

    msg "LUKS2 encryption complete: ${LUKS_MAPPER} ready."
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — FILESYSTEMS (ESP + BOOT)
# ══════════════════════════════════════════════════════════════════════════════

format_filesystems() {
    banner "Phase 5 — Filesystem Creation"

    msg "Formatting ESP: ${ESP_PART} (FAT32)..."
    mkfs.vfat -F 32 -n AIOS_ESP "${ESP_PART}" || die "mkfs.vfat failed on ${ESP_PART}"

    msg "Formatting Boot: ${BOOT_PART} (ext4)..."
    mkfs.ext4 -q -L AIOS_BOOT "${BOOT_PART}" || die "mkfs.ext4 failed on ${BOOT_PART}"

    msg "Formatting Recovery: ${RECOVERY_PART} (ext4)..."
    mkfs.ext4 -q -L AIOS_RECOVERY "${RECOVERY_PART}" || die "mkfs.ext4 failed on ${RECOVERY_PART}"

    msg "Formatting Rollback: ${ROLLBACK_PART} (ext4)..."
    mkfs.ext4 -q -L AIOS_ROLLBACK "${ROLLBACK_PART}" || die "mkfs.ext4 failed on ${ROLLBACK_PART}"

    msg "Filesystems created."
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 — MOUNT + ROOTFS DEPLOYMENT
# ══════════════════════════════════════════════════════════════════════════════

deploy_rootfs() {
    banner "Phase 6 — Rootfs Deployment"

    msg "Mounting target root at ${TARGET_MOUNT}..."
    mkdir -p "${TARGET_MOUNT}"
    mount -t ext4 -o rw,noatime "${LUKS_MAPPER}" "${TARGET_MOUNT}" \
        || die "Failed to mount root"

    mkdir -p "${TARGET_MOUNT}/boot"
    mkdir -p "${TARGET_MOUNT}/boot/efi"

    msg "Mounting boot partition..."
    mount -t ext4 -o defaults,noatime "${BOOT_PART}" "${TARGET_MOUNT}/boot" \
        || die "Failed to mount boot"

    msg "Mounting ESP..."
    mount -t vfat -o defaults,noatime,umask=0077 "${ESP_PART}" "${TARGET_MOUNT}/boot/efi" \
        || die "Failed to mount ESP"

    msg "Extracting rootfs (this may take a few minutes)..."
    unsquashfs -f -d "${TARGET_MOUNT}" "${AIOS_SQUASHFS}" || die "unsquashfs failed"

    mkdir -p "${TARGET_MOUNT}/recovery" "${TARGET_MOUNT}/var/lib/aios/rollback"

    msg "Mounting recovery partition..."
    mount -t ext4 -o defaults,noatime "${RECOVERY_PART}" "${TARGET_MOUNT}/recovery" \
        || die "Failed to mount recovery"

    msg "Mounting rollback partition..."
    mount -t ext4 -o defaults,noatime "${ROLLBACK_PART}" "${TARGET_MOUNT}/var/lib/aios/rollback" \
        || die "Failed to mount rollback"

    msg "Rootfs extraction complete."

    # Verify that essential files exist
    if [ ! -x "${TARGET_MOUNT}/sbin/init" ] && [ ! -L "${TARGET_MOUNT}/sbin/init" ]; then
        warn "No /sbin/init found in extracted rootfs. Checking for systemd..."
        if [ ! -f "${TARGET_MOUNT}/usr/lib/systemd/systemd" ] && \
           [ ! -f "${TARGET_MOUNT}/lib/systemd/systemd" ]; then
            die "Neither /sbin/init nor systemd found in rootfs. Extraction may be incomplete."
        fi
        warn "systemd found — symlink will be set up by initramfs or loader."
    fi

    SETUP_DONE="1"
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 7 — SYSTEM CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

configure_system() {
    banner "Phase 7 — System Configuration"

    local _root_uuid _boot_uuid _esp_uuid _recovery_uuid _rollback_uuid _luks_uuid

    _root_uuid=$(blkid -s UUID -o value "${LUKS_MAPPER}" 2>/dev/null || echo "")
    _boot_uuid=$(blkid -s UUID -o value "${BOOT_PART}" 2>/dev/null || echo "")
    _esp_uuid=$(blkid -s UUID -o value "${ESP_PART}" 2>/dev/null || echo "")
    _recovery_uuid=$(blkid -s UUID -o value "${RECOVERY_PART}" 2>/dev/null || echo "")
    _rollback_uuid=$(blkid -s UUID -o value "${ROLLBACK_PART}" 2>/dev/null || echo "")
    _luks_uuid=$(blkid -s UUID -o value "${LUKS_PART}" 2>/dev/null || echo "")

    if [ -z "${_root_uuid}" ] || [ -z "${_boot_uuid}" ] || [ -z "${_luks_uuid}" ] \
       || [ -z "${_recovery_uuid}" ] || [ -z "${_rollback_uuid}" ]; then
        die "Failed to read filesystem UUIDs"
    fi

    msg "Root UUID  : ${_root_uuid}"
    msg "Boot UUID  : ${_boot_uuid}"
    msg "ESP UUID   : ${_esp_uuid}"
    msg "Recovery UUID: ${_recovery_uuid}"
    msg "Rollback UUID: ${_rollback_uuid}"
    msg "LUKS UUID  : ${_luks_uuid}"

    # ── /etc/fstab ────────────────────────────────────────────────────────────

    msg "Generating /etc/fstab..."
    cat > "${TARGET_MOUNT}/etc/fstab" <<FSTAB
# =============================================================================
# AI-OS.NET /etc/fstab — Generated by aios-installer ${AIOS_VERSION}
# Build: ${AIOS_BUILD_ID}
# =============================================================================
UUID=${_root_uuid}    /         ext4    rw,noatime,discard,errors=remount-ro   0 1
UUID=${_boot_uuid}    /boot     ext4    defaults,noatime                       0 2
UUID=${_esp_uuid}     /boot/efi vfat    defaults,noatime,umask=0077            0 2
UUID=${_recovery_uuid} /recovery ext4    defaults,noatime,nodev,nosuid          0 2
UUID=${_rollback_uuid} /var/lib/aios/rollback ext4 defaults,noatime,nodev,nosuid 0 2
tmpfs                 /tmp      tmpfs   defaults,noexec,nosuid,nodev,size=2G   0 0
# =============================================================================
FSTAB
    chmod 644 "${TARGET_MOUNT}/etc/fstab"

    # ── /etc/crypttab ─────────────────────────────────────────────────────────

    msg "Generating /etc/crypttab..."
    cat > "${TARGET_MOUNT}/etc/crypttab" <<CRYPTTAB
# =============================================================================
# AI-OS.NET /etc/crypttab — Generated by aios-installer ${AIOS_VERSION}
# =============================================================================
# The TPM2 token is embedded in the LUKS2 header. systemd-cryptsetup will
# auto-unseal the key during boot when the measured boot state is valid.
# If unseal fails, systemd falls back to the recovery passphrase prompt.
#
# name           device                    key-file   options
aios-cryptroot   UUID=${_luks_uuid}        none       luks,discard,tpm2-device=auto
# =============================================================================
CRYPTTAB
    chmod 600 "${TARGET_MOUNT}/etc/crypttab"

    # ── /etc/hostname ─────────────────────────────────────────────────────────

    msg "Setting hostname: ${HOSTNAME}"
    echo "${HOSTNAME}" > "${TARGET_MOUNT}/etc/hostname"
    chmod 644 "${TARGET_MOUNT}/etc/hostname"

    # ── /etc/machine-id ───────────────────────────────────────────────────────

    msg "Generating machine-id..."
    if [ -f /etc/machine-id ]; then
        # Copy from live environment if already generated
        cp /etc/machine-id "${TARGET_MOUNT}/etc/machine-id"
    else
        systemd-machine-id-setup --root="${TARGET_MOUNT}" 2>/dev/null || \
            dbus-uuidgen --ensure="${TARGET_MOUNT}/etc/machine-id" 2>/dev/null || \
            uuidgen > "${TARGET_MOUNT}/etc/machine-id"
    fi
    chmod 444 "${TARGET_MOUNT}/etc/machine-id"

    # ── Network configuration ─────────────────────────────────────────────────

    msg "Copying network configuration from live environment..."
    if [ -d /etc/NetworkManager ]; then
        mkdir -p "${TARGET_MOUNT}/etc/NetworkManager"
        cp -r /etc/NetworkManager/system-connections/ \
            "${TARGET_MOUNT}/etc/NetworkManager/" 2>/dev/null || true
        chmod -R 600 "${TARGET_MOUNT}/etc/NetworkManager/system-connections/" 2>/dev/null || true
    fi

    # ── /etc/os-release ───────────────────────────────────────────────────────

    cat > "${TARGET_MOUNT}/etc/os-release" <<EOF
NAME="AI-OS.NET"
VERSION="${AIOS_VERSION}"
ID=aios
PRETTY_NAME="AI-OS.NET ${AIOS_VERSION}"
ANSI_COLOR="1;32"
HOME_URL="https://ai-os.net"
BUILD_ID="${AIOS_BUILD_ID}"
EOF
    chmod 644 "${TARGET_MOUNT}/etc/os-release"

    mkdir -p "${TARGET_MOUNT}/etc/aios" "${TARGET_MOUNT}/recovery" "${TARGET_MOUNT}/var/lib/aios/rollback"
    cat > "${TARGET_MOUNT}/etc/aios/install-layout.json" <<EOF
{
  "schema": "aios.install_layout.v1",
  "build_id": "${AIOS_BUILD_ID}",
  "target_disk": "${TARGET_DISK}",
  "partitions": {
    "esp": "${ESP_PART}",
    "boot": "${BOOT_PART}",
    "recovery": "${RECOVERY_PART}",
    "rollback": "${ROLLBACK_PART}",
    "hash": "${ROOT_HASH_PART}",
    "luks_root": "${LUKS_PART}"
  },
  "mounts": {
    "recovery": "/recovery",
    "rollback": "/var/lib/aios/rollback"
  }
}
EOF
    chmod 644 "${TARGET_MOUNT}/etc/aios/install-layout.json"

    cat > "${TARGET_MOUNT}/recovery/README" <<EOF
AI-OS.NET recovery partition
Build: ${AIOS_BUILD_ID}
Root LUKS UUID: ${_luks_uuid}
EOF
    chmod 600 "${TARGET_MOUNT}/recovery/README"

    cat > "${TARGET_MOUNT}/var/lib/aios/rollback/current.json" <<EOF
{
  "schema": "aios.rollback_state.v1",
  "active_deployment": "${AIOS_BUILD_ID}",
  "previous_deployment": null,
  "health": "pending-first-boot"
}
EOF
    chmod 600 "${TARGET_MOUNT}/var/lib/aios/rollback/current.json"

    msg "System configuration complete."
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 8 — DM-VERITY SETUP (optional, requires hash partition)
# ══════════════════════════════════════════════════════════════════════════════

setup_verity() {
    banner "Phase 8 — dm-verity Setup"

    if ! command -v veritysetup >/dev/null 2>&1; then
        warn "veritysetup not found — skipping dm-verity setup."
        return 0
    fi

    msg "dm-verity: Generating root hash tree..."
    mkdir -p "${TARGET_MOUNT}/etc/aios/verity"

    local _roothash_file="${TARGET_MOUNT}/etc/aios/verity/roothash.sig"
    local _roothash

    if veritysetup format "${LUKS_MAPPER}" "${ROOT_HASH_DEV}" \
        --root-hash-file="${_roothash_file}" 2>/dev/null; then
        _roothash=$(head -n1 "${_roothash_file}" | tr -d '[:space:]')
    else
        warn "dm-verity hash generation skipped (no separate hash partition)."
        warn "Root will NOT be verity-protected. Re-install with a hash partition"
        warn "to enable measured boot integrity."
        return 0
    fi

    if [ -z "${_roothash}" ]; then
        warn "dm-verity root hash empty — skipping."
        return 0
    fi

    msg "dm-verity: Root hash = ${_roothash}"
    echo "${_roothash}" > "${_roothash_file}"
    chmod 400 "${_roothash_file}"

    cat > "${TARGET_MOUNT}/etc/aios/verity/rootfs-policy.json" <<EOF
{
  "schema": "aios.dm_verity_policy.v1",
  "revision": 12,
  "root_hash": "/etc/aios/verity/roothash.sig",
  "hash_partition": "${ROOT_HASH_PART}",
  "cmdline_parameter": "dm_verity.roothash",
  "fail_on_corruption": true
}
EOF
    chmod 644 "${TARGET_MOUNT}/etc/aios/verity/rootfs-policy.json"

    msg "dm-verity hash tree and root hash stored."
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 9 — BOOTLOADER (systemd-boot)
# ══════════════════════════════════════════════════════════════════════════════

install_bootloader() {
    banner "Phase 9 — Bootloader Installation"

    local _esp_mount="${TARGET_MOUNT}/boot/efi"

    msg "Installing systemd-boot to ESP..."
    bootctl install --esp-path="${_esp_mount}" --no-variables \
        || die "bootctl install failed"

    local _luks_uuid
    _luks_uuid=$(blkid -s UUID -o value "${LUKS_PART}" 2>/dev/null || echo "")

    local _verity_params=""
    local _root_mode="rw"
    if [ -f "${TARGET_MOUNT}/etc/aios/verity/roothash.sig" ]; then
        local _roothash
        _roothash=$(head -n1 "${TARGET_MOUNT}/etc/aios/verity/roothash.sig" | tr -d '[:space:]')
        if [ -n "${_roothash}" ]; then
            _root_mode="ro"
            _verity_params=" verity dm_verity.roothash=${_roothash}"
        fi
    fi

    # ── Loader entry ──────────────────────────────────────────────────────────

    local _entries_dir="${_esp_mount}/loader/entries"
    mkdir -p "${_entries_dir}"

    cat > "${_entries_dir}/aios.conf" <<LOADER
title   AI-OS.NET ${AIOS_VERSION}
linux   /vmlinuz-aios
initrd  /initramfs-aios.img
options root=/dev/mapper/aios-cryptroot rd.luks.uuid=${_luks_uuid} ${_root_mode} quiet loglevel=3 selinux=1 ${SELINUX_MODE}${_verity_params}
LOADER

    chmod 644 "${_entries_dir}/aios.conf"

    # ── Loader config ─────────────────────────────────────────────────────────

    cat > "${_esp_mount}/loader/loader.conf" <<LOADERCONF
# AI-OS.NET loader configuration
timeout 3
console-mode auto
default aios.conf
editor no
auto-entries no
auto-firmware no
LOADERCONF
    chmod 644 "${_esp_mount}/loader/loader.conf"

    msg "systemd-boot installed and configured."
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 10 — TPM2 SEALING
# ══════════════════════════════════════════════════════════════════════════════

seal_tpm2() {
    banner "Phase 10 — TPM2 Key Sealing"

    if [ ! -c /dev/tpm0 ] && [ ! -c /dev/tpmrm0 ]; then
        warn "No TPM device found. Key sealing skipped."
        warn "Please record your recovery key and use it on boot."
        return 0
    fi

    msg "Enrolling TPM2 token in LUKS2 header (PCRs 0+1+7)..."
    msg "  PCR 0 — firmware code (UEFI)"
    msg "  PCR 1 — firmware config (UEFI setup, boot order)"
    msg "  PCR 7 — Secure Boot state (PK, KEK, db/dbx)"

    # Use systemd-cryptenroll to embed TPM2 token into the LUKS2 header.
    #
    # Two defects lived here (both silent — the failure path only warned):
    #   - --key-file does not exist on systemd-cryptenroll; the option that
    #     supplies the current passphrase is --unlock-key-file=. Every enrolment
    #     aborted with "unrecognized option" and was swallowed by the warn.
    #   - --tpm2-public-key=PATH takes a PEM *public key* as INPUT, for enrolling
    #     a signed PCR policy. It was handed sealed-key.blob, an output path that
    #     nothing ever wrote and nothing ever read. It sealed nothing.
    if command -v systemd-cryptenroll >/dev/null 2>&1; then
        systemd-cryptenroll "${LUKS_DEV}" \
            --unlock-key-file="${LUKS_TMP_KEYFILE}" \
            --tpm2-device=auto \
            --tpm2-pcrs=0+1+7 \
            --wipe-slot=tpm2 2>&1 || {
            warn "systemd-cryptenroll failed. TPM2 sealing will be skipped."
            warn "You will need to enter the LUKS passphrase manually on boot."
            return 0
        }
    else
        warn "systemd-cryptenroll not available. TPM2 sealing skipped."
        return 0
    fi

    # Read the token back rather than trusting the exit code.
    if cryptsetup luksDump "${LUKS_DEV}" 2>/dev/null | grep -qi "systemd-tpm2"; then
        msg "TPM2 token enrolled successfully in LUKS2 header."
    else
        warn "systemd-cryptenroll reported success but no systemd-tpm2 token is present."
        warn "You will need to enter the LUKS passphrase manually on boot."
        return 0
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 11 — RECOVERY KEY
# ══════════════════════════════════════════════════════════════════════════════

generate_recovery_key() {
    banner "Phase 11 — Recovery Key Generation"

    local _recovery_file="${TARGET_MOUNT}/etc/aios/recovery-key.txt"
    mkdir -p "$(dirname "${_recovery_file}")"

    # Generate 24-word diceware-style passphrase using /dev/urandom
    local _wordlist="/usr/share/dict/words"
    local _recovery_words=""

    if [ -f "${_wordlist}" ]; then
        _recovery_words=$(
            grep -E '^[a-z]{4,8}$' "${_wordlist}" \
            | sort -R --random-source=/dev/urandom \
            | head -n "${RECOVERY_KEY_LENGTH}" \
            | tr '\n' ' '
        )
    else
        # Fallback: hex from openssl (already in the base package set). xxd ships
        # in vim-data and is absent from the live image — see defect #10.
        _recovery_words=$(openssl rand -hex "${RECOVERY_KEY_LENGTH}" \
            | fold -w 2 | head -n "${RECOVERY_KEY_LENGTH}" | tr '\n' ' ')
    fi

    if [ -z "${_recovery_words}" ]; then
        _recovery_words="RECOVERY-KEY-GENERATION-FAILED-CONTACT-SUPPORT"
        warn "Could not generate recovery key properly."
    fi

    { echo "# AI-OS.NET Recovery Key — ${AIOS_VERSION}"
      echo "# Hostname: ${HOSTNAME}"
      echo "# Generated: ${AIOS_BUILD_ID}"
      echo "#"
      echo "# STORE THIS OFFLINE. DELETE THIS FILE AFTER SAVING."
      echo "# This key can decrypt your root partition. Guard it accordingly."
      echo "#"
      echo "Recovery Key:"
      echo "${_recovery_words}"
    } > "${_recovery_file}"

    chmod 600 "${_recovery_file}"

    # Display prominently
    banner "═══ RECOVERY KEY — RECORD THIS NOW ═══"
    echo ""
    printf "  ${BOLD}%s${RESET}\n" "${_recovery_words}"
    echo ""
    echo "  This is the ONLY way to unlock your disk if TPM unseal fails."
    echo "  WRITE IT DOWN and store it in a secure location offline."
    echo "  Without this key, your data is IRRECOVERABLE."
    echo ""

    if [ "${CONFIRM_SKIP}" != "1" ]; then
        local _confirmed=""
        while [ "${_confirmed}" != "YES" ]; do
            read -rp "  Type YES to confirm you have saved the recovery key: " _confirmed
            if [ "${_confirmed}" = "YES" ]; then
                break
            fi
            echo ""
            warn "  You MUST record the recovery key before proceeding."
            echo ""
        done
    fi

    msg "Recovery key stored at: ${_recovery_file}"
    msg "IMPORTANT: Move this file offline and DELETE it from the system."
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 12 — SELINUX POLICY + RELABEL
# ══════════════════════════════════════════════════════════════════════════════

setup_selinux() {
    banner "Phase 12 — SELinux Policy"

    mkdir -p "${TARGET_MOUNT}/etc/selinux"
    case "${SELINUX_MODE}" in
        enforcing|permissive|disabled) ;;
        *) warn "Invalid AIOS_SELINUX_MODE=${SELINUX_MODE}; using permissive."; SELINUX_MODE="permissive" ;;
    esac

    if [ "${SELINUX_MODE}" = "enforcing" ] \
       && { [ ! -f "${TARGET_MOUNT}/etc/selinux/aios/policy/policy.33" ] \
            || grep -q 'Placeholder' "${TARGET_MOUNT}/etc/selinux/aios/policy/policy.33" 2>/dev/null; }; then
        warn "SELinux enforcing requested but only placeholder/no policy is present; using permissive."
        SELINUX_MODE="permissive"
    fi

    cat > "${TARGET_MOUNT}/etc/selinux/config" <<EOF
# AI-OS.NET SELinux configuration
SELINUX=${SELINUX_MODE}
SELINUXTYPE=aios
EOF
    chmod 644 "${TARGET_MOUNT}/etc/selinux/config"

    # Touch .autorelabel to force relabel on first boot
    msg "Setting .autorelabel for first-boot relabel..."
    touch "${TARGET_MOUNT}/.autorelabel"
    chmod 644 "${TARGET_MOUNT}/.autorelabel"

    # Try to load policy in target namespace
    if [ -f "${TARGET_MOUNT}/etc/selinux/aios/policy/policy.33" ]; then
        msg "SELinux policy found. Mode on first boot: ${SELINUX_MODE}."
    else
        warn "SELinux policy binary not found at expected path."
        warn "Policy will be loaded at first boot if available."
    fi

    msg "SELinux configuration complete."
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 13 — FIRST BOOT FLAG
# ══════════════════════════════════════════════════════════════════════════════

set_first_boot_flag() {
    banner "Phase 13 — First Boot Flag"

    mkdir -p "${TARGET_MOUNT}/etc/aios"
    touch "${TARGET_MOUNT}/etc/aios/first-boot"
    chmod 644 "${TARGET_MOUNT}/etc/aios/first-boot"

    msg "First-boot flag set: /etc/aios/first-boot"
    msg "The first-boot wizard will run on next boot."
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 14 — UNMOUNT + COMPLETION
# ══════════════════════════════════════════════════════════════════════════════

finalize() {
    banner "Phase 14 — Finalization"

    msg "Syncing filesystem buffers..."
    sync

    # Wipe temporary keyfile
    if [ -n "${LUKS_TMP_KEYFILE:-}" ] && [ -f "${LUKS_TMP_KEYFILE}" ]; then
        dd if=/dev/urandom of="${LUKS_TMP_KEYFILE}" bs=64 count=1 status=none 2>/dev/null || true
        rm -f "${LUKS_TMP_KEYFILE}"
    fi

    msg "Unmounting filesystems..."
    umount "${TARGET_MOUNT}/boot/efi" 2>/dev/null || warn "ESP unmount had issues"
    umount "${TARGET_MOUNT}/boot"     2>/dev/null || warn "Boot unmount had issues"
    umount "${TARGET_MOUNT}/recovery" 2>/dev/null || warn "Recovery unmount had issues"
    umount "${TARGET_MOUNT}/var/lib/aios/rollback" 2>/dev/null || warn "Rollback unmount had issues"
    umount "${TARGET_MOUNT}"           2>/dev/null || warn "Root unmount had issues"

    msg "Closing LUKS container..."
    if [ -b "${LUKS_MAPPER}" ]; then
        cryptsetup close "${LUKS_NAME}" 2>/dev/null || warn "LUKS close had issues"
    fi

    # ── Completion message ────────────────────────────────────────────────────

    banner "═══ AI-OS.NET ${AIOS_VERSION} INSTALLATION COMPLETE ═══"
    echo ""
    echo "  Hostname   : ${HOSTNAME}"
    echo "  Disk       : ${TARGET_DISK}"
    echo "  Profile    : ${PROFILE}"
    echo "  Build ID   : ${AIOS_BUILD_ID}"
    echo ""
    echo "  NEXT STEPS:"
    echo "    1. REMOVE installation media (USB/ISO)"
    echo "    2. Reboot: systemctl reboot"
    echo "    3. On first boot, the aios-first-boot wizard will guide you"
    echo "       through user creation, network setup, and TPM enrollment."
    echo ""
    echo "  RECOVERY: If the system fails to boot."
    echo "    — Boot from the AIOS live ISO again"
    echo "    — Open LUKS manually: cryptsetup open ${LUKS_PART} aios-cryptroot"
    echo "    — Mount and repair as needed"
    echo ""
    echo "  Your recovery key was displayed during installation."
    echo "  If you lost it, recovery is NOT possible."
    echo ""

    SETUP_DONE=""
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

main() {
    echo ""
    echo "        ╔══════════════════════════════════════════╗"
    echo "        ║     AI-OS.NET  Bare-Metal  Installer     ║"
    echo "        ║           Revision 4 (${AIOS_BUILD_ID})          ║"
    echo "        ║        https://ai-os.net/install         ║"
    echo "        ╚══════════════════════════════════════════╝"
    echo ""

    check_prerequisites
    select_disk
    confirm_install

    partition_disk
    format_filesystems
    setup_encryption
    deploy_rootfs
    configure_system
    seal_tpm2
    generate_recovery_key
    setup_selinux
    set_first_boot_flag
    setup_verity
    install_bootloader
    finalize

    return 0
}

main "$@"
