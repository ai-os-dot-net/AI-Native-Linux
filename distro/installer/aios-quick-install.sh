#!/bin/bash
set -euo pipefail

# =============================================================================
# AI-OS.NET Quick (Non-Interactive) Installer — Revision 4
# =============================================================================
# Fully automated installer for CI pipelines, fleet provisioning, and
# pre-configured VM/cloud images. Takes all parameters from environment
# variables — no TTY required.
#
# MANDATORY ENVIRONMENT VARIABLES:
#   AIOS_TARGET_DISK         Target block device (e.g. /dev/sda)
#   AIOS_HOSTNAME            System hostname
#   AIOS_CONFIRM_SKIP=1      Must be set (by caller) — suppresses all prompts
#
# OPTIONAL ENVIRONMENT VARIABLES:
#   AIOS_PROFILE             Security profile (default: CI_BARE)
#   AIOS_ESP_SIZE_MB         ESP size in MiB (default: 512)
#   AIOS_BOOT_SIZE_MB        Boot size in MiB (default: 1024)
#   AIOS_RECOVERY_SIZE_MB    Recovery partition size in MiB (default: 2048)
#   AIOS_ROLLBACK_SIZE_MB    Rollback partition size in MiB (default: 4096)
#   AIOS_HASH_SIZE_MB        dm-verity hash partition size in MiB (default: 1024)
#   AIOS_MIN_DISK_GB         Minimum disk GB (default: 40)
#   AIOS_SQUASHFS            Path to squashed rootfs (auto-detected if unset)
#   AIOS_SKIP_VERITY=1       Skip dm-verity setup
#   AIOS_SKIP_TPM=1          Skip TPM2 sealing
#   AIOS_SKIP_SELINUX=1      Skip SELinux setup
#   AIOS_SELINUX_MODE        SELinux mode (permissive|enforcing|disabled)
#
# EXIT CODES:
#   0   Success
#   1   Generic error
#   2   Invalid arguments / missing environment
#   3   Disk validation failed
#   4   Partitioning failed
#   5   Encryption failed
#   6   Filesystem error
#   7   Rootfs extraction failed
#   8   Bootloader install failed
#
# USAGE:
#   AIOS_TARGET_DISK=/dev/vda AIOS_HOSTNAME=aios-ci AIOS_CONFIRM_SKIP=1 \
#     bash aios-quick-install.sh
# =============================================================================

readonly AIOS_VERSION="REV4"
AIOS_BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)"
readonly AIOS_BUILD_ID

# ── Log helpers (no colour, structured for CI log parsers) ────────────────────

msg()  { printf "[AIOS-QUICK]  OK   %s\n" "$*"; }
warn() { printf "[AIOS-QUICK]  WARN  %s\n" "$*" >&2; }
err()  { printf "[AIOS-QUICK]  ERROR %s\n" "$*" >&2; }
info() { printf "[AIOS-QUICK]  INFO  %s\n" "$*"; }

die() {
    local _code="${2:-1}"
    err "$1 (exit code ${_code})"
    cleanup_on_failure
    exit "${_code}"
}

# ── Cleanup ───────────────────────────────────────────────────────────────────

TARGET_MOUNT="/mnt/aios-target"
LUKS_TMP_KEYFILE="/tmp/aios-quick-luks-key.XXXXXX"
SETUP_MOUNTED=0

cleanup_on_failure() {
    warn "=== Cleanup after failure ==="
    if [ "${SETUP_MOUNTED}" -eq 1 ]; then
        umount "${TARGET_MOUNT}/boot/efi" 2>/dev/null || true
        umount "${TARGET_MOUNT}/boot"     2>/dev/null || true
        umount "${TARGET_MOUNT}/recovery" 2>/dev/null || true
        umount "${TARGET_MOUNT}/var/lib/aios/rollback" 2>/dev/null || true
        umount "${TARGET_MOUNT}"           2>/dev/null || true
    fi
    if [ -b "/dev/mapper/aios-cryptroot" ]; then
        cryptsetup close aios-cryptroot 2>/dev/null || true
    fi
    rm -f "${LUKS_TMP_KEYFILE}" 2>/dev/null || true
}

trap 'cleanup_on_failure' ERR
trap 'cleanup_on_failure; exit 130' INT TERM

# ── Validate environment ──────────────────────────────────────────────────────

validate_env() {
    info "=== Validating environment ==="

    if [ "$(id -u)" -ne 0 ]; then
        die "Must run as root" 2
    fi

    if [ -z "${AIOS_TARGET_DISK:-}" ]; then
        die "AIOS_TARGET_DISK is required" 2
    fi
    TARGET_DISK="${AIOS_TARGET_DISK}"

    if [ -z "${AIOS_HOSTNAME:-}" ]; then
        die "AIOS_HOSTNAME is required" 2
    fi
    HOSTNAME="${AIOS_HOSTNAME}"

    if [ "${AIOS_CONFIRM_SKIP:-}" != "1" ]; then
        die "AIOS_CONFIRM_SKIP must be '1' for non-interactive mode" 2
    fi

    PROFILE="${AIOS_PROFILE:-CI_BARE}"
    ESP_SIZE_MB="${AIOS_ESP_SIZE_MB:-512}"
    BOOT_SIZE_MB="${AIOS_BOOT_SIZE_MB:-1024}"
    RECOVERY_SIZE_MB="${AIOS_RECOVERY_SIZE_MB:-2048}"
    ROLLBACK_SIZE_MB="${AIOS_ROLLBACK_SIZE_MB:-4096}"
    HASH_SIZE_MB="${AIOS_HASH_SIZE_MB:-1024}"
    MIN_DISK_GB="${AIOS_MIN_DISK_GB:-40}"
    SELINUX_MODE="${AIOS_SELINUX_MODE:-permissive}"
    AIOS_SQUASHFS="${AIOS_SQUASHFS:-/run/initramfs/live/aios.squashfs}"

    if [ ! -f "${AIOS_SQUASHFS}" ]; then
        # /run/initramfs/live-media is where OUR initramfs (distro/aios-boot/
        # initramfs/init, try_mount_live_medium) mounts the live ISO; /run is
        # mount --move'd wholesale into the real root at switch_root (init
        # Step 6), so the path survives into the running live system. The
        # remaining entries are dracut/archiso/live-boot conventions kept as
        # fallbacks.
        for _alt in /run/initramfs/live-media/live/aios.squashfs \
                    /run/initramfs/live/filesystem.squashfs \
                    /run/archiso/bootmnt/aios.squashfs \
                    /run/live/medium/aios.squashfs; do
            if [ -f "${_alt}" ]; then
                AIOS_SQUASHFS="${_alt}"
                break
            fi
        done
    fi

    if [ ! -f "${AIOS_SQUASHFS}" ]; then
        die "Squashfs not found at ${AIOS_SQUASHFS}" 2
    fi

    # Validate disk
    if [ ! -b "${TARGET_DISK}" ]; then
        die "Not a valid block device: ${TARGET_DISK}" 3
    fi

    local _size_gb
    _size_gb=$(lsblk -b -d -n -o SIZE "${TARGET_DISK}" 2>/dev/null || echo 0)
    _size_gb=$(( _size_gb / 1024 / 1024 / 1024 ))
    if [ "${_size_gb}" -lt "${MIN_DISK_GB}" ]; then
        die "Disk too small: ${_size_gb}GB < ${MIN_DISK_GB}GB min" 3
    fi

    if mount | grep -q "^${TARGET_DISK}"; then
        die "Disk is currently mounted: ${TARGET_DISK}" 3
    fi

    # Tool check
    for _bin in lsblk sgdisk mkfs.vfat mkfs.ext4 cryptsetup unsquashfs bootctl blkid; do
        if ! command -v "${_bin}" >/dev/null 2>&1; then
            die "Missing required tool: ${_bin}" 2
        fi
    done

    info "Environment validated: disk=${TARGET_DISK} host=${HOSTNAME} profile=${PROFILE}"
}

# ── Partition ─────────────────────────────────────────────────────────────────

do_partition() {
    info "=== Partitioning ${TARGET_DISK} ==="

    sgdisk --zap-all "${TARGET_DISK}" || die "sgdisk --zap-all failed" 4
    partprobe "${TARGET_DISK}" 2>/dev/null || true
    sleep 1

    sgdisk --clear \
        "--new=1:0:+${ESP_SIZE_MB}M"  --typecode=1:ef00 --change-name=1:AIOS_ESP \
        "--new=2:0:+${BOOT_SIZE_MB}M" --typecode=2:8300 --change-name=2:AIOS_BOOT \
        "--new=3:0:+${RECOVERY_SIZE_MB}M" --typecode=3:8300 --change-name=3:AIOS_RECOVERY \
        "--new=4:0:+${ROLLBACK_SIZE_MB}M" --typecode=4:8300 --change-name=4:AIOS_ROLLBACK \
        "--new=5:0:+${HASH_SIZE_MB}M" --typecode=5:8300 --change-name=5:AIOS_HASH \
        --new=6:0:0                 --typecode=6:8309 --change-name=6:AIOS_LUKS \
        "${TARGET_DISK}" || die "Partition creation failed" 4

    partprobe "${TARGET_DISK}" 2>/dev/null || true
    sleep 2

    # Determine partition suffix
    local _suffix=""
    case "${TARGET_DISK}" in
        /dev/nvme*|/dev/mmcblk*) _suffix="p" ;;
        *)                        _suffix=""  ;;
    esac

    ESP_PART="${TARGET_DISK}${_suffix}1"
    BOOT_PART="${TARGET_DISK}${_suffix}2"
    RECOVERY_PART="${TARGET_DISK}${_suffix}3"
    ROLLBACK_PART="${TARGET_DISK}${_suffix}4"
    ROOT_HASH_PART="${TARGET_DISK}${_suffix}5"
    ROOT_HASH_DEV="${ROOT_HASH_PART}"
    LUKS_PART="${TARGET_DISK}${_suffix}6"

    for _p in "${ESP_PART}" "${BOOT_PART}" "${RECOVERY_PART}" "${ROLLBACK_PART}" "${ROOT_HASH_PART}" "${LUKS_PART}"; do
        lsblk -n "${_p}" >/dev/null 2>&1 || die "Partition ${_p} not created" 4
    done

    msg "Partitions: ESP=${ESP_PART} BOOT=${BOOT_PART} RECOVERY=${RECOVERY_PART} ROLLBACK=${ROLLBACK_PART} HASH=${ROOT_HASH_PART} LUKS=${LUKS_PART}"
}

# ── Filesystems ───────────────────────────────────────────────────────────────

do_filesystems() {
    info "=== Creating filesystems ==="
    mkfs.vfat -F 32 -n AIOS_ESP "${ESP_PART}" || die "mkfs.vfat ESP failed" 6
    mkfs.ext4 -q -L AIOS_BOOT "${BOOT_PART}" || die "mkfs.ext4 boot failed" 6
    mkfs.ext4 -q -L AIOS_RECOVERY "${RECOVERY_PART}" || die "mkfs.ext4 recovery failed" 6
    mkfs.ext4 -q -L AIOS_ROLLBACK "${ROLLBACK_PART}" || die "mkfs.ext4 rollback failed" 6
    msg "ESP + BOOT + RECOVERY + ROLLBACK formatted"
}

# ── Encryption ────────────────────────────────────────────────────────────────

do_encryption() {
    info "=== Setting up LUKS2 encryption ==="

    LUKS_TMP_KEYFILE="$(mktemp /tmp/aios-quick-luks-key.XXXXXX)"
    dd if=/dev/urandom of="${LUKS_TMP_KEYFILE}" bs=64 count=1 status=none || die "Keygen failed" 5
    chmod 600 "${LUKS_TMP_KEYFILE}"

    cryptsetup luksFormat --type luks2 \
        --pbkdf argon2id \
        --pbkdf-memory 1048576 \
        --pbkdf-parallel 4 \
        --pbkdf-force-iterations 4 \
        --key-file "${LUKS_TMP_KEYFILE}" \
        --batch-mode \
        "${LUKS_PART}" || die "LUKS2 format failed" 5

    cryptsetup open --key-file "${LUKS_TMP_KEYFILE}" \
        "${LUKS_PART}" aios-cryptroot || die "LUKS open failed" 5

    LUKS_MAPPER="/dev/mapper/aios-cryptroot"
    mkfs.ext4 -q -L aios-root "${LUKS_MAPPER}" || die "mkfs.ext4 root failed" 6

    msg "LUKS2 container opened at ${LUKS_MAPPER}"
}

# ── Mount + extract rootfs ────────────────────────────────────────────────────

do_deploy() {
    info "=== Deploying rootfs ==="

    mkdir -p "${TARGET_MOUNT}"
    mount -t ext4 -o rw,noatime "${LUKS_MAPPER}" "${TARGET_MOUNT}" || die "Root mount failed" 7
    SETUP_MOUNTED=1

    mkdir -p "${TARGET_MOUNT}/boot" "${TARGET_MOUNT}/boot/efi"
    mount -t ext4 -o defaults,noatime "${BOOT_PART}" "${TARGET_MOUNT}/boot" || die "Boot mount failed" 7
    mount -t vfat -o defaults,noatime,umask=0077 "${ESP_PART}" "${TARGET_MOUNT}/boot/efi" || die "ESP mount failed" 7

    msg "Extracting squashfs (${AIOS_SQUASHFS})..."
    unsquashfs -f -d "${TARGET_MOUNT}" "${AIOS_SQUASHFS}" || die "unsquashfs failed" 7

    mkdir -p "${TARGET_MOUNT}/recovery" "${TARGET_MOUNT}/var/lib/aios/rollback"
    mount -t ext4 -o defaults,noatime "${RECOVERY_PART}" "${TARGET_MOUNT}/recovery" \
        || die "Recovery mount failed" 7
    mount -t ext4 -o defaults,noatime "${ROLLBACK_PART}" "${TARGET_MOUNT}/var/lib/aios/rollback" \
        || die "Rollback mount failed" 7

    msg "Rootfs extracted. $(du -sh "${TARGET_MOUNT}" 2>/dev/null | awk '{print $1}') on disk."
}

# ── System configuration ──────────────────────────────────────────────────────

do_configure() {
    info "=== Generating system configuration ==="

    local _root_uuid _boot_uuid _esp_uuid _recovery_uuid _rollback_uuid _luks_uuid
    _root_uuid=$(blkid -s UUID -o value "${LUKS_MAPPER}" 2>/dev/null || echo "")
    _boot_uuid=$(blkid -s UUID -o value "${BOOT_PART}" 2>/dev/null || echo "")
    _esp_uuid=$(blkid -s UUID -o value "${ESP_PART}" 2>/dev/null || echo "")
    _recovery_uuid=$(blkid -s UUID -o value "${RECOVERY_PART}" 2>/dev/null || echo "")
    _rollback_uuid=$(blkid -s UUID -o value "${ROLLBACK_PART}" 2>/dev/null || echo "")
    _luks_uuid=$(blkid -s UUID -o value "${LUKS_PART}" 2>/dev/null || echo "")

    if [ -z "${_root_uuid}" ] || [ -z "${_luks_uuid}" ] || [ -z "${_recovery_uuid}" ] || [ -z "${_rollback_uuid}" ]; then
        die "UUID read failed" 1
    fi

    # /etc/fstab
    cat > "${TARGET_MOUNT}/etc/fstab" <<FSTAB
# AI-OS.NET fstab — CI-generated (${AIOS_BUILD_ID})
UUID=${_root_uuid}    /         ext4    rw,noatime,discard,errors=remount-ro  0 1
UUID=${_boot_uuid}    /boot     ext4    defaults,noatime                      0 2
UUID=${_esp_uuid}     /boot/efi vfat    defaults,noatime,umask=0077           0 2
UUID=${_recovery_uuid} /recovery ext4    defaults,noatime,nodev,nosuid         0 2
UUID=${_rollback_uuid} /var/lib/aios/rollback ext4 defaults,noatime,nodev,nosuid 0 2
tmpfs                 /tmp      tmpfs   defaults,noexec,nosuid,nodev,size=2G  0 0
FSTAB
    chmod 644 "${TARGET_MOUNT}/etc/fstab"

    # /etc/crypttab
    cat > "${TARGET_MOUNT}/etc/crypttab" <<CRYPTTAB
# AI-OS.NET crypttab — CI-generated (${AIOS_BUILD_ID})
aios-cryptroot   UUID=${_luks_uuid}   none   luks,discard,tpm2-device=auto
CRYPTTAB
    chmod 600 "${TARGET_MOUNT}/etc/crypttab"

    # hostname, machine-id
    echo "${HOSTNAME}" > "${TARGET_MOUNT}/etc/hostname"
    chmod 644 "${TARGET_MOUNT}/etc/hostname"
    uuidgen > "${TARGET_MOUNT}/etc/machine-id"
    chmod 444 "${TARGET_MOUNT}/etc/machine-id"

    # os-release
    cat > "${TARGET_MOUNT}/etc/os-release" <<EOF
NAME="AI-OS.NET"
VERSION="${AIOS_VERSION}"
ID=aios
PRETTY_NAME="AI-OS.NET ${AIOS_VERSION} (CI)"
BUILD_ID="${AIOS_BUILD_ID}"
HOME_URL="https://ai-os.net"
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

    msg "System configuration written."
}

# ── Bootloader ────────────────────────────────────────────────────────────────

do_bootloader() {
    info "=== Installing systemd-boot ==="

    bootctl install --esp-path="${TARGET_MOUNT}/boot/efi" --no-variables \
        || die "bootctl install failed" 8

    local _luks_uuid
    _luks_uuid=$(blkid -s UUID -o value "${LUKS_PART}" 2>/dev/null || echo "")

    local _root_mode="rw"
    local _verity_params=""
    if [ -f "${TARGET_MOUNT}/etc/aios/verity/roothash.sig" ]; then
        local _roothash
        _roothash=$(head -n1 "${TARGET_MOUNT}/etc/aios/verity/roothash.sig" | tr -d '[:space:]')
        if [ -n "${_roothash}" ]; then
            _root_mode="ro"
            _verity_params=" verity dm_verity.roothash=${_roothash}"
        fi
    fi

    local _entries_dir="${TARGET_MOUNT}/boot/efi/loader/entries"
    mkdir -p "${_entries_dir}"

    cat > "${_entries_dir}/aios.conf" <<LOADER
title   AI-OS.NET ${AIOS_VERSION} (CI)
linux   /vmlinuz-aios
initrd  /initramfs-aios.img
options root=/dev/mapper/aios-cryptroot rd.luks.uuid=${_luks_uuid} ${_root_mode} quiet loglevel=3 selinux=1 ${SELINUX_MODE}${_verity_params}
LOADER
    chmod 644 "${_entries_dir}/aios.conf"

    cat > "${TARGET_MOUNT}/boot/efi/loader/loader.conf" <<LOADERCONF
timeout 3
console-mode auto
default aios.conf
editor no
auto-entries no
auto-firmware no
LOADERCONF
    chmod 644 "${TARGET_MOUNT}/boot/efi/loader/loader.conf"

    msg "systemd-boot installed."
}

# ── TPM2 seal (optional) ──────────────────────────────────────────────────────

do_tpm2_seal() {
    if [ "${AIOS_SKIP_TPM:-0}" = "1" ]; then
        info "TPM2 sealing skipped (AIOS_SKIP_TPM=1)."
        return 0
    fi

    if [ ! -c /dev/tpm0 ] && [ ! -c /dev/tpmrm0 ]; then
        warn "No TPM device — sealing skipped."
        return 0
    fi

    if ! command -v systemd-cryptenroll >/dev/null 2>&1; then
        warn "systemd-cryptenroll not found — sealing skipped."
        return 0
    fi

    info "=== Enrolling TPM2 token ==="
    systemd-cryptenroll "${LUKS_PART}" \
        --tpm2-device=auto \
        --tpm2-pcrs=0+1+7 \
        --wipe-slot=tpm2 \
        --key-file "${LUKS_TMP_KEYFILE}" 2>&1 || {
        warn "systemd-cryptenroll failed."
        return 0
    }

    mkdir -p "${TARGET_MOUNT}/etc/aios"
    systemd-cryptenroll "${LUKS_PART}" \
        --tpm2-device=auto \
        --tpm2-pcrs=0+1+7 \
        --tpm2-public-key="${TARGET_MOUNT}/etc/aios/sealed-key.blob" \
        --key-file "${LUKS_TMP_KEYFILE}" 2>/dev/null || true
    chmod 400 "${TARGET_MOUNT}/etc/aios/sealed-key.blob" 2>/dev/null || true

    msg "TPM2 token enrolled."
}

# ── dm-verity (optional) ──────────────────────────────────────────────────────

do_verity() {
    if [ "${AIOS_SKIP_VERITY:-0}" = "1" ]; then
        info "dm-verity skipped (AIOS_SKIP_VERITY=1)."
        return 0
    fi
    if ! command -v veritysetup >/dev/null 2>&1; then
        warn "veritysetup not found — dm-verity skipped."
        return 0
    fi
    mkdir -p "${TARGET_MOUNT}/etc/aios/verity"
    local _roothash_file="${TARGET_MOUNT}/etc/aios/verity/roothash.sig"
    local _roothash

    if veritysetup format "${LUKS_MAPPER}" "${ROOT_HASH_DEV}" \
        --root-hash-file="${_roothash_file}" 2>/dev/null; then
        _roothash=$(head -n1 "${_roothash_file}" | tr -d '[:space:]')
    else
        warn "dm-verity hash generation skipped."
        return 0
    fi

    if [ -z "${_roothash}" ]; then
        warn "dm-verity root hash empty — skipped."
        return 0
    fi

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
    msg "dm-verity root hash stored at ${_roothash_file}."
    return 0
}

# ── SELinux ───────────────────────────────────────────────────────────────────

do_selinux() {
    if [ "${AIOS_SKIP_SELINUX:-0}" = "1" ]; then
        info "SELinux skipped (AIOS_SKIP_SELINUX=1)."
        return 0
    fi

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
SELINUX=${SELINUX_MODE}
SELINUXTYPE=aios
EOF
    chmod 644 "${TARGET_MOUNT}/etc/selinux/config"
    touch "${TARGET_MOUNT}/.autorelabel"
    msg "SELinux configured (${SELINUX_MODE}); autorelabel set."
}

# ── First-boot ────────────────────────────────────────────────────────────────

do_first_boot() {
    mkdir -p "${TARGET_MOUNT}/etc/aios"
    touch "${TARGET_MOUNT}/etc/aios/first-boot"
    chmod 644 "${TARGET_MOUNT}/etc/aios/first-boot"

    # Write recovery key (hex)
    local _recovery="${TARGET_MOUNT}/etc/aios/recovery-key.txt"
    local _hexkey
    _hexkey=$(xxd -l 24 -p /dev/urandom | fold -w 2 | head -n 24 | tr '\n' ' ')
    echo "${_hexkey}" > "${_recovery}"
    chmod 600 "${_recovery}"

    msg "First-boot flag + recovery key written."
    msg "Recovery key: ${_recovery}"
}

# ── Finalize ──────────────────────────────────────────────────────────────────

do_finalize() {
    info "=== Finalizing ==="
    sync

    if [ -f "${LUKS_TMP_KEYFILE}" ]; then
        dd if=/dev/urandom of="${LUKS_TMP_KEYFILE}" bs=64 count=1 status=none 2>/dev/null || true
        rm -f "${LUKS_TMP_KEYFILE}"
    fi

    umount "${TARGET_MOUNT}/boot/efi" 2>/dev/null || true
    umount "${TARGET_MOUNT}/boot"     2>/dev/null || true
    umount "${TARGET_MOUNT}/recovery" 2>/dev/null || true
    umount "${TARGET_MOUNT}/var/lib/aios/rollback" 2>/dev/null || true
    umount "${TARGET_MOUNT}"           2>/dev/null || true
    SETUP_MOUNTED=0

    if [ -b "/dev/mapper/aios-cryptroot" ]; then
        cryptsetup close aios-cryptroot 2>/dev/null || true
    fi

    msg "AI-OS.NET ${AIOS_VERSION} installation complete."
    msg "Target: ${TARGET_DISK}  Hostname: ${HOSTNAME}  Profile: ${PROFILE}"
    msg "Ready for reboot or snapshot."
}

# ══════════════════════════════════════════════════════════════════════════════

main() {
    validate_env
    do_partition
    do_filesystems
    do_encryption
    do_deploy
    do_configure
    do_tpm2_seal
    do_selinux
    do_first_boot
    do_verity
    do_bootloader
    do_finalize
}

main "$@"
