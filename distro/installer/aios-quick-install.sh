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
VAR_KEYFILE=""
SETUP_MOUNTED=0
CHROOT_MOUNTED=0
# do_verity computes the dm-verity root hash and stores it HERE (a shell global),
# not in a file on the verity-protected root. do_bootloader reads it from this
# variable to build the loader cmdline. Writing the hash into the root would
# change the root after it was hashed and trip panic-on-corruption at boot.
ROOT_HASH_VALUE=""

# Unmount the pseudo-filesystems bound into the target for the dracut chroot.
# Order matters: /dev last, since the others may be busy while it is bound.
umount_chroot() {
    umount "${TARGET_MOUNT}/proc" 2>/dev/null || true
    umount "${TARGET_MOUNT}/sys"  2>/dev/null || true
    umount "${TARGET_MOUNT}/dev"  2>/dev/null || true
    CHROOT_MOUNTED=0
}

cleanup_on_failure() {
    warn "=== Cleanup after failure ==="
    if [ "${CHROOT_MOUNTED}" -eq 1 ]; then
        umount_chroot
    fi
    if [ "${SETUP_MOUNTED}" -eq 1 ]; then
        umount "${TARGET_MOUNT}/boot/efi" 2>/dev/null || true
        umount "${TARGET_MOUNT}/boot"     2>/dev/null || true
        umount "${TARGET_MOUNT}/recovery" 2>/dev/null || true
        umount "${TARGET_MOUNT}/var/lib/aios/rollback" 2>/dev/null || true
        umount "${TARGET_MOUNT}/var"      2>/dev/null || true
        umount "${TARGET_MOUNT}"           2>/dev/null || true
    fi
    if [ -b "/dev/mapper/aios-var" ]; then
        cryptsetup close aios-var 2>/dev/null || true
    fi
    if [ -b "/dev/mapper/aios-cryptroot" ]; then
        cryptsetup close aios-cryptroot 2>/dev/null || true
    fi
    rm -f "${LUKS_TMP_KEYFILE}" 2>/dev/null || true
    [ -n "${VAR_KEYFILE}" ] && rm -f "${VAR_KEYFILE}" 2>/dev/null || true
}

trap 'cleanup_on_failure' ERR
trap 'cleanup_on_failure; exit 130' INT TERM

# ── Live-medium self-mount fallback ───────────────────────────────────────────
#
# Pipeline-4679 evidence: the initramfs mountpoint /run/initramfs/live-media
# does NOT survive switch_root (systemd mounts a fresh /run tmpfs; init's
# `mount --move /run` is `|| true`, so a failed subtree move is silent). The
# overlay root keeps working because kernel mount objects outlive path
# visibility — but no PATH to the squashfs remains. So the installer mounts
# the live medium itself: derive the ISO label from the kernel cmdline
# (root=live:CDLABEL=X, same grammar as distro/aios-boot/initramfs/init) and
# scan the same candidate device list the initramfs uses.

LIVE_MEDIUM_MOUNT="/run/aios-installer/medium"

mount_live_medium_fallback() {
    local _cmdline _label="" _dev

    _cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
    case "${_cmdline}" in
        *root=live:CDLABEL=*)
            _label="${_cmdline##*root=live:CDLABEL=}"; _label="${_label%% *}" ;;
        *root=live:LABEL=*)
            _label="${_cmdline##*root=live:LABEL=}"; _label="${_label%% *}" ;;
    esac

    mkdir -p "${LIVE_MEDIUM_MOUNT}"
    modprobe iso9660 2>/dev/null || true

    # Label first (exact medium), then the initramfs candidate scan order.
    for _dev in \
        ${_label:+"/dev/disk/by-label/${_label}"} \
        /dev/cdrom /dev/sr0 /dev/sr1 \
        /dev/vd[a-z] /dev/sd[a-z]; do
        [ -e "${_dev}" ] || continue
        if mount -o ro "${_dev}" "${LIVE_MEDIUM_MOUNT}" 2>/dev/null \
           || mount -t iso9660 -o ro "${_dev}" "${LIVE_MEDIUM_MOUNT}" 2>/dev/null; then
            if [ -f "${LIVE_MEDIUM_MOUNT}/live/aios.squashfs" ]; then
                AIOS_SQUASHFS="${LIVE_MEDIUM_MOUNT}/live/aios.squashfs"
                msg "Live medium self-mounted: ${_dev} -> ${LIVE_MEDIUM_MOUNT}"
                return 0
            fi
            umount "${LIVE_MEDIUM_MOUNT}" 2>/dev/null || true
        fi
    done

    warn "Live medium self-mount failed (label='${_label:-<none>}')"
    return 1
}

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
    # Root becomes a fixed size so that a separate, writable /var can take the
    # remainder of the disk. This is step 1 of making the root immutable under
    # dm-verity: a verity-protected root is read-only by construction, so every
    # writer that lives on it today (systemd's machine-id and logs, first-boot's
    # keys and evidence) has to move off it. /var is where that writable state
    # goes. 24 GiB leaves generous room for the OS image plus a future A/B second
    # slot; the operator can override it.
    ROOT_SIZE_MB="${AIOS_ROOT_SIZE_MB:-24576}"
    MIN_DISK_GB="${AIOS_MIN_DISK_GB:-40}"
    SELINUX_MODE="${AIOS_SELINUX_MODE:-permissive}"
    AIOS_SQUASHFS="${AIOS_SQUASHFS:-/run/initramfs/live/aios.squashfs}"

    # dm-verity is enforced by default. Enforcement means the loader entry sets
    # root= to the verity device and hands systemd the root hash, so the kernel's
    # dm-verity target refuses to hand out corrupted blocks (panic-on-corruption).
    # AIOS_SKIP_VERITY=1 turns the whole feature off (do_verity returns early and
    # the loader boots the plain LUKS root read-write, as before). This single
    # flag drives every verity-conditional branch below (fstab root mode, crypttab
    # /var handling, the /etc overlay, and the loader cmdline) so they can never
    # disagree — a half-enforced root that claims verity but does not boot it is
    # exactly the false-green class this installer keeps being bitten by.
    if [ "${AIOS_SKIP_VERITY:-0}" = "1" ]; then
        VERITY_ENFORCE=0
    else
        VERITY_ENFORCE=1
    fi

    if [ ! -f "${AIOS_SQUASHFS}" ]; then
        # Path probes, in order: our initramfs mounts the live ISO at
        # /run/initramfs/live-media (distro/aios-boot/initramfs/init,
        # try_mount_live_medium) — but pipeline 4679 proved that path does NOT
        # survive into the running live system: init's `mount --move /run` is
        # `|| true` (a subtree move can fail silently) and systemd mounts a
        # fresh /run tmpfs, so the initramfs mountpoints vanish while the
        # overlay root keeps working (kernel mount objects outlive path
        # visibility). The remaining entries are dracut/archiso/live-boot
        # conventions. If NO path probe hits, mount_live_medium_fallback()
        # below self-mounts the medium.
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
        mount_live_medium_fallback || true
    fi

    if [ ! -f "${AIOS_SQUASHFS}" ]; then
        # Self-diagnosing failure: dump what IS visible so the serial log of a
        # failed gate names the real state instead of just "not found".
        msg "ERROR diagnostics: /run/initramfs contents: $(ls /run/initramfs 2>/dev/null || echo '<absent>')"
        msg "ERROR diagnostics: live mounts: $(findmnt -rn -o TARGET,SOURCE 2>/dev/null | grep -iE 'iso9660|squash|live' || echo '<none>')"
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

    # Tool check. dracut is required because the rootfs ships no prebuilt
    # initramfs (zypper --root runs no kernel hooks) — do_initramfs builds it.
    local _required_tools="lsblk sgdisk mkfs.vfat mkfs.ext4 cryptsetup dmsetup unsquashfs bootctl blkid dracut"
    # veritysetup is a hard requirement when verity is enforced: without it
    # do_verity cannot build the hash tree, and a loader entry already committed
    # to root=/dev/mapper/root would then be unbootable. Fail here, early, rather
    # than at boot.
    if [ "${VERITY_ENFORCE}" = "1" ]; then
        _required_tools="${_required_tools} veritysetup"
    fi
    for _bin in ${_required_tools}; do
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
        "--new=6:0:+${ROOT_SIZE_MB}M" --typecode=6:8309 --change-name=6:AIOS_LUKS \
        --new=7:0:0                 --typecode=7:8309 --change-name=7:AIOS_VAR \
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
    VAR_PART="${TARGET_DISK}${_suffix}7"

    for _p in "${ESP_PART}" "${BOOT_PART}" "${RECOVERY_PART}" "${ROLLBACK_PART}" "${ROOT_HASH_PART}" "${LUKS_PART}" "${VAR_PART}"; do
        lsblk -n "${_p}" >/dev/null 2>&1 || die "Partition ${_p} not created" 4
    done

    msg "Partitions: ESP=${ESP_PART} BOOT=${BOOT_PART} RECOVERY=${RECOVERY_PART} ROLLBACK=${ROLLBACK_PART} HASH=${ROOT_HASH_PART} LUKS=${LUKS_PART} VAR=${VAR_PART}"
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

# device-mapper must be FUNCTIONAL before cryptsetup can create the /dev/mapper
# target. The live env does not autoload the modules, and /dev/mapper/control
# can exist as a static device node even when dm_mod is not actually loaded — so
# a node-existence check is not a real test. The authoritative test is a live DM
# ioctl via `dmsetup version`. Pipeline 4791 proved the install reaches LUKS then
# fails with "Cannot initialize device-mapper. Is dm_mod kernel module loaded?"
# even though the modprobe/control-node guard passed. On failure we now dump
# forensic diagnostics to the serial console so the install-gate log pinpoints
# the cause (module .ko absent vs modules.dep missing vs modprobe error) instead
# of the opaque cryptsetup message.
ensure_device_mapper() {
    local kver _mod _line
    kver="$(uname -r)"

    : > /tmp/aios-modprobe.err
    for _mod in dm_mod dm_crypt dm_verity; do
        modprobe "${_mod}" 2>>/tmp/aios-modprobe.err || true
    done

    if dmsetup version >/dev/null 2>&1; then
        return 0
    fi

    warn "device-mapper NON-FUNCTIONAL — collecting diagnostics"
    warn "dm-diag: uname=${kver}"
    warn "dm-diag: modules.dep $([ -e "/lib/modules/${kver}/modules.dep" ] && echo present || echo MISSING)"
    if [ -s /tmp/aios-modprobe.err ]; then
        while IFS= read -r _line; do warn "dm-diag: modprobe: ${_line}"; done < /tmp/aios-modprobe.err
    fi

    # modprobe returns EPERM ("Permission denied") from THREE distinct enforcers:
    # kernel lockdown, IMA MODULE_CHECK appraisal, or module.sig_enforce. They are
    # indistinguishable from modprobe's message alone, so name the enforcer here.
    warn "dm-diag: lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo unreadable)"
    warn "dm-diag: sig_enforce=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null || echo n/a)"
    warn "dm-diag: ima_appraise cmdline=$(grep -oE 'ima_appraise=[a-z]+|lockdown=[a-z]+|module.sig_enforce=[0-9]' /proc/cmdline | tr '\n' ' ' || echo none)"
    warn "dm-diag: ima runtime measurements=$([ -r /sys/kernel/security/integrity/ima/runtime_measurements_count ] && cat /sys/kernel/security/integrity/ima/runtime_measurements_count || echo n/a)"
    warn "dm-diag: dm_mod signed=$(modinfo -F sig_id /lib/modules/${kver}/kernel/drivers/md/dm-mod.ko* 2>/dev/null | head -n1 || echo unknown)"
    # the kernel logs the exact rejection reason to dmesg (lockdown/ima/sig)
    dmesg 2>/dev/null | grep -aiE "lockdown|ima:|appraise|module.*(sig|verif|reject)|dm_mod|device-mapper" | tail -n 8 \
        | while IFS= read -r _line; do warn "dm-diag: dmesg: ${_line}"; done
    dmsetup version 2>&1 | while IFS= read -r _line; do warn "dm-diag: dmsetup: ${_line}"; done

    die "device-mapper unavailable (dmsetup version failed after modprobe dm_mod)" 5
}

do_encryption() {
    info "=== Setting up LUKS2 encryption ==="

    ensure_device_mapper

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

    # /var is a separate encrypted volume, unlocked at boot by a key file that
    # lives on the (encrypted, and later verity-protected) root — not by its own
    # TPM enrolment. One TPM2 slot unlocks the root; the root then carries the
    # key that unlocks /var. Leaving /var in the clear would put logs, evidence
    # and machine state on disk unencrypted, which is worse than today.
    VAR_KEYFILE="$(mktemp /tmp/aios-quick-var-key.XXXXXX)"
    dd if=/dev/urandom of="${VAR_KEYFILE}" bs=64 count=1 status=none || die "var keygen failed" 5
    chmod 600 "${VAR_KEYFILE}"

    cryptsetup luksFormat --type luks2 \
        --pbkdf argon2id \
        --pbkdf-memory 1048576 \
        --pbkdf-parallel 4 \
        --pbkdf-force-iterations 4 \
        --key-file "${VAR_KEYFILE}" \
        --batch-mode \
        "${VAR_PART}" || die "LUKS2 format of /var failed" 5

    cryptsetup open --key-file "${VAR_KEYFILE}" \
        "${VAR_PART}" aios-var || die "LUKS open of /var failed" 5

    VAR_MAPPER="/dev/mapper/aios-var"
    mkfs.ext4 -q -L aios-var "${VAR_MAPPER}" || die "mkfs.ext4 /var failed" 6

    msg "Encrypted /var opened at ${VAR_MAPPER}"
}

# ── Mount + extract rootfs ────────────────────────────────────────────────────

do_deploy() {
    info "=== Deploying rootfs ==="

    mkdir -p "${TARGET_MOUNT}"
    mount -t ext4 -o rw,noatime "${LUKS_MAPPER}" "${TARGET_MOUNT}" || die "Root mount failed" 7
    SETUP_MOUNTED=1

    mkdir -p "${TARGET_MOUNT}/boot"
    mount -t ext4 -o defaults,noatime "${BOOT_PART}" "${TARGET_MOUNT}/boot" || die "Boot mount failed" 7

    # The ESP mount point must be created *after* BOOT_PART is mounted: mounting
    # the freshly-formatted (empty) boot partition over ${TARGET_MOUNT}/boot
    # shadows anything created underneath it, so /boot/efi has to be made on the
    # mounted boot filesystem or the ESP mount fails with "mount point does not
    # exist" (pipeline 5118, defect #9).
    mkdir -p "${TARGET_MOUNT}/boot/efi"
    mount -t vfat -o defaults,noatime,umask=0077 "${ESP_PART}" "${TARGET_MOUNT}/boot/efi" || die "ESP mount failed" 7

    msg "Extracting squashfs (${AIOS_SQUASHFS})..."
    unsquashfs -f -d "${TARGET_MOUNT}" "${AIOS_SQUASHFS}" || die "unsquashfs failed" 7

    # Move the image's /var onto the dedicated encrypted volume, then mount it
    # there. The base ships a populated /var (rpm database, journal skeleton,
    # subvolumes); mounting an empty partition straight over it would hide all of
    # that from the running system. cp -a preserves ownership, modes and the
    # SELinux/xattr labels the policy relies on. This must happen before the
    # rollback mount below, which lands *inside* /var.
    local _var_stage="/mnt/aios-var-stage"
    mkdir -p "${_var_stage}"
    mount -t ext4 -o rw,noatime "${VAR_MAPPER}" "${_var_stage}" || die "var stage mount failed" 7
    cp -a "${TARGET_MOUNT}/var/." "${_var_stage}/" || die "seeding /var failed" 7
    umount "${_var_stage}" || die "var stage unmount failed" 7
    rmdir "${_var_stage}" 2>/dev/null || true
    mount -t ext4 -o rw,noatime "${VAR_MAPPER}" "${TARGET_MOUNT}/var" || die "var mount failed" 7

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

    local _root_uuid _boot_uuid _esp_uuid _recovery_uuid _rollback_uuid _luks_uuid _var_luks_uuid _var_fs_uuid
    _root_uuid=$(blkid -s UUID -o value "${LUKS_MAPPER}" 2>/dev/null || echo "")
    _boot_uuid=$(blkid -s UUID -o value "${BOOT_PART}" 2>/dev/null || echo "")
    _esp_uuid=$(blkid -s UUID -o value "${ESP_PART}" 2>/dev/null || echo "")
    _recovery_uuid=$(blkid -s UUID -o value "${RECOVERY_PART}" 2>/dev/null || echo "")
    _rollback_uuid=$(blkid -s UUID -o value "${ROLLBACK_PART}" 2>/dev/null || echo "")
    _luks_uuid=$(blkid -s UUID -o value "${LUKS_PART}" 2>/dev/null || echo "")
    _var_luks_uuid=$(blkid -s UUID -o value "${VAR_PART}" 2>/dev/null || echo "")
    _var_fs_uuid=$(blkid -s UUID -o value "${VAR_MAPPER}" 2>/dev/null || echo "")

    if [ -z "${_root_uuid}" ] || [ -z "${_luks_uuid}" ] || [ -z "${_recovery_uuid}" ] || [ -z "${_rollback_uuid}" ]; then
        die "UUID read failed" 1
    fi
    if [ -z "${_var_luks_uuid}" ] || [ -z "${_var_fs_uuid}" ]; then
        die "var UUID read failed" 1
    fi

    # The key that unlocks /var. It lives on the root filesystem, which is itself
    # encrypted (and, once verity lands, read-only and attested). crypttab
    # unlocks aios-var with this file after the TPM has unlocked the root, so the
    # whole chain still hangs off the single TPM2 enrolment.
    mkdir -p "${TARGET_MOUNT}/etc/aios"
    install -m 0400 "${VAR_KEYFILE}" "${TARGET_MOUNT}/etc/aios/var.key" \
        || die "installing /var key onto the root failed" 6

    # The root line depends on whether verity is enforced. Under verity the
    # running root device is the read-only /dev/mapper/root the systemd verity
    # generator creates (NOT the LUKS mapper) — it is mounted read-only by the
    # initramfs and must be listed read-only here so systemd adopts it without
    # attempting a remount-rw that a verity device refuses. fsck pass is 0: the
    # image is immutable and hash-verified, and e2fsck against a read-only verity
    # target is pointless. Without verity the root is the plain LUKS mapper,
    # read-write, as before.
    local _root_fstab
    if [ "${VERITY_ENFORCE}" = "1" ]; then
        _root_fstab="/dev/mapper/root      /         ext4    ro,noatime                            0 0"
    else
        _root_fstab="UUID=${_root_uuid}    /         ext4    rw,noatime,discard,errors=remount-ro  0 1"
    fi

    # /etc/fstab
    cat > "${TARGET_MOUNT}/etc/fstab" <<FSTAB
# AI-OS.NET fstab — CI-generated (${AIOS_BUILD_ID})
${_root_fstab}
UUID=${_boot_uuid}    /boot     ext4    defaults,noatime                      0 2
UUID=${_esp_uuid}     /boot/efi vfat    defaults,noatime,umask=0077           0 2
UUID=${_var_fs_uuid}  /var      ext4    rw,noatime,nodev,nosuid               0 2
UUID=${_recovery_uuid} /recovery ext4    defaults,noatime,nodev,nosuid         0 2
UUID=${_rollback_uuid} /var/lib/aios/rollback ext4 defaults,noatime,nodev,nosuid 0 2
tmpfs                 /tmp      tmpfs   defaults,noexec,nosuid,nodev,size=2G  0 0
FSTAB
    chmod 644 "${TARGET_MOUNT}/etc/fstab"

    # /etc/crypttab
    # /var is unlocked by the key file on the (already-unlocked) root, not by the
    # TPM directly. Its crypttab line therefore names a key path rather than
    # "none"; systemd-cryptsetup orders it after the root is available.
    cat > "${TARGET_MOUNT}/etc/crypttab" <<CRYPTTAB
# AI-OS.NET crypttab — CI-generated (${AIOS_BUILD_ID})
aios-cryptroot   UUID=${_luks_uuid}       none               luks,discard,tpm2-device=auto
aios-var         UUID=${_var_luks_uuid}   /etc/aios/var.key  luks,discard
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

    stage_etc_overlay_module

    msg "System configuration written."
}

# ── Writable /etc overlay for the read-only verity root ───────────────────────
#
# A verity root is read-only by construction, so every process that writes /etc
# at boot (systemd-sysusers, systemd-tmpfiles, machine-id updates, first-boot,
# network config) would fail. The fix is an overlayfs on /etc: the read-only
# image /etc as the lower layer, a writable upper+work on the encrypted /var.
#
# It has to be assembled in the initramfs, before switch-root, so the real
# system's PID 1 sees a writable /etc from its very first action. dracut's own
# 90overlayfs module cannot do this — its check() is `[[ $hostonly ]] && return 1`,
# i.e. it deliberately excludes itself from a host-built (hostonly) initramfs
# because it is meant for live media. So we ship a small custom module and force
# it in with `--add aios-etc-overlay` in do_initramfs.
#
# /var is a separate encrypted volume unlocked by a key on the root. dracut must
# NOT embed that key (do_initramfs asserts it is absent from the unencrypted
# /boot image), so the volume cannot be unlocked by systemd in the initrd the
# normal way. Instead the pre-pivot hook reads the key from the just-mounted
# read-only /sysroot and unlocks /var itself. The crypttab entry stays `auto`
# (no noauto): if this hook fails for any reason, the post-pivot systemd path
# still unlocks and mounts /var normally — the system boots (with a read-only
# /etc, degraded but observable) rather than bricking. systemd-cryptsetup treats
# the already-open volume as "already active" and succeeds, so the early unlock
# and the normal path never collide.
#
# This module is staged BEFORE do_initramfs (which runs dracut) and BEFORE
# do_verity (which hashes the root), so it is a write into the root that must
# precede verity — the main() call order already guarantees this.
stage_etc_overlay_module() {
    if [ "${VERITY_ENFORCE}" != "1" ]; then
        return 0
    fi

    # Persistent upper/work for the /etc overlay, on the encrypted /var. The
    # hook also creates these at boot (idempotent); making them here keeps the
    # on-disk layout explicit and inspectable right after install.
    mkdir -p "${TARGET_MOUNT}/var/lib/aios/etc/upper" \
             "${TARGET_MOUNT}/var/lib/aios/etc/work" \
        || die "creating /etc overlay dirs on /var failed" 6

    local _moddir="${TARGET_MOUNT}/usr/lib/dracut/modules.d/98aios-etc-overlay"
    mkdir -p "${_moddir}" || die "creating dracut module dir failed" 6

    # Quoted heredoc: $moddir/$hostonly/etc are dracut/runtime variables that
    # must land in the target file verbatim, not be expanded by the installer.
    cat > "${_moddir}/module-setup.sh" <<'MODSETUP'
#!/bin/bash
# AI-OS.NET: assemble a writable /etc overlay for the read-only dm-verity root.
# Forced in via `dracut --add aios-etc-overlay`; check() stays permissive so the
# --add is honoured under hostonly (where 90overlayfs excludes itself).

check() {
    return 0
}

depends() {
    # Needs device-mapper (for the verity root and the LUKS /var) and the crypt
    # tooling to unlock /var from the key on the just-mounted root.
    echo dm crypt
    return 0
}

installkernel() {
    # overlayfs must be in the initramfs, not just the real root.
    instmods overlay
}

install() {
    # cryptsetup comes from 90crypt; list it optionally as belt-and-suspenders.
    # grep is used by the hook's already-mounted guard.
    inst_multiple -o cryptsetup mount mkdir grep
    inst_hook pre-pivot 50 "$moddir/aios-etc-overlay.sh"
}
MODSETUP
    chmod 755 "${_moddir}/module-setup.sh"

    cat > "${_moddir}/aios-etc-overlay.sh" <<'OVERLAYHOOK'
#!/bin/sh
# AI-OS.NET pre-pivot hook: unlock the encrypted /var and layer a writable
# overlay on the read-only verity root's /etc, before switch-root.
#
# Runs after sysroot.mount (dracut-pre-pivot.service ordering), so /sysroot is
# the read-only verity root. On any failure it warns loudly and exits 0 rather
# than dropping to an emergency shell: verity integrity is enforced by the kernel
# regardless of this hook, and a bricked boot is worse than a read-only /etc that
# the post-pivot path can still bring /var up under. Every exit reason is printed.

command -v warn >/dev/null 2>&1 || . /lib/dracut-lib.sh 2>/dev/null || true
_say() { warn "aios-etc-overlay: $*" 2>/dev/null || echo "aios-etc-overlay: $*" >&2; }

SYSROOT="${NEWROOT:-/sysroot}"
CRYPTTAB="${SYSROOT}/etc/crypttab"

[ -f "${CRYPTTAB}" ] || { _say "no ${CRYPTTAB}; /etc stays read-only"; exit 0; }

# Parse the aios-var line: <name> <device> <keyfile> <options>. No awk (not in
# the initramfs); skip comment lines.
_name=""; _dev=""; _key=""
while read -r f1 f2 f3 _rest; do
    case "${f1}" in
        \#*|"") continue ;;
        aios-var) _name="${f1}"; _dev="${f2}"; _key="${f3}"; break ;;
    esac
done < "${CRYPTTAB}"

[ -n "${_name}" ] || { _say "no aios-var in crypttab; /etc stays read-only"; exit 0; }

# Resolve UUID=/PARTUUID= specifiers to a device path cryptsetup accepts.
case "${_dev}" in
    UUID=*)     _dev="/dev/disk/by-uuid/${_dev#UUID=}" ;;
    PARTUUID=*) _dev="/dev/disk/by-partuuid/${_dev#PARTUUID=}" ;;
esac

# Unlock /var if it is not already open (e.g. a re-run). The key lives on the
# read-only root; it is never placed in the unencrypted initramfs.
if [ ! -b /dev/mapper/aios-var ]; then
    if [ ! -f "${SYSROOT}${_key}" ]; then
        _say "var key ${SYSROOT}${_key} missing; /etc stays read-only"; exit 0
    fi
    if ! cryptsetup open --key-file "${SYSROOT}${_key}" "${_dev}" aios-var; then
        _say "cryptsetup open aios-var failed; /etc stays read-only"; exit 0
    fi
fi

# Mount /var under the sysroot if it is not there yet.
mkdir -p "${SYSROOT}/var"
if ! grep -q " ${SYSROOT}/var " /proc/mounts 2>/dev/null; then
    if ! mount -t ext4 -o rw,noatime /dev/mapper/aios-var "${SYSROOT}/var"; then
        _say "mount /var failed; /etc stays read-only"; exit 0
    fi
fi

_upper="${SYSROOT}/var/lib/aios/etc/upper"
_work="${SYSROOT}/var/lib/aios/etc/work"
if ! mkdir -p "${_upper}" "${_work}"; then
    _say "mkdir overlay upper/work failed; /etc stays read-only"; exit 0
fi

if mount -t overlay aios-etc \
        -o "lowerdir=${SYSROOT}/etc,upperdir=${_upper},workdir=${_work}" \
        "${SYSROOT}/etc"; then
    _say "writable /etc overlay assembled (upper on encrypted /var)"
else
    _say "overlay mount failed; /etc stays read-only"
fi
exit 0
OVERLAYHOOK
    chmod 755 "${_moddir}/aios-etc-overlay.sh"

    msg "Staged 98aios-etc-overlay dracut module for the read-only root's writable /etc."
}

# ── Initramfs (defect #12b) ───────────────────────────────────────────────────
#
# The openSUSE rootfs ships a real kernel (/usr/lib/modules/<kver>/vmlinuz, with
# /boot/vmlinuz-<kver> only a symlink to it) but NO initramfs: `zypper --root`
# does not run the kernel package's post-install hooks, so dracut was never
# invoked at build time. The loader entry references /initramfs-aios.img, which
# consequently existed nowhere on the target (pipeline 5309) — the kernel would
# have no way to unlock the LUKS2 root even once a loader could run it.
#
# This MUST stay ahead of do_verity: veritysetup hashes the whole root device,
# so dracut's writes into the root afterwards would invalidate the root hash.
do_initramfs() {
    info "=== Generating initramfs ==="

    local _modules_dir="${TARGET_MOUNT}/usr/lib/modules"
    [ -d "${_modules_dir}" ] || die "No ${_modules_dir} — rootfs ships no kernel" 9

    local _kver
    _kver="$(ls -1 "${_modules_dir}" 2>/dev/null | head -n1)"
    [ -n "${_kver}" ] || die "No kernel version directory under ${_modules_dir}" 9
    [ -f "${_modules_dir}/${_kver}/vmlinuz" ] \
        || die "No kernel image for ${_kver}" 9
    # build-opensuse-rootfs.sh runs depmod itself (zypper --root skips the
    # hooks); without modules.dep dracut silently produces a module-less image.
    [ -f "${_modules_dir}/${_kver}/modules.dep" ] \
        || die "depmod metadata missing for ${_kver}" 9
    msg "Kernel version: ${_kver}"

    mkdir -p "${TARGET_MOUNT}/proc" "${TARGET_MOUNT}/sys" "${TARGET_MOUNT}/dev"
    mount -t proc  proc  "${TARGET_MOUNT}/proc" || die "chroot /proc mount failed" 9
    mount -t sysfs sysfs "${TARGET_MOUNT}/sys"  || die "chroot /sys mount failed" 9
    mount --bind /dev    "${TARGET_MOUNT}/dev"  || die "chroot /dev mount failed" 9
    CHROOT_MOUNTED=1

    # --hostonly, deliberately, and NOT --no-hostonly.
    #
    # --no-hostonly was the earlier choice, reasoned as "the image must boot on
    # real hardware, not only the QEMU host that generated it". That reasoning
    # was wrong: this initramfs is built by the installer *on the target system*,
    # from inside the target's own root. The target IS the host. There is no
    # second machine for it to be portable to — the image never leaves this disk.
    #
    # The cost of that mistake was concrete. dracut's 90crypt module gates its
    # whole TPM2 path on hostonly plus a crypttab that names it:
    #
    #     depends() {
    #         if [[ $hostonly && -f "$dracutsysrootdir"/etc/crypttab ]]; then
    #             if grep -q ... -e "tpm2-device=" ...
    #
    # --no-hostonly therefore built an image with no TPM2 support at all, so the
    # LUKS2 token this installer enrols could never be used and boot stalled on
    # "Please enter passphrase for disk AIOS_LUKS" until the gate killed it — an
    # unattended install that cannot come up unattended. Putting
    # rd.luks.options=tpm2-device=auto on the cmdline could not rescue it: the
    # option asks for a stack the image does not contain.
    #
    # do_configure has already written /etc/crypttab with tpm2-device=auto, so
    # hostonly reads it and pulls the TPM2 path in as designed.
    #
    # --add "crypt dm": the root is LUKS2 at /dev/mapper/aios-cryptroot, so the
    #   initramfs must be able to unlock it; without these the kernel panics
    #   with "unable to mount root fs".
    local _dracut_log="/tmp/aios-dracut.log"
    # Every module here is named explicitly, and nothing is left to dracut's
    # host detection, because that detection cannot work from where we stand:
    #
    #   90crypt/check()    includes crypt only if host_fs_types contains
    #                      crypto_LUKS -- i.e. only if the LUKS volume backs the
    #                      root of the *running* system. We run inside a chroot
    #                      from the installer; the target's LUKS root is not our
    #                      root, so that probe answers "no" about a machine dracut
    #                      is not running on.
    #   90crypt/depends()  pulls tpm2-tss only when $hostonly is set AND
    #                      /etc/crypttab names tpm2-device=. Both hold here, but
    #                      the chain runs only if crypt survived check() above.
    #   91tpm2-tss/check() returns 255 -- "include me only if someone requires
    #                      me" -- so it never volunteers on its own.
    #
    # --add forces a module in regardless of its check(), which is exactly the
    # guarantee this boot path needs. hostonly stays on to match the distro
    # default (01-dist.conf sets hostonly=yes); -v makes dracut print
    # "Including module:" lines so its decisions are readable in the log below
    # instead of inferred.
    # When verity is enforced the initramfs also needs:
    #   systemd-veritysetup — runs systemd-veritysetup@root.service, which the
    #     veritysetup generator emits from the roothash=/systemd.verity_root_*
    #     cmdline params, opening /dev/mapper/root between the LUKS unlock and the
    #     root mount. Its own check() returns 255 (include only if required), so
    #     like tpm2-tss it never volunteers and must be forced in.
    #   aios-etc-overlay — our pre-pivot hook that gives the read-only root a
    #     writable /etc (staged by stage_etc_overlay_module).
    local _dracut_modules="crypt dm tpm2-tss"
    # Kernel drivers forced in regardless of hostonly auto-detection. dracut in
    # hostonly mode includes only drivers the *running* system uses; the installer
    # chroot uses neither dm-verity nor overlay, so both must be forced or the
    # image ships without them.
    local _dracut_drivers=""
    if [ "${VERITY_ENFORCE}" = "1" ]; then
        _dracut_modules="${_dracut_modules} systemd-veritysetup aios-etc-overlay"
        # 01systemd-veritysetup installs veritysetup + the generator + units, but
        # has NO installkernel(), so it never pulls the kernel dm-verity target
        # module. Without dm-verity.ko in the image, systemd-veritysetup asks
        # device-mapper for a "verity" target the kernel does not know and boot
        # dies with "device-mapper: table: verity: unknown target type" →
        # /dev/mapper/root never appears. overlay.ko is likewise needed by the
        # aios-etc-overlay pre-pivot hook. Force both in.
        _dracut_drivers="dm-verity overlay"
    fi
    if ! chroot "${TARGET_MOUNT}" dracut --force --hostonly -v \
            --add "${_dracut_modules}" \
            ${_dracut_drivers:+--add-drivers "${_dracut_drivers}"} \
            /boot/initramfs-aios.img "${_kver}" > "${_dracut_log}" 2>&1; then
        err "dracut failed — last 30 lines:"
        tail -n 30 "${_dracut_log}" >&2 || true
        die "initramfs generation failed" 9
    fi

    # dracut can exit 0 having quietly skipped the TPM2 path (its check() and
    # depends() self-disable on unmet conditions). The whole point of enrolling
    # a TPM2 token is an unattended boot, so verify the stack is really in the
    # image instead of discovering it as a passphrase prompt at boot.
    # Ask dracut what it did, not lsinitrd what it can see. The obvious check --
    # `lsinitrd <img> | grep tpm2` -- reports NO TPM2 stack on an image that
    # demonstrably has one: the same build it condemned went on to unlock the
    # volume from the TPM with zero passphrase prompts. A check that cries wolf
    # gets ignored, which is how a real one gets missed.
    if grep -aq "Including module: tpm2-tss" "${_dracut_log}" 2>/dev/null; then
        msg "initramfs carries the TPM2 stack (dracut: Including module: tpm2-tss)."
    else
        warn "initramfs has NO TPM2 stack — boot will stop at a passphrase prompt."
        # dracut's own decisions are the ground truth about why. 90crypt only
        # pulls in tpm2-tss when hostonly is on AND /etc/crypttab names
        # tpm2-device=; tpm2-tss itself self-disables unless a `tpm2` binary
        # exists. Any of those failing is silent, so show all three inputs.
        warn "dracut: modules it decided to include:"
        grep -aoE "Including module: [a-z0-9-]+" "${_dracut_log}" 2>/dev/null \
            | sed 's/^/    /' | tr '\n' ' ' | head -c 700 || true
        printf '\n'
        warn "dracut: hostonly / tpm2 / crypt decisions:"
        grep -aiE "hostonly|tpm2|omitting|crypt" "${_dracut_log}" 2>/dev/null \
            | sed 's/^/    dracut: /' | head -n 8 || true
        warn "target /etc/crypttab:"
        sed 's/^/    /' "${TARGET_MOUNT}/etc/crypttab" 2>/dev/null | head -n 4 || true
        warn "tpm2 binary in target: $(test -x "${TARGET_MOUNT}/usr/bin/tpm2" && echo present || echo MISSING)"
    fi

    # Fail closed on verity enforcement. If the loader entry will boot
    # root=/dev/mapper/root but the initramfs carries no systemd-veritysetup, the
    # verity device is never opened and the kernel panics on a missing root. And
    # without aios-etc-overlay the read-only root has no writable /etc. Both are
    # forced in via --add above; assert dracut actually included them, from
    # dracut's own "Including module:" lines (the same ground truth the tpm2
    # check uses), rather than discovering the gap at boot.
    if [ "${VERITY_ENFORCE}" = "1" ]; then
        if grep -aq "Including module: systemd-veritysetup" "${_dracut_log}" 2>/dev/null; then
            msg "initramfs carries systemd-veritysetup (verity opens before root mount)."
        else
            err "dracut did NOT include systemd-veritysetup — decisions:"
            grep -aoE "Including module: [a-z0-9-]+" "${_dracut_log}" 2>/dev/null \
                | sed 's/^/    /' | tr '\n' ' ' | head -c 900 >&2 || true
            printf '\n' >&2
            die "verity enforced but initramfs has no systemd-veritysetup — root would never open" 9
        fi
        if grep -aq "Including module: aios-etc-overlay" "${_dracut_log}" 2>/dev/null; then
            msg "initramfs carries aios-etc-overlay (writable /etc on the read-only root)."
        else
            die "verity enforced but initramfs has no aios-etc-overlay — /etc would be read-only" 9
        fi
        # The dracut *modules* above are the userspace side. The kernel dm-verity
        # target module is the other half and is forced via --add-drivers; assert
        # it physically landed in the image, else boot dies with "verity: unknown
        # target type". lsinitrd is authoritative for kernel modules, BUT it
        # extracts and decompresses the ~98MB image on every call and its FIRST
        # invocation in the cramped installer env can emit a truncated listing
        # (observed: the very next identical call listed dm-verity.ko fine). So
        # capture the listing ONCE and assert against that single snapshot — never
        # re-invoke lsinitrd per module, which reintroduces the flaky-first-call
        # false negative. An empty capture means lsinitrd itself failed (a real
        # blocker), distinct from a complete listing that lacks the module.
        local _initrd_list
        _initrd_list="$(chroot "${TARGET_MOUNT}" lsinitrd /boot/initramfs-aios.img 2>/dev/null)"
        if [ -z "${_initrd_list}" ]; then
            die "cannot verify initramfs contents — lsinitrd produced no listing for /boot/initramfs-aios.img" 9
        fi
        # Match with a bash `case` on the captured listing, NOT an external grep.
        # A prior `grep -qF "dm-verity.ko"` here cried wolf on an image that
        # demonstrably carried the module (the very next `grep -F "drivers/md/dm-"`
        # on the SAME variable printed the dm-verity.ko line) — the live installer's
        # grep does not behave like GNU grep, and no pattern form (-E, -F, escaped
        # or not) was reliable. bash's own glob matching is built in, uses no
        # subprocess, and is immune to whatever grep sits in PATH, so it is the
        # authoritative test for "is this substring in the listing".
        case "${_initrd_list}" in
            *dm-verity.ko*)
                msg "initramfs carries the dm-verity kernel target (dm-verity.ko present)." ;;
            *)
                err "dracut did NOT include dm-verity.ko — md/ modules in image:"
                printf '%s\n' "${_initrd_list}" | while IFS= read -r _l; do
                    case "${_l}" in *drivers/md/dm-*) printf '    %s\n' "${_l}" >&2 ;; esac
                done
                die "verity enforced but initramfs has no dm-verity.ko — root would fail with 'verity: unknown target type'" 9 ;;
        esac
        case "${_initrd_list}" in
            *overlay.ko*)
                msg "initramfs carries overlay.ko (aios-etc-overlay can mount the writable /etc)." ;;
            *)
                die "verity enforced but initramfs has no overlay.ko — the /etc overlay hook would fail" 9 ;;
        esac
    fi

    # Fail closed on a key leak. The initramfs lands on /boot, which is NOT
    # encrypted. /var's key file lives on the encrypted root precisely so it is
    # never on unencrypted media — but dracut --hostonly reads the whole
    # /etc/crypttab, and if it decided to embed the aios-var key to unlock /var
    # early, that key would sit in the clear on /boot and the /var encryption
    # would be worthless. /var is not on the path to root, so dracut should not
    # pull it in; this asserts that rather than trusting it. Checked before the
    # size gate so a leak is reported even on an otherwise valid image.
    # Matched with a bash `case`, NOT an external grep: the live installer's grep
    # proved unreliable for substring tests (see the dm-verity check above), and
    # this is a security guard that must not fail open. bash glob matching is a
    # builtin, immune to whatever grep is in PATH. Reuse the listing captured in
    # the verity block when present; capture here when verity is off (that path
    # never populated _initrd_list) so the guard always runs against a real image.
    local _leak_list="${_initrd_list:-}"
    if [ -z "${_leak_list}" ]; then
        _leak_list="$(chroot "${TARGET_MOUNT}" lsinitrd /boot/initramfs-aios.img 2>/dev/null)"
    fi
    case "${_leak_list}" in
        *etc/aios/var.key*|*/cryptsetup-keys.d/aios-var*)
            die "SECURITY: dracut embedded the /var key into the unencrypted /boot initramfs" 9 ;;
    esac

    umount_chroot

    # Fail closed: dracut can exit 0 and still leave a useless image. A real
    # initramfs with crypt+dm is tens of MB; anything tiny means the modules
    # were not picked up.
    local _img="${TARGET_MOUNT}/boot/initramfs-aios.img"
    [ -s "${_img}" ] || die "dracut exited 0 but ${_img} is missing/empty" 9
    local _sz
    _sz=$(stat -c%s "${_img}" 2>/dev/null || echo 0)
    [ "${_sz}" -ge 8000000 ] \
        || die "initramfs is only ${_sz} bytes — modules were not included" 9
    msg "initramfs generated: ${_img} (${_sz} bytes)"

    # /boot/vmlinuz-<kver> is a symlink into /usr/lib/modules. Dereference it
    # here so /boot always holds a real kernel image next to its initramfs.
    cp -L --remove-destination "${_modules_dir}/${_kver}/vmlinuz" \
        "${TARGET_MOUNT}/boot/vmlinuz-aios" || die "kernel copy to /boot failed" 9
    chmod 644 "${TARGET_MOUNT}/boot/vmlinuz-aios"
    msg "Kernel staged at ${TARGET_MOUNT}/boot/vmlinuz-aios."
}

# ── Bootloader ────────────────────────────────────────────────────────────────

do_bootloader() {
    info "=== Installing systemd-boot ==="

    # bootctl installs the loader from the *running* system's payload directory.
    # The systemd package provides bootctl; the EFI payload itself comes from
    # the separate systemd-boot package. When that package is absent bootctl
    # still creates the ESP directory skeleton and loader.conf without ever
    # reporting a hard failure — pipeline 5309 measured an ESP with zero .efi
    # files while this function had already printed "systemd-boot installed."
    # Check the payload explicitly rather than trusting the exit code.
    local _payload="/usr/lib/systemd/boot/efi/systemd-bootx64.efi"
    [ -f "${_payload}" ] \
        || die "systemd-boot payload ${_payload} is missing (systemd-boot package not installed)" 8

    local _esp="${TARGET_MOUNT}/boot/efi"

    bootctl install --esp-path="${_esp}" --no-variables \
        || die "bootctl install failed" 8

    local _luks_uuid
    _luks_uuid=$(blkid -s UUID -o value "${LUKS_PART}" 2>/dev/null || echo "")

    # Root device and mode. Without verity the root is the plain LUKS mapper,
    # read-write. With verity enforced, root= names the verity device the systemd
    # veritysetup generator creates — /dev/mapper/root (the generator hardcodes
    # the volume name "root" for the root fs; it is NOT configurable to
    # "aios-verity") — mounted read-only, and the cmdline carries the parameters
    # that generator consumes to build it.
    #
    # The old invented tokens (" verity dm_verity.roothash=<hash>") are gone:
    # nothing in the base read dm_verity.roothash, and the bare word "verity" was
    # passed to init as an argument. What replaces them is systemd's own,
    # real verity boot path.
    local _root_dev="/dev/mapper/aios-cryptroot"
    local _root_mode="rw"
    local _verity_params=""
    if [ "${VERITY_ENFORCE}" = "1" ]; then
        local _roothash _hash_partuuid
        # Read the hash from the shell global do_verity set, NOT a file inside the
        # root: the root is now frozen read-only and carries no roothash file (that
        # would have changed the hashed bytes). do_verity runs before this in main.
        _roothash="${ROOT_HASH_VALUE}"
        [ -n "${_roothash}" ] \
            || die "verity enforced but do_verity left no root hash" 8
        # The hash device (p5) is referenced by GPT PARTUUID, which exists
        # regardless of any filesystem/verity superblock UUID and is resolved
        # early by udev by-partuuid links. The systemd veritysetup generator runs
        # the value through fstab_node_to_udev_node(), which understands PARTUUID=.
        _hash_partuuid=$(blkid -s PARTUUID -o value "${ROOT_HASH_PART}" 2>/dev/null || echo "")
        [ -n "${_hash_partuuid}" ] \
            || die "cannot read PARTUUID of the verity hash partition ${ROOT_HASH_PART}" 8
        _root_dev="/dev/mapper/root"
        _root_mode="ro"
        # roothash= + systemd.verity_root_data= + systemd.verity_root_hash= are
        # the generator's real inputs (present in this base). Data device = the
        # LUKS mapper (post-unlock, same bytes the hash tree was built over); hash
        # device = p5. panic-on-corruption is the kernel dm-verity target's own
        # refuse-to-serve-tampered-blocks behaviour — the operator's refuse-to-boot
        # decision, enforced by the kernel, not by any userspace policy file.
        _verity_params="roothash=${_roothash} systemd.verity_root_data=/dev/mapper/aios-cryptroot systemd.verity_root_hash=PARTUUID=${_hash_partuuid} systemd.verity_root_options=panic-on-corruption"
    fi

    # The kernel has no bare `permissive`/`enforcing` parameter — the mode is
    # carried by enforcing=0|1, and SELinux itself is switched off with
    # selinux=0. This previously emitted "selinux=1 permissive", so the mode
    # word was an inert token the kernel ignored and the installed system's
    # actual mode came from /etc/selinux/config alone. Same form the boot gate
    # asserts: security=selinux selinux=1 enforcing=0.
    local _selinux_params
    case "${SELINUX_MODE}" in
        enforcing)  _selinux_params="security=selinux selinux=1 enforcing=1" ;;
        permissive) _selinux_params="security=selinux selinux=1 enforcing=0" ;;
        *)          _selinux_params="selinux=0" ;;
    esac

    # The installed system had no console= at all, so it emitted nothing to the
    # serial port and the phase-2 boot gate could only ever see the loader's own
    # menu. Phase 1 gets a console via QEMU -append; phase 2 boots from this
    # entry and inherited none. A serial console is also the normal expectation
    # on server hardware, so it is unconditional; tty0 keeps the local display.
    local _console_params="console=tty0 console=ttyS0,115200n8"

    # rd.luks.name=<uuid>=<name>, NOT rd.luks.uuid=<uuid>.
    #
    # rd.luks.uuid= assembles the volume under dracut's default name,
    # /dev/mapper/luks-<uuid>, ignoring the name /etc/crypttab gives it. The
    # loader entry below asks for root=/dev/mapper/aios-cryptroot, so the two
    # never met: the volume unlocked correctly and unattended, systemd logged
    # "Finished Cryptography Setup for luks-e75269b0-...", and the initqueue then
    # sat waiting for /dev/mapper/aios-cryptroot until it timed out into the
    # dracut emergency shell. The disk was open the whole time under a name
    # nothing was looking for.
    #
    # rd.luks.name= states the mapping explicitly, so the device that appears is
    # the device root= asks for.
    local _luks_options="rd.luks.name=${_luks_uuid}=aios-cryptroot rd.luks.options=tpm2-device=auto"

    # CI_BARE must be observable: `quiet` makes systemd suppress its status
    # lines, so "Reached target ..." — the only marker a running OS can emit
    # that a bootloader cannot fake — would never reach the log. Hardened
    # profiles stay quiet.
    # systemd.log_level=debug on CI_BARE: initrd-switch-root.service fails after
    # the disk is unlocked and the root filesystem is mounted, and systemd loops
    # through Switch Root six times before giving up to the emergency shell. At
    # the default level it reports only "[FAILED] Failed to start Switch Root."
    # and points at `systemctl status`, which nothing in a headless gate can run.
    # Two guesses have already been spent on this (the bare `verity` token, and
    # dracut hostonly); the reason has to come from systemd itself.
    # `rd.debug` is deliberately NOT added -- it is shell tracing and floods the
    # serial line hard enough to threaten the phase-2 timeout.
    local _verbosity="quiet loglevel=3"
    case "${PROFILE}" in
        # systemd.log_level=debug is deliberately NOT here. It routes to the
        # journal, so surfacing it needs systemd.log_target=console too, and that
        # pair floods ~10k lines through a 115200-baud serial console -- enough
        # to push a 10s boot past the 240s phase-2 gate timeout on wall-clock
        # alone, a false red. It earned its keep once (it found the missing /run
        # by naming initrd-switch-root's exact failure) and is left as a
        # documented opt-in via AIOS_DEBUG rather than always on.
        CI_BARE) _verbosity="loglevel=7 systemd.show_status=yes" ;;
    esac
    if [ "${AIOS_DEBUG:-0}" = "1" ]; then
        _verbosity="${_verbosity} systemd.log_level=debug systemd.log_target=console"
    fi

    local _entries_dir="${TARGET_MOUNT}/boot/efi/loader/entries"
    mkdir -p "${_entries_dir}"

    cat > "${_entries_dir}/aios.conf" <<LOADER
title   AI-OS.NET ${AIOS_VERSION} (CI)
linux   /vmlinuz-aios
initrd  /initramfs-aios.img
options root=${_root_dev} ${_verity_params} ${_luks_options} ${_root_mode} ${_console_params} ${_verbosity} ${_selinux_params}
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

    # We install with --no-variables: no NVRAM boot entry is written, so the
    # firmware can ONLY ever start the removable fallback \EFI\BOOT\BOOTX64.EFI.
    # bootctl normally places it; assert it and install it ourselves if not.
    if [ ! -f "${_esp}/EFI/BOOT/BOOTX64.EFI" ]; then
        mkdir -p "${_esp}/EFI/BOOT"
        cp "${_payload}" "${_esp}/EFI/BOOT/BOOTX64.EFI" \
            || die "fallback EFI/BOOT/BOOTX64.EFI install failed" 8
        msg "Fallback EFI/BOOT/BOOTX64.EFI installed from payload."
    fi
    [ -f "${_esp}/EFI/systemd/systemd-bootx64.efi" ] \
        || die "bootctl exited 0 but installed no loader binary" 8

    # systemd-boot reads FAT only — it cannot read the ext4 /boot partition, so
    # the kernel and initramfs named by the loader entry must sit on the ESP.
    cp --remove-destination "${TARGET_MOUNT}/boot/vmlinuz-aios" \
        "${_esp}/vmlinuz-aios" || die "kernel copy to ESP failed" 8
    cp --remove-destination "${TARGET_MOUNT}/boot/initramfs-aios.img" \
        "${_esp}/initramfs-aios.img" || die "initramfs copy to ESP failed" 8
    sync

    esp_diag

    # Only claim success once every artifact the firmware and kernel need is
    # provably on the ESP.
    [ -s "${_esp}/vmlinuz-aios" ] && [ -s "${_esp}/initramfs-aios.img" ] \
        || die "kernel/initramfs missing from the ESP after copy" 8

    msg "systemd-boot installed."
}

# ── ESP diagnostics (defect #12) ──────────────────────────────────────────────
#
# Phase-2 boot dropped straight to the EFI shell: the firmware reported
# "failed to load Boot0002 ... Not Found" for the disk and never ran a loader.
# We install with --no-variables (no NVRAM entry is written), so the firmware
# can ONLY boot via the removable fallback path \EFI\BOOT\BOOTX64.EFI. Record
# exactly what bootctl left on the ESP, and where the kernel/initrd actually
# live, so the next cycle fixes a measured cause instead of a guess.
esp_diag() {
    local _esp="${TARGET_MOUNT}/boot/efi"

    info "=== ESP diagnostics (defect #12) ==="

    msg "esp-diag: tree under ${_esp}:"
    find "${_esp}" -maxdepth 4 2>&1 | head -n 40 || true

    if [ -f "${_esp}/EFI/BOOT/BOOTX64.EFI" ]; then
        msg "esp-diag: fallback EFI/BOOT/BOOTX64.EFI PRESENT"
    else
        msg "esp-diag: fallback EFI/BOOT/BOOTX64.EFI MISSING <-- firmware cannot boot"
    fi

    # The loader entry references /vmlinuz-aios and /initramfs-aios.img. Those
    # paths are resolved by systemd-boot on the ESP/XBOOTLDR, which must be FAT
    # — systemd-boot cannot read ext4. Show where they really are.
    msg "esp-diag: kernel/initrd on the ESP:"
    ls -la "${_esp}/vmlinuz-aios" "${_esp}/initramfs-aios.img" 2>&1 | head -n 4 || true
    msg "esp-diag: kernel/initrd on /boot:"
    ls -la "${TARGET_MOUNT}/boot/vmlinuz-aios" "${TARGET_MOUNT}/boot/initramfs-aios.img" 2>&1 | head -n 4 || true

    msg "esp-diag: filesystem types:"
    findmnt -no SOURCE,FSTYPE,TARGET "${_esp}" 2>&1 || true
    findmnt -no SOURCE,FSTYPE,TARGET "${TARGET_MOUNT}/boot" 2>&1 || true

    msg "esp-diag: bootctl status:"
    bootctl --esp-path="${_esp}" status 2>&1 | head -n 25 || true
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

    # systemd-cryptenroll has no --key-file: the option that supplies an
    # existing passphrase to unlock the volume before enrolling is
    # --unlock-key-file=. Passing --key-file made every enrolment abort with
    # "unrecognized option", and the `|| warn; return 0` below turned that into
    # a silent skip — the installs reported success with no TPM2 token in the
    # LUKS header at all.
    # Capture the reason. The previous code discarded it, so the --key-file
    # defect above survived unseen behind a bare "systemd-cryptenroll failed."
    # This is a BOOTSTRAP enrolment and is deliberately not bound to PCRs.
    #
    # An installer cannot bind to PCR 0+1+7 and have it work: those registers are
    # measured by the firmware of the boot chain that is running *right now* --
    # the live installation medium -- and the installed system boots a different
    # chain. Sealing against 0+1+7 here produced a token that could never be
    # unsealed later, so every boot fell through to a passphrase prompt while the
    # LUKS header truthfully reported an enrolled TPM2 token. Measured, not
    # guessed: the CI installer runs with no UEFI firmware at all (direct kernel
    # boot) while the installed system runs through OVMF, so PCR 0/1/7 could not
    # have matched under any circumstances.
    #
    # The real binding happens on first boot, from inside the installed system,
    # where the PCRs are the ones that will actually exist at every later boot.
    # aios-first-boot re-enrols with --tpm2-pcrs=0+1+7 and wipes this slot; the
    # gate proves the final state is PCR-bound rather than assuming it.
    #
    # Why an unbound TPM2 slot rather than a keyfile: the key stays inside the
    # TPM instead of sitting in the clear on the unencrypted ESP next to the
    # disk it protects. The exposure window is one boot, and it requires physical
    # possession of this specific machine rather than just its disk.
    local _enroll_log="/tmp/aios-cryptenroll.log"
    if ! systemd-cryptenroll "${LUKS_PART}" \
            --unlock-key-file="${LUKS_TMP_KEYFILE}" \
            --tpm2-device=auto \
            --tpm2-pcrs= \
            --wipe-slot=tpm2 > "${_enroll_log}" 2>&1; then
        warn "systemd-cryptenroll failed:"
        sed 's/^/    cryptenroll: /' "${_enroll_log}" 2>/dev/null | head -n 12 || true
        warn "TPM2 devices present: $(ls /dev/tpm* 2>/dev/null | tr '\n' ' ' || echo none)"
        return 0
    fi

    # Verify rather than trust the exit code: the token has to be readable back
    # out of the LUKS2 header, otherwise "enrolled" is just a hopeful message.
    if cryptsetup luksDump "${LUKS_PART}" 2>/dev/null | grep -qi "systemd-tpm2"; then
        msg "TPM2 token enrolled and present in the LUKS2 header."
    else
        warn "systemd-cryptenroll reported success but no systemd-tpm2 token is in the LUKS2 header."
        return 0
    fi
}

# ── dm-verity (optional) ──────────────────────────────────────────────────────

do_verity() {
    if [ "${AIOS_SKIP_VERITY:-0}" = "1" ]; then
        info "dm-verity skipped (AIOS_SKIP_VERITY=1)."
        return 0
    fi
    # validate_env already made veritysetup a hard requirement when enforcing, so
    # this only trips if that guard was bypassed; fail closed rather than silently
    # producing an unenforced root under a loader entry committed to verity.
    if ! command -v veritysetup >/dev/null 2>&1; then
        die "veritysetup not found but verity is enforced" 5
    fi
    # CRITICAL ORDERING: veritysetup hashes the raw LUKS block device, so the
    # on-disk bytes of the root ext4 must be FINAL and FROZEN before the hash is
    # taken, and NOTHING may change them afterwards — any later write (even a
    # single metadata block) makes the boot-time hash check fail and the kernel
    # panics "dm-verity device corrupted" on a pristine install. This bit us
    # exactly that way: the old code wrote roothash.sig + rootfs-policy.json INTO
    # the root AFTER hashing, and hashed while the fs was still mounted rw (dirty
    # pages/journal not flushed to the device). The fixes below, in order:
    #
    #   1. The descriptive policy file is the LAST write into the root, and it is
    #      written BEFORE the freeze so it is covered by the hash (immutable and
    #      truthful). It no longer references a roothash.sig file (that file is
    #      gone — the hash lives on the kernel cmdline, not inside the root).
    #   2. sync + remount the root READ-ONLY: this flushes every dirty page and
    #      commits the ext4 journal, so the block device bytes are stable and
    #      identical to what the kernel will verity-check at boot (also mounted
    #      ro). do_bootloader only touches /boot and /boot/efi (separate rw
    #      partitions), so it needs no writable root.
    #   3. The root hash goes to a shell global + a tmp file OUTSIDE the root, so
    #      storing it does not perturb the hashed bytes.
    mkdir -p "${TARGET_MOUNT}/etc/aios/verity"
    cat > "${TARGET_MOUNT}/etc/aios/verity/rootfs-policy.json" <<EOF
{
  "schema": "aios.dm_verity_policy.v1",
  "revision": 14,
  "root_hash": "kernel-cmdline:roothash=",
  "hash_partition": "${ROOT_HASH_PART}",
  "verity_device": "/dev/mapper/root",
  "data_device": "/dev/mapper/aios-cryptroot",
  "enforced_at_boot": true,
  "fail_on_corruption": true,
  "corruption_action": "panic-on-corruption",
  "status": "ENFORCED",
  "note": "Root hash is on the kernel cmdline (roothash= + systemd.verity_root_data= + systemd.verity_root_hash=), NOT stored inside this read-only root. systemd-veritysetup opens /dev/mapper/root in the initramfs and root= boots it. systemd.verity_root_options=panic-on-corruption makes the kernel dm-verity target panic on any block whose hash does not match. This policy file is itself covered by the hash (written before the tree was built)."
}
EOF
    chmod 644 "${TARGET_MOUNT}/etc/aios/verity/rootfs-policy.json"

    # Freeze the root: flush + commit the journal, then make it read-only so the
    # bytes cannot change between hashing here and verification at boot.
    sync
    if ! mount -o remount,ro "${TARGET_MOUNT}" 2>/dev/null; then
        die "cannot remount the root read-only before hashing — refusing to hash a live rw fs" 5
    fi

    # Build the hash tree over the now-frozen data device. --root-hash-file points
    # at installer-local storage (a tmpfs path), never the target root.
    local _roothash_file="/run/aios-verity-roothash"
    if ! veritysetup format "${LUKS_MAPPER}" "${ROOT_HASH_DEV}" \
        --root-hash-file="${_roothash_file}" 2>/dev/null; then
        die "dm-verity hash generation failed (verity is enforced)" 5
    fi
    ROOT_HASH_VALUE=$(head -n1 "${_roothash_file}" | tr -d '[:space:]')
    rm -f "${_roothash_file}"
    if [ -z "${ROOT_HASH_VALUE}" ]; then
        die "dm-verity produced an empty root hash (verity is enforced)" 5
    fi

    msg "dm-verity hash tree built over the frozen (ro) root; root hash ${ROOT_HASH_VALUE}."
    msg "dm-verity is ENFORCED — the loader cmdline boots /dev/mapper/root with panic-on-corruption."
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

    # Find the real compiled binary policy the way build-aios-iso.sh does, and
    # take the store name from its path.
    #
    # This used to hardcode SELINUXTYPE=aios and gate enforcing on
    # /etc/selinux/aios/policy/policy.33 — a `touchplaceholder` stub from the
    # retired Rev12 mkrootfs.sh path. The R13 openSUSE base ships
    # selinux-policy-targeted, i.e. /etc/selinux/targeted/policy/policy.34. So
    # the guard tested for a file this pipeline never produces: enforcing was
    # unreachable by construction and every install silently fell back to
    # permissive, which R13.7 forbids for STIG_ALIGNED and AIRGAP_HIGH.
    local _policy _policy_type
    _policy="$(find "${TARGET_MOUNT}/etc/selinux" -mindepth 3 -maxdepth 3 \
        -type f -path '*/policy/policy.*' 2>/dev/null | sort | head -n1)"

    if [ -n "${_policy}" ]; then
        _policy_type="$(basename "$(dirname "$(dirname "${_policy}")")")"
        msg "SELinux policy found: ${_policy} (store: ${_policy_type})"
    else
        _policy_type="targeted"
        if [ "${SELINUX_MODE}" = "enforcing" ]; then
            warn "SELinux enforcing requested but no compiled policy is present; using permissive."
            SELINUX_MODE="permissive"
        fi
    fi

    cat > "${TARGET_MOUNT}/etc/selinux/config" <<EOF
SELINUX=${SELINUX_MODE}
SELINUXTYPE=${_policy_type}
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

    # Write recovery key (hex) AND enrol it into the LUKS2 header.
    #
    # This used to only write the file. Nothing ever called luksAddKey, so the
    # "recovery key" was a random number in a text file that unlocked nothing --
    # while installer/README.md told the operator it was their way back in. A
    # recovery key that does not recover is worse than none: it is relied upon
    # exactly once, at the moment recovery is already needed.
    local _recovery="${TARGET_MOUNT}/etc/aios/recovery-key.txt"
    local _hexkey
    # openssl (already in the base package set) instead of xxd, which ships in
    # vim-data and is absent from the live image — it exited 127 here (defect #10).
    _hexkey=$(openssl rand -hex 24 | fold -w 2 | head -n 24 | tr '\n' ' ')

    # No trailing newline in the key material: cryptsetup reads a key file
    # verbatim, but a typed passphrase carries no newline. Writing the file with
    # `echo` would enrol "<key>\n" and the operator typing "<key>" would be
    # rejected -- the key would exist in the header and still be unusable by hand.
    local _rk_tmp
    _rk_tmp="$(mktemp /tmp/aios-recovery-key.XXXXXX)"
    chmod 600 "${_rk_tmp}"
    printf '%s' "${_hexkey}" > "${_rk_tmp}"

    if ! cryptsetup luksAddKey "${LUKS_PART}" "${_rk_tmp}" \
            --key-file "${LUKS_TMP_KEYFILE}" 2>/dev/null; then
        shred -u "${_rk_tmp}" 2>/dev/null || rm -f "${_rk_tmp}"
        die "recovery key could not be enrolled into the LUKS2 header" 6
    fi

    # Prove it unlocks. An exit code says the command ran, not that the key works.
    if ! cryptsetup open --test-passphrase --key-file "${_rk_tmp}" "${LUKS_PART}" 2>/dev/null; then
        shred -u "${_rk_tmp}" 2>/dev/null || rm -f "${_rk_tmp}"
        die "recovery key was added but does not unlock the volume" 6
    fi
    shred -u "${_rk_tmp}" 2>/dev/null || rm -f "${_rk_tmp}"

    printf '%s\n' "${_hexkey}" > "${_recovery}"
    chmod 600 "${_recovery}"

    msg "First-boot flag written."
    msg "Recovery key enrolled in the LUKS2 header and verified to unlock."
    msg "Recovery key: ${_recovery}"
}

# ── Finalize ──────────────────────────────────────────────────────────────────

do_finalize() {
    info "=== Finalizing ==="
    sync

    for _kf in "${LUKS_TMP_KEYFILE}" "${VAR_KEYFILE}"; do
        if [ -n "${_kf}" ] && [ -f "${_kf}" ]; then
            dd if=/dev/urandom of="${_kf}" bs=64 count=1 status=none 2>/dev/null || true
            rm -f "${_kf}"
        fi
    done

    umount "${TARGET_MOUNT}/boot/efi" 2>/dev/null || true
    umount "${TARGET_MOUNT}/boot"     2>/dev/null || true
    umount "${TARGET_MOUNT}/recovery" 2>/dev/null || true
    umount "${TARGET_MOUNT}/var/lib/aios/rollback" 2>/dev/null || true
    umount "${TARGET_MOUNT}/var"      2>/dev/null || true
    umount "${TARGET_MOUNT}"           2>/dev/null || true
    SETUP_MOUNTED=0

    if [ -b "/dev/mapper/aios-var" ]; then
        cryptsetup close aios-var 2>/dev/null || true
    fi
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
    # Must precede do_verity: veritysetup hashes the entire root device, so any
    # write into the root after it (dracut's temporaries) invalidates the hash.
    do_initramfs
    do_verity
    do_bootloader
    do_finalize
}

main "$@"
