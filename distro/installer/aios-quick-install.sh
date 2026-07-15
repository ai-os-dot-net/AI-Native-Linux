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
CHROOT_MOUNTED=0

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
        umount "${TARGET_MOUNT}"           2>/dev/null || true
    fi
    if [ -b "/dev/mapper/aios-cryptroot" ]; then
        cryptsetup close aios-cryptroot 2>/dev/null || true
    fi
    rm -f "${LUKS_TMP_KEYFILE}" 2>/dev/null || true
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
    MIN_DISK_GB="${AIOS_MIN_DISK_GB:-40}"
    SELINUX_MODE="${AIOS_SELINUX_MODE:-permissive}"
    AIOS_SQUASHFS="${AIOS_SQUASHFS:-/run/initramfs/live/aios.squashfs}"

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
    for _bin in lsblk sgdisk mkfs.vfat mkfs.ext4 cryptsetup dmsetup unsquashfs bootctl blkid dracut; do
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

    # --no-hostonly: the image must boot the installed disk on real hardware,
    #   not only on the QEMU host that happened to generate it.
    # --add "crypt dm": the root is LUKS2 at /dev/mapper/aios-cryptroot, so the
    #   initramfs must be able to unlock it; without these the kernel panics
    #   with "unable to mount root fs".
    local _dracut_log="/tmp/aios-dracut.log"
    if ! chroot "${TARGET_MOUNT}" dracut --force --no-hostonly \
            --add "crypt dm" \
            /boot/initramfs-aios.img "${AIOS_KVER}" > "${_dracut_log}" 2>&1; then
        err "dracut failed — last 30 lines:"
        tail -n 30 "${_dracut_log}" >&2 || true
        die "initramfs generation failed" 9
    fi

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
    cp -L --remove-destination "${_modules_dir}/${AIOS_KVER}/vmlinuz" \
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
    # openssl (already in the base package set) instead of xxd, which ships in
    # vim-data and is absent from the live image — it exited 127 here (defect #10).
    _hexkey=$(openssl rand -hex 24 | fold -w 2 | head -n 24 | tr '\n' ' ')
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
    # Must precede do_verity: veritysetup hashes the entire root device, so any
    # write into the root after it (dracut's temporaries) invalidates the hash.
    do_initramfs
    do_verity
    do_bootloader
    do_finalize
}

main "$@"
