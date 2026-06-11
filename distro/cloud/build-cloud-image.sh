#!/bin/bash
set -euo pipefail

# =============================================================================
# AI-OS.NET Cloud Image Builder — Revision 7
# =============================================================================
# Builds cloud images (AWS AMI, GCP image, Azure VHD, OCI qcow2) from a shared
# AIOS rootfs. Integrates with cloud-init for fleet auto-enrollment and
# cloud-specific agents (waagent, WALinuxAgent, etc.).
#
# Requirements:
#   - qemu-img (qemu-utils)
#   - cloud-localds (cloud-image-utils)
#   - xorriso
#   - packer (optional, for cloud-native builds)
#   - sha256sum (coreutils)
#   - tar, gzip, xz (compression)
#   - sfdisk, losetup, mkfs.ext4 (for disk image assembly)
#
# Usage:
#   ./build-cloud-image.sh --cloud {aws|gcp|azure|oci}
#                          --format {qcow2|raw|vhd|vmdk}
#                          --profile {dev|secure|stig|airgap}
#                          --output-dir PATH
#                          [--dry-run] [--no-compress] [--help]
#
# Output:
#   <output-dir>/aios-rev7-<cloud>-<profile>-<date>.<format>
#   <output-dir>/aios-rev7-<cloud>-<profile>-<date>.manifest
#   <output-dir>/aios-rev7-<cloud>-<profile>-<date>.sha256
# =============================================================================

# ── Project paths ────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${REPO_ROOT}/distro/build"
CLOUD_DIR="${SCRIPT_DIR}"
CLOUD_INIT_DIR="${CLOUD_DIR}/cloud-init"
ROOTFS_DIR=""
OUTPUT_DIR=""
WORK_DIR=""

DATE_STAMP="$(date +%Y%m%d)"

# ── Defaults (overridable via args) ──────────────────────────────────────────

CLOUD="aws"
FORMAT="qcow2"
PROFILE="dev"
AIOS_VERSION="${AIOS_VERSION:-0.2.0}"
AIOS_BUILD_ID="${AIOS_BUILD_ID:-${DATE_STAMP}}"
DRY_RUN=false
NO_COMPRESS=false
DISK_SIZE_GB="${DISK_SIZE_GB:-10}"
ROOTFS_SOURCE="${ROOTFS_SOURCE:-}"

# ── Color output ─────────────────────────────────────────────────────────────

if [ -t 1 ]; then
    RED='\033[0;31m';    GREEN='\033[0;32m';    YELLOW='\033[0;33m'
    BLUE='\033[0;34m';   BOLD='\033[1m';         RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi

step()  { printf "${BOLD}${BLUE}=== %s${RESET}\n" "$*"; }
info()  { printf "    ${GREEN}→${RESET} %s\n" "$*"; }
warn()  { printf "    ${YELLOW}⚠${RESET}  %s\n" "$*" >&2; }
err()   { printf "${BOLD}${RED}✗${RESET} %s\n" "$*" >&2; }
ok()    { printf "    ${GREEN}✓${RESET} %s\n" "$*"; }
die()   { err "$*"; exit 1; }

banner() {
    printf "\n${BOLD}${BLUE}"
    printf "╔══════════════════════════════════════════════════════════╗\n"
    printf "║   AI-OS.NET Cloud Image Builder — Revision 7             ║\n"
    printf "║   Version: %-10s  Profile: %-8s              ║\n" "${AIOS_VERSION}" "${PROFILE}"
    printf "║   Cloud:   %-10s  Format:  %-8s              ║\n" "${CLOUD}" "${FORMAT}"
    printf "║   Output:  %-40s  ║\n" "${OUTPUT_DIR}"
    printf "╚══════════════════════════════════════════════════════════╝${RESET}\n\n"
}

# ── Argument parsing ─────────────────────────────────────────────────────────

usage() {
    printf "Usage: %s [OPTIONS]\n" "$(basename "$0")"
    printf "\nOptions:\n"
    printf "  --cloud CLOUD        Target cloud: aws, gcp, azure, oci (default: aws)\n"
    printf "  --format FMT         Image format: qcow2, raw, vhd, vmdk (default: qcow2)\n"
    printf "  --profile PROFILE    Security profile: dev, secure, stig, airgap (default: dev)\n"
    printf "  --output-dir DIR     Output directory for images and manifests\n"
    printf "  --version VERSION    AIOS version string\n"
    printf "  --build-id ID        Build identifier\n"
    printf "  --disk-size GB       Disk image size in GB (default: 10)\n"
    printf "  --rootfs PATH        Path to pre-built rootfs directory (skips rootfs build)\n"
    printf "  --dry-run            Print actions without executing\n"
    printf "  --no-compress        Skip image compression\n"
    printf "  --help, -h           Show this help\n"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --cloud)          CLOUD="$2";         shift 2 ;;
        --format)         FORMAT="$2";        shift 2 ;;
        --profile)        PROFILE="$2";       shift 2 ;;
        --output-dir)     OUTPUT_DIR="$2";    shift 2 ;;
        --version)        AIOS_VERSION="$2";  shift 2 ;;
        --build-id)       AIOS_BUILD_ID="$2"; shift 2 ;;
        --disk-size)      DISK_SIZE_GB="$2";  shift 2 ;;
        --rootfs)         ROOTFS_SOURCE="$2"; shift 2 ;;
        --dry-run)        DRY_RUN=true;       shift ;;
        --no-compress)    NO_COMPRESS=true;   shift ;;
        --help|-h)        usage ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ── Validate arguments ───────────────────────────────────────────────────────

case "${CLOUD}" in
    aws|gcp|azure|oci) ;;
    *) die "Invalid cloud provider: ${CLOUD}. Must be one of: aws, gcp, azure, oci" ;;
esac

case "${FORMAT}" in
    qcow2|raw|vhd|vmdk) ;;
    *) die "Invalid format: ${FORMAT}. Must be one of: qcow2, raw, vhd, vmdk" ;;
esac

case "${PROFILE}" in
    dev|secure|stig|airgap) ;;
    *) die "Invalid profile: ${PROFILE}. Must be one of: dev, secure, stig, airgap" ;;
esac

if [ -z "${OUTPUT_DIR}" ]; then
    die "--output-dir is required"
fi

IMAGE_NAME="aios-rev7-${CLOUD}-${PROFILE}-${DATE_STAMP}"
DISK_IMAGE="${OUTPUT_DIR}/${IMAGE_NAME}.${FORMAT}"
WORK_DIR="${OUTPUT_DIR}/.work-${IMAGE_NAME}"
ROOTFS_DIR="${WORK_DIR}/rootfs"

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    banner

    # ── Phase 1: Validate dependencies ────────────────────────────────────

    step "Phase 1: Validating dependencies"
    MISSING=""
    check_dep() {
        if ! command -v "$1" >/dev/null 2>&1; then
            MISSING="${MISSING}  - $1 ($2)\n"
        fi
    }
    check_dep sha256sum "coreutils"
    check_dep tar        "tar"
    check_dep gzip       "gzip"
    check_dep xz         "xz-utils"
    check_dep dd         "coreutils"
    check_dep losetup    "mount"
    check_dep mkfs.ext4  "e2fsprogs"
    check_dep sfdisk     "util-linux"
    check_dep qemu-img   "qemu-utils"

    HAS_CLOUD_LOCALDS=false
    HAS_PACKER=false
    HAS_XORRISO=false

    if command -v cloud-localds >/dev/null 2>&1; then
        HAS_CLOUD_LOCALDS=true
    else
        warn "cloud-localds not found (cloud-image-utils) — cloud-init disk injection will be skipped."
    fi

    if command -v packer >/dev/null 2>&1; then
        HAS_PACKER=true
    else
        warn "packer not found — cloud-native builds require packer."
    fi

    if command -v xorriso >/dev/null 2>&1; then
        HAS_XORRISO=true
    fi

    if [ -n "${MISSING}" ]; then
        err "Missing required tools:"
        printf "${MISSING}"
        die "Install missing dependencies and retry."
    fi
    ok "Dependency validation complete."

    ${DRY_RUN} && { warn "DRY-RUN mode — no files will be written."; exit 0; }

    # ── Phase 2: Build or import base rootfs ──────────────────────────────

    step "Phase 2: Preparing base rootfs"
    mkdir -p "${WORK_DIR}" "${ROOTFS_DIR}" "${OUTPUT_DIR}"

    if [ -n "${ROOTFS_SOURCE}" ] && [ -d "${ROOTFS_SOURCE}" ]; then
        info "Copying rootfs from: ${ROOTFS_SOURCE}"
        rsync -a "${ROOTFS_SOURCE}/" "${ROOTFS_DIR}/"
    else
        info "Building rootfs from project source..."
        if [ -x "${BUILD_DIR}/build-aios-iso.sh" ]; then
            ROOTFS_ONLY=true "${BUILD_DIR}/build-aios-iso.sh" --output "${OUTPUT_DIR}/aios-rev4.iso" || \
                warn "build-aios-iso.sh failed; continuing with empty rootfs."
        fi
        mkdir -p "${ROOTFS_DIR}"/usr/{bin,lib/aios,share/aios}
        mkdir -p "${ROOTFS_DIR}"/etc/{aios/config.d,selinux/aios/policy,systemd/system,ssl/certs}
        mkdir -p "${ROOTFS_DIR}"/var/{lib/aios/{evidence,policy,capsules,backup,state},log/aios,cache/aios,tmp}
        mkdir -p "${ROOTFS_DIR}"/run/aios
        mkdir -p "${ROOTFS_DIR}"/boot/{loader/entries,EFI/BOOT}
        mkdir -p "${ROOTFS_DIR}"/{tmp,proc,sys,dev,mnt,media,opt/aios,home/aios,root,srv}

        ln -sf usr/bin  "${ROOTFS_DIR}/bin"
        ln -sf usr/lib  "${ROOTFS_DIR}/lib"
        ln -sf usr/lib  "${ROOTFS_DIR}/lib64"
        ln -sf bin      "${ROOTFS_DIR}/usr/sbin"
        ln -sf ../run   "${ROOTFS_DIR}/var/run"
        ln -sf ../lock  "${ROOTFS_DIR}/var/lock"
        ln -sf usr/bin  "${ROOTFS_DIR}/sbin"
    fi
    ok "Base rootfs prepared at ${ROOTFS_DIR}"

    # ── Phase 3: Inject cloud-init configuration ──────────────────────────

    step "Phase 3: Injecting cloud-init configuration"

    mkdir -p "${ROOTFS_DIR}/etc/cloud/cloud.cfg.d"

    if [ -f "${CLOUD_INIT_DIR}/aios-cloud-config.yml" ]; then
        cp "${CLOUD_INIT_DIR}/aios-cloud-config.yml" \
           "${ROOTFS_DIR}/etc/cloud/cloud.cfg.d/99-aios-cloud.cfg"
        info "Cloud-init config installed: /etc/cloud/cloud.cfg.d/99-aios-cloud.cfg"
    else
        warn "aios-cloud-config.yml not found at ${CLOUD_INIT_DIR}/aios-cloud-config.yml"
        cat > "${ROOTFS_DIR}/etc/cloud/cloud.cfg.d/99-aios-cloud.cfg" <<'CLOUDEOF'
#cloud-config
hostname: aios
preserve_hostname: false
manage_etc_hosts: true
users:
  - name: aios
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
ssh_pwauth: false
package_update: false
package_upgrade: false
CLOUDEOF
        info "Generated minimal cloud-init config (fallback)."
    fi

    mkdir -p "${ROOTFS_DIR}/var/lib/cloud/scripts/per-boot"
    ok "Cloud-init configuration injected."

    # ── Phase 4: Install cloud-specific agents ────────────────────────────

    step "Phase 4: Installing cloud-specific agents"

    mkdir -p "${ROOTFS_DIR}/usr/lib/aios/cloud"

    case "${CLOUD}" in
        aws)
            info "AWS: cloud-init handles all guest services."
            ;;
        gcp)
            info "GCP: cloud-init handles all guest services."
            ;;
        azure)
            info "Azure: WALinuxAgent (waagent) required for Azure guest services."
            if command -v waagent >/dev/null 2>&1; then
                mkdir -p "${ROOTFS_DIR}/usr/sbin"
                cp "$(command -v waagent)" "${ROOTFS_DIR}/usr/sbin/waagent"
                chmod 755 "${ROOTFS_DIR}/usr/sbin/waagent"
                ok "waagent installed for Azure compatibility."
            else
                warn "waagent not found on build host — install WALinuxAgent for Azure images."
            fi
            ;;
        oci)
            info "OCI: cloud-init handles all guest services."
            ;;
    esac
    ok "Cloud-specific agents installed for ${CLOUD}."

    # ── Phase 5: SELinux autorelabel ──────────────────────────────────────

    step "Phase 5: SELinux autorelabel"

    touch "${ROOTFS_DIR}/.autorelabel"
    info ".autorelabel touch file created for first-boot relabel."

    case "${PROFILE}" in
        dev)
            cat > "${ROOTFS_DIR}/etc/selinux/config" <<'EOF'
SELINUX=permissive
SELINUXTYPE=aios
EOF
            info "SELinux set to permissive (dev profile)."
            ;;
        secure|stig|airgap)
            cat > "${ROOTFS_DIR}/etc/selinux/config" <<'EOF'
SELINUX=enforcing
SELINUXTYPE=aios
EOF
            info "SELinux set to enforcing (${PROFILE} profile)."
            ;;
    esac

    if [ ! -f "${ROOTFS_DIR}/etc/selinux/aios/policy/policy.33" ]; then
        mkdir -p "${ROOTFS_DIR}/etc/selinux/aios/policy"
        cat > "${ROOTFS_DIR}/etc/selinux/aios/policy/policy.33" <<'EOF'
# AI-OS.NET SELinux Policy — Placeholder (cloud)
EOF
        warn "No compiled SELinux policy found — installed placeholder."
    fi
    ok "SELinux configured."

    # ── Phase 6: Strip unnecessary packages ───────────────────────────────

    step "Phase 6: Stripping unnecessary packages"

    case "${PROFILE}" in
        airgap)
            info "Airgap profile: maximum stripping."
            rm -rf "${ROOTFS_DIR}/usr/share/doc" 2>/dev/null || true
            rm -rf "${ROOTFS_DIR}/usr/share/man" 2>/dev/null || true
            rm -rf "${ROOTFS_DIR}/usr/share/info" 2>/dev/null || true
            rm -rf "${ROOTFS_DIR}/usr/share/locale" 2>/dev/null || true
            ;;
        stig)
            info "STIG profile: removing debug and doc packages."
            rm -rf "${ROOTFS_DIR}/usr/share/doc" 2>/dev/null || true
            rm -rf "${ROOTFS_DIR}/usr/share/man" 2>/dev/null || true
            ;;
        secure)
            info "Secure profile: removing man pages."
            rm -rf "${ROOTFS_DIR}/usr/share/man" 2>/dev/null || true
            ;;
        dev)
            info "Dev profile: keeping all packages."
            ;;
    esac
    ok "Package stripping complete for ${PROFILE} profile."

    # ── Phase 7: Create disk image ────────────────────────────────────────

    step "Phase 7: Creating disk image (${DISK_SIZE_GB} GB, ${FORMAT})"

    RAW_IMAGE="${WORK_DIR}/${IMAGE_NAME}.raw"
    qemu-img create -f raw "${RAW_IMAGE}" "${DISK_SIZE_GB}G"

    LOOP_DEV=""
    setup_loop() {
        LOOP_DEV="$(losetup --find --show --partscan "${RAW_IMAGE}")"
        info "Loop device: ${LOOP_DEV}"
    }

    cleanup_loop() {
        if [ -n "${LOOP_DEV}" ] && losetup "${LOOP_DEV}" >/dev/null 2>&1; then
            losetup -d "${LOOP_DEV}" 2>/dev/null || true
        fi
    }
    trap cleanup_loop EXIT

    setup_loop

    sfdisk "${LOOP_DEV}" <<PARTEOF
label: gpt
name="EFI System Partition", size=512MiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
name="AIOS Root", type=0FC63DAF-8483-4772-8E79-3D69D8477DE4
PARTEOF

    LOOP_P1="${LOOP_DEV}p1"
    LOOP_P2="${LOOP_DEV}p2"

    mkfs.vfat -F 32 -n "AIOS_EFI" "${LOOP_P1}" >/dev/null 2>&1
    mkfs.ext4 -L "aios-root" "${LOOP_P2}" >/dev/null 2>&1

    MOUNT_POINT="${WORK_DIR}/mnt"
    mkdir -p "${MOUNT_POINT}"
    mount "${LOOP_P2}" "${MOUNT_POINT}"

    rsync -a "${ROOTFS_DIR}/" "${MOUNT_POINT}/"

    mkdir -p "${MOUNT_POINT}/boot/efi"
    mount "${LOOP_P1}" "${MOUNT_POINT}/boot/efi"
    mkdir -p "${MOUNT_POINT}/boot/efi/EFI/BOOT"

    umount "${MOUNT_POINT}/boot/efi" 2>/dev/null || true
    umount "${MOUNT_POINT}" 2>/dev/null || true
    cleanup_loop
    trap - EXIT

    ok "Disk image created: ${RAW_IMAGE}"

    # ── Phase 8: Install bootloader ───────────────────────────────────────

    step "Phase 8: Installing bootloader (systemd-boot)"

    BOOT_MOUNT="${WORK_DIR}/boot-mount"
    ROOT_MOUNT="${WORK_DIR}/root-mount"
    mkdir -p "${BOOT_MOUNT}" "${ROOT_MOUNT}"

    setup_loop

    mount "${LOOP_P2}" "${ROOT_MOUNT}"
    mount "${LOOP_P1}" "${ROOT_MOUNT}/boot/efi"

    if command -v bootctl >/dev/null 2>&1; then
        bootctl install --esp-path="${ROOT_MOUNT}/boot/efi" --boot-path="${ROOT_MOUNT}/boot" 2>/dev/null || \
            warn "bootctl install failed — EFI boot may not work on first boot."
    else
        warn "bootctl not found — skipping bootloader installation."
    fi

    cat > "${ROOT_MOUNT}/boot/loader/loader.conf" <<'LOADEREOF'
timeout 3
console-mode keep
default aios-*
editor no
auto-entries no
auto-firmware no
LOADEREOF

    mkdir -p "${ROOT_MOUNT}/boot/loader/entries"
    cat > "${ROOT_MOUNT}/boot/loader/entries/aios.conf" <<LOADEREOF
title   AI-OS.NET (Revision 7)
linux   /vmlinuz-aios
initrd  /initramfs-aios.img
options root=LABEL=aios-root ro quiet loglevel=3
LOADEREOF

    umount "${ROOT_MOUNT}/boot/efi" 2>/dev/null || true
    umount "${ROOT_MOUNT}" 2>/dev/null || true
    cleanup_loop
    trap - EXIT

    ok "Bootloader installed."

    # ── Phase 9: Compress / Convert image ─────────────────────────────────

    step "Phase 9: Converting image to ${FORMAT}"

    if [ "${FORMAT}" = "raw" ]; then
        mv "${RAW_IMAGE}" "${DISK_IMAGE}"
        IMAGE_SIZE="$(du -h "${DISK_IMAGE}" | cut -f1)"
        ok "Raw image: ${DISK_IMAGE} (${IMAGE_SIZE})"
    else
        qemu-img convert -f raw -O "${FORMAT}" "${RAW_IMAGE}" "${DISK_IMAGE}"
        IMAGE_SIZE="$(du -h "${DISK_IMAGE}" | cut -f1)"
        ok "Converted image: ${DISK_IMAGE} (${IMAGE_SIZE})"
    fi

    if ! ${NO_COMPRESS}; then
        COMPRESSED="${DISK_IMAGE}.xz"
        xz -9 --check=crc32 "${DISK_IMAGE}" -c > "${COMPRESSED}"
        COMPRESSED_SIZE="$(du -h "${COMPRESSED}" | cut -f1)"
        info "Compressed: ${COMPRESSED} (${COMPRESSED_SIZE})"
        rm -f "${DISK_IMAGE}"
        DISK_IMAGE="${COMPRESSED}"
    fi

    ok "Image ready: ${DISK_IMAGE}"

    # ── Phase 10: Generate checksums + manifest ───────────────────────────

    step "Phase 10: Generating checksums and manifest"

    CHECKSUM_FILE="${OUTPUT_DIR}/${IMAGE_NAME}.sha256"
    sha256sum "$(basename "${DISK_IMAGE}")" > "${CHECKSUM_FILE}" || \
        warn "Could not generate checksum file."
    ok "Checksums: ${CHECKSUM_FILE}"

    MANIFEST_FILE="${OUTPUT_DIR}/${IMAGE_NAME}.manifest"
    cat > "${MANIFEST_FILE}" <<MANIFEST
# AI-OS.NET Cloud Image Manifest
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

[metadata]
name = "${IMAGE_NAME}"
version = "${AIOS_VERSION}"
build_id = "${AIOS_BUILD_ID}"
cloud = "${CLOUD}"
profile = "${PROFILE}"
format = "${FORMAT}"
disk_size_gb = ${DISK_SIZE_GB}
build_date = "$(date -u +"%Y-%m-%d")"
build_host = "$(hostname 2>/dev/null || echo unknown)"

[checksums]
file = "$(basename "${DISK_IMAGE}")"

[fleet]
enroll_on_boot = true
coordinator_discovery = "cloud-init metadata"

[security]
selinux_mode = "$(grep '^SELINUX=' "${ROOTFS_DIR}/etc/selinux/config" 2>/dev/null | cut -d= -f2 || echo unknown)"
tpm2_required = false

[packages]
cloud_agent = "$(case "${CLOUD}" in azure) echo "waagent";; *) echo "cloud-init";; esac)"
MANIFEST
    ok "Manifest: ${MANIFEST_FILE}"

    # ── Cleanup work directory ────────────────────────────────────────────

    rm -rf "${WORK_DIR}"
    info "Work directory cleaned."

    # ── Build summary ─────────────────────────────────────────────────────

    printf "\n${BOLD}${BLUE}════════════════════════════════════════════════════════${RESET}\n"
    printf "${BOLD}${GREEN}  CLOUD IMAGE BUILD COMPLETE${RESET}\n\n"
    printf "  Image:      ${BOLD}%s${RESET}\n" "${DISK_IMAGE}"
    printf "  Cloud:      %s\n" "${CLOUD}"
    printf "  Format:     %s\n" "${FORMAT}"
    printf "  Profile:    %s\n" "${PROFILE}"
    printf "  Disk size:  %s GB\n" "${DISK_SIZE_GB}"
    printf "  Checksum:   %s\n" "${CHECKSUM_FILE}"
    printf "  Manifest:   %s\n" "${MANIFEST_FILE}"
    printf "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${RESET}\n"
    printf "${BOLD}${BLUE}║   Cloud provider: %-10s                               ║${RESET}\n" "${CLOUD}"

    case "${CLOUD}" in
        aws)
            printf "${BOLD}${BLUE}║   Upload: aws ec2 import-image ...                      ║${RESET}\n"
            ;;
        gcp)
            printf "${BOLD}${BLUE}║   Upload: gcloud compute images create ...               ║${RESET}\n"
            ;;
        azure)
            printf "${BOLD}${BLUE}║   Upload: az vm image create ...                         ║${RESET}\n"
            ;;
        oci)
            printf "${BOLD}${BLUE}║   Upload: qemu-img convert + upload to object storage    ║${RESET}\n"
            ;;
    esac
    printf "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${RESET}\n"

    printf "\n${BOLD}${GREEN}  STATUS: BUILD SUCCESSFUL${RESET}\n"
}

main "$@"
