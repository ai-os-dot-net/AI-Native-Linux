#!/bin/bash
set -euo pipefail

# AI-OS.NET R13.1 openSUSE base-rootfs builder.
#
# Builds a production Linux userspace rootfs for build-aios-iso.sh.
# The default is openSUSE Leap 16.0, x86_64, with a 24-month support window.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

OUTPUT="${AIOS_OPENSUSE_ROOTFS:-}"
RELEASE="${AIOS_OPENSUSE_RELEASE:-16.0}"
SERIES="${AIOS_OPENSUSE_SERIES:-16.x}"
ARCH="${AIOS_OPENSUSE_ARCH:-x86_64}"
VARIANT="${AIOS_OPENSUSE_VARIANT:-leap}"
SUPPORT_MONTHS="${AIOS_OPENSUSE_SUPPORT_MONTHS:-24}"
EOL_DATE="${AIOS_OPENSUSE_EOL_DATE:-2027-10-31}"
REPO_OSS="${AIOS_OPENSUSE_REPO_OSS:-}"
REPO_UPDATE="${AIOS_OPENSUSE_REPO_UPDATE:-}"
PACKAGE_SET="${AIOS_OPENSUSE_PACKAGE_SET:-server}"
ZYPPER_SETTLE_SECONDS="${AIOS_ZYPPER_SETTLE_SECONDS:-5}"
DRY_RUN=false
FORCE=false
RESUME=false

BASE_PACKAGES=(
    patterns-base-minimal_base
    aaa_base
    bash
    coreutils
    findutils
    grep
    sed
    gawk
    tar
    gzip
    xz
    # NB: systemd-sysvcompat does not exist in Leap 16.0 (dropped upstream);
    # the initramfs init discovers /usr/lib/systemd/systemd directly.
    systemd
    # systemd ships bootctl, but NOT the loader binary it installs. The EFI
    # payload (/usr/lib/systemd/boot/efi/systemd-bootx64.efi) lives in the
    # separate systemd-boot package. Without it `bootctl install` creates only
    # the ESP directory skeleton + loader.conf and installs no EFI binary, so
    # the firmware finds nothing to boot and drops to the EFI shell (defect
    # #12a: pipeline 5309 ESP had zero .efi files while bootctl was present).
    systemd-boot
    dbus-1
    util-linux
    iproute2
    iputils
    ca-certificates
    openssl
    jq
    shadow
    sudo
    timezone
    kernel-default
    kernel-firmware-all
    dracut
    cryptsetup
    tpm2.0-tools
    # tpm2.0-tools pulls the tss2 stack (esys/sys/mu/rc/tctildr) but NOT a TCTI
    # *driver*. tctildr is only the loader that goes looking for one; without a
    # driver every TPM call dies with "TPM TCTI driver not available" even
    # though /dev/tpm0 and /dev/tpmrm0 are present. systemd-cryptenroll then
    # fails and the installer's warn-and-continue path hid it, so installs
    # completed with no TPM2 token in the LUKS2 header (R13.4).
    # Same shape as defect #12a: the tool ships, the payload does not.
    libtss2-tcti-device0    # talks to /dev/tpm0 and /dev/tpmrm0 (real + swtpm)
    libtss2-tcti-cmd0       # command-channel TCTI, used by swtpm/mssim setups
    device-mapper
    lvm2
    # Installer tool dependencies (distro/installer/aios-quick-install.sh
    # requires: lsblk sgdisk mkfs.vfat mkfs.ext4 cryptsetup unsquashfs bootctl
    # blkid). lsblk/blkid come from util-linux, cryptsetup + bootctl(systemd,
    # with its EFI payload from systemd-boot) are already above; these provide
    # the rest. Pipeline 4742 proved the unattended install reaches the tool
    # check and dies on missing sgdisk.
    gptfdisk       # sgdisk (GPT partitioning)
    dosfstools     # mkfs.vfat (ESP)
    e2fsprogs      # mkfs.ext4 (boot/recovery/root/rollback)
    squashfs       # unsquashfs (rootfs extraction from the live medium)
    policycoreutils
    restorecond
    selinux-policy-targeted
    audit
    grub2
    grub2-x86_64-efi
    shim
    mokutil
    openssh-server
    wicked
)

DESKTOP_PACKAGES=(
    patterns-kde-kde_plasma
    sddm
    konsole
)

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --output PATH          Rootfs output path
  --release VERSION     openSUSE Leap version (default: ${RELEASE})
  --arch ARCH           Target architecture: x86_64|aarch64 (default: ${ARCH})
  --repo-oss URL        openSUSE OSS repository URL
  --repo-update URL     openSUSE update repository URL
  --package-set NAME    minimal|server|desktop (default: ${PACKAGE_SET})
  --force               Replace an existing output directory
  --resume              Continue an existing partial rootfs
  --dry-run             Print zypper commands without modifying output
  -h, --help            Show this help

Output metadata:
  /etc/aios/base-rootfs.env
  /etc/aios/base-rootfs.json

Real package installation must run as root or inside a rootful container.
Set AIOS_ALLOW_ROOTLESS_ZYPPER=1 only for debugging zypper target behavior.
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '[opensuse-rootfs] %s\n' "$*"
}

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output)      [ "$#" -ge 2 ] || die "--output requires PATH"; OUTPUT="$2"; shift 2 ;;
        --release)     [ "$#" -ge 2 ] || die "--release requires VERSION"; RELEASE="$2"; shift 2 ;;
        --arch)        [ "$#" -ge 2 ] || die "--arch requires ARCH"; ARCH="$2"; shift 2 ;;
        --repo-oss)    [ "$#" -ge 2 ] || die "--repo-oss requires URL"; REPO_OSS="$2"; shift 2 ;;
        --repo-update) [ "$#" -ge 2 ] || die "--repo-update requires URL"; REPO_UPDATE="$2"; shift 2 ;;
        --package-set) [ "$#" -ge 2 ] || die "--package-set requires NAME"; PACKAGE_SET="$2"; shift 2 ;;
        --force)       FORCE=true; shift ;;
        --resume)      RESUME=true; shift ;;
        --dry-run)     DRY_RUN=true; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             die "unknown argument: $1" ;;
    esac
done

case "${ARCH}" in
    x86_64|aarch64) ;;
    *) die "unsupported R13.1 architecture: ${ARCH}" ;;
esac

case "${SUPPORT_MONTHS}" in
    ''|*[!0-9]*) die "AIOS_OPENSUSE_SUPPORT_MONTHS must be numeric: ${SUPPORT_MONTHS}" ;;
esac

case "${ZYPPER_SETTLE_SECONDS}" in
    ''|*[!0-9]*) die "AIOS_ZYPPER_SETTLE_SECONDS must be numeric: ${ZYPPER_SETTLE_SECONDS}" ;;
esac

[ -n "${EOL_DATE}" ] || die "AIOS_OPENSUSE_EOL_DATE must not be empty"

[ -n "${OUTPUT}" ] \
    || OUTPUT="${REPO_ROOT}/distro/build/out/rootfs-opensuse-leap-${RELEASE}-${ARCH}"
# Normalize to an absolute path so the --force safety allowlist below matches
# CI-style relative paths (e.g. distro/build/out/rootfs-...).
case "${OUTPUT}" in
    /*) : ;;
    *)  OUTPUT="${REPO_ROOT}/${OUTPUT}" ;;
esac
[ -n "${REPO_OSS}" ] \
    || REPO_OSS="https://download.opensuse.org/distribution/leap/${RELEASE}/repo/oss/"
if [ -z "${REPO_UPDATE}" ]; then
    case "${RELEASE}" in
        16.*) REPO_UPDATE="${REPO_OSS}" ;;
        *)    REPO_UPDATE="https://download.opensuse.org/update/leap/${RELEASE}/oss/" ;;
    esac
fi

case "${PACKAGE_SET}" in
    minimal|server) PACKAGES=("${BASE_PACKAGES[@]}") ;;
    desktop)        PACKAGES=("${BASE_PACKAGES[@]}" "${DESKTOP_PACKAGES[@]}") ;;
    *)              die "unsupported package set: ${PACKAGE_SET}" ;;
esac

if ! ${DRY_RUN} && ! command -v zypper >/dev/null 2>&1; then
    die "zypper not found. Run this builder on openSUSE/SUSE or use a container with zypper."
fi

if ! ${DRY_RUN} \
    && [ "$(id -u)" -ne 0 ] \
    && [ "${AIOS_ALLOW_ROOTLESS_ZYPPER:-0}" != "1" ]; then
    die "real openSUSE rootfs build requires root or a rootful container. Use --dry-run for validation, or set AIOS_ALLOW_ROOTLESS_ZYPPER=1 only for debugging."
fi

if ${FORCE} && ${RESUME}; then
    die "--force and --resume are mutually exclusive"
fi

if [ -e "${OUTPUT}" ] && ! ${FORCE} && ! ${RESUME}; then
    die "output already exists: ${OUTPUT} (use --force to replace or --resume to continue)"
fi

ZYPPER_BASE=(
    zypper
    --non-interactive
    --gpg-auto-import-keys
    --root "${OUTPUT}"
)

print_cmd() {
    local arg
    printf '+'
    for arg in "$@"; do
        printf ' %q' "${arg}"
    done
    printf '\n'
}

run_cmd() {
    if ${DRY_RUN}; then
        print_cmd "$@"
    else
        "$@"
    fi
}

run_zypper() {
    local attempt
    local log_file
    local rc

    if ${DRY_RUN}; then
        print_cmd "$@"
        return 0
    fi

    attempt=1
    while [ "${attempt}" -le 3 ]; do
        log_file="$(mktemp "${TMPDIR:-/tmp}/aios-zypper.XXXXXX")"
        if "$@" >"${log_file}" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        cat "${log_file}"
        if [ "${rc}" -eq 0 ] && ! grep -q 'Target initialization failed' "${log_file}"; then
            rm -f "${log_file}"
            return 0
        fi

        if [ "${rc}" -ne 4 ] && ! grep -q 'Target initialization failed' "${log_file}"; then
            rm -f "${log_file}"
            return "${rc}"
        fi

        rm -f "${log_file}"
        info "Retrying zypper command after target initialization failure (${attempt}/3)"
        sync
        sleep 2
        attempt=$(( attempt + 1 ))
    done

    return 1
}

prepare_target_root() {
    run_cmd mkdir -p \
        "${OUTPUT}" \
        "${OUTPUT}/usr/lib/rpm/gnupg/keys" \
        "${OUTPUT}/var/lib/rpm" \
        "${OUTPUT}/var/lib/zypp" \
        "${OUTPUT}/var/cache/zypp" \
        "${OUTPUT}/etc/zypp/repos.d"
}

add_repo() {
    local repo_url="$1"
    local repo_alias="$2"
    local repo_file="${OUTPUT}/etc/zypp/repos.d/${repo_alias}.repo"

    if [ -f "${repo_file}" ]; then
        info "Repository already present: ${repo_alias}"
        return 0
    fi

    run_zypper "${ZYPPER_BASE[@]}" ar -f "${repo_url}" "${repo_alias}"
    if ${DRY_RUN} || [ -f "${repo_file}" ]; then
        return 0
    fi

    info "Retrying repository add after missing repo file: ${repo_alias}"
    run_zypper "${ZYPPER_BASE[@]}" ar -f "${repo_url}" "${repo_alias}"
    [ -f "${repo_file}" ] || die "zypper did not create repository file: ${repo_file}"
}

write_metadata() {
    local meta_dir="${OUTPUT}/etc/aios"
    run_cmd mkdir -p "${meta_dir}"

    if ${DRY_RUN}; then
        info "would write ${meta_dir}/base-rootfs.env"
        info "would write ${meta_dir}/base-rootfs.json"
        return 0
    fi

    cat > "${meta_dir}/base-rootfs.env" <<EOF
AIOS_BASE_FAMILY=opensuse
AIOS_BASE_VARIANT=${VARIANT}
AIOS_BASE_VERSION=${RELEASE}
AIOS_BASE_SERIES=${SERIES}
AIOS_BASE_ARCH=${ARCH}
AIOS_BASE_SUPPORT_MONTHS=${SUPPORT_MONTHS}
AIOS_BASE_EOL_DATE=${EOL_DATE}
AIOS_BASE_KERNEL_POLICY=vendor-kernel
AIOS_BASE_PACKAGE_POLICY=hybrid-rpm-aios
AIOS_BASE_REPO_OSS=${REPO_OSS}
AIOS_BASE_REPO_UPDATE=${REPO_UPDATE}
AIOS_BASE_BUILDER=build-opensuse-rootfs.sh
EOF
    chmod 644 "${meta_dir}/base-rootfs.env"

    cat > "${meta_dir}/base-rootfs.json" <<EOF
{
  "schema": "aios.base_rootfs.v1",
  "revision": 13,
  "base_family": "opensuse",
  "variant": "$(json_escape "${VARIANT}")",
  "version": "$(json_escape "${RELEASE}")",
  "series": "$(json_escape "${SERIES}")",
  "architecture": "$(json_escape "${ARCH}")",
  "support_window_months": ${SUPPORT_MONTHS},
  "eol_date": "$(json_escape "${EOL_DATE}")",
  "kernel_policy": "vendor-kernel",
  "package_policy": "hybrid-rpm-aios",
  "repositories": {
    "oss": "$(json_escape "${REPO_OSS}")",
    "update": "$(json_escape "${REPO_UPDATE}")"
  },
  "builder": "build-opensuse-rootfs.sh"
}
EOF
    chmod 644 "${meta_dir}/base-rootfs.json"
}

# Regenerate kernel module dependency metadata and force the device-mapper stack
# to autoload at boot. `zypper --root` does not reliably run the kernel-default
# %posttrans depmod, so modules.dep can be missing/stale in the produced rootfs.
# The live installer then hits "Cannot initialize device-mapper. Is dm_mod
# kernel module loaded?" at the LUKS step (pipeline 4791) because modprobe cannot
# resolve dm_mod even though dm-mod.ko is physically present. Fail closed if the
# module is genuinely absent — that is a packaging defect, not a depmod gap.
finalize_kernel_modules() {
    ${DRY_RUN} && return 0

    # Locate the PHYSICAL modules tree. Never follow an absolute usrmerge symlink
    # (that would escape to the build host); pick the real directory.
    local mroot="" kver=""
    local cand
    for cand in "${OUTPUT}/usr/lib/modules" "${OUTPUT}/lib/modules"; do
        if [ -d "${cand}" ] && [ ! -L "${cand}" ]; then mroot="${cand}"; break; fi
    done
    [ -n "${mroot}" ] || die "no kernel modules directory in rootfs (kernel-default missing?)"

    kver="$(ls -1 "${mroot}" 2>/dev/null | head -n1)"
    [ -n "${kver}" ] || die "no kernel version directory under ${mroot}"

    # device-mapper .ko must physically exist, else LUKS install is impossible
    if ! ls "${mroot}/${kver}"/kernel/drivers/md/dm-mod.ko* >/dev/null 2>&1; then
        die "device-mapper module (dm-mod.ko) absent under ${mroot}/${kver} — kernel-default packaging problem"
    fi

    # Prefer an in-rootfs chroot depmod (no host-escape risk); fall back to a
    # host depmod bound to the rootfs.
    if [ -x "${OUTPUT}/usr/bin/depmod" ] || [ -x "${OUTPUT}/usr/sbin/depmod" ] || [ -x "${OUTPUT}/sbin/depmod" ]; then
        chroot "${OUTPUT}" depmod -a "${kver}" || die "depmod (chroot) failed for ${kver}"
    elif command -v depmod >/dev/null 2>&1; then
        depmod -b "${OUTPUT}" "${kver}" || die "depmod (host, -b) failed for ${kver}"
    else
        die "depmod not available (in rootfs or on host) to generate modules.dep for ${kver}"
    fi
    [ -f "${mroot}/${kver}/modules.dep" ] || die "modules.dep not generated for ${kver}"

    # NOTE: deliberately NOT writing modules-load.d for the dm stack. Forcing
    # dm_mod/dm_crypt/dm_verity at every boot makes systemd-modules-load.service
    # FAIL (and the boot-health gate DEGRADED, pipeline 4844) whenever any of the
    # three cannot load in a given boot context. The installer loads them
    # best-effort at install time (ensure_device_mapper) with a functional
    # dmsetup check, which is the correct place and non-fatal.

    info "kernel modules finalized for ${kver} (depmod-generated modules.dep)"
}

info "R13.1 base: openSUSE Leap ${RELEASE} (${ARCH}), support ${SUPPORT_MONTHS} months"
info "Output: ${OUTPUT}"
info "Package set: ${PACKAGE_SET}"

if ! ${DRY_RUN}; then
    if ${FORCE}; then
        case "${OUTPUT}" in
            "${REPO_ROOT}"/distro/build/out/*|/tmp/aios-*|/var/tmp/aios-*) rm -rf "${OUTPUT}" ;;
            *) die "refusing to remove unsafe output path: ${OUTPUT}" ;;
        esac
    fi
fi

prepare_target_root
if ! ${DRY_RUN} && [ "${ZYPPER_SETTLE_SECONDS}" -gt 0 ]; then
    sync
    sleep "${ZYPPER_SETTLE_SECONDS}"
fi

add_repo "${REPO_OSS}" "opensuse-${RELEASE}-oss"
if [ "${REPO_UPDATE}" = "${REPO_OSS}" ]; then
    info "Using repo-oss for updates; openSUSE Leap ${RELEASE} has no dedicated update repo"
else
    add_repo "${REPO_UPDATE}" "opensuse-${RELEASE}-update"
fi
run_zypper "${ZYPPER_BASE[@]}" refresh
run_zypper "${ZYPPER_BASE[@]}" install --no-recommends -y "${PACKAGES[@]}"

run_cmd mkdir -p "${OUTPUT}/proc" "${OUTPUT}/sys" "${OUTPUT}/dev" "${OUTPUT}/run" "${OUTPUT}/tmp"
if ! ${DRY_RUN}; then
    chmod 1777 "${OUTPUT}/tmp"
    # usrmerge trap: ${OUTPUT}/sbin is an ABSOLUTE symlink to /usr/sbin, so any
    # path THROUGH it resolves against the BUILD HOST, not the rootfs — both
    # the old existence check and the old ln wrote to the wrong tree. Always
    # operate on the physical location. Leap 16 dropped systemd-sysvcompat,
    # so nothing else provides the init entry (switch_root panics without it).
    if [ -x "${OUTPUT}/usr/lib/systemd/systemd" ]; then
        if [ ! -e "${OUTPUT}/usr/sbin/init" ] && [ ! -L "${OUTPUT}/usr/sbin/init" ]; then
            mkdir -p "${OUTPUT}/usr/sbin"
            ln -s ../lib/systemd/systemd "${OUTPUT}/usr/sbin/init"
        fi
    fi
    # legacy layout: sbin is a real directory, not a usrmerge symlink
    if [ -d "${OUTPUT}/sbin" ] && [ ! -L "${OUTPUT}/sbin" ] \
        && [ ! -e "${OUTPUT}/sbin/init" ] && [ ! -L "${OUTPUT}/sbin/init" ] \
        && [ -x "${OUTPUT}/usr/lib/systemd/systemd" ]; then
        ln -s ../usr/lib/systemd/systemd "${OUTPUT}/sbin/init"
    fi
fi

write_metadata

finalize_kernel_modules

if ! ${DRY_RUN}; then
    [ -x "${OUTPUT}/usr/lib/systemd/systemd" ] \
        || die "rootfs does not contain systemd (usr/lib/systemd/systemd)"
    # physical-path init entry (never resolve through the sbin usrmerge symlink)
    [ -L "${OUTPUT}/usr/sbin/init" ] || [ -e "${OUTPUT}/usr/sbin/init" ] \
        || { [ ! -L "${OUTPUT}/sbin" ] && { [ -L "${OUTPUT}/sbin/init" ] || [ -e "${OUTPUT}/sbin/init" ]; }; } \
        || die "rootfs does not contain an init entry (usr/sbin/init)"
    [ -f "${OUTPUT}/etc/aios/base-rootfs.json" ] \
        || die "base-rootfs metadata missing"
fi

info "openSUSE base rootfs ready: ${OUTPUT}"
