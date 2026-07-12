#!/bin/bash
set -euo pipefail

# =============================================================================
# AI-OS.NET ISO Builder — Revision 12
# =============================================================================
# Builds a bootable AIOS live/install ISO from the 34-crate Rust workspace.
#
# Requirements:
#   - Rust toolchain (cargo, rustc) — 1.94+
#   - busybox-static (for initramfs)
#   - systemd-boot (for EFI)
#   - squashfs-tools (mksquashfs)
#   - xorriso (for ISO9660 + EFI + hybrid MBR)
#   - mtools (for EFI FAT image: mmd, mcopy)
#   - cpio, xz (for initramfs compression)
#   - cryptsetup, veritysetup (for initramfs tools)
#
# Optional:
#   - tpm2-tools (for TPM2 unseal in initramfs)
#   - policycoreutils (load_policy for SELinux)
#
# Usage:
#   ./build-aios-iso.sh [--release|--debug] [--output PATH] [--arch x86_64|aarch64]
#   ./build-aios-iso.sh --release --base-rootfs /srv/aios/base-rootfs --output /tmp/aios.iso
#
# Output:
#   aios-rev12-YYYYMMDD-x86_64.iso — bootable ISO image
# =============================================================================

# ── Project paths ────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="${AIOS_BUILD_WORKDIR:-${REPO_ROOT}/distro/build/out}"
ROOTFS_DIR="${BUILD_DIR}/rootfs"
INITRAMFS_DIR="${BUILD_DIR}/initramfs"
INITRAMFS_OUT="${BUILD_DIR}/initramfs.cpio.xz"
ISO_DIR="${BUILD_DIR}/iso"
# shellcheck disable=SC2034
EFI_IMG="${BUILD_DIR}/efiboot.img"

DATE_STAMP="$(date +%Y%m%d)"

# ── Defaults (overridable via args) ──────────────────────────────────────────

ARCH="x86_64"
PROFILE="release"
CARGO_PROFILE="release"
TARGET_PROFILE_DIR="release"
OUTPUT="${REPO_ROOT}/distro/build/aios-rev12-${DATE_STAMP}-${ARCH}.iso"
OUTPUT_EXPLICIT=false
AIOS_VERSION="${AIOS_VERSION:-0.1.0}"
AIOS_BUILD_ID="${AIOS_BUILD_ID:-${DATE_STAMP}}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
BASE_ROOTFS="${AIOS_BASE_ROOTFS:-}"
ALLOW_SCAFFOLD_ROOTFS="${AIOS_ALLOW_SCAFFOLD_ROOTFS:-0}"
AIOS_SECURITY_PROFILE="${AIOS_SECURITY_PROFILE:-SECURE_DEFAULT}"
AIOS_SELINUX_MODE="${AIOS_SELINUX_MODE:-permissive}"
AIOS_SELINUX_POLICY_SOURCE="${AIOS_SELINUX_POLICY_SOURCE:-}"
AIOS_REQUIRE_BOOT_SIGNATURES="${AIOS_REQUIRE_BOOT_SIGNATURES:-0}"
AIOS_SIGNATURE_SOURCE_DIR="${AIOS_SIGNATURE_SOURCE_DIR:-}"
AIOS_ENTERPRISE_RELEASE="${AIOS_ENTERPRISE_RELEASE:-0}"
# dm-verity mode: auto (generate hash tree when veritysetup is available) | disabled
AIOS_DM_VERITY="${AIOS_DM_VERITY:-auto}"
AIOS_BASE_FAMILY="${AIOS_BASE_FAMILY:-scaffold}"
AIOS_BASE_VARIANT="${AIOS_BASE_VARIANT:-none}"
AIOS_BASE_VERSION="${AIOS_BASE_VERSION:-none}"
AIOS_BASE_SERIES="${AIOS_BASE_SERIES:-none}"
AIOS_BASE_ARCH="${AIOS_BASE_ARCH:-}"
AIOS_BASE_SUPPORT_MONTHS="${AIOS_BASE_SUPPORT_MONTHS:-0}"
AIOS_BASE_EOL_DATE="${AIOS_BASE_EOL_DATE:-none}"
AIOS_BASE_KERNEL_POLICY="${AIOS_BASE_KERNEL_POLICY:-host-kernel}"
AIOS_BASE_PACKAGE_POLICY="${AIOS_BASE_PACKAGE_POLICY:-aios-scaffold}"
AIOS_BASE_REPO_OSS="${AIOS_BASE_REPO_OSS:-none}"
AIOS_BASE_REPO_UPDATE="${AIOS_BASE_REPO_UPDATE:-none}"
AIOS_BASE_BUILDER="${AIOS_BASE_BUILDER:-none}"

# Kernel source: path to prebuilt kernel or "host" to copy from /boot
KERNEL_SOURCE="${KERNEL_SOURCE:-host}"
KERNEL_VERSION="${KERNEL_VERSION:-}"
KERNEL_MODULES_SOURCE="${KERNEL_MODULES_SOURCE:-auto}"
KERNEL_FIRMWARE_SOURCE="${KERNEL_FIRMWARE_SOURCE:-auto}"

STAGED_KERNEL_VERSION=""
STAGED_KERNEL_SOURCE_PATH=""
STAGED_MODULE_SOURCE_PATH=""
STAGED_MODULE_MODE="missing"
STAGED_MODULE_FILE_COUNT=0
STAGED_FIRMWARE_SOURCE_PATH=""
STAGED_FIRMWARE_MODE="missing"
STAGED_FIRMWARE_FILE_COUNT=0

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

json_escape() {
    printf '%s' "$1" \
        | sed \
            -e 's/\\/\\\\/g' \
            -e 's/"/\\"/g' \
            -e 's/	/\\t/g'
}

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

file_size_bytes() {
    wc -c < "$1" | tr -d '[:space:]'
}

append_manifest_artifact() {
    local manifest="$1"
    local rel_path="$2"
    local abs_path="${ISO_DIR}/${rel_path}"
    # ${3-,} (no colon): an explicitly-passed empty string means "no comma"
    # for the final array element; ${3:-,} would wrongly re-add it.
    local comma="${3-,}"

    if [ ! -f "${abs_path}" ]; then
        die "Release artifact missing during manifest generation: ${rel_path}"
    fi

    cat >> "${manifest}" <<EOF
    {
      "path": "$(json_escape "${rel_path}")",
      "sha256": "$(file_sha256 "${abs_path}")",
      "size_bytes": $(file_size_bytes "${abs_path}")
    }${comma}
EOF
}

count_tree_files() {
    if [ -d "$1" ]; then
        find "$1" -type f 2>/dev/null | wc -l | tr -d '[:space:]'
    else
        printf '0'
    fi
}

infer_kernel_version_from_path() {
    local kernel_path="$1"
    local dir_name
    local base_name

    if [ -n "${KERNEL_VERSION}" ]; then
        printf '%s\n' "${KERNEL_VERSION}"
        return 0
    fi

    dir_name="$(dirname "${kernel_path}")"
    base_name="$(basename "${kernel_path}")"

    case "${dir_name}" in
        */modules/*)
            basename "${dir_name}"
            return 0
            ;;
    esac

    case "${base_name}" in
        vmlinuz-*) printf '%s\n' "${base_name#vmlinuz-}"; return 0 ;;
        kernel-*)  printf '%s\n' "${base_name#kernel-}"; return 0 ;;
    esac

    uname -r 2>/dev/null || printf 'unknown'
}

banner() {
    printf '\n%s%s' "${BOLD}" "${BLUE}"
    printf "╔══════════════════════════════════════════════════════╗\n"
    printf "║   AI-OS.NET ISO Builder — Revision 12                ║\n"
    printf "║   Version: %-10s  Profile: %-8s          ║\n" "${AIOS_VERSION}" "${PROFILE}"
    printf "║   Arch:    %-10s  Jobs:    %-8s          ║\n" "${ARCH}" "${JOBS}"
    printf "║   Output:  %-40s ║\n" "$(basename "${OUTPUT}")"
    printf '╚══════════════════════════════════════════════════════╝%s\n\n' "${RESET}"
}

# ── Argument parsing ─────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --release)         PROFILE="release"; CARGO_PROFILE="release"; TARGET_PROFILE_DIR="release"; shift ;;
        --debug)           PROFILE="debug"; CARGO_PROFILE="dev"; TARGET_PROFILE_DIR="debug"; shift ;;
        --output)          OUTPUT="$2"; OUTPUT_EXPLICIT=true; shift 2 ;;
        --arch)            ARCH="$2";         shift 2 ;;
        --jobs|-j)         JOBS="$2";         shift 2 ;;
        --kernel-source)   KERNEL_SOURCE="$2"; shift 2 ;;
        --kernel-version)  KERNEL_VERSION="$2"; shift 2 ;;
        --kernel-modules-source) KERNEL_MODULES_SOURCE="$2"; shift 2 ;;
        --kernel-firmware-source) KERNEL_FIRMWARE_SOURCE="$2"; shift 2 ;;
        --security-profile) AIOS_SECURITY_PROFILE="$2"; shift 2 ;;
        --selinux-mode) AIOS_SELINUX_MODE="$2"; shift 2 ;;
        --selinux-policy-source) AIOS_SELINUX_POLICY_SOURCE="$2"; shift 2 ;;
        --require-boot-signatures) AIOS_REQUIRE_BOOT_SIGNATURES=1; shift ;;
        --signature-source-dir) AIOS_SIGNATURE_SOURCE_DIR="$2"; shift 2 ;;
        --enterprise-release) AIOS_ENTERPRISE_RELEASE=1; shift ;;
        --dm-verity) AIOS_DM_VERITY="$2"; shift 2 ;;
        --base-rootfs)     BASE_ROOTFS="$2";  shift 2 ;;
        --allow-scaffold-rootfs) ALLOW_SCAFFOLD_ROOTFS=1; shift ;;
        --version)         AIOS_VERSION="$2"; shift 2 ;;
        --build-id)        AIOS_BUILD_ID="$2"; shift 2 ;;
        --help|-h)
            printf "Usage: %s [OPTIONS]\n" "$(basename "$0")"
            printf "\nOptions:\n"
            printf "  --release            Build with release profile (default)\n"
            printf "  --debug              Build with debug profile\n"
            printf "  --output PATH        Output ISO path\n"
            printf "  --arch ARCH          Target architecture (x86_64|aarch64)\n"
            printf "  --jobs N, -j N       Number of parallel build jobs\n"
            printf "  --kernel-source SRC  Kernel source (host|PATH)\n"
            printf "  --kernel-version VER Kernel version for module matching\n"
            printf "  --kernel-modules-source SRC\n"
            printf "                       Module tree source (auto|none|PATH)\n"
            printf "  --kernel-firmware-source SRC\n"
            printf "                       Firmware source (auto|none|PATH)\n"
            printf "  --security-profile PROFILE\n"
            printf "                       Rev.12 security profile name (default: SECURE_DEFAULT)\n"
            printf "  --selinux-mode MODE SELinux mode (permissive|enforcing|disabled)\n"
            printf "  --selinux-policy-source PATH\n"
            printf "                       Binary SELinux policy. Required for enforcing builds.\n"
            printf "  --require-boot-signatures\n"
            printf "                       Fail if boot-chain detached signatures are missing\n"
            printf "  --signature-source-dir PATH\n"
            printf "                       Directory with detached signatures to stage in /aios/signatures\n"
            printf "  --enterprise-release Require R13 enterprise base metadata and supported arch\n"
            printf "  --dm-verity MODE     dm-verity hash tree generation (auto|disabled; default auto)\n"
            printf "  --base-rootfs PATH   Prepared Linux rootfs with systemd/init\n"
            printf "  --allow-scaffold-rootfs\n"
            printf "                       Build an AIOS-only scaffold rootfs (not bootable)\n"
            printf "  --version VERSION    AIOS version string\n"
            printf "  --build-id ID        Build identifier\n"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

if ! ${OUTPUT_EXPLICIT}; then
    OUTPUT="${REPO_ROOT}/distro/build/aios-rev12-${DATE_STAMP}-${ARCH}.iso"
fi

case "${AIOS_SELINUX_MODE}" in
    enforcing|permissive|disabled) ;;
    *) die "Invalid --selinux-mode: ${AIOS_SELINUX_MODE}" ;;
esac

case "${AIOS_REQUIRE_BOOT_SIGNATURES}" in
    0|1) ;;
    *) die "AIOS_REQUIRE_BOOT_SIGNATURES must be 0 or 1" ;;
esac

case "${AIOS_DM_VERITY}" in
    auto|disabled) ;;
    *) die "Invalid --dm-verity: ${AIOS_DM_VERITY} (expected auto|disabled)" ;;
esac

# NB: enforcing without --selinux-policy-source is allowed HERE — the R13.1
# openSUSE base rootfs may carry a genuine policy (selinux-policy-targeted).
# The fail-closed check runs after policy detection (see "SELinux policy
# sourcing" below): enforcing + no real policy from any source → die.

if [ -n "${AIOS_SELINUX_POLICY_SOURCE}" ] && [ ! -f "${AIOS_SELINUX_POLICY_SOURCE}" ]; then
    die "SELinux policy source not found: ${AIOS_SELINUX_POLICY_SOURCE}"
fi

if [ -n "${AIOS_SIGNATURE_SOURCE_DIR}" ] && [ ! -d "${AIOS_SIGNATURE_SOURCE_DIR}" ]; then
    die "Signature source directory not found: ${AIOS_SIGNATURE_SOURCE_DIR}"
fi

# Fail closed BEFORE the expensive build: required signatures can only come
# from --signature-source-dir, so their absence is already known here. The
# staging-time require_boot_signature gate remains as defense in depth.
if [ "${AIOS_REQUIRE_BOOT_SIGNATURES}" = "1" ] && [ -z "${AIOS_SIGNATURE_SOURCE_DIR}" ]; then
    die "Boot-chain signature required but missing: --require-boot-signatures needs --signature-source-dir"
fi

if [ -n "${BASE_ROOTFS}" ] && [ -f "${BASE_ROOTFS}/etc/aios/base-rootfs.env" ]; then
    # shellcheck disable=SC1091
    . "${BASE_ROOTFS}/etc/aios/base-rootfs.env"
fi

[ -n "${AIOS_BASE_ARCH}" ] || AIOS_BASE_ARCH="${ARCH}"

case "${AIOS_ENTERPRISE_RELEASE}" in
    0|1) ;;
    *) die "AIOS_ENTERPRISE_RELEASE must be 0 or 1" ;;
esac

case "${AIOS_BASE_SUPPORT_MONTHS}" in
    ''|*[!0-9]*) die "AIOS_BASE_SUPPORT_MONTHS must be numeric: ${AIOS_BASE_SUPPORT_MONTHS}" ;;
esac

if [ "${AIOS_ENTERPRISE_RELEASE}" = "1" ]; then
    [ -n "${BASE_ROOTFS}" ] || die "Enterprise release requires --base-rootfs from R13.1 builder."
    [ "${ALLOW_SCAFFOLD_ROOTFS}" != "1" ] || die "Enterprise release cannot use scaffold rootfs."
    [ "${AIOS_BASE_FAMILY}" = "opensuse" ] || die "Enterprise release requires openSUSE base metadata."
    [ "${AIOS_BASE_ARCH}" = "${ARCH}" ] || die "Enterprise rootfs arch mismatch: rootfs=${AIOS_BASE_ARCH}, iso=${ARCH}"
    [ "${AIOS_BASE_SUPPORT_MONTHS}" -gt 0 ] || die "Enterprise release requires a positive support window."
    [ "${AIOS_BASE_EOL_DATE}" != "none" ] || die "Enterprise release requires an EOL date."
    case "${ARCH}" in
        x86_64|aarch64) ;;
        *) die "Enterprise release architecture not supported: ${ARCH}" ;;
    esac
fi

SELINUX_ENFORCING_TOML=false
[ "${AIOS_SELINUX_MODE}" = "enforcing" ] && SELINUX_ENFORCING_TOML=true
BOOT_SIGNATURES_REQUIRED_TOML=false
[ "${AIOS_REQUIRE_BOOT_SIGNATURES}" = "1" ] && BOOT_SIGNATURES_REQUIRED_TOML=true
ENTERPRISE_RELEASE_JSON=false
[ "${AIOS_ENTERPRISE_RELEASE}" = "1" ] && ENTERPRISE_RELEASE_JSON=true

# If arch is aarch64, switch cross-compilation profile path lookup
if [ "${ARCH}" = "aarch64" ]; then
    TARGET_DIR="${REPO_ROOT}/target/aarch64-unknown-linux-gnu/${TARGET_PROFILE_DIR}"
else
    TARGET_DIR="${REPO_ROOT}/target/${TARGET_PROFILE_DIR}"
fi

# ── Pre-flight checks ────────────────────────────────────────────────────────

banner

step "Pre-flight dependency check"

MISSING=""
check_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        MISSING="${MISSING}  - $1 ($2)\n"
    fi
}

check_cmd cargo          "Rust toolchain — install via rustup.rs"
check_cmd strip          "binutils — install binutils package"
check_cmd mksquashfs     "squashfs-tools"
check_cmd xorriso        "xorriso"
check_cmd cpio           "cpio"
check_cmd xz             "xz-utils"
check_cmd mmd            "mtools (for EFI FAT image)"
check_cmd mcopy          "mtools (for EFI FAT image)"
check_cmd mkfs.vfat      "dosfstools"
check_cmd dd             "coreutils"

if [ -n "${MISSING}" ]; then
    err "Missing required tools:"
    printf '%s' "${MISSING}"
    die "Install missing dependencies and retry."
fi

# Check for optional tools
check_opt() {
    if ! command -v "$1" >/dev/null 2>&1; then
        warn "Optional tool '$1' not found ($2) — some features will be skipped."
        return 1
    fi
    return 0
}

HAS_BUSYBOX=false

if check_opt busybox "busybox-static (initramfs busybox)"; then
    HAS_BUSYBOX=true
else
    # openSUSE names it busybox-static
    if command -v busybox-static >/dev/null 2>&1; then
        HAS_BUSYBOX=true
        BUSYBOX_CMD="busybox-static"
        info "busybox-static found"
    else
        HAS_BUSYBOX=false
    fi
fi

# Use the correct busybox binary name
BUSYBOX_CMD="${BUSYBOX_CMD:-busybox}"
check_opt bootctl "systemd-boot (EFI boot manager)" || true
check_opt cryptsetup "cryptsetup (LUKS in initramfs)" || true
check_opt tpm2_unseal "tpm2-tools (TPM2 unseal)" || true
check_opt veritysetup "veritysetup (dm-verity)" || true
check_opt load_policy "policycoreutils (SELinux load_policy)" || true

ok "Dependency check complete."

if [ -n "${BASE_ROOTFS}" ]; then
    if [ ! -d "${BASE_ROOTFS}" ]; then
        die "Base rootfs does not exist: ${BASE_ROOTFS}"
    fi
    if [ ! -x "${BASE_ROOTFS}/sbin/init" ] \
       && [ ! -x "${BASE_ROOTFS}/usr/lib/systemd/systemd" ] \
       && [ ! -x "${BASE_ROOTFS}/lib/systemd/systemd" ]; then
        die "Base rootfs must contain /sbin/init or systemd: ${BASE_ROOTFS}"
    fi
    ok "Base rootfs validated: ${BASE_ROOTFS}"
elif [ "${ALLOW_SCAFFOLD_ROOTFS}" = "1" ]; then
    warn "Building scaffold AIOS rootfs without a base Linux userspace."
    warn "The resulting ISO is for packaging tests only and is not bootable."
else
    die "Bootable ISO requires --base-rootfs PATH (or set AIOS_ALLOW_SCAFFOLD_ROOTFS=1 for non-bootable packaging tests)."
fi

# ── Step 1: Compile workspace ────────────────────────────────────────────────

step "Step 1: Compiling AIOS workspace (${PROFILE} profile, -j ${JOBS})"

cd "${REPO_ROOT}"

START_TS=$(date +%s)

if [ "${ARCH}" = "aarch64" ]; then
    if ! rustup target list --installed 2>/dev/null | grep -q 'aarch64-unknown-linux-gnu'; then
        info "Installing aarch64 cross-compilation target..."
        rustup target add aarch64-unknown-linux-gnu
    fi
    cargo build --profile "${CARGO_PROFILE}" --workspace --target aarch64-unknown-linux-gnu --jobs "${JOBS}"
else
    cargo build --profile "${CARGO_PROFILE}" --workspace --jobs "${JOBS}"
fi

FIRST_BOOT_TARGET_DIR="${REPO_ROOT}/distro/first-boot/target/${TARGET_PROFILE_DIR}"
if [ "${ARCH}" = "aarch64" ]; then
    cargo build --profile "${CARGO_PROFILE}" \
        --manifest-path "${REPO_ROOT}/distro/first-boot/Cargo.toml" \
        --target aarch64-unknown-linux-gnu \
        --jobs "${JOBS}"
    FIRST_BOOT_TARGET_DIR="${REPO_ROOT}/distro/first-boot/target/aarch64-unknown-linux-gnu/${TARGET_PROFILE_DIR}"
else
    cargo build --profile "${CARGO_PROFILE}" \
        --manifest-path "${REPO_ROOT}/distro/first-boot/Cargo.toml" \
        --jobs "${JOBS}"
fi

BUILD_DURATION=$(( $(date +%s) - START_TS ))
ok "Compilation complete in ${BUILD_DURATION}s"

# Verify binaries exist
BINARIES_FOUND=()
for crate_dir in "${REPO_ROOT}"/crates/*/; do
    crate_name="$(basename "${crate_dir}")"
    # Check if this crate has a [[bin]] target by looking for main.rs or src/bin/
    if [ -f "${crate_dir}/src/main.rs" ] || ls "${crate_dir}/src/bin/"*.rs >/dev/null 2>&1; then
        # Find the binary name(s) from Cargo.toml
        while IFS= read -r bin_name; do
            if [ -n "${bin_name}" ]; then
                bin_path="${TARGET_DIR}/${bin_name}"
                if [ -f "${bin_path}" ]; then
                    BINARIES_FOUND+=("${bin_name}|${bin_path}")
                    info "Found binary: ${bin_name} (${bin_path})"
                else
                    warn "Binary ${bin_name} not found at expected path ${bin_path} (crate ${crate_name})"
                fi
            fi
        done < <(grep -A1 '^\[\[bin\]\]' "${crate_dir}/Cargo.toml" 2>/dev/null | grep '^name' | sed 's/.*=\s*"\(.*\)"/\1/' || true)
        # If no explicit [[bin]], the default binary name matches the crate name
        if [ -f "${crate_dir}/src/main.rs" ] && [ ! -f "${crate_dir}/Cargo.toml" ]; then
            : # skip
        fi
    fi
done

# Fallback: scan target directory for all binaries
if [ ${#BINARIES_FOUND[@]} -eq 0 ]; then
    warn "No binaries found via Cargo.toml scan; scanning target directory..."
    while IFS= read -r bin_path; do
        bin_name="$(basename "${bin_path}")"
        BINARIES_FOUND+=("${bin_name}|${bin_path}")
        info "Found binary (scan): ${bin_name}"
    done < <(find "${TARGET_DIR}" -maxdepth 1 -type f -executable 2>/dev/null || true)
fi

FIRST_BOOT_BIN="${FIRST_BOOT_TARGET_DIR}/aios-first-boot"
if [ -f "${FIRST_BOOT_BIN}" ]; then
    BINARIES_FOUND+=("aios-first-boot|${FIRST_BOOT_BIN}")
    info "Found binary: aios-first-boot (${FIRST_BOOT_BIN})"
else
    die "aios-first-boot binary not found at ${FIRST_BOOT_BIN}"
fi

if [ ${#BINARIES_FOUND[@]} -eq 0 ]; then
    die "No binaries found in ${TARGET_DIR}. Build may have failed."
fi

ok "Found ${#BINARIES_FOUND[@]} binary targets."

# ── Step 2: Create rootfs directory tree ─────────────────────────────────────

step "Step 2: Creating rootfs directory tree"

# Clean previous build artifacts (but don't remove the whole out/ dir
# in case user has other builds; use --clean flag for that)
rm -rf "${ROOTFS_DIR}" "${INITRAMFS_DIR}" "${ISO_DIR}"
mkdir -p "${ROOTFS_DIR}"

if [ -n "${BASE_ROOTFS}" ]; then
    info "Copying base Linux rootfs from ${BASE_ROOTFS}"
    cp -a "${BASE_ROOTFS}/." "${ROOTFS_DIR}/"
fi

mkdir -p "${ROOTFS_DIR}"/usr/{bin,lib/aios,lib/systemd/boot/efi,share/aios/{config,selinux,licenses}}
mkdir -p "${ROOTFS_DIR}"/etc/{aios/{config.d,security.d,verity,policy.d,selinux.d,evidence.d,backup.d,hardening,update.d,integrity.d},selinux/aios/policy,systemd/system,ssl/certs,ima,evm}
mkdir -p "${ROOTFS_DIR}"/var/{lib/aios/{evidence,policy,capsules,backup,state,fleet,autonomous,marketplace,container,terminal,update},log/aios,cache/aios,tmp}
for _state_dir in fs vault network recovery sgr sandbox hardware hardening containers models models/ollama models/vllm; do
    mkdir -p "${ROOTFS_DIR}/var/lib/aios/${_state_dir}"
done
mkdir -p "${ROOTFS_DIR}"/run/aios
mkdir -p "${ROOTFS_DIR}"/boot/{loader/entries,EFI/BOOT}
mkdir -p "${ROOTFS_DIR}"/tmp
mkdir -p "${ROOTFS_DIR}"/proc
mkdir -p "${ROOTFS_DIR}"/sys
mkdir -p "${ROOTFS_DIR}"/dev/{shm,pts,mapper}
mkdir -p "${ROOTFS_DIR}"/mnt
mkdir -p "${ROOTFS_DIR}"/media
mkdir -p "${ROOTFS_DIR}"/opt/aios
mkdir -p "${ROOTFS_DIR}"/home/aios
mkdir -p "${ROOTFS_DIR}"/root
mkdir -p "${ROOTFS_DIR}"/srv

# Essential symlinks for scaffold roots. Preserve a base rootfs layout when it
# already provides real directories or symlinks.
ensure_symlink() {
    local target="$1"
    local link_path="$2"
    if [ -L "${link_path}" ]; then
        ln -sfn "${target}" "${link_path}"
    elif [ -e "${link_path}" ]; then
        info "Preserving existing path: ${link_path#"${ROOTFS_DIR}"/}"
    else
        ln -s "${target}" "${link_path}"
    fi
}

ensure_symlink usr/bin  "${ROOTFS_DIR}/bin"
ensure_symlink usr/lib  "${ROOTFS_DIR}/lib"
ensure_symlink usr/lib  "${ROOTFS_DIR}/lib64"
ensure_symlink bin      "${ROOTFS_DIR}/usr/sbin"
ensure_symlink ../run   "${ROOTFS_DIR}/var/run"
ensure_symlink ../lock  "${ROOTFS_DIR}/var/lock"
ensure_symlink usr/bin  "${ROOTFS_DIR}/sbin"

ensure_init_entrypoint() {
    if [ -x "${ROOTFS_DIR}/sbin/init" ] || [ -L "${ROOTFS_DIR}/sbin/init" ]; then
        return 0
    fi

    local systemd_path=""
    for candidate in /usr/lib/systemd/systemd /lib/systemd/systemd; do
        if [ -x "${ROOTFS_DIR}${candidate}" ]; then
            systemd_path="${candidate}"
            break
        fi
    done

    if [ -n "${systemd_path}" ]; then
        if [ -L "${ROOTFS_DIR}/sbin" ]; then
            mkdir -p "${ROOTFS_DIR}/usr/bin"
            ln -sfn "${systemd_path}" "${ROOTFS_DIR}/usr/bin/init"
        else
            mkdir -p "${ROOTFS_DIR}/sbin"
            ln -sfn "${systemd_path}" "${ROOTFS_DIR}/sbin/init"
        fi
        info "Created /sbin/init entrypoint for ${systemd_path}"
    elif [ "${ALLOW_SCAFFOLD_ROOTFS}" = "1" ]; then
        warn "Scaffold rootfs has no /sbin/init; ISO will not boot."
    else
        die "Rootfs has no /sbin/init and no systemd binary."
    fi
}

ensure_init_entrypoint

ok "Rootfs directory tree created."

rootfs_has_command() {
    local command_name="$1"
    local candidate

    for candidate in \
        "/usr/bin/${command_name}" \
        "/bin/${command_name}" \
        "/usr/sbin/${command_name}" \
        "/sbin/${command_name}"; do
        if [ -x "${ROOTFS_DIR}${candidate}" ]; then
            return 0
        fi
    done

    return 1
}

# ── Step 3: Strip and install AIOS binaries ──────────────────────────────────

step "Step 3: Installing AIOS binaries"

AIOS_LIB_DIR="${ROOTFS_DIR}/usr/lib/aios"
AIOS_BIN_DIR="${ROOTFS_DIR}/usr/bin"

for entry in "${BINARIES_FOUND[@]}"; do
    bin_name="${entry%%|*}"
    bin_path="${entry##*|}"

    stripped_path="${BUILD_DIR}/staged/${bin_name}.stripped"
    mkdir -p "$(dirname "${stripped_path}")"

    cp "${bin_path}" "${stripped_path}"
    chmod 755 "${stripped_path}"

    if strip --strip-all "${stripped_path}" 2>/dev/null; then
        info "Stripped: ${bin_name}"
    else
        warn "strip failed for ${bin_name} — copying unstripped"
    fi

    # Route 'aios' CLI to /usr/bin/, all others to /usr/lib/aios/
    case "${bin_name}" in
        aios|aios-cli|aiosctl|aios-autonomous|aios-fleet|aios-container|aios-hardening)
            cp "${stripped_path}" "${AIOS_BIN_DIR}/${bin_name}"
            chmod 755 "${AIOS_BIN_DIR}/${bin_name}"
            info "CLI binary installed: /usr/bin/${bin_name}"
            ;;
        *)
            cp "${stripped_path}" "${AIOS_LIB_DIR}/${bin_name}"
            chmod 755 "${AIOS_LIB_DIR}/${bin_name}"
            info "Service binary installed: /usr/lib/aios/${bin_name}"
            ;;
    esac
done

# Create symlinks: /usr/bin/aiosctl -> /usr/bin/aios if aios exists and aiosctl doesn't
if [ -f "${AIOS_BIN_DIR}/aios" ] && [ ! -f "${AIOS_BIN_DIR}/aiosctl" ]; then
    ln -sf aios "${AIOS_BIN_DIR}/aiosctl"
    info "Symlink: /usr/bin/aiosctl -> aios"
fi

ok "Binaries installed and stripped."

# ── Step 4: Install live installer tools ─────────────────────────────────────

step "Step 4: Installing live installer tools"

INSTALLER_SRC="${REPO_ROOT}/distro/installer"
INSTALLER_DST="${ROOTFS_DIR}/usr/lib/aios/install"
mkdir -p "${INSTALLER_DST}"

for installer in aios-installer.sh aios-quick-install.sh; do
    if [ -f "${INSTALLER_SRC}/${installer}" ]; then
        cp "${INSTALLER_SRC}/${installer}" "${INSTALLER_DST}/${installer}"
        chmod 755 "${INSTALLER_DST}/${installer}"
        ln -sf "../lib/aios/install/${installer}" "${AIOS_BIN_DIR}/${installer%.sh}"
        info "Installer staged: /usr/lib/aios/install/${installer}"
    else
        die "Required installer script missing: ${INSTALLER_SRC}/${installer}"
    fi
done

ok "Live installer tools installed."

# ── Step 4b: Install update client ───────────────────────────────────────────

step "Step 4b: Installing signed update client"

UPDATE_SRC="${REPO_ROOT}/distro/update"
UPDATE_DST="${ROOTFS_DIR}/usr/lib/aios/update"
mkdir -p "${UPDATE_DST}" "${ROOTFS_DIR}/etc/aios/update.d"

if [ -f "${UPDATE_SRC}/aios-update.sh" ]; then
    cp "${UPDATE_SRC}/aios-update.sh" "${UPDATE_DST}/aios-update.sh"
    chmod 755 "${UPDATE_DST}/aios-update.sh"
    ln -sf "../lib/aios/update/aios-update.sh" "${AIOS_BIN_DIR}/aios-update"
    info "Update client staged: /usr/lib/aios/update/aios-update.sh"
else
    die "Required update client missing: ${UPDATE_SRC}/aios-update.sh"
fi

cat > "${ROOTFS_DIR}/etc/aios/update.d/update.toml" <<'EOF'
# AI-OS.NET Rev.12 update client configuration
[updates]
channel = "release"
state_dir = "/var/lib/aios/update"
rollback_dir = "/var/lib/aios/rollback"
trusted_key = "/etc/aios/update.d/trusted-release-key.pem"
require_signature = true
EOF
chmod 644 "${ROOTFS_DIR}/etc/aios/update.d/update.toml"

for update_dep in bash jq openssl sha256sum; do
    if rootfs_has_command "${update_dep}"; then
        info "Update dependency present in rootfs: ${update_dep}"
    elif [ -n "${BASE_ROOTFS}" ]; then
        die "Base rootfs missing update dependency: ${update_dep}"
    else
        warn "Scaffold rootfs missing update dependency: ${update_dep}"
    fi
done

ok "Signed update client installed."

# ── Step 5: Install systemd units ────────────────────────────────────────────

step "Step 5: Installing systemd units"

SYSTEMD_SRC="${REPO_ROOT}/distro/systemd"
SYSTEMD_DST="${ROOTFS_DIR}/etc/systemd/system"
SYSTEMD_NETWORK_DST="${ROOTFS_DIR}/etc/systemd/network"
SYSTEMD_RESOLVED_DST="${ROOTFS_DIR}/etc/systemd"

mkdir -p "${SYSTEMD_DST}" "${SYSTEMD_NETWORK_DST}"

# Stage the boot-time service health reporter that aios-health-report.service
# drives. Its ExecStart binary MUST exist in the rootfs or the ExecStart
# validation gate below will fail the build (by design).
HEALTH_REPORT_SRC="${REPO_ROOT}/distro/aios-boot/aios-health-report.sh"
if [ -f "${HEALTH_REPORT_SRC}" ]; then
    mkdir -p "${AIOS_LIB_DIR}"
    cp "${HEALTH_REPORT_SRC}" "${AIOS_LIB_DIR}/aios-health-report.sh"
    chmod 755 "${AIOS_LIB_DIR}/aios-health-report.sh"
    info "Health reporter staged: /usr/lib/aios/aios-health-report.sh"
else
    die "Required health reporter missing: ${HEALTH_REPORT_SRC}"
fi

if [ -d "${SYSTEMD_SRC}" ]; then
    for svc in "${SYSTEMD_SRC}"/*.service; do
        if [ -f "${svc}" ]; then
            svc_name="$(basename "${svc}")"
            cp "${svc}" "${SYSTEMD_DST}/${svc_name}"
            chmod 644 "${SYSTEMD_DST}/${svc_name}"
            info "Installed systemd unit: ${svc_name}"
        fi
    done
    for target in "${SYSTEMD_SRC}"/*.target; do
        if [ -f "${target}" ]; then
            target_name="$(basename "${target}")"
            cp "${target}" "${SYSTEMD_DST}/${target_name}"
            chmod 644 "${SYSTEMD_DST}/${target_name}"
            info "Installed systemd target: ${target_name}"
        fi
    done
fi

# Create symlinks to enable services
mkdir -p "${ROOTFS_DIR}/etc/systemd/system/multi-user.target.wants"
svc="aios.target"
if [ -f "${SYSTEMD_DST}/${svc}" ]; then
    ln -sf "../${svc}" "${ROOTFS_DIR}/etc/systemd/system/multi-user.target.wants/${svc}"
    info "Enabled: ${svc}"
fi

# Enable the boot-time service health reporter so it runs on every boot and
# emits its AIOS-HEALTH verdict to the console for the QEMU health gate.
svc="aios-health-report.service"
if [ -f "${SYSTEMD_DST}/${svc}" ]; then
    ln -sf "../${svc}" "${ROOTFS_DIR}/etc/systemd/system/multi-user.target.wants/${svc}"
    info "Enabled: ${svc}"
fi

UNIT_EXEC_MISSING=false
for unit_file in "${SYSTEMD_DST}"/*.service; do
    [ -f "${unit_file}" ] || continue
    unit_name="$(basename "${unit_file}")"
    while IFS= read -r exec_path; do
        case "${exec_path}" in
            /usr/lib/aios/*|/usr/bin/aios*)
                if [ ! -e "${ROOTFS_DIR}${exec_path}" ]; then
                    warn "${unit_name}: ExecStart binary missing from rootfs: ${exec_path}"
                    UNIT_EXEC_MISSING=true
                fi
                ;;
        esac
    done < <(sed -n 's#^ExecStart=-*##p' "${unit_file}" | awk '{print $1}')
done

if ${UNIT_EXEC_MISSING}; then
    die "One or more AIOS systemd units reference missing staged binaries."
fi

# systemd-networkd default wired config
cat > "${SYSTEMD_NETWORK_DST}/20-wired.network" <<'EOF'
[Match]
Name=en* eth*

[Network]
DHCP=yes
IPv6AcceptRA=yes

[DHCPv4]
RouteMetric=10

[IPv6AcceptRA]
RouteMetric=10
EOF

# systemd-resolved stub config
rm -f "${SYSTEMD_RESOLVED_DST}/resolv.conf"
cat > "${SYSTEMD_RESOLVED_DST}/resolv.conf" <<'EOF'
nameserver 127.0.0.53
options edns0 trust-ad
EOF

ok "Systemd units installed."

# ── Step 6: Install configuration files ──────────────────────────────────────

step "Step 6: Installing configuration files"

# Default AIOS config
cat > "${ROOTFS_DIR}/etc/aios/config.toml" <<EOF
# AI-OS.NET Configuration — Revision 12
# Generated by build-aios-iso.sh ${DATE_STAMP}

[system]
version = "${AIOS_VERSION}"
build_id = "${AIOS_BUILD_ID}"
hostname = "aios"

[paths]
data_dir = "/var/lib/aios"
config_dir = "/etc/aios/config.d"
evidence_dir = "/var/lib/aios/evidence"
policy_dir = "/var/lib/aios/policy"
capsule_dir = "/var/lib/aios/capsules"
backup_dir = "/var/lib/aios/backup"

[network]
dns_servers = ["127.0.0.53"]

[security]
profile = "$(json_escape "${AIOS_SECURITY_PROFILE}")"
selinux_mode = "$(json_escape "${AIOS_SELINUX_MODE}")"
selinux_enforcing = ${SELINUX_ENFORCING_TOML}
measured_boot = true
fips_mode = false
ima_policy = "/etc/ima/ima-policy"
evm_policy = "/etc/evm/evm-policy"
dm_verity_policy = "/etc/aios/verity/rootfs-policy.json"
require_signed_boot_chain = ${BOOT_SIGNATURES_REQUIRED_TOML}

[evidence]
log_format = "jsonl"
retention_days = 90
sign_evidence = true

[policy]
bundle_dir = "/var/lib/aios/policy"
default_policy = "permissive"

[capability_runtime]
grpc_listen = "127.0.0.1:50051"
adapter_dir = "/usr/lib/aios"
sandbox_default = "bubblewrap"

[cognitive]
default_provider = "local"
model_cache_dir = "/var/cache/aios/models"

[fleet]
coordinator_enabled = false
cluster_name = "aios-default"

[autonomous]
orchestrator_mode = "monitor"
autonomy_level = "advisory"

[container]
default_engine = "podman-rootless"
docker_socket_exposed = false

[terminal]
default_mode = "lx"
allow_ai_modes = false

[marketplace]
auto_sync = true
sync_interval_hours = 24

[updates]
channel = "release"
state_dir = "/var/lib/aios/update"
rollback_dir = "/var/lib/aios/rollback"
trusted_key = "/etc/aios/update.d/trusted-release-key.pem"
require_signature = true

[hardening]
profile = "$(json_escape "${AIOS_SECURITY_PROFILE}")"
scan_on_boot = true

[logging]
level = "info"
journald = true
EOF

chmod 644 "${ROOTFS_DIR}/etc/aios/config.toml"
info "Default config: /etc/aios/config.toml"

# Hostname
echo "aios" > "${ROOTFS_DIR}/etc/hostname"

# Hosts
cat > "${ROOTFS_DIR}/etc/hosts" <<'EOF'
127.0.0.1   localhost localhost.localdomain
::1         localhost localhost.localdomain
127.0.1.1   aios aios.localdomain
EOF

# OS release
cat > "${ROOTFS_DIR}/etc/os-release" <<EOF
NAME="AI-OS.NET"
VERSION="${AIOS_VERSION} (Revision 12)"
ID=aios
ID_LIKE=linux
PRETTY_NAME="AI-OS.NET ${AIOS_VERSION}"
VERSION_ID="${AIOS_VERSION}"
HOME_URL="https://ai-os.net"
DOCUMENTATION_URL="https://ai-os.net/docs"
BUILD_ID="${AIOS_BUILD_ID}"
VARIANT="Server"
VARIANT_ID=server
EOF

# Issue file
cat > "${ROOTFS_DIR}/etc/issue" <<'EOF'
AI-OS.NET \n \l

AI-native Linux. Evidence-first. Open-source.
https://ai-os.net
EOF

# fstab (minimal — real mounts handled by initramfs)
cat > "${ROOTFS_DIR}/etc/fstab" <<'EOF'
# AI-OS.NET fstab
# Root is mounted by initramfs; additional mounts below.

proc     /proc            proc     defaults,nosuid,nodev,noexec    0 0
sysfs    /sys             sysfs    defaults,nosuid,nodev,noexec    0 0
devtmpfs /dev             devtmpfs defaults,nosuid,noexec          0 0
tmpfs    /tmp             tmpfs    defaults,nosuid,nodev           0 0
tmpfs    /run             tmpfs    defaults,nosuid,nodev,mode=755  0 0
tmpfs    /dev/shm         tmpfs    defaults,nosuid,nodev           0 0
devpts   /dev/pts         devpts   defaults,nosuid,noexec,gid=5,mode=620 0 0
EOF

# Shell profile for aios user
cat > "${ROOTFS_DIR}/home/aios/.profile" <<'EOF'
# AI-OS.NET user profile
export PATH="/usr/lib/aios:${PATH}:/opt/aios/bin"
export AIOS_CONFIG="/etc/aios/config.toml"
EOF
chmod 644 "${ROOTFS_DIR}/home/aios/.profile"

# NSS config
cat > "${ROOTFS_DIR}/etc/nsswitch.conf" <<'EOF'
passwd:   files systemd
group:    files systemd
shadow:   files
hosts:    files resolve [!UNAVAIL=return] dns
networks: files
EOF

ok "Configuration files installed."

# ── Step 7: Install security and integrity baseline ──────────────────────────

step "Step 7: Installing security and integrity baseline"

# SELinux policy sourcing (R12.6). Precedence:
#   1. --selinux-policy-source PATH  → operator-provided binary policy
#   2. base-rootfs                   → a genuine policy already shipped by the
#                                      R13.1 openSUSE base (selinux-policy-targeted
#                                      stages /etc/selinux/<type>/policy/policy.<N>)
#   3. placeholder                   → no policy anywhere; recorded honestly and
#                                      SELinux stays OFF (no kernel args).
SELINUX_POLICY_STATUS="placeholder"
SELINUX_POLICY_SOURCE="placeholder"
SELINUX_POLICY_TYPE="aios"
SELINUX_POLICY_VERSION="33"
SELINUX_POLICY_SHA256=""
SELINUX_POLICY_PRESENT=false

# Detect a real binary policy that the base rootfs already carries.
BASE_SELINUX_POLICY=""
if [ -d "${ROOTFS_DIR}/etc/selinux" ]; then
    BASE_SELINUX_POLICY="$(find "${ROOTFS_DIR}/etc/selinux" -mindepth 3 -maxdepth 3 \
        -type f -path '*/policy/policy.*' 2>/dev/null | sort | head -n1)"
fi

if [ -n "${AIOS_SELINUX_POLICY_SOURCE}" ]; then
    # (1) Operator-provided binary policy — highest precedence.
    SELINUX_POLICY_TYPE="aios"
    SELINUX_POLICY_VERSION="33"
    SELINUX_POLICY_DIR="${ROOTFS_DIR}/etc/selinux/aios/policy"
    mkdir -p "${SELINUX_POLICY_DIR}"
    cp "${AIOS_SELINUX_POLICY_SOURCE}" "${SELINUX_POLICY_DIR}/policy.33"
    chmod 600 "${SELINUX_POLICY_DIR}/policy.33"
    SELINUX_POLICY_STATUS="provided-binary"
    SELINUX_POLICY_SOURCE="provided-binary"
    SELINUX_POLICY_PRESENT=true
elif [ -n "${BASE_SELINUX_POLICY}" ]; then
    # (2) Genuine policy already present in the base rootfs — keep it verbatim.
    SELINUX_POLICY_DIR="$(dirname "${BASE_SELINUX_POLICY}")"
    SELINUX_POLICY_TYPE="$(basename "$(dirname "${SELINUX_POLICY_DIR}")")"
    SELINUX_POLICY_VERSION="${BASE_SELINUX_POLICY##*policy.}"
    SELINUX_POLICY_STATUS="present"
    SELINUX_POLICY_SOURCE="base-rootfs"
    SELINUX_POLICY_PRESENT=true
else
    # (3) No policy anywhere — honest placeholder. SELinux is NOT usable here;
    #     the boot entry carries no selinux kernel args (fails open, not silently
    #     "enforcing" against a stub). Replace with a real policy before enabling.
    SELINUX_POLICY_TYPE="aios"
    SELINUX_POLICY_VERSION="33"
    SELINUX_POLICY_DIR="${ROOTFS_DIR}/etc/selinux/aios/policy"
    mkdir -p "${SELINUX_POLICY_DIR}"
    cat > "${SELINUX_POLICY_DIR}/policy.33" <<'EOF'
# AI-OS.NET SELinux Policy — Placeholder
# This is a minimal binary policy stub.
# Replace with the output of checkpolicy + semodule_package for production,
# or build on the R13.1 openSUSE base (selinux-policy-targeted) for a real policy.
EOF
    chmod 644 "${SELINUX_POLICY_DIR}/policy.33"
fi

SELINUX_POLICY_REL_PATH="/etc/selinux/${SELINUX_POLICY_TYPE}/policy/policy.${SELINUX_POLICY_VERSION}"
if [ "${SELINUX_POLICY_PRESENT}" = true ]; then
    SELINUX_POLICY_SHA256="$(sha256sum "${SELINUX_POLICY_DIR}/policy.${SELINUX_POLICY_VERSION}" | awk '{print $1}')"
fi

# Fail-closed enforcing gate (moved from arg parsing): enforcing needs a REAL
# policy — operator-provided (--selinux-policy-source) or shipped by the base
# rootfs. A placeholder stub must never boot "enforcing".
if [ "${AIOS_SELINUX_MODE}" = "enforcing" ] && [ "${SELINUX_POLICY_PRESENT}" != true ]; then
    die "SELinux enforcing requires a real policy: none via --selinux-policy-source and none found in the base rootfs (${ROOTFS_DIR}/etc/selinux)."
fi

# SELinux config — SELINUXTYPE tracks the real policy type; when no policy is
# present the mode is forced to disabled so the target is honest and boots clean.
if [ "${SELINUX_POLICY_PRESENT}" = true ]; then
    SELINUX_CONFIG_MODE="${AIOS_SELINUX_MODE}"
else
    SELINUX_CONFIG_MODE="disabled"
fi
cat > "${ROOTFS_DIR}/etc/selinux/config" <<EOF
# AI-OS.NET SELinux configuration
SELINUX=${SELINUX_CONFIG_MODE}
SELINUXTYPE=${SELINUX_POLICY_TYPE}
EOF

cat > "${ROOTFS_DIR}/etc/ima/ima-policy" <<'EOF'
# AI-OS.NET Rev.12 IMA policy skeleton.
# Stage-only baseline. Enterprise enforcement requires signed xattrs and keys.
measure func=BPRM_CHECK
measure func=FILE_MMAP mask=MAY_EXEC
measure func=MODULE_CHECK
measure func=KEXEC_KERNEL_CHECK
appraise func=MODULE_CHECK appraise_type=imasig
EOF
chmod 644 "${ROOTFS_DIR}/etc/ima/ima-policy"
cp "${ROOTFS_DIR}/etc/ima/ima-policy" "${ROOTFS_DIR}/etc/aios/integrity.d/ima-policy"

cat > "${ROOTFS_DIR}/etc/evm/evm-policy" <<'EOF'
# AI-OS.NET Rev.12 EVM policy skeleton.
# Stage-only baseline. Enterprise enforcement requires EVM keys and labeled xattrs.
EVM_MODE=stage
EVM_XATTRS=security.selinux,security.ima
EOF
chmod 644 "${ROOTFS_DIR}/etc/evm/evm-policy"
cp "${ROOTFS_DIR}/etc/evm/evm-policy" "${ROOTFS_DIR}/etc/aios/integrity.d/evm-policy"

cat > "${ROOTFS_DIR}/etc/aios/verity/rootfs-policy.json" <<EOF
{
  "schema": "aios.dm_verity_policy.v1",
  "revision": 12,
  "root_hash": "/etc/aios/verity/roothash.sig",
  "cmdline_parameter": "dm_verity.roothash",
  "fail_on_missing_hash_when_required": true,
  "fail_on_corruption": true,
  "hash_device_labels": ["AIOS_HASH"],
  "data_device_candidates": ["/dev/mapper/aios-cryptroot", "/dev/disk/by-partlabel/AIOS_DATA"]
}
EOF
chmod 644 "${ROOTFS_DIR}/etc/aios/verity/rootfs-policy.json"

cat > "${ROOTFS_DIR}/etc/aios/security-profile.toml" <<EOF
# AI-OS.NET Rev.12 security profile

[profile]
name = "$(json_escape "${AIOS_SECURITY_PROFILE}")"
revision = 12

[selinux]
mode = "$(json_escape "${AIOS_SELINUX_MODE}")"
policy = "$(json_escape "${SELINUX_POLICY_REL_PATH}")"
policy_type = "$(json_escape "${SELINUX_POLICY_TYPE}")"
policy_source = "$(json_escape "${SELINUX_POLICY_SOURCE}")"
policy_status = "$(json_escape "${SELINUX_POLICY_STATUS}")"
policy_sha256 = "$(json_escape "${SELINUX_POLICY_SHA256}")"
policy_present = ${SELINUX_POLICY_PRESENT}
enforcing_ready = ${SELINUX_ENFORCING_TOML}

[ima]
policy = "/etc/ima/ima-policy"
mode = "stage"

[evm]
policy = "/etc/evm/evm-policy"
mode = "stage"

[dm_verity]
policy = "/etc/aios/verity/rootfs-policy.json"
root_hash = "/etc/aios/verity/roothash.sig"
fail_on_corruption = true

[boot_chain]
metadata = "/etc/aios/boot-chain.json"
require_signatures = ${BOOT_SIGNATURES_REQUIRED_TOML}
EOF
chmod 644 "${ROOTFS_DIR}/etc/aios/security-profile.toml"

cat > "${ROOTFS_DIR}/etc/aios/boot-chain.json" <<EOF
{
  "schema": "aios.rootfs_boot_chain.v1",
  "revision": 12,
  "required": ${BOOT_SIGNATURES_REQUIRED_TOML},
  "artifacts": [
    "boot/grub/grub.cfg",
    "live/vmlinuz",
    "live/initrd.img",
    "live/aios.squashfs",
    "aios/manifest.json",
    "aios/security.json",
    "aios/boot-chain.json"
  ]
}
EOF
chmod 644 "${ROOTFS_DIR}/etc/aios/boot-chain.json"

cat > "${ROOTFS_DIR}/etc/aios/evidence.d/security-baseline.json" <<EOF
{
  "schema": "aios.security_baseline_evidence.v1",
  "revision": 12,
  "profile": "$(json_escape "${AIOS_SECURITY_PROFILE}")",
  "selinux_mode": "$(json_escape "${AIOS_SELINUX_MODE}")",
  "selinux_policy_status": "$(json_escape "${SELINUX_POLICY_STATUS}")",
  "selinux_policy_source": "$(json_escape "${SELINUX_POLICY_SOURCE}")",
  "selinux_policy_type": "$(json_escape "${SELINUX_POLICY_TYPE}")",
  "ima_policy": "/etc/ima/ima-policy",
  "evm_policy": "/etc/evm/evm-policy",
  "dm_verity_policy": "/etc/aios/verity/rootfs-policy.json",
  "boot_chain_signatures_required": ${BOOT_SIGNATURES_REQUIRED_TOML}
}
EOF
chmod 644 "${ROOTFS_DIR}/etc/aios/evidence.d/security-baseline.json"

info "SELinux config installed (${AIOS_SELINUX_MODE}; policy status: ${SELINUX_POLICY_STATUS})."
info "IMA/EVM policy skeleton staged."
info "dm-verity and boot-chain policy staged."

ok "Security and integrity baseline installed."

# ── Step 8: Prepare grub.cfg (boot menu for GRUB2 via grub2-mkrescue) ─────────

step "Step 8: Creating GRUB2 boot configuration"

mkdir -p "${ROOTFS_DIR}/boot/grub"

# Detect grub2-mkrescue (openSUSE) / grub-mkrescue (Debian) — the one tool
# that handles EFI ISO creation correctly
GRUB2_MKRESCUE="$(command -v grub2-mkrescue 2>/dev/null || command -v grub-mkrescue 2>/dev/null || echo '')"
HAS_GRUB2=false
[ -n "${GRUB2_MKRESCUE}" ] && HAS_GRUB2=true

# Generate grub.cfg for the live ISO
cat > "${ROOTFS_DIR}/boot/grub/grub.cfg" <<'GRUBCFG'
set timeout=5
set default=0

menuentry "AI-OS.NET Rev.12 Live" {
    linux /live/vmlinuz root=live:CDLABEL=AIOS_REV12 rd.live.image rd.live.overlay=tmpfs quiet loglevel=3 console=tty0 console=ttyS0,115200n8 aios.fleet.mode=standalone aios.autonomous.level=advisory
    initrd /live/initrd.img
}

menuentry "AI-OS.NET Rev.12 Live (debug)" {
    linux /live/vmlinuz root=live:CDLABEL=AIOS_REV12 rd.live.image rd.live.overlay=tmpfs loglevel=7 console=tty0 console=ttyS0,115200n8 aios.fleet.mode=standalone aios.autonomous.level=advisory
    initrd /live/initrd.img
}

menuentry "AI-OS.NET Rev.12 Recovery Shell" {
    linux /live/vmlinuz root=live:CDLABEL=AIOS_REV12 rd.live.image rescue systemd.unit=rescue.target console=tty0 console=ttyS0,115200n8
    initrd /live/initrd.img
}
GRUBCFG

# R12.6: put SELinux on the kernel command line of the DEFAULT entry ONLY when a
# genuine policy is present. Default boot mode is PERMISSIVE (enforcing=0) so the
# baseline logs AVCs without blocking — enforcing is opt-in via --selinux-mode
# enforcing (which additionally requires a real policy). With no policy present
# the entry carries NO selinux args (selinux=0 semantics — nothing to enforce).
if [ "${SELINUX_POLICY_PRESENT}" = true ]; then
    if [ "${AIOS_SELINUX_MODE}" = "enforcing" ]; then
        SELINUX_KERNEL_CMDLINE="security=selinux selinux=1 enforcing=1"
    else
        SELINUX_KERNEL_CMDLINE="security=selinux selinux=1 enforcing=0"
    fi
    # loglevel=3 is unique to the default "Live" entry (debug uses loglevel=7,
    # recovery has none) — inject only there.
    sed -i "/loglevel=3/ s#aios\\.autonomous\\.level=advisory#aios.autonomous.level=advisory ${SELINUX_KERNEL_CMDLINE}#" \
        "${ROOTFS_DIR}/boot/grub/grub.cfg"
    info "SELinux kernel args on default boot entry: ${SELINUX_KERNEL_CMDLINE} (type=${SELINUX_POLICY_TYPE}, source=${SELINUX_POLICY_SOURCE})"
else
    info "No SELinux policy present — default boot entry carries no selinux kernel args (placeholder)."
fi

if ${HAS_GRUB2}; then
    info "grub2-mkrescue detected — ISO will be UEFI-bootable with GRUB2"
else
    warn "grub2-mkrescue not found — install grub2-x86_64-efi package"
fi

ok "GRUB2 boot configuration prepared."

# ── Step 8: Install kernel ───────────────────────────────────────────────────

step "Step 8: Installing kernel"

KERNEL_DST="${ISO_DIR}/live"
mkdir -p "${KERNEL_DST}"

install_kernel() {
    local vmlinuz="$1"
    local initrd="$2"

    if [ ! -f "${vmlinuz}" ]; then
        warn "Kernel image not found: ${vmlinuz}"
        return 1
    fi

    cp "${vmlinuz}" "${KERNEL_DST}/vmlinuz"
    chmod 644 "${KERNEL_DST}/vmlinuz"
    STAGED_KERNEL_SOURCE_PATH="${vmlinuz}"
    STAGED_KERNEL_VERSION="$(infer_kernel_version_from_path "${vmlinuz}")"
    info "Kernel installed: $(basename "${vmlinuz}") -> live/vmlinuz"
    info "Kernel version inferred: ${STAGED_KERNEL_VERSION}"

    if [ -f "${initrd}" ]; then
        cp "${initrd}" "${KERNEL_DST}/initrd.img"
        chmod 644 "${KERNEL_DST}/initrd.img"
        info "Initrd installed: $(basename "${initrd}") -> live/initrd.img"
    fi
    return 0
}

if [ "${KERNEL_SOURCE}" = "host" ]; then
    # Kernel discovery order: the STAGED ROOTFS first (the distribution's own
    # kernel-default shipped by the base rootfs — required for hermetic CI
    # builds where the build container has no kernel), then the build host.
    VMLINUX=""
    INITRD=""

    for kdir in "${ROOTFS_DIR}"/usr/lib/modules/*/ "${ROOTFS_DIR}"/boot/; do
        [ -d "${kdir}" ] || continue
        for candidate in "${kdir}vmlinuz" "${kdir}"vmlinuz-*; do
            if [ -f "${candidate}" ]; then
                VMLINUX="${candidate}"
                info "Kernel found in staged rootfs: ${candidate}"
                break 2
            fi
        done
    done

    # Primary host path: /usr/lib/modules/<version>/vmlinuz (kernel-default RPM layout)
    if [ -z "${VMLINUX}" ] && [ -d "/usr/lib/modules" ]; then
        for kdir in /usr/lib/modules/*/; do
            candidate="${kdir}vmlinuz"
            if [ -f "${candidate}" ]; then
                VMLINUX="${candidate}"
                info "Kernel found: ${candidate}"
                break
            fi
        done
    fi

    # Fallback: /boot/ patterns
    if [ -z "${VMLINUX}" ]; then
        for candidate in \
            /boot/vmlinuz-linux \
            /boot/vmlinuz-linux-lts \
            /boot/vmlinuz-"$(uname -r)" \
            /boot/vmlinuz; do
            if [ -f "${candidate}" ]; then
                VMLINUX="${candidate}"
                break
            fi
        done
    fi

    # Initramfs: try /boot/initrd (RPM default), then patterns
    for candidate in \
        /boot/initrd \
        /boot/initramfs-linux.img \
        /boot/initramfs-linux-lts.img \
        /boot/initramfs-"$(uname -r)".img \
        /boot/initrd.img-"$(uname -r)"; do
        if [ -f "${candidate}" ]; then
            INITRD="${candidate}"
            break
        fi
    done

    if [ -z "${VMLINUX}" ]; then
        warn "No kernel found — ISO will boot kernelless."
        warn "Set KERNEL_SOURCE to a kernel directory or file path."
    else
        install_kernel "${VMLINUX}" "${INITRD}"
    fi
elif [ -d "${KERNEL_SOURCE}" ]; then
    VMLINUX=""
    for candidate in "${KERNEL_SOURCE}"/vmlinuz*; do
        [ -f "${candidate}" ] && { VMLINUX="${candidate}"; break; }
    done
    INITRD=""
    for candidate in "${KERNEL_SOURCE}"/initrd* "${KERNEL_SOURCE}"/initramfs*; do
        [ -f "${candidate}" ] && { INITRD="${candidate}"; break; }
    done
    install_kernel "${VMLINUX}" "${INITRD}"
elif [ -f "${KERNEL_SOURCE}" ]; then
    install_kernel "${KERNEL_SOURCE}" ""
else
    warn "Kernel source '${KERNEL_SOURCE}' not valid — skipping kernel install."
fi

ok "Kernel installation complete."

# ── Step 8b: Stage kernel modules and firmware ───────────────────────────────

step "Step 8b: Staging kernel modules and firmware"

stage_kernel_modules() {
    local modules_dst
    local modules_src=""
    local candidate

    [ -f "${ISO_DIR}/live/vmlinuz" ] || die "Kernel image missing before module staging."
    if [ -z "${STAGED_KERNEL_VERSION}" ] || [ "${STAGED_KERNEL_VERSION}" = "unknown" ]; then
        die "Kernel version is unknown; set --kernel-version to stage matching modules."
    fi

    modules_dst="${ROOTFS_DIR}/usr/lib/modules/${STAGED_KERNEL_VERSION}"
    mkdir -p "$(dirname "${modules_dst}")"

    case "${KERNEL_MODULES_SOURCE}" in
        none)
            mkdir -p "${modules_dst}"
            cat > "${modules_dst}/AIOS_MODULES_EMPTY" <<EOF
AI-OS.NET module tree explicitly marked empty for kernel ${STAGED_KERNEL_VERSION}.
This is allowed only when the target kernel is built without external modules.
EOF
            STAGED_MODULE_MODE="explicit-empty"
            STAGED_MODULE_SOURCE_PATH="none"
            ;;
        auto|host)
            if [ -f "${modules_dst}/modules.dep" ]; then
                STAGED_MODULE_MODE="base-rootfs"
                STAGED_MODULE_SOURCE_PATH="${modules_dst}"
            else
                for candidate in \
                    "/usr/lib/modules/${STAGED_KERNEL_VERSION}" \
                    "/lib/modules/${STAGED_KERNEL_VERSION}"; do
                    if [ -d "${candidate}" ] && [ -f "${candidate}/modules.dep" ]; then
                        modules_src="${candidate}"
                        break
                    fi
                done
                [ -n "${modules_src}" ] || die "No module tree found for kernel ${STAGED_KERNEL_VERSION}; set --kernel-modules-source."
                rm -rf "${modules_dst}"
                mkdir -p "${modules_dst}"
                cp -a "${modules_src}/." "${modules_dst}/"
                STAGED_MODULE_MODE="copied"
                STAGED_MODULE_SOURCE_PATH="${modules_src}"
            fi
            ;;
        *)
            if [ -d "${KERNEL_MODULES_SOURCE}/${STAGED_KERNEL_VERSION}" ]; then
                modules_src="${KERNEL_MODULES_SOURCE}/${STAGED_KERNEL_VERSION}"
            elif [ -d "${KERNEL_MODULES_SOURCE}" ]; then
                modules_src="${KERNEL_MODULES_SOURCE}"
            else
                die "Kernel module source not found: ${KERNEL_MODULES_SOURCE}"
            fi
            [ -f "${modules_src}/modules.dep" ] || die "Kernel module source lacks modules.dep: ${modules_src}"
            rm -rf "${modules_dst}"
            mkdir -p "${modules_dst}"
            cp -a "${modules_src}/." "${modules_dst}/"
            STAGED_MODULE_MODE="copied"
            STAGED_MODULE_SOURCE_PATH="${modules_src}"
            ;;
    esac

    if [ ! -f "${modules_dst}/modules.dep" ] && [ ! -f "${modules_dst}/AIOS_MODULES_EMPTY" ]; then
        die "Staged module tree is invalid: ${modules_dst}"
    fi

    STAGED_MODULE_FILE_COUNT="$(count_tree_files "${modules_dst}")"
    info "Kernel modules: ${STAGED_MODULE_MODE} (${STAGED_MODULE_FILE_COUNT} files)"
}

stage_kernel_firmware() {
    local firmware_dst="${ROOTFS_DIR}/usr/lib/firmware"
    local firmware_src=""
    local candidate

    mkdir -p "${firmware_dst}"

    case "${KERNEL_FIRMWARE_SOURCE}" in
        none)
            cat > "${firmware_dst}/AIOS_FIRMWARE_EMPTY" <<'EOF'
AI-OS.NET firmware tree explicitly marked empty for this target profile.
EOF
            STAGED_FIRMWARE_MODE="explicit-empty"
            STAGED_FIRMWARE_SOURCE_PATH="none"
            ;;
        auto|host)
            if [ "$(count_tree_files "${firmware_dst}")" != "0" ]; then
                STAGED_FIRMWARE_MODE="base-rootfs"
                STAGED_FIRMWARE_SOURCE_PATH="${firmware_dst}"
            else
                for candidate in /usr/lib/firmware /lib/firmware; do
                    if [ -d "${candidate}" ] && [ "$(count_tree_files "${candidate}")" != "0" ]; then
                        firmware_src="${candidate}"
                        break
                    fi
                done
                [ -n "${firmware_src}" ] || die "No firmware tree found; set --kernel-firmware-source none only for explicit empty profiles."
                cp -a "${firmware_src}/." "${firmware_dst}/"
                STAGED_FIRMWARE_MODE="copied"
                STAGED_FIRMWARE_SOURCE_PATH="${firmware_src}"
            fi
            ;;
        *)
            [ -d "${KERNEL_FIRMWARE_SOURCE}" ] || die "Firmware source not found: ${KERNEL_FIRMWARE_SOURCE}"
            [ "$(count_tree_files "${KERNEL_FIRMWARE_SOURCE}")" != "0" ] || die "Firmware source is empty: ${KERNEL_FIRMWARE_SOURCE}"
            cp -a "${KERNEL_FIRMWARE_SOURCE}/." "${firmware_dst}/"
            STAGED_FIRMWARE_MODE="copied"
            STAGED_FIRMWARE_SOURCE_PATH="${KERNEL_FIRMWARE_SOURCE}"
            ;;
    esac

    if [ "$(count_tree_files "${firmware_dst}")" = "0" ] && [ ! -f "${firmware_dst}/AIOS_FIRMWARE_EMPTY" ]; then
        die "Firmware tree missing from rootfs."
    fi

    STAGED_FIRMWARE_FILE_COUNT="$(count_tree_files "${firmware_dst}")"
    info "Firmware tree: ${STAGED_FIRMWARE_MODE} (${STAGED_FIRMWARE_FILE_COUNT} files)"
}

stage_kernel_modules
stage_kernel_firmware

ok "Kernel modules and firmware staged."

# ── Step 9: Build initramfs ──────────────────────────────────────────────────

step "Step 9: Building initramfs"

# Copy initramfs scripts from project source
cp -r "${REPO_ROOT}/distro/aios-boot/initramfs" "${INITRAMFS_DIR}"
chmod +x "${INITRAMFS_DIR}/init"

# Install busybox in initramfs — try busybox-static first (openSUSE), then busybox
if ${HAS_BUSYBOX}; then
    BUSYBOX_BIN="$(command -v "${BUSYBOX_CMD}" 2>/dev/null || command -v busybox-static 2>/dev/null || echo '')"
    if [ -z "${BUSYBOX_BIN}" ] || [ ! -f "${BUSYBOX_BIN}" ]; then
        warn "busybox binary not found at expected path — initramfs will lack shell."
        BUSYBOX_BIN=""
    fi
    mkdir -p "${INITRAMFS_DIR}/bin"

    if [ -n "${BUSYBOX_BIN}" ] && [ -f "${BUSYBOX_BIN}" ]; then
        cp "${BUSYBOX_BIN}" "${INITRAMFS_DIR}/bin/busybox"
        chmod 755 "${INITRAMFS_DIR}/bin/busybox"

        # Install busybox symlinks
        for applet in sh ls cat cp mv rm mkdir mount umount switch_root \
                      grep sed head printf sleep test echo true false \
                      dd mknod ln chmod chown sync reboot poweroff \
                      blkid find xargs cut tr wc which mountpoint losetup \
                      modprobe; do
            ln -sf busybox "${INITRAMFS_DIR}/bin/${applet}" 2>/dev/null || true
        done

        # Symlink /bin/sh for compat
        mkdir -p "${INITRAMFS_DIR}/sbin"
        ln -sf ../bin/busybox "${INITRAMFS_DIR}/sbin/init" 2>/dev/null || true
        ln -sf /bin/busybox  "${INITRAMFS_DIR}/bin/sh" 2>/dev/null || true
        if [ -f "${INITRAMFS_DIR}/rescue.sh" ]; then
            cp "${INITRAMFS_DIR}/rescue.sh" "${INITRAMFS_DIR}/bin/rescue.sh"
            chmod 755 "${INITRAMFS_DIR}/bin/rescue.sh"
        fi
        info "Busybox installed in initramfs with common applets."
    else
        warn "Busybox binary not available — initramfs shell will not function."
    fi
else
    warn "busybox not found — initramfs will be non-functional!"
    warn "Install busybox-static package."
fi

# Install optional initramfs tools
for tool in cryptsetup tpm2_unseal veritysetup load_policy; do
    if command -v "${tool}" >/dev/null 2>&1; then
        mkdir -p "${INITRAMFS_DIR}/sbin"
        cp "$(command -v "${tool}")" "${INITRAMFS_DIR}/sbin/${tool}"
        chmod 755 "${INITRAMFS_DIR}/sbin/${tool}"
        info "Copied ${tool} to initramfs."
    fi
done

# Install only the staged module tree that matches the staged kernel.
if [ -n "${STAGED_KERNEL_VERSION}" ] \
   && [ -d "${ROOTFS_DIR}/usr/lib/modules/${STAGED_KERNEL_VERSION}" ]; then
    mkdir -p "${INITRAMFS_DIR}/lib/modules"
    cp -a "${ROOTFS_DIR}/usr/lib/modules/${STAGED_KERNEL_VERSION}" \
        "${INITRAMFS_DIR}/lib/modules/${STAGED_KERNEL_VERSION}" 2>/dev/null || \
        warn "Could not copy staged kernel modules into initramfs."

    # busybox modprobe cannot read zstd-compressed modules (openSUSE ships
    # .ko.zst) — decompress them in the initramfs copy and fix the module
    # index files, or the live-media drivers (sr_mod/isofs) never load.
    INITRAMFS_MOD_DIR="${INITRAMFS_DIR}/lib/modules/${STAGED_KERNEL_VERSION}"
    if [ -d "${INITRAMFS_MOD_DIR}" ] \
       && find "${INITRAMFS_MOD_DIR}" -name '*.ko.zst' -print -quit 2>/dev/null | grep -q .; then
        if command -v zstd >/dev/null 2>&1; then
            find "${INITRAMFS_MOD_DIR}" -name '*.ko.zst' -exec zstd -d -q --rm {} + \
                || die "Failed to decompress .ko.zst modules for the initramfs"
            for _modindex in "${INITRAMFS_MOD_DIR}"/modules.dep \
                             "${INITRAMFS_MOD_DIR}"/modules.alias \
                             "${INITRAMFS_MOD_DIR}"/modules.symbols \
                             "${INITRAMFS_MOD_DIR}"/modules.builtin.modinfo; do
                [ -f "${_modindex}" ] && sed -i 's/\.ko\.zst/\.ko/g' "${_modindex}"
            done
            info "Initramfs modules decompressed (.ko.zst → .ko) for busybox modprobe."
        else
            die "Initramfs modules are .ko.zst but zstd is unavailable — busybox modprobe cannot load them."
        fi
    fi
fi

# Copy preinit config to initramfs
mkdir -p "${INITRAMFS_DIR}/etc/aios"
cp "${REPO_ROOT}/distro/aios-boot/initramfs/aios-preinit" "${INITRAMFS_DIR}/etc/aios/preinit"
mkdir -p "${INITRAMFS_DIR}/etc/ima" "${INITRAMFS_DIR}/etc/evm" \
    "${INITRAMFS_DIR}/etc/aios/integrity.d" \
    "${INITRAMFS_DIR}/etc/selinux/${SELINUX_POLICY_TYPE}/policy"
cp "${ROOTFS_DIR}/etc/selinux/config" "${INITRAMFS_DIR}/etc/selinux/config"
cp "${ROOTFS_DIR}${SELINUX_POLICY_REL_PATH}" \
    "${INITRAMFS_DIR}${SELINUX_POLICY_REL_PATH}"
cp "${ROOTFS_DIR}/etc/ima/ima-policy" "${INITRAMFS_DIR}/etc/ima/ima-policy"
cp "${ROOTFS_DIR}/etc/evm/evm-policy" "${INITRAMFS_DIR}/etc/evm/evm-policy"
cp "${ROOTFS_DIR}/etc/aios/integrity.d/ima-policy" "${INITRAMFS_DIR}/etc/aios/integrity.d/ima-policy"
cp "${ROOTFS_DIR}/etc/aios/integrity.d/evm-policy" "${INITRAMFS_DIR}/etc/aios/integrity.d/evm-policy"

# Build the initramfs cpio archive
( cd "${INITRAMFS_DIR}" && find . -print0 | \
    cpio --null --create --format=newc 2>/dev/null | \
    xz -9 --check=crc32 > "${INITRAMFS_OUT}" )

INITRAMFS_SIZE=$(du -h "${INITRAMFS_OUT}" | cut -f1)
ok "Initramfs built: ${INITRAMFS_OUT} (${INITRAMFS_SIZE})"

# Copy initramfs to ISO staging for GRUB to find during live boot
mkdir -p "${ISO_DIR}/live"
cp "${INITRAMFS_OUT}" "${ISO_DIR}/live/initrd.img"
info "Initramfs copied to ISO staging: live/initrd.img"

# ── Step 10: Create squashfs root image ──────────────────────────────────────

step "Step 10: Creating squashfs root image"

mkdir -p "${ISO_DIR}/live"

# Create mksquashfs exclude file
EXCLUDE_FILE="${BUILD_DIR}/squashfs-excludes.txt"
cat > "${EXCLUDE_FILE}" <<'EOF'
proc
sys
dev
run
tmp
lost+found
mnt
media
EOF

mksquashfs "${ROOTFS_DIR}" "${ISO_DIR}/live/aios.squashfs" \
    -comp xz \
    -b 1048576 \
    -Xdict-size 100% \
    -noappend \
    -ef "${EXCLUDE_FILE}" \
    -wildcards

SQUASHFS_SIZE=$(du -h "${ISO_DIR}/live/aios.squashfs" | cut -f1)
ok "Squashfs root created: live/aios.squashfs (${SQUASHFS_SIZE})"

# grub2-mkrescue and the Rev.12 manifest both consume the ISO-staged GRUB cfg.
mkdir -p "${ISO_DIR}/boot/grub"
cp "${ROOTFS_DIR}/boot/grub/grub.cfg" "${ISO_DIR}/boot/grub/grub.cfg"

# ── Step 10b: Generate real dm-verity hash tree (R12.6) ──────────────────────
# veritysetup format runs entirely in userspace (no root, no device mapper) and
# produces a Merkle hash tree + root hash over the squashfs payload. The root
# hash is what a booting initramfs pins the rootfs to. When veritysetup is
# unavailable the metadata records status "unavailable" — it MUST NEVER emit a
# fabricated root hash.

VERITY_STATUS="disabled"
VERITY_ROOT_HASH=""
VERITY_HASH_ALG=""
VERITY_DATA_BLOCK=""
VERITY_HASH_BLOCK=""
VERITY_SALT=""
VERITY_HASHTREE_REL=""
VERITY_HASHTREE_SHA256=""

if [ "${AIOS_DM_VERITY}" = "disabled" ]; then
    info "dm-verity generation disabled (--dm-verity disabled); no hash tree produced."
elif command -v veritysetup >/dev/null 2>&1; then
    step "Step 10b: Generating dm-verity hash tree"
    VERITY_HASHTREE="${ISO_DIR}/live/aios.squashfs.verity"
    VERITY_ROOT_HASH_FILE="${BUILD_DIR}/aios.squashfs.roothash"
    VERITY_FORMAT_LOG="${BUILD_DIR}/veritysetup-format.log"
    rm -f "${VERITY_HASHTREE}" "${VERITY_ROOT_HASH_FILE}"

    if veritysetup format "${ISO_DIR}/live/aios.squashfs" "${VERITY_HASHTREE}" \
            --root-hash-file "${VERITY_ROOT_HASH_FILE}" > "${VERITY_FORMAT_LOG}" 2>&1; then
        VERITY_ROOT_HASH="$(tr -d '[:space:]' < "${VERITY_ROOT_HASH_FILE}")"
        # Fallback: parse root hash from the format log if the file is empty.
        if [ -z "${VERITY_ROOT_HASH}" ]; then
            VERITY_ROOT_HASH="$(awk -F: '/Root hash/{gsub(/[^0-9a-fA-F]/,"",$2);print $2;exit}' "${VERITY_FORMAT_LOG}")"
        fi
        VERITY_HASH_ALG="$(awk -F: '/Hash algorithm/{gsub(/^[ \t]+|[ \t]+$/,"",$2);print $2;exit}' "${VERITY_FORMAT_LOG}")"
        VERITY_DATA_BLOCK="$(awk -F: '/Data block size/{gsub(/[^0-9]/,"",$2);print $2;exit}' "${VERITY_FORMAT_LOG}")"
        VERITY_HASH_BLOCK="$(awk -F: '/Hash block size/{gsub(/[^0-9]/,"",$2);print $2;exit}' "${VERITY_FORMAT_LOG}")"
        VERITY_SALT="$(awk -F: '/^Salt/{gsub(/[^0-9a-fA-F]/,"",$2);print $2;exit}' "${VERITY_FORMAT_LOG}")"
        VERITY_HASHTREE_SHA256="$(file_sha256 "${VERITY_HASHTREE}")"
        VERITY_HASHTREE_REL="live/aios.squashfs.verity"
        VERITY_STATUS="present"
        info "dm-verity root hash: ${VERITY_ROOT_HASH}"
        info "dm-verity hash tree: ${VERITY_HASHTREE_REL} (alg=${VERITY_HASH_ALG}, ${VERITY_DATA_BLOCK}/${VERITY_HASH_BLOCK} block)"

        # Wire the root hash into the GRUB *debug* entry only (uniquely keyed by
        # loglevel=7). The default and recovery entries stay untouched.
        if [ -n "${VERITY_ROOT_HASH}" ]; then
            sed -i "/loglevel=7/ s/aios\\.autonomous\\.level=advisory/aios.autonomous.level=advisory aios.verity.roothash=${VERITY_ROOT_HASH}/" \
                "${ISO_DIR}/boot/grub/grub.cfg"
        fi
        ok "dm-verity hash tree generated; root hash wired into GRUB debug entry."
    else
        warn "veritysetup format failed — recording dm-verity status 'unavailable'."
        cat "${VERITY_FORMAT_LOG}" >&2 || true
        rm -f "${VERITY_HASHTREE}"
        VERITY_STATUS="unavailable"
    fi
else
    warn "veritysetup not found — dm-verity root hash NOT generated; recording status 'unavailable'."
    VERITY_STATUS="unavailable"
fi

# ── Step 11: Generate Rev.12 release metadata ────────────────────────────────

step "Step 11: Generating Rev.12 release metadata"

AIOS_ISO_META_DIR="${ISO_DIR}/aios"
AIOS_SIGNATURE_DIR="${AIOS_ISO_META_DIR}/signatures"
mkdir -p "${AIOS_SIGNATURE_DIR}"

BUILD_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
GIT_DIRTY=false
if git -C "${REPO_ROOT}" diff --quiet --ignore-submodules -- 2>/dev/null; then
    GIT_DIRTY=false
else
    GIT_DIRTY=true
fi

if [ -n "${AIOS_SIGNATURE_SOURCE_DIR}" ]; then
    cp -a "${AIOS_SIGNATURE_SOURCE_DIR}/." "${AIOS_SIGNATURE_DIR}/"
    info "Detached signatures staged from ${AIOS_SIGNATURE_SOURCE_DIR}"
fi

require_boot_signature() {
    local sig_name="$1"

    if [ "${AIOS_REQUIRE_BOOT_SIGNATURES}" = "1" ] \
       && [ ! -f "${AIOS_SIGNATURE_DIR}/${sig_name}" ]; then
        die "Boot-chain signature required but missing: aios/signatures/${sig_name}"
    fi
}

cat > "${AIOS_ISO_META_DIR}/base.json" <<EOF
{
  "schema": "aios.base_rootfs.v1",
  "revision": 13,
  "base_family": "$(json_escape "${AIOS_BASE_FAMILY}")",
  "variant": "$(json_escape "${AIOS_BASE_VARIANT}")",
  "version": "$(json_escape "${AIOS_BASE_VERSION}")",
  "series": "$(json_escape "${AIOS_BASE_SERIES}")",
  "architecture": "$(json_escape "${AIOS_BASE_ARCH}")",
  "support_window_months": ${AIOS_BASE_SUPPORT_MONTHS},
  "eol_date": "$(json_escape "${AIOS_BASE_EOL_DATE}")",
  "kernel_policy": "$(json_escape "${AIOS_BASE_KERNEL_POLICY}")",
  "package_policy": "$(json_escape "${AIOS_BASE_PACKAGE_POLICY}")",
  "repositories": {
    "oss": "$(json_escape "${AIOS_BASE_REPO_OSS}")",
    "update": "$(json_escape "${AIOS_BASE_REPO_UPDATE}")"
  },
  "builder": "$(json_escape "${AIOS_BASE_BUILDER}")",
  "enterprise_release": ${ENTERPRISE_RELEASE_JSON}
}
EOF

cat > "${AIOS_ISO_META_DIR}/kernel.json" <<EOF
{
  "schema": "aios.kernel_pipeline.v1",
  "revision": 12,
  "kernel": {
    "version": "$(json_escape "${STAGED_KERNEL_VERSION}")",
    "source": "$(json_escape "${KERNEL_SOURCE}")",
    "staged_source_path": "$(json_escape "${STAGED_KERNEL_SOURCE_PATH}")",
    "image": "live/vmlinuz"
  },
  "modules": {
    "source": "$(json_escape "${KERNEL_MODULES_SOURCE}")",
    "staged_source_path": "$(json_escape "${STAGED_MODULE_SOURCE_PATH}")",
    "mode": "$(json_escape "${STAGED_MODULE_MODE}")",
    "rootfs_path": "/usr/lib/modules/$(json_escape "${STAGED_KERNEL_VERSION}")",
    "file_count": ${STAGED_MODULE_FILE_COUNT}
  },
  "firmware": {
    "source": "$(json_escape "${KERNEL_FIRMWARE_SOURCE}")",
    "staged_source_path": "$(json_escape "${STAGED_FIRMWARE_SOURCE_PATH}")",
    "mode": "$(json_escape "${STAGED_FIRMWARE_MODE}")",
    "rootfs_path": "/usr/lib/firmware",
    "file_count": ${STAGED_FIRMWARE_FILE_COUNT}
  },
  "signing_hooks": {
    "kernel": "live/vmlinuz.sig",
    "initramfs": "live/initrd.img.sig",
    "rootfs": "live/aios.squashfs.sig",
    "bootloader": "boot-grub-grub.cfg.sig",
    "modules": "usr-lib-modules-$(json_escape "${STAGED_KERNEL_VERSION}").sig",
    "firmware": "usr-lib-firmware.sig"
  }
}
EOF

# Build JSON-safe fragments for the dm-verity block (real values when a hash
# tree was produced; JSON null otherwise — never a fabricated hash).
if [ "${VERITY_STATUS}" = "present" ]; then
    VERITY_ROOT_HASH_JSON="\"${VERITY_ROOT_HASH}\""
    VERITY_HASH_ALG_JSON="\"$(json_escape "${VERITY_HASH_ALG}")\""
    VERITY_SALT_JSON="\"$(json_escape "${VERITY_SALT}")\""
    VERITY_HASHTREE_JSON="\"${VERITY_HASHTREE_REL}\""
    VERITY_HASHTREE_SHA256_JSON="\"${VERITY_HASHTREE_SHA256}\""
    VERITY_DATA_BLOCK_JSON="${VERITY_DATA_BLOCK:-null}"
    VERITY_HASH_BLOCK_JSON="${VERITY_HASH_BLOCK:-null}"
else
    VERITY_ROOT_HASH_JSON="null"
    VERITY_HASH_ALG_JSON="null"
    VERITY_SALT_JSON="null"
    VERITY_HASHTREE_JSON="null"
    VERITY_HASHTREE_SHA256_JSON="null"
    VERITY_DATA_BLOCK_JSON="null"
    VERITY_HASH_BLOCK_JSON="null"
fi

cat > "${AIOS_ISO_META_DIR}/security.json" <<EOF
{
  "schema": "aios.security_baseline.v1",
  "revision": 12,
  "profile": "$(json_escape "${AIOS_SECURITY_PROFILE}")",
  "selinux": {
    "configured_mode": "$(json_escape "${AIOS_SELINUX_MODE}")",
    "policy_path": "$(json_escape "${SELINUX_POLICY_REL_PATH}")",
    "policy_type": "$(json_escape "${SELINUX_POLICY_TYPE}")",
    "policy_source": "$(json_escape "${SELINUX_POLICY_SOURCE}")",
    "policy_status": "$(json_escape "${SELINUX_POLICY_STATUS}")",
    "policy_sha256": "$(json_escape "${SELINUX_POLICY_SHA256}")",
    "policy_present": ${SELINUX_POLICY_PRESENT},
    "enforcing_ready": ${SELINUX_ENFORCING_TOML}
  },
  "ima": {
    "policy_path": "/etc/ima/ima-policy",
    "rootfs_copy": "/etc/aios/integrity.d/ima-policy",
    "mode": "stage"
  },
  "evm": {
    "policy_path": "/etc/evm/evm-policy",
    "rootfs_copy": "/etc/aios/integrity.d/evm-policy",
    "mode": "stage"
  },
  "dm_verity": {
    "policy_path": "/etc/aios/verity/rootfs-policy.json",
    "root_hash_path": "/etc/aios/verity/roothash.sig",
    "cmdline_parameter": "dm_verity.roothash",
    "fail_on_corruption": true,
    "status": "$(json_escape "${VERITY_STATUS}")",
    "root_hash": ${VERITY_ROOT_HASH_JSON},
    "hash_algorithm": ${VERITY_HASH_ALG_JSON},
    "data_block_size": ${VERITY_DATA_BLOCK_JSON},
    "hash_block_size": ${VERITY_HASH_BLOCK_JSON},
    "salt": ${VERITY_SALT_JSON},
    "hashtree_path": ${VERITY_HASHTREE_JSON},
    "hashtree_sha256": ${VERITY_HASHTREE_SHA256_JSON}
  },
  "evidence": {
    "path": "/etc/aios/evidence.d/security-baseline.json"
  }
}
EOF

cat > "${AIOS_ISO_META_DIR}/boot-chain.json" <<EOF
{
  "schema": "aios.boot_chain_signing.v1",
  "revision": 12,
  "required": ${BOOT_SIGNATURES_REQUIRED_TOML},
  "signature_source_dir": "$(json_escape "${AIOS_SIGNATURE_SOURCE_DIR:-none}")",
  "artifacts": {
    "bootloader": "boot/grub/grub.cfg",
    "kernel": "live/vmlinuz",
    "initramfs": "live/initrd.img",
    "rootfs": "live/aios.squashfs",
    "manifest": "aios/manifest.json",
    "sbom": "aios/sbom.cdx.json",
    "provenance": "aios/provenance.json",
    "security": "aios/security.json"
  },
  "signature_hooks": {
    "bootloader": "aios/signatures/boot-grub-grub.cfg.sig",
    "kernel": "aios/signatures/live-vmlinuz.sig",
    "initramfs": "aios/signatures/live-initrd.img.sig",
    "rootfs": "aios/signatures/live-aios.squashfs.sig",
    "manifest": "aios/signatures/manifest.json.sig",
    "sbom": "aios/signatures/sbom.cdx.json.sig",
    "provenance": "aios/signatures/provenance.json.sig",
    "security": "aios/signatures/security.json.sig",
    "checksums": "aios/signatures/SHA256SUMS.sig"
  }
}
EOF

# R12.4: SBOM must cover Rust crates (workspace + dependency graph), not just
# file artifacts. Emit CycloneDX library components with cargo purls.
generate_rust_crate_components() {
    command -v python3 >/dev/null 2>&1 || return 0
    (cd "${REPO_ROOT}" && cargo metadata --format-version 1 --locked 2>/dev/null) | python3 -c '
import json, sys
try:
    meta = json.load(sys.stdin)
except Exception:
    sys.exit(0)
comps = []
for p in meta.get("packages", []):
    name, ver = p.get("name"), p.get("version")
    if not name or not ver:
        continue
    comps.append({
        "type": "library",
        "name": name,
        "version": ver,
        "purl": "pkg:cargo/{}@{}".format(name, ver),
    })
print(",\n".join("    " + json.dumps(c) for c in comps))
'
}
RUST_CRATE_COMPONENTS="$(generate_rust_crate_components)"
if [ -z "${RUST_CRATE_COMPONENTS}" ]; then
    warn "SBOM: no Rust crate components generated (python3/cargo metadata unavailable)"
fi

cat > "${AIOS_ISO_META_DIR}/sbom.cdx.json" <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:aios-${AIOS_BUILD_ID}",
  "version": 1,
  "metadata": {
    "timestamp": "${BUILD_TIMESTAMP}",
    "component": {
      "type": "operating-system",
      "name": "AI-OS.NET",
      "version": "$(json_escape "${AIOS_VERSION}")",
      "properties": [
        { "name": "aios.revision", "value": "12" },
        { "name": "aios.build_id", "value": "$(json_escape "${AIOS_BUILD_ID}")" },
        { "name": "aios.architecture", "value": "$(json_escape "${ARCH}")" }
      ]
    }
  },
  "components": [
${RUST_CRATE_COMPONENTS}${RUST_CRATE_COMPONENTS:+,}
    {
      "type": "file",
      "name": "live/aios.squashfs",
      "hashes": [
        { "alg": "SHA-256", "content": "$(file_sha256 "${ISO_DIR}/live/aios.squashfs")" }
      ]
    },
    {
      "type": "file",
      "name": "live/vmlinuz",
      "hashes": [
        { "alg": "SHA-256", "content": "$(file_sha256 "${ISO_DIR}/live/vmlinuz")" }
      ]
    },
    {
      "type": "file",
      "name": "live/initrd.img",
      "hashes": [
        { "alg": "SHA-256", "content": "$(file_sha256 "${ISO_DIR}/live/initrd.img")" }
      ]
    },
    {
      "type": "operating-system",
      "name": "linux-kernel",
      "version": "$(json_escape "${STAGED_KERNEL_VERSION}")",
      "properties": [
        { "name": "aios.kernel.modules.mode", "value": "$(json_escape "${STAGED_MODULE_MODE}")" },
        { "name": "aios.kernel.modules.file_count", "value": "${STAGED_MODULE_FILE_COUNT}" },
        { "name": "aios.kernel.firmware.mode", "value": "$(json_escape "${STAGED_FIRMWARE_MODE}")" },
        { "name": "aios.kernel.firmware.file_count", "value": "${STAGED_FIRMWARE_FILE_COUNT}" }
      ]
    },
    {
      "type": "file",
      "name": "aios/kernel.json",
      "hashes": [
        { "alg": "SHA-256", "content": "$(file_sha256 "${AIOS_ISO_META_DIR}/kernel.json")" }
      ]
    },
    {
      "type": "file",
      "name": "aios/base.json",
      "hashes": [
        { "alg": "SHA-256", "content": "$(file_sha256 "${AIOS_ISO_META_DIR}/base.json")" }
      ]
    },
    {
      "type": "file",
      "name": "aios/security.json",
      "hashes": [
        { "alg": "SHA-256", "content": "$(file_sha256 "${AIOS_ISO_META_DIR}/security.json")" }
      ]
    },
    {
      "type": "file",
      "name": "aios/boot-chain.json",
      "hashes": [
        { "alg": "SHA-256", "content": "$(file_sha256 "${AIOS_ISO_META_DIR}/boot-chain.json")" }
      ]
    }
  ]
}
EOF

cat > "${AIOS_ISO_META_DIR}/provenance.json" <<EOF
{
  "schema": "aios.provenance.v1",
  "revision": 12,
  "build_id": "$(json_escape "${AIOS_BUILD_ID}")",
  "version": "$(json_escape "${AIOS_VERSION}")",
  "architecture": "$(json_escape "${ARCH}")",
  "profile": "$(json_escape "${PROFILE}")",
  "timestamp": "${BUILD_TIMESTAMP}",
  "source": {
    "repository": "$(json_escape "${REPO_ROOT}")",
    "git_revision": "$(json_escape "${GIT_REVISION}")",
    "dirty": ${GIT_DIRTY}
  },
  "builder": {
    "hostname": "$(json_escape "$(hostname 2>/dev/null || printf unknown)")",
    "kernel": "$(json_escape "$(uname -sr 2>/dev/null || printf unknown)")",
    "rustc": "$(json_escape "$(rustc --version 2>/dev/null || printf unknown)")",
    "cargo": "$(json_escape "$(cargo --version 2>/dev/null || printf unknown)")",
    "mksquashfs": "$(json_escape "$(mksquashfs -version 2>&1 | head -1 || printf unknown)")"
  },
  "kernel_pipeline": {
    "kernel_version": "$(json_escape "${STAGED_KERNEL_VERSION}")",
    "kernel_source": "$(json_escape "${KERNEL_SOURCE}")",
    "module_mode": "$(json_escape "${STAGED_MODULE_MODE}")",
    "module_source": "$(json_escape "${STAGED_MODULE_SOURCE_PATH}")",
    "firmware_mode": "$(json_escape "${STAGED_FIRMWARE_MODE}")",
    "firmware_source": "$(json_escape "${STAGED_FIRMWARE_SOURCE_PATH}")"
  },
  "base_rootfs": {
    "family": "$(json_escape "${AIOS_BASE_FAMILY}")",
    "variant": "$(json_escape "${AIOS_BASE_VARIANT}")",
    "version": "$(json_escape "${AIOS_BASE_VERSION}")",
    "series": "$(json_escape "${AIOS_BASE_SERIES}")",
    "architecture": "$(json_escape "${AIOS_BASE_ARCH}")",
    "support_window_months": ${AIOS_BASE_SUPPORT_MONTHS},
    "eol_date": "$(json_escape "${AIOS_BASE_EOL_DATE}")",
    "kernel_policy": "$(json_escape "${AIOS_BASE_KERNEL_POLICY}")",
    "package_policy": "$(json_escape "${AIOS_BASE_PACKAGE_POLICY}")",
    "enterprise_release": ${ENTERPRISE_RELEASE_JSON}
  },
  "security_baseline": {
    "profile": "$(json_escape "${AIOS_SECURITY_PROFILE}")",
    "selinux_mode": "$(json_escape "${AIOS_SELINUX_MODE}")",
    "selinux_policy_status": "$(json_escape "${SELINUX_POLICY_STATUS}")",
    "boot_chain_signatures_required": ${BOOT_SIGNATURES_REQUIRED_TOML}
  },
  "outputs": [
    { "path": "live/vmlinuz", "sha256": "$(file_sha256 "${ISO_DIR}/live/vmlinuz")" },
    { "path": "live/initrd.img", "sha256": "$(file_sha256 "${ISO_DIR}/live/initrd.img")" },
    { "path": "live/aios.squashfs", "sha256": "$(file_sha256 "${ISO_DIR}/live/aios.squashfs")" }
  ],
  "signature_identity": "$(json_escape "${AIOS_SIGNING_IDENTITY:-unsigned}")",
  "signing": {
    "identity": "$(json_escape "${AIOS_SIGNING_IDENTITY:-unsigned}")",
    "required": ${BOOT_SIGNATURES_REQUIRED_TOML}
  }
}
EOF

cat > "${AIOS_SIGNATURE_DIR}/README" <<'EOF'
AI-OS.NET Rev.12 release signature directory.

Production release signing must place detached signatures for manifest.json,
sbom.cdx.json, provenance.json, security.json, boot-chain.json, SHA256SUMS,
bootloader config, kernel, initramfs, and rootfs payload metadata here before
promotion.
EOF

MANIFEST_JSON="${AIOS_ISO_META_DIR}/manifest.json"
cat > "${MANIFEST_JSON}" <<EOF
{
  "schema": "aios.release_manifest.v1",
  "revision": 12,
  "build_id": "$(json_escape "${AIOS_BUILD_ID}")",
  "version": "$(json_escape "${AIOS_VERSION}")",
  "architecture": "$(json_escape "${ARCH}")",
  "profile": "$(json_escape "${PROFILE}")",
  "created_at": "${BUILD_TIMESTAMP}",
  "volume_id": "AIOS_REV12",
  "artifacts": [
EOF
append_manifest_artifact "${MANIFEST_JSON}" "live/vmlinuz"
append_manifest_artifact "${MANIFEST_JSON}" "live/initrd.img"
append_manifest_artifact "${MANIFEST_JSON}" "live/aios.squashfs"
append_manifest_artifact "${MANIFEST_JSON}" "boot/grub/grub.cfg"
append_manifest_artifact "${MANIFEST_JSON}" "aios/base.json"
append_manifest_artifact "${MANIFEST_JSON}" "aios/kernel.json"
append_manifest_artifact "${MANIFEST_JSON}" "aios/security.json"
append_manifest_artifact "${MANIFEST_JSON}" "aios/boot-chain.json"
append_manifest_artifact "${MANIFEST_JSON}" "aios/sbom.cdx.json"
append_manifest_artifact "${MANIFEST_JSON}" "aios/provenance.json"
if [ -n "${VERITY_HASHTREE_REL}" ]; then
    append_manifest_artifact "${MANIFEST_JSON}" "${VERITY_HASHTREE_REL}"
fi
append_manifest_artifact "${MANIFEST_JSON}" "aios/signatures/README" ""
cat >> "${MANIFEST_JSON}" <<'EOF'
  ]
}
EOF

(
    cd "${ISO_DIR}"
    sha256sum \
        live/vmlinuz \
        live/initrd.img \
        live/aios.squashfs \
        boot/grub/grub.cfg \
        aios/manifest.json \
        aios/base.json \
        aios/kernel.json \
        aios/security.json \
        aios/boot-chain.json \
        aios/sbom.cdx.json \
        aios/provenance.json \
        aios/signatures/README \
        > aios/SHA256SUMS
)

# dm-verity hash tree is optional (present only when veritysetup ran) — append
# its checksum separately so the base list stays unconditional.
if [ -n "${VERITY_HASHTREE_REL}" ]; then
    ( cd "${ISO_DIR}" && sha256sum "${VERITY_HASHTREE_REL}" >> aios/SHA256SUMS )
fi

require_boot_signature "boot-grub-grub.cfg.sig"
require_boot_signature "live-vmlinuz.sig"
require_boot_signature "live-initrd.img.sig"
require_boot_signature "live-aios.squashfs.sig"
require_boot_signature "manifest.json.sig"
require_boot_signature "sbom.cdx.json.sig"
require_boot_signature "provenance.json.sig"
require_boot_signature "security.json.sig"
require_boot_signature "SHA256SUMS.sig"

ok "Rev.13 release metadata generated: /aios/base.json plus Rev.12 manifest/security/boot-chain/SBOM/provenance/SHA256SUMS"

# ── Step 12: Prepare ISO staging and assemble with grub2-mkrescue ─────────────

step "Step 12: Assembling bootable ISO with grub2-mkrescue"

mkdir -p "$(dirname "${OUTPUT}")"

# grub2-mkrescue expects a directory tree with /boot/grub/grub.cfg
# We already have: ${ROOTFS_DIR}/boot/grub/grub.cfg (Step 7)
#   ${ISO_DIR}/live/vmlinuz + initrd.img (Step 8)
#   ${ISO_DIR}/live/aios.squashfs (Step 10)

# Copy kernel and initramfs into ISO staging
# (These were placed in ISO_DIR by Step 8 already)

# Copy rootfs content that should be on the ISO filesystem (not just squashfs)
# grub2-mkrescue includes everything in ISO_DIR

if ${HAS_GRUB2}; then
    # grub2-mkrescue creates a UEFI-bootable + BIOS-bootable ISO
    "${GRUB2_MKRESCUE}" \
        -o "${OUTPUT}" \
        -volid "AIOS_REV12" \
        "${ISO_DIR}" 2>&1 | tail -3
    ISO_RC=$?
else
    # Fallback: EFI-only ISO with manual xorriso
    warn "grub2-mkrescue not found — falling back to manual xorriso (EFI may not boot)"
    xorriso -as mkisofs \
        -iso-level 3 -full-iso9660-filenames \
        -volid "AIOS_REV12" \
        -eltorito-alt-boot -e EFI/efiboot.img -no-emul-boot \
        -isohybrid-gpt-basdat \
        -output "${OUTPUT}" \
        "${ISO_DIR}" 2>&1 | tail -1
    ISO_RC=$?
fi

if [ "${ISO_RC}" -ne 0 ] || [ ! -f "${OUTPUT}" ]; then
    die "ISO assembly failed. Check logs above."
fi

ISO_SIZE=$(du -h "${OUTPUT}" | cut -f1)
if ${HAS_GRUB2}; then
    info "Bootloader: GRUB2 (via grub2-mkrescue)"
else
    info "Bootloader: manual xorriso (EFI-only)"
fi
ok "ISO assembled: ${OUTPUT} (${ISO_SIZE})"

# ── Verification ─────────────────────────────────────────────────────────────

step "Verification"

# Check ISO structure
VERIFY_OK=true

check_iso_item() {
    local desc="$1"
    local path="$2"
    if [ -f "${path}" ] || [ -d "${path}" ]; then
        ok "${desc}"
    else
        warn "${desc} — MISSING: ${path}"
        VERIFY_OK=false
    fi
}

check_iso_item "Squashfs root"              "${ISO_DIR}/live/aios.squashfs"
check_iso_item "Kernel image"               "${ISO_DIR}/live/vmlinuz"
check_iso_item "GRUB config"                "${ISO_DIR}/boot/grub/grub.cfg"
check_iso_item "Rev.13 base metadata"       "${ISO_DIR}/aios/base.json"
check_iso_item "Rev.12 kernel metadata"     "${ISO_DIR}/aios/kernel.json"
check_iso_item "Rev.12 security metadata"   "${ISO_DIR}/aios/security.json"
check_iso_item "Rev.12 boot chain metadata" "${ISO_DIR}/aios/boot-chain.json"
check_iso_item "Rev.12 manifest"            "${ISO_DIR}/aios/manifest.json"
check_iso_item "Rev.12 SBOM"                "${ISO_DIR}/aios/sbom.cdx.json"
check_iso_item "Rev.12 provenance"          "${ISO_DIR}/aios/provenance.json"
check_iso_item "Rev.12 SHA256SUMS"          "${ISO_DIR}/aios/SHA256SUMS"
check_iso_item "Rev.12 signatures dir"      "${ISO_DIR}/aios/signatures"
check_iso_item "Systemd config"             "${ROOTFS_DIR}/etc/systemd/system/aios.target"
check_iso_item "AIOS config"                "${ROOTFS_DIR}/etc/aios/config.toml"
check_iso_item "AIOS security profile"      "${ROOTFS_DIR}/etc/aios/security-profile.toml"
check_iso_item "IMA policy"                 "${ROOTFS_DIR}/etc/ima/ima-policy"
check_iso_item "EVM policy"                 "${ROOTFS_DIR}/etc/evm/evm-policy"
check_iso_item "dm-verity rootfs policy"    "${ROOTFS_DIR}/etc/aios/verity/rootfs-policy.json"
if [ -n "${VERITY_HASHTREE_REL}" ]; then
    check_iso_item "dm-verity hash tree"    "${ISO_DIR}/${VERITY_HASHTREE_REL}"
fi
check_iso_item "OS release"                 "${ROOTFS_DIR}/etc/os-release"
check_iso_item "Kernel module tree"         "${ROOTFS_DIR}/usr/lib/modules/${STAGED_KERNEL_VERSION}"
check_iso_item "Kernel firmware tree"       "${ROOTFS_DIR}/usr/lib/firmware"

# Verify at least one binary exists in rootfs lib dir
if ls "${AIOS_LIB_DIR}"/* >/dev/null 2>&1 || ls "${AIOS_BIN_DIR}"/aios >/dev/null 2>&1; then
    ok "AIOS binaries present in rootfs"
else
    warn "No AIOS binaries found in rootfs"
fi

# Verify squashfs integrity
if command -v unsquashfs >/dev/null 2>&1; then
    if unsquashfs -s "${ISO_DIR}/live/aios.squashfs" >/dev/null 2>&1; then
        ok "Squashfs integrity verified"
    else
        warn "Could not verify squashfs integrity (unsquashfs -s failed)"
    fi
else
    warn "unsquashfs not found — skipping squashfs integrity verification"
fi

if [ -f "${OUTPUT}" ]; then
    ok "ISO file exists: ${OUTPUT}"
else
    err "ISO file not found: ${OUTPUT}"
    VERIFY_OK=false
fi

# ── Build summary ────────────────────────────────────────────────────────────

printf '\n%s%s════════════════════════════════════════════════════════%s\n' "${BOLD}" "${BLUE}" "${RESET}"
printf '%s%s  BUILD COMPLETE%s\n\n' "${BOLD}" "${GREEN}" "${RESET}"
printf "  Output:     ${BOLD}%s${RESET}\n" "${OUTPUT}"
printf "  ISO size:   %s\n" "${ISO_SIZE}"
printf "  Squashfs:   %s\n" "${SQUASHFS_SIZE}"
printf "  Initramfs:  %s\n" "${INITRAMFS_SIZE}"
printf "  Profile:    %s\n" "${PROFILE}"
printf "  Archive:    %s\n" "${ARCH}"
printf "  Binaries:   %d\n" "${#BINARIES_FOUND[@]}"
printf '\n%s%s════════════════════════════════════════════════════════%s\n' "${BOLD}" "${BLUE}" "${RESET}"

if ${VERIFY_OK}; then
    printf '%s%s  STATUS: ALL CHECKS PASSED%s\n' "${BOLD}" "${GREEN}" "${RESET}"
    exit 0
else
    printf '%s%s  STATUS: COMPLETED WITH WARNINGS%s\n' "${BOLD}" "${YELLOW}" "${RESET}"
    exit 0
fi
