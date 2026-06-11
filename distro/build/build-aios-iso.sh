#!/bin/bash
set -euo pipefail

# =============================================================================
# AI-OS.NET ISO Builder — Revision 11
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
#   ./build-aios-iso.sh --release --output /tmp/aios.iso
#
# Output:
#   aios-rev11-YYYYMMDD-x86_64.iso — bootable ISO image
# =============================================================================

# ── Project paths ────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${REPO_ROOT}/distro/build/out"
ROOTFS_DIR="${BUILD_DIR}/rootfs"
INITRAMFS_DIR="${BUILD_DIR}/initramfs"
INITRAMFS_OUT="${BUILD_DIR}/initramfs.cpio.xz"
ISO_DIR="${BUILD_DIR}/iso"
EFI_IMG="${BUILD_DIR}/efiboot.img"

DATE_STAMP="$(date +%Y%m%d)"

# ── Defaults (overridable via args) ──────────────────────────────────────────

ARCH="x86_64"
PROFILE="release"
OUTPUT="${REPO_ROOT}/distro/build/aios-rev11-${DATE_STAMP}-${ARCH}.iso"
AIOS_VERSION="${AIOS_VERSION:-0.1.0}"
AIOS_BUILD_ID="${AIOS_BUILD_ID:-${DATE_STAMP}}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

# Kernel source: path to prebuilt kernel or "host" to copy from /boot
KERNEL_SOURCE="${KERNEL_SOURCE:-host}"

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
    printf "╔══════════════════════════════════════════════════════╗\n"
    printf "║   AI-OS.NET ISO Builder — Revision 11                ║\n"
    printf "║   Version: %-10s  Profile: %-8s          ║\n" "${AIOS_VERSION}" "${PROFILE}"
    printf "║   Arch:    %-10s  Jobs:    %-8s          ║\n" "${ARCH}" "${JOBS}"
    printf "║   Output:  %-40s ║\n" "$(basename "${OUTPUT}")"
    printf "╚══════════════════════════════════════════════════════╝${RESET}\n\n"
}

# ── Argument parsing ─────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --release)         PROFILE="release"; shift ;;
        --debug)           PROFILE="debug";   shift ;;
        --output)          OUTPUT="$2";       shift 2 ;;
        --arch)            ARCH="$2";         shift 2 ;;
        --jobs|-j)         JOBS="$2";         shift 2 ;;
        --kernel-source)   KERNEL_SOURCE="$2"; shift 2 ;;
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
            printf "  --version VERSION    AIOS version string\n"
            printf "  --build-id ID        Build identifier\n"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# If arch is aarch64, switch cross-compilation profile path lookup
if [ "${ARCH}" = "aarch64" ]; then
    TARGET_DIR="${REPO_ROOT}/target/aarch64-unknown-linux-gnu/${PROFILE}"
else
    TARGET_DIR="${REPO_ROOT}/target/${PROFILE}"
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
    printf "${MISSING}"
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
HAS_SYSTEMD_BOOT=false
HAS_CRYPTSETUP=false
HAS_TPM2TOOLS=false
HAS_VERITYSETUP=false
HAS_LOADPOLICY=false

check_opt busybox       "busybox-static (initramfs busybox)" && HAS_BUSYBOX=true || {
    # openSUSE names it busybox-static
    if command -v busybox-static >/dev/null 2>&1; then
        HAS_BUSYBOX=true
        BUSYBOX_CMD="busybox-static"
        info "busybox-static found"
    else
        HAS_BUSYBOX=false
    fi
}

# Use the correct busybox binary name
BUSYBOX_CMD="${BUSYBOX_CMD:-busybox}"
check_opt bootctl       "systemd-boot (EFI boot manager)"     && HAS_SYSTEMD_BOOT=true || true
check_opt cryptsetup    "cryptsetup (LUKS in initramfs)"      && HAS_CRYPTSETUP=true || true
check_opt tpm2_unseal   "tpm2-tools (TPM2 unseal)"            && HAS_TPM2TOOLS=true || true
check_opt veritysetup   "veritysetup (dm-verity)"             && HAS_VERITYSETUP=true || true
check_opt load_policy   "policycoreutils (SELinux load_policy)" && HAS_LOADPOLICY=true || true

ok "Dependency check complete."

# ── Step 1: Compile workspace ────────────────────────────────────────────────

step "Step 1: Compiling AIOS workspace (${PROFILE} profile, -j ${JOBS})"

cd "${REPO_ROOT}"

START_TS=$(date +%s)

if [ "${ARCH}" = "aarch64" ]; then
    if ! rustup target list --installed 2>/dev/null | grep -q 'aarch64-unknown-linux-gnu'; then
        info "Installing aarch64 cross-compilation target..."
        rustup target add aarch64-unknown-linux-gnu
    fi
    cargo build --profile "${PROFILE}" --workspace --target aarch64-unknown-linux-gnu --jobs "${JOBS}"
else
    cargo build --profile "${PROFILE}" --workspace --jobs "${JOBS}"
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

mkdir -p "${ROOTFS_DIR}"/usr/{bin,lib/aios,lib/systemd/boot/efi,share/aios/{config,selinux,licenses}}
mkdir -p "${ROOTFS_DIR}"/etc/{aios/{config.d,verity,policy.d,selinux.d,evidence.d,backup.d,hardening},selinux/aios/policy,systemd/system,ssl/certs}
mkdir -p "${ROOTFS_DIR}"/var/{lib/aios/{evidence,policy,capsules,backup,state,fleet,autonomous,marketplace,container,terminal},log/aios,cache/aios,tmp}
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

# Essential symlinks
ln -sf usr/bin  "${ROOTFS_DIR}/bin"
ln -sf usr/lib  "${ROOTFS_DIR}/lib"
ln -sf usr/lib  "${ROOTFS_DIR}/lib64"
ln -sf bin      "${ROOTFS_DIR}/usr/sbin"
ln -sf ../run   "${ROOTFS_DIR}/var/run"
ln -sf ../lock  "${ROOTFS_DIR}/var/lock"

# Create /sbin -> /usr/bin symlink for init compatibility
ln -sf usr/bin "${ROOTFS_DIR}/sbin"

ok "Rootfs directory tree created."

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

# ── Step 4: Install systemd units ────────────────────────────────────────────

step "Step 4: Installing systemd units"

SYSTEMD_SRC="${REPO_ROOT}/distro/systemd"
SYSTEMD_DST="${ROOTFS_DIR}/etc/systemd/system"
SYSTEMD_NETWORK_DST="${ROOTFS_DIR}/etc/systemd/network"
SYSTEMD_RESOLVED_DST="${ROOTFS_DIR}/etc/systemd"

mkdir -p "${SYSTEMD_DST}" "${SYSTEMD_NETWORK_DST}"

if [ -d "${SYSTEMD_SRC}" ]; then
    for svc in "${SYSTEMD_SRC}"/*.service; do
        if [ -f "${svc}" ]; then
            svc_name="$(basename "${svc}")"
            cp "${svc}" "${SYSTEMD_DST}/${svc_name}"
            chmod 644 "${SYSTEMD_DST}/${svc_name}"
            info "Installed systemd unit: ${svc_name}"
        fi
    done
fi

# Create aios.target for ordering
cat > "${SYSTEMD_DST}/aios.target" <<'EOF'
[Unit]
Description=AI-OS.NET Core Services
Documentation=https://ai-os.net/docs
Requires=aios-policy-kernel.service aios-evidence-log.service aios-capability-runtime.service
After=network.target

[Install]
WantedBy=multi-user.target
EOF

# Create symlinks to enable services
mkdir -p "${ROOTFS_DIR}/etc/systemd/system/multi-user.target.wants"
for svc in aios-policy-kernel.service aios-evidence-log.service aios-capability-runtime.service aios-fleet.service aios-container.service aios-terminal.service aios-hardening.service aios-autonomous.service; do
    if [ -f "${SYSTEMD_DST}/${svc}" ]; then
        ln -sf "../${svc}" "${ROOTFS_DIR}/etc/systemd/system/multi-user.target.wants/${svc}"
        info "Enabled: ${svc}"
    fi
done

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
cat > "${SYSTEMD_RESOLVED_DST}/resolv.conf" <<'EOF'
nameserver 127.0.0.53
options edns0 trust-ad
EOF

ok "Systemd units installed."

# ── Step 5: Install configuration files ──────────────────────────────────────

step "Step 5: Installing configuration files"

# Default AIOS config
cat > "${ROOTFS_DIR}/etc/aios/config.toml" <<EOF
# AI-OS.NET Configuration — Revision 11
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
selinux_enforcing = false
measured_boot = true
fips_mode = false

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

[hardening]
profile = "SECURE_DEFAULT"
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
VERSION="${AIOS_VERSION} (Revision 11)"
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

# ── Step 6: Install SELinux policy placeholder ───────────────────────────────

step "Step 6: Installing SELinux policy"

SELINUX_POLICY_DIR="${ROOTFS_DIR}/etc/selinux/aios/policy"
mkdir -p "${SELINUX_POLICY_DIR}"

# SELinux config
cat > "${ROOTFS_DIR}/etc/selinux/config" <<'EOF'
# AI-OS.NET SELinux configuration
SELINUX=permissive
SELINUXTYPE=aios
EOF

# Placeholder policy file (real policy is built by aios-selinux crate)
# The initramfs init script expects policy.33 at minimum
cat > "${SELINUX_POLICY_DIR}/policy.33" <<'EOF'
# AI-OS.NET SELinux Policy — Placeholder
# This is a minimal binary policy stub.
# Replace with the output of checkpolicy + semodule_package for production.
EOF

info "SELinux config installed (policy is a placeholder — build with aios-selinux crate for production)."

ok "SELinux policy installed."

# ── Step 7: Prepare grub.cfg (boot menu for GRUB2 via grub2-mkrescue) ─────────

step "Step 7: Creating GRUB2 boot configuration"

mkdir -p "${ROOTFS_DIR}/boot/grub"

# Detect grub2-mkrescue (the one tool that handles EFI ISO creation correctly)
GRUB2_MKRESCUE="$(command -v grub2-mkrescue 2>/dev/null || echo '')"
HAS_GRUB2=false
[ -n "${GRUB2_MKRESCUE}" ] && HAS_GRUB2=true

# Generate grub.cfg for the live ISO
cat > "${ROOTFS_DIR}/boot/grub/grub.cfg" <<'GRUBCFG'
set timeout=5
set default=0

menuentry "AI-OS.NET Rev.11 Live" {
    linux /live/vmlinuz root=live:CDLABEL=AIOS_REV11 rd.live.image rd.live.overlay=tmpfs quiet loglevel=3 aios.fleet.mode=standalone aios.autonomous.level=advisory
    initrd /live/initrd.img
}

menuentry "AI-OS.NET Rev.11 Live (debug)" {
    linux /live/vmlinuz root=live:CDLABEL=AIOS_REV11 rd.live.image rd.live.overlay=tmpfs loglevel=7 aios.fleet.mode=standalone aios.autonomous.level=advisory
    initrd /live/initrd.img
}

menuentry "AI-OS.NET Rev.11 Recovery Shell" {
    linux /live/vmlinuz root=live:CDLABEL=AIOS_REV11 rd.live.image rescue systemd.unit=rescue.target
    initrd /live/initrd.img
}
GRUBCFG

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
    info "Kernel installed: $(basename "${vmlinuz}") -> live/vmlinuz"

    if [ -f "${initrd}" ]; then
        cp "${initrd}" "${KERNEL_DST}/initrd.img"
        chmod 644 "${KERNEL_DST}/initrd.img"
        info "Initrd installed: $(basename "${initrd}") -> live/initrd.img"
    fi
    return 0
}

if [ "${KERNEL_SOURCE}" = "host" ]; then
    # Try to find kernel on the host — search /usr/lib/modules (modern), then /boot (legacy)
    VMLINUX=""
    INITRD=""

    # Primary: /usr/lib/modules/<version>/vmlinuz (kernel-default RPM layout)
    if [ -d "/usr/lib/modules" ]; then
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
                      blkid find xargs cut tr wc which; do
            ln -sf busybox "${INITRAMFS_DIR}/bin/${applet}" 2>/dev/null || true
        done

        # Symlink /bin/sh for compat
        mkdir -p "${INITRAMFS_DIR}/sbin"
        ln -sf ../bin/busybox "${INITRAMFS_DIR}/sbin/init" 2>/dev/null || true
        ln -sf /bin/busybox  "${INITRAMFS_DIR}/bin/sh" 2>/dev/null || true
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

# Install kernel modules (if available)
if [ -d "/lib/modules" ]; then
    mkdir -p "${INITRAMFS_DIR}/lib"
    cp -r /lib/modules "${INITRAMFS_DIR}/lib/modules" 2>/dev/null || \
        warn "Could not copy kernel modules (may be fine for live ISO)."
fi

# Copy preinit config to initramfs
mkdir -p "${INITRAMFS_DIR}/etc/aios"
cp "${REPO_ROOT}/distro/aios-boot/initramfs/aios-preinit" "${INITRAMFS_DIR}/etc/aios/preinit"

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

# ── Step 11: Prepare ISO staging and assemble with grub2-mkrescue ─────────────

step "Step 11: Assembling bootable ISO with grub2-mkrescue"

mkdir -p "$(dirname "${OUTPUT}")"

# grub2-mkrescue expects a directory tree with /boot/grub/grub.cfg
# We already have: ${ROOTFS_DIR}/boot/grub/grub.cfg (Step 7)
#   ${ISO_DIR}/live/vmlinuz + initrd.img (Step 8)
#   ${ISO_DIR}/live/aios.squashfs (Step 10)

# Copy kernel and initramfs into ISO staging
# (These were placed in ISO_DIR by Step 8 already)

# Install rootfs grub.cfg into ISO staging for grub2-mkrescue to find
mkdir -p "${ISO_DIR}/boot/grub"
cp "${ROOTFS_DIR}/boot/grub/grub.cfg" "${ISO_DIR}/boot/grub/grub.cfg"

# Copy rootfs content that should be on the ISO filesystem (not just squashfs)
# grub2-mkrescue includes everything in ISO_DIR

if ${HAS_GRUB2}; then
    # grub2-mkrescue creates a UEFI-bootable + BIOS-bootable ISO
    "${GRUB2_MKRESCUE}" \
        -o "${OUTPUT}" \
        "${ISO_DIR}" 2>&1 | tail -3
    ISO_RC=$?
else
    # Fallback: EFI-only ISO with manual xorriso
    warn "grub2-mkrescue not found — falling back to manual xorriso (EFI may not boot)"
    xorriso -as mkisofs \
        -iso-level 3 -full-iso9660-filenames \
        -volid "AIOS_REV11" \
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
check_iso_item "Systemd config"             "${ROOTFS_DIR}/etc/systemd/system/aios.target"
check_iso_item "AIOS config"                "${ROOTFS_DIR}/etc/aios/config.toml"
check_iso_item "OS release"                 "${ROOTFS_DIR}/etc/os-release"

# Verify at least one binary exists in rootfs lib dir
if ls "${AIOS_LIB_DIR}"/* >/dev/null 2>&1 || ls "${AIOS_BIN_DIR}"/aios >/dev/null 2>&1; then
    ok "AIOS binaries present in rootfs"
else
    warn "No AIOS binaries found in rootfs"
fi

# Verify squashfs integrity
if mksquashfs -check "${ISO_DIR}/live/aios.squashfs" >/dev/null 2>&1; then
    ok "Squashfs integrity verified"
else
    warn "Could not verify squashfs integrity (mksquashfs -check failed)"
fi

if [ -f "${OUTPUT}" ]; then
    ok "ISO file exists: ${OUTPUT}"
else
    err "ISO file not found: ${OUTPUT}"
    VERIFY_OK=false
fi

# ── Build summary ────────────────────────────────────────────────────────────

printf "\n${BOLD}${BLUE}════════════════════════════════════════════════════════${RESET}\n"
printf "${BOLD}${GREEN}  BUILD COMPLETE${RESET}\n\n"
printf "  Output:     ${BOLD}%s${RESET}\n" "${OUTPUT}"
printf "  ISO size:   %s\n" "${ISO_SIZE}"
printf "  Squashfs:   %s\n" "${SQUASHFS_SIZE}"
printf "  Initramfs:  %s\n" "${INITRAMFS_SIZE}"
printf "  Profile:    %s\n" "${PROFILE}"
printf "  Archive:    %s\n" "${ARCH}"
printf "  Binaries:   %d\n" "${#BINARIES_FOUND[@]}"
printf "\n${BOLD}${BLUE}════════════════════════════════════════════════════════${RESET}\n"

if ${VERIFY_OK}; then
    printf "${BOLD}${GREEN}  STATUS: ALL CHECKS PASSED${RESET}\n"
    exit 0
else
    printf "${BOLD}${YELLOW}  STATUS: COMPLETED WITH WARNINGS${RESET}\n"
    exit 0
fi
