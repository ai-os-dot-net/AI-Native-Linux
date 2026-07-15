#!/bin/bash
set -euo pipefail

# =============================================================================
# AI-OS.NET Build Dependency Checker — Revision 4
# =============================================================================
# Verifies that all required and optional tools are available for building
# the AIOS bootable ISO.
#
# Usage:
#   ./build-deps-check.sh [--verbose] [--json]
#
# Exit codes:
#   0 — all required deps present
#   1 — one or more required deps missing
#   2 — required deps present, but some optional deps missing
# =============================================================================

VERBOSE=false
JSON_OUT=false

while [ $# -gt 0 ]; do
    case "$1" in
        --verbose|-v) VERBOSE=true; shift ;;
        --json)       JSON_OUT=true; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ── Color output ─────────────────────────────────────────────────────────────

if [ -t 1 ] && ! ${JSON_OUT}; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi

# ── Dependency registry ──────────────────────────────────────────────────────
# Format: "command|package|category|required|description"
# category: toolchain, filesystem, boot, security, optional

DEPENDENCIES=(
    # ── Required: Toolchain ──────────────────────────────────────────────
    "cargo|rustup|toolchain|true|Rust package manager and build system"
    "rustc|rustup|toolchain|true|Rust compiler (>= 1.94)"
    "strip|binutils|toolchain|true|Binary stripper (ELF)"

    # ── Required: Filesystem / Image Tools ───────────────────────────────
    "mksquashfs|squashfs-tools|filesystem|true|SquashFS image builder"
    "unsquashfs|squashfs-tools|filesystem|true|SquashFS image extractor (for verification)"
    "xorriso|xorriso|filesystem|true|ISO 9660 + EFI boot image assembler"
    "cpio|cpio|filesystem|true|Archive tool (initramfs creation)"
    "xz|xz-utils|filesystem|true|LZMA2 compressor (initramfs, squashfs)"

    # ── Required: EFI Boot ───────────────────────────────────────────────
    "mkfs.vfat|dosfstools|boot|true|FAT filesystem formatter (EFI system partition)"
    "mmd|mtools|boot|true|FAT directory creator (mtools)"
    "mcopy|mtools|boot|true|FAT file copier (mtools)"
    "dd|coreutils|boot|true|Block device / image writer"

    # ── Required: Build Infrastructure ───────────────────────────────────
    "bash|bash|shell|true|Bash shell (>= 5.0)"
    "find|findutils|shell|true|File search utility"
    "grep|grep|shell|true|Pattern search utility"
    "sed|sed|shell|true|Stream editor"
    "nproc|coreutils|shell|true|CPU count utility (or pass --jobs)"

    # ── Optional: Boot Components ────────────────────────────────────────
    #
    # These stay OPTIONAL on purpose: this script checks the BUILD HOST, and the
    # ISO build never consumes the loader from it (build-aios-iso.sh only does a
    # `check_opt bootctl ... || true`). The machine that genuinely needs the
    # loader payload is the INSTALLED system, so the binding requirement lives in
    # the rootfs package set (`systemd-boot` in build-opensuse-rootfs.sh), not
    # here. Do not "harden" this into required=true: it would fail hosts that
    # build correctly while still not catching the real defect.
    #
    # This distinction is not academic. Defect #12a shipped precisely because
    # `bootctl` (from the systemd package) was present and the separate
    # systemd-boot payload was not, so `bootctl install` produced an ESP with
    # zero .efi files and reported success. What actually guards it now:
    #   - build-opensuse-rootfs.sh ships the systemd-boot package
    #   - test-rev13-opensuse-base.sh fails if that package is dropped
    #   - aios-quick-install.sh do_bootloader dies if the payload is missing
    "busybox|busybox-static|boot|false|Multi-call binary for initramfs /bin/sh"
    "bootctl|systemd-boot|boot|false|systemd-boot EFI boot manager"
    "systemd-bootx64.efi|systemd-boot|boot|false|systemd-boot EFI stub (x86_64) — required in the ROOTFS, not on the build host"
    "systemd-bootaa64.efi|systemd-boot|boot|false|systemd-boot EFI stub (aarch64) — required in the ROOTFS, not on the build host"

    # ── Optional: Security ───────────────────────────────────────────────
    "cryptsetup|cryptsetup|security|false|LUKS disk encryption (initramfs)"
    "veritysetup|veritysetup|security|false|dm-verity root hash verification"
    "tpm2_unseal|tpm2-tools|security|false|TPM 2.0 unseal utility"
    "load_policy|policycoreutils|security|false|SELinux policy loader"
    "checkpolicy|checkpolicy|security|false|SELinux policy compiler"

    # ── Optional: Developers ─────────────────────────────────────────────
    "rustup|rustup|dev|false|Rust toolchain manager"
    "cargo-audit|cargo-audit|dev|false|Rust dependency vulnerability scanner"
    "clippy|clippy|dev|false|Rust linter"
    "rustfmt|rustfmt|dev|false|Rust formatter"

    # ── Optional: Cross-compilation ──────────────────────────────────────
    "gcc-aarch64-linux-gnu|aarch64-linux-gnu-gcc|cross|false|AArch64 cross-compiler"
    "qemu-aarch64-static|qemu-user-static|cross|false|AArch64 user-mode emulator"
)

# ── Check functions ──────────────────────────────────────────────────────────

declare -A DEP_STATUS
REQUIRED_MISSING=0
OPTIONAL_MISSING=0
REQUIRED_TOTAL=0
OPTIONAL_TOTAL=0
ALL_FOUND=()

check_dep() {
    local cmd="$1"
    local pkg="$2"
    local cat="$3"
    local required="$4"
    local desc="$5"

    local found=false
    local version=""
    local path=""

    # Special: EFI stubs are files, not commands
    case "${cmd}" in
        *.efi)
            if [ -f "/usr/lib/systemd/boot/efi/${cmd}" ]; then
                found=true
                path="/usr/lib/systemd/boot/efi/${cmd}"
            fi
            ;;
        *)
            if command -v "${cmd}" >/dev/null 2>&1; then
                found=true
                path="$(command -v "${cmd}")"
                version="$(${cmd} --version 2>&1 | head -1 || true)"
            fi
            ;;
    esac

    DEP_STATUS["${cmd}"]="${found}"
    DEP_STATUS["${cmd}_path"]="${path}"
    DEP_STATUS["${cmd}_version"]="${version}"
    DEP_STATUS["${cmd}_pkg"]="${pkg}"
    DEP_STATUS["${cmd}_cat"]="${cat}"
    DEP_STATUS["${cmd}_required"]="${required}"
    DEP_STATUS["${cmd}_desc"]="${desc}"

    if ${found}; then
        ALL_FOUND+=("${cmd}")
        if [ "${required}" = "true" ]; then
            REQUIRED_TOTAL=$((REQUIRED_TOTAL + 1))
        else
            OPTIONAL_TOTAL=$((OPTIONAL_TOTAL + 1))
        fi
    else
        if [ "${required}" = "true" ]; then
            REQUIRED_MISSING=$((REQUIRED_MISSING + 1))
        else
            OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
        fi
    fi
}

# ── Execute checks ───────────────────────────────────────────────────────────

for dep in "${DEPENDENCIES[@]}"; do
    IFS='|' read -r cmd pkg cat required desc <<< "${dep}"
    check_dep "${cmd}" "${pkg}" "${cat}" "${required}" "${desc}"
done

# ── Output ───────────────────────────────────────────────────────────────────

if ${JSON_OUT}; then
    # JSON output for programmatic consumption
    printf '{\n'
    printf '  "status": "%s",\n' "$([ ${REQUIRED_MISSING} -eq 0 ] && echo "ok" || echo "fail")"
    printf '  "required_missing": %d,\n' "${REQUIRED_MISSING}"
    printf '  "optional_missing": %d,\n' "${OPTIONAL_MISSING}"
    printf '  "dependencies": {\n'
    first=true
    for dep in "${DEPENDENCIES[@]}"; do
        IFS='|' read -r cmd pkg cat required desc <<< "${dep}"
        ${first} && first=false || printf ',\n'
        printf '    "%s": {\n' "${cmd}"
        printf '      "found": %s,\n' "${DEP_STATUS[${cmd}]}"
        printf '      "path": "%s",\n' "${DEP_STATUS[${cmd}_path]}"
        printf '      "required": %s,\n' "${required}"
        printf '      "package": "%s",\n' "${pkg}"
        printf '      "category": "%s",\n' "${cat}"
        printf '      "description": "%s"' "${desc}"
        printf '\n    }'
    done
    printf '\n  }\n}\n'
else
    # Human-readable output
    printf "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${RESET}\n"
    printf "${BOLD}${BLUE}║   AI-OS.NET Build Dependency Checker — Revision 4         ║${RESET}\n"
    printf "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${RESET}\n\n"

    # Rust version check
    if command -v rustc >/dev/null 2>&1; then
        RUST_VER="$(rustc --version | cut -d' ' -f2)"
        MIN_RUST="1.94"
        printf "  Rust: ${GREEN}${RUST_VER}${RESET}"
        if printf '%s\n%s\n' "${MIN_RUST}" "${RUST_VER}" | sort -V -C 2>/dev/null; then
            printf " (>= ${MIN_RUST} ${GREEN}✓${RESET})\n"
        else
            printf " ${RED}(< ${MIN_RUST} — UPGRADE REQUIRED)${RESET}\n"
        fi
    fi

    # Required dependencies
    printf "\n${BOLD}Required Dependencies:${RESET}\n"
    for dep in "${DEPENDENCIES[@]}"; do
        IFS='|' read -r cmd pkg cat required desc <<< "${dep}"
        if [ "${required}" != "true" ]; then continue; fi
        if ${DEP_STATUS["${cmd}"]}; then
            printf "  ${GREEN}✓${RESET} %-20s %s\n" "${cmd}" "(${pkg})"
            if ${VERBOSE}; then
                printf "         path: %s\n" "${DEP_STATUS[${cmd}_path]}"
                [ -n "${DEP_STATUS[${cmd}_version]}" ] && printf "         ver:  %s\n" "${DEP_STATUS[${cmd}_version]}"
            fi
        else
            printf "  ${RED}✗${RESET} %-20s ${RED}MISSING${RESET}  install: ${pkg}\n" "${cmd}"
        fi
    done

    # Optional dependencies
    printf "\n${BOLD}Optional Dependencies:${RESET}\n"
    for dep in "${DEPENDENCIES[@]}"; do
        IFS='|' read -r cmd pkg cat required desc <<< "${dep}"
        if [ "${required}" = "true" ]; then continue; fi
        if ${DEP_STATUS["${cmd}"]}; then
            printf "  ${GREEN}✓${RESET} %-20s %s\n" "${cmd}" "${desc}"
            if ${VERBOSE}; then
                printf "         path: %s\n" "${DEP_STATUS[${cmd}_path]}"
                [ -n "${DEP_STATUS[${cmd}_version]}" ] && printf "         ver:  %s\n" "${DEP_STATUS[${cmd}_version]}"
            fi
        else
            printf "  ${YELLOW}○${RESET} %-20s ${YELLOW}optional${RESET}  install: ${pkg}\n" "${cmd}"
        fi
    done

    # Summary
    printf "\n${BOLD}${BLUE}────────────────────────────────────────────────────────${RESET}\n"
    printf "  Required:  ${GREEN}%d found${RESET}" "$((REQUIRED_TOTAL))"
    if [ ${REQUIRED_MISSING} -gt 0 ]; then
        printf ", ${RED}%d missing${RESET}" "${REQUIRED_MISSING}"
    fi
    printf "\n"
    printf "  Optional:  %d found" "$((OPTIONAL_TOTAL))"
    if [ ${OPTIONAL_MISSING} -gt 0 ]; then
        printf ", ${YELLOW}%d missing${RESET}" "${OPTIONAL_MISSING}"
    fi
    printf "\n"

    # Section summary by category
    if ${VERBOSE}; then
        printf "\n${BOLD}By Category:${RESET}\n"
        declare -A CAT_MISSING
        for dep in "${DEPENDENCIES[@]}"; do
            IFS='|' read -r cmd pkg cat required desc <<< "${dep}"
            if ! ${DEP_STATUS["${cmd}"]}; then
                CAT_MISSING["${cat}"]="${CAT_MISSING[${cat}]} ${cmd}"
            fi
        done
        for cat in toolchain filesystem boot security dev cross shell; do
            if [ -n "${CAT_MISSING[${cat}]:-}" ]; then
                printf "  ${cat}: install packages for —${CAT_MISSING[${cat}]}\n"
            fi
        done
    fi

    # Final status
    printf "\n"
    if [ ${REQUIRED_MISSING} -eq 0 ]; then
        if [ ${OPTIONAL_MISSING} -eq 0 ]; then
            printf "${BOLD}${GREEN}STATUS: ALL DEPENDENCIES SATISFIED${RESET}\n"
        else
            printf "${BOLD}${GREEN}STATUS: READY (${OPTIONAL_MISSING} optional tools missing)${RESET}\n"
        fi
    else
        printf "${BOLD}${RED}STATUS: ${REQUIRED_MISSING} REQUIRED DEPENDENCIES MISSING${RESET}\n"
        printf "\nInstall missing packages:\n"
        for dep in "${DEPENDENCIES[@]}"; do
            IFS='|' read -r cmd pkg cat required desc <<< "${dep}"
            if [ "${required}" = "true" ] && ! ${DEP_STATUS["${cmd}"]}; then
                printf "  - %s (%s)\n" "${pkg}" "${desc}"
            fi
        done
        exit 1
    fi
fi

# Exit code
if [ ${REQUIRED_MISSING} -gt 0 ]; then
    exit 1
elif [ ${OPTIONAL_MISSING} -gt 0 ]; then
    exit 2
else
    exit 0
fi
