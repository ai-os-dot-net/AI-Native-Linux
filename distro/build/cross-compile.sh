#!/bin/bash
set -euo pipefail

# =============================================================================
# AI-OS.NET Cross-Compilation Helper — Revision 4
# =============================================================================
# Sets up cross-compilation targets and builds the 25-crate workspace for
# aarch64 (ARM64) or other supported targets.
#
# Usage:
#   ./cross-compile.sh [--target aarch64-unknown-linux-gnu] [--release|--debug]
#   ./cross-compile.sh --setup-only               # just install toolchains
#   ./cross-compile.sh --target riscv64gc-unknown-linux-gnu  # RISC-V
#
# Supported targets:
#   - aarch64-unknown-linux-gnu      (ARM64 / AArch64)
#   - x86_64-unknown-linux-gnu       (native — no-op, for CI)
#   - riscv64gc-unknown-linux-gnu    (RISC-V 64-bit, requires LLVM)
#
# Requirements:
#   - rustup (for target installation)
#   - Cross-compiler toolchain (gcc-{target} or clang)
#   - qemu-user-static (optional, for testing)
# =============================================================================

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────────────

TARGET="aarch64-unknown-linux-gnu"
PROFILE="release"
SETUP_ONLY=false
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
LINKER=""

# ── Color output ─────────────────────────────────────────────────────────────

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi

info()  { printf "    ${GREEN}→${RESET} %s\n" "$*"; }
warn()  { printf "    ${YELLOW}⚠${RESET}  %s\n" "$*" >&2; }
err()   { printf "${BOLD}${RED}✗${RESET} %s\n" "$*" >&2; }
ok()    { printf "    ${GREEN}✓${RESET} %s\n" "$*"; }
die()   { err "$*"; exit 1; }

# ── Argument parsing ─────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --target)
            TARGET="$2"; shift 2 ;;
        --release)
            PROFILE="release"; shift ;;
        --debug)
            PROFILE="debug"; shift ;;
        --setup-only)
            SETUP_ONLY=true; shift ;;
        --jobs|-j)
            JOBS="$2"; shift 2 ;;
        --linker)
            LINKER="$2"; shift 2 ;;
        --help|-h)
            printf "Usage: %s [OPTIONS]\n" "$(basename "$0")"
            printf "\nOptions:\n"
            printf "  --target TARGET     Rust target triple (default: aarch64-unknown-linux-gnu)\n"
            printf "  --release           Build with release profile (default)\n"
            printf "  --debug             Build with debug profile\n"
            printf "  --setup-only        Only install toolchains, don't build\n"
            printf "  --jobs N, -j N      Number of parallel build jobs\n"
            printf "  --linker PATH       Custom linker path\n"
            printf "\nSupported targets:\n"
            printf "  aarch64-unknown-linux-gnu       ARM64 / AArch64\n"
            printf "  x86_64-unknown-linux-gnu        x86-64 (native)\n"
            printf "  riscv64gc-unknown-linux-gnu     RISC-V 64-bit\n"
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ── Target configuration ─────────────────────────────────────────────────────

printf "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${RESET}\n"
printf "${BOLD}${BLUE}║   AI-OS.NET Cross-Compilation Helper — Revision 4         ║${RESET}\n"
printf "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${RESET}\n\n"

printf "  Target:   ${BOLD}%s${RESET}\n" "${TARGET}"
printf "  Profile:  ${BOLD}%s${RESET}\n" "${PROFILE}"
printf "  Jobs:     ${BOLD}%s${RESET}\n" "${JOBS}"
printf "\n"

# ── LLVM dependency for some targets ─────────────────────────────────────────

TARGET_ARCH="${TARGET%%-*}"
TARGET_VENDOR="$(echo "${TARGET}" | cut -d'-' -f2)"
TARGET_OS="$(echo "${TARGET}" | cut -d'-' -f3-)"

# Map target to linker prefix and required packages
case "${TARGET}" in
    aarch64-unknown-linux-gnu)
        CROSS_PREFIX="aarch64-linux-gnu-"
        CROSS_PKG="gcc-aarch64-linux-gnu"
        QEMU_STATIC="qemu-aarch64-static"
        CARGO_TARGET_LINKER="aarch64-linux-gnu-gcc"
        ;;
    riscv64gc-unknown-linux-gnu)
        CROSS_PREFIX="riscv64-linux-gnu-"
        CROSS_PKG="gcc-riscv64-linux-gnu"
        QEMU_STATIC="qemu-riscv64-static"
        CARGO_TARGET_LINKER="riscv64-linux-gnu-gcc"
        ;;
    x86_64-unknown-linux-gnu)
        CROSS_PREFIX=""
        CROSS_PKG=""
        QEMU_STATIC=""
        CARGO_TARGET_LINKER=""
        ;;
    *)
        # Generic: try prefix derived from target
        CROSS_PREFIX="${TARGET_ARCH}-linux-gnu-"
        CROSS_PKG="gcc-${TARGET_ARCH}-linux-gnu"
        QEMU_STATIC="qemu-${TARGET_ARCH}-static"
        CARGO_TARGET_LINKER="${TARGET_ARCH}-linux-gnu-gcc"
        ;;
esac

# ── Pre-flight ───────────────────────────────────────────────────────────────

if ! command -v rustup >/dev/null 2>&1; then
    die "rustup not found. Install from https://rustup.rs"
fi

if ! command -v cargo >/dev/null 2>&1; then
    die "cargo not found. Install via rustup."
fi

# ── Step 1: Install Rust target ──────────────────────────────────────────────

printf "${BOLD}Step 1: Installing Rust target ${TARGET}${RESET}\n"

if rustup target list --installed 2>/dev/null | grep -q "^${TARGET}$"; then
    ok "Target ${TARGET} already installed."
else
    info "Adding target ${TARGET}..."
    rustup target add "${TARGET}"
    ok "Target ${TARGET} installed."
fi

# ── Step 2: Check/install cross-compiler ─────────────────────────────────────

printf "\n${BOLD}Step 2: Checking cross-compiler toolchain${RESET}\n"

NEED_CROSS=false
if [ -n "${CARGO_TARGET_LINKER}" ]; then
    if ! command -v "${CARGO_TARGET_LINKER}" >/dev/null 2>&1; then
        if [ "${TARGET}" != "x86_64-unknown-linux-gnu" ]; then
            NEED_CROSS=true
            warn "Cross-compiler '${CARGO_TARGET_LINKER}' not found."
            warn "Install with: apt install ${CROSS_PKG}"
            warn "        or:  dnf install ${CROSS_PKG}"
        fi
    else
        CROSS_VER="$(${CARGO_TARGET_LINKER} --version | head -1)"
        ok "Cross-compiler found: ${CROSS_VER}"
    fi
else
    ok "Native target — using host compiler."
fi

# Configure cargo for cross-compilation
CARGO_CONFIG_DIR="${REPO_ROOT}/.cargo"
mkdir -p "${CARGO_CONFIG_DIR}"

if [ -n "${CARGO_TARGET_LINKER}" ] && [ "${TARGET}" != "x86_64-unknown-linux-gnu" ]; then
    # If cross-compiler is available, configure cargo.toml linker setting
    if command -v "${CARGO_TARGET_LINKER}" >/dev/null 2>&1 || [ -n "${LINKER}" ]; then
        LINKER_TO_USE="${LINKER:-${CARGO_TARGET_LINKER}}"
        info "Configuring cargo linker for ${TARGET}: ${LINKER_TO_USE}"
        export "CARGO_TARGET_$(echo "${TARGET}" | tr '[:lower:]-' '[:upper:]_')_LINKER"="${LINKER_TO_USE}"
        ok "Linker configured via environment variable."
    else
        warn "Cross-compiler not available — build may fail."
        warn "To proceed anyway, set the linker explicitly with --linker PATH"
        if ${NEED_CROSS} && ! ${SETUP_ONLY}; then
            die "Cross-compiler required but not found. Use --setup-only to skip build."
        fi
    fi
fi

# ── Step 3: Check qemu-user-static (optional) ────────────────────────────────

printf "\n${BOLD}Step 3: Checking qemu-user-static (for testing)${RESET}\n"

if [ -n "${QEMU_STATIC}" ]; then
    if command -v "${QEMU_STATIC}" >/dev/null 2>&1; then
        ok "qemu-user-static found: ${QEMU_STATIC}"
    else
        warn "qemu-user-static not found — cannot run cross-compiled binaries locally."
        warn "Install with: apt install qemu-user-static"
    fi
else
    ok "Native target — qemu not needed."
fi

# ── Step 4: Install additional target support packages ───────────────────────

printf "\n${BOLD}Step 4: Checking target support packages${RESET}\n"

# Check for OpenSSL development headers for the target (needed by some crates)
OPENSSL_DIR=""
case "${TARGET}" in
    aarch64-unknown-linux-gnu)
        if [ -d "/usr/aarch64-linux-gnu" ]; then
            export PKG_CONFIG_PATH="/usr/aarch64-linux-gnu/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
            ok "aarch64 sysroot found at /usr/aarch64-linux-gnu"
        else
            warn "aarch64 sysroot not found at /usr/aarch64-linux-gnu"
            warn "Install with: apt install libssl-dev:arm64 crossbuild-essential-arm64"
        fi
        ;;
esac

# ── Setup only mode ──────────────────────────────────────────────────────────

if ${SETUP_ONLY}; then
    printf "\n${BOLD}${GREEN}════════════════════════════════════════════════════════${RESET}\n"
    printf "${BOLD}${GREEN}  SETUP COMPLETE${RESET}\n\n"
    printf "  Target ${TARGET} is installed.\n"
    printf "  Run without --setup-only to build.\n"
    printf "${BOLD}${GREEN}════════════════════════════════════════════════════════${RESET}\n"
    exit 0
fi

# ── Step 5: Build workspace ──────────────────────────────────────────────────

printf "\n${BOLD}Step 5: Building workspace for ${TARGET}${RESET}\n"

cd "${REPO_ROOT}"

START_TS=$(date +%s)

cargo build \
    --profile "${PROFILE}" \
    --workspace \
    --target "${TARGET}" \
    --jobs "${JOBS}" \
    2>&1

BUILD_DURATION=$(( $(date +%s) - START_TS ))

if [ $? -eq 0 ]; then
    ok "Build successful! (${BUILD_DURATION}s)"
else
    die "Build failed."
fi

# ── Step 6: Verify binaries ──────────────────────────────────────────────────

printf "\n${BOLD}Step 6: Verifying cross-compiled binaries${RESET}\n"

TARGET_DIR="${REPO_ROOT}/target/${TARGET}/${PROFILE}"

if [ ! -d "${TARGET_DIR}" ]; then
    warn "Target directory ${TARGET_DIR} not found."
    exit 1
fi

BIN_COUNT=0
while IFS= read -r binary; do
    if [ -f "${binary}" ] && [ -x "${binary}" ]; then
        BIN_COUNT=$((BIN_COUNT + 1))
        bin_name="$(basename "${binary}")"
        # Verify architecture
        ARCH_INFO=""
        if command -v file >/dev/null 2>&1; then
            ARCH_INFO="$(file "${binary}" | cut -d: -f2 | head -c 60)"
        fi
        info "  ${bin_name}${ARCH_INFO:+ —${ARCH_INFO}}"
    fi
done < <(find "${TARGET_DIR}" -maxdepth 1 -type f -executable 2>/dev/null || true)

ok "Found ${BIN_COUNT} cross-compiled binaries."

# ── Summary ──────────────────────────────────────────────────────────────────

printf "\n${BOLD}${BLUE}════════════════════════════════════════════════════════${RESET}\n"
printf "${BOLD}${GREEN}  CROSS-COMPILATION COMPLETE${RESET}\n\n"
printf "  Target:     ${BOLD}%s${RESET}\n" "${TARGET}"
printf "  Profile:    ${BOLD}%s${RESET}\n" "${PROFILE}"
printf "  Duration:   ${BOLD}%ds${RESET}\n" "${BUILD_DURATION}"
printf "  Binaries:   ${BOLD}%d${RESET}\n" "${BIN_COUNT}"
printf "\n  Output:     target/%s/%s/\n" "${TARGET}" "${PROFILE}"
printf "\n  Build ISO:  ./build-aios-iso.sh --arch %s\n" "${TARGET_ARCH}"
printf "${BOLD}${BLUE}════════════════════════════════════════════════════════${RESET}\n"
