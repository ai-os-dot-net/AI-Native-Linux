#!/bin/bash
set -euo pipefail

# ci-build-all.sh — AI-OS.NET Revision 13 full CI pipeline
# Runs check → test → lint → build → ISO assemble in sequence.
# Designed to be called from GitLab CI, GitHub Actions, or a local Docker runner.
#
# Usage:
#   ./distro/build/ci-build-all.sh
#   docker run --rm -v "$PWD:/build" aios-ci:rev13 /build/distro/build/ci-build-all.sh

ISO_REVISION="${AIOS_RELEASE_REVISION:-12}"
if [[ "${AIOS_ENTERPRISE_RELEASE:-0}" == "1" ]]; then
    ISO_REVISION="${AIOS_RELEASE_REVISION:-13}"
fi

ISO_OUTPUT="${ISO_OUTPUT:-distro/build/aios-rev${ISO_REVISION}-${CI_COMMIT_SHORT_SHA:-snapshot}-x86_64.iso}"
OPENSUSE_RELEASE="${AIOS_OPENSUSE_RELEASE:-16.0}"
OPENSUSE_ARCH="${AIOS_OPENSUSE_ARCH:-x86_64}"
OPENSUSE_PACKAGE_SET="${AIOS_OPENSUSE_PACKAGE_SET:-server}"
OPENSUSE_ROOTFS="${AIOS_OPENSUSE_ROOTFS:-distro/build/out/rootfs-opensuse-leap-${OPENSUSE_RELEASE}-${OPENSUSE_ARCH}}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  AI-OS.NET CI — Revision ${ISO_REVISION}                             ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Rust version: $(rustc --version)"
    echo "Cargo version: $(cargo --version)"
    echo "Build date:    $(date -Iseconds)"
    echo "Workspace:     34 crates"
    echo "Target ISO:    ${ISO_OUTPUT}"
    echo ""
}

step_header() {
    echo ""
    echo -e "${CYAN}━━━ ${1} ━━━${NC}"
}

fail() {
    echo -e "${RED}FAIL: ${1}${NC}" >&2
    exit 1
}

# ── Buckle up ───────────────────────────────────────────────────────
banner

# ── STEP 1: cargo check ─────────────────────────────────────────────
step_header "STEP 1/5: cargo check --workspace"
cargo check --workspace --locked || fail "cargo check failed"

# ── STEP 2: cargo test ──────────────────────────────────────────────
step_header "STEP 2/5: cargo test --workspace"
cargo test --workspace --no-fail-fast || fail "cargo test failed"

# ── STEP 3: cargo clippy + fmt ──────────────────────────────────────
step_header "STEP 3/5: cargo clippy --workspace"
cargo clippy --workspace --all-targets -- -D warnings || fail "cargo clippy failed"

step_header "STEP 3b: cargo fmt"
cargo fmt --all -- --check || fail "cargo fmt failed"

# ── STEP 4: cargo build --release ───────────────────────────────────
step_header "STEP 4/5: cargo build --release --workspace"
cargo build --release --workspace --locked || fail "cargo build failed"

# ── STEP 5: assemble ISO ────────────────────────────────────────────
step_header "STEP 5/5: assemble ISO"
if [[ ! -x distro/build/build-aios-iso.sh ]]; then
    echo "WARNING: distro/build/build-aios-iso.sh not found or not executable"
    echo "Skipping ISO assembly. Binary artifacts are in target/release/"
    exit 0
fi

ISO_ARGS=(--release --output "${ISO_OUTPUT}")

if [[ -z "${AIOS_BASE_ROOTFS:-}" && "${AIOS_BUILD_OPENSUSE_ROOTFS:-0}" == "1" ]]; then
    [[ -x distro/build/build-opensuse-rootfs.sh ]] \
        || fail "distro/build/build-opensuse-rootfs.sh not found or not executable"
    distro/build/build-opensuse-rootfs.sh \
        --output "${OPENSUSE_ROOTFS}" \
        --release "${OPENSUSE_RELEASE}" \
        --arch "${OPENSUSE_ARCH}" \
        --package-set "${OPENSUSE_PACKAGE_SET}" \
        || fail "openSUSE base rootfs build failed"
    AIOS_BASE_ROOTFS="${OPENSUSE_ROOTFS}"
fi

if [[ -n "${AIOS_BASE_ROOTFS:-}" ]]; then
    ISO_ARGS+=(--base-rootfs "${AIOS_BASE_ROOTFS}")
else
    echo "WARNING: AIOS_BASE_ROOTFS not set; building scaffold packaging ISO, not a bootable distro ISO."
    ISO_ARGS+=(--allow-scaffold-rootfs)
fi

if [[ "${AIOS_ENTERPRISE_RELEASE:-0}" == "1" ]]; then
    [[ -n "${AIOS_BASE_ROOTFS:-}" ]] || fail "AIOS_ENTERPRISE_RELEASE=1 requires AIOS_BASE_ROOTFS or AIOS_BUILD_OPENSUSE_ROOTFS=1"
    ISO_ARGS+=(--enterprise-release)
fi

./distro/build/build-aios-iso.sh "${ISO_ARGS[@]}" || fail "ISO assembly failed"

if [[ "${AIOS_QEMU_BOOT_TEST:-0}" == "1" ]]; then
    step_header "STEP 5b: QEMU live ISO boot smoke test"
    chmod +x distro/build/qemu-boot-smoke.sh
    ./distro/build/qemu-boot-smoke.sh \
        --iso "${ISO_OUTPUT}" \
        --timeout "${AIOS_QEMU_BOOT_TIMEOUT:-120}" \
        || fail "QEMU live ISO boot smoke test failed"
else
    echo "QEMU live ISO boot smoke test skipped; set AIOS_QEMU_BOOT_TEST=1 to enable the Rev.12 boot gate."
fi

# ── Done ────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  CI BUILD COMPLETE                                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
ls -lh "${ISO_OUTPUT}" 2>/dev/null || echo "ISO not in expected location; check ${ISO_OUTPUT}"
echo ""
echo "SHA256:"
sha256sum "${ISO_OUTPUT}" 2>/dev/null || echo "(no ISO to hash)"
