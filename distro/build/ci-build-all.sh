#!/bin/bash
set -euo pipefail

# ci-build-all.sh — AI-OS.NET Revision 4 full CI pipeline
# Runs check → test → lint → build → ISO assemble in sequence.
# Designed to be called from GitLab CI, GitHub Actions, or a local Docker runner.
#
# Usage:
#   ./distro/build/ci-build-all.sh
#   docker run --rm -v "$PWD:/build" aios-ci:rev4 /build/distro/build/ci-build-all.sh

ISO_OUTPUT="${ISO_OUTPUT:-aios-rev4-${CI_COMMIT_SHORT_SHA:-snapshot}-x86_64.iso}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  AI-OS.NET CI — Revision 4                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Rust version: $(rustc --version)"
    echo "Cargo version: $(cargo --version)"
    echo "Build date:    $(date -Iseconds)"
    echo "Workspace:     25 crates"
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

./distro/build/build-aios-iso.sh --release --output "${ISO_OUTPUT}" || fail "ISO assembly failed"

# ── Done ────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  CI BUILD COMPLETE                                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
ls -lh "distro/build/${ISO_OUTPUT}" 2>/dev/null || echo "ISO not in expected location; check distro/build/"
echo ""
echo "SHA256:"
sha256sum "distro/build/${ISO_OUTPUT}" 2>/dev/null || echo "(no ISO to hash)"
