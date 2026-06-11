# =============================================================================
# AI-OS.NET Build System Makefile — Revision 4
# =============================================================================
# Top-level Makefile wrapper for the AIOS ISO build system.
#
# Targets:
#   make iso          Build release ISO (default)
#   make iso-debug    Build debug ISO
#   make iso-aarch64  Build aarch64 cross-compiled ISO
#   make check-deps   Verify build dependencies
#   make cross-setup  Install cross-compilation toolchains
#   make clean        Remove build artifacts
#   make clean-all    Remove build artifacts + Rust target dir
#   make verify       Verify the built ISO structure
#   make test         Run workspace tests
#   make lint         Run clippy lints
#   make fmt          Run rustfmt
#   make audit        Run cargo-audit
#   make all          check-deps + test + lint + iso
# =============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

REPO_ROOT  := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))/../..
BUILD_DIR  := $(REPO_ROOT)/distro/build
OUT_DIR    := $(BUILD_DIR)/out
ISO_OUT    := $(BUILD_DIR)/aios-rev4-$(shell date +%Y%m%d)-x86_64.iso
ISO_ARM    := $(BUILD_DIR)/aios-rev4-$(shell date +%Y%m%d)-aarch64.iso

JOBS       ?= $(shell nproc 2>/dev/null || echo 4)
CARGO      := cargo
BUILD_SH   := $(BUILD_DIR)/build-aios-iso.sh
DEPS_SH    := $(BUILD_DIR)/build-deps-check.sh
CROSS_SH   := $(BUILD_DIR)/cross-compile.sh

# ── Default target ───────────────────────────────────────────────────────────

.PHONY: iso
iso: check-deps
	@echo "Building AIOS release ISO..."
	@$(BUILD_SH) --release --jobs $(JOBS) --output $(ISO_OUT)
	@echo ""
	@echo "ISO built: $(ISO_OUT)"

# ── Debug ISO ────────────────────────────────────────────────────────────────

.PHONY: iso-debug
iso-debug: check-deps
	@echo "Building AIOS debug ISO..."
	@$(BUILD_SH) --debug --jobs $(JOBS)

# ── AArch64 cross-compiled ISO ───────────────────────────────────────────────

.PHONY: iso-aarch64
iso-aarch64: cross-setup
	@echo "Building AIOS aarch64 ISO..."
	@$(CROSS_SH) --target aarch64-unknown-linux-gnu --release
	@$(BUILD_SH) --release --arch aarch64 --output $(ISO_ARM)
	@echo ""
	@echo "AArch64 ISO built: $(ISO_ARM)"

# ── Dependency checks ────────────────────────────────────────────────────────

.PHONY: check-deps
check-deps:
	@$(DEPS_SH)

.PHONY: check-deps-verbose
check-deps-verbose:
	@$(DEPS_SH) --verbose

.PHONY: check-deps-json
check-deps-json:
	@$(DEPS_SH) --json

# ── Cross-compilation setup ──────────────────────────────────────────────────

.PHONY: cross-setup
cross-setup:
	@echo "Setting up cross-compilation toolchains..."
	@$(CROSS_SH) --setup-only --target aarch64-unknown-linux-gnu

.PHONY: cross-setup-all
cross-setup-all:
	@echo "Setting up all cross-compilation toolchains..."
	@$(CROSS_SH) --setup-only --target aarch64-unknown-linux-gnu
	@$(CROSS_SH) --setup-only --target riscv64gc-unknown-linux-gnu || true

# ── Testing ──────────────────────────────────────────────────────────────────

.PHONY: test
test:
	@echo "Running AIOS workspace tests..."
	@cd $(REPO_ROOT) && $(CARGO) test --workspace -- --test-threads=$(JOBS)

.PHONY: test-release
test-release:
	@echo "Running AIOS workspace tests (release profile)..."
	@cd $(REPO_ROOT) && $(CARGO) test --workspace --release -- --test-threads=$(JOBS)

.PHONY: test-cross
test-cross:
	@echo "Running cross-compiled tests via qemu (aarch64)..."
	@cd $(REPO_ROOT) && CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=qemu-aarch64-static \
		$(CARGO) test --target aarch64-unknown-linux-gnu --workspace

# ── Linting ──────────────────────────────────────────────────────────────────

.PHONY: lint
lint:
	@echo "Running clippy lints..."
	@cd $(REPO_ROOT) && $(CARGO) clippy --workspace --all-targets -- -D warnings

.PHONY: lint-fix
lint-fix:
	@echo "Auto-fixing clippy lints..."
	@cd $(REPO_ROOT) && $(CARGO) clippy --workspace --all-targets --fix --allow-dirty

# ── Formatting ───────────────────────────────────────────────────────────────

.PHONY: fmt
fmt:
	@echo "Running rustfmt..."
	@cd $(REPO_ROOT) && $(CARGO) fmt --all -- --check

.PHONY: fmt-fix
fmt-fix:
	@echo "Applying rustfmt..."
	@cd $(REPO_ROOT) && $(CARGO) fmt --all

# ── Security audit ───────────────────────────────────────────────────────────

.PHONY: audit
audit:
	@echo "Running cargo-audit..."
	@cd $(REPO_ROOT) && $(CARGO) audit || true

# ── Verification ─────────────────────────────────────────────────────────────

.PHONY: verify
verify:
	@echo "Verifying ISO integrity..."
	@if [ -f "$(ISO_OUT)" ]; then \
		echo "ISO exists: $(ISO_OUT)"; \
		echo "Size: $$(du -h $(ISO_OUT) | cut -f1)"; \
		xorriso -indev "$(ISO_OUT)" -toc 2>/dev/null | head -20 || true; \
	else \
		echo "No ISO found. Run 'make iso' first."; \
		exit 1; \
	fi

# ── Cleaning ─────────────────────────────────────────────────────────────────

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OUT_DIR)
	@rm -f $(BUILD_DIR)/aios-rev4-*.iso
	@echo "Build artifacts cleaned."

.PHONY: clean-all
clean-all: clean
	@echo "Cleaning Rust target directory..."
	@cd $(REPO_ROOT) && $(CARGO) clean
	@echo "Full clean complete."

# ── Full pipeline ────────────────────────────────────────────────────────────

.PHONY: all
all: check-deps test lint iso
	@echo ""
	@echo "Full build pipeline complete."
	@echo "ISO: $(ISO_OUT)"

# ── Quick iteration (skip tests, skip lint) ──────────────────────────────────

.PHONY: quick
quick:
	@echo "Quick build (no tests, no lint)..."
	@$(BUILD_SH) --release --jobs $(JOBS) --output $(ISO_OUT)

# ── CI target ────────────────────────────────────────────────────────────────

.PHONY: ci
ci: check-deps test lint iso
	@echo "CI pipeline complete."

# ── Help ─────────────────────────────────────────────────────────────────────

.PHONY: help
help:
	@echo "AI-OS.NET Build System — Revision 4"
	@echo ""
	@echo "Core targets:"
	@echo "  make iso              Build release ISO (default)"
	@echo "  make iso-debug         Build debug ISO"
	@echo "  make iso-aarch64       Build aarch64 cross-compiled ISO"
	@echo "  make quick             Quick build (skip tests + lint)"
	@echo ""
	@echo "Dependency checks:"
	@echo "  make check-deps        Verify all required build tools"
	@echo "  make check-deps-json   Dependency report as JSON"
	@echo ""
	@echo "Cross-compilation:"
	@echo "  make cross-setup       Install aarch64 toolchain"
	@echo "  make cross-setup-all   Install all cross-compilation targets"
	@echo ""
	@echo "Quality gates:"
	@echo "  make test              Run workspace tests"
	@echo "  make lint              Run clippy (strict)"
	@echo "  make fmt               Check formatting"
	@echo "  make audit             Run cargo-audit (security)"
	@echo ""
	@echo "Verification:"
	@echo "  make verify            Verify built ISO integrity"
	@echo ""
	@echo "Cleaning:"
	@echo "  make clean             Remove build artifacts"
	@echo "  make clean-all         Remove build + target dirs"
	@echo ""
	@echo "Full pipeline:"
	@echo "  make ci                check-deps + test + lint + iso"
	@echo "  make all               Same as ci (alias)"
	@echo ""
	@echo "Variables:"
	@echo "  JOBS=n                 Parallel build jobs (default: nproc)"
