#!/bin/sh
#
# AI-OS.NET Rev.11 Build System Sanity Test
#
# This test validates that the Rev.11 upgrade has been applied correctly:
#   1. Build script exists and is executable
#   2. Build script syntax is valid (bash -n)
#   3. All expected output directories are referenced
#   4. Legacy Rev.11 files keep their Revision 11 markers; ISO builder is Rev.12
#   5. All 6 new systemd unit files exist
#   6. Rootfs layout has the new fleet/autonomous/marketplace/container/terminal dirs
#   7. First-boot script references the new phases (11-15)
#   8. Loader entry has Revision 11 in the title
#
# Run: sh distro/build/tests/test-rev11-build.sh
#
# POSIX-compatible.  Uses the same patterns as test-session-start.sh.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

msg "=== AI-OS.NET Rev.11 Build System Tests ==="
msg "Build directory: ${BUILD_DIR}"
msg "Distro directory: ${DISTRO_DIR}"

# ── Test 1: Build script exists and is executable ────────────────────────────

msg "Test 1: Build script exists and is executable"

BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"

if [ -f "${BUILD_SCRIPT}" ]; then
    pass "Build script exists: build-aios-iso.sh"
else
    fail "Missing: build-aios-iso.sh"
fi

if [ -x "${BUILD_SCRIPT}" ]; then
    pass "Build script is executable"
else
    fail "Build script is NOT executable"
fi

# ── Test 2: Build script syntax check (bash -n) ──────────────────────────────

msg "Test 2: bash -n syntax check"

for _script in \
    "${BUILD_DIR}/build-aios-iso.sh" \
    "${BUILD_DIR}/build-deps-check.sh" \
    "${BUILD_DIR}/ci-build-all.sh" \
    "${BUILD_DIR}/cross-compile.sh"; do

    if [ ! -f "${_script}" ]; then
        fail "Missing: ${_script}"
        continue
    fi

    if bash -n "${_script}" 2>/dev/null; then
        pass "Syntax OK: $(basename "${_script}")"
    else
        fail "Syntax ERROR: $(basename "${_script}")"
    fi
done

# ── Test 3: Expected output directories are referenced ───────────────────────

msg "Test 3: Expected output directories referenced in build script"

for _dir in \
    'BUILD_DIR' \
    'ROOTFS_DIR' \
    'INITRAMFS_DIR' \
    'INITRAMFS_OUT' \
    'ISO_DIR' \
    'EFI_IMG'; do

    if grep -q "${_dir}" "${BUILD_SCRIPT}"; then
        pass "Directory variable referenced: ${_dir}"
    else
        fail "Directory variable missing: ${_dir}"
    fi
done

# ── Test 4: Revision markers ─────────────────────────────────────────────────

msg "Test 4: Revision markers"

for _file in \
    "${DISTRO_DIR}/aios-boot/loader-entry.conf" \
    "${DISTRO_DIR}/first-boot/aios-first-boot.sh"; do

    if [ ! -f "${_file}" ]; then
        fail "Missing: ${_file}"
        continue
    fi

    _rel="${_file#"${DISTRO_DIR}"/}"
    if grep -q 'Revision 11' "${_file}"; then
        pass "Revision 11 found: ${_rel}"
    else
        fail "Revision 11 NOT found: ${_rel}"
    fi
done

if grep -q 'Revision 12' "${BUILD_SCRIPT}" 2>/dev/null; then
    pass "Build script says Revision 12"
else
    fail "Build script does NOT say Revision 12"
fi

# ── Test 5: All 6 new systemd unit files exist ───────────────────────────────

msg "Test 5: New Rev.11 systemd unit files"

for _svc in \
    'aios-fleet.service' \
    'aios-autonomous.service' \
    'aios-marketplace.service' \
    'aios-container.service' \
    'aios-terminal.service' \
    'aios-cognitive-core.service'; do

    _path="${DISTRO_DIR}/systemd/${_svc}"
    if [ -f "${_path}" ]; then
        pass "Unit exists: ${_svc}"
    else
        fail "Missing unit: ${_svc}"
    fi
done

# ── Test 6: Rootfs layout has new directories ────────────────────────────────

msg "Test 6: Rootfs layout lists new fleet/autonomous/marketplace/container/terminal dirs"

LAYOUT_FILE="${DISTRO_DIR}/aios-boot/rootfs-layout.txt"

if [ ! -f "${LAYOUT_FILE}" ]; then
    fail "rootfs-layout.txt not found"
else
    for _d in 'fleet' 'autonomous' 'marketplace' 'container' 'terminal'; do
        if grep -q "^│.*${_d}/" "${LAYOUT_FILE}" 2>/dev/null \
           || grep -q "${_d}/" "${LAYOUT_FILE}" 2>/dev/null; then
            pass "Layout references: ${_d}/"
        else
            fail "Missing from layout: ${_d}/"
        fi
    done

    if grep -q 'Revision 11' "${LAYOUT_FILE}"; then
        pass "Layout header says Revision 11"
    else
        fail "Layout header does NOT say Revision 11"
    fi
fi

# ── Test 7: First-boot script references new phases (11-15) ──────────────────

msg "Test 7: First-boot script references phases 11-15"

FIRST_BOOT_SH="${DISTRO_DIR}/first-boot/aios-first-boot.sh"
FIRST_BOOT_RS="${DISTRO_DIR}/first-boot/aios-first-boot.rs"

if [ ! -f "${FIRST_BOOT_SH}" ]; then
    fail "First-boot shell script not found"
else
    for _phase in 11 12 13 14 15; do
        if grep -q "^# PHASE ${_phase}:" "${FIRST_BOOT_SH}" 2>/dev/null \
           || grep -q "Phase ${_phase}:" "${FIRST_BOOT_SH}" 2>/dev/null \
           || grep -q "phase ${_phase}" "${FIRST_BOOT_SH}" 2>/dev/null; then
            pass "Phase ${_phase} referenced in first-boot script"
        else
            fail "Phase ${_phase} NOT found in first-boot script"
        fi
    done
fi

# Also check first-boot variable declarations for new directories

for _var in 'FLEET_DIR' 'AUTONOMOUS_DIR' 'MARKETPLACE_DIR' 'CONTAINER_DIR'; do
    if grep -q "^${_var}=" "${FIRST_BOOT_SH}" 2>/dev/null \
       || grep -q "const ${_var}:" "${FIRST_BOOT_RS}" 2>/dev/null; then
        pass "Variable declared: ${_var}"
    else
        fail "Variable NOT declared: ${_var}"
    fi
done

if [ ! -f "${FIRST_BOOT_RS}" ]; then
    fail "Rust first-boot binary source not found"
else
    for _fn in \
        'phase_10_fleet_membership' \
        'phase_11_autonomous_governance' \
        'phase_12_marketplace' \
        'phase_13_container_runtime' \
        'phase_14_readiness'; do
        if grep -q "fn ${_fn}" "${FIRST_BOOT_RS}" 2>/dev/null; then
            pass "Rust first-boot phase implemented: ${_fn}"
        else
            fail "Rust first-boot phase missing: ${_fn}"
        fi
    done
fi

# ── Test 8: Loader entry has Revision 11 in the title ────────────────────────

msg "Test 8: Loader entry has Revision 11 title"

LOADER_FILE="${DISTRO_DIR}/aios-boot/loader-entry.conf"

if [ ! -f "${LOADER_FILE}" ]; then
    fail "loader-entry.conf not found"
else
    if grep -q 'Revision 11' "${LOADER_FILE}"; then
        pass "Loader title: Revision 11 found"
    else
        fail "Loader title: Revision 11 NOT found"
    fi
fi

# ── Bonus: ISO output naming check ───────────────────────────────────────────

msg "Bonus: ISO output naming"

if [ -f "${BUILD_SCRIPT}" ]; then
    if grep -q 'aios-rev12' "${BUILD_SCRIPT}"; then
        pass "ISO output filename uses aios-rev12"
    else
        fail "ISO output filename does NOT use aios-rev12"
    fi
fi

# ── Bonus: VOLID check ───────────────────────────────────────────────────────

if [ -f "${BUILD_SCRIPT}" ]; then
    if grep -q 'AIOS_REV12' "${BUILD_SCRIPT}" 2>/dev/null; then
        pass "VOLID is set to AIOS_REV12"
    else
        if grep -q 'AIOS_REV4' "${BUILD_SCRIPT}" 2>/dev/null; then
            fail "VOLID is still set to AIOS_REV4 (should be AIOS_REV12)"
        else
            fail "VOLID not AIOS_REV12"
        fi
    fi
fi

# ── Test 9: Bootable ISO guards ──────────────────────────────────────────────

msg "Test 9: Bootable ISO guards and live initramfs support"

if grep -q -- '--base-rootfs' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q 'AIOS_ALLOW_SCAFFOLD_ROOTFS' "${BUILD_SCRIPT}" 2>/dev/null; then
    pass "Build script requires explicit base rootfs or scaffold override"
else
    fail "Build script does not guard bootable ISO base rootfs"
fi

if grep -q 'cargo build --profile.*distro/first-boot/Cargo.toml' "${BUILD_SCRIPT}" 2>/dev/null \
   || grep -q 'aios-first-boot' "${BUILD_SCRIPT}" 2>/dev/null; then
    pass "Build script stages aios-first-boot binary"
else
    fail "Build script does not stage aios-first-boot binary"
fi

if grep -q 'run-service' "${DISTRO_DIR}/systemd/aios-policy-kernel.service" 2>/dev/null \
   && grep -q 'run-service' "${DISTRO_DIR}/systemd/aios-evidence-log.service" 2>/dev/null; then
    pass "Core systemd units use aios-system service runner"
else
    fail "Core systemd units still reference missing per-service binaries"
fi

if grep -q 'aios-ollama.service' "${DISTRO_DIR}/systemd/aios.target" 2>/dev/null \
   || grep -q 'aios-vllm.service' "${DISTRO_DIR}/systemd/aios.target" 2>/dev/null; then
    fail "aios.target pulls optional external inference services by default"
else
    pass "aios.target excludes optional external inference services"
fi

INITRAMFS_INIT="${DISTRO_DIR}/aios-boot/initramfs/init"
if grep -q 'mount_live_root' "${INITRAMFS_INIT}" 2>/dev/null \
   && grep -q 'live/aios.squashfs' "${INITRAMFS_INIT}" 2>/dev/null; then
    pass "Initramfs supports live squashfs root"
else
    fail "Initramfs does not support live squashfs root"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

printf '\n'
msg "=== Test Summary ==="
printf '  Passed: %d\n' "${PASSED}"
printf '  Failed: %d\n' "${FAILED}"

if [ "${FAILED}" -eq 0 ]; then
    printf '  \033[1;32mALL TESTS PASSED\033[0m\n'
    exit 0
else
    printf '  \033[1;31mSOME TESTS FAILED\033[0m\n'
    exit 1
fi
