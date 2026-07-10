#!/usr/bin/env bash
#
# AI-OS.NET Rev.12 NEGATIVE functional gate tests
# (spec distro/build/REV12-DISTRIBUTION-SPEC.md §5 and §9 acceptance tests).
#
# Unlike the sibling test-rev12-*.sh harnesses that grep the scripts for
# expected strings, this harness ACTUALLY EXECUTES the installer / ISO builder
# with known-bad inputs and asserts each guard FAILS CLOSED (non-zero exit +
# meaningful diagnostic), while proving that NO destructive block-device tool
# ran before the guard rejected the input.
#
# Every dangerous binary (sgdisk, cryptsetup, mkfs.*, dd, wipefs, mount,
# partprobe, unsquashfs, bootctl, veritysetup, umount, ...) is replaced by a
# PATH stub that records its invocation into a tripwire log and exits non-zero.
# After each installer run the tripwire log MUST be empty — if any stub fired,
# validation let a destructive step start and the test FAILS.
#
# No real block device is ever touched: targets are /dev/nonexistent-disk and
# the disk-validation guard rejects them before any tool is invoked.
#
# Scenarios (guards asserted, with source citations):
#   1. Invalid target disk    -> aios-quick-install.sh validate_env
#                                 line 137-138 `[ ! -b ... ]` die code 3.
#   2. Missing rootfs payload  -> aios-quick-install.sh validate_env
#                                 line 132-134 `Squashfs not found` die code 2.
#   3a. Boot-signature input   -> build-aios-iso.sh line 255-258
#                                 `AIOS_REQUIRE_BOOT_SIGNATURES must be 0 or 1`.
#   3b. Boot-chain fail-closed -> build-aios-iso.sh require_boot_signature()
#                                 line 1483-1490 (called 1802-1810) die
#                                 `Boot-chain signature required but missing`.
#                                 OPT-IN: needs a full workspace build; enable
#                                 with AIOS_NEG_BUILD_GATE=1 (see FINDING below).
#   4. SELinux enforcing gate   -> build-aios-iso.sh line 260-262
#                                 `SELinux enforcing requires --selinux-policy-source`.
#
# FINDING: the boot-chain signature fail-closed gate (scenario 3b) is invoked
# at lines 1802-1810 — AFTER the full `cargo build --workspace`, kernel/module
# staging and mksquashfs (line 1446). There is no cheap or robust invocation
# that reaches it; a real negative test of that gate requires a full scaffold
# build. It is therefore gated behind AIOS_NEG_BUILD_GATE=1 and runs in CI's
# full-build job (ci-build-all.sh), not in this fast harness. Scenario 3a
# exercises the cheap, early boot-signature INPUT guard by default so the
# boot-signature surface still has a real default-run assertion.
#
# Run (fast, default):   bash distro/build/tests/test-rev12-negative-gates.sh
# Run (incl. full gate): AIOS_NEG_BUILD_GATE=1 \
#                        bash distro/build/tests/test-rev12-negative-gates.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"

QUICK_INSTALLER="${DISTRO_DIR}/installer/aios-quick-install.sh"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"

FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }
skip() { printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; }

# ── Sandbox: temp workdir + PATH stubs for dangerous binaries ─────────────────

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-neg-gates.XXXXXX")"
STUB_DIR="${WORK}/stub"
TRIPWIRE="${WORK}/tripwire.log"
mkdir -p "${STUB_DIR}"
: > "${TRIPWIRE}"

cleanup() { rm -rf "${WORK}" 2>/dev/null || true; }
trap cleanup EXIT

REAL_ID="$(command -v id || echo /usr/bin/id)"

# Dangerous binaries: record invocation to the tripwire and fail hard. If any of
# these ever runs, a destructive step began before validation rejected input.
DANGEROUS="sgdisk cryptsetup veritysetup mkfs.vfat mkfs.ext4 mkfs.btrfs mkfs \
dd wipefs mount umount partprobe unsquashfs bootctl systemd-cryptenroll \
blkid lsblk"

for _bin in ${DANGEROUS}; do
    {
        printf '#!/bin/sh\n'
        printf 'printf "%%s %%s\\n" "%s" "$*" >> "%s"\n' "${_bin}" "${TRIPWIRE}"
        printf 'exit 1\n'
    } > "${STUB_DIR}/${_bin}"
    chmod +x "${STUB_DIR}/${_bin}"
done

# Fake-root stub so `id -u` returns 0 and we reach the installer's disk/squashfs
# guards. This does NOT weaken the test: destructive tools are still stubbed
# tripwires, and the target disks never exist, so no destructive step can run.
{
    printf '#!/bin/sh\n'
    printf 'if [ "$1" = "-u" ]; then echo 0; exit 0; fi\n'
    printf 'exec %s "$@"\n' "${REAL_ID}"
} > "${STUB_DIR}/id"
chmod +x "${STUB_DIR}/id"

STUB_PATH="${STUB_DIR}:${PATH}"

tripwire_clean() {
    if [ -s "${TRIPWIRE}" ]; then
        return 1
    fi
    return 0
}

reset_tripwire() { : > "${TRIPWIRE}"; }

# ── Pre-flight: scripts exist, executable, syntax OK ──────────────────────────

msg "=== AI-OS.NET Rev.12 Negative Gate Tests ==="

for _f in "${QUICK_INSTALLER}" "${BUILD_SCRIPT}"; do
    if [ -f "${_f}" ]; then
        pass "exists: $(basename "${_f}")"
    else
        fail "missing: ${_f}"
    fi
    if bash -n "${_f}" 2>/dev/null; then
        pass "syntax OK: $(basename "${_f}")"
    else
        fail "syntax error: ${_f}"
    fi
done

# ── Scenario 1: installer rejects invalid target disk ─────────────────────────
# Guard: aios-quick-install.sh:137-138 `[ ! -b "${TARGET_DISK}" ]` die code 3.

msg "--- Scenario 1: reject invalid target disk (guard installer:137-138) ---"

_valid_sq="${WORK}/fake-rootfs.squashfs"
: > "${_valid_sq}"   # exists -> passes the squashfs guard (installer:132) so we
                     # reach the disk guard (installer:137).
reset_tripwire
_rc=0
_out="$(
    PATH="${STUB_PATH}" \
    AIOS_TARGET_DISK="/dev/nonexistent-disk" \
    AIOS_HOSTNAME="neg-test" \
    AIOS_CONFIRM_SKIP="1" \
    AIOS_SQUASHFS="${_valid_sq}" \
    bash "${QUICK_INSTALLER}" 2>&1
)" || _rc=$?

if [ "${_rc}" -ne 0 ]; then
    pass "installer exited non-zero on invalid disk (rc=${_rc})"
else
    fail "installer accepted /dev/nonexistent-disk (rc=0)"
fi
if [ "${_rc}" -eq 3 ]; then
    pass "installer used disk-validation exit code 3"
else
    fail "installer exit code ${_rc} != expected 3 (disk validation)"
fi
if printf '%s' "${_out}" | grep -qi 'not a valid block device'; then
    pass "installer emitted 'Not a valid block device' diagnostic"
else
    fail "installer did not emit the disk-validation diagnostic"
fi
if tripwire_clean; then
    pass "no destructive tool ran before disk rejection"
else
    fail "destructive tool(s) fired before disk rejection: $(tr '\n' ';' < "${TRIPWIRE}")"
fi

# ── Scenario 2: installer rejects missing rootfs payload ──────────────────────
# Guard: aios-quick-install.sh:132-134 `Squashfs not found` die code 2.

msg "--- Scenario 2: reject missing rootfs payload (guard installer:132-134) ---"

reset_tripwire
_rc=0
_out="$(
    PATH="${STUB_PATH}" \
    AIOS_TARGET_DISK="/dev/nonexistent-disk" \
    AIOS_HOSTNAME="neg-test" \
    AIOS_CONFIRM_SKIP="1" \
    AIOS_SQUASHFS="/nonexistent" \
    bash "${QUICK_INSTALLER}" 2>&1
)" || _rc=$?

if [ "${_rc}" -ne 0 ]; then
    pass "installer exited non-zero on missing squashfs (rc=${_rc})"
else
    fail "installer accepted missing squashfs (rc=0)"
fi
if [ "${_rc}" -eq 2 ]; then
    pass "installer used env/payload validation exit code 2"
else
    fail "installer exit code ${_rc} != expected 2 (payload validation)"
fi
if printf '%s' "${_out}" | grep -qi 'squashfs not found'; then
    pass "installer emitted 'Squashfs not found' diagnostic"
else
    fail "installer did not emit the squashfs-missing diagnostic"
fi
if tripwire_clean; then
    pass "no destructive tool ran before payload rejection"
else
    fail "destructive tool(s) fired before payload rejection: $(tr '\n' ';' < "${TRIPWIRE}")"
fi

# ── Scenario 3a: boot-signature INPUT guard (cheap, default) ──────────────────
# Guard: build-aios-iso.sh:255-258 `AIOS_REQUIRE_BOOT_SIGNATURES must be 0 or 1`.
# Runs before pre-flight/compile, so it is fast and needs no toolchain.

msg "--- Scenario 3a: reject invalid boot-signature flag (guard build:255-258) ---"

_rc=0
_out="$(
    PATH="${STUB_PATH}" \
    AIOS_REQUIRE_BOOT_SIGNATURES="bogus" \
    bash "${BUILD_SCRIPT}" --allow-scaffold-rootfs 2>&1
)" || _rc=$?

if [ "${_rc}" -ne 0 ]; then
    pass "builder rejected invalid AIOS_REQUIRE_BOOT_SIGNATURES (rc=${_rc})"
else
    fail "builder accepted AIOS_REQUIRE_BOOT_SIGNATURES=bogus (rc=0)"
fi
if printf '%s' "${_out}" | grep -qi 'AIOS_REQUIRE_BOOT_SIGNATURES must be 0 or 1'; then
    pass "builder emitted boot-signature input diagnostic"
else
    fail "builder did not emit boot-signature input diagnostic"
fi

# ── Scenario 4: SELinux enforcing without policy source ───────────────────────
# Guard: build-aios-iso.sh:260-262
#        `SELinux enforcing requires --selinux-policy-source`.
# Argument validation; fires before pre-flight/compile -> fast exit.

msg "--- Scenario 4: reject enforcing SELinux w/o policy (guard build:260-262) ---"

_rc=0
_out="$(
    PATH="${STUB_PATH}" \
    bash "${BUILD_SCRIPT}" --selinux-mode enforcing --allow-scaffold-rootfs 2>&1
)" || _rc=$?

if [ "${_rc}" -ne 0 ]; then
    pass "builder rejected enforcing SELinux without policy (rc=${_rc})"
else
    fail "builder accepted enforcing SELinux without policy source (rc=0)"
fi
if printf '%s' "${_out}" | grep -qi 'selinux enforcing requires .*selinux-policy-source'; then
    pass "builder emitted SELinux-policy-required diagnostic"
else
    fail "builder did not emit SELinux-policy-required diagnostic"
fi
if tripwire_clean; then
    pass "no destructive tool ran during SELinux argument validation"
else
    fail "destructive tool(s) fired during SELinux validation: $(tr '\n' ';' < "${TRIPWIRE}")"
fi

# ── Scenario 3b: boot-chain fail-closed gate (OPT-IN full build) ──────────────
# Guard: build-aios-iso.sh require_boot_signature() line 1483-1490, invoked at
#        1802-1810 -> die `Boot-chain signature required but missing`.
# Reaching it requires a full scaffold build (compile + squashfs), so it is
# opt-in. Needs a stageable host kernel; skips cleanly if unavailable.

msg "--- Scenario 3b: boot-chain fail-closed gate (guard build:1483-1490 / 1802) ---"

# Kernel is stageable if any candidate the builder scans (build-aios-iso.sh
# stage_kernel, lines ~1160-1163) is present. A symlink counts even if its
# target is momentarily unresolved from this shell, matching builder behaviour.
_have_kernel=0
for _k in /boot/vmlinuz-linux /boot/vmlinuz-linux-lts \
          "/boot/vmlinuz-$(uname -r)" /boot/vmlinuz; do
    if [ -e "${_k}" ] || [ -L "${_k}" ]; then
        _have_kernel=1
        break
    fi
done

if [ "${AIOS_NEG_BUILD_GATE:-0}" != "1" ]; then
    skip "full-build boot-chain gate (set AIOS_NEG_BUILD_GATE=1 to run; see FINDING in header)"
elif [ "${_have_kernel}" -ne 1 ]; then
    skip "no stageable host kernel under /boot; cannot run full-build gate"
else
    _bwork="${WORK}/bwork"
    mkdir -p "${_bwork}"
    _rc=0
    _out="$(
        AIOS_BUILD_WORKDIR="${_bwork}" \
        bash "${BUILD_SCRIPT}" \
            --debug --allow-scaffold-rootfs --require-boot-signatures \
            --kernel-source host --kernel-version "$(uname -r)" \
            --kernel-modules-source none --kernel-firmware-source none \
            --output "${WORK}/neg-gate.iso" 2>&1
    )" || _rc=$?

    if [ "${_rc}" -ne 0 ]; then
        pass "builder failed closed with signatures required but absent (rc=${_rc})"
    else
        fail "builder produced an ISO despite missing boot-chain signatures (rc=0)"
    fi
    if printf '%s' "${_out}" | grep -qi 'boot-chain signature required but missing'; then
        pass "builder emitted 'Boot-chain signature required but missing' diagnostic"
    else
        fail "builder did not emit boot-chain-signature diagnostic (died elsewhere?)"
    fi
    if [ ! -f "${WORK}/neg-gate.iso" ]; then
        pass "no ISO artifact was emitted"
    else
        fail "ISO artifact was emitted despite the signature gate"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

printf '\n'
msg "=== Test Summary ==="
printf '  Passed: %d\n' "${PASSED}"
printf '  Failed: %d\n' "${FAILED}"

if [ "${FAILED}" -eq 0 ]; then
    printf '  \033[1;32mALL TESTS PASSED\033[0m\n'
    exit 0
fi

printf '  \033[1;31mSOME TESTS FAILED\033[0m\n'
exit 1
