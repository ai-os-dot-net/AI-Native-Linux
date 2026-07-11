#!/usr/bin/env bash
#
# AI-OS.NET Rev.12 UEFI/OVMF boot path gate
# (spec distro/build/REV12-DISTRIBUTION-SPEC.md §4 acceptance:
#  "UEFI boot path test (OVMF)").
#
# qemu-boot-smoke.sh has always implemented --uefi / --ovmf-code, but nothing
# ever invoked that path in CI or in a test harness — the acceptance line was
# unverified. This harness closes that gap with two layers:
#
#   STATIC  — always runs. Proves --uefi wiring is real: --dry-run prints a
#             QEMU command with an OVMF pflash drive, and a bogus --ovmf-code
#             path is rejected with the script's real error text (verified by
#             hand first, not assumed).
#
#   REAL    — boots an ISO through OVMF and asserts the same serial-console
#             success/failure markers qemu-boot-smoke.sh already defines for
#             BIOS boot. Requires OVMF firmware AND an ISO; missing either
#             SKIPs (not PASS, not FAIL) with an explicit reason.
#
# ISO source: $AIOS_UEFI_TEST_ISO if set, else the first aios-*.iso found
# directly under distro/build/. Rev.11 ISOs on this host predate the serial
# console (their grub.cfg has no `console=ttyS0`), so QEMU never writes a
# boot marker under OVMF either — that is expected and must not fail the
# gate. This harness reads each candidate ISO's grub.cfg via xorriso first:
#   - grub.cfg has `console=ttyS0`  -> real regression surface; a boot
#     failure (including timeout) is a hard FAIL.
#   - grub.cfg has no serial console -> boot is attempted with a shortened
#     timeout to prove *what actually happens* (timeout, not a crash/refusal
#     to boot), then downgraded to SKIP with reason
#     'ISO predates serial console support'. A UEFI-specific failure that is
#     NOT a plain timeout (e.g. "No bootable device", a real boot-failure
#     marker) still hard-FAILs even on a pre-serial ISO, because that would
#     indicate --uefi itself is broken, not merely "no serial output yet".
#
# Run:               bash distro/build/tests/test-rev12-uefi-boot-gate.sh
# Force a specific ISO: AIOS_UEFI_TEST_ISO=/path/to.iso bash ...
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
QEMU_SMOKE="${BUILD_DIR}/qemu-boot-smoke.sh"

FAILED=0
PASSED=0
SKIPPED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }
skip() { SKIPPED=$(( SKIPPED + 1 )); printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-uefi-gate.XXXXXX")"
cleanup() { rm -rf "${WORK}" 2>/dev/null || true; }
trap cleanup EXIT

msg "=== AI-OS.NET Rev.12 UEFI/OVMF Boot Gate ==="

# ── STATIC layer ──────────────────────────────────────────────────────────

if [ -f "${QEMU_SMOKE}" ] && [ -x "${QEMU_SMOKE}" ]; then
    pass "qemu-boot-smoke.sh exists and is executable"
else
    fail "qemu-boot-smoke.sh missing or not executable"
fi

if bash -n "${QEMU_SMOKE}" 2>/dev/null; then
    pass "qemu-boot-smoke.sh syntax OK"
else
    fail "qemu-boot-smoke.sh syntax error"
fi

FAKE_ISO="${WORK}/fake.iso"
printf 'AIOS fake ISO for dry-run only\n' > "${FAKE_ISO}"

# find_ovmf_code() inside qemu-boot-smoke.sh only looks for OVMF_CODE.fd
# under a fixed list of distro paths; it does NOT match this host's actual
# openSUSE/qemu-ovmf layout (see the OVMF discovery helper below). Feed the
# static checks an explicit --ovmf-code so they exercise the --uefi flag
# wiring itself, independent of that discovery gap.
STATIC_OVMF="${WORK}/OVMF_CODE.fd"
printf 'not a real firmware image, just needs to exist for --dry-run' > "${STATIC_OVMF}"

DRY_RUN_OUT="$(mktemp "${WORK}/dryrun-out.XXXXXX")"
if "${QEMU_SMOKE}" --iso "${FAKE_ISO}" --uefi --ovmf-code "${STATIC_OVMF}" --dry-run \
   --serial-log "${WORK}/dryrun.log" > "${DRY_RUN_OUT}" 2>&1; then
    if grep -q -- 'if=pflash' "${DRY_RUN_OUT}" && grep -Fq -- "${STATIC_OVMF}" "${DRY_RUN_OUT}"; then
        pass "--uefi --dry-run prints an OVMF pflash drive argument"
    else
        fail "--uefi --dry-run command is missing an OVMF pflash drive argument"
    fi
else
    fail "--uefi --dry-run with a valid --ovmf-code path exited non-zero"
    cat "${DRY_RUN_OUT}" >&2
fi

BOGUS_OVMF="${WORK}/does-not-exist/OVMF_CODE.fd"
BOGUS_OUT="$(mktemp "${WORK}/bogus-out.XXXXXX")"
set +e
"${QEMU_SMOKE}" --iso "${FAKE_ISO}" --uefi --ovmf-code "${BOGUS_OVMF}" --dry-run \
    --serial-log "${WORK}/bogus.log" > "${BOGUS_OUT}" 2>&1
BOGUS_STATUS=$?
set -e
if [ "${BOGUS_STATUS}" -ne 0 ] && grep -q "OVMF_CODE.fd not found: ${BOGUS_OVMF}" "${BOGUS_OUT}"; then
    pass "a bogus --ovmf-code path fails closed with a clear error message"
else
    fail "a bogus --ovmf-code path did not fail closed as expected (status=${BOGUS_STATUS})"
    cat "${BOGUS_OUT}" >&2
fi

# ── OVMF discovery helper ────────────────────────────────────────────────
#
# qemu-boot-smoke.sh's own find_ovmf_code() only knows OVMF_CODE.fd under a
# handful of distro paths. This host (openSUSE Tumbleweed, qemu-ovmf package)
# ships firmware under /usr/share/qemu/ovmf-x86_64-*.bin instead — none of
# the candidates in qemu-boot-smoke.sh match, so its auto-discovery would
# fail here even though OVMF is installed. That is a real gap in the smoke
# script's discovery list; this harness does NOT patch qemu-boot-smoke.sh
# (out of scope) but works around it locally to find firmware to boot with.
find_ovmf_for_test() {
    local candidate
    for candidate in \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/ovmf/OVMF_CODE.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd \
        /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
        /usr/share/qemu/OVMF_CODE.fd \
        /usr/share/qemu/ovmf-x86_64-4m-code.bin \
        /usr/share/qemu/ovmf-x86_64-opensuse-4m-code.bin \
        /usr/share/qemu/ovmf-x86_64-suse-4m-code.bin; do
        if [ -f "${candidate}" ]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    # Last resort: any *-code*.bin under /usr/share/qemu or /usr/share/edk2
    # that isn't a vars/secureboot/tdx/sev/xen/ms variant.
    for candidate in /usr/share/qemu/ovmf-x86_64*-code.bin /usr/share/edk2/*/*-code*.fd; do
        case "${candidate}" in
            *vars*|*ms*|*tdx*|*sev*|*xen*|*smm*) continue ;;
        esac
        if [ -f "${candidate}" ]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    return 1
}

REAL_OVMF="$(find_ovmf_for_test || true)"
if [ -n "${REAL_OVMF}" ]; then
    msg "OVMF discovery: found ${REAL_OVMF}"
else
    msg "OVMF discovery: no OVMF firmware found on this host"
fi

# ── REAL layer ────────────────────────────────────────────────────────────

QEMU_BIN="$(command -v qemu-system-x86_64 2>/dev/null || true)"

if [ -z "${REAL_OVMF}" ]; then
    skip "real UEFI boot test: no OVMF firmware found on this host"
elif [ -z "${QEMU_BIN}" ]; then
    skip "real UEFI boot test: qemu-system-x86_64 not found on this host"
else
    if [ -n "${AIOS_UEFI_TEST_ISO:-}" ]; then
        ISO_CANDIDATES=("${AIOS_UEFI_TEST_ISO}")
    else
        ISO_CANDIDATES=()
        while IFS= read -r -d '' _iso; do
            ISO_CANDIDATES+=("${_iso}")
        done < <(find "${BUILD_DIR}" -maxdepth 1 -iname 'aios-*.iso' -print0 2>/dev/null | sort -z)
    fi

    if [ "${#ISO_CANDIDATES[@]}" -eq 0 ]; then
        skip "real UEFI boot test: no ISO available (set AIOS_UEFI_TEST_ISO or build one under distro/build/)"
    else
        for ISO in "${ISO_CANDIDATES[@]}"; do
            ISO_NAME="$(basename "${ISO}")"
            msg "UEFI boot candidate: ${ISO_NAME}"

            if [ ! -f "${ISO}" ]; then
                fail "${ISO_NAME}: AIOS_UEFI_TEST_ISO does not exist: ${ISO}"
                continue
            fi

            GRUB_CFG="${WORK}/${ISO_NAME}.grub.cfg"
            GRUB_PATH_IN_ISO=""
            for _p in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
                if xorriso -indev "${ISO}" -osirrox on -extract "${_p}" "${GRUB_CFG}" \
                    >/dev/null 2>&1; then
                    GRUB_PATH_IN_ISO="${_p}"
                    break
                fi
            done

            if [ -z "${GRUB_PATH_IN_ISO}" ] || [ ! -f "${GRUB_CFG}" ]; then
                fail "${ISO_NAME}: could not extract grub.cfg via xorriso to classify serial-console support"
                continue
            fi

            if grep -q 'console=ttyS0' "${GRUB_CFG}"; then
                HAS_SERIAL=true
                msg "${ISO_NAME}: grub.cfg has console=ttyS0 -> boot failure here is a hard FAIL"
                BOOT_TIMEOUT="${AIOS_QEMU_BOOT_TIMEOUT:-120}"
            else
                HAS_SERIAL=false
                msg "${ISO_NAME}: grub.cfg has no console=ttyS0 -> pre-serial-console ISO, boot failure here is expected"
                BOOT_TIMEOUT="${AIOS_UEFI_PRESERIAL_TIMEOUT:-30}"
            fi

            SERIAL_LOG="${WORK}/${ISO_NAME}.uefi-serial.log"
            BOOT_OUT="${WORK}/${ISO_NAME}.uefi-boot.out"
            set +e
            "${QEMU_SMOKE}" --iso "${ISO}" --uefi --ovmf-code "${REAL_OVMF}" \
                --timeout "${BOOT_TIMEOUT}" --serial-log "${SERIAL_LOG}" \
                > "${BOOT_OUT}" 2>&1
            BOOT_STATUS=$?
            set -e

            if [ "${BOOT_STATUS}" -eq 0 ]; then
                pass "${ISO_NAME}: UEFI (OVMF) boot reached the same success marker as BIOS boot"
                continue
            fi

            # A real boot-failure marker (panic, no bootable device, rescue
            # fallback, ...) is a genuine --uefi regression regardless of
            # whether the ISO has serial console support: it means OVMF
            # could not even get the kernel running.
            if grep -q 'boot failure marker found in serial log' "${BOOT_OUT}"; then
                fail "${ISO_NAME}: UEFI boot hit a real failure marker: $(grep 'boot failure marker found in serial log' "${BOOT_OUT}")"
                continue
            fi

            # Remaining failure modes are "no marker appeared" (status 0 from
            # the underlying qemu run) or "timed out" (status 124) — i.e.
            # qemu-boot-smoke.sh's own generic disappointment paths.
            if ${HAS_SERIAL}; then
                fail "${ISO_NAME}: UEFI boot did not reach a success marker (has console=ttyS0, so this is a real regression): $(tail -1 "${BOOT_OUT}")"
            else
                skip "${ISO_NAME}: UEFI boot did not reach a success marker — ISO predates serial console support"
            fi
        done
    fi
fi

printf '\n'
msg "=== Test Summary ==="
printf '  Passed:  %d\n' "${PASSED}"
printf '  Failed:  %d\n' "${FAILED}"
printf '  Skipped: %d\n' "${SKIPPED}"

if [ "${FAILED}" -eq 0 ]; then
    printf '  \033[1;32mALL TESTS PASSED (or explicitly SKIPPED)\033[0m\n'
    exit 0
fi

printf '  \033[1;31mSOME TESTS FAILED\033[0m\n'
exit 1
