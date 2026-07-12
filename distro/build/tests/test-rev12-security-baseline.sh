#!/bin/sh
#
# AI-OS.NET Rev.12 security baseline sanity test.
#
# Run: sh distro/build/tests/test-rev12-security-baseline.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"
INITRAMFS_INIT="${DISTRO_DIR}/aios-boot/initramfs/init"
PREINIT="${DISTRO_DIR}/aios-boot/initramfs/aios-preinit"
RESCUE="${DISTRO_DIR}/aios-boot/initramfs/rescue.sh"
QUICK_INSTALL="${DISTRO_DIR}/installer/aios-quick-install.sh"
INTERACTIVE_INSTALL="${DISTRO_DIR}/installer/aios-installer.sh"
FAILED=0
PASSED=0
SKIPPED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }
skip() { SKIPPED=$(( SKIPPED + 1 )); printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; }

check_file() {
    _label="$1"
    _file="$2"
    if [ -f "${_file}" ]; then
        pass "${_label}"
    else
        fail "${_label} missing: ${_file}"
    fi
}

check_bash_syntax() {
    _label="$1"
    _file="$2"
    if bash -n "${_file}" 2>/dev/null; then
        pass "${_label} syntax OK"
    else
        fail "${_label} syntax error"
    fi
}

check_grep() {
    _label="$1"
    _file="$2"
    _pattern="$3"
    if grep -E -q -- "${_pattern}" "${_file}" 2>/dev/null; then
        pass "${_label}"
    else
        fail "${_label}"
    fi
}

check_not_grep() {
    _label="$1"
    _file="$2"
    _pattern="$3"
    if grep -E -q -- "${_pattern}" "${_file}" 2>/dev/null; then
        fail "${_label}"
    else
        pass "${_label}"
    fi
}

# Read a dotted JSON path (e.g. selinux.policy_source) from a file; empty on miss.
json_field() {
    _jf_file="$1"
    _jf_path="$2"
    python3 - "${_jf_file}" "${_jf_path}" <<'PY' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
except Exception:
    sys.exit(0)
cur = d
for key in sys.argv[2].split('.'):
    if isinstance(cur, dict) and key in cur:
        cur = cur[key]
    else:
        sys.exit(0)
if isinstance(cur, bool):
    print("true" if cur else "false")
elif cur is None:
    print("")
else:
    print(cur)
PY
}

msg "=== AI-OS.NET Rev.12 Security Baseline Tests ==="

for _entry in \
    "Build script:${BUILD_SCRIPT}" \
    "Initramfs init:${INITRAMFS_INIT}" \
    "Preinit config:${PREINIT}" \
    "Rescue shell:${RESCUE}" \
    "Quick installer:${QUICK_INSTALL}" \
    "Interactive installer:${INTERACTIVE_INSTALL}"; do
    check_file "${_entry%%:*} exists" "${_entry#*:}"
done

for _entry in \
    "Build script:${BUILD_SCRIPT}" \
    "Initramfs init:${INITRAMFS_INIT}" \
    "Rescue shell:${RESCUE}" \
    "Quick installer:${QUICK_INSTALL}" \
    "Interactive installer:${INTERACTIVE_INSTALL}"; do
    check_bash_syntax "${_entry%%:*}" "${_entry#*:}"
done

msg "Build metadata and rootfs policy markers"
for _needle in \
    'AIOS_SECURITY_PROFILE' \
    'AIOS_SELINUX_MODE' \
    'AIOS_SELINUX_POLICY_SOURCE' \
    'AIOS_REQUIRE_BOOT_SIGNATURES' \
    'AIOS_SIGNATURE_SOURCE_DIR' \
    'aios.security_baseline.v1' \
    'aios.boot_chain_signing.v1' \
    'security.json' \
    'boot-chain.json' \
    '/etc/ima/ima-policy' \
    '/etc/evm/evm-policy' \
    'rootfs-policy.json' \
    'dm_verity.roothash' \
    'veritysetup format' \
    'aios.squashfs.verity' \
    'aios.verity.roothash' \
    'Generating dm-verity hash tree' \
    'Boot-chain signature required but missing' \
    'Rev.12 security metadata' \
    'Rev.12 boot chain metadata'; do
    check_grep "Build script marker: ${_needle}" "${BUILD_SCRIPT}" "${_needle}"
done

# Guard moved after policy detection: enforcing is allowed without
# --selinux-policy-source when the base rootfs ships a real policy, but a
# placeholder must still fail closed.
check_grep "Build blocks enforcing without a real policy (post-detection guard)" "${BUILD_SCRIPT}" 'SELinux enforcing requires a real policy'
check_grep "Enforcing guard is placement-correct (checks SELINUX_POLICY_PRESENT)" "${BUILD_SCRIPT}" 'AIOS_SELINUX_MODE}" = "enforcing" \] && \[ "\${SELINUX_POLICY_PRESENT}" != true'

msg "SELinux base-rootfs policy sourcing markers (R12.6)"
for _needle in \
    'SELINUX_POLICY_SOURCE' \
    'SELINUX_POLICY_PRESENT' \
    'SELINUX_POLICY_SHA256' \
    'SELINUX_POLICY_REL_PATH' \
    'base-rootfs' \
    "policy/policy\\.\\*" \
    'security=selinux selinux=1 enforcing=0'; do
    check_grep "Build script SELinux marker: ${_needle}" "${BUILD_SCRIPT}" "${_needle}"
done
check_grep "openSUSE base ships a real SELinux policy package" \
    "${BUILD_DIR}/build-opensuse-rootfs.sh" 'selinux-policy-targeted'
check_grep "Build stages IMA policy into initramfs" "${BUILD_SCRIPT}" 'INITRAMFS_DIR}/etc/ima/ima-policy'
check_grep "Build stages EVM policy into initramfs" "${BUILD_SCRIPT}" 'INITRAMFS_DIR}/etc/evm/evm-policy'

msg "Initramfs security enforcement markers"
for _needle in \
    'AIOS_IMA_POLICY' \
    'AIOS_EVM_POLICY' \
    'Loading IMA policy' \
    'dm_verity.roothash' \
    'dm-verity required but root hash is missing' \
    'dm-verity required but data/hash device is missing' \
    'dm-verity verification failed'; do
    check_grep "Initramfs marker: ${_needle}" "${INITRAMFS_INIT}" "${_needle}"
done
check_not_grep "Initramfs no longer ignores dm-verity corruption" "${INITRAMFS_INIT}" '--ignore-corruption'
check_grep "Preinit defines IMA policy path" "${PREINIT}" 'AIOS_IMA_POLICY=/etc/ima/ima-policy'
check_grep "Preinit defines EVM policy path" "${PREINIT}" 'AIOS_EVM_POLICY=/etc/evm/evm-policy'

msg "Installer consistency markers"
# shellcheck disable=SC2016
for _needle in \
    'AIOS_HASH' \
    'ROOT_HASH_PART' \
    'ROOT_HASH_DEV' \
    'AIOS_HASH_SIZE_MB' \
    'roothash.sig' \
    'dm_verity.roothash' \
    'AIOS_SELINUX_MODE' \
    'SELINUX=\${SELINUX_MODE}' \
    'Placeholder/no policy|placeholder/no policy'; do
    check_grep "Interactive installer marker: ${_needle}" "${INTERACTIVE_INSTALL}" "${_needle}"
done

# shellcheck disable=SC2016
for _needle in \
    'AIOS_HASH' \
    'ROOT_HASH_PART' \
    'ROOT_HASH_DEV' \
    'AIOS_HASH_SIZE_MB' \
    'roothash.sig' \
    'dm_verity.roothash' \
    'AIOS_SELINUX_MODE' \
    'SELINUX=\${SELINUX_MODE}'; do
    check_grep "Quick installer marker: ${_needle}" "${QUICK_INSTALL}" "${_needle}"
done

msg "Recovery repair markers"
check_grep "Rescue provides security policy repair command" "${RESCUE}" 'aios-repair-security-policy'
check_grep "Rescue provides rollback state repair command" "${RESCUE}" 'aios-repair-rollback-state'
check_grep "Rescue repair touches autorelabel" "${RESCUE}" '\.autorelabel'

# ─────────────────────────────────────────────────────────────────────────
# Dynamic layer: run the cheap scaffold build and PROVE dm-verity is real —
# a hash tree file is emitted, `veritysetup verify` succeeds against the
# recorded root hash, and the security.json metadata matches the artifacts on
# disk. This is the authoritative evidence that dm-verity is REAL, not staged.
#
# SKIPs (never FAILs) when a build prerequisite is missing. dm-verity assertions
# SKIP explicitly when veritysetup is absent (the build then honestly records
# status "unavailable", which we still assert).
# ─────────────────────────────────────────────────────────────────────────

msg "dm-verity dynamic proof (scaffold build)"

DYN_OK=true
for _tool in mksquashfs xorriso cargo python3; do
    if ! command -v "${_tool}" >/dev/null 2>&1; then
        skip "dm-verity dynamic build (${_tool} not on PATH — required to reach Step 11)"
        DYN_OK=false
    fi
done

if [ "${DYN_OK}" = true ]; then
    VERITY_PRESENT=true
    command -v veritysetup >/dev/null 2>&1 || VERITY_PRESENT=false

    WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/aios-rev12-verity-test.XXXXXX")"
    BUILD_LOG="${WORKDIR}/build.log"
    ISO_STAGING="${WORKDIR}/iso"
    SQUASHFS="${ISO_STAGING}/live/aios.squashfs"
    VERITY_FILE="${ISO_STAGING}/live/aios.squashfs.verity"
    SECURITY_JSON="${ISO_STAGING}/aios/security.json"

    msg "Running scaffold build in ${WORKDIR} (log: ${BUILD_LOG})"
    BUILD_EXIT=0
    AIOS_BUILD_WORKDIR="${WORKDIR}" \
        "${BUILD_SCRIPT}" \
            --debug \
            --allow-scaffold-rootfs \
            --kernel-modules-source none \
            --kernel-firmware-source none \
            --output "${WORKDIR}/aios-verity-test.iso" \
            --jobs "$(nproc 2>/dev/null || echo 2)" \
            > "${BUILD_LOG}" 2>&1 || BUILD_EXIT=$?

    if [ -f "${SECURITY_JSON}" ]; then
        pass "Build reached Step 11: security.json emitted (build exit=${BUILD_EXIT})"
    else
        fail "Build did NOT reach Step 11 — security.json missing (build exit=${BUILD_EXIT})"
        printf '  --- last 40 lines of build log ---\n' >&2
        tail -n 40 "${BUILD_LOG}" >&2 2>/dev/null || true
    fi

    # Read metadata fields with python3 (tab-separated: status<TAB>root_hash<TAB>hashtree_path<TAB>hashtree_sha256).
    META_STATUS=""
    META_ROOTHASH=""
    META_HASHTREE=""
    META_HASHTREE_SHA=""
    if [ -f "${SECURITY_JSON}" ]; then
        _meta="$(python3 - "${SECURITY_JSON}" <<'PY' 2>/dev/null || true
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
v = d.get("dm_verity", {})
def s(x):
    return "" if x is None else str(x)
print("\t".join([s(v.get("status")), s(v.get("root_hash")),
                 s(v.get("hashtree_path")), s(v.get("hashtree_sha256"))]))
PY
)"
        META_STATUS="$(printf '%s' "${_meta}" | cut -f1)"
        META_ROOTHASH="$(printf '%s' "${_meta}" | cut -f2)"
        META_HASHTREE="$(printf '%s' "${_meta}" | cut -f3)"
        META_HASHTREE_SHA="$(printf '%s' "${_meta}" | cut -f4)"
    fi

    if [ "${VERITY_PRESENT}" = true ]; then
        # 1. hash tree artifact exists
        if [ -f "${VERITY_FILE}" ]; then
            pass "dm-verity hash tree artifact exists: live/aios.squashfs.verity"
        else
            fail "dm-verity hash tree artifact missing: ${VERITY_FILE}"
        fi

        # 2. metadata status is 'present' with a non-empty root hash
        if [ "${META_STATUS}" = "present" ] && [ -n "${META_ROOTHASH}" ]; then
            pass "security.json dm_verity.status=present with root_hash=${META_ROOTHASH}"
        else
            fail "security.json dm_verity status/root_hash wrong (status='${META_STATUS}' root_hash='${META_ROOTHASH}')"
        fi

        # 3. veritysetup verify passes against the RECORDED root hash (real crypto check)
        if [ -f "${SQUASHFS}" ] && [ -f "${VERITY_FILE}" ] && [ -n "${META_ROOTHASH}" ]; then
            if veritysetup verify "${SQUASHFS}" "${VERITY_FILE}" "${META_ROOTHASH}" >/dev/null 2>&1; then
                pass "veritysetup verify PASSES against recorded root hash (dm-verity is REAL)"
            else
                fail "veritysetup verify FAILED against recorded root hash — hash tree or metadata is bogus"
            fi
        else
            fail "Cannot run veritysetup verify — squashfs/verity/root_hash inputs incomplete"
        fi

        # 4. metadata hashtree_path + hashtree_sha256 match the artifact on disk
        if [ "${META_HASHTREE}" = "live/aios.squashfs.verity" ]; then
            pass "security.json hashtree_path matches artifact"
        else
            fail "security.json hashtree_path mismatch (got '${META_HASHTREE}')"
        fi
        if [ -f "${VERITY_FILE}" ]; then
            _actual_sha="$(sha256sum "${VERITY_FILE}" | awk '{print $1}')"
            if [ "${META_HASHTREE_SHA}" = "${_actual_sha}" ]; then
                pass "security.json hashtree_sha256 matches artifact on disk"
            else
                fail "security.json hashtree_sha256 mismatch (meta='${META_HASHTREE_SHA}' disk='${_actual_sha}')"
            fi
        fi

        # 5. manifest + SHA256SUMS reference the verity artifact
        check_grep "manifest.json references verity artifact" \
            "${ISO_STAGING}/aios/manifest.json" 'live/aios.squashfs.verity'
        check_grep "SHA256SUMS references verity artifact" \
            "${ISO_STAGING}/aios/SHA256SUMS" 'live/aios.squashfs.verity'

        # 6. GRUB debug entry carries the real root hash
        check_grep "GRUB debug entry carries real root hash" \
            "${ISO_STAGING}/boot/grub/grub.cfg" "aios.verity.roothash=${META_ROOTHASH}"
    else
        skip "dm-verity crypto assertions (veritysetup not on PATH)"
        # Even without veritysetup the build must be HONEST: status 'unavailable', no fake hash.
        if [ "${META_STATUS}" = "unavailable" ] && [ -z "${META_ROOTHASH}" ]; then
            pass "security.json honestly records dm_verity.status=unavailable with no fabricated hash"
        else
            fail "security.json dishonest without veritysetup (status='${META_STATUS}' root_hash='${META_ROOTHASH}')"
        fi
    fi

    # ── SELinux honesty (scaffold = NO policy present) ───────────────────────
    # A scaffold build has no base rootfs and no --selinux-policy-source, so the
    # only honest outcome is: policy_source=placeholder, policy_present=false,
    # and the default GRUB entry carries NO selinux kernel args.
    msg "SELinux scaffold honesty (no policy present)"
    if [ -f "${SECURITY_JSON}" ]; then
        _sel_source="$(json_field "${SECURITY_JSON}" selinux.policy_source)"
        _sel_present="$(json_field "${SECURITY_JSON}" selinux.policy_present)"
        _sel_sha="$(json_field "${SECURITY_JSON}" selinux.policy_sha256)"
        if [ "${_sel_source}" = "placeholder" ] && [ "${_sel_present}" = "false" ]; then
            pass "scaffold security.json honestly records policy_source=placeholder / policy_present=false"
        else
            fail "scaffold security.json dishonest (source='${_sel_source}' present='${_sel_present}')"
        fi
        if [ -z "${_sel_sha}" ]; then
            pass "scaffold security.json has no fabricated policy sha256"
        else
            fail "scaffold security.json fabricated a policy sha256 for a placeholder ('${_sel_sha}')"
        fi
        _grub="${ISO_STAGING}/boot/grub/grub.cfg"
        if [ -f "${_grub}" ] && grep -E 'loglevel=3' "${_grub}" | grep -q 'security=selinux'; then
            fail "scaffold default GRUB entry carries selinux args without a policy"
        else
            pass "scaffold default GRUB entry carries NO selinux kernel args (correct for placeholder)"
        fi
    else
        skip "SELinux scaffold honesty (security.json missing)"
    fi

    if [ "${AIOS_TEST_KEEP_WORKDIR:-0}" != "1" ]; then
        rm -rf "${WORKDIR}"
    fi

    # ── SELinux present-policy proof (synthetic base rootfs) ──────────────────
    # Build with a minimal base rootfs that already carries a genuine binary
    # policy at /etc/selinux/targeted/policy/policy.NN (mirrors the R13.1 openSUSE
    # selinux-policy-targeted layout). The build must KEEP that policy, record
    # policy_source=base-rootfs with the real sha256, and put permissive selinux
    # args on the default GRUB entry.
    msg "SELinux present-policy proof (synthetic base rootfs)"
    BASE_ROOTFS="$(mktemp -d "${TMPDIR:-/tmp}/aios-rev12-selinux-base.XXXXXX")"
    B_WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-rev12-selinux-build.XXXXXX")"
    B_STAGING="${B_WORK}/iso"
    B_SECJSON="${B_STAGING}/aios/security.json"
    B_GRUB="${B_STAGING}/boot/grub/grub.cfg"
    # Minimal init + update deps so build-aios-iso accepts the base rootfs.
    mkdir -p "${BASE_ROOTFS}/sbin" "${BASE_ROOTFS}/usr/bin" \
        "${BASE_ROOTFS}/etc/selinux/targeted/policy"
    printf '#!/bin/sh\nexec /sbin/init "$@"\n' > "${BASE_ROOTFS}/sbin/init"
    chmod 755 "${BASE_ROOTFS}/sbin/init"
    for _dep in bash jq openssl sha256sum; do
        printf '#!/bin/sh\n:\n' > "${BASE_ROOTFS}/usr/bin/${_dep}"
        chmod 755 "${BASE_ROOTFS}/usr/bin/${_dep}"
    done
    # Synthetic binary policy blob (deterministic content → known sha256).
    head -c 4096 /dev/urandom > "${BASE_ROOTFS}/etc/selinux/targeted/policy/policy.35"
    SYNTH_SHA="$(sha256sum "${BASE_ROOTFS}/etc/selinux/targeted/policy/policy.35" | awk '{print $1}')"

    B_EXIT=0
    AIOS_BUILD_WORKDIR="${B_WORK}" \
        "${BUILD_SCRIPT}" \
            --debug \
            --base-rootfs "${BASE_ROOTFS}" \
            --kernel-modules-source none \
            --kernel-firmware-source none \
            --output "${B_WORK}/aios-selinux-test.iso" \
            --jobs "$(nproc 2>/dev/null || echo 2)" \
            > "${B_WORK}/build.log" 2>&1 || B_EXIT=$?

    if [ -f "${B_SECJSON}" ]; then
        pass "present-policy build reached Step 11: security.json emitted (exit=${B_EXIT})"
        _b_source="$(json_field "${B_SECJSON}" selinux.policy_source)"
        _b_type="$(json_field "${B_SECJSON}" selinux.policy_type)"
        _b_present="$(json_field "${B_SECJSON}" selinux.policy_present)"
        _b_sha="$(json_field "${B_SECJSON}" selinux.policy_sha256)"
        _b_path="$(json_field "${B_SECJSON}" selinux.policy_path)"
        if [ "${_b_source}" = "base-rootfs" ] && [ "${_b_present}" = "true" ] && [ "${_b_type}" = "targeted" ]; then
            pass "security.json records policy_source=base-rootfs, type=targeted, present=true"
        else
            fail "security.json wrong for base-rootfs policy (source='${_b_source}' type='${_b_type}' present='${_b_present}')"
        fi
        if [ "${_b_path}" = "/etc/selinux/targeted/policy/policy.35" ]; then
            pass "security.json policy_path points at the real base-rootfs policy"
        else
            fail "security.json policy_path wrong ('${_b_path}')"
        fi
        if [ "${_b_sha}" = "${SYNTH_SHA}" ]; then
            pass "security.json policy_sha256 matches the staged policy file (real hash)"
        else
            fail "security.json policy_sha256 mismatch (meta='${_b_sha}' file='${SYNTH_SHA}')"
        fi
        if [ -f "${B_GRUB}" ] && grep -E 'loglevel=3' "${B_GRUB}" | grep -q 'security=selinux selinux=1 enforcing=0'; then
            pass "default GRUB entry carries permissive selinux args (security=selinux enforcing=0)"
        else
            fail "default GRUB entry missing permissive selinux args"
        fi
    else
        fail "present-policy build did NOT reach Step 11 — security.json missing (exit=${B_EXIT})"
        printf '  --- last 40 lines of build log ---\n' >&2
        tail -n 40 "${B_WORK}/build.log" >&2 2>/dev/null || true
    fi

    if [ "${AIOS_TEST_KEEP_WORKDIR:-0}" != "1" ]; then
        rm -rf "${BASE_ROOTFS}" "${B_WORK}"
    fi
fi

printf '\n'
msg "=== Test Summary ==="
printf '  Passed:  %d\n' "${PASSED}"
printf '  Failed:  %d\n' "${FAILED}"
printf '  Skipped: %d\n' "${SKIPPED}"

if [ "${FAILED}" -eq 0 ]; then
    printf '  \033[1;32mALL TESTS PASSED\033[0m\n'
    exit 0
fi

printf '  \033[1;31mSOME TESTS FAILED\033[0m\n'
exit 1
