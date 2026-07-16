#!/bin/sh
#
# AI-OS.NET Rev.12 installer sanity test.
#
# Run: sh distro/build/tests/test-rev12-installer.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DISTRO_DIR="$(cd "${BUILD_DIR}/.." && pwd)"
BUILD_SCRIPT="${BUILD_DIR}/build-aios-iso.sh"
QUICK_INSTALL="${DISTRO_DIR}/installer/aios-quick-install.sh"
INTERACTIVE_INSTALL="${DISTRO_DIR}/installer/aios-installer.sh"
FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

msg "=== AI-OS.NET Rev.12 Installer Tests ==="

for _script in "${QUICK_INSTALL}" "${INTERACTIVE_INSTALL}"; do
    if [ -f "${_script}" ]; then
        pass "Installer script exists: ${_script#"${DISTRO_DIR}"/}"
    else
        fail "Installer script missing: ${_script#"${DISTRO_DIR}"/}"
    fi

    if bash -n "${_script}" 2>/dev/null; then
        pass "Installer syntax OK: ${_script#"${DISTRO_DIR}"/}"
    else
        fail "Installer syntax error: ${_script#"${DISTRO_DIR}"/}"
    fi
done

for _needle in \
    'AIOS_RECOVERY_SIZE_MB' \
    'AIOS_ROLLBACK_SIZE_MB' \
    'AIOS_RECOVERY' \
    'AIOS_ROLLBACK' \
    'RECOVERY_PART' \
    'ROLLBACK_PART' \
    '/recovery' \
    '/var/lib/aios/rollback' \
    'aios.install_layout.v1' \
    'aios.rollback_state.v1'; do
    if grep -q -- "${_needle}" "${QUICK_INSTALL}" 2>/dev/null \
       && grep -q -- "${_needle}" "${INTERACTIVE_INSTALL}" 2>/dev/null; then
        pass "Installers contain Rev.12 marker: ${_needle}"
    else
        fail "Installer missing Rev.12 marker: ${_needle}"
    fi
done

if grep -q 'aios-installer.sh' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q 'aios-quick-install.sh' "${BUILD_SCRIPT}" 2>/dev/null \
   && grep -q '/usr/lib/aios/install' "${BUILD_SCRIPT}" 2>/dev/null; then
    pass "Build script stages live installer tools"
else
    fail "Build script does not stage live installer tools"
fi

printf '\n'
msg "=== Boot chain: loader payload + initramfs (defect #12) ==="

# Pipeline 5309 installed "successfully" and then dropped to the EFI shell. Two
# causes, both silent: bootctl exited 0 having installed no .efi (the payload
# package was absent), and the loader entry named an initramfs that existed
# nowhere on the target. These assert the installer can no longer claim success
# in either case.
for _needle in \
    'do_initramfs' \
    'dracut --force --hostonly' \
    '/usr/lib/systemd/boot/efi/systemd-bootx64.efi' \
    'EFI/BOOT/BOOTX64.EFI' \
    'initramfs-aios.img'; do
    if grep -q -- "${_needle}" "${QUICK_INSTALL}" 2>/dev/null; then
        pass "Quick installer contains boot-chain marker: ${_needle}"
    else
        fail "Quick installer missing boot-chain marker: ${_needle}"
    fi
done

# Ordering is load-bearing, not cosmetic: veritysetup hashes the whole root
# device, so dracut's writes into the root must land BEFORE do_verity or the
# stored root hash no longer matches the filesystem it describes.
# dracut's own module resolution cannot be trusted from inside the installer's
# chroot: 90crypt/check() only volunteers when the *running* system's root sits
# on crypto_LUKS, and 91tpm2-tss/check() returns 255 (never volunteers at all).
# Naming both on --add is what forces them in; without tpm2-tss the installed
# system boots to a passphrase prompt instead of unlocking from the TPM.
if grep -qE '^\s*--add "[^"]*\btpm2-tss\b[^"]*"' "${QUICK_INSTALL}" 2>/dev/null; then
    pass "Quick installer force-adds tpm2-tss (dracut never volunteers it)"
else
    fail "Quick installer must --add tpm2-tss; dracut's check() returns 255 and will omit it"
fi

_ir_line="$(grep -n '^\s*do_initramfs\s*$' "${QUICK_INSTALL}" 2>/dev/null | tail -n1 | cut -d: -f1)"
_vr_line="$(grep -n '^\s*do_verity\s*$' "${QUICK_INSTALL}" 2>/dev/null | tail -n1 | cut -d: -f1)"
if [ -n "${_ir_line}" ] && [ -n "${_vr_line}" ] && [ "${_ir_line}" -lt "${_vr_line}" ]; then
    pass "Quick installer builds the initramfs before dm-verity hashes the root"
else
    fail "Quick installer must call do_initramfs before do_verity (got initramfs=${_ir_line:-none} verity=${_vr_line:-none})"
fi

printf '\n'
msg "=== TPM2 enrolment: real option, verified result (R13.4) ==="

# Both installers passed `--key-file` to systemd-cryptenroll, which has no such
# option. Every enrolment died with "unrecognized option" and the failure path
# only warned, so installs reported success with no TPM2 token in the LUKS2
# header. The correct option is --unlock-key-file=.
for _f in "${QUICK_INSTALL}" "${INTERACTIVE_INSTALL}"; do
    _name="$(basename "${_f}")"

    # Isolate the systemd-cryptenroll invocations: cryptsetup legitimately uses
    # --key-file, so a file-wide grep would give a false pass.
    _enroll="$(awk '/systemd-cryptenroll /{p=1} p{print} p&&/2>&1|2>\/dev\/null|--wipe-slot/{if(/\\$/)next; p=0}' "${_f}" 2>/dev/null)"

    if printf '%s' "${_enroll}" | grep -qE '^\s*--unlock-key-file='; then
        pass "${_name}: systemd-cryptenroll uses --unlock-key-file"
    else
        fail "${_name}: systemd-cryptenroll must use --unlock-key-file"
    fi

    if printf '%s' "${_enroll}" | grep -qE '^\s*--key-file'; then
        fail "${_name}: systemd-cryptenroll still passes the nonexistent --key-file"
    else
        pass "${_name}: no bare --key-file on systemd-cryptenroll"
    fi

    # --tpm2-public-key takes a PEM public key as INPUT. Both installers handed
    # it sealed-key.blob, an output path nothing wrote and nothing read.
    if grep -q 'tpm2-public-key.*sealed-key.blob' "${_f}" 2>/dev/null; then
        fail "${_name}: --tpm2-public-key still fed the bogus sealed-key.blob output path"
    else
        pass "${_name}: no bogus --tpm2-public-key sealed-key.blob"
    fi

    # An exit code is not evidence the token landed in the header.
    if grep -q 'luksDump' "${_f}" 2>/dev/null && grep -q 'systemd-tpm2' "${_f}" 2>/dev/null; then
        pass "${_name}: TPM2 enrolment is verified against the LUKS2 header"
    else
        fail "${_name}: TPM2 enrolment must be read back from the LUKS2 header, not assumed"
    fi
done

printf '\n'
msg "=== Recovery key must actually recover (defect #13) ==="

# Strip comments before matching: the code carries comments explaining these very
# defects, and a naive whole-file grep matches the explanation and reports a
# defect that is not there.
_qi_code="$(grep -vE '^\s*#' "${QUICK_INSTALL}" 2>/dev/null)"

# do_first_boot wrote /etc/aios/recovery-key.txt and installer/README.md told the
# operator it was their way back in -- but nothing ever called luksAddKey, so the
# file held a random number that unlocked nothing. A recovery key that does not
# recover is worse than none: it is relied on exactly once, when recovery is
# already needed.
if printf '%s' "${_qi_code}" | grep -q 'luksAddKey'; then
    pass "Quick installer enrols the recovery key into the LUKS2 header"
else
    fail "Quick installer writes a recovery key it never adds to LUKS (unlocks nothing)"
fi

if printf '%s' "${_qi_code}" | grep -q 'test-passphrase'; then
    pass "Quick installer proves the recovery key actually unlocks the volume"
else
    fail "Quick installer must verify the recovery key unlocks, not trust luksAddKey's exit code"
fi

printf '\n'
msg "=== TPM2 PCR binding happens where the PCRs are real (R13.4) ==="

# The installer runs in the live medium's boot chain, so PCR 0/1/7 it can measure
# are not the ones the installed system will have. Sealing against them at install
# time yielded a token that never unsealed: every boot fell through to a passphrase
# prompt while the LUKS header truthfully reported an enrolled TPM2 token. The
# install-time slot must therefore be unbound, and the real binding must happen on
# first boot from inside the installed system.
if printf '%s' "${_qi_code}" | grep -qE '^\s*--tpm2-pcrs=0\+1\+7'; then
    fail "Installer still seals against PCRs it measured in the wrong boot chain"
else
    pass "Installer does not bind PCRs it cannot know (bootstrap slot is unbound)"
fi

if grep -q '"0+1+7"' "${DISTRO_DIR}/first-boot/aios-first-boot.rs" 2>/dev/null \
   && grep -q -- '--tpm2-pcrs=' "${DISTRO_DIR}/first-boot/aios-first-boot.rs" 2>/dev/null; then
    pass "First-boot re-enrols TPM2 bound to the installed system's real PCRs"
else
    fail "First-boot must re-enrol with --tpm2-pcrs=0+1+7; otherwise the unbound bootstrap slot becomes permanent"
fi

if grep -q 'wipe-slot=tpm2' "${DISTRO_DIR}/first-boot/aios-first-boot.rs" 2>/dev/null; then
    pass "First-boot wipes the unbound bootstrap slot after re-enrolling"
else
    fail "First-boot must wipe the unbound bootstrap slot, or it survives alongside the bound one"
fi

printf '\n'
msg "=== The unlocked volume must appear under the name root= asks for ==="

# rd.luks.uuid=<uuid> assembles the volume as /dev/mapper/luks-<uuid>, ignoring
# the name /etc/crypttab gives it, while the loader entry asked for
# root=/dev/mapper/aios-cryptroot. The volume unlocked from the TPM correctly and
# unattended -- "Finished Cryptography Setup for luks-e75269b0-..." -- and the
# initqueue then waited out its timeout for a device name that was never going to
# appear, landing in the dracut emergency shell. The disk was open the whole time.
if printf '%s' "${_qi_code}" | grep -q 'rd.luks.uuid='; then
    fail "Loader entry uses rd.luks.uuid=, which names the device luks-<uuid>, not the name root= asks for"
else
    pass "Loader entry does not use rd.luks.uuid= (it names the device wrong)"
fi

if printf '%s' "${_qi_code}" | grep -q 'rd.luks.name=.*=aios-cryptroot'; then
    pass "Loader entry maps the LUKS UUID to aios-cryptroot explicitly"
else
    fail "Loader entry must use rd.luks.name=<uuid>=aios-cryptroot so the device matches root="
fi

# The two must agree. A test that checks each in isolation would pass a system
# where someone changed one of them.
if printf '%s' "${_qi_code}" | grep -q 'root=/dev/mapper/aios-cryptroot'; then
    pass "root= and the rd.luks.name mapping name the same device"
else
    fail "root= must name the same device rd.luks.name creates"
fi

printf '\n'
msg "=== dm-verity: no invented kernel parameters, no false claims ==="

# " verity dm_verity.roothash=<hash>" was emitted onto the kernel cmdline and both
# tokens were invented. Nothing in the base reads dm_verity.roothash (zero hits
# across /usr/lib/dracut), and the kernel's verdict on the bare word is "Unknown
# kernel command line parameters "verity", will be passed to user space" -- so it
# reached init as an argument. They bought no protection and were not harmless.
if printf '%s' "${_qi_code}" | grep -q 'dm_verity\.roothash='; then
    fail "Installer still emits dm_verity.roothash= — no code in the base reads it"
else
    pass "Installer emits no invented dm_verity.roothash= parameter"
fi

if printf '%s' "${_qi_code}" | grep -qE '_verity_params=" verity'; then
    fail "Installer still emits the bare 'verity' token — the kernel passes it to init as an argument"
else
    pass "Installer emits no bare 'verity' cmdline token"
fi

# The stored policy must describe what exists. It claimed fail_on_corruption:true
# for a check that was never wired up -- and a policy file is what an audit reads.
if printf '%s' "${_qi_code}" | grep -q '"fail_on_corruption": true'; then
    fail "verity policy claims fail_on_corruption while no boot-time check reads the hash"
else
    pass "verity policy does not claim enforcement that is not wired up"
fi

printf '\n'
msg "=== SELinux: reachable enforcing, real store, real cmdline (R13.7) ==="

# The quick installer was pinned to the retired Rev12 assumptions: SELINUXTYPE=aios
# and an enforcing guard keyed on /etc/selinux/aios/policy/policy.33 — a
# touchplaceholder stub that only mkrootfs.sh ever made. The R13 openSUSE base
# ships selinux-policy-targeted (/etc/selinux/targeted/policy/policy.34), so the
# guard tested for a file this pipeline never produces and enforcing could never
# be selected. R13.7 forbids permissive for STIG_ALIGNED / AIRGAP_HIGH.
# Strip comments before matching: the code carries a comment explaining these
# very defects, and a naive whole-file grep matches the explanation and reports
# a defect that is not there.
_qi_code="$(grep -vE '^\s*#' "${QUICK_INSTALL}" 2>/dev/null)"

if printf '%s' "${_qi_code}" | grep -q 'SELINUXTYPE=aios'; then
    fail "Quick installer still hardcodes SELINUXTYPE=aios (base ships 'targeted')"
else
    pass "Quick installer does not hardcode the retired 'aios' policy store"
fi

if printf '%s' "${_qi_code}" | grep -q 'selinux/aios/policy/policy\.33'; then
    fail "Quick installer still gates enforcing on the Rev12 placeholder policy.33"
else
    pass "Quick installer does not gate enforcing on the Rev12 placeholder"
fi

# Must discover the real policy the same way build-aios-iso.sh does.
if grep -q "path '\*/policy/policy\.\*'" "${QUICK_INSTALL}" 2>/dev/null; then
    pass "Quick installer detects the real compiled policy by path"
else
    fail "Quick installer must detect the real compiled binary policy, not a fixed path"
fi

# The kernel takes enforcing=0|1; a bare 'permissive' token is inert.
if printf '%s' "${_qi_code}" | grep -qE 'selinux=1 \$\{SELINUX_MODE\}'; then
    fail "Boot entry still emits a bare SELinux mode word the kernel ignores"
else
    pass "Boot entry does not emit a bare SELinux mode word"
fi

if printf '%s' "${_qi_code}" | grep -q 'enforcing=1' \
   && printf '%s' "${_qi_code}" | grep -q 'enforcing=0'; then
    pass "Boot entry carries the real kernel parameter (enforcing=0|1)"
else
    fail "Boot entry must carry enforcing=0|1"
fi

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
