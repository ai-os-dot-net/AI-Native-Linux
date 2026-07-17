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
# The module set is now assembled in a _dracut_modules variable and passed as
# --add "${_dracut_modules}". Assert both: tpm2-tss is in that set AND the set is
# force-added. (grep the raw file — the variable spans its own line.)
if grep -qE '_dracut_modules="[^"]*\btpm2-tss\b' "${QUICK_INSTALL}" 2>/dev/null \
   && grep -qE '^\s*--add "\$\{_dracut_modules\}"' "${QUICK_INSTALL}" 2>/dev/null; then
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

printf '\n'
msg "=== dm-verity is ENFORCED: real systemd verity params, verity device as root ==="

# Under enforcement root= no longer names the LUKS mapper — it names the verity
# device the systemd veritysetup generator creates. That generator hardcodes the
# volume name "root", so the device is /dev/mapper/root (NOT a configurable
# "aios-verity"). The LUKS mapper is now the verity DATA device instead.
if printf '%s' "${_qi_code}" | grep -q '_root_dev="/dev/mapper/root"'; then
    pass "Loader boots root=/dev/mapper/root (the systemd verity device) under enforcement"
else
    fail "Under verity, root= must name the generator's verity device /dev/mapper/root"
fi

# The verity data device must be the same LUKS mapper rd.luks.name creates, or the
# hash tree (built over that mapper) is checked against the wrong bytes. Checking
# them together, not in isolation, catches a change to only one.
if printf '%s' "${_qi_code}" | grep -q 'systemd.verity_root_data=/dev/mapper/aios-cryptroot' \
   && printf '%s' "${_qi_code}" | grep -q 'rd.luks.name=.*=aios-cryptroot'; then
    pass "verity data device is the LUKS mapper rd.luks.name creates (they agree)"
else
    fail "systemd.verity_root_data= must be /dev/mapper/aios-cryptroot, the rd.luks.name device"
fi

# The hash device is referenced by PARTUUID (stable, superblock-independent,
# resolved early by udev; the generator runs it through fstab_node_to_udev_node).
if printf '%s' "${_qi_code}" | grep -q 'systemd.verity_root_hash=PARTUUID='; then
    pass "verity hash device is referenced by PARTUUID"
else
    fail "systemd.verity_root_hash= must reference the hash partition by PARTUUID="
fi

# panic-on-corruption IS the enforcement: the kernel dm-verity target refuses to
# serve a block whose hash does not match. This is the byte-flip acceptance
# property — flip a byte in /usr and the machine must refuse to boot.
if printf '%s' "${_qi_code}" | grep -q 'systemd.verity_root_options=panic-on-corruption'; then
    pass "verity uses panic-on-corruption (kernel refuses a tampered block)"
else
    fail "verity must set systemd.verity_root_options=panic-on-corruption"
fi

# roothash= is the generator's real input; dm_verity.roothash= and the bare
# 'verity' token were invented and read by nothing. They must not return.
if printf '%s' "${_qi_code}" | grep -qE '\broothash=\$\{_roothash\}|\broothash=[0-9a-f]'; then
    pass "cmdline carries the real roothash= parameter"
else
    fail "cmdline must carry roothash= for the systemd veritysetup generator"
fi
if printf '%s' "${_qi_code}" | grep -q 'dm_verity\.roothash='; then
    fail "Installer still emits the invented dm_verity.roothash= — nothing reads it"
else
    pass "Installer emits no invented dm_verity.roothash= parameter"
fi
if printf '%s' "${_qi_code}" | grep -qE '_verity_params=" verity'; then
    fail "Installer still emits the bare 'verity' token"
else
    pass "Installer emits no bare 'verity' cmdline token"
fi

# The stored policy must describe what exists. Now that enforcement IS wired, it
# must truthfully say so — the inverse of the pre-enforcement state.
if printf '%s' "${_qi_code}" | grep -q '"fail_on_corruption": true' \
   && printf '%s' "${_qi_code}" | grep -q '"enforced_at_boot": true' \
   && printf '%s' "${_qi_code}" | grep -q '"status": "ENFORCED"'; then
    pass "verity policy truthfully reports enforcement (wired to the cmdline)"
else
    fail "verity policy must report enforced_at_boot/fail_on_corruption true, status ENFORCED"
fi
if printf '%s' "${_qi_code}" | grep -q 'COMPUTED_NOT_ENFORCED'; then
    fail "verity policy still carries the old COMPUTED_NOT_ENFORCED status"
else
    pass "verity policy no longer claims the pre-enforcement state"
fi

# CRITICAL: the root bytes must be frozen before hashing and never touched after,
# or the kernel panics "dm-verity device corrupted" on a pristine install. Assert
# do_verity remounts the root read-only BEFORE veritysetup format runs. Both
# strings are unique to do_verity, so compare their global line numbers.
_remount_ln="$(printf '%s\n' "${_qi_code}" | grep -n 'remount,ro' | head -1 | cut -d: -f1)"
_format_ln="$(printf '%s\n' "${_qi_code}" | grep -n 'veritysetup format' | head -1 | cut -d: -f1)"
if [ -n "${_remount_ln}" ] && [ -n "${_format_ln}" ] && [ "${_remount_ln}" -lt "${_format_ln}" ]; then
    pass "do_verity freezes the root (remount,ro) BEFORE veritysetup format"
else
    fail "do_verity must remount the root read-only before hashing (else fresh install panics dm-verity corrupted)"
fi
# The root hash must NOT be written into the verity-protected root (that write
# would change the hashed bytes). do_verity stores it in a shell global; the
# roothash.sig file inside the root is gone.
if printf '%s\n' "${_qi_code}" | grep -qE 'root-hash-file=.*TARGET_MOUNT'; then
    fail "do_verity writes the root hash file INTO the root — that invalidates the hash at boot"
else
    pass "do_verity keeps the root-hash file out of the verity root"
fi
if printf '%s\n' "${_qi_code}" | grep -q 'ROOT_HASH_VALUE=\$(head'; then
    pass "do_verity exports the root hash via a shell global (not a root-internal file)"
else
    fail "do_verity must export the root hash via ROOT_HASH_VALUE for do_bootloader"
fi
# do_bootloader must consume that global, not read a file from the frozen root.
if printf '%s\n' "${_qi_code}" | grep -q '_roothash="${ROOT_HASH_VALUE}"'; then
    pass "do_bootloader reads the root hash from the shell global, not the frozen root"
else
    fail "do_bootloader must read ROOT_HASH_VALUE (the root is frozen ro and has no roothash file)"
fi

# The systemd-veritysetup dracut module installs the userspace tool but has no
# installkernel(), so it never pulls the kernel dm-verity target. Under hostonly
# dracut also will not auto-include it (the installer chroot uses no verity), so
# the initramfs would ship without dm-verity.ko and boot dies with "verity:
# unknown target type". The installer must force the driver in.
if printf '%s' "${_qi_code}" | grep -qE '_dracut_drivers=.*dm-verity' \
   && printf '%s' "${_qi_code}" | grep -q 'add-drivers'; then
    pass "Installer force-adds the dm-verity kernel driver into the initramfs"
else
    fail "Installer must --add-drivers dm-verity (systemd-veritysetup does not pull the kernel target)"
fi
# ...and must fail closed if the driver did not actually land in the image, rather
# than discovering the missing target at boot.
if printf '%s' "${_qi_code}" | grep -q 'has no dm-verity.ko'; then
    pass "Installer fails closed if dm-verity.ko is absent from the built initramfs"
else
    fail "Installer must verify dm-verity.ko is in the initramfs and die if it is not"
fi
# The initramfs/live-installer grep proved unreliable for substring tests (a
# grep -qF that should have matched "dm-verity.ko" in the listing cried wolf on
# an image that carried it). The module and key-leak checks that run there must
# therefore match with a bash `case` (a builtin, no external grep), not any grep.
if printf '%s' "${_qi_code}" | grep -qF '*dm-verity.ko*)' \
   && printf '%s' "${_qi_code}" | grep -qF '*overlay.ko*)'; then
    pass "initramfs module checks use a bash case (grep-free), immune to the installer's grep"
else
    fail "dm-verity.ko / overlay.ko checks must match with a bash case, not an external grep"
fi
if printf '%s' "${_qi_code}" | grep -qF '*etc/aios/var.key*|*/cryptsetup-keys.d/aios-var*)'; then
    pass "The /var key-leak guard matches with a bash case (cannot fail open on a grep quirk)"
else
    fail "The /var key-leak guard must match with a bash case, not an external grep"
fi
# And must not regress to the escaped-dot ERE that silently neutered the guard.
if printf '%s' "${_qi_code}" | grep -qF 'grep -qE "etc/aios/var\.key'; then
    fail "The /var key-leak guard reintroduced the escaped-dot ERE — busybox would fail it open"
else
    pass "The /var key-leak guard carries no escaped-dot ERE"
fi

printf '\n'
msg "=== dm-verity enforcement fails closed, and the boot chain is wired ==="

# do_verity must die on a failed hash build, not warn-and-return: do_bootloader
# is about to point root= at the verity device, so a missing hash is unbootable.
# Extract to the next top-level section marker, NOT the first '^}' — do_verity now
# contains a JSON heredoc whose closing brace sits at column 0 and would truncate
# a '/^}/' range before the die lines below it.
_verity_body="$(sed -n '/^do_verity()/,/^# ── SELinux/p' "${QUICK_INSTALL}" 2>/dev/null | grep -vE '^\s*#')"
if printf '%s' "${_verity_body}" | grep -q 'die "dm-verity hash generation failed'; then
    pass "do_verity dies on a failed hash build (no warn-and-continue)"
else
    fail "do_verity must die when the hash build fails under enforcement"
fi

# The initramfs must carry systemd-veritysetup (opens the verity device) and
# aios-etc-overlay (writable /etc on the read-only root). Both are force-added
# because their check() self-disables under hostonly.
if printf '%s' "${_qi_code}" | grep -qE '_dracut_modules=.*systemd-veritysetup'; then
    pass "do_initramfs force-adds systemd-veritysetup (verity never volunteers it)"
else
    fail "do_initramfs must --add systemd-veritysetup or the verity device never opens"
fi
if printf '%s' "${_qi_code}" | grep -qE '_dracut_modules=.*aios-etc-overlay'; then
    pass "do_initramfs force-adds aios-etc-overlay (writable /etc)"
else
    fail "do_initramfs must --add aios-etc-overlay for the read-only root's /etc"
fi

# The installer must stage the custom overlay module (dracut's own 90overlayfs
# excludes itself under hostonly).
if printf '%s' "${_qi_code}" | grep -q '98aios-etc-overlay' \
   && printf '%s' "${_qi_code}" | grep -q 'lowerdir=.*upperdir=.*workdir='; then
    pass "Installer stages the 98aios-etc-overlay dracut module with an overlay mount"
else
    fail "Installer must stage a custom /etc overlay dracut module"
fi

# The read-only root must be mounted ro in fstab, or systemd tries a remount-rw
# the verity device refuses.
if printf '%s' "${_qi_code}" | grep -qE '_root_fstab="/dev/mapper/root\s+/\s+ext4\s+ro'; then
    pass "fstab mounts the verity root read-only"
else
    fail "fstab root line must mount /dev/mapper/root read-only under verity"
fi

# do_bootloader writes the verity cmdline, so it must run AFTER do_verity emits
# the hash. (do_initramfs-before-do_verity is asserted separately above.)
_vr_line="$(grep -n '^\s*do_verity\s*$' "${QUICK_INSTALL}" 2>/dev/null | tail -n1 | cut -d: -f1)"
_bl_line="$(grep -n '^\s*do_bootloader\s*$' "${QUICK_INSTALL}" 2>/dev/null | tail -n1 | cut -d: -f1)"
if [ -n "${_vr_line}" ] && [ -n "${_bl_line}" ] && [ "${_vr_line}" -lt "${_bl_line}" ]; then
    pass "do_verity runs before do_bootloader (hash exists before the cmdline is written)"
else
    fail "do_verity must run before do_bootloader (got verity=${_vr_line:-none} bootloader=${_bl_line:-none})"
fi

printf '\n'
msg "=== First-boot state lives off the read-only root ==="

# Host keypair and host-id must be written to the encrypted /var, not the
# read-only root (and not into the /etc overlay upper by side effect).
_fb_src="${DISTRO_DIR}/first-boot/aios-first-boot.rs"
if grep -qE 'HOST_KEY_PRIV:\s*&str\s*=\s*"/var/lib/aios/' "${_fb_src}" 2>/dev/null \
   && grep -qE 'HOST_ID_FILE:\s*&str\s*=\s*"/var/lib/aios/' "${_fb_src}" 2>/dev/null; then
    pass "first-boot writes host keypair and host-id to /var/lib/aios (off the ro root)"
else
    fail "first-boot host key/host-id must live under /var/lib/aios, not /etc on the ro root"
fi

printf '\n'
msg "=== The image must ship the mount points a read-only root cannot create ==="

# mksquashfs excluded `run`, `proc`, `sys`, `dev`, `tmp` and `mnt` as bare names,
# which drops the directories, not just their contents. do_deploy unsquashes this
# same image onto the installed disk, so the installed root had no mount points at
# all. Its root mounts read-only, so PID 1 could not create them either:
#   "Failed to create /sysroot/run: Read-only file system"
#   "Failed to switch root, trying to continue: No such file or directory"
# switch-root retried six times and fell into the dracut emergency shell -- on a
# system whose disk had already unlocked from the TPM and whose root had mounted.
_excl="$(sed -n '/^cat > "${EXCLUDE_FILE}"/,/^EOF$/p' "${BUILD_SCRIPT}" 2>/dev/null)"
for _d in proc sys dev run tmp mnt; do
    if printf '%s' "${_excl}" | grep -qE "^${_d}$"; then
        fail "squashfs excludes bare '${_d}' — that drops the mount point, not just its contents"
    else
        pass "squashfs keeps the '${_d}' mount point"
    fi
done

printf '\n'
msg "=== Immutable-root step 1: writable state lives on a separate encrypted /var ==="

# A verity-protected root is read-only by construction, so every writer that
# lives on the root today (systemd machine-id/logs, first-boot keys/evidence)
# must move to a separate volume before verity can be enforced. Step 1 carves out
# an encrypted /var. It must be encrypted -- a plaintext /var would put logs,
# evidence and machine state on disk in the clear, worse than the status quo --
# and it must be unlocked from a key on the already-unlocked root, so the whole
# chain still hangs off the single TPM2 enrolment rather than a second one.
if printf '%s' "${_qi_code}" | grep -q 'AIOS_VAR'; then
    pass "Installer creates a dedicated AIOS_VAR partition"
else
    fail "Installer must create a separate /var partition for writable state"
fi

if printf '%s' "${_qi_code}" | grep -qE 'luksFormat[^\n]*VAR_PART|VAR_PART[^\n]*luksFormat' \
   || printf '%s' "${_qi_code}" | grep -q 'aios-var'; then
    pass "The /var volume is LUKS-encrypted"
else
    fail "/var must be encrypted, not plaintext"
fi

if printf '%s' "${_qi_code}" | grep -qE 'aios-var\s+UUID=[^ ]+\s+/etc/aios/var.key'; then
    pass "crypttab unlocks /var from a key on the root (single TPM2 enrolment)"
else
    fail "/var must be unlocked by a root-resident key file, not its own TPM slot"
fi

if printf '%s' "${_qi_code}" | grep -qE '/var\s+ext4'; then
    pass "fstab mounts the dedicated /var"
else
    fail "fstab must mount the separate /var volume"
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
