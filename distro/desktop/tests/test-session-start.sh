#!/bin/sh
#
# AI-OS.NET Session Manager Syntax & Sanity Test
#
# This test validates the session-manager.sh script:
#   1. bash -n syntax check on all shell scripts
#   2. Key function definitions present
#   3. POSIX compliance (no bashisms)
#
# Run: sh distro/desktop/tests/test-session-start.sh
#
# POSIX-compatible.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DESKTOP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

msg "=== AI-OS.NET Session Manager Tests ==="
msg "Desktop directory: ${DESKTOP_DIR}"

# ── Test 1: Syntax check all shell scripts ───────────────────────────────────

msg "Test 1: bash -n syntax check on all .sh files"

for _script in \
    "${DESKTOP_DIR}/session-manager.sh" \
    "${DESKTOP_DIR}/plasma-autostart/aios-renderer-kde.sh" \
    "${DESKTOP_DIR}/plasma-autostart/aios-cognitive-init.sh" \
    "${DESKTOP_DIR}/plasma-autostart/aios-evidence-tray.sh"; do

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

# ── Test 2: Shebang check ────────────────────────────────────────────────────

msg "Test 2: Shebang lines"

for _script in \
    "${DESKTOP_DIR}/session-manager.sh" \
    "${DESKTOP_DIR}/plasma-autostart/aios-renderer-kde.sh" \
    "${DESKTOP_DIR}/plasma-autostart/aios-cognitive-init.sh" \
    "${DESKTOP_DIR}/plasma-autostart/aios-evidence-tray.sh"; do

    if [ ! -f "${_script}" ]; then
        continue
    fi

    _shebang=$(head -n1 "${_script}")
    case "${_shebang}" in
        '#!/bin/sh'|'#!/bin/bash')
            pass "Shebang OK: $(basename "${_script}") -> ${_shebang}"
            ;;
        *)
            fail "Unexpected shebang in $(basename "${_script}"): ${_shebang}"
            ;;
    esac
done

# ── Test 3: Session manager function coverage ────────────────────────────────

msg "Test 3: Session manager function definitions"

SESSION_MGR="${DESKTOP_DIR}/session-manager.sh"
if [ -f "${SESSION_MGR}" ]; then
    for _func in \
        'generate_session_id' \
        'read_posture' \
        'start_daemon' \
        'stop_daemon' \
        'log_evidence' \
        'verify_tpm2_attestation' \
        'setup_dbus_session' \
        'setup_wayland_env' \
        'start_policy_kernel' \
        'start_evidence_daemon' \
        'start_plasma_session' \
        'teardown_all' \
        'main'; do

        if grep -q "^${_func}()" "${SESSION_MGR}"; then
            pass "Function defined: ${_func}"
        else
            fail "Function missing: ${_func}"
        fi
    done
else
    fail "session-manager.sh not found."
fi

# ── Test 4: POSIX compliance (no bashisms) ───────────────────────────────────

msg "Test 4: POSIX compliance check (no bashisms)"

if command -v checkbashisms >/dev/null 2>&1; then
    for _script in \
        "${DESKTOP_DIR}/session-manager.sh" \
        "${DESKTOP_DIR}/plasma-autostart/aios-renderer-kde.sh" \
        "${DESKTOP_DIR}/plasma-autostart/aios-cognitive-init.sh" \
        "${DESKTOP_DIR}/plasma-autostart/aios-evidence-tray.sh"; do

        if [ ! -f "${_script}" ]; then
            continue
        fi

        if checkbashisms "${_script}" 2>&1 | grep -q 'possible bashism'; then
            fail "Bashisms detected in: $(basename "${_script}")"
        else
            pass "No bashisms: $(basename "${_script}")"
        fi
    done
else
    printf '  \033[1;33mSKIP\033[0m checkbashisms not installed — skipping POSIX compliance check.\n'
fi

# ── Test 5: Desktop entry validation ─────────────────────────────────────────

msg "Test 5: Desktop entry file check"

DESKTOP_FILE="${DESKTOP_DIR}/aios-plasma.desktop"
if [ -f "${DESKTOP_FILE}" ]; then
    if grep -q '\[Desktop Entry\]' "${DESKTOP_FILE}"; then
        pass "Desktop entry header present."
    else
        fail "Missing [Desktop Entry] header."
    fi
    if grep -q 'Type=XSession' "${DESKTOP_FILE}"; then
        pass "Desktop entry type is XSession."
    else
        fail "Missing Type=XSession."
    fi
    if grep -q 'Exec=' "${DESKTOP_FILE}"; then
        pass "Desktop entry has Exec key."
    else
        fail "Missing Exec key."
    fi
    if grep -q 'Name=' "${DESKTOP_FILE}"; then
        pass "Desktop entry has Name key."
    else
        fail "Missing Name key."
    fi
else
    fail "aios-plasma.desktop not found."
fi

# ── Test 6: Autostart scripts existence ──────────────────────────────────────

msg "Test 6: Autostart script files"

for _script in \
    "${DESKTOP_DIR}/plasma-autostart/aios-renderer-kde.sh" \
    "${DESKTOP_DIR}/plasma-autostart/aios-cognitive-init.sh" \
    "${DESKTOP_DIR}/plasma-autostart/aios-evidence-tray.sh"; do

    if [ -f "${_script}" ]; then
        pass "File exists: $(basename "${_script}")"
    else
        fail "Missing: $(basename "${_script}")"
    fi
done

# ── Test 7: SDDM theme files existence ───────────────────────────────────────

msg "Test 7: SDDM theme files"

for _file in \
    "${DESKTOP_DIR}/sddm-aios-theme/Main.qml" \
    "${DESKTOP_DIR}/sddm-aios-theme/theme.conf" \
    "${DESKTOP_DIR}/sddm-aios-theme/components/SubjectSelector.qml" \
    "${DESKTOP_DIR}/sddm-aios-theme/components/PostureIndicator.qml"; do

    if [ -f "${_file}" ]; then
        pass "File exists: sddm-aios-theme/$(basename "${_file}")"
    else
        fail "Missing: ${_file}"
    fi
done

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
