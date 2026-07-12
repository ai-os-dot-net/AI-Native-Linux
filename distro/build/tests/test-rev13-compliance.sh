#!/usr/bin/env bash
#
# AI-OS.NET R13.8 compliance-baseline gate test.
#
# Proves the distro-level CIS/STIG control map (distro/compliance/controls.json)
# validates green with the real, in-repo enforcement references, AND that the
# validator is a genuine anti-fake gate: it must FAIL on a tampered map with a
# bogus enforcement_ref, a duplicate control_id, or an out-of-vocabulary status.
#
# Run: bash distro/build/tests/test-rev13-compliance.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${BUILD_DIR}/../.." && pwd)"

COMPLIANCE_DIR="${REPO_ROOT}/distro/compliance"
CONTROLS="${COMPLIANCE_DIR}/controls.json"
VALIDATOR="${COMPLIANCE_DIR}/validate-controls.py"

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
BLUE=$'\033[1;34m'
RESET=$'\033[0m'

PASSED=0
FAILED=0

msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-compliance.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

# Emit a tampered copy of controls.json using an in-line python mutation.
# $1 = destination file, $2 = mutation keyword understood by the helper.
tamper() {
    _dest="$1"
    _mode="$2"
    python3 - "${CONTROLS}" "${_dest}" "${_mode}" <<'PY'
import json
import sys

src, dest, mode = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src, encoding="utf-8") as handle:
    doc = json.load(handle)

controls = doc["controls"]
if mode == "bogus-ref":
    controls[0]["status"] = "enforced"
    controls[0]["enforcement_ref"] = "distro/compliance/DOES-NOT-EXIST.file::nope"
elif mode == "dup-id":
    controls[1]["control_id"] = controls[0]["control_id"]
elif mode == "bad-status":
    controls[0]["status"] = "totally-bogus"
elif mode == "bad-marker":
    # Real file, marker that is guaranteed absent -> anti-fake path check.
    controls[0]["status"] = "enforced"
    controls[0]["enforcement_ref"] = (
        "distro/aios-boot/kernel-config::CONFIG_THIS_FLAG_DOES_NOT_EXIST=y"
    )
elif mode == "eu-ai-act-bogus-ref":
    # Tamper an EU AI Act entry with a non-resolving enforcement_ref.
    target = next(c for c in controls if c["baseline"] == "eu-ai-act")
    target["status"] = "enforced"
    target["enforcement_ref"] = "distro/compliance/NO-SUCH-EUAI.file::nope"
else:
    raise SystemExit(f"unknown mode: {mode}")

with open(dest, "w", encoding="utf-8") as handle:
    json.dump(doc, handle, indent=2)
PY
}

# Assert the validator PASSES (exit 0) for the given controls file.
expect_pass() {
    _label="$1"
    _file="$2"
    if python3 "${VALIDATOR}" --controls "${_file}" --repo-root "${REPO_ROOT}" --quiet; then
        pass "${_label}"
    else
        fail "${_label} (validator unexpectedly returned non-zero)"
    fi
}

# Assert the validator FAILS (exit 1) for the given controls file.
expect_fail() {
    _label="$1"
    _file="$2"
    if python3 "${VALIDATOR}" --controls "${_file}" --repo-root "${REPO_ROOT}" --quiet \
        >/dev/null 2>&1; then
        fail "${_label} (validator PASSED a tampered map — anti-fake gate is broken)"
    else
        pass "${_label}"
    fi
}

msg "R13.8 artifacts exist"
[ -f "${CONTROLS}" ]  && pass "controls.json present" || fail "controls.json missing: ${CONTROLS}"
[ -f "${VALIDATOR}" ] && pass "validate-controls.py present" || fail "validator missing"
[ -f "${COMPLIANCE_DIR}/README.md" ] && pass "compliance README present" \
    || fail "compliance README missing"

msg "Validator passes on the real control map"
expect_pass "real controls.json validates green" "${CONTROLS}"

msg "Validator is a real anti-fake gate (must reject tampered maps)"
tamper "${WORK}/bogus-ref.json"  "bogus-ref"
tamper "${WORK}/bad-marker.json" "bad-marker"
tamper "${WORK}/dup-id.json"     "dup-id"
tamper "${WORK}/bad-status.json" "bad-status"
expect_fail "rejects a non-resolving enforcement_ref path"   "${WORK}/bogus-ref.json"
expect_fail "rejects a resolving path with a bogus marker"   "${WORK}/bad-marker.json"
expect_fail "rejects a duplicate control_id"                 "${WORK}/dup-id.json"
expect_fail "rejects an out-of-vocabulary status"            "${WORK}/bad-status.json"

msg "EU AI Act baseline is present with real coverage"
EUAI_COUNT="$(python3 - "${CONTROLS}" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    doc = json.load(handle)
print(sum(1 for c in doc["controls"] if c.get("baseline") == "eu-ai-act"))
PY
)"
if [ "${EUAI_COUNT}" -ge 10 ]; then
    pass "eu-ai-act baseline has ${EUAI_COUNT} entries (>= 10)"
else
    fail "eu-ai-act baseline has too few entries: ${EUAI_COUNT} (< 10)"
fi

if python3 "${VALIDATOR}" --controls "${CONTROLS}" --repo-root "${REPO_ROOT}" \
    | grep -q "eu-ai-act"; then
    pass "validator summary counts the eu-ai-act baseline"
else
    fail "validator summary does not list the eu-ai-act baseline"
fi

msg "Anti-fake gate covers the eu-ai-act baseline too"
tamper "${WORK}/euai-bogus.json" "eu-ai-act-bogus-ref"
expect_fail "rejects a tampered eu-ai-act entry (bogus ref)" "${WORK}/euai-bogus.json"

msg "Control-map counts (per baseline / per status)"
python3 "${VALIDATOR}" --controls "${CONTROLS}" --repo-root "${REPO_ROOT}"

echo
msg "Summary: ${PASSED} passed, ${FAILED} failed"
if [ "${FAILED}" -ne 0 ]; then
    exit 1
fi
exit 0
