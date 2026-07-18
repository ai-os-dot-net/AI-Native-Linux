#!/usr/bin/env bash
#
# AI-OS.NET R13.8 — mandatory audit-artifact presence gate test.
#
# Proves the release-gate mechanism behind "Release is blocked if mandatory audit
# artifacts are missing" (REV13-ENTERPRISE-SPEC.md §11): the compliance exporter
# actually produces the machine-readable audit artifacts, and the presence checker
# (aios-audit-artifacts-check.sh) FAILS CLOSED when any is missing, empty, or
# malformed. Uses only real tooling + real controls.json — fabricates no compliance
# data.
#
# Run: bash distro/build/tests/test-rev13-audit-artifacts-present.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISTRO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
EXPORTER="${DISTRO_DIR}/compliance/aios-compliance-export.py"
CHECKER="${DISTRO_DIR}/compliance/aios-audit-artifacts-check.sh"
CONTROLS="${DISTRO_DIR}/compliance/controls.json"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
PASSED=0; FAILED=0
msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-audit.XXXXXX")"
cleanup() { case "${WORK}" in /tmp/*|"${TMPDIR:-/tmp}"/*) rm -rf "${WORK}" ;; esac; }
trap cleanup EXIT INT TERM

msg "0. presence / syntax"
[ -f "${CHECKER}" ]  && pass "checker exists"       || fail "checker missing: ${CHECKER}"
[ -x "${CHECKER}" ]  && pass "checker executable"   || fail "checker not executable"
bash -n "${CHECKER}" 2>/dev/null && pass "checker syntax OK" || fail "checker syntax error"
[ -f "${EXPORTER}" ] && pass "exporter exists"      || fail "exporter missing: ${EXPORTER}"
[ -f "${CONTROLS}" ] && pass "controls.json exists" || fail "controls.json missing"
command -v python3 >/dev/null 2>&1 && pass "python3 present" || fail "python3 missing"

# ── generate the real audit export ────────────────────────────────────────────
msg "1. exporter produces the mandatory audit artifacts"
EXPORT="${WORK}/export"
if python3 "${EXPORTER}" --controls "${CONTROLS}" --out-dir "${EXPORT}" >/dev/null 2>&1; then
    pass "aios-compliance-export.py ran"
else
    fail "aios-compliance-export.py failed"
fi
for f in compliance-report.json control-matrix.csv exception-register.json compliance-report.md; do
    [ -s "${EXPORT}/${f}" ] && pass "produced non-empty ${f}" || fail "missing/empty ${f}"
done

# ── checker PASSES on a complete export ───────────────────────────────────────
msg "2. checker passes on a complete audit set"
if bash "${CHECKER}" --dir "${EXPORT}" >/dev/null 2>&1; then
    pass "checker PASS on complete export"
else
    fail "checker failed on a complete export"
fi

# ── checker FAILS CLOSED on each missing artifact ─────────────────────────────
msg "3. checker fails closed on missing / empty / malformed artifacts"
for f in compliance-report.json control-matrix.csv exception-register.json compliance-report.md; do
    d="${WORK}/miss-${f}"; cp -r "${EXPORT}" "${d}"; rm -f "${d}/${f}"
    if bash "${CHECKER}" --dir "${d}" >/dev/null 2>&1; then
        fail "checker PASSED despite missing ${f} (should fail closed)"
    else
        pass "checker fails closed when ${f} is missing"
    fi
done

# empty artifact
d="${WORK}/empty"; cp -r "${EXPORT}" "${d}"; : > "${d}/compliance-report.json"
if bash "${CHECKER}" --dir "${d}" >/dev/null 2>&1; then
    fail "checker PASSED on an empty artifact"
else
    pass "checker fails closed on an empty artifact"
fi

# malformed JSON
d="${WORK}/bad"; cp -r "${EXPORT}" "${d}"; printf '{not json' > "${d}/compliance-report.json"
if bash "${CHECKER}" --dir "${d}" >/dev/null 2>&1; then
    fail "checker PASSED on malformed JSON"
else
    pass "checker fails closed on malformed JSON"
fi

# missing directory entirely
if bash "${CHECKER}" --dir "${WORK}/does-not-exist" >/dev/null 2>&1; then
    fail "checker PASSED on a missing audit directory"
else
    pass "checker fails closed on a missing audit directory"
fi

# ── extended --require (e.g. SBOM/provenance) also enforced ──────────────────
msg "4. custom --require enforces additional mandatory files"
if bash "${CHECKER}" --dir "${EXPORT}" \
     --require "compliance-report.json,sbom.cdx.json" >/dev/null 2>&1; then
    fail "checker PASSED despite a required file (sbom.cdx.json) absent"
else
    pass "checker fails closed when an extra --require file is absent"
fi
# and passes when that file is present
cp "${CONTROLS}" "${EXPORT}/sbom.cdx.json"
if bash "${CHECKER}" --dir "${EXPORT}" \
     --require "compliance-report.json,sbom.cdx.json" >/dev/null 2>&1; then
    pass "checker passes when all --require files are present"
else
    fail "checker failed when all --require files were present"
fi

printf '\n%s[TEST]%s audit-artifact gate: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" "${RED}" "${FAILED}" "${RESET}"
[ "${FAILED}" -eq 0 ] || exit 1
