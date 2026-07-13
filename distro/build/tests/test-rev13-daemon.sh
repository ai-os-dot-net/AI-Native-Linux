#!/usr/bin/env bash
#
# AI-OS.NET R13.3 daemon-architecture + systemd-finalization gate test.
#
# Proves the R13.3 contract is real and enforced:
#   1. DAEMON-ARCHITECTURE.md exists and documents EXACTLY the units present in
#      distro/systemd/ (no undocumented unit, no documented-but-missing unit).
#   2. Every required service defines Restart, RestartSec/TimeoutStartSec, and
#      a Type — restart/failure behaviour is not left to systemd defaults.
#   3. Optional services do not block boot: they are pulled only via the target's
#      soft Wants= (aios.target does not hard-Requires= any member).
#   4. aios-security-score.sh runs, PASSES on the real units, and FAILS closed on
#      a synthetic under-hardened required unit (threshold gate works).
#   5. Restart / fail-closed Requires= behaviour is asserted on the core chain.
#
# Deterministic: uses a fixed --epoch, never the wall clock. POSIX-friendly bash.
#
# Run: TMPDIR=$HOME/.tmp-aios bash distro/build/tests/test-rev13-daemon.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${BUILD_DIR}/../.." && pwd)"

SYSTEMD_DIR="${REPO_ROOT}/distro/systemd"
DOC="${SYSTEMD_DIR}/DAEMON-ARCHITECTURE.md"
SCORE="${SYSTEMD_DIR}/aios-security-score.sh"
TARGET="${SYSTEMD_DIR}/aios.target"

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
BLUE=$'\033[1;34m'
RESET=$'\033[0m'

PASSED=0
FAILED=0

msg()  { printf '%s[TEST]%s %s\n' "${BLUE}" "${RESET}" "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  %sPASS%s %s\n' "${GREEN}" "${RESET}" "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  %sFAIL%s %s\n' "${RED}" "${RESET}" "$*" >&2; }

# Deterministic epoch so the run never touches the wall clock.
EPOCH=1700000000

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aios-r13-daemon.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

# Required-service set — MUST mirror the gated classes in aios-security-score.sh
# and the "Required services" table in DAEMON-ARCHITECTURE.md.
REQUIRED_SERVICES="aios-policy-kernel aios-evidence-log aios-vault-broker \
aios-capability-runtime aios-fs-daemon aios-sandbox-composer aios-sgr-daemon \
aios-recovery-watchdog aios-network-daemon aios-hardware-daemon"

# ── 1. Doc exists and documents exactly the present units ─────────────────────
msg "1. DAEMON-ARCHITECTURE.md covers every unit (no drift)"

if [ -f "${DOC}" ]; then
    pass "DAEMON-ARCHITECTURE.md exists"
else
    fail "DAEMON-ARCHITECTURE.md missing"
fi

if [ -f "${SCORE}" ]; then
    pass "aios-security-score.sh exists"
else
    fail "aios-security-score.sh missing"
fi

# Every *.service / *.target present in distro/systemd must be named in the doc.
for unit_file in "${SYSTEMD_DIR}"/*.service "${SYSTEMD_DIR}"/*.target; do
    [ -f "${unit_file}" ] || continue
    unit_base="$(basename "${unit_file}")"
    unit_name="${unit_base%.*}"
    if grep -q "${unit_name}" "${DOC}"; then
        pass "documented: ${unit_base}"
    else
        fail "unit present but NOT documented: ${unit_base}"
    fi
done

# Reverse direction: every backtick-quoted aios-*.service token in the doc must
# correspond to a real unit file (no documented-but-missing unit).
DOC_UNITS="$(grep -oE 'aios-[a-z-]+\.service' "${DOC}" | sort -u)"
for du in ${DOC_UNITS}; do
    if [ -f "${SYSTEMD_DIR}/${du}" ]; then
        pass "documented unit exists: ${du}"
    else
        fail "documented-but-missing unit: ${du}"
    fi
done

# ── 2. Required services define restart/failure behaviour explicitly ──────────
msg "2. Required services define Restart + RestartSec/TimeoutStartSec + Type"

for svc in ${REQUIRED_SERVICES}; do
    uf="${SYSTEMD_DIR}/${svc}.service"
    if [ ! -f "${uf}" ]; then
        fail "required unit file missing: ${svc}.service"
        continue
    fi
    if grep -Eq '^Type=' "${uf}"; then
        pass "${svc}: Type= defined"
    else
        fail "${svc}: no Type="
    fi
    if grep -Eq '^Restart=' "${uf}"; then
        pass "${svc}: Restart= defined"
    else
        fail "${svc}: no Restart="
    fi
    # Failure timing must be explicit: RestartSec or TimeoutStartSec.
    if grep -Eq '^RestartSec=|^TimeoutStartSec=' "${uf}"; then
        pass "${svc}: RestartSec/TimeoutStartSec defined"
    else
        fail "${svc}: no RestartSec/TimeoutStartSec"
    fi
done

# ── 3. Optional services do not block boot ────────────────────────────────────
msg "3. aios.target pulls members via soft Wants= only (no hard Requires=)"

if [ -f "${TARGET}" ]; then
    pass "aios.target exists"
else
    fail "aios.target missing"
fi

# The target must not hard-Requires= any AIOS service (that would let an optional
# unit's failure fail the target and stall boot).
if grep -Eq '^Requires=' "${TARGET}"; then
    fail "aios.target has a hard Requires= (optional units could block boot)"
else
    pass "aios.target has no hard Requires= (members are soft Wants=)"
fi

if grep -Eq '^Wants=.*aios-' "${TARGET}"; then
    pass "aios.target pulls services via Wants="
else
    fail "aios.target does not Wants= any aios- service"
fi

# Spot-check a representative optional service is only soft-wanted, not required.
for opt in aios-marketplace aios-fleet aios-autonomous aios-cognitive-core; do
    if grep -Eq "^Wants=.*${opt}" "${TARGET}"; then
        pass "optional ${opt} is in target Wants="
    else
        fail "optional ${opt} not soft-wanted by target"
    fi
done

# ── 4. Security score gate: passes real units, fails a bad required unit ───────
msg "4. aios-security-score.sh runs and the threshold gate works"

SCORE_JSON="${WORK}/score.json"
_rc=0
bash "${SCORE}" --threshold 30 --epoch "${EPOCH}" --json "${SCORE_JSON}" \
    >"${WORK}/score.out" 2>&1 || _rc=$?
if [ "${_rc}" -eq 0 ]; then
    pass "security score PASSES on the real units (exit 0)"
else
    fail "security score unexpectedly failed on real units (rc=${_rc})"
    cat "${WORK}/score.out" >&2 || true
fi

# JSON summary is schema-valid and reports gate=pass with no required failures.
if python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d["schema"] == "aios.systemd_security_score.v1", d.get("schema")
assert d["gate"] == "pass", d["gate"]
assert d["required_failures"] == 0, d["required_failures"]
assert d["generated_epoch"] == '"${EPOCH}"', d["generated_epoch"]
gated = [u for u in d["units"] if u["gated"]]
assert len(gated) >= 10, len(gated)
for u in gated:
    assert u["exposure_ep"] <= d["threshold_ep"], u
' "${SCORE_JSON}" 2>/dev/null; then
    pass "score JSON schema + gate=pass + >=10 gated units valid"
else
    fail "score JSON invalid or a gated unit exceeds threshold"
fi

# Determinism: two runs produce byte-identical JSON.
bash "${SCORE}" --threshold 30 --epoch "${EPOCH}" --json "${WORK}/score-b.json" \
    >/dev/null 2>&1 || true
if diff -q "${SCORE_JSON}" "${WORK}/score-b.json" >/dev/null 2>&1; then
    pass "score output is deterministic (two runs identical)"
else
    fail "score output is non-deterministic"
fi

# Synthetic under-hardened REQUIRED unit → gate MUST fail closed (non-zero).
BAD_DIR="${WORK}/bad-units"
mkdir -p "${BAD_DIR}"
cat > "${BAD_DIR}/aios-capability-runtime.service" <<'EOF'
[Unit]
Description=deliberately under-hardened required unit
[Service]
Type=simple
ExecStart=/usr/lib/aios/aios-system run-service aios-capability-runtime
EOF
if bash "${SCORE}" --units "${BAD_DIR}" --threshold 30 --epoch "${EPOCH}" \
        >/dev/null 2>&1; then
    fail "under-hardened required unit did NOT fail the gate (anti-fake broken)"
else
    pass "under-hardened required unit fails the gate (blocks release)"
fi

# And the same bad unit PASSES if the operator raises the threshold above its
# exposure — proves the threshold is a real, tunable knob, not hardcoded.
if bash "${SCORE}" --units "${BAD_DIR}" --threshold 200 --epoch "${EPOCH}" \
        >/dev/null 2>&1; then
    pass "raising --threshold above exposure lets it pass (threshold is real)"
else
    fail "threshold knob does not take effect"
fi

# ── 5. Restart + fail-closed Requires= behaviour on the core chain ────────────
msg "5. Core chain restart policy + fail-closed dependencies"

# Core substrate daemons must Restart=always (self-heal), not on-failure/no.
for svc in aios-policy-kernel aios-evidence-log aios-capability-runtime \
           aios-fs-daemon aios-recovery-watchdog; do
    if grep -Eq '^Restart=always' "${SYSTEMD_DIR}/${svc}.service"; then
        pass "${svc}: Restart=always (self-heals)"
    else
        fail "${svc}: expected Restart=always"
    fi
done

# capability-runtime must hard-Requires= policy-kernel AND evidence-log
# (fail-closed: no execution without policy + evidence).
CR="${SYSTEMD_DIR}/aios-capability-runtime.service"
if grep -Eq '^Requires=.*aios-policy-kernel' "${CR}" \
   && grep -Eq '^Requires=.*aios-evidence-log' "${CR}"; then
    pass "capability-runtime hard-Requires= policy-kernel + evidence-log (fail-closed)"
else
    fail "capability-runtime does not fail-closed on policy/evidence"
fi

# High-risk daemons must constrain their capability bounding set.
for svc in aios-capability-runtime aios-network-daemon aios-hardware-daemon; do
    if grep -Eq '^CapabilityBoundingSet=' "${SYSTEMD_DIR}/${svc}.service"; then
        pass "${svc}: CapabilityBoundingSet= constrained"
    else
        fail "${svc}: high-risk unit without CapabilityBoundingSet="
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL=$(( PASSED + FAILED ))
printf '\n%s[TEST]%s Daemon-architecture gate: %s%d passed%s, %s%d failed%s\n' \
    "${BLUE}" "${RESET}" "${GREEN}" "${PASSED}" "${RESET}" \
    "${RED}" "${FAILED}" "${RESET}"

if [ "${FAILED}" -eq 0 ]; then
    printf 'RESULT: PASS (%d/%d checks)\n' "${PASSED}" "${TOTAL}"
    exit 0
else
    printf 'RESULT: FAIL (%d/%d checks)\n' "${PASSED}" "${TOTAL}"
    exit 1
fi
