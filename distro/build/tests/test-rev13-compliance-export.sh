#!/bin/sh
#
# R13.8 — compliance audit export gate.
#
# Proves that distro/compliance/aios-compliance-export.py turns the validated
# control map into the three auditor-facing artifacts, that the numbers in those
# artifacts are FAITHFUL to controls.json (not a hand-written fixture), and that
# the generator is a genuine anti-fake gate: it reflects a tampered map and
# refuses a structurally broken one.
#
# Run: sh distro/build/tests/test-rev13-compliance-export.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISTRO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPLIANCE_DIR="${DISTRO_DIR}/compliance"
EXPORT="${COMPLIANCE_DIR}/aios-compliance-export.py"
CONTROLS="${COMPLIANCE_DIR}/controls.json"
STAMP="2026-01-01T00:00:00Z"
FAILED=0
PASSED=0

msg()  { printf '\033[1;34m[TEST]\033[0m %s\n' "$*"; }
pass() { PASSED=$(( PASSED + 1 )); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { FAILED=$(( FAILED + 1 )); printf '  \033[1;31mFAIL\033[0m %s\n' "$*" >&2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

msg "=== R13.8 compliance audit export ==="

[ -f "${EXPORT}" ]   && pass "exporter present" || { fail "exporter missing: ${EXPORT}"; exit 1; }
[ -f "${CONTROLS}" ] && pass "controls.json present" || { fail "controls.json missing"; exit 1; }

# ---- 1. Real run over the real control map -------------------------------------
OUT="${WORK}/real"
if python3 "${EXPORT}" --controls "${CONTROLS}" --out-dir "${OUT}" --generated-at "${STAMP}" >/dev/null 2>&1; then
    pass "exporter runs green over the real control map"
else
    fail "exporter failed on the real control map"
fi

for f in compliance-report.json control-matrix.csv exception-register.json compliance-report.md; do
    [ -s "${OUT}/${f}" ] && pass "emitted ${f}" || fail "missing/empty ${f}"
done

# operator-readable Markdown (R13.8) is faithful to the JSON report: same title,
# tables present, and one controls-table row per control in the JSON.
python3 - "${OUT}/compliance-report.md" "${OUT}/compliance-report.json" <<'PY' \
    && pass "compliance-report.md is faithful to the JSON (row-per-control)" \
    || fail "compliance-report.md missing/inconsistent"
import json, sys
md = open(sys.argv[1], encoding="utf-8").read()
rep = json.load(open(sys.argv[2]))
assert md.startswith("# AI-OS.NET Compliance Report"), "no title"
assert "## Controls" in md and "## Exceptions" in md, "missing sections"
assert rep["generated_at"] in md, "stamp not carried into markdown"
ids = [c["control_id"] for c in rep["controls"]]
missing = [i for i in ids if f"| {i} |" not in md]
assert not missing, f"controls absent from markdown table: {missing[:5]}"
PY

# report is valid JSON with the expected schema + stamp
python3 - "${OUT}/compliance-report.json" "${STAMP}" <<'PY' && pass "compliance-report.json is well-formed (schema + fixed stamp)" || fail "compliance-report.json malformed"
import json, sys
d = json.load(open(sys.argv[1]))
assert d["schema"] == "aios.compliance_report.v1", d.get("schema")
assert d["generated_at"] == sys.argv[2], d.get("generated_at")
assert isinstance(d["controls"], list) and d["controls"], "no controls"
assert "by_status" in d["summary"]
PY

# ---- 2. Numbers are faithful to the source (not a fixture) ---------------------
# Compute the truth straight from controls.json and compare to the report.
python3 - "${CONTROLS}" "${OUT}/compliance-report.json" "${OUT}/exception-register.json" "${OUT}/control-matrix.csv" <<'PY' && pass "report/register/matrix counts match controls.json exactly" || fail "export counts DO NOT match controls.json"
import csv, json, sys
from collections import Counter
src = json.load(open(sys.argv[1]))["controls"]
rep = json.load(open(sys.argv[2]))
reg = json.load(open(sys.argv[3]))
by_status = dict(sorted(Counter(c["status"] for c in src).items()))
assert rep["summary"]["total"] == len(src), (rep["summary"]["total"], len(src))
assert rep["summary"]["by_status"] == by_status, (rep["summary"]["by_status"], by_status)
exc = [c for c in src if c["status"] in ("partial", "documented")]
assert reg["count"] == len(exc), (reg["count"], len(exc))
assert {e["control_id"] for e in reg["exceptions"]} == {c["control_id"] for c in exc}
with open(sys.argv[4], newline="") as fh:
    rows = list(csv.DictReader(fh))
assert len(rows) == len(src), (len(rows), len(src))
assert {r["control_id"] for r in rows} == {c["control_id"] for c in src}
PY

# ---- 3. Anti-fake: a tampered map must change the export ------------------------
# Flip one enforced control to 'documented' -> exception count must go up by 1.
python3 - "${CONTROLS}" "${WORK}/tampered.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for c in d["controls"]:
    if c["status"] == "enforced":
        c["status"] = "documented"
        break
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
BASE_EXC="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["count"])' "${OUT}/exception-register.json")"
OUT2="${WORK}/tampered"
python3 "${EXPORT}" --controls "${WORK}/tampered.json" --out-dir "${OUT2}" --generated-at "${STAMP}" >/dev/null 2>&1 || true
NEW_EXC="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["count"])' "${OUT2}/exception-register.json" 2>/dev/null || echo -1)"
if [ "${NEW_EXC}" = "$(( BASE_EXC + 1 ))" ]; then
    pass "tampering the map moves the exception register (real generator, not a fixture)"
else
    fail "export did not reflect the tampered map (base=${BASE_EXC} new=${NEW_EXC})"
fi

# ---- 4. Anti-fake: a structurally broken map must be REFUSED --------------------
# Duplicate a control_id -> exporter must exit non-zero.
python3 - "${CONTROLS}" "${WORK}/dup.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["controls"].append(dict(d["controls"][0]))  # duplicate control_id
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
if python3 "${EXPORT}" --controls "${WORK}/dup.json" --out-dir "${WORK}/dup" --generated-at "${STAMP}" >/dev/null 2>&1; then
    fail "exporter accepted a map with a duplicate control_id"
else
    pass "exporter refuses a structurally broken map (duplicate control_id)"
fi

# Out-of-vocabulary status -> refused.
python3 - "${CONTROLS}" "${WORK}/badstatus.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["controls"][0]["status"] = "totally-made-up"
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
if python3 "${EXPORT}" --controls "${WORK}/badstatus.json" --out-dir "${WORK}/bad" --generated-at "${STAMP}" >/dev/null 2>&1; then
    fail "exporter accepted an out-of-vocabulary status"
else
    pass "exporter refuses an out-of-vocabulary status"
fi

printf '\n'
if [ "${FAILED}" -eq 0 ]; then
    printf '\033[1;32mALL TESTS PASSED\033[0m  (Passed: %s  Failed: %s)\n' "${PASSED}" "${FAILED}"
    exit 0
else
    printf '\033[1;31mSOME TESTS FAILED\033[0m (Passed: %s  Failed: %s)\n' "${PASSED}" "${FAILED}"
    exit 1
fi
