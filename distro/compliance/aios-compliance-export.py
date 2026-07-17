#!/usr/bin/env python3
"""Generate operator/auditor-facing compliance exports from controls.json.

The control map (`controls.json`) is the single source of truth; `validate-controls.py`
proves it is well-formed. This tool turns that validated map into the audit
artifacts an assessor asks for, WITHOUT inventing any data it does not contain:

  * compliance-report.json  — machine-readable: metadata, summary counts
                              (by status / baseline / mechanism), and the full
                              per-control list.
  * control-matrix.csv       — one row per control (id, baseline, title,
                              mechanism, status, enforcement_ref, evidence type).
  * exception-register.json  — every control NOT fully `enforced`
                              (status in {partial, documented}), with the
                              mechanism and enforcement_ref that show where it
                              stands and why it is not yet closed.

NIST 800-53 control-family mapping is deliberately NOT emitted: controls.json
carries no `nist_family` field, and mapping CIS/STIG/EU-AI-Act controls to NIST
families is an authoring decision for a compliance SME, not something this tool
may fabricate. Add `nist_family` to each control's source record first; this
tool will then export it.

Exit non-zero on any structural problem so it is safe to wire into a gate.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

# Kept in lockstep with controls.json's own vocabularies; a value outside these
# is a source-map defect, not something to paper over in the export.
STATUS_VOCAB = {"enforced", "partial", "documented"}
# Anything that is not fully enforced belongs in the exception register.
EXCEPTION_STATUSES = {"partial", "documented"}
REQUIRED_CONTROL_KEYS = {
    "control_id",
    "title",
    "baseline",
    "aios_mechanism",
    "enforcement_ref",
    "status",
    "evidence_record_type",
}


def load_controls(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"error: cannot read controls map {path}: {exc}")
    if not isinstance(doc, dict) or not isinstance(doc.get("controls"), list):
        sys.exit(f"error: {path} is not a controls map (missing 'controls' list)")
    controls = doc["controls"]
    seen: set[str] = set()
    for i, ctrl in enumerate(controls):
        if not isinstance(ctrl, dict):
            sys.exit(f"error: control #{i} is not an object")
        missing = REQUIRED_CONTROL_KEYS - ctrl.keys()
        if missing:
            sys.exit(
                f"error: control #{i} ({ctrl.get('control_id', '?')}) "
                f"missing keys: {sorted(missing)}"
            )
        cid = ctrl["control_id"]
        if cid in seen:
            sys.exit(f"error: duplicate control_id {cid}")
        seen.add(cid)
        if ctrl["status"] not in STATUS_VOCAB:
            sys.exit(
                f"error: control {cid} has out-of-vocabulary status "
                f"'{ctrl['status']}' (allowed: {sorted(STATUS_VOCAB)})"
            )
    return doc


def _summary(controls: list[dict]) -> dict:
    total = len(controls)
    by_status = Counter(c["status"] for c in controls)
    return {
        "total": total,
        "by_status": dict(sorted(by_status.items())),
        "by_baseline": dict(sorted(Counter(c["baseline"] for c in controls).items())),
        "by_mechanism": dict(
            sorted(Counter(c["aios_mechanism"] for c in controls).items())
        ),
        "enforced_ratio": round(by_status.get("enforced", 0) / total, 4) if total else 0.0,
    }


def build_report(doc: dict, generated_at: str) -> dict:
    controls = doc["controls"]
    return {
        "schema": "aios.compliance_report.v1",
        "generated_at": generated_at,
        "source_schema": doc.get("schema"),
        "source_revision": doc.get("revision"),
        "summary": _summary(controls),
        "controls": controls,
    }


def build_exception_register(doc: dict, generated_at: str) -> dict:
    exceptions = [
        {
            "control_id": c["control_id"],
            "title": c["title"],
            "baseline": c["baseline"],
            "status": c["status"],
            "aios_mechanism": c["aios_mechanism"],
            "enforcement_ref": c["enforcement_ref"],
            "reason": (
                "Not fully enforced; tracked toward 'enforced'. "
                f"Current mechanism: {c['aios_mechanism']}."
            ),
        }
        for c in doc["controls"]
        if c["status"] in EXCEPTION_STATUSES
    ]
    return {
        "schema": "aios.compliance_exception_register.v1",
        "generated_at": generated_at,
        "source_revision": doc.get("revision"),
        "count": len(exceptions),
        "exceptions": exceptions,
    }


def write_matrix_csv(controls: list[dict], path: Path) -> None:
    fields = [
        "control_id",
        "baseline",
        "title",
        "aios_mechanism",
        "status",
        "enforcement_ref",
        "evidence_record_type",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for ctrl in sorted(controls, key=lambda c: c["control_id"]):
            writer.writerow({k: ctrl.get(k, "") for k in fields})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    parser.add_argument("--controls", type=Path, default=here / "controls.json")
    parser.add_argument("--out-dir", type=Path, default=here / "export")
    parser.add_argument(
        "--generated-at",
        default="",
        help="ISO-8601 stamp for the exports (default: UTC now). "
        "Pass a fixed value for reproducible/gated runs.",
    )
    args = parser.parse_args()

    generated_at = args.generated_at
    if not generated_at:
        # Imported lazily so a fixed --generated-at run needs no clock at all.
        from datetime import datetime, timezone

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc = load_controls(args.controls)
    controls = doc["controls"]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(doc, generated_at)
    register = build_exception_register(doc, generated_at)

    (args.out_dir / "compliance-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.out_dir / "exception-register.json").write_text(
        json.dumps(register, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    write_matrix_csv(controls, args.out_dir / "control-matrix.csv")

    s = report["summary"]
    print(f"AIOS compliance export -> {args.out_dir}")
    print(f"  controls:   {s['total']}")
    print(f"  by status:  {s['by_status']}")
    print(f"  exceptions: {register['count']} (not fully enforced)")
    print("  files:      compliance-report.json, control-matrix.csv, exception-register.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
