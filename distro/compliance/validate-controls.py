#!/usr/bin/env python3
"""Validate the AI-OS.NET R13.8 CIS/STIG control map (controls.json).

This is the anti-fake gate for the distro-level compliance baseline. It proves
that every non-null ``enforcement_ref`` actually resolves to a file (and, when a
``::marker`` suffix is present, that the exact directive / CONFIG_ flag / code
token really lives in that file) inside THIS repository. A control cannot claim
``enforced``/``partial`` without a resolvable reference.

Exit status:
    0  all checks passed
    1  one or more violations (schema, vocabulary, uniqueness, or a dangling
       enforcement_ref that does not resolve)
    2  usage / I/O error (controls file missing or not valid JSON)

Usage:
    validate-controls.py [--controls PATH] [--repo-root PATH] [--quiet]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

MECHANISM_VOCABULARY = {
    "aios-policy",
    "systemd-hardening",
    "selinux",
    "kernel-config",
    "evidence-log",
    "boot-integrity",
    "update-signature",
}
STATUS_VOCABULARY = {"enforced", "partial", "documented"}
BASELINE_VOCABULARY = {"cis", "stig", "eu-ai-act"}
REQUIRED_FIELDS = {
    "control_id": str,
    "title": str,
    "baseline": str,
    "aios_mechanism": str,
    "enforcement_ref": (str, type(None)),
    "status": str,
    "evidence_record_type": (str, type(None)),
}


def _default_repo_root() -> str:
    # This script lives at <repo>/distro/compliance/validate-controls.py.
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", ".."))


def _default_controls() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "controls.json")


def resolve_enforcement_ref(ref: str, repo_root: str) -> str | None:
    """Return an error string if ``ref`` does not resolve, else ``None``.

    ``ref`` is a repo-relative path optionally suffixed with ``::<marker>``.
    The path must exist; when a marker is present, the file must contain that
    literal substring somewhere in its text.
    """
    if "::" in ref:
        rel_path, marker = ref.split("::", 1)
    else:
        rel_path, marker = ref, None

    rel_path = rel_path.strip()
    if not rel_path:
        return "empty path in enforcement_ref"

    abs_path = os.path.join(repo_root, rel_path)
    if not os.path.exists(abs_path):
        return f"path does not exist: {rel_path}"
    if not os.path.isfile(abs_path):
        return f"path is not a regular file: {rel_path}"

    if marker is not None:
        marker = marker.strip()
        if not marker:
            return f"empty marker for {rel_path}"
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
                content = handle.read()
        except OSError as exc:  # pragma: no cover - defensive
            return f"could not read {rel_path}: {exc}"
        if marker not in content:
            return f"marker not found in {rel_path}: {marker!r}"

    return None


def validate(doc: dict, repo_root: str) -> list[str]:
    """Return a list of human-readable violation strings (empty == valid)."""
    violations: list[str] = []

    controls = doc.get("controls")
    if not isinstance(controls, list) or not controls:
        violations.append("top-level 'controls' must be a non-empty array")
        return violations

    seen_ids: set[str] = set()

    for index, control in enumerate(controls):
        where = f"controls[{index}]"
        if not isinstance(control, dict):
            violations.append(f"{where}: not an object")
            continue

        cid = control.get("control_id", f"<{where}>")

        # Field presence and types.
        for field, expected in REQUIRED_FIELDS.items():
            if field not in control:
                violations.append(f"{cid}: missing field '{field}'")
                continue
            if not isinstance(control[field], expected):
                violations.append(
                    f"{cid}: field '{field}' has wrong type "
                    f"({type(control[field]).__name__})"
                )

        # Unique control_id.
        if isinstance(cid, str):
            if cid in seen_ids:
                violations.append(f"{cid}: duplicate control_id")
            seen_ids.add(cid)

        # Vocabulary checks.
        baseline = control.get("baseline")
        if baseline not in BASELINE_VOCABULARY:
            violations.append(f"{cid}: baseline '{baseline}' not in {sorted(BASELINE_VOCABULARY)}")

        mechanism = control.get("aios_mechanism")
        if mechanism not in MECHANISM_VOCABULARY:
            violations.append(
                f"{cid}: aios_mechanism '{mechanism}' not in {sorted(MECHANISM_VOCABULARY)}"
            )

        status = control.get("status")
        if status not in STATUS_VOCABULARY:
            violations.append(f"{cid}: status '{status}' not in {sorted(STATUS_VOCABULARY)}")

        # enforcement_ref semantics.
        ref = control.get("enforcement_ref")
        if ref is None:
            if status in ("enforced", "partial"):
                violations.append(
                    f"{cid}: status '{status}' requires a non-null enforcement_ref"
                )
        elif isinstance(ref, str):
            err = resolve_enforcement_ref(ref, repo_root)
            if err is not None:
                violations.append(f"{cid}: enforcement_ref does not resolve — {err}")

    return violations


def summarize(controls: list[dict]) -> tuple[Counter, Counter]:
    by_baseline: Counter = Counter()
    by_status: Counter = Counter()
    for control in controls:
        if isinstance(control, dict):
            by_baseline[control.get("baseline", "?")] += 1
            by_status[control.get("status", "?")] += 1
    return by_baseline, by_status


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate the R13.8 CIS/STIG control map.")
    parser.add_argument("--controls", default=_default_controls(), help="Path to controls.json")
    parser.add_argument("--repo-root", default=_default_repo_root(), help="Repository root")
    parser.add_argument("--quiet", action="store_true", help="Suppress the summary on success")
    args = parser.parse_args(argv)

    try:
        with open(args.controls, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
    except FileNotFoundError:
        print(f"ERROR: controls file not found: {args.controls}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"ERROR: {args.controls} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if not isinstance(doc, dict):
        print("ERROR: top-level JSON must be an object", file=sys.stderr)
        return 2

    violations = validate(doc, args.repo_root)
    controls = doc.get("controls", []) if isinstance(doc.get("controls"), list) else []

    if violations:
        print(f"FAIL: {len(violations)} violation(s) in {args.controls}", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1

    if not args.quiet:
        by_baseline, by_status = summarize(controls)
        print(f"PASS: {len(controls)} controls validated in {args.controls}")
        print("  by baseline:")
        for key in sorted(by_baseline):
            print(f"    {key:12s} {by_baseline[key]}")
        print("  by status:")
        for key in sorted(by_status):
            print(f"    {key:12s} {by_status[key]}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
