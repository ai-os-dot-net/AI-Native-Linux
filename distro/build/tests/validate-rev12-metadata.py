#!/usr/bin/env python3
"""AI-OS.NET Rev.12 release metadata validator.

Validates the ACTUALLY GENERATED JSON artifacts staged by
distro/build/build-aios-iso.sh Step 11 ("Generating Rev.12 release
metadata") against the requirements in
distro/build/REV12-DISTRIBUTION-SPEC.md section 7 ("SBOM and provenance
requirements" + "Acceptance tests").

Usage:
    python3 validate-rev12-metadata.py <iso_staging_dir>

<iso_staging_dir> is the ISO staging directory produced by the build
script (i.e. "${AIOS_BUILD_WORKDIR}/iso" or the default
"distro/build/out/iso"). It must contain an "aios/" subdirectory with
the Rev.12 metadata JSON files and the "live/", "boot/" artifact trees
referenced by manifest.json.

Output protocol (read by test-rev12-release-metadata.sh):
    Each check emits exactly one line to stdout:
        PASS\t<message>
        FAIL\t<message>
    Nothing else is written to stdout. Diagnostic detail goes to stderr.

Exit code is always 0 (the caller counts PASS/FAIL lines); a non-zero
exit means the validator itself crashed (e.g. directory missing).
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


RESULTS: list[tuple[bool, str]] = []


def check(ok: bool, message: str) -> None:
    RESULTS.append((ok, message))


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path, label: str) -> dict[str, Any] | None:
    if not path.is_file():
        check(False, f"{label}: file missing at {path}")
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        check(False, f"{label}: unreadable ({exc})")
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        check(False, f"{label}: invalid JSON ({exc})")
        return None
    check(True, f"{label}: parses as valid JSON")
    return data


def require_field(data: dict[str, Any], path: str, label: str) -> Any:
    """Dotted-path lookup with a PASS/FAIL check for presence + non-empty."""
    node: Any = data
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            check(False, f"{label}: missing required field '{path}'")
            return None
        node = node[part]
    if node in ("", None):
        check(False, f"{label}: field '{path}' is present but empty")
        return None
    check(True, f"{label}: field '{path}' present ({node!r})")
    return node


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ISO8601_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def validate_manifest(iso_dir: Path) -> None:
    label = "manifest.json"
    data = load_json(iso_dir / "aios" / "manifest.json", label)
    if data is None:
        return

    if data.get("schema") == "aios.release_manifest.v1":
        check(True, f"{label}: schema == aios.release_manifest.v1")
    else:
        check(False, f"{label}: schema is {data.get('schema')!r}, expected aios.release_manifest.v1")

    require_field(data, "revision", label)
    require_field(data, "version", label)
    require_field(data, "architecture", label)
    require_field(data, "build_id", label)

    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) == 0:
        check(False, f"{label}: 'artifacts' must be a non-empty list")
        return
    check(True, f"{label}: 'artifacts' is a non-empty list ({len(artifacts)} entries)")

    all_hashes_ok = True
    for entry in artifacts:
        rel_path = entry.get("path")
        sha256 = entry.get("sha256")
        size_bytes = entry.get("size_bytes")

        if not rel_path:
            all_hashes_ok = False
            check(False, f"{label}: artifact entry missing 'path': {entry!r}")
            continue
        if not sha256 or not SHA256_RE.match(str(sha256)):
            all_hashes_ok = False
            check(False, f"{label}: artifact '{rel_path}' has malformed sha256: {sha256!r}")
            continue
        if not isinstance(size_bytes, int) or size_bytes <= 0:
            all_hashes_ok = False
            check(False, f"{label}: artifact '{rel_path}' has invalid size_bytes: {size_bytes!r}")
            continue

        artifact_path = iso_dir / rel_path
        if not artifact_path.is_file():
            all_hashes_ok = False
            check(False, f"{label}: artifact '{rel_path}' listed but not present on disk at {artifact_path}")
            continue

        actual_sha256 = sha256_of(artifact_path)
        actual_size = artifact_path.stat().st_size
        if actual_sha256 != sha256:
            all_hashes_ok = False
            check(
                False,
                f"{label}: sha256 mismatch for '{rel_path}': manifest={sha256} actual={actual_sha256}",
            )
        if actual_size != size_bytes:
            all_hashes_ok = False
            check(
                False,
                f"{label}: size_bytes mismatch for '{rel_path}': manifest={size_bytes} actual={actual_size}",
            )

    if all_hashes_ok:
        check(True, f"{label}: all {len(artifacts)} artifact sha256/size_bytes entries verified against disk")


def validate_sbom(iso_dir: Path) -> None:
    label = "sbom.cdx.json"
    data = load_json(iso_dir / "aios" / "sbom.cdx.json", label)
    if data is None:
        return

    if data.get("bomFormat") == "CycloneDX":
        check(True, f"{label}: bomFormat == CycloneDX")
    else:
        check(False, f"{label}: bomFormat is {data.get('bomFormat')!r}, expected CycloneDX")

    require_field(data, "specVersion", label)
    require_field(data, "serialNumber", label)
    require_field(data, "metadata.component.name", label)
    require_field(data, "metadata.component.version", label)

    components = data.get("components")
    if not isinstance(components, list) or len(components) == 0:
        check(False, f"{label}: 'components' must be a non-empty list")
        return
    check(True, f"{label}: 'components' is a non-empty list ({len(components)} entries)")

    # Spec requirement (REV12-DISTRIBUTION-SPEC.md sec.7): "SBOM covers
    # Rust crates, packaged OS dependencies, kernel, modules, firmware, and
    # installer scripts where tooling can enumerate them." Look for at
    # least one component that identifies an actual Rust crate/dependency
    # (via a cargo/crates.io purl, a "rust-crate" type marker, or a
    # cargo-metadata-style name+version pair distinct from the OS/file
    # artifact entries the build script always emits).
    def looks_like_rust_crate(comp: dict[str, Any]) -> bool:
        purl = str(comp.get("purl", ""))
        if purl.startswith("pkg:cargo/"):
            return True
        props = comp.get("properties", [])
        if isinstance(props, list):
            for prop in props:
                name = str(prop.get("name", ""))
                if name in ("aios.crate", "cdx:cargo:package") or name.startswith("cargo:"):
                    return True
        group = str(comp.get("group", ""))
        if group == "crates.io":
            return True
        return False

    crate_components = [c for c in components if isinstance(c, dict) and looks_like_rust_crate(c)]
    if crate_components:
        check(
            True,
            f"{label}: components include {len(crate_components)} Rust crate entries "
            f"(e.g. {crate_components[0].get('name')})",
        )
    else:
        check(
            False,
            f"{label}: components list has {len(components)} entries but NONE identify a Rust "
            "crate (no pkg:cargo/ purl, no cargo:* property, no crates.io group) — spec sec.7 "
            "requires 'SBOM covers Rust crates ... where tooling can enumerate them'",
        )


def validate_provenance(iso_dir: Path) -> None:
    label = "provenance.json"
    data = load_json(iso_dir / "aios" / "provenance.json", label)
    if data is None:
        return

    if data.get("schema") == "aios.provenance.v1":
        check(True, f"{label}: schema == aios.provenance.v1")
    else:
        check(False, f"{label}: schema is {data.get('schema')!r}, expected aios.provenance.v1")

    # Spec sec.7: "Provenance records source commit, builder, build time,
    # build inputs, tool versions, output hashes, and signature identity."
    git_rev = require_field(data, "source.git_revision", label)
    if git_rev is not None and git_rev == "unknown":
        check(False, f"{label}: source.git_revision is 'unknown' — not a resolvable source commit")

    timestamp = require_field(data, "timestamp", label)
    if timestamp is not None and not ISO8601_RE.match(str(timestamp)):
        check(False, f"{label}: timestamp {timestamp!r} is not UTC ISO-8601 (YYYY-MM-DDTHH:MM:SSZ)")

    require_field(data, "builder.hostname", label)
    require_field(data, "builder.rustc", label)
    require_field(data, "builder.cargo", label)

    require_field(data, "kernel_pipeline.kernel_version", label)
    require_field(data, "base_rootfs.family", label)

    # "output hashes" — provenance itself must carry (or directly
    # reference) hashes of the produced release artifacts, not merely
    # describe build inputs/tooling.
    has_output_hashes = False
    for key in ("output_hashes", "outputs", "artifact_hashes"):
        val = data.get(key)
        if isinstance(val, (list, dict)) and len(val) > 0:
            has_output_hashes = True
            break
    if has_output_hashes:
        check(True, f"{label}: carries an output-hashes field")
    else:
        check(
            False,
            f"{label}: no output-hashes field (output_hashes/outputs/artifact_hashes) — spec sec.7 "
            "requires provenance to record 'output hashes'; only manifest.json currently carries them",
        )

    # "signature identity" — who/what signed (or will sign) the release,
    # e.g. a key ID / signer identity, not just a path to a detached
    # signature file.
    has_signature_identity = False
    for key in ("signature_identity", "signer", "signing_identity", "key_id"):
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            has_signature_identity = True
            break
    if has_signature_identity:
        check(True, f"{label}: carries a signature-identity field")
    else:
        check(
            False,
            f"{label}: no signature-identity field (signature_identity/signer/signing_identity/key_id) "
            "— spec sec.7 requires provenance to record 'signature identity'",
        )


def validate_security(iso_dir: Path) -> None:
    label = "security.json"
    data = load_json(iso_dir / "aios" / "security.json", label)
    if data is None:
        return
    if data.get("schema") == "aios.security_baseline.v1":
        check(True, f"{label}: schema == aios.security_baseline.v1")
    else:
        check(False, f"{label}: schema is {data.get('schema')!r}, expected aios.security_baseline.v1")
    require_field(data, "profile", label)
    require_field(data, "selinux.configured_mode", label)


def validate_boot_chain(iso_dir: Path) -> None:
    label = "boot-chain.json"
    data = load_json(iso_dir / "aios" / "boot-chain.json", label)
    if data is None:
        return
    if data.get("schema") == "aios.boot_chain_signing.v1":
        check(True, f"{label}: schema == aios.boot_chain_signing.v1")
    else:
        check(False, f"{label}: schema is {data.get('schema')!r}, expected aios.boot_chain_signing.v1")
    artifacts = data.get("artifacts")
    if isinstance(artifacts, dict) and len(artifacts) > 0:
        check(True, f"{label}: 'artifacts' map is non-empty ({len(artifacts)} entries)")
    else:
        check(False, f"{label}: 'artifacts' map missing or empty")


def validate_kernel(iso_dir: Path) -> None:
    label = "kernel.json"
    data = load_json(iso_dir / "aios" / "kernel.json", label)
    if data is None:
        return
    if data.get("schema") == "aios.kernel_pipeline.v1":
        check(True, f"{label}: schema == aios.kernel_pipeline.v1")
    else:
        check(False, f"{label}: schema is {data.get('schema')!r}, expected aios.kernel_pipeline.v1")
    require_field(data, "kernel.version", label)
    require_field(data, "modules.mode", label)
    require_field(data, "firmware.mode", label)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <iso_staging_dir>", file=sys.stderr)
        return 2

    iso_dir = Path(sys.argv[1])
    if not iso_dir.is_dir():
        print(f"ERROR: ISO staging directory not found: {iso_dir}", file=sys.stderr)
        return 2

    validate_manifest(iso_dir)
    validate_sbom(iso_dir)
    validate_provenance(iso_dir)
    validate_security(iso_dir)
    validate_boot_chain(iso_dir)
    validate_kernel(iso_dir)

    for ok, message in RESULTS:
        status = "PASS" if ok else "FAIL"
        print(f"{status}\t{message}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
