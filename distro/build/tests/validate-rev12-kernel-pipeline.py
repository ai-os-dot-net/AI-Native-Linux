#!/usr/bin/env python3
"""AI-OS.NET Rev.12 kernel/module/firmware pipeline validator.

Validates the ACTUALLY STAGED kernel/module/firmware output of
distro/build/build-aios-iso.sh (Step 8 "Installing kernel", Step 8b
"Staging kernel modules and firmware", Step 9 "Building initramfs") against
distro/build/REV12-DISTRIBUTION-SPEC.md section 8 acceptance tests: the
kernel image, initramfs, module tree, and firmware tree must actually exist
in the built tree, and aios/kernel.json must describe them truthfully (its
mode/version/file_count fields must match what is really on disk, not just
be present).

This is deliberately independent of validate-rev12-metadata.py, which only
checks kernel.json's shallow shape (schema + required fields) as part of
the general release-metadata gate. This validator cross-checks kernel.json
content against the real staged rootfs/initramfs/iso trees.

Usage:
    python3 validate-rev12-kernel-pipeline.py <build_workdir>

<build_workdir> is the AIOS_BUILD_WORKDIR used for the build (i.e. the
value passed to build-aios-iso.sh via AIOS_BUILD_WORKDIR). It must contain
"rootfs/", "initramfs/", and "iso/" subdirectories, matching the layout
build-aios-iso.sh always produces (BUILD_DIR/{rootfs,initramfs,iso}).

Output protocol (read by test-rev12-kernel-pipeline.sh):
    Each check emits exactly one line to stdout:
        PASS\t<message>
        FAIL\t<message>
    Nothing else is written to stdout. Diagnostic detail goes to stderr.

Exit code is always 0 (the caller counts PASS/FAIL lines); a non-zero exit
means the validator itself crashed (e.g. directory missing).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


RESULTS: list[tuple[bool, str]] = []


def check(ok: bool, message: str) -> None:
    RESULTS.append((ok, message))


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


def count_tree_files(path: Path) -> int:
    """Mirror build-aios-iso.sh's count_tree_files(): find -type f | wc -l."""
    if not path.is_dir():
        return 0
    return sum(1 for p in path.rglob("*") if p.is_file())


def check_nonempty_file(path: Path, label: str) -> bool:
    if not path.is_file():
        check(False, f"{label}: missing at {path}")
        return False
    size = path.stat().st_size
    if size <= 0:
        check(False, f"{label}: present but empty (0 bytes) at {path}")
        return False
    check(True, f"{label}: exists and is non-empty ({size} bytes)")
    return True


def validate_staged_tree(
    *,
    tree_label: str,
    disk_dir: Path,
    json_mode: Any,
    json_file_count: Any,
    json_rootfs_path: Any,
    expected_rootfs_path: str,
    empty_marker_name: str,
    real_marker_name: str | None,
) -> None:
    """Cross-check one kernel.json sub-section (modules or firmware)
    against the real staged directory on disk.

    empty_marker_name: filename written by build-aios-iso.sh when the
        source mode is "none" (e.g. AIOS_MODULES_EMPTY / AIOS_FIRMWARE_EMPTY).
    real_marker_name: a filename that must exist when the tree carries real
        staged content (e.g. "modules.dep" for the module tree). None for
        trees that don't have a fixed real-content marker (firmware).
    """
    if json_rootfs_path == expected_rootfs_path:
        check(True, f"kernel.json {tree_label}.rootfs_path == {expected_rootfs_path!r}")
    else:
        check(
            False,
            f"kernel.json {tree_label}.rootfs_path is {json_rootfs_path!r}, "
            f"expected {expected_rootfs_path!r}",
        )

    if not disk_dir.is_dir():
        check(False, f"{tree_label}: staged directory missing on disk at {disk_dir}")
        return
    check(True, f"{tree_label}: staged directory exists on disk at {disk_dir}")

    actual_count = count_tree_files(disk_dir)
    if not isinstance(json_file_count, int):
        check(False, f"kernel.json {tree_label}.file_count is not an integer: {json_file_count!r}")
    elif actual_count == json_file_count:
        check(
            True,
            f"kernel.json {tree_label}.file_count ({json_file_count}) matches real file count on disk "
            f"({actual_count})",
        )
    else:
        check(
            False,
            f"kernel.json {tree_label}.file_count LIES: claims {json_file_count} but disk actually has "
            f"{actual_count} files under {disk_dir} — spec sec.8 requires kernel.json to describe staged "
            "output truthfully",
        )

    has_empty_marker = (disk_dir / empty_marker_name).is_file()
    has_real_marker = real_marker_name is not None and (disk_dir / real_marker_name).is_file()

    if json_mode == "explicit-empty":
        if has_empty_marker:
            check(True, f"{tree_label}: mode 'explicit-empty' matches disk ({empty_marker_name} present)")
        else:
            check(
                False,
                f"{tree_label}: kernel.json claims mode 'explicit-empty' but {empty_marker_name} is "
                f"NOT present on disk at {disk_dir} — mode does not match reality",
            )
        if real_marker_name is not None and has_real_marker:
            check(
                False,
                f"{tree_label}: kernel.json claims mode 'explicit-empty' but real content marker "
                f"'{real_marker_name}' IS present on disk — mode does not match reality",
            )
    elif json_mode in ("copied", "base-rootfs"):
        if has_empty_marker:
            check(
                False,
                f"{tree_label}: kernel.json claims mode {json_mode!r} (real staged content) but the "
                f"empty-tree marker {empty_marker_name} is present on disk — mode does not match reality",
            )
        elif real_marker_name is not None:
            if has_real_marker:
                check(
                    True,
                    f"{tree_label}: mode {json_mode!r} matches disk ({real_marker_name} present, real "
                    "staged content)",
                )
            else:
                check(
                    False,
                    f"{tree_label}: kernel.json claims mode {json_mode!r} but required real-content "
                    f"marker '{real_marker_name}' is missing on disk at {disk_dir}",
                )
        else:
            # No fixed real-content marker for this tree (firmware) — real
            # content is proven by a non-zero, non-marker-only file count.
            if actual_count > 0:
                check(True, f"{tree_label}: mode {json_mode!r} matches disk (non-empty staged content, {actual_count} files)")
            else:
                check(
                    False,
                    f"{tree_label}: kernel.json claims mode {json_mode!r} but staged directory is empty "
                    f"on disk at {disk_dir}",
                )
    elif json_mode == "missing":
        check(False, f"{tree_label}: kernel.json mode is 'missing' — staging never ran or failed")
    else:
        check(False, f"{tree_label}: kernel.json mode is an unrecognized value: {json_mode!r}")


def validate_initramfs_mirror(workdir: Path, kernel_version: str, rootfs_modules_dir: Path) -> None:
    """build-aios-iso.sh Step 9 copies the staged module tree that matches
    the staged kernel version into the initramfs (INITRAMFS_DIR/lib/modules/
    <version>). Verify that mirror actually happened and actually matches."""
    label = "initramfs module mirror"
    initramfs_modules_dir = workdir / "initramfs" / "lib" / "modules" / kernel_version

    if not rootfs_modules_dir.is_dir():
        check(False, f"{label}: cannot verify — rootfs module tree missing at {rootfs_modules_dir}")
        return

    if not initramfs_modules_dir.is_dir():
        check(
            False,
            f"{label}: initramfs is missing the staged kernel-version module tree at "
            f"{initramfs_modules_dir} (spec sec.8 requires initramfs to carry the module tree that "
            "matches the staged kernel)",
        )
        return
    check(True, f"{label}: initramfs carries a module tree at usr/lib/modules/{kernel_version} equivalent")

    rootfs_count = count_tree_files(rootfs_modules_dir)
    initramfs_count = count_tree_files(initramfs_modules_dir)
    if rootfs_count == initramfs_count:
        check(True, f"{label}: initramfs module tree file count ({initramfs_count}) matches rootfs ({rootfs_count})")
    else:
        check(
            False,
            f"{label}: initramfs module tree file count ({initramfs_count}) does NOT match rootfs "
            f"({rootfs_count}) — staged trees have diverged",
        )


def validate_kernel_pipeline(workdir: Path) -> None:
    iso_dir = workdir / "iso"
    rootfs_dir = workdir / "rootfs"

    vmlinuz = iso_dir / "live" / "vmlinuz"
    initrd = iso_dir / "live" / "initrd.img"
    check_nonempty_file(vmlinuz, "live/vmlinuz")
    check_nonempty_file(initrd, "live/initrd.img")

    label = "kernel.json"
    data = load_json(iso_dir / "aios" / "kernel.json", label)
    if data is None:
        return

    if data.get("schema") == "aios.kernel_pipeline.v1":
        check(True, f"{label}: schema == aios.kernel_pipeline.v1")
    else:
        check(False, f"{label}: schema is {data.get('schema')!r}, expected aios.kernel_pipeline.v1")

    kernel = data.get("kernel", {})
    kernel_version = kernel.get("version")
    if isinstance(kernel_version, str) and kernel_version not in ("", "unknown"):
        check(True, f"{label}: kernel.version is a real value ({kernel_version!r})")
    else:
        check(False, f"{label}: kernel.version is missing/unknown ({kernel_version!r})")
        return

    if kernel.get("image") == "live/vmlinuz":
        check(True, f"{label}: kernel.image == 'live/vmlinuz'")
    else:
        check(False, f"{label}: kernel.image is {kernel.get('image')!r}, expected 'live/vmlinuz'")

    staged_source_path = kernel.get("staged_source_path")
    if isinstance(staged_source_path, str) and staged_source_path and Path(staged_source_path).is_file():
        check(True, f"{label}: kernel.staged_source_path points to a real file that still exists ({staged_source_path})")
    else:
        check(
            False,
            f"{label}: kernel.staged_source_path ({staged_source_path!r}) does not point to a real, "
            "still-existing file",
        )

    modules = data.get("modules", {})
    validate_staged_tree(
        tree_label="modules",
        disk_dir=rootfs_dir / "usr" / "lib" / "modules" / kernel_version,
        json_mode=modules.get("mode"),
        json_file_count=modules.get("file_count"),
        json_rootfs_path=modules.get("rootfs_path"),
        expected_rootfs_path=f"/usr/lib/modules/{kernel_version}",
        empty_marker_name="AIOS_MODULES_EMPTY",
        real_marker_name="modules.dep",
    )

    firmware = data.get("firmware", {})
    validate_staged_tree(
        tree_label="firmware",
        disk_dir=rootfs_dir / "usr" / "lib" / "firmware",
        json_mode=firmware.get("mode"),
        json_file_count=firmware.get("file_count"),
        json_rootfs_path=firmware.get("rootfs_path"),
        expected_rootfs_path="/usr/lib/firmware",
        empty_marker_name="AIOS_FIRMWARE_EMPTY",
        real_marker_name=None,
    )

    signing_hooks = data.get("signing_hooks", {})
    expected_modules_sig = f"usr-lib-modules-{kernel_version}.sig"
    if signing_hooks.get("modules") == expected_modules_sig:
        check(True, f"{label}: signing_hooks.modules == {expected_modules_sig!r} (matches staged kernel version)")
    else:
        check(
            False,
            f"{label}: signing_hooks.modules is {signing_hooks.get('modules')!r}, expected "
            f"{expected_modules_sig!r}",
        )

    validate_initramfs_mirror(workdir, kernel_version, rootfs_dir / "usr" / "lib" / "modules" / kernel_version)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <build_workdir>", file=sys.stderr)
        return 2

    workdir = Path(sys.argv[1])
    if not workdir.is_dir():
        print(f"ERROR: build workdir not found: {workdir}", file=sys.stderr)
        return 2

    validate_kernel_pipeline(workdir)

    for ok, message in RESULTS:
        status = "PASS" if ok else "FAIL"
        print(f"{status}\t{message}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
