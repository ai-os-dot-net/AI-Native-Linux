#!/usr/bin/env bash
#
# AI-OS.NET R13.2 — build-input lock generator.
#
# Captures the pinned, verifiable build inputs of the CURRENT tree into a
# deterministic JSON lockfile (build-inputs.lock.json). This is the INPUT side
# of the reproducible-build contract (REV13-ENTERPRISE-SPEC.md §5): what source,
# what dependencies, what tools a release was built from.
#
# It does NOT modify any existing build script. It only reads:
#   - Cargo.lock                                    (Rust dependency pins)
#   - rust-toolchain.toml or `rustc --version`      (Rust toolchain pin)
#   - distro/build/build-opensuse-rootfs.sh         (BASE_PACKAGES + repo URLs)
#   - host toolchain (xorriso/mksquashfs/grub/veritysetup)
#   - git HEAD commit timestamp                     (SOURCE_DATE_EPOCH)
#
# Output is deterministic: sorted object keys, preserved array order, and NO
# wall-clock timestamps — the only time value is the git-commit-derived epoch.
# Two consecutive runs over an unchanged tree are byte-identical.
#
# Usage:
#   generate-build-lock.sh [--repo-root DIR] [--output FILE] [--stdout]
#
#   --repo-root DIR   tree to inspect            (default: repo root of this script)
#   --output FILE     lockfile path to write     (default: <root>/distro/build/build-inputs.lock.json)
#   --stdout          print JSON to stdout instead of writing a file
#
# Env:
#   SOURCE_DATE_EPOCH  overrides the git-derived epoch (used for non-git trees)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

REPO_ROOT="${DEFAULT_ROOT}"
OUTPUT=""
TO_STDOUT=false

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --repo-root) [ "$#" -ge 2 ] || { echo "--repo-root requires DIR" >&2; exit 2; }; REPO_ROOT="$2"; shift 2 ;;
        --output)    [ "$#" -ge 2 ] || { echo "--output requires FILE" >&2; exit 2; }; OUTPUT="$2"; shift 2 ;;
        --stdout)    TO_STDOUT=true; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 3; }

REPO_ROOT="$(cd "${REPO_ROOT}" && pwd)"
CARGO_LOCK="${REPO_ROOT}/Cargo.lock"
ROOTFS_SCRIPT="${REPO_ROOT}/distro/build/build-opensuse-rootfs.sh"

[ -f "${CARGO_LOCK}" ]    || { echo "Cargo.lock not found: ${CARGO_LOCK}" >&2; exit 4; }
[ -f "${ROOTFS_SCRIPT}" ] || { echo "rootfs script not found: ${ROOTFS_SCRIPT}" >&2; exit 4; }

# ── (a) Cargo inputs ──────────────────────────────────────────────────────────
cargo_sha="$(sha256sum "${CARGO_LOCK}" | awk '{print $1}')"
crate_count="$(grep -c '^\[\[package\]\]' "${CARGO_LOCK}" || true)"
crate_count="${crate_count:-0}"

if [ -f "${REPO_ROOT}/rust-toolchain.toml" ]; then
    rust_src="rust-toolchain.toml"
    rust_ver="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
        "${REPO_ROOT}/rust-toolchain.toml" | head -1)"
    [ -n "${rust_ver}" ] || rust_ver="unspecified"
elif command -v rustc >/dev/null 2>&1; then
    rust_src="rustc"
    rust_ver="$(rustc --version 2>/dev/null | head -1 || printf 'unknown')"
else
    rust_src="none"
    rust_ver="absent"
fi

# ── (b) rootfs package inputs (parsed, not hardcoded) ─────────────────────────
mapfile -t pkgs < <(awk '
    /^BASE_PACKAGES=\(/ { f=1; next }
    f && /^\)/          { f=0 }
    f {
        gsub(/[ \t]/, "")
        if ($0 != "" && $0 !~ /^#/) print
    }' "${ROOTFS_SCRIPT}")
pkg_count="${#pkgs[@]}"

mapfile -t repos < <(grep -oE "https://download\.opensuse\.org[^\"' )]*" "${ROOTFS_SCRIPT}" | sort -u)
repo_count="${#repos[@]}"

if [ "${pkg_count}" -gt 0 ]; then
    pkgs_json="$(printf '%s\n' "${pkgs[@]}" | jq -R . | jq -s .)"
else
    pkgs_json="[]"
fi
if [ "${repo_count}" -gt 0 ]; then
    repos_json="$(printf '%s\n' "${repos[@]}" | jq -R . | jq -s .)"
else
    repos_json="[]"
fi

# ── (c) toolchain inputs (host-dependent; "absent" recorded honestly) ─────────
capture_version() {
    local cmd="$1"; shift
    local out
    if command -v "${cmd}" >/dev/null 2>&1; then
        out="$("$@" 2>&1 || true)"
        printf '%s\n' "${out}" | sed -n '1{s/[[:space:]]*$//;p;}'
    else
        printf 'absent'
    fi
}

xorriso_v="$(capture_version xorriso xorriso -version)"
mksquashfs_v="$(capture_version mksquashfs mksquashfs -version)"
veritysetup_v="$(capture_version veritysetup veritysetup --version)"

if command -v grub2-mkrescue >/dev/null 2>&1; then
    grub_v="$(grub2-mkrescue --version 2>&1 | sed -n '1{s/[[:space:]]*$//;p;}')"
elif command -v grub-mkrescue >/dev/null 2>&1; then
    grub_v="$(grub-mkrescue --version 2>&1 | sed -n '1{s/[[:space:]]*$//;p;}')"
else
    grub_v="absent"
fi

# ── (d) SOURCE_DATE_EPOCH (git HEAD commit timestamp) ─────────────────────────
epoch="${SOURCE_DATE_EPOCH:-$(git -C "${REPO_ROOT}" log -1 --format=%ct HEAD 2>/dev/null || echo 0)}"
case "${epoch}" in
    ''|*[!0-9]*) epoch=0 ;;
esac
git_rev="$(git -C "${REPO_ROOT}" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"

# ── Assemble deterministic JSON (jq -S = sorted keys; arrays keep order) ──────
lock_json="$(jq -Sn \
    --arg    schema        "aios.build-inputs.lock.v1" \
    --arg    cargo_path    "Cargo.lock" \
    --arg    cargo_sha     "${cargo_sha}" \
    --argjson crate_count  "${crate_count}" \
    --arg    rust_src      "${rust_src}" \
    --arg    rust_ver      "${rust_ver}" \
    --argjson base_packages "${pkgs_json}" \
    --argjson pkg_count    "${pkg_count}" \
    --argjson repositories "${repos_json}" \
    --arg    xorriso       "${xorriso_v}" \
    --arg    mksquashfs    "${mksquashfs_v}" \
    --arg    grub          "${grub_v}" \
    --arg    veritysetup   "${veritysetup_v}" \
    --argjson epoch        "${epoch}" \
    --arg    git_rev       "${git_rev}" \
    '{
        schema: $schema,
        cargo: {
            lockfile_path:   $cargo_path,
            lockfile_sha256: $cargo_sha,
            crate_count:     $crate_count,
            rust_toolchain:  { source: $rust_src, version: $rust_ver }
        },
        rootfs: {
            base_packages:      $base_packages,
            base_package_count: $pkg_count,
            repositories:       $repositories
        },
        toolchain: {
            xorriso:       $xorriso,
            mksquashfs:    $mksquashfs,
            grub_mkrescue: $grub,
            veritysetup:   $veritysetup
        },
        source: {
            source_date_epoch: $epoch,
            git_revision:      $git_rev
        }
    }')"

if ${TO_STDOUT}; then
    printf '%s\n' "${lock_json}"
else
    [ -n "${OUTPUT}" ] || OUTPUT="${REPO_ROOT}/distro/build/build-inputs.lock.json"
    printf '%s\n' "${lock_json}" > "${OUTPUT}"
    echo "Wrote build-input lock: ${OUTPUT}" >&2
fi
