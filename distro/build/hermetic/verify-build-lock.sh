#!/usr/bin/env bash
#
# AI-OS.NET R13.2 — build-input lock verifier.
#
# Given an existing build-inputs.lock.json and the CURRENT tree, re-derives the
# inputs (via generate-build-lock.sh, the single source of truth) and checks for
# drift. Enforces REV13-ENTERPRISE-SPEC.md §5 "Rebuild drift is detected and
# reported" for the input side of the contract.
#
# Verdict policy:
#   FAIL (exit 1, fail-closed) — Cargo.lock sha256 drift, crate-count drift,
#                                BASE_PACKAGES set mismatch, repo URL mismatch,
#                                missing/unreadable lock, missing required field
#   WARN (exit 0)             — toolchain / rust version drift (host-dependent)
#
# Usage:
#   verify-build-lock.sh [--repo-root DIR] [--lock FILE] [--json]
#
#   --repo-root DIR   tree to verify against  (default: repo root of this script)
#   --lock FILE       lockfile to verify      (default: <root>/distro/build/build-inputs.lock.json)
#   --json            emit a machine verdict as JSON (no colored output)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
GEN="${SCRIPT_DIR}/generate-build-lock.sh"

REPO_ROOT="${DEFAULT_ROOT}"
LOCK=""
JSON_OUT=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --repo-root) [ "$#" -ge 2 ] || { echo "--repo-root requires DIR" >&2; exit 2; }; REPO_ROOT="$2"; shift 2 ;;
        --lock)      [ "$#" -ge 2 ] || { echo "--lock requires FILE" >&2; exit 2; }; LOCK="$2"; shift 2 ;;
        --json)      JSON_OUT=true; shift ;;
        -h|--help)   sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 3; }
[ -x "${GEN}" ] || [ -f "${GEN}" ] || { echo "generator not found: ${GEN}" >&2; exit 3; }

REPO_ROOT="$(cd "${REPO_ROOT}" && pwd)"
[ -n "${LOCK}" ] || LOCK="${REPO_ROOT}/distro/build/build-inputs.lock.json"
[ -f "${LOCK}" ] || { echo "lock file not found (fail-closed): ${LOCK}" >&2; exit 5; }

STORED="$(cat "${LOCK}")"
jq -e . >/dev/null 2>&1 <<<"${STORED}" || { echo "lock file is not valid JSON (fail-closed): ${LOCK}" >&2; exit 5; }

# Re-derive current inputs from the same generator = single source of truth.
CUR="$(bash "${GEN}" --repo-root "${REPO_ROOT}" --stdout)"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[1;34m'; RESET=$'\033[0m'
FAILS=0
WARNS=0
CHECKS_JSON="[]"

record() { # status name detail
    local status="$1" name="$2" detail="${3:-}"
    case "${status}" in
        FAIL) FAILS=$(( FAILS + 1 )) ;;
        WARN) WARNS=$(( WARNS + 1 )) ;;
    esac
    if ! ${JSON_OUT}; then
        local color="${GREEN}"
        case "${status}" in FAIL) color="${RED}" ;; WARN) color="${YELLOW}" ;; esac
        printf '  %s%-4s%s %s' "${color}" "${status}" "${RESET}" "${name}"
        [ -n "${detail}" ] && printf ' — %s' "${detail}"
        printf '\n'
    fi
    CHECKS_JSON="$(jq -c --arg s "${status}" --arg n "${name}" --arg d "${detail}" \
        '. += [{name:$n, status:$s, detail:$d}]' <<<"${CHECKS_JSON}")"
}

jval() { jq -r "$1 // empty" <<<"$2"; }

${JSON_OUT} || printf '%s[verify]%s build-input lock: %s\n' "${BLUE}" "${RESET}" "${LOCK}"

# ── Cargo.lock sha256 (FAIL on drift) ─────────────────────────────────────────
lock_sha="$(jval '.cargo.lockfile_sha256' "${STORED}")"
cur_sha="$(jval '.cargo.lockfile_sha256' "${CUR}")"
if [ -z "${lock_sha}" ]; then
    record FAIL "cargo.lockfile_sha256" "missing in lock"
elif [ "${lock_sha}" = "${cur_sha}" ]; then
    record PASS "Cargo.lock sha256" "${lock_sha}"
else
    record FAIL "Cargo.lock sha256" "lock=${lock_sha} current=${cur_sha}"
fi

# ── crate count (FAIL on drift) ───────────────────────────────────────────────
lock_cc="$(jval '.cargo.crate_count' "${STORED}")"
cur_cc="$(jval '.cargo.crate_count' "${CUR}")"
if [ -z "${lock_cc}" ]; then
    record FAIL "cargo.crate_count" "missing in lock"
elif [ "${lock_cc}" = "${cur_cc}" ]; then
    record PASS "crate count" "${lock_cc}"
else
    record FAIL "crate count" "lock=${lock_cc} current=${cur_cc}"
fi

# ── BASE_PACKAGES set (FAIL + diff on mismatch) ───────────────────────────────
lock_pkgs="$(jq -r '.rootfs.base_packages[]?' <<<"${STORED}" | sort)"
cur_pkgs="$(jq -r '.rootfs.base_packages[]?' <<<"${CUR}" | sort)"
if [ "${lock_pkgs}" = "${cur_pkgs}" ]; then
    record PASS "BASE_PACKAGES set" "$(jval '.rootfs.base_package_count' "${STORED}") packages"
else
    pkg_diff="$(diff <(printf '%s\n' "${lock_pkgs}") <(printf '%s\n' "${cur_pkgs}") || true)"
    record FAIL "BASE_PACKAGES set" "package set drift (< lock / > current)"
    if ! ${JSON_OUT}; then
        printf '%s\n' "${pkg_diff}" | sed 's/^/      /'
    else
        CHECKS_JSON="$(jq -c --arg d "${pkg_diff}" \
            '(.[-1].diff) = $d' <<<"${CHECKS_JSON}")"
    fi
fi

# ── zypper repo URLs (FAIL + diff on mismatch) ────────────────────────────────
lock_repos="$(jq -r '.rootfs.repositories[]?' <<<"${STORED}" | sort)"
cur_repos="$(jq -r '.rootfs.repositories[]?' <<<"${CUR}" | sort)"
if [ "${lock_repos}" = "${cur_repos}" ]; then
    record PASS "zypper repo URLs" "match"
else
    repo_diff="$(diff <(printf '%s\n' "${lock_repos}") <(printf '%s\n' "${cur_repos}") || true)"
    record FAIL "zypper repo URLs" "repo URL drift (< lock / > current)"
    if ! ${JSON_OUT}; then
        printf '%s\n' "${repo_diff}" | sed 's/^/      /'
    else
        CHECKS_JSON="$(jq -c --arg d "${repo_diff}" '(.[-1].diff) = $d' <<<"${CHECKS_JSON}")"
    fi
fi

# ── toolchain + rust version drift (WARN, host-dependent) ─────────────────────
lock_rust="$(jval '.cargo.rust_toolchain.version' "${STORED}")"
cur_rust="$(jval '.cargo.rust_toolchain.version' "${CUR}")"
if [ "${lock_rust}" = "${cur_rust}" ]; then
    record PASS "rust toolchain" "${lock_rust}"
else
    record WARN "rust toolchain" "lock=${lock_rust} host=${cur_rust}"
fi

for key in xorriso mksquashfs grub_mkrescue veritysetup; do
    lv="$(jq -r --arg k "${key}" '.toolchain[$k] // "absent"' <<<"${STORED}")"
    cv="$(jq -r --arg k "${key}" '.toolchain[$k] // "absent"' <<<"${CUR}")"
    if [ "${lv}" = "${cv}" ]; then
        record PASS "toolchain ${key}" "${lv}"
    else
        record WARN "toolchain ${key}" "lock=${lv} host=${cv}"
    fi
done

verdict="pass"
[ "${FAILS}" -eq 0 ] || verdict="fail"

if ${JSON_OUT}; then
    jq -n --arg verdict "${verdict}" --argjson fails "${FAILS}" --argjson warns "${WARNS}" \
        --argjson checks "${CHECKS_JSON}" \
        '{verdict:$verdict, fails:$fails, warns:$warns, checks:$checks}'
else
    printf '\n%s[verify]%s verdict=%s  fails=%d  warns=%d\n' "${BLUE}" "${RESET}" "${verdict}" "${FAILS}" "${WARNS}"
fi

[ "${FAILS}" -eq 0 ] || exit 1
exit 0
