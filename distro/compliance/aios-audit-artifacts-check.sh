#!/usr/bin/env bash
#
# AI-OS.NET R13.8 — mandatory audit-artifact presence gate.
#
# Fails closed if any REQUIRED audit artifact for a release candidate is missing
# or empty. This is the enforcement behind the spec acceptance line "Release is
# blocked if mandatory audit artifacts are missing" (REV13-ENTERPRISE-SPEC.md §11):
# a release pipeline runs this against the generated audit-export directory (and,
# in the assemble stage, against the built ISO's SBOM/provenance) and a missing or
# zero-byte artifact aborts the release.
#
# It only checks PRESENCE + non-emptiness (and light JSON well-formedness) of files
# that OTHER, already-verified tooling produces — it fabricates no compliance data.
#
# Usage:
#   aios-audit-artifacts-check.sh --dir DIR [--require a.json,b.csv,...]
#
# Defaults to the three files aios-compliance-export.py emits. Exit: 0 all present,
# 1 one or more missing/empty/malformed, 2 usage error.
set -u

DIR=""
REQUIRE="compliance-report.json,control-matrix.csv,exception-register.json,compliance-report.md"

die() { printf '[audit-check] ERROR: %s\n' "$*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --dir)     DIR="${2:-}"; shift 2 ;;
        --require) REQUIRE="${2:-}"; shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "${DIR}" ] || die "--dir DIR is required"
[ -d "${DIR}" ] || { printf '[audit-check] FAIL: audit directory missing: %s\n' "${DIR}" >&2; exit 1; }

rc=0
IFS=','
for name in ${REQUIRE}; do
    unset IFS
    name="$(printf '%s' "${name}" | sed 's/^ *//;s/ *$//')"
    [ -n "${name}" ] || continue
    path="${DIR}/${name}"
    if [ ! -f "${path}" ]; then
        printf '[audit-check] FAIL: missing mandatory audit artifact: %s\n' "${name}" >&2
        rc=1
    elif [ ! -s "${path}" ]; then
        printf '[audit-check] FAIL: mandatory audit artifact is empty: %s\n' "${name}" >&2
        rc=1
    else
        case "${name}" in
            *.json)
                if command -v python3 >/dev/null 2>&1; then
                    if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "${path}" >/dev/null 2>&1; then
                        printf '[audit-check] OK: %s\n' "${name}"
                    else
                        printf '[audit-check] FAIL: malformed JSON audit artifact: %s\n' "${name}" >&2
                        rc=1
                    fi
                else
                    printf '[audit-check] OK (json, unchecked — no python3): %s\n' "${name}"
                fi
                ;;
            *) printf '[audit-check] OK: %s\n' "${name}" ;;
        esac
    fi
    IFS=','
done
unset IFS

if [ "${rc}" -eq 0 ]; then
    printf '[audit-check] PASS: all mandatory audit artifacts present in %s\n' "${DIR}"
else
    printf '[audit-check] BLOCKED: mandatory audit artifacts missing — release must not proceed\n' >&2
fi
exit "${rc}"
