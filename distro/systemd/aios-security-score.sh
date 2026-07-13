#!/usr/bin/env bash
#
# AI-OS.NET R13.3 systemd hardening exposure scorer + release gate.
#
# Purpose
#   Enforce the R13.3 acceptance criterion "Hardening score below threshold
#   blocks release". For every AIOS systemd unit it computes an exposure score
#   from the hardening directives actually present in the unit file, then EXITS
#   NON-ZERO if any REQUIRED-class unit exceeds the threshold.
#
# Why a static scorer (not just `systemd-analyze security`)
#   `systemd-analyze security` scores LOADED units on a running systemd host and
#   is unavailable in the minimal CI image (neurocad-ci-tools). It is also non-
#   hermetic: its score depends on the host's systemd version and enabled LSMs.
#   R13.2 requires deterministic, hermetic gates. This script's DEFAULT gate is a
#   self-contained static parser of the unit files, so it produces byte-identical
#   results in CI and on a dev box. `systemd-analyze` is offered as an OPTIONAL,
#   advisory cross-check (--systemd-analyze) and never drives the exit code.
#
# Taxonomy honesty (E-grade)
#   - Static exposure gate: REAL (E3) — deterministic, tested by
#     distro/build/tests/test-rev13-daemon.sh.
#   - systemd-analyze cross-check: PARTIAL — advisory only, environment-dependent,
#     never gates.
#
# Scoring model (integer "exposure points", EP; 0 = fully hardened)
#   Each required hardening directive that is ABSENT from a unit adds its weight
#   to that unit's exposure. Present directives add nothing. A perfectly hardened
#   core unit scores 0. Weights (sum to 100 for the core set):
#       NoNewPrivileges=yes .......... 20
#       ProtectSystem=strict ......... 20
#       PrivateTmp=yes ............... 15
#       SELinuxContext= .............. 15
#       ReadWritePaths= .............. 15
#       Restart= ..................... 15
#   High-risk units (elevated CapabilityBoundingSet) additionally require:
#       CapabilityBoundingSet= ....... 15
#   Only REQUIRED-class units (core + high-risk) are GATED. Optional / isolated /
#   oneshot helper units are reported for visibility but never fail the gate,
#   because they legitimately relax some directives (e.g. third-party inference
#   binaries have no AIOS SELinux type; oneshot reporters need no Restart).
#
# Determinism (R13.2)
#   generated_epoch comes ONLY from --epoch or the git HEAD commit time, never
#   the wall clock. The unit scan order is sorted. No timestamps are read.
#
# Usage
#   distro/systemd/aios-security-score.sh [--units DIR] [--threshold EP]
#                                         [--json PATH] [--systemd-analyze]
#                                         [--epoch SECONDS]
#   Exit 0  → every required-class unit is at/under the threshold.
#   Exit 1  → at least one required-class unit exceeds the threshold.
#   Exit 2  → usage / environment error.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

UNITS_DIR="${SCRIPT_DIR}"
THRESHOLD_EP=30
JSON_OUT=""
USE_SYSTEMD_ANALYZE=false
EPOCH_ARG=""

die() { printf 'aios-security-score: %s\n' "$*" >&2; exit 2; }

usage() {
    cat <<'EOF'
Usage: aios-security-score.sh [OPTIONS]

  --units DIR         Directory of *.service unit files (default: this script's dir)
  --threshold EP      Max exposure points a REQUIRED unit may have (default: 30)
  --json PATH         Write the machine-readable JSON summary to PATH (else stdout tail)
  --systemd-analyze   Also print advisory `systemd-analyze security` scores when available
  --epoch SECONDS     Deterministic epoch for the report (default: git HEAD commit time)
  -h, --help          Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --units)          UNITS_DIR="${2:-}"; shift 2 ;;
        --threshold)      THRESHOLD_EP="${2:-}"; shift 2 ;;
        --json)           JSON_OUT="${2:-}"; shift 2 ;;
        --systemd-analyze) USE_SYSTEMD_ANALYZE=true; shift ;;
        --epoch)          EPOCH_ARG="${2:-}"; shift 2 ;;
        -h|--help)        usage; exit 0 ;;
        *)                die "unknown argument: $1" ;;
    esac
done

case "${THRESHOLD_EP}" in
    ''|*[!0-9]*) die "--threshold must be a non-negative integer (exposure points)" ;;
esac
[ -d "${UNITS_DIR}" ] || die "units dir not found: ${UNITS_DIR}"

# ── Deterministic epoch (arg > git HEAD; never wall clock) ────────────────────
if [ -n "${EPOCH_ARG}" ]; then
    case "${EPOCH_ARG}" in
        ''|*[!0-9]*) die "--epoch must be a positive integer (unix seconds)" ;;
    esac
    GENERATED_EPOCH="${EPOCH_ARG}"
else
    GENERATED_EPOCH="$(git -C "${REPO_ROOT}" show -s --format=%ct HEAD 2>/dev/null || true)"
    [ -n "${GENERATED_EPOCH}" ] || GENERATED_EPOCH=0
fi

# ── Service class membership (hardcoded, auditable) ───────────────────────────
# Required-core: L0–L4 cognitive-shell substrate that must reach a healthy state
#   after boot. Required-high-risk: units granted elevated CapabilityBoundingSet.
# capability-runtime appears in both; the high-risk (stricter) rule wins.
# Rationale is documented in distro/systemd/DAEMON-ARCHITECTURE.md.
REQUIRED_CORE="aios-policy-kernel aios-evidence-log aios-vault-broker \
aios-capability-runtime aios-fs-daemon aios-sandbox-composer \
aios-sgr-daemon aios-recovery-watchdog"
REQUIRED_HIGHRISK="aios-capability-runtime aios-hardware-daemon aios-network-daemon"

in_list() {
    # $1 = needle, $2 = space-separated haystack
    case " $2 " in
        *" $1 "*) return 0 ;;
        *)        return 1 ;;
    esac
}

classify() {
    # Prints the class for a unit base-name.
    _name="$1"
    if in_list "${_name}" "${REQUIRED_HIGHRISK}"; then
        printf 'required-high-risk'
    elif in_list "${_name}" "${REQUIRED_CORE}"; then
        printf 'required-core'
    else
        printf 'optional'
    fi
}

# ── Directive presence + weights ──────────────────────────────────────────────
has_directive() {
    # $1 = unit file, $2 = anchored ERE for the directive line
    grep -Eq "$2" "$1"
}

RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[1;34m'
RESET=$'\033[0m'
# Drop colour when not writing to a TTY so logs stay clean.
if [ ! -t 1 ]; then RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""; fi

printf '%s[SEC-SCORE]%s AIOS systemd hardening exposure — units=%s threshold=%sEP epoch=%s\n' \
    "${BLUE}" "${RESET}" "${UNITS_DIR}" "${THRESHOLD_EP}" "${GENERATED_EPOCH}"
printf '%s%-28s %-20s %6s  %s%s\n' "${BLUE}" "UNIT" "CLASS" "SCORE" "MISSING" "${RESET}"

REQUIRED_FAILURES=0
UNIT_COUNT=0
JSON_UNITS=""

# Sorted iteration → deterministic output.
for unit_file in $(printf '%s\n' "${UNITS_DIR}"/*.service | sort); do
    [ -f "${unit_file}" ] || continue
    unit_base="$(basename "${unit_file}" .service)"
    unit_class="$(classify "${unit_base}")"
    UNIT_COUNT=$(( UNIT_COUNT + 1 ))

    ep=0
    missing=""

    # Base required directive set (applies to every gated class + reported for all).
    if ! has_directive "${unit_file}" '^NoNewPrivileges=yes[[:space:]]*$'; then
        ep=$(( ep + 20 )); missing="${missing} NoNewPrivileges"
    fi
    if ! has_directive "${unit_file}" '^ProtectSystem=strict[[:space:]]*$'; then
        ep=$(( ep + 20 )); missing="${missing} ProtectSystem=strict"
    fi
    if ! has_directive "${unit_file}" '^PrivateTmp=yes[[:space:]]*$'; then
        ep=$(( ep + 15 )); missing="${missing} PrivateTmp"
    fi
    if ! has_directive "${unit_file}" '^SELinuxContext='; then
        ep=$(( ep + 15 )); missing="${missing} SELinuxContext"
    fi
    if ! has_directive "${unit_file}" '^ReadWritePaths='; then
        ep=$(( ep + 15 )); missing="${missing} ReadWritePaths"
    fi
    if ! has_directive "${unit_file}" '^Restart='; then
        ep=$(( ep + 15 )); missing="${missing} Restart"
    fi
    # High-risk units must additionally constrain their capability bounding set.
    if [ "${unit_class}" = "required-high-risk" ]; then
        if ! has_directive "${unit_file}" '^CapabilityBoundingSet='; then
            ep=$(( ep + 15 )); missing="${missing} CapabilityBoundingSet"
        fi
    fi

    [ -n "${missing}" ] || missing=" none"
    missing="${missing# }"

    # Human display: EP and a systemd-analyze-style 0.0–10.0 view (EP/10, capped).
    disp_whole=$(( ep / 10 ))
    disp_frac=$(( ep % 10 ))
    [ "${disp_whole}" -le 10 ] || { disp_whole=10; disp_frac=0; }

    gated=false
    verdict_colour="${GREEN}"
    verdict="ok"
    case "${unit_class}" in
        required-*)
            gated=true
            if [ "${ep}" -gt "${THRESHOLD_EP}" ]; then
                REQUIRED_FAILURES=$(( REQUIRED_FAILURES + 1 ))
                verdict_colour="${RED}"; verdict="OVER-THRESHOLD"
            fi
            ;;
        *)
            [ "${ep}" -eq 0 ] || verdict_colour="${YELLOW}"
            verdict="report-only"
            ;;
    esac

    printf '%s%-28s%s %-20s %2d.%d/10  %s%s%s\n' \
        "${verdict_colour}" "${unit_base}" "${RESET}" \
        "${unit_class}" "${disp_whole}" "${disp_frac}" \
        "${verdict_colour}" "${missing}" "${RESET}"

    # JSON fragment (missing directives as a JSON array).
    json_missing=""
    if [ "${missing}" != "none" ]; then
        for d in ${missing}; do
            json_missing="${json_missing}\"${d}\","
        done
        json_missing="${json_missing%,}"
    fi
    frag="$(printf '{"unit":"%s.service","class":"%s","gated":%s,"exposure_ep":%d,"score_out_of_10":"%d.%d","missing":[%s],"verdict":"%s"}' \
        "${unit_base}" "${unit_class}" "${gated}" "${ep}" \
        "${disp_whole}" "${disp_frac}" "${json_missing}" "${verdict}")"
    JSON_UNITS="${JSON_UNITS}${frag},"
done

JSON_UNITS="${JSON_UNITS%,}"

GATE_STATUS="pass"
[ "${REQUIRED_FAILURES}" -eq 0 ] || GATE_STATUS="fail"

JSON="$(printf '{"schema":"aios.systemd_security_score.v1","generated_epoch":%s,"units_dir":"%s","threshold_ep":%d,"unit_count":%d,"required_failures":%d,"gate":"%s","units":[%s]}' \
    "${GENERATED_EPOCH}" "${UNITS_DIR}" "${THRESHOLD_EP}" \
    "${UNIT_COUNT}" "${REQUIRED_FAILURES}" "${GATE_STATUS}" "${JSON_UNITS}")"

if [ -n "${JSON_OUT}" ]; then
    printf '%s\n' "${JSON}" > "${JSON_OUT}"
    printf '%s[SEC-SCORE]%s JSON summary written: %s\n' "${BLUE}" "${RESET}" "${JSON_OUT}"
else
    printf '%s[SEC-SCORE]%s JSON: %s\n' "${BLUE}" "${RESET}" "${JSON}"
fi

# ── Optional advisory cross-check (never gates) ───────────────────────────────
if [ "${USE_SYSTEMD_ANALYZE}" = true ]; then
    if command -v systemd-analyze >/dev/null 2>&1; then
        printf '%s[SEC-SCORE]%s advisory systemd-analyze security (offline, non-gating):\n' \
            "${BLUE}" "${RESET}"
        for unit_file in $(printf '%s\n' "${UNITS_DIR}"/*.service | sort); do
            [ -f "${unit_file}" ] || continue
            # --offline is best-effort; older systemd lacks it. Failure is non-fatal.
            _sa="$(systemd-analyze security --offline=true "${unit_file}" 2>/dev/null \
                | awk '/Overall exposure level/ {print $0}')" || true
            printf '  %-28s %s\n' "$(basename "${unit_file}" .service)" "${_sa:-<systemd-analyze offline unsupported>}"
        done
    else
        printf '%s[SEC-SCORE]%s systemd-analyze not available — advisory cross-check skipped (PARTIAL)\n' \
            "${YELLOW}" "${RESET}"
    fi
fi

# ── Verdict ───────────────────────────────────────────────────────────────────
if [ "${REQUIRED_FAILURES}" -eq 0 ]; then
    printf '%s[SEC-SCORE]%s GATE PASS — all %d required-class units at/under %sEP\n' \
        "${GREEN}" "${RESET}" "${UNIT_COUNT}" "${THRESHOLD_EP}"
    exit 0
else
    printf '%s[SEC-SCORE]%s GATE FAIL — %d required-class unit(s) exceed %sEP\n' \
        "${RED}" "${RESET}" "${REQUIRED_FAILURES}" "${THRESHOLD_EP}" >&2
    exit 1
fi
