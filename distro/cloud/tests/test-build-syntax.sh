#!/bin/bash
set -euo pipefail
# =============================================================================
# AI-OS.NET Cloud Image — Bash Syntax Test
# =============================================================================
# Runs bash -n on all shell scripts in distro/cloud/.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLOUD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PASS=0
FAIL=0
FAILED_FILES=()

echo "=== AI-OS.NET Cloud — Bash Syntax Check ==="
echo ""

for script in "${CLOUD_DIR}"/*.sh; do
    if [ ! -f "${script}" ]; then
        continue
    fi
    script_name="$(basename "${script}")"
    if bash -n "${script}" 2>&1; then
        echo "  PASS  ${script_name}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  ${script_name}"
        FAIL=$((FAIL + 1))
        FAILED_FILES+=("${script_name}")
    fi
done

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [ ${FAIL} -gt 0 ]; then
    echo ""
    echo "Failed files:"
    for f in "${FAILED_FILES[@]}"; do
        echo "  - ${f}"
    done
    exit 1
fi

echo ""
echo "All bash syntax checks passed."
exit 0
