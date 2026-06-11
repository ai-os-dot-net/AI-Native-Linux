#!/bin/bash
set -euo pipefail
# =============================================================================
# AI-OS.NET Cloud Image — Packer Validate Test
# =============================================================================
# Runs 'packer validate' on all Packer templates in distro/cloud/packer/.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PACKER_DIR="$(cd "${SCRIPT_DIR}/../packer" && pwd)"

if ! command -v packer >/dev/null 2>&1; then
    echo "SKIP: packer not installed — skipping Packer template validation."
    exit 0
fi

PASS=0
FAIL=0
FAILED_FILES=()

echo "=== AI-OS.NET Cloud — Packer Template Validation ==="
echo "Packer version: $(packer version | head -1)"
echo ""

packer init "${PACKER_DIR}" 2>/dev/null || true

for template in "${PACKER_DIR}"/*.pkr.hcl; do
    if [ ! -f "${template}" ]; then
        continue
    fi
    template_name="$(basename "${template}")"
    if packer validate -evaluate-datasources=false "${template}" 2>&1; then
        echo "  PASS  ${template_name}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  ${template_name}"
        FAIL=$((FAIL + 1))
        FAILED_FILES+=("${template_name}")
    fi
done

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [ ${FAIL} -gt 0 ]; then
    echo ""
    echo "Failed templates:"
    for f in "${FAILED_FILES[@]}"; do
        echo "  - ${f}"
    done
    exit 1
fi

echo ""
echo "All Packer templates validated."
exit 0
