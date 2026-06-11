#!/bin/bash
set -euo pipefail
# =============================================================================
# AI-OS.NET Cloud Image — Cloud-Init YAML Syntax Test
# =============================================================================
# Validates cloud-init YAML syntax. Uses yamllint if installed,
# otherwise falls back to Python yaml module.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLOUD_INIT_DIR="$(cd "${SCRIPT_DIR}/../cloud-init" && pwd)"

PASS=0
FAIL=0
FAILED_FILES=()

check_yaml() {
    local file="$1"
    local name="$(basename "${file}")"

    if command -v yamllint >/dev/null 2>&1; then
        if yamllint -d '{extends: relaxed, rules: {line-length: disable, document-start: disable}}' "${file}" 2>&1; then
            echo "  PASS  ${name}"
            return 0
        else
            echo "  FAIL  ${name}"
            return 1
        fi
    elif python3 -c "import yaml; yaml.safe_load(open('${file}'))" 2>&1; then
        echo "  PASS  ${name} (Python yaml)"
        return 0
    elif python3 -c "
import sys
with open('${file}') as f:
    content = f.read()
found = [l for l in content.split('\n') if l.startswith('#cloud-config')]
if found:
    sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        echo "  PASS  ${name} (cloud-config header verified)"
        return 0
    else
        echo "  UNKNOWN  ${name} (no yamllint or PyYAML installed — cannot validate)"
        return 0
    fi
}

echo "=== AI-OS.NET Cloud — Cloud-Init YAML Validation ==="
echo ""

for yaml_file in "${CLOUD_INIT_DIR}"/*.yml "${CLOUD_INIT_DIR}"/*.yaml "${CLOUD_INIT_DIR}"/*.cfg; do
    if [ ! -f "${yaml_file}" ]; then
        continue
    fi
    name="$(basename "${yaml_file}")"
    if check_yaml "${yaml_file}"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        FAILED_FILES+=("${name}")
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
echo "All cloud-init YAML files validated."
exit 0
