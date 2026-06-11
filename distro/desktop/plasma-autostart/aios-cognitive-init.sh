#!/bin/sh
#
# AI-OS.NET Cognitive Init Autostart
#
# Checks if Ollama or vLLM are available and pre-warms AI models
# for the cognitive core. Runs asynchronously to avoid blocking
# the desktop session startup.
#
# POSIX-compatible

set -e

msg()  { printf '[AIOS-COGNITIVE] %s\n' "$*"; }
warn() { printf '[AIOS-COGNITIVE] %s\n' "$*" >&2; }
ok()   { printf '[AIOS-COGNITIVE] %s\n' "$*"; }

AIOS_BIN="${AIOS_BIN:-/usr/bin/aios}"

OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"
VLLM_HOST="${VLLM_HOST:-http://127.0.0.1:8000}"

COGNITIVE_MODEL="${AIOS_COGNITIVE_MODEL:-}"
COGNITIVE_PREWARM="${AIOS_COGNITIVE_PREWARM:-0}"

msg "Checking AI model providers..."

check_ollama() {
    if command -v ollama >/dev/null 2>&1; then
        ok "Ollama found."
        if [ "${COGNITIVE_PREWARM}" -eq 1 ] && [ -n "${COGNITIVE_MODEL}" ]; then
            msg "Pre-warming Ollama model: ${COGNITIVE_MODEL}"
            ollama pull "${COGNITIVE_MODEL}" >/dev/null 2>&1 &
        fi
        return 0
    fi

    if command -v curl >/dev/null 2>&1; then
        if curl -s -o /dev/null -w '%{http_code}' "${OLLAMA_HOST}/api/tags" 2>/dev/null | grep -q '200'; then
            ok "Ollama HTTP endpoint available at ${OLLAMA_HOST}."
            return 0
        fi
    fi

    warn "Ollama not available — cognitive core will use fallback providers."
    return 1
}

check_vllm() {
    if command -v vllm >/dev/null 2>&1; then
        ok "vLLM found."
        return 0
    fi

    if command -v curl >/dev/null 2>&1; then
        if curl -s -o /dev/null -w '%{http_code}' "${VLLM_HOST}/health" 2>/dev/null | grep -q '200'; then
            ok "vLLM HTTP endpoint available at ${VLLM_HOST}."
            return 0
        fi
    fi

    warn "vLLM not available."
    return 1
}

check_ollama
check_vllm

if [ -x "${AIOS_BIN}" ]; then
    msg "Triggering cognitive core readiness check..."
    "${AIOS_BIN}" cognitive status 2>/dev/null || warn "Cognitive core status query failed (may not be running yet)."
else
    warn "aios CLI not found — skipping cognitive core check."
fi

msg "Cognitive init complete."
