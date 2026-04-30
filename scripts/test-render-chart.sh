#!/usr/bin/env bash
# test-render-chart.sh — Integration assertions for render-chart.sh per-stage MODEL overrides.
#
# Cases:
#   1. Back-compat: MODEL=glm-4.7-flash (no per-stage vars) → all six seeds use glm-4.7-flash.
#   2. Per-stage:   MODEL=glm-4.7-flash INVESTIGATE_MODEL=qwen3-32b →
#                   investigate seed = qwen3-32b, all other seeds = glm-4.7-flash.
#
# Exit 0 on all assertions passing, non-zero otherwise.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RENDER="${SCRIPT_DIR}/render-chart.sh"
TEMPLATE="${REPO_ROOT}/charts/mallcop-operational.toml.tmpl"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

PASS=0
FAIL=0

assert_contains() {
  local label="$1"
  local file="$2"
  local pattern="$3"
  if grep -qF "${pattern}" "${file}"; then
    echo "  PASS: ${label}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${label}"
    echo "        expected pattern: ${pattern}"
    echo "        in file: ${file}"
    grep -n "model" "${file}" | head -20 || true
    FAIL=$((FAIL + 1))
  fi
}

assert_not_contains() {
  local label="$1"
  local file="$2"
  local pattern="$3"
  if ! grep -qF "${pattern}" "${file}"; then
    echo "  PASS: ${label}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${label}"
    echo "        unexpected pattern present: ${pattern}"
    FAIL=$((FAIL + 1))
  fi
}

# ---------------------------------------------------------------------------
# Case 1: back-compat — single MODEL, no per-stage vars set
# ---------------------------------------------------------------------------
echo "=== Case 1: back-compat (MODEL=glm-4.7-flash, no per-stage vars) ==="
OUT1="${TMPDIR}/rendered-compat.toml"
RUN_ID=test-compat \
  FORGE_API_KEY=forge-sk-test \
  MODEL=glm-4.7-flash \
  "${RENDER}" "${TEMPLATE}" "${OUT1}"

assert_contains     "triage seed has glm-4.7-flash"          "${OUT1}" 'model     = "glm-4.7-flash"'
assert_contains     "investigate seed has glm-4.7-flash"     "${OUT1}" 'model     = "glm-4.7-flash"'
assert_contains     "deep-investigate seed has glm-4.7-flash" "${OUT1}" 'model = "glm-4.7-flash"'
assert_contains     "investigate-merge seed has glm-4.7-flash" "${OUT1}" 'model = "glm-4.7-flash"'
assert_contains     "escalate seed has glm-4.7-flash"        "${OUT1}" 'model     = "glm-4.7-flash"'
assert_contains     "heal seed has glm-4.7-flash"            "${OUT1}" 'model     = "glm-4.7-flash"'
assert_not_contains "no unresolved placeholders"             "${OUT1}" '{{MODEL}}'
assert_not_contains "no TRIAGE_MODEL placeholder"            "${OUT1}" '{{TRIAGE_MODEL}}'
assert_not_contains "no INVESTIGATE_MODEL placeholder"       "${OUT1}" '{{INVESTIGATE_MODEL}}'
assert_not_contains "no DEEP_INVESTIGATE_MODEL placeholder"  "${OUT1}" '{{DEEP_INVESTIGATE_MODEL}}'
assert_not_contains "no INVESTIGATE_MERGE_MODEL placeholder" "${OUT1}" '{{INVESTIGATE_MERGE_MODEL}}'
assert_not_contains "no ESCALATE_MODEL placeholder"          "${OUT1}" '{{ESCALATE_MODEL}}'
assert_not_contains "no HEAL_MODEL placeholder"              "${OUT1}" '{{HEAL_MODEL}}'

# ---------------------------------------------------------------------------
# Case 2: per-stage override — INVESTIGATE_MODEL=qwen3-32b, rest fall back to MODEL
# ---------------------------------------------------------------------------
echo ""
echo "=== Case 2: per-stage override (MODEL=glm-4.7-flash INVESTIGATE_MODEL=qwen3-32b) ==="
OUT2="${TMPDIR}/rendered-per-stage.toml"
RUN_ID=test-perstage \
  FORGE_API_KEY=forge-sk-test \
  MODEL=glm-4.7-flash \
  INVESTIGATE_MODEL=qwen3-32b \
  "${RENDER}" "${TEMPLATE}" "${OUT2}"

assert_contains     "triage seed has glm-4.7-flash"          "${OUT2}" 'model     = "glm-4.7-flash"'
assert_contains     "investigate seed has qwen3-32b"         "${OUT2}" 'model     = "qwen3-32b"'
assert_contains     "deep-investigate seed has glm-4.7-flash" "${OUT2}" 'model = "glm-4.7-flash"'
assert_contains     "investigate-merge seed has glm-4.7-flash" "${OUT2}" 'model = "glm-4.7-flash"'
assert_contains     "escalate seed has glm-4.7-flash"        "${OUT2}" 'model     = "glm-4.7-flash"'
assert_contains     "heal seed has glm-4.7-flash"            "${OUT2}" 'model     = "glm-4.7-flash"'
assert_not_contains "investigate does not have glm-flash as triage-style model line" \
                    "${OUT2}" '{{INVESTIGATE_MODEL}}'

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Summary: ${PASS} passed, ${FAIL} failed ==="
if [[ ${FAIL} -gt 0 ]]; then
  exit 1
fi
