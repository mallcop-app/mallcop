#!/usr/bin/env bash
# render-chart.sh — Render a mallcop chart template with runtime substitutions.
#
# Usage:
#   RUN_ID=fanout-validate-20260429 \
#   FORGE_API_KEY=forge-sk-... \
#   MODEL=claude-haiku-4-5 \
#   scripts/render-chart.sh charts/mallcop-operational.toml.tmpl <output-path>
#
# Optional environment variables:
#   FORGE_API_URL   — Forge API base URL (default: https://forge.3dl.dev)
#   MODEL           — Model ID to use (default: claude-haiku-4-5)
#   TOOL_BIN_DIR    — Tool binary directory (default: <repo-root>/bin)
#   WORK_CAMPFIRE   — Hex campfire ID to use as the work campfire.
#                     If unset, the template placeholder "operational-<RUN_ID>"
#                     is used (requires a named campfire to be set up).
#
# Substitutions applied:
#   {{MODEL}}        → $MODEL
#   {{RUN_ID}}       → $RUN_ID
#   {{FORGE_API_URL}} → $FORGE_API_URL
#   {{FORGE_API_KEY}} → $FORGE_API_KEY
#   {{TOOL_BIN_DIR}} → $TOOL_BIN_DIR
#   operational-<RUN_ID> (campfire name) → $WORK_CAMPFIRE (if set)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TEMPLATE="${1:-}"
OUTPUT="${2:-}"

if [[ -z "${TEMPLATE}" || -z "${OUTPUT}" ]]; then
  echo "Usage: $0 <template.toml.tmpl> <output.toml>" >&2
  exit 1
fi

if [[ ! -f "${TEMPLATE}" ]]; then
  echo "Error: template not found: ${TEMPLATE}" >&2
  exit 1
fi

RUN_ID="${RUN_ID:-}"
if [[ -z "${RUN_ID}" ]]; then
  echo "Error: RUN_ID is required" >&2
  exit 1
fi

FORGE_API_URL="${FORGE_API_URL:-https://forge.3dl.dev}"
FORGE_API_KEY="${FORGE_API_KEY:-}"
MODEL="${MODEL:-claude-haiku-4-5}"
TOOL_BIN_DIR="${TOOL_BIN_DIR:-${REPO_ROOT}/bin}"
WORK_CAMPFIRE="${WORK_CAMPFIRE:-}"

if [[ -z "${FORGE_API_KEY}" ]]; then
  echo "Error: FORGE_API_KEY is required" >&2
  exit 1
fi

mkdir -p "$(dirname "${OUTPUT}")"

SED_EXPR="s/{{MODEL}}/${MODEL}/g; \
   s/{{RUN_ID}}/${RUN_ID}/g; \
   s|{{FORGE_API_URL}}|${FORGE_API_URL}|g; \
   s|{{FORGE_API_KEY}}|${FORGE_API_KEY}|g; \
   s|{{TOOL_BIN_DIR}}|${TOOL_BIN_DIR}|g"

if [[ -n "${WORK_CAMPFIRE}" ]]; then
  # Replace only the campfire name in the worksources section (not the key_file path)
  sed "${SED_EXPR}" "${TEMPLATE}" | \
    sed "s|campfire = \"operational-${RUN_ID}\"|campfire = \"${WORK_CAMPFIRE}\"|g" \
    > "${OUTPUT}"
else
  sed "${SED_EXPR}" "${TEMPLATE}" > "${OUTPUT}"
fi

echo "rendered: ${OUTPUT}"

# Show a quick verification of key fields
echo "--- verification ---"
grep -E "model\s*=|forge_api_url|api_key\s*=|score_floor|enabled\s*=\s*true" "${OUTPUT}" | head -8
