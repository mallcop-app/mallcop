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
#   MALLCOP_HOME    — Absolute path to the deployment dir. When set, identity
#                     and transport paths in the rendered chart are rewritten
#                     to point at $MALLCOP_HOME/.mallcop/... instead of the
#                     legacy .run/operational-<RUN_ID>/ layout. See
#                     docs/design/deployment-and-identity.md (mallcop-pro).
#
# Substitutions applied:
#   {{MODEL}}        → $MODEL
#   {{RUN_ID}}       → $RUN_ID
#   {{FORGE_API_URL}} → $FORGE_API_URL
#   {{FORGE_API_KEY}} → $FORGE_API_KEY
#   {{TOOL_BIN_DIR}} → $TOOL_BIN_DIR
#   operational-<RUN_ID> (campfire name)      → $WORK_CAMPFIRE  (if set)
#   .run/operational-<RUN_ID>/identity.json   → $MALLCOP_HOME/.mallcop/automaton/identity.json   (if MALLCOP_HOME set)
#   .run/operational-<RUN_ID>/campfires       → $MALLCOP_HOME/.mallcop/campfires                  (if MALLCOP_HOME set)
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
MALLCOP_HOME="${MALLCOP_HOME:-}"

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

# Compose extra remaps based on optional env vars.
EXTRA_SEDS=()
if [[ -n "${WORK_CAMPFIRE}" ]]; then
  EXTRA_SEDS+=(-e "s|campfire = \"operational-${RUN_ID}\"|campfire = \"${WORK_CAMPFIRE}\"|g")
fi
if [[ -n "${MALLCOP_HOME}" ]]; then
  # Rewrite paths in the chart so it points at the deployment dir instead of
  # mallcop-legion source-tree relatives (.run/...) or cwd-relatives (agents/).
  # See docs/design/deployment-and-identity.md (mallcop-pro) for the layout.
  # The single-identity model collapses operator+automaton into one key file;
  # the chart's key_file points at .mallcop/identity.json directly (the legacy
  # .run/operational-<RUN_ID>/identity.json placeholder maps there).
  EXTRA_SEDS+=(-e "s|\.run/operational-${RUN_ID}/identity\.json|${MALLCOP_HOME}/.mallcop/identity.json|g")
  EXTRA_SEDS+=(-e "s|\.run/operational-${RUN_ID}/campfires|${MALLCOP_HOME}/.mallcop/campfires|g")
  EXTRA_SEDS+=(-e "s|^dir = \"agents\"|dir = \"${MALLCOP_HOME}/.mallcop/agents\"|g")
  EXTRA_SEDS+=(-e "s|^  \"agents/\",|  \"${MALLCOP_HOME}/.mallcop/agents/\",|g")
fi

if [[ ${#EXTRA_SEDS[@]} -gt 0 ]]; then
  sed "${SED_EXPR}" "${TEMPLATE}" | sed "${EXTRA_SEDS[@]}" > "${OUTPUT}"
else
  sed "${SED_EXPR}" "${TEMPLATE}" > "${OUTPUT}"
fi

# Bake jail_root into the rendered chart so `we start` keeps jails inside
# the deployment even when invoked without LEGION_JAIL_ROOT set. jail_root is
# a top-level key on AutomatonConfig (see legion internal/automaton/config.go).
# Prepend so it sits outside any [section] block.
if [[ -n "${MALLCOP_HOME}" ]]; then
  TMP_OUT="${OUTPUT}.render.tmp"
  {
    echo "# Per-deployment isolation overrides (rendered by render-chart.sh)"
    echo "jail_root = \"${MALLCOP_HOME}/.mallcop/jails\""
    echo
    cat "${OUTPUT}"
  } > "${TMP_OUT}"
  mv "${TMP_OUT}" "${OUTPUT}"
fi

echo "rendered: ${OUTPUT}"

# Show a quick verification of key fields
echo "--- verification ---"
grep -E "model\s*=|forge_api_url|api_key\s*=|score_floor|enabled\s*=\s*true" "${OUTPUT}" | head -8
