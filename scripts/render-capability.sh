#!/usr/bin/env bash
# Render one per-skill capability TOML from the template under capabilities/.
# Substitutes {{MODEL}}, {{RUN_ID}}, {{TOOL_BIN_DIR}} into the template body.
#
# Usage:
#   render-capability.sh <skill-name> <model> [--run-id <id>] [--tool-bin-dir <dir>]
#
# Reads from   ./capabilities/<skill-name>.toml.tmpl
# Writes to    stdout
#
# {{RUN_ID}} defaults to $RUN_ID env var (legion convention).
# {{TOOL_BIN_DIR}} defaults to $TOOL_BIN_DIR env var (legion convention).
# A missing required placeholder for the skill exits 2.
set -euo pipefail

SKILL="${1:?usage: render-capability.sh <skill-name> <model> [--run-id <id>] [--tool-bin-dir <dir>]}"
MODEL="${2:?usage: render-capability.sh <skill-name> <model> [--run-id <id>] [--tool-bin-dir <dir>]}"
shift 2

RUN_ID="${RUN_ID:-}"
TOOL_BIN_DIR="${TOOL_BIN_DIR:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id) RUN_ID="$2"; shift 2 ;;
    --tool-bin-dir) TOOL_BIN_DIR="$2"; shift 2 ;;
    *) echo "render-capability.sh: unknown flag $1" >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TMPL="$REPO_ROOT/capabilities/${SKILL}.toml.tmpl"

[[ -f "$TMPL" ]] || { echo "render-capability.sh: template not found: $TMPL" >&2; exit 1; }

body="$(cat "$TMPL")"
body="${body//\{\{MODEL\}\}/$MODEL}"
body="${body//\{\{RUN_ID\}\}/$RUN_ID}"
body="${body//\{\{TOOL_BIN_DIR\}\}/$TOOL_BIN_DIR}"

# Detect un-substituted placeholders — only error for ones the skill actually uses.
if grep -q '{{' <<<"$body"; then
  remaining=$(grep -oE '\{\{[A-Z_]+\}\}' <<<"$body" | sort -u | tr '\n' ' ')
  echo "render-capability.sh: template has unsubstituted placeholders: $remaining" >&2
  echo "render-capability.sh: pass --run-id / --tool-bin-dir or set env" >&2
  exit 2
fi

printf "%s" "$body"
