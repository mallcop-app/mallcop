#!/usr/bin/env bash
# Verify each per-skill capability TOML.tmpl renders byte-equivalent to the
# corresponding [[capabilities.seed]] block in the chart template.
#
# For each skill: extract block from chart, render TOML.tmpl. Both go through
# the same normalization (replace skill-specific {{*_MODEL}} → {{MODEL}}) so
# the comparison is structural, not value-sensitive.
#
# Usage: bash scripts/test-capability-render.sh
# Exits 0 on full match, 1 with diff output on any mismatch.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CHART="$REPO_ROOT/charts/mallcop-operational.toml.tmpl"

declare -A SKILL_MODEL_PLACEHOLDER=(
  [triage]="{{TRIAGE_MODEL}}"
  [investigate]="{{INVESTIGATE_MODEL}}"
  [deep-investigate]="{{DEEP_INVESTIGATE_MODEL}}"
  [investigate-merge]="{{INVESTIGATE_MERGE_MODEL}}"
  [escalate]="{{ESCALATE_MODEL}}"
  [heal]="{{HEAL_MODEL}}"
)

# Stable test values for the non-model placeholders.
TEST_RUN_ID="bk-test-20260605-000000"
TEST_TOOL_BIN_DIR="/path/to/bin"
TEST_MODEL="MODEL-PLACEHOLDER-FOR-DIFF"

fail=0
for skill in triage investigate deep-investigate investigate-merge escalate heal; do
  chart_placeholder="${SKILL_MODEL_PLACEHOLDER[$skill]}"

  # Extract from chart and normalize:
  #   skill-specific model placeholder → TEST_MODEL  (same as render-chart.sh)
  #   {{MODEL}} → TEST_MODEL                          (render-chart.sh also subs {{MODEL}} globally)
  #   {{RUN_ID}} → TEST_RUN_ID
  #   {{TOOL_BIN_DIR}} → TEST_TOOL_BIN_DIR
  expected="$(bash "$SCRIPT_DIR/extract-seed-block.sh" "$CHART" "$skill")"
  expected="${expected//$chart_placeholder/$TEST_MODEL}"
  expected="${expected//\{\{MODEL\}\}/$TEST_MODEL}"
  expected="${expected//\{\{RUN_ID\}\}/$TEST_RUN_ID}"
  expected="${expected//\{\{TOOL_BIN_DIR\}\}/$TEST_TOOL_BIN_DIR}"

  # Render the TOML.tmpl with the same substitutions.
  if [[ ! -f "$REPO_ROOT/capabilities/${skill}.toml.tmpl" ]]; then
    echo "FAIL $skill: capabilities/${skill}.toml.tmpl does not exist" >&2
    fail=1
    continue
  fi
  actual="$(bash "$SCRIPT_DIR/render-capability.sh" \
    "$skill" "$TEST_MODEL" \
    --run-id "$TEST_RUN_ID" \
    --tool-bin-dir "$TEST_TOOL_BIN_DIR")"

  if [[ "$(printf '%s\n' "$expected")" != "$(printf '%s\n' "$actual")" ]]; then
    echo "FAIL $skill: rendered TOML differs from chart seed block" >&2
    diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
    fail=1
    continue
  fi
  echo "PASS $skill"
done

exit $fail
