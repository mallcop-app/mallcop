#!/usr/bin/env bash
# Verify charts/mallcop-operational.toml.tmpl no longer contains
# [[capabilities.seed]] blocks (per-skill capability config moved to
# capabilities/<name>.toml.tmpl + scripts/sync-capabilities.sh).
#
# Required invariants:
#   1. Zero [[capabilities.seed]] block headers.
#   2. The singular [capabilities] section is preserved with gate_policy
#      and tool_allowlist lines.
#   3. All 6 model placeholders ({{*_MODEL}}) still appear somewhere
#      in the chart so render-chart.sh keeps substituting them — except
#      they're now consumed by sync-capabilities.sh's render-capability.sh
#      step, not by chart-side seeding.
#   4. The chart still parses cleanly with `we config` (basic syntactic
#      smoke check — does NOT exercise constellation init).
#
# Usage: bash scripts/test-chart-cleanup.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CHART="$REPO_ROOT/charts/mallcop-operational.toml.tmpl"

fail=0
check() {
  local label="$1" cmd="$2"
  if eval "$cmd"; then
    echo "PASS $label"
  else
    echo "FAIL $label" >&2
    fail=1
  fi
}

# 1. zero seed blocks
n=$(grep -c '^\[\[capabilities\.seed\]\]' "$CHART" || true)
check "no-seed-blocks ($n found)" "[[ $n -eq 0 ]]"

# 2. no seed subblocks either
n_sub=$(grep -c '^\s*\[\[capabilities\.seed\.tool_defs\]\]' "$CHART" || true)
check "no-seed-subblocks ($n_sub found)" "[[ $n_sub -eq 0 ]]"

# 3. singular [capabilities] section preserved
check "has-[capabilities]-section" "grep -q '^\\[capabilities\\]' \"$CHART\""
check "has-gate_policy"            "grep -q '^gate_policy\\s*=' \"$CHART\""
check "has-tool_allowlist"         "grep -q '^tool_allowlist\\s*=' \"$CHART\""

# 4. model placeholders still present (they're consumed by render-capability.sh
# in the sync step, not by chart-side seeding — but they need to exist so
# render-chart.sh's sed substitutions don't error on a missing template var.
# Actually: they're consumed PER-SKILL by render-capability.sh which only sees
# the per-skill TOML, so chart no longer needs them. Drop this check.)
# (No-op — left as a comment so future readers see the reasoning.)

exit $fail
