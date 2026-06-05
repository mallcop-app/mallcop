#!/usr/bin/env bash
# Integration test for sync-capabilities.sh — hermetic, uses tmp cf
# session and `/tmp/we-local`. Exits 0 if all scenarios pass, non-zero
# on any failure with diff output.
#
# Scenarios:
#   1. Initial sync against empty campfire → PROPOSE+FULFILL each TOML.
#   2. Idempotency: re-run same desired state → all NOOP.
#   3. Drift detection: change one TOML's model → SUPERSEDE that one only.
#   4. After supersede: re-run → all NOOP.
#   5. Recovery: simulate kill between propose+fulfill → next sync
#      detects PENDING and fulfills (no duplicate propose).
#
# Usage: WE_BIN=/path/to/we bash scripts/test-sync-capabilities.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WE_BIN="${WE_BIN:-/tmp/we-local}"
if [[ ! -x "$WE_BIN" ]]; then
  echo "we binary not found at $WE_BIN; set WE_BIN env var" >&2
  exit 2
fi

SESS_DIR=$(cf init --session 2>/dev/null | head -1)
[[ -z "$SESS_DIR" || ! -d "$SESS_DIR" ]] && { echo "cf init --session failed" >&2; exit 1; }
export CF_HOME="$SESS_DIR"
TRANSPORT="$CF_HOME/campfires"
TDIR="$CF_HOME/tomls"; mkdir -p "$TDIR"

cat > "$CF_HOME/chart.toml" <<EOF
[identity]
name="test-sync"
type="worker"
key_file="$CF_HOME/identity.json"
[[worksources]]
type="ready"
campfire="x"
skills=["task:triage","task:investigate"]
[budget]
max_tokens_per_task=1000
[autonomy]
max_tasks_per_session=10
[capabilities]
gate_policy="ungated"
tool_allowlist=["check-baseline"]
[inference]
forge_api_url="https://forge.3dl.dev"
api_key="unused"
[agents]
dir="agents"
[campfire]
transport_dir="$TRANSPORT"
EOF

CHART="$CF_HOME/chart.toml"
SYNC() { WE_BIN="$WE_BIN" bash "$SCRIPT_DIR/sync-capabilities.sh" --chart "$CHART" --tomls-dir "$TDIR" --transport-dir "$TRANSPORT" "$@"; }

bash "$SCRIPT_DIR/render-capability.sh" triage glm-4.7-flash --run-id rid --tool-bin-dir /tmp/b > "$TDIR/triage.toml"
bash "$SCRIPT_DIR/render-capability.sh" investigate glm-5 --run-id rid --tool-bin-dir /tmp/b > "$TDIR/investigate.toml"

fail=0
assert_plan_count() {
  local label="$1" needle="$2" want="$3"
  local out got
  out=$(SYNC --dry-run)
  got=$(grep -c "$needle" <<<"$out" || true)
  if [[ "$got" != "$want" ]]; then
    echo "FAIL $label: expected $want lines matching '$needle', got $got" >&2
    echo "--- plan output ---" >&2; echo "$out" >&2
    fail=1
  else
    echo "PASS $label ($got × $needle)"
  fi
}

# Scenario 1: initial PROPOSE
assert_plan_count "1-initial-propose-plan" "PROPOSE" 2

# Execute
SYNC >/dev/null

# Scenario 2: idempotency
assert_plan_count "2-idempotency-noop" "NOOP" 2

# Scenario 3: drift
bash "$SCRIPT_DIR/render-capability.sh" triage claude-sonnet-4-6 --run-id rid --tool-bin-dir /tmp/b > "$TDIR/triage.toml"
assert_plan_count "3-drift-supersede" "SUPERSEDE" 1
assert_plan_count "3-drift-other-noop" "NOOP" 1

# Execute supersede
SYNC >/dev/null

# Scenario 4: stable after supersede
assert_plan_count "4-post-supersede-noop" "NOOP" 2

# Scenario 5: recovery — propose without fulfill
bash "$SCRIPT_DIR/render-capability.sh" triage glm-4.7-flash --run-id rid --tool-bin-dir /tmp/b > "$TDIR/triage.toml"
# Issue propose manually, no fulfill.
"$WE_BIN" capability propose --chart "$CHART" --transport-dir "$TRANSPORT" --file "$TDIR/triage.toml" >/dev/null 2>&1
assert_plan_count "5-recovery-fulfill-pending" "FULFILL-PND" 1
# Run sync for real — should fulfill (we expect a supersede for the now-orphan
# active old triage, AND a fulfill of the pending. The plan above caught the
# pending detection. Execute to verify it completes cleanly.)
SYNC >/dev/null
assert_plan_count "5-recovery-stable" "NOOP" 2

if [[ $fail -ne 0 ]]; then
  echo "FAILED" >&2
  exit 1
fi
echo "ALL SCENARIOS PASSED"
