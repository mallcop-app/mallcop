#!/usr/bin/env bash
# Ground-source test: each rendered TOML must be accepted by
# `we capability propose --file`. This catches schema-drift bugs that
# the byte-equivalence test alone cannot (e.g. unknown fields that the
# chart has but legion rejects).
#
# Requires WE_BIN env var pointing at a `we` binary. Uses a per-run
# temp CF_HOME so the test is hermetic — never touches real campfires.
#
# Usage: WE_BIN=/path/to/we bash scripts/test-capability-propose-acceptance.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

WE_BIN="${WE_BIN:-/tmp/we-local}"
if [[ ! -x "$WE_BIN" ]]; then
  echo "we binary not found at $WE_BIN; set WE_BIN env var" >&2
  exit 2
fi

TMPDIR="$(mktemp -d /tmp/cap-accept-test-XXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

# Create an ephemeral cf session identity. `cf init --session` prints the
# session-dir path on line 1 of its stdout.
SESS_DIR=$(cf init --session 2>/dev/null | head -1)
[[ -z "$SESS_DIR" || ! -d "$SESS_DIR" ]] && { echo "cf init --session produced no session dir" >&2; exit 1; }
export CF_HOME="$SESS_DIR"

# Create a capabilities campfire for proposes to target.
CAP_ID=$(cf create --description "test-cap-accept" --no-config 2>&1 | head -1)
[[ -z "$CAP_ID" ]] && { echo "cf create returned empty id" >&2; exit 1; }
echo "$CAP_ID" > "$CF_HOME/capabilities-campfire-id"

# Minimal chart pointing at this CF_HOME.
CHART="$TMPDIR/chart.toml"
cat > "$CHART" <<EOF
[identity]
name = "test-cap-accept"
type = "worker"
key_file = "$CF_HOME/identity.json"

[[worksources]]
type = "ready"
campfire = "x"
skills = ["task:triage"]

[budget]
max_tokens_per_task = 1000

[autonomy]
max_tasks_per_session = 10

[capabilities]
gate_policy = "ungated"
tool_allowlist = ["check-baseline"]

[inference]
forge_api_url = "https://forge.3dl.dev"
api_key = "unused"

[agents]
dir = "agents"

[campfire]
transport_dir = "$CF_HOME/campfires"
EOF

fail=0
for skill in triage investigate deep-investigate investigate-merge escalate heal; do
  toml="$TMPDIR/${skill}.toml"
  bash "$SCRIPT_DIR/render-capability.sh" "$skill" "claude-haiku-4-5" \
    --run-id "bk-test" --tool-bin-dir "/tmp/bin" > "$toml"
  if output=$("$WE_BIN" capability propose --chart "$CHART" --file "$toml" 2>&1); then
    msg_id=$(echo "$output" | tail -1)
    echo "PASS $skill (msg-id=${msg_id:0:12}...)"
  else
    echo "FAIL $skill: $output" >&2
    fail=1
  fi
done

exit $fail
