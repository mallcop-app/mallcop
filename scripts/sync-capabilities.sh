#!/usr/bin/env bash
# Sync a directory of per-skill capability TOMLs into a live capabilities
# campfire via legion's `we capability propose/fulfill/supersede` primitives.
#
# Usage:
#   sync-capabilities.sh --chart <path> --tomls-dir <dir> [--dry-run]
#                        [--transport-dir <dir>] [--cf-home <dir>]
#                        [--we-bin <path>] [--show-active-only]
#
# Algorithm (per skill):
#   - Compute desired payload's canonical JSON from the TOML.
#   - Read live capabilities-campfire state by parsing CBOR messages on
#     disk (bypassing `cf read` per legion-cd41).
#   - Plan:
#       NOOP            — desired matches live active
#       PROPOSE         — no live entry exists
#       SUPERSEDE <id>  — live exists but payload differs
#       FULFILL-PENDING — propose succeeded last run, fulfill never ran
#   - Print plan. With --dry-run, exit 0.
#   - Otherwise: execute `we capability propose [--supersedes]` then
#     `we capability fulfill --decision active`.
#
# Idempotent: a second run against the same state prints all NOOP.
# Recovery: if propose succeeded but fulfill didn't, re-run detects the
# pending future and only re-fulfills.
#
# Bypasses for known legion bugs:
#   legion-b80  — we capability show overwrites the pointer; never used.
#   legion-cd41 — CLI default transport-dir diverges from running automaton;
#                 we always pass --transport-dir explicitly to we, and read
#                 the campfire data from the chart's [campfire] transport_dir
#                 (or --transport-dir override).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CHART=""
TOMLS_DIR=""
DRY_RUN=0
TRANSPORT_DIR=""
CF_HOME_OVERRIDE=""
WE_BIN="${WE_BIN:-we}"
SHOW_ACTIVE_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --chart) CHART="$2"; shift 2 ;;
    --tomls-dir) TOMLS_DIR="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --transport-dir) TRANSPORT_DIR="$2"; shift 2 ;;
    --cf-home) CF_HOME_OVERRIDE="$2"; shift 2 ;;
    --we-bin) WE_BIN="$2"; shift 2 ;;
    --show-active-only) SHOW_ACTIVE_ONLY=1; shift ;;
    -h|--help)
      sed -n '/^# Usage:/,/^set/p' "$0" | sed -n 's/^# \?//p' | head -40
      exit 0
      ;;
    *) echo "sync-capabilities.sh: unknown flag $1" >&2; exit 2 ;;
  esac
done

[[ -z "$CHART" ]] && { echo "sync-capabilities.sh: --chart is required" >&2; exit 2; }
[[ -z "$TOMLS_DIR" ]] && { echo "sync-capabilities.sh: --tomls-dir is required" >&2; exit 2; }
[[ ! -f "$CHART" ]] && { echo "sync-capabilities.sh: chart not found: $CHART" >&2; exit 2; }
[[ ! -d "$TOMLS_DIR" ]] && { echo "sync-capabilities.sh: tomls-dir not found: $TOMLS_DIR" >&2; exit 2; }

# Resolve transport dir.
if [[ -z "$TRANSPORT_DIR" ]]; then
  TRANSPORT_DIR=$(python3 -c "
import re, sys
text = open('$CHART').read()
# Find [campfire] block, then transport_dir = '...'
m = re.search(r'\[campfire\][^\[]*?transport_dir\s*=\s*\"([^\"]+)\"', text, re.DOTALL)
print(m.group(1) if m else '')
")
fi
[[ -z "$TRANSPORT_DIR" ]] && {
  echo "sync-capabilities.sh: could not resolve transport dir; pass --transport-dir" >&2
  exit 2
}

# Resolve identity dir (parent of chart's identity.key_file).
IDENTITY_DIR=$(python3 -c "
import os, re, sys
text = open('$CHART').read()
m = re.search(r'\[identity\][^\[]*?key_file\s*=\s*\"([^\"]+)\"', text, re.DOTALL)
if not m: sys.exit('chart missing identity.key_file')
print(os.path.dirname(m.group(1)))
")

# Find capabilities-campfire-id pointer. Legion writes it next to identity.json.
POINTER_FILE="$IDENTITY_DIR/capabilities-campfire-id"
CAP_CF_ID=""
[[ -f "$POINTER_FILE" ]] && CAP_CF_ID="$(cat "$POINTER_FILE")"

# Venv with cbor2 for reading the campfire on disk.
VENV="${SYNC_CAPS_VENV:-$SCRIPT_DIR/../.venv-sync-caps}"
if [[ ! -x "$VENV/bin/python3" ]]; then
  python3 -m venv "$VENV" >/dev/null
  "$VENV/bin/pip" install -q cbor2 tomli 2>/dev/null || "$VENV/bin/pip" install -q cbor2
fi
PYBIN="$VENV/bin/python3"

# Read live state via direct CBOR parse.
LIVE_STATE='{}'
if [[ -n "$CAP_CF_ID" && -d "$TRANSPORT_DIR/$CAP_CF_ID" ]]; then
  LIVE_STATE="$("$PYBIN" "$SCRIPT_DIR/_sync_read_state.py" "$TRANSPORT_DIR" "$CAP_CF_ID")"
fi

if [[ "$SHOW_ACTIVE_ONLY" == "1" ]]; then
  printf '%s\n' "$LIVE_STATE"
  exit 0
fi

# Read desired state from TOMLs dir.
DESIRED_STATE="$("$PYBIN" "$SCRIPT_DIR/_sync_desired_state.py" "$TOMLS_DIR")"

# Compute plan.
PLAN_FILE=$(mktemp /tmp/sync-plan-XXXX.json)
trap 'rm -f "$PLAN_FILE"' EXIT
"$PYBIN" - "$LIVE_STATE" "$DESIRED_STATE" <<'PY' > "$PLAN_FILE"
import json, sys
live = json.loads(sys.argv[1])
desired = json.loads(sys.argv[2])

plan = []
for name in sorted(desired):
    d = desired[name]
    l = live.get(name, {})
    active = l.get('active')
    pending = l.get('pending')

    if pending and (not active or active['canonical'] != d['canonical']):
        # Pending future from a previous interrupted run.
        if pending['canonical'] == d['canonical']:
            plan.append({'op': 'FULFILL-PENDING', 'name': name,
                         'msg_id': pending['msg_id'],
                         'toml_path': d['toml_path']})
            continue

    if active and active['canonical'] == d['canonical']:
        plan.append({'op': 'NOOP', 'name': name,
                     'msg_id': active['msg_id']})
    elif active:
        plan.append({'op': 'SUPERSEDE', 'name': name,
                     'msg_id': active['msg_id'],
                     'toml_path': d['toml_path']})
    else:
        plan.append({'op': 'PROPOSE', 'name': name,
                     'toml_path': d['toml_path']})

# Names live but not desired — leave alone (no auto-revoke).
for name in sorted(set(live) - set(desired)):
    if 'active' in live[name]:
        plan.append({'op': 'LIVE-NOT-DESIRED', 'name': name,
                     'msg_id': live[name]['active']['msg_id']})

print(json.dumps(plan, indent=2))
PY

PLAN=$(cat "$PLAN_FILE")

# Print plan.
"$PYBIN" - "$PLAN" <<'PY'
import json, sys
plan = json.loads(sys.argv[1])
for item in plan:
    op = item['op']
    name = item['name']
    if op == 'NOOP':
        print(f"  NOOP        {name}  (msg-id={item['msg_id'][:12]}...)")
    elif op == 'PROPOSE':
        print(f"  PROPOSE     {name}")
    elif op == 'SUPERSEDE':
        print(f"  SUPERSEDE   {name}  (old msg-id={item['msg_id'][:12]}...)")
    elif op == 'FULFILL-PENDING':
        print(f"  FULFILL-PND {name}  (pending msg-id={item['msg_id'][:12]}...)")
    elif op == 'LIVE-NOT-DESIRED':
        print(f"  LEAVE-ALONE {name}  (live-only, no auto-revoke)")
PY

if [[ "$DRY_RUN" == "1" ]]; then
  exit 0
fi

# Execute. Use \x1f (US/unit-separator) as field delimiter — bash's read
# collapses consecutive tabs when IFS is whitespace, eating empty fields.
EXEC_FAILED=0
OP_LINES=$(echo "$PLAN" | "$PYBIN" -c "
import json, sys
plan = json.load(sys.stdin)
for i in plan:
    if i['op'] in ('PROPOSE','SUPERSEDE','FULFILL-PENDING'):
        msg_id = i.get('msg_id','')
        toml_path = i.get('toml_path','')
        print(f\"{i['op']}\x1f{i['name']}\x1f{msg_id}\x1f{toml_path}\")
")
while IFS=$'\x1f' read -r OP NAME OLD_MSG TOML; do
  [[ -z "$OP" ]] && continue

  case "$OP" in
    PROPOSE)
      new_id=$("$WE_BIN" capability propose --chart "$CHART" --transport-dir "$TRANSPORT_DIR" --file "$TOML" 2>&1 | tail -1)
      if [[ -z "$new_id" || "$new_id" == *"error"* || "$new_id" == *"failed"* ]]; then
        echo "  PROPOSE $NAME FAILED: $new_id" >&2; EXEC_FAILED=1; continue
      fi
      "$WE_BIN" capability fulfill --chart "$CHART" --transport-dir "$TRANSPORT_DIR" --decision active "$new_id" >/dev/null 2>&1 \
        || { echo "  FULFILL $NAME FAILED" >&2; EXEC_FAILED=1; continue; }
      echo "  ✓ PROPOSE+FULFILL $NAME (new msg-id=${new_id:0:12}...)"
      ;;
    SUPERSEDE)
      new_id=$("$WE_BIN" capability propose --chart "$CHART" --transport-dir "$TRANSPORT_DIR" --supersedes "$OLD_MSG" --file "$TOML" 2>&1 | tail -1)
      if [[ -z "$new_id" || "$new_id" == *"error"* || "$new_id" == *"failed"* ]]; then
        echo "  SUPERSEDE $NAME FAILED: $new_id" >&2; EXEC_FAILED=1; continue
      fi
      "$WE_BIN" capability fulfill --chart "$CHART" --transport-dir "$TRANSPORT_DIR" --decision active "$new_id" >/dev/null 2>&1 \
        || { echo "  FULFILL $NAME FAILED" >&2; EXEC_FAILED=1; continue; }
      # Revoke the old active.
      "$WE_BIN" capability fulfill --chart "$CHART" --transport-dir "$TRANSPORT_DIR" --decision revoked "$OLD_MSG" >/dev/null 2>&1 \
        || echo "  warn: revoke of superseded $NAME failed (old will linger but new is active)" >&2
      echo "  ✓ SUPERSEDE+FULFILL $NAME (new=${new_id:0:12}... → revoked old=${OLD_MSG:0:12}...)"
      ;;
    FULFILL-PENDING)
      "$WE_BIN" capability fulfill --chart "$CHART" --transport-dir "$TRANSPORT_DIR" --decision active "$OLD_MSG" >/dev/null 2>&1 \
        || { echo "  FULFILL-PENDING $NAME FAILED" >&2; EXEC_FAILED=1; continue; }
      echo "  ✓ FULFILL-PENDING $NAME (msg-id=${OLD_MSG:0:12}...)"
      ;;
  esac
done <<< "$OP_LINES"

exit $EXEC_FAILED
