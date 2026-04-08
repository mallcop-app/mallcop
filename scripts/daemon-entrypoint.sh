#!/bin/bash
set -e
# Mallcop daemon entrypoint for campfire 0.16+ hosted relay
#
# Authenticates with operator API key, joins the customer's campfire,
# and runs the mallcop daemon loop.
#
# Required env vars:
#   CAMPFIRE_REMOTE_URL       — hosted relay (e.g. https://mcp.getcampfire.dev)
#   CAMPFIRE_API_KEY          — operator API key (forge-sk-*)
#   MALLCOP_CAMPFIRE_ID       — customer's campfire ID
#
# Optional:
#   CAMPFIRE_JOIN_CREDENTIAL  — invite code (unused when operator key auth
#                               gives implicit access, kept for future
#                               invite-only enforcement)

MCP_ENDPOINT="${CAMPFIRE_REMOTE_URL}/api/mcp"

mcp_call() {
    local bearer="$1" tool="$2" args="$3"
    curl -sf -X POST "$MCP_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${bearer}" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"${tool}\",\"arguments\":${args}}}"
}

# Step 1: Initialize session with operator API key.
# Operator key auth (forge-sk-*) gives us a persistent session scoped to
# the operator account. All campfires created by this operator are accessible.
echo "[daemon] Initializing campfire session..."
INIT_TEXT=$(mcp_call "$CAMPFIRE_API_KEY" "campfire_init" '{}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['content'][0]['text'])")

SESSION_TOKEN=$(echo "$INIT_TEXT" | python3 -c "
import sys
for line in sys.stdin:
    if 'Session token:' in line:
        print(line.split('Session token:')[1].strip()); break")

if [ -z "$SESSION_TOKEN" ]; then
    echo "[daemon] ERROR: Failed to get session token" >&2
    echo "[daemon] Response: ${INIT_TEXT:0:300}" >&2
    exit 1
fi
echo "[daemon] Session established (operator key auth)"

# Step 2: Verify access to the customer's campfire.
# With operator key auth, the session creator is already a member of all
# campfires they created. Verify by listing, skip explicit join.
if [ -n "$MALLCOP_CAMPFIRE_ID" ]; then
    echo "[daemon] Verifying campfire access ${MALLCOP_CAMPFIRE_ID:0:16}..."
    LS_RESULT=$(mcp_call "$SESSION_TOKEN" "campfire_ls" '{}' 2>&1) || true
    if echo "$LS_RESULT" | grep -q "$MALLCOP_CAMPFIRE_ID" 2>/dev/null; then
        echo "[daemon] Campfire accessible (operator member)"
    else
        echo "[daemon] WARNING: Campfire not in member list, attempting join..." >&2
        JOIN_ARGS="{\"campfire_id\":\"${MALLCOP_CAMPFIRE_ID}\""
        if [ -n "$CAMPFIRE_JOIN_CREDENTIAL" ]; then
            JOIN_ARGS="${JOIN_ARGS},\"invite_code\":\"${CAMPFIRE_JOIN_CREDENTIAL}\""
        fi
        JOIN_ARGS="${JOIN_ARGS}}"
        JOIN_RESULT=$(mcp_call "$SESSION_TOKEN" "campfire_join" "$JOIN_ARGS" 2>&1) || true
        echo "[daemon] Join result: $(echo "$JOIN_RESULT" | head -c 200)"
    fi
fi

# Export session for mallcop daemon to use for campfire message operations
export CAMPFIRE_SESSION_TOKEN="$SESSION_TOKEN"
export CAMPFIRE_MCP_ENDPOINT="$MCP_ENDPOINT"

echo "[daemon] Starting mallcop watch --daemon"
exec mallcop watch --daemon --dir /workspace
