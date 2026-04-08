#!/bin/bash
set -e
# Mallcop daemon entrypoint for campfire 0.16+ hosted relay
#
# Uses the MCP API directly for all campfire operations.
# The cf CLI is filesystem-oriented; the hosted relay is MCP-only.
#
# Required env vars:
#   CAMPFIRE_REMOTE_URL       — hosted relay (e.g. https://mcp.getcampfire.dev)
#   CAMPFIRE_API_KEY          — operator API key
#   MALLCOP_CAMPFIRE_ID       — customer's campfire ID
#   CAMPFIRE_JOIN_CREDENTIAL  — invite code for the customer's campfire

MCP_ENDPOINT="${CAMPFIRE_REMOTE_URL}/api/mcp"

mcp_call() {
    local token="$1" method="$2" args="$3"
    curl -sf -X POST "$MCP_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${token}" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"${method}\",\"arguments\":${args}}}"
}

extract_text() {
    python3 -c "import json,sys; print(json.load(sys.stdin)['result']['content'][0]['text'])"
}

extract_session_token() {
    python3 -c "
import sys
for line in sys.stdin:
    if 'Session token:' in line:
        print(line.split('Session token:')[1].strip())
        break"
}

# Step 1: Initialize session on the hosted relay using operator API key
echo "[daemon] Initializing campfire session..."
INIT_RESULT=$(mcp_call "$CAMPFIRE_API_KEY" "campfire_init" '{}')
SESSION_TOKEN=$(echo "$INIT_RESULT" | extract_text | extract_session_token)

if [ -z "$SESSION_TOKEN" ]; then
    echo "[daemon] ERROR: Failed to get session token from campfire_init" >&2
    echo "[daemon] Response: $(echo "$INIT_RESULT" | head -c 500)" >&2
    exit 1
fi
echo "[daemon] Session established"

# Step 2: Join the customer's invite-only campfire
if [ -n "$MALLCOP_CAMPFIRE_ID" ] && [ -n "$CAMPFIRE_JOIN_CREDENTIAL" ]; then
    echo "[daemon] Joining campfire ${MALLCOP_CAMPFIRE_ID:0:16}... (invite-only)"
    JOIN_ARGS="{\"campfire_id\":\"${MALLCOP_CAMPFIRE_ID}\",\"invite_code\":\"${CAMPFIRE_JOIN_CREDENTIAL}\"}"
    JOIN_RESULT=$(mcp_call "$SESSION_TOKEN" "campfire_join" "$JOIN_ARGS" 2>&1) || true

    if echo "$JOIN_RESULT" | python3 -c "import json,sys; r=json.load(sys.stdin); exit(1 if r.get('error') else 0)" 2>/dev/null; then
        echo "[daemon] Joined campfire"
    else
        echo "[daemon] WARNING: Join failed: $(echo "$JOIN_RESULT" | head -c 300)" >&2
    fi
fi

# Export the session token so mallcop can use the MCP API for campfire operations
export CAMPFIRE_SESSION_TOKEN="$SESSION_TOKEN"
export CAMPFIRE_MCP_ENDPOINT="$MCP_ENDPOINT"

echo "[daemon] Starting mallcop watch --daemon"
exec mallcop watch --daemon --dir /workspace
