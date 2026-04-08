#!/bin/bash
set -e
# Mallcop daemon entrypoint for campfire 0.16+
#
# Authenticates to the hosted campfire relay via operator API key,
# joins the customer's invite-only campfire using the join credential,
# then runs the mallcop daemon loop.
#
# Required env vars:
#   CAMPFIRE_REMOTE_URL       — hosted relay URL (e.g. https://mcp.getcampfire.dev)
#   CAMPFIRE_API_KEY          — operator API key for the relay
#   MALLCOP_CAMPFIRE_ID       — customer's campfire ID
#   CAMPFIRE_JOIN_CREDENTIAL  — invite code for the customer's campfire
#
# Optional:
#   MALLCOP_PRO_SERVICE_TOKEN — service token (for billing identity)
#   MALLCOP_TELEGRAM_BOT_TOKEN / MALLCOP_TELEGRAM_CHAT_ID — Telegram delivery

MCP_ENDPOINT="${CAMPFIRE_REMOTE_URL}/api/mcp"

# Step 1: Initialize identity on the hosted relay.
# Embed the API key in the URL as userinfo — cf init --remote extracts it.
_relay_scheme="${CAMPFIRE_REMOTE_URL%%://*}"
_relay_host="${CAMPFIRE_REMOTE_URL#*://}"
_relay_url="${_relay_scheme}://${CAMPFIRE_API_KEY}@${_relay_host}"

echo "[daemon] Initializing campfire identity..."
cf init --remote "$_relay_url"

# Step 2: Join the customer's invite-only campfire.
# The cf CLI doesn't expose invite_code as a flag, so we call the MCP API
# directly. The session token from cf init is stored in the cf home dir.
if [ -n "$MALLCOP_CAMPFIRE_ID" ] && [ -n "$CAMPFIRE_JOIN_CREDENTIAL" ]; then
    echo "[daemon] Joining campfire ${MALLCOP_CAMPFIRE_ID:0:16}... (invite-only)"

    # Extract session token from cf's stored session
    SESSION_TOKEN=$(cf config get store.session_token 2>/dev/null || true)

    # If cf config doesn't expose the token, fall back to calling campfire_init
    # via the MCP API to get a fresh session token.
    if [ -z "$SESSION_TOKEN" ]; then
        SESSION_TOKEN=$(curl -sf -X POST "$MCP_ENDPOINT" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${CAMPFIRE_API_KEY}" \
            -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"campfire_init","arguments":{}}}' \
            | python3 -c "
import json, sys
r = json.load(sys.stdin)
text = r['result']['content'][0]['text']
for line in text.split('\n'):
    if line.strip().startswith('Session token:'):
        print(line.split(':', 1)[1].strip())
        break
")
    fi

    if [ -z "$SESSION_TOKEN" ]; then
        echo "[daemon] ERROR: Could not obtain session token" >&2
        exit 1
    fi

    # Join with invite code via MCP API
    JOIN_RESULT=$(curl -sf -X POST "$MCP_ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${SESSION_TOKEN}" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"campfire_join\",\"arguments\":{\"campfire_id\":\"${MALLCOP_CAMPFIRE_ID}\",\"invite_code\":\"${CAMPFIRE_JOIN_CREDENTIAL}\"}}}" \
        2>&1) || true

    if echo "$JOIN_RESULT" | python3 -c "import json,sys; r=json.load(sys.stdin); sys.exit(0 if 'error' not in r or r.get('error') is None else 1)" 2>/dev/null; then
        echo "[daemon] Joined campfire successfully"
    else
        echo "[daemon] WARNING: Join may have failed: ${JOIN_RESULT:0:200}" >&2
        # Continue anyway — the daemon can retry on next message
    fi
fi

echo "[daemon] Starting mallcop watch --daemon"
exec mallcop watch --daemon --dir /workspace
