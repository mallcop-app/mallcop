#!/bin/bash
set -e
# Mallcop daemon entrypoint for campfire 0.16.5+
#
# Uses cf CLI with persistent named identity and p2p-http relay transport.
# All campfire operations go through the CLI — no raw MCP API calls.
#
# Required env vars:
#   CAMPFIRE_REMOTE_URL       — hosted relay (e.g. https://mcp.getcampfire.dev)
#   MALLCOP_CAMPFIRE_ID       — customer's campfire ID
#   CAMPFIRE_JOIN_CREDENTIAL  — invite code for the customer's campfire
#
# Optional:
#   CAMPFIRE_API_KEY          — operator API key (not needed for p2p-http join)

export CF_HOME="${CF_HOME:-/home/mallcop/.campfire/agents/mallcop-daemon}"
RELAY_ENDPOINT="${CAMPFIRE_REMOTE_URL}/api"

# Step 1: Create persistent named identity (idempotent — skips if exists)
if [ ! -f "$CF_HOME/identity.json" ]; then
    echo "[daemon] Creating persistent identity..."
    mkdir -p "$(dirname "$CF_HOME")"
    cf init --name mallcop-daemon --cf-home "$(dirname "$CF_HOME")"
fi
echo "[daemon] Identity: $(cf id --cf-home "$CF_HOME" 2>/dev/null | head -1)"

# Step 2: Join the customer's campfire via relay with invite code
if [ -n "$MALLCOP_CAMPFIRE_ID" ]; then
    if [ -d "$CF_HOME/campfires/$MALLCOP_CAMPFIRE_ID" ]; then
        echo "[daemon] Already joined campfire ${MALLCOP_CAMPFIRE_ID:0:16}..."
    elif [ -n "$CAMPFIRE_JOIN_CREDENTIAL" ]; then
        echo "[daemon] Joining campfire ${MALLCOP_CAMPFIRE_ID:0:16}... (invite-only)"
        cf join --via "$RELAY_ENDPOINT" \
            --invite-code "$CAMPFIRE_JOIN_CREDENTIAL" \
            "$MALLCOP_CAMPFIRE_ID" \
            --cf-home "$CF_HOME" || {
            echo "[daemon] WARNING: Join failed, continuing anyway" >&2
        }
    else
        echo "[daemon] WARNING: No invite code, attempting open join" >&2
        cf join --via "$RELAY_ENDPOINT" \
            "$MALLCOP_CAMPFIRE_ID" \
            --cf-home "$CF_HOME" || {
            echo "[daemon] WARNING: Join failed" >&2
        }
    fi
fi

echo "[daemon] Starting mallcop watch --daemon"
exec mallcop watch --daemon --dir /workspace
