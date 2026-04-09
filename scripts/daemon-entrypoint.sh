#!/bin/bash
set -e
# Mallcop daemon entrypoint for campfire 0.16.5+
#
# Clones the customer's deploy repo as the workspace, joins the campfire,
# runs the daemon loop, and pushes findings back to git.
#
# Required env vars:
#   MALLCOP_DEPLOY_REPO       — git clone URL (e.g. https://github.com/org/mallcop-deploy.git)
#   MALLCOP_PRO_SERVICE_TOKEN — service token for mallcop-pro API
#   CAMPFIRE_REMOTE_URL       — hosted relay (e.g. https://mcp.getcampfire.dev)
#   MALLCOP_CAMPFIRE_ID       — customer's campfire ID
#   CAMPFIRE_JOIN_CREDENTIAL  — invite code for the campfire

WORKSPACE="/workspace"
export CF_HOME="${CF_HOME:-/home/mallcop/.campfire/agents/mallcop-daemon}"
RELAY_ENDPOINT="${CAMPFIRE_REMOTE_URL}/api"

# Step 1: Clone the deploy repo
if [ -z "$MALLCOP_DEPLOY_REPO" ]; then
    echo "[daemon] ERROR: MALLCOP_DEPLOY_REPO not set" >&2
    exit 1
fi

echo "[daemon] Cloning deploy repo..."
# Get a GitHub installation token for git auth via mallcop-pro
TOKEN=$(curl -sf -X POST "https://api.mallcop.app/v1/github/token" \
    -H "Authorization: Bearer ${MALLCOP_PRO_SERVICE_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"installation_id":0}' 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)

if [ -n "$TOKEN" ]; then
    # Inject token into clone URL: https://x-access-token:TOKEN@github.com/...
    CLONE_URL=$(echo "$MALLCOP_DEPLOY_REPO" | sed "s|https://|https://x-access-token:${TOKEN}@|")
else
    CLONE_URL="$MALLCOP_DEPLOY_REPO"
fi

git clone --depth 1 "$CLONE_URL" "$WORKSPACE"
cd "$WORKSPACE"
git config user.name "mallcop[bot]"
git config user.email "mallcop[bot]@users.noreply.github.com"
echo "[daemon] Workspace ready: $(ls mallcop.yaml 2>/dev/null && echo 'mallcop.yaml found' || echo 'no mallcop.yaml')"

# Step 2: Create persistent identity (idempotent)
if [ ! -f "$CF_HOME/identity.json" ]; then
    echo "[daemon] Creating persistent identity..."
    mkdir -p "$(dirname "$CF_HOME")"
    cf init --name mallcop-daemon --cf-home "$(dirname "$CF_HOME")"
fi

# Step 3: Join campfire via relay with invite code
if [ -n "$MALLCOP_CAMPFIRE_ID" ] && [ -n "$CAMPFIRE_JOIN_CREDENTIAL" ]; then
    if [ ! -d "$CF_HOME/campfires/$MALLCOP_CAMPFIRE_ID" ]; then
        echo "[daemon] Joining campfire ${MALLCOP_CAMPFIRE_ID:0:16}..."
        cf join --via "$RELAY_ENDPOINT" \
            --invite-code "$CAMPFIRE_JOIN_CREDENTIAL" \
            "$MALLCOP_CAMPFIRE_ID" \
            --cf-home "$CF_HOME" || echo "[daemon] WARNING: Join failed" >&2
    fi
fi

# Step 4: Run the daemon
echo "[daemon] Starting mallcop watch --daemon"
mallcop watch --daemon --dir "$WORKSPACE"

# Step 5: Push findings back to git
cd "$WORKSPACE"
git add events/ .mallcop/ 2>/dev/null
if ! git diff --staged --quiet 2>/dev/null; then
    git commit -m "mallcop: daemon scan $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    git push || echo "[daemon] WARNING: git push failed" >&2
fi
