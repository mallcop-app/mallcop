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
# Get a GitHub installation token for git auth via mallcop-pro.
# Use the Functions default hostname (always valid TLS) rather than custom domain
# which may have cert propagation delays after infrastructure changes.
MALLCOP_API="${MALLCOP_PRO_INFERENCE_URL:-https://mallcop-pro-api.azurewebsites.net}"
INST_ID="${MALLCOP_INSTALLATION_ID:-0}"
echo "[daemon] Fetching GitHub token (installation_id=${INST_ID})..."
TOKEN_RESP=$(curl -s --max-time 10 -X POST "${MALLCOP_API}/v1/github/token" \
    -H "Authorization: Bearer ${MALLCOP_PRO_SERVICE_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"installation_id\":${INST_ID}}" 2>&1)
TOKEN=$(echo "$TOKEN_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || true)
if [ -z "$TOKEN" ]; then
    echo "[daemon] WARNING: Token fetch failed: ${TOKEN_RESP:0:200}" >&2
fi

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

# Step 2: Create persistent identity and adopt conventions
if [ ! -f "$CF_HOME/identity.json" ]; then
    echo "[daemon] Creating persistent identity..."
    mkdir -p "$(dirname "$CF_HOME")"
    cf init --name mallcop-daemon --cf-home "$(dirname "$CF_HOME")"
fi

# Adopt mallcop-relay convention declarations (idempotent — skips if already adopted)
if [ -d /app/conventions/mallcop-relay ]; then
    echo "[daemon] Adopting mallcop-relay convention..."
    cf convention adopt /app/conventions/mallcop-relay/ --cf-home "$CF_HOME" 2>&1 || echo "[daemon] WARNING: Convention adopt failed" >&2
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
