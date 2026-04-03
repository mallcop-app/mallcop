#!/bin/bash
set -e
export CF_HOME=/mnt/campfire
# cf 0.14.3 co-locates transport at $CF_HOME/campfires/.
# WriteInbound writes beads to $CF_HOME/<campfireID>/messages/ (share root).
# Set CF_TRANSPORT_DIR=$CF_HOME so cf uses the same path as WriteInbound.
export CF_TRANSPORT_DIR=/mnt/campfire
# Clear stale cf state from previous containers
rm -f "$CF_HOME/store.db" "$CF_HOME/identity.json" "$CF_HOME/aliases.json"
rm -rf "$CF_HOME/center"
cf init --force 2>&1 || true
# Join the customer's campfire (cf 0.14.3 handles this properly now)
if [ -n "$MALLCOP_CAMPFIRE_ID" ]; then
    cf join "$MALLCOP_CAMPFIRE_ID" 2>&1 || true
fi
exec mallcop watch --daemon --dir /workspace
