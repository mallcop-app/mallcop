#!/bin/bash
set -e
export CF_HOME=/mnt/campfire
# Clear stale cf state from previous containers (identity, store, aliases)
# but preserve the campfire message directories
rm -f "$CF_HOME/store.db" "$CF_HOME/identity.json" "$CF_HOME/aliases.json"
rm -rf "$CF_HOME/center"
cf init --force 2>&1 || true
# Join the customer's campfire so cf send works
if [ -n "$MALLCOP_CAMPFIRE_ID" ]; then
    cf join "$MALLCOP_CAMPFIRE_ID" 2>&1 || true
fi
exec mallcop watch --daemon --dir /workspace
