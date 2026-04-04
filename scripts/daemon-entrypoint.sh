#!/bin/bash
set -e
export CF_HOME=/mnt/campfire
# Clear stale cf state from previous containers
rm -f "$CF_HOME/store.db" "$CF_HOME/identity.json" "$CF_HOME/aliases.json"
rm -rf "$CF_HOME/center"
cf init --force 2>&1 || true
# TODO(mallcop-pro-qkc): join campfire via hosted campfire API instead of
# bootstrapping CBOR metadata files directly.
if [ -n "$MALLCOP_CAMPFIRE_ID" ]; then
    cf join "$MALLCOP_CAMPFIRE_ID" 2>&1 || true
fi
exec mallcop watch --daemon --dir /workspace
