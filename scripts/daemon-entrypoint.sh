#!/bin/bash
set -e
export CF_HOME=/mnt/campfire
cf init --force 2>/dev/null || true
# Join the customer's campfire so cf send works
if [ -n "$MALLCOP_CAMPFIRE_ID" ]; then
    cf join "$MALLCOP_CAMPFIRE_ID" 2>/dev/null || true
fi
exec mallcop watch --daemon --dir /workspace
