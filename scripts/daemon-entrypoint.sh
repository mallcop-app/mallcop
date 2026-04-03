#!/bin/bash
set -e
export CF_HOME=/mnt/campfire
export CF_TRANSPORT_DIR=/mnt/campfire
# Clear stale cf state from previous containers
rm -f "$CF_HOME/store.db" "$CF_HOME/identity.json" "$CF_HOME/aliases.json"
rm -rf "$CF_HOME/center"
cf init --force 2>&1 || true
# Ensure campfire directory has campfire.cbor metadata (required by cf join).
# WriteInbound only creates messages — this bootstraps the metadata.
if [ -n "$MALLCOP_CAMPFIRE_ID" ]; then
    CFDIR="$CF_HOME/$MALLCOP_CAMPFIRE_ID"
    mkdir -p "$CFDIR/messages" "$CFDIR/members"
    if [ ! -f "$CFDIR/campfire.cbor" ]; then
        python3 -c "
import cbor2, os, time
cid = bytes.fromhex(os.environ['MALLCOP_CAMPFIRE_ID'])
# Minimal campfire state: id, empty signature, open protocol, no requirements, timestamp, 1 member
state = {1: cid, 2: b'\x00'*64, 3: 'open', 4: [], 5: int(time.time_ns()), 6: 1}
with open('$CFDIR/campfire.cbor', 'wb') as f:
    f.write(cbor2.dumps(state))
print('Created campfire.cbor')
" 2>&1
    fi
    cf join "$MALLCOP_CAMPFIRE_ID" 2>&1 || true
fi
exec mallcop watch --daemon --dir /workspace
