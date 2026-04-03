#!/bin/bash
set -e
export CF_HOME=/mnt/campfire
# Clear stale cf state from previous containers (identity, store, aliases)
# but preserve the campfire message directories
rm -f "$CF_HOME/store.db" "$CF_HOME/identity.json" "$CF_HOME/aliases.json"
rm -rf "$CF_HOME/center"
cf init --force 2>&1 || true
# Register the customer's campfire as a membership in cf's store.
# cf join requires campfire.cbor metadata which doesn't exist for
# WriteInbound-created campfires. Insert the membership directly.
if [ -n "$MALLCOP_CAMPFIRE_ID" ]; then
    python3 -c "
import sqlite3, time, os
db = os.path.join(os.environ['CF_HOME'], 'store.db')
conn = sqlite3.connect(db)
cid = os.environ['MALLCOP_CAMPFIRE_ID']
path = os.path.join(os.environ['CF_HOME'], cid)
ts = int(time.time())
conn.execute('''INSERT OR REPLACE INTO campfire_memberships
    (campfire_id, path, join_protocol, role, joined_at, member_count, description, creator_pubkey, transport, is_muted)
    VALUES (?, ?, 'open', 'full', ?, 1, 'pro-online', '', 'filesystem', 0)''',
    (cid, path, ts))
conn.commit()
conn.close()
print(f'Registered campfire {cid[:12]} in store.db')
" 2>&1
fi
exec mallcop watch --daemon --dir /workspace
