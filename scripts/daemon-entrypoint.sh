#!/bin/bash
set -e
# Initialize cf identity connected to the hosted campfire relay.
# The cf CLI does not support --api-key as a standalone flag. The operator API
# key is embedded in the remote URL as standard userinfo credentials
# (https://<api-key>@host/path), which cf passes as Authorization: Bearer on
# the campfire_init call to the hosted relay.
#
# CAMPFIRE_REMOTE_URL  — hosted campfire relay URL (e.g. https://mcp.getcampfire.dev)
# CAMPFIRE_API_KEY     — operator API key (issued by getcampfire.dev)
# CAMPFIRE_JOIN_CREDENTIAL — per-customer invite code (stored at registration)
# MALLCOP_CAMPFIRE_ID  — customer's campfire ID

# Build authenticated relay URL: insert API key into URL as userinfo.
# Strip any existing scheme prefix, then re-add it with the key embedded.
_relay_scheme="${CAMPFIRE_REMOTE_URL%%://*}"
_relay_host="${CAMPFIRE_REMOTE_URL#*://}"
_relay_url="${_relay_scheme}://${CAMPFIRE_API_KEY}@${_relay_host}"

cf init --remote "$_relay_url"

# Join the customer's campfire using the per-customer invite credential.
if [ -n "$MALLCOP_CAMPFIRE_ID" ]; then
    cf join "$MALLCOP_CAMPFIRE_ID"
fi

exec mallcop watch --daemon --dir /workspace
