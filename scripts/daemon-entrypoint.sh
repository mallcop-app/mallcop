#!/bin/bash
set -e
export CF_HOME=/mnt/campfire
cf init --force 2>/dev/null || true
exec mallcop watch --daemon --dir /workspace
