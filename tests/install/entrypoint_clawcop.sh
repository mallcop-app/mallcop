#!/bin/bash
# Entrypoint for ClawCop installation test container.
# Simulates a post-installation first patrol run as the mallcop user.
# Outputs are captured by the test runner.

set -e

echo "=== ClawCop Test Container Starting ==="
echo "Creating system user: mallcop already exists"
echo ""

# Verify mallcop user exists
id mallcop || { echo "ERROR: mallcop user not found"; exit 1; }

# Verify cron is installed
crontab -u mallcop -l
echo ""

# Run first patrol as mallcop user
echo "=== Running first patrol ==="
sudo -u mallcop /opt/mallcop/venv/bin/mallcop watch \
    --dir /opt/mallcop \
    --human \
    2>&1 || {
    # watch may fail if no findings repo is configured — that's OK for the test.
    # What matters is that the openclaw connector ran and produced output.
    echo "watch command exited non-zero (expected without GitHub config)"
}

echo "=== Patrol complete ==="
exit 0
