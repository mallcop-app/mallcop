#!/usr/bin/env bash
# setup-telegram-ci.sh — wire a Telegram test bot into local env and GitHub CI.
#
# What this does automatically:
#   1. Verifies the bot token with Telegram's getMe API
#   2. Discovers your chat ID from getUpdates (reads the first message you sent)
#   3. Sets MALLCOP_TEST_TELEGRAM_BOT_TOKEN + MALLCOP_TEST_TELEGRAM_CHAT_ID
#      as GitHub Actions secrets in the mallcop repo
#   4. Prints the export commands to paste into your shell profile
#
# What you must do BEFORE running this:
#   1. Open Telegram, search @BotFather → /newbot → follow prompts → copy token
#   2. Send any message to your new bot (so getUpdates can find your chat ID)
#
# Usage:
#   TELEGRAM_BOT_TOKEN=<token> ./scripts/setup-telegram-ci.sh
#   or:
#   ./scripts/setup-telegram-ci.sh <token>

set -euo pipefail

TOKEN="${TELEGRAM_BOT_TOKEN:-${1:-}}"

if [[ -z "$TOKEN" ]]; then
    echo "Usage: TELEGRAM_BOT_TOKEN=<token> $0"
    echo "   or: $0 <token>"
    echo ""
    echo "Get a token from @BotFather on Telegram, then send your bot one message."
    exit 1
fi

API="https://api.telegram.org/bot${TOKEN}"

# --- Step 1: verify token ---
echo "Verifying token..."
ME=$(curl -sf "${API}/getMe") || { echo "ERROR: could not reach Telegram API. Check your token."; exit 1; }
BOT_NAME=$(echo "$ME" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['result']['username'])")
echo "  Bot: @${BOT_NAME}"

# --- Step 2: discover chat ID ---
echo "Looking for your chat ID in recent messages..."
UPDATES=$(curl -sf "${API}/getUpdates?limit=20")
CHAT_ID=$(echo "$UPDATES" | python3 -c "
import sys, json
data = json.load(sys.stdin)
results = data.get('result', [])
if not results:
    print('')
else:
    # Take the most recent message's chat id
    last = results[-1]
    msg = last.get('message') or last.get('channel_post') or {}
    chat = msg.get('chat', {})
    print(chat.get('id', ''))
")

if [[ -z "$CHAT_ID" ]]; then
    echo ""
    echo "ERROR: No messages found. Please send any message to @${BOT_NAME} in Telegram, then re-run this script."
    exit 1
fi

echo "  Chat ID: ${CHAT_ID}"

# --- Step 3: set GitHub Actions secrets ---
REPO=$(git -C "$(dirname "$0")/.." remote get-url origin 2>/dev/null \
    | sed 's|.*github.com[:/]||; s|\.git$||')

if [[ -n "$REPO" ]] && command -v gh &>/dev/null; then
    echo "Setting GitHub Actions secrets on ${REPO}..."
    gh secret set MALLCOP_TEST_TELEGRAM_BOT_TOKEN --body "$TOKEN"   --repo "$REPO"  # for tests
    gh secret set MALLCOP_TEST_TELEGRAM_CHAT_ID   --body "$CHAT_ID" --repo "$REPO"  # for tests
    gh secret set MALLCOP_TELEGRAM_BOT_TOKEN      --body "$TOKEN"   --repo "$REPO"  # for CLI
    gh secret set MALLCOP_TELEGRAM_CHAT_ID        --body "$CHAT_ID" --repo "$REPO"  # for CLI
    echo "  Done."
else
    echo "  (skipping GitHub secrets — gh not found or not in a git repo)"
fi

# --- Step 4: print local export commands ---
echo ""
echo "Paste these into your shell profile (~/.bashrc or ~/.zshrc):"
echo ""
echo "  export MALLCOP_TELEGRAM_BOT_TOKEN='${TOKEN}'"
echo "  export MALLCOP_TELEGRAM_CHAT_ID='${CHAT_ID}'"
echo "  export MALLCOP_TEST_TELEGRAM_BOT_TOKEN='${TOKEN}'  # for test suite"
echo "  export MALLCOP_TEST_TELEGRAM_CHAT_ID='${CHAT_ID}'  # for test suite"
echo ""
echo "Or for this session only:"
echo ""
echo "  export MALLCOP_TELEGRAM_BOT_TOKEN='${TOKEN}' MALLCOP_TELEGRAM_CHAT_ID='${CHAT_ID}' MALLCOP_TEST_TELEGRAM_BOT_TOKEN='${TOKEN}' MALLCOP_TEST_TELEGRAM_CHAT_ID='${CHAT_ID}'"
echo ""
echo "Done. You can now close mallcop-pro-dl4 in rd."
