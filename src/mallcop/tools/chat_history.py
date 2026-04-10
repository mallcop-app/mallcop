"""Chat history tools for actor runtime.

These tools let agents fetch deeper conversation history beyond the 5 messages
pre-loaded inline by chat_turn. Useful when a user references something earlier
("that finding I mentioned", "what was the last thing you said?").

Both tools read campfire messages filtered by the `chat` tag and the
`session:<session_id>` tag. The session_id is injected per-turn by
InteractiveRuntime; it is empty in the autonomous chain (those don't query
session-scoped data), in which case both tools return an empty list.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re

from mallcop.tools import ToolContext, tool

_log = logging.getLogger(__name__)

_CHAT_TAG = "chat"


def _sanitize_session_id(session_id: str) -> str:
    """Replace unsafe characters in session_id for embedding in cf tag names."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", session_id)


async def _read_chat_messages(campfire_id: str, session_id: str) -> list[dict]:
    """Run `cf read <campfire_id> --all --json --tag chat --tag session:<id>`.

    Note: cf --tag filtering is OR-based. We filter client-side to require
    both the `chat` tag and the `session:<id>` tag on each message.

    Returns list of raw campfire message dicts, or empty list on any error.
    """
    safe_sid = _sanitize_session_id(session_id)
    cmd = [
        "cf", "read", campfire_id,
        "--all", "--json",
        "--tag", _CHAT_TAG,
        "--tag", f"session:{safe_sid}",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        _log.warning("cf binary not found or not executable: %s", exc)
        return []

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
    except asyncio.TimeoutError:
        _log.warning("cf read timed out for campfire=%s session=%s", campfire_id, session_id)
        return []

    if proc.returncode != 0:
        _log.warning(
            "cf read failed (exit %d) for campfire=%s session=%s: %s",
            proc.returncode, campfire_id, session_id,
            stderr.decode(errors="replace").strip(),
        )
        return []

    raw = stdout.decode(errors="replace").strip()
    if not raw:
        return []

    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        _log.warning("cf read returned non-JSON output for campfire=%s", campfire_id)
        return []

    if not isinstance(items, list):
        _log.warning("cf read returned non-list JSON for campfire=%s", campfire_id)
        return []

    # cf --tag filtering is OR-based; filter client-side to require BOTH tags
    session_tag = f"session:{safe_sid}"
    filtered = [
        m for m in items
        if isinstance(m.get("tags"), list)
        and _CHAT_TAG in m["tags"]
        and session_tag in m["tags"]
    ]
    return filtered


def _parse_message(msg: dict) -> dict | None:
    """Extract role, content, and timestamp from a raw campfire message dict.

    Returns None if the message cannot be parsed.
    """
    tags = msg.get("tags", [])

    # Determine role from instance tag (user/assistant) or fall back to tags
    instance = msg.get("instance", "")
    if instance in ("user", "human"):
        role = "user"
    elif instance in ("assistant", "agent"):
        role = "assistant"
    else:
        # Try to infer from tags
        role_tag = next((t for t in tags if t.startswith("role:")), None)
        role = role_tag[len("role:"):] if role_tag else "assistant"

    # Payload is in the "payload" field (campfire wire format); may be JSON envelope
    payload_raw = msg.get("payload") or msg.get("content") or ""
    if isinstance(payload_raw, dict):
        # Already decoded somewhere
        content = payload_raw.get("content", "")
        timestamp = payload_raw.get("timestamp", msg.get("timestamp", ""))
    else:
        try:
            envelope = json.loads(payload_raw)
            if isinstance(envelope, dict):
                content = envelope.get("content", str(payload_raw))
                timestamp = envelope.get("timestamp", msg.get("timestamp", ""))
            else:
                content = str(payload_raw)
                timestamp = msg.get("timestamp", "")
        except (json.JSONDecodeError, TypeError):
            content = str(payload_raw)
            timestamp = msg.get("timestamp", "")

    if not content:
        return None

    return {
        "role": role,
        "content": content,
        "timestamp": str(timestamp),
    }


@tool(
    name="read-recent-chat",
    description="Read the N most recent chat messages for this session (1-20, default 5). Returns chronological order.",
    permission="read",
)
async def read_recent_chat(context: ToolContext, n: int = 5) -> dict:
    """Return the N most recent chat messages for this session.

    n must be between 1 and 20. Messages are returned in chronological order
    (oldest first). Returns empty list if session_id is empty or no messages exist.
    """
    if not context.session_id:
        return {"messages": [], "count": 0}

    n = max(1, min(20, n))

    campfire_id = context.config.delivery.campfire_id
    if not campfire_id:
        return {"messages": [], "count": 0}

    raw_msgs = await _read_chat_messages(campfire_id, context.session_id)

    parsed = []
    for msg in raw_msgs:
        entry = _parse_message(msg)
        if entry is not None:
            parsed.append(entry)

    # raw_msgs are already in campfire order (chronological); take last N
    recent = parsed[-n:] if len(parsed) > n else parsed
    return {"messages": recent, "count": len(recent)}


@tool(
    name="search-chat-history",
    description="Search chat history for this session by keyword. Returns up to 10 matching messages, most recent first.",
    permission="read",
)
async def search_chat_history(context: ToolContext, query: str) -> dict:
    """Return up to 10 chat messages whose content contains query (case-insensitive).

    Messages are returned most-recent-first. Returns empty list if session_id is
    empty, query is empty, or no matches are found.
    """
    if not context.session_id or not query:
        return {"messages": [], "count": 0}

    campfire_id = context.config.delivery.campfire_id
    if not campfire_id:
        return {"messages": [], "count": 0}

    raw_msgs = await _read_chat_messages(campfire_id, context.session_id)

    query_lower = query.lower()
    matches = []
    for msg in reversed(raw_msgs):  # most recent first
        entry = _parse_message(msg)
        if entry is not None and query_lower in entry["content"].lower():
            matches.append(entry)
            if len(matches) >= 10:
                break

    return {"messages": matches, "count": len(matches)}
