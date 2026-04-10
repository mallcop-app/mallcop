"""mallcop chat — interactive REPL that queries managed inference with conversation context."""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import uuid
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# Default tokens per donut for burn-rate footer display.
# 1 donut = 1000 tokens (heuristic; matches cost_estimator usage).
TOKENS_PER_DONUT: int = 1000

# Max tokens per turn enforced on every request.
MAX_TOKENS_PER_TURN: int = 2000

# Surface identifier sent as X-Mallcop-Surface header.
SURFACE: str = "cli"

# Default donut budget warning threshold per session.
DEFAULT_BUDGET_WARNING_THRESHOLD: int = 50

# Per-session cumulative donut spend tracker.
# Maps session_id -> cumulative donuts spent (float).
_session_donut_spend: dict[str, float] = {}

# Maximum number of sessions tracked in _session_donut_spend before eviction.
_MAX_TRACKED_SESSIONS: int = 1000

# User-facing platform error messages.
_MSG_402: str = (
    "I received your message but can't respond right now — "
    "insufficient donut balance. "
    "Your message is saved and I'll respond when service resumes."
)
_MSG_503: str = (
    "I received your message but can't respond right now — "
    "inference service unavailable. "
    "Your message is saved and I'll respond when service resumes."
)

# Budget warning threshold — resolved at module load from the env var.
# Tests that use monkeypatch.setenv override this before calling chat_turn,
# so we re-read the env var inside chat_turn to respect per-test overrides.
_BUDGET_WARNING_THRESHOLD: int = DEFAULT_BUDGET_WARNING_THRESHOLD


async def _platform_error_response(
    session_id: str,
    store: Any,
    msg: str,
) -> dict[str, Any]:
    """Append *msg* as an assistant message and return the standard platform-error dict."""
    try:
        _r = store.append(
            session_id=session_id,
            surface=SURFACE,
            role="assistant",
            content=msg,
            tokens_used=0,
        )
        if inspect.isawaitable(_r):
            await _r
    except Exception as store_exc:
        _log.error("chat: failed to persist platform message: %s", store_exc)
    return {
        "response": msg,
        "tokens_used": 0,
        "footer": _burn_rate_footer(0),
        "is_platform_error": True,
    }


def _burn_rate_footer(tokens_used: int) -> str:
    """Return a burn-rate footer string like '[1.2 donuts]'."""
    donuts = tokens_used / TOKENS_PER_DONUT
    return f"[{donuts:.1f} donuts]"


async def chat_turn(
    question: str,
    session_id: str,
    interactive_runner: Any,
    store: Any,
    root: Path,
) -> dict[str, Any]:
    """Execute one chat turn using InteractiveRuntime, store result.

    Parameters
    ----------
    question:
        The user's question text.
    session_id:
        UUID4 session identifier (generated once at REPL start).
    interactive_runner:
        InteractiveRuntime instance, or None for non-pro users.
    store:
        ConversationStore for persisting messages.
    root:
        Deployment root directory (unused; kept for interface compatibility).

    Returns
    -------
    dict with keys:
        response: str — the assistant's text response
        tokens_used: int — total tokens used this turn
        footer: str — burn-rate footer string
    """
    from mallcop.llm_types import LLMAPIError

    # Early-return for non-pro users (BEFORE appending user message).
    if interactive_runner is None:
        return await _platform_error_response(
            session_id, store,
            "Pro subscription required for interactive chat. Run: mallcop init --pro"
        )

    # Append user message to store.
    # Support both sync (ConversationStore) and async (CampfireConversationAdapter) stores.
    _r = store.append(
        session_id=session_id,
        surface=SURFACE,
        role="user",
        content=question,
    )
    if inspect.isawaitable(_r):
        await _r

    # Load last 5 messages (inline, no ContextWindowManager).
    _l = store.load_session(session_id)
    history = await _l if inspect.isawaitable(_l) else _l
    recent = history[-5:]
    messages = [{"role": m.role, "content": m.content} for m in recent]

    # Read budget warning threshold from env var (allows per-test override via monkeypatch).
    _budget_threshold = int(
        os.environ.get("MALLCOP_BUDGET_WARNING_THRESHOLD", DEFAULT_BUDGET_WARNING_THRESHOLD)
    )
    if _budget_threshold <= 0:
        _log.warning(
            "chat: MALLCOP_BUDGET_WARNING_THRESHOLD=%d is invalid (must be > 0); "
            "using default %d",
            _budget_threshold,
            DEFAULT_BUDGET_WARNING_THRESHOLD,
        )
        _budget_threshold = DEFAULT_BUDGET_WARNING_THRESHOLD

    try:
        turn_result = interactive_runner.run_turn(
            messages=messages,
            turn_budget_donuts=12,
            session_id=session_id,
        )
    except LLMAPIError as exc:
        if exc.status_code == 402:
            return await _platform_error_response(session_id, store, _MSG_402)
        if exc.status_code == 503:
            return await _platform_error_response(session_id, store, _MSG_503)
        raise

    text = turn_result.text
    tokens_used = turn_result.tokens_used

    # Track cumulative donut spend for this session.
    donuts_this_turn = tokens_used / TOKENS_PER_DONUT
    _session_donut_spend[session_id] = _session_donut_spend.get(session_id, 0.0) + donuts_this_turn
    cumulative_donuts = _session_donut_spend[session_id]

    # Evict tracked sessions when the dict grows too large.
    if len(_session_donut_spend) > _MAX_TRACKED_SESSIONS:
        keep = list(_session_donut_spend.keys())[_MAX_TRACKED_SESSIONS // 2:]
        for k in list(_session_donut_spend.keys()):
            if k not in keep:
                del _session_donut_spend[k]

    # Append assistant response to store.
    _r = store.append(
        session_id=session_id,
        surface=SURFACE,
        role="assistant",
        content=text,
        tokens_used=tokens_used,
    )
    if inspect.isawaitable(_r):
        await _r

    footer = _burn_rate_footer(tokens_used)
    result: dict[str, Any] = {"response": text, "tokens_used": tokens_used, "footer": footer}

    # Emit budget warning if cumulative spend exceeds threshold.
    if cumulative_donuts >= _budget_threshold:
        result["budget_warning"] = (
            f"This conversation has used {cumulative_donuts:.1f} donuts. "
            f"Your remaining balance is unknown."
        )

    return result


def run_chat_repl(
    interactive_runner: Any,
    root: Path,
) -> None:
    """Run the interactive chat REPL.

    Reads questions from stdin, calls chat_turn(), prints responses with
    burn-rate footer until EOF or 'exit'/'quit'.
    """
    import click
    from mallcop.conversation import ConversationStore

    session_id = str(uuid.uuid4())
    store = ConversationStore(root / "conversations.jsonl")

    click.echo(f"mallcop chat  (session {session_id[:8]}...)  type 'exit' to quit")
    click.echo("")

    while True:
        try:
            question = click.prompt("you", prompt_suffix="> ")
        except (EOFError, click.exceptions.Abort):
            break

        question = question.strip()
        if not question:
            continue
        if question.lower() in {"exit", "quit"}:
            break

        try:
            result = asyncio.run(chat_turn(
                question=question,
                session_id=session_id,
                interactive_runner=interactive_runner,
                store=store,
                root=root,
            ))
            click.echo(f"\nmallcop> {result['response']}")
            click.echo(result["footer"])
            if result.get("budget_warning"):
                click.echo(f"\n[budget] {result['budget_warning']}")
            click.echo("")
        except Exception as exc:
            click.echo(f"ERROR: {exc}", err=True)
