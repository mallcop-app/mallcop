"""mallcop chat — interactive REPL that queries managed inference with conversation context."""

from __future__ import annotations

import json
import logging
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

# System prompt base.
_BASE_SYSTEM_PROMPT = (
    "You are a security analyst assistant for mallcop. "
    "Help the operator understand security findings, events, and posture. "
    "Be concise, actionable, and grounded in the findings provided."
)


def _load_finding_summaries(root: Path) -> list[str]:
    """Load finding summaries from findings.jsonl in root, returning list of strings."""
    findings_path = root / "findings.jsonl"
    if not findings_path.exists():
        return []
    summaries: list[str] = []
    try:
        for line in findings_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                finding_id = obj.get("id", "")
                severity = obj.get("severity", "")
                title = obj.get("title", obj.get("summary", ""))
                if title:
                    summaries.append(f"[{severity}] {finding_id}: {title}")
            except Exception:
                pass
    except Exception as exc:
        _log.debug("chat: could not load findings.jsonl: %s", exc)
    return summaries


def _build_system_prompt(root: Path) -> str:
    """Build the system prompt, including current finding summaries."""
    summaries = _load_finding_summaries(root)
    if not summaries:
        return _BASE_SYSTEM_PROMPT
    findings_block = "\n".join(summaries)
    return (
        f"{_BASE_SYSTEM_PROMPT}\n\n"
        f"Current findings:\n{findings_block}"
    )


def _burn_rate_footer(tokens_used: int) -> str:
    """Return a burn-rate footer string like '[1.2 donuts]'."""
    donuts = tokens_used / TOKENS_PER_DONUT
    return f"[{donuts:.1f} donuts]"


def chat_turn(
    question: str,
    session_id: str,
    managed_client: Any,
    store: Any,
    context_manager: Any,
    root: Path,
) -> dict[str, Any]:
    """Execute one chat turn: send question to managed inference, store result.

    Parameters
    ----------
    question:
        The user's question text.
    session_id:
        UUID4 session identifier (generated once at REPL start).
    managed_client:
        ManagedClient instance with X-Mallcop-Session and X-Mallcop-Surface headers set.
    store:
        ConversationStore for persisting messages.
    context_manager:
        ContextWindowManager for building trimmed history.
    root:
        Deployment root directory (for loading findings.jsonl).

    Returns
    -------
    dict with keys:
        response: str — the assistant's text response
        tokens_used: int — total tokens used this turn
        footer: str — burn-rate footer string
    """
    # Append user message to store.
    store.append(
        session_id=session_id,
        surface=SURFACE,
        role="user",
        content=question,
    )

    # Load full session history and build context.
    history = store.load_session(session_id)
    context = context_manager.build_context(history)

    # Build messages list for inference from context.
    messages = [
        {"role": m["role"], "content": m["content"]}
        for m in context["messages"]
    ]

    # Prepend summary if context manager summarized older messages.
    if context.get("summary"):
        summary_msg = {
            "role": "user",
            "content": f"[Earlier conversation summary]: {context['summary']}",
        }
        messages = [summary_msg] + messages

    # Ensure the current user question is at the end (it was just appended).
    # The history already includes it, so messages should end with user role.

    system_prompt = _build_system_prompt(root)

    response = managed_client.chat(
        model="detective",
        system_prompt=system_prompt,
        messages=messages,
        tools=[],
        max_tokens=MAX_TOKENS_PER_TURN,
    )

    # Extract text from response.
    text = ""
    if response.raw_resolution and isinstance(response.raw_resolution, dict):
        text = response.raw_resolution.get("content", "") or ""
    if not text and response.raw_resolution:
        text = str(response.raw_resolution)

    tokens_used = response.tokens_used

    # Append assistant response to store.
    store.append(
        session_id=session_id,
        surface=SURFACE,
        role="assistant",
        content=text,
        tokens_used=tokens_used,
    )

    footer = _burn_rate_footer(tokens_used)
    return {"response": text, "tokens_used": tokens_used, "footer": footer}


def run_chat_repl(
    managed_client: Any,
    root: Path,
) -> None:
    """Run the interactive chat REPL.

    Reads questions from stdin, calls chat_turn(), prints responses with
    burn-rate footer until EOF or 'exit'/'quit'.
    """
    import click
    from mallcop.conversation import ConversationStore
    from mallcop.context_window import ContextWindowManager

    session_id = str(uuid.uuid4())
    store = ConversationStore(root / "conversations.jsonl")
    context_manager = ContextWindowManager(managed_client=managed_client)

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
            result = chat_turn(
                question=question,
                session_id=session_id,
                managed_client=managed_client,
                store=store,
                context_manager=context_manager,
                root=root,
            )
            click.echo(f"\nmallcop> {result['response']}")
            click.echo(result["footer"])
            click.echo("")
        except Exception as exc:
            click.echo(f"ERROR: {exc}", err=True)
