"""mallcop chat — interactive REPL that queries managed inference with conversation context."""

from __future__ import annotations

import json
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

# Maximum findings loaded into the system prompt.
MAX_FINDINGS_IN_PROMPT: int = 20

# Default donut budget warning threshold per session.
DEFAULT_BUDGET_WARNING_THRESHOLD: int = 50

# System prompt base.
_BASE_SYSTEM_PROMPT = (
    "You are a security analyst assistant for mallcop. "
    "Help the operator understand security findings, events, and posture. "
    "Be concise, actionable, and grounded in the findings provided."
)

# Per-session cumulative donut spend tracker.
# Maps session_id -> cumulative donuts spent (float).
_session_donut_spend: dict[str, float] = {}


def _load_finding_summaries(root: Path, max_findings: int = MAX_FINDINGS_IN_PROMPT) -> list[str]:
    """Load finding summaries from findings.jsonl in root, returning list of strings.

    Returns at most *max_findings* entries, selecting the most recent by timestamp.
    """
    findings_path = root / "findings.jsonl"
    if not findings_path.exists():
        return []
    findings: list[tuple[str, str]] = []  # (timestamp, formatted_summary)
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
                timestamp = obj.get("timestamp", obj.get("created_at", ""))
                if title:
                    findings.append((str(timestamp), f"[{severity}] {finding_id}: {title}"))
            except Exception:
                pass
    except Exception as exc:
        _log.debug("chat: could not load findings.jsonl: %s", exc)
        return []

    # Sort descending by timestamp, take most recent max_findings.
    findings.sort(key=lambda x: x[0], reverse=True)
    return [summary for _, summary in findings[:max_findings]]


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

    # Read budget warning threshold from env var or use default.
    budget_threshold = int(
        os.environ.get("MALLCOP_BUDGET_WARNING_THRESHOLD", DEFAULT_BUDGET_WARNING_THRESHOLD)
    )
    if budget_threshold <= 0:
        _log.warning(
            "chat: MALLCOP_BUDGET_WARNING_THRESHOLD=%d is invalid (must be > 0); "
            "using default %d",
            budget_threshold,
            DEFAULT_BUDGET_WARNING_THRESHOLD,
        )
        budget_threshold = DEFAULT_BUDGET_WARNING_THRESHOLD

    try:
        response = managed_client.chat(
            model="detective",
            system_prompt=system_prompt,
            messages=messages,
            tools=[],
            max_tokens=MAX_TOKENS_PER_TURN,
        )
    except Exception as exc:
        # Check if this is a Forge HTTP error (402 or 503).
        # LLMAPIError carries status_code directly; fall back to inspecting
        # any .status_code attribute for other HTTP client exceptions.
        status_code: int | None = getattr(exc, "status_code", None)

        if status_code == 402:
            platform_msg = (
                "I received your message but can't respond right now — "
                "insufficient donut balance. "
                "Your message is saved and I'll respond when service resumes."
            )
            try:
                store.append(
                    session_id=session_id,
                    surface=SURFACE,
                    role="assistant",
                    content=platform_msg,
                    tokens_used=0,
                )
            except Exception as store_exc:
                _log.error("chat: failed to persist 402 platform message: %s", store_exc)
            return {"response": platform_msg, "tokens_used": 0, "footer": _burn_rate_footer(0)}
        elif status_code == 503:
            platform_msg = (
                "I received your message but can't respond right now — "
                "inference service unavailable. "
                "Your message is saved and I'll respond when service resumes."
            )
            try:
                store.append(
                    session_id=session_id,
                    surface=SURFACE,
                    role="assistant",
                    content=platform_msg,
                    tokens_used=0,
                )
            except Exception as store_exc:
                _log.error("chat: failed to persist 503 platform message: %s", store_exc)
            return {"response": platform_msg, "tokens_used": 0, "footer": _burn_rate_footer(0)}
        raise

    # Extract text from response.
    text = ""
    if response.raw_resolution and isinstance(response.raw_resolution, dict):
        text = response.raw_resolution.get("content", "") or ""
    if not text and response.raw_resolution:
        text = str(response.raw_resolution)

    tokens_used = response.tokens_used

    # Track cumulative donut spend for this session.
    donuts_this_turn = tokens_used / TOKENS_PER_DONUT
    _session_donut_spend[session_id] = _session_donut_spend.get(session_id, 0.0) + donuts_this_turn
    cumulative_donuts = _session_donut_spend[session_id]

    # Append assistant response to store.
    store.append(
        session_id=session_id,
        surface=SURFACE,
        role="assistant",
        content=text,
        tokens_used=tokens_used,
    )

    footer = _burn_rate_footer(tokens_used)
    result: dict[str, Any] = {"response": text, "tokens_used": tokens_used, "footer": footer}

    # Emit budget warning if cumulative spend exceeds threshold.
    if cumulative_donuts >= budget_threshold:
        # Attempt to get remaining balance from client (best-effort).
        remaining: str = "unknown"
        try:
            balance_info = managed_client.get_balance()
            if isinstance(balance_info, dict):
                remaining = str(balance_info.get("donuts", balance_info.get("balance", "unknown")))
        except Exception:
            pass
        result["budget_warning"] = (
            f"This conversation has used {cumulative_donuts:.1f} donuts. "
            f"Your remaining balance is {remaining}."
        )

    return result


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
