"""ContextWindowManager — builds a context-window-aware system prompt injection.

Given a list of ConversationMessage objects, fits them within a token budget.
When the total exceeds 60% of the context window, older messages are summarized.
The last 10 messages are always included verbatim.
"""

from __future__ import annotations

import logging
from typing import Any

from mallcop.conversation import ConversationMessage

logger = logging.getLogger(__name__)

DEFAULT_CONTEXT_BUDGET = 100_000  # tokens
DEFAULT_THRESHOLD_RATIO = 0.60    # 60% of context budget
DEFAULT_VERBATIM_COUNT = 10       # last N messages always verbatim

SUMMARY_SYSTEM_PROMPT = (
    "You are a concise summarizer. Summarize the following conversation history "
    "into a compact paragraph that preserves key facts, decisions, and context. "
    "Be brief but complete."
)


def _count_tokens(text: str) -> int:
    """Heuristic token count: word_count * 1.3."""
    words = len(text.split())
    return int(words * 1.3)


def _message_tokens(msg: ConversationMessage) -> int:
    return _count_tokens(msg.content)


class ContextWindowManager:
    """Builds a prompt-injectable context block from conversation history.

    Parameters
    ----------
    context_budget:
        Maximum token budget for the full context window.
    threshold_ratio:
        Fraction of context_budget at which summarization kicks in.
    verbatim_count:
        Number of most-recent messages always included verbatim.
    managed_client:
        Optional ManagedClient for LLM-based summarization. If None,
        a simple truncation fallback is used (useful for testing without
        a live endpoint).
    """

    def __init__(
        self,
        context_budget: int = DEFAULT_CONTEXT_BUDGET,
        threshold_ratio: float = DEFAULT_THRESHOLD_RATIO,
        verbatim_count: int = DEFAULT_VERBATIM_COUNT,
        managed_client: Any | None = None,
    ) -> None:
        self._context_budget = context_budget
        self._threshold = int(context_budget * threshold_ratio)
        self._verbatim_count = verbatim_count
        self._client = managed_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_context(
        self, messages: list[ConversationMessage]
    ) -> dict[str, Any]:
        """Build a context dict from conversation messages.

        Returns
        -------
        dict with keys:
            messages: list[dict] — verbatim messages to include in the prompt
            summary: str | None — summary of older messages (if summarized)
            finding_refs: list[str] — deduplicated finding references
            total_tokens: int — estimated token count of returned messages
        """
        finding_refs = _collect_finding_refs(messages)

        if len(messages) <= self._verbatim_count:
            # All messages fit verbatim — no summarization needed
            token_total = sum(_message_tokens(m) for m in messages)
            return {
                "messages": [_to_dict(m) for m in messages],
                "summary": None,
                "finding_refs": finding_refs,
                "total_tokens": token_total,
            }

        # Split: older messages vs. last N verbatim
        verbatim_messages = messages[-self._verbatim_count:]
        older_messages = messages[: -self._verbatim_count]

        total_tokens = sum(_message_tokens(m) for m in messages)

        if total_tokens <= self._threshold:
            # Under budget — return everything verbatim
            return {
                "messages": [_to_dict(m) for m in messages],
                "summary": None,
                "finding_refs": finding_refs,
                "total_tokens": total_tokens,
            }

        # Over threshold — summarize older messages, keep last N verbatim
        summary = self._summarize(older_messages)
        verbatim_tokens = sum(_message_tokens(m) for m in verbatim_messages)
        summary_tokens = _count_tokens(summary) if summary else 0

        return {
            "messages": [_to_dict(m) for m in verbatim_messages],
            "summary": summary,
            "finding_refs": finding_refs,
            "total_tokens": verbatim_tokens + summary_tokens,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _summarize(self, messages: list[ConversationMessage]) -> str | None:
        """Summarize a list of older messages using the managed client."""
        if not messages:
            return None

        if self._client is None:
            # Fallback: simple truncation summary without LLM
            logger.warning("ContextWindowManager: no managed_client; using truncation fallback")
            combined = " ".join(m.content for m in messages)
            words = combined.split()
            if len(words) > 100:
                combined = " ".join(words[:100]) + "..."
            return f"[Summary of {len(messages)} earlier messages]: {combined}"

        # Build a single-turn prompt for the LLM
        history_text = "\n".join(
            f"{m.role.upper()}: {m.content}" for m in messages
        )
        summary_messages = [
            {"role": "user", "content": f"Conversation history to summarize:\n\n{history_text}"},
        ]

        try:
            response = self._client.chat(
                model="patrol",
                system_prompt=SUMMARY_SYSTEM_PROMPT,
                messages=summary_messages,
                tools=[],
            )
            # LLMResponse.raw_resolution may hold text; check text via raw_resolution
            if response.raw_resolution and isinstance(response.raw_resolution, dict):
                text = response.raw_resolution.get("content", "") or ""
            else:
                # Fallback: use str representation if no structured resolution
                text = str(response.raw_resolution) if response.raw_resolution else ""
            return text or f"[Summary of {len(messages)} earlier messages]"
        except Exception as exc:
            logger.warning("ContextWindowManager: summarization failed: %s", exc)
            return f"[Summary of {len(messages)} earlier messages — summarization unavailable]"


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _to_dict(msg: ConversationMessage) -> dict[str, Any]:
    return msg.to_dict()


def _collect_finding_refs(messages: list[ConversationMessage]) -> list[str]:
    """Collect and deduplicate finding_refs from all messages, preserving order."""
    seen: set[str] = set()
    refs: list[str] = []
    for msg in messages:
        for ref in msg.finding_refs:
            if ref not in seen:
                seen.add(ref)
                refs.append(ref)
    return refs
