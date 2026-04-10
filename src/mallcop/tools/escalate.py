"""Tool: escalate-to-investigator.

Hands a finding off to the investigator actor for deep analysis.
"""

from __future__ import annotations

from typing import Any

from mallcop.chat import TOKENS_PER_DONUT
from mallcop.tools import ToolContext, tool


@tool(
    name="escalate-to-investigator",
    description=(
        "Hand a specific finding off to the investigator agent for deep analysis. "
        "Use when the operator asks for thorough investigation of a finding, when the "
        "finding looks complex, or when surface signals are ambiguous. Returns the "
        "investigator's structured resolution (action, reason, confidence). The "
        "investigator uses more tools and more iterations than you do."
    ),
    permission="write",
)
def escalate_to_investigator(
    context: ToolContext,
    finding_id: str,
    budget_donuts: int = 20,  # cap 30
) -> dict[str, Any]:
    """Escalate a finding to the investigator actor."""
    if context.actor_runner is None:
        return {"error": "investigator chain not available in this context"}

    # Cap budget silently: [1, 30]
    budget_donuts = max(1, min(30, budget_donuts))

    # Look up the finding
    findings = context.store.query_findings()
    target_finding = next((f for f in findings if f.id == finding_id), None)
    if target_finding is None:
        return {"error": f"finding '{finding_id}' not found"}

    budget_tokens = budget_donuts * TOKENS_PER_DONUT

    try:
        result = context.actor_runner(
            target_finding,
            actor_name="investigate",
            finding_token_budget=budget_tokens,
        )
    except Exception as exc:
        return {"error": f"investigator failed: {type(exc).__name__}: {exc}"}

    resolution = result.resolution
    return {
        "finding_id": finding_id,
        "action": resolution.action.value if resolution else "no_resolution",
        "reason": resolution.reason if resolution else "",
        "confidence": getattr(resolution, "confidence", None),
        "iterations": result.iterations,
        "tokens_used": result.tokens_used,
        "donuts_used": result.tokens_used / TOKENS_PER_DONUT,
    }
