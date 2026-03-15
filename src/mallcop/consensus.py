"""Consensus resolution: multiple independent investigations must agree.

When the actor chain resolves a finding (rather than escalating), run N
additional independent investigations. If ANY dissents (escalates), the
finding escalates to human. Unanimous resolve required to accept.

This catches stochastic model failures on ambiguous findings where the
model is sometimes right and sometimes wrong on the same input.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.schemas import Finding

_log = logging.getLogger(__name__)

DEFAULT_CONSENSUS_RUNS = 3  # additional runs beyond the first


def needs_consensus(result: RunResult) -> bool:
    """Check if a result needs consensus validation.

    Only findings that the actor chain RESOLVED need consensus.
    Escalated findings are already going to a human — no need to double-check.
    """
    if result.resolution is None:
        return False
    return result.resolution.action == ResolutionAction.RESOLVED


def run_consensus(
    finding: Finding,
    actor_runner: Callable[..., RunResult],
    first_result: RunResult,
    n_runs: int = DEFAULT_CONSENSUS_RUNS,
    **runner_kwargs: Any,
) -> RunResult:
    """Run additional independent investigations and check for unanimous resolve.

    Args:
        finding: The finding to re-investigate.
        actor_runner: The actor chain runner (same as used for first result).
        first_result: The original RunResult that resolved the finding.
        n_runs: Number of additional independent runs.
        **runner_kwargs: Passed to actor_runner (e.g. actor_name).

    Returns:
        The first_result if consensus is unanimous (all resolve).
        A synthetic escalation RunResult if any run dissents.
    """
    actions = [first_result.resolution.action.value]
    total_tokens = first_result.tokens_used

    for i in range(n_runs):
        try:
            result = actor_runner(finding, **runner_kwargs)
            total_tokens += result.tokens_used

            if result.resolution is not None:
                actions.append(result.resolution.action.value)
            else:
                # No resolution = treat as escalation (uncertain)
                actions.append("escalated")
        except Exception as e:
            _log.warning("Consensus run %d failed: %s", i + 1, e)
            actions.append("escalated")  # error = escalate

    resolve_count = sum(1 for a in actions if a == "resolved")
    escalate_count = sum(1 for a in actions if a == "escalated")

    _log.info(
        "Consensus for %s: %d resolve, %d escalate (of %d runs)",
        finding.id, resolve_count, escalate_count, len(actions),
    )

    if escalate_count == 0:
        # Unanimous resolve — accept the original result
        return RunResult(
            resolution=first_result.resolution,
            tokens_used=total_tokens,
            iterations=first_result.iterations,
        )

    # Dissent detected — override to escalate
    reasons = [f"{resolve_count}/{len(actions)} resolved, {escalate_count}/{len(actions)} escalated"]
    return RunResult(
        resolution=ActorResolution(
            finding_id=finding.id,
            action=ResolutionAction.ESCALATED,
            reason=f"Consensus escalation: {reasons[0]}. "
            f"Original reason: {first_result.resolution.reason}",
            confidence=0.0,
        ),
        tokens_used=total_tokens,
        iterations=first_result.iterations,
    )
