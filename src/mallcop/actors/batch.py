"""Batch processing for actor runtime: build_batch_context and run_batch."""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Callable

from mallcop.actors._schema import ActorManifest, ActorResolution, ResolutionAction
from mallcop.schemas import Finding

from mallcop.actors.channels import _deliver_channel_batch

_log = logging.getLogger(__name__)


# Import these here so runtime.py can import from batch.py
# Avoid circular import by importing RunResult/BatchResult lazily or from the module that defines them.
# RunResult and BatchResult are defined in runtime.py, so we import at function level.


def build_batch_context(findings: list[Finding]) -> str | None:
    """Build a framing summary for a batch of findings.

    Returns a string summarizing counts by detector and severity, or None
    if the batch has fewer than 2 findings (framing is only useful for
    multi-finding batches).

    Uses ONLY internal metadata (detector name, severity) — no
    attacker-controlled strings (titles, actors, targets).
    """
    if len(findings) < 2:
        return None

    counts: Counter[tuple[str, str]] = Counter()
    for f in findings:
        counts[(f.detector, f.severity.value)] += 1

    total = len(findings)
    parts = []
    for (detector, severity), count in sorted(counts.items()):
        parts.append(f"{count} from {detector}({severity})")

    return (
        f"You have {total} findings: {', '.join(parts)}. "
        "Review each independently."
    )


def run_batch(
    actor_runner: Callable[..., Any],
    findings: list[Finding],
    *,
    actor_name: str | None = None,
    finding_token_budget: int | None = None,
    max_tokens: int | None = None,
) -> Any:
    """Run actor_runner on a batch of findings with aggregate token tracking.

    Channel actor delivery is deferred until the batch completes, then all
    channel-bound findings are delivered in a single consolidated digest POST.

    Args:
        actor_runner: Callable (finding, **kwargs) -> RunResult.
        findings: List of findings to process.
        actor_name: Actor name to pass to the runner.
        finding_token_budget: Per-finding token budget.
        max_tokens: Max total tokens across the batch. Stops processing
            when this limit would be exceeded.

    Returns:
        BatchResult with per-finding results and total token count.
    """
    from mallcop.actors.runtime import BatchResult, RunResult
    from pathlib import Path

    results: list[RunResult] = []
    total_tokens = 0
    # Channel findings deferred for consolidated delivery at batch end.
    # Each entry is (finding, result_index) so we can update results in-place.
    _deferred_channel: list[tuple[Finding, int]] = []
    # Channel metadata set by actor_runner on first deferral: (manifest, dir, config)
    _deferred_channel_meta: list[tuple[ActorManifest, Path, Any]] = []

    batch_context = build_batch_context(findings)

    for finding in findings:
        # Check batch token budget before starting next finding
        if max_tokens is not None and total_tokens >= max_tokens:
            break

        kwargs: dict[str, Any] = {}
        if actor_name is not None:
            kwargs["actor_name"] = actor_name
        if finding_token_budget is not None:
            kwargs["finding_token_budget"] = finding_token_budget
        if batch_context is not None:
            kwargs["batch_context"] = batch_context
        kwargs["_deferred_channel"] = _deferred_channel
        kwargs["_deferred_channel_meta"] = _deferred_channel_meta

        result = actor_runner(finding, **kwargs)
        result_idx = len(results)
        results.append(result)
        total_tokens += result.tokens_used

        # If this result was deferred, record the index for later update
        if (
            result.resolution is not None
            and result.resolution.reason.startswith("Deferred for batch channel delivery")
        ):
            _deferred_channel.append((finding, result_idx))

        # Stop if we've exceeded the batch budget after this finding
        if max_tokens is not None and total_tokens >= max_tokens:
            break

    # Consolidated channel delivery
    if _deferred_channel and _deferred_channel_meta:
        ch_manifest, ch_dir, runtime_config = _deferred_channel_meta[0]
        deferred_findings = [f for f, _ in _deferred_channel]
        _deliver_channel_batch(
            ch_manifest, ch_dir, deferred_findings, results,
            [idx for _, idx in _deferred_channel], runtime_config,
        )

    return BatchResult(results=results, total_tokens=total_tokens)
