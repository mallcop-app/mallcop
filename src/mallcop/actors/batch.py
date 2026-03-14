"""Batch processing for actor runtime: build_batch_context and run_batch."""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Callable

from mallcop.actors._schema import ActorManifest, ActorResolution, ResolutionAction
from mallcop.schemas import Finding

from mallcop.actors.channels import _deliver_channel_batch

_log = logging.getLogger(__name__)

# Detectors that require individual review regardless of batch size
_NON_BULK_DETECTORS = frozenset({"priv-escalation", "new-external-access"})

# Action keywords that make a finding non-bulk-resolvable
_NON_BULK_ACTION_KEYWORDS = ("export", "dump", "backup")

# Cold start thresholds
_COLD_START_MIN_ACTORS = 3
_COLD_START_MIN_FREQ_ENTRIES = 50


def is_cold_start(baseline: Any) -> bool:
    """Detect if the baseline represents a new/thin deployment.

    Cold start = actor_context has < 3 actors OR frequency_tables has < 50 entries.
    Both conditions must be met for warmth (OR logic for cold start).

    Args:
        baseline: Baseline instance, or None.

    Returns:
        True if this appears to be a new/thin deployment.
    """
    if baseline is None:
        return True
    actor_count = len(getattr(baseline, "actor_context", {}))
    freq_count = len(getattr(baseline, "frequency_tables", {}))
    return actor_count < _COLD_START_MIN_ACTORS or freq_count < _COLD_START_MIN_FREQ_ENTRIES


def is_non_bulk_resolvable(finding: Finding) -> bool:
    """Check if a finding must be reviewed individually (not bulk-resolved).

    Hard constraints:
    - priv-escalation detector: privilege changes always need individual audit
    - new-external-access detector: boundary changes need individual audit
    - action contains export/dump/backup keywords: data export findings

    Args:
        finding: The finding to check.

    Returns:
        True if the finding must be presented individually.
    """
    if finding.detector in _NON_BULK_DETECTORS:
        return True
    action = finding.metadata.get("action", "")
    if action and any(kw in action.lower() for kw in _NON_BULK_ACTION_KEYWORDS):
        return True
    return False


# Import these here so runtime.py can import from batch.py
# Avoid circular import by importing RunResult/BatchResult lazily or from the module that defines them.
# RunResult and BatchResult are defined in runtime.py, so we import at function level.


def build_batch_context(findings: list[Finding], baseline: Any = None) -> str | None:
    """Build a framing summary for a batch of findings.

    Returns a string summarizing counts by detector and severity, or None
    if the batch has fewer than 2 findings (framing is only useful for
    multi-finding batches).

    When baseline indicates a cold start, prepends onboarding guidance.

    Uses ONLY internal metadata (detector name, severity) — no
    attacker-controlled strings (titles, actors, targets).

    Args:
        findings: The batch of findings.
        baseline: Optional Baseline for cold-start detection.
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

    summary = (
        f"You have {total} findings: {', '.join(parts)}. "
        "Review each independently."
    )

    if is_cold_start(baseline):
        cold_start_prefix = (
            "This appears to be a new deployment. "
            "Most of these findings are likely normal operations for your environment. "
            "Help me learn what's normal by resolving the obvious ones. "
        )
        return cold_start_prefix + summary

    return summary


def run_batch(
    actor_runner: Callable[..., Any],
    findings: list[Finding],
    *,
    actor_name: str | None = None,
    finding_token_budget: int | None = None,
    max_tokens: int | None = None,
    baseline: Any = None,
) -> Any:
    """Run actor_runner on a batch of findings with aggregate token tracking.

    Channel actor delivery is deferred until the batch completes, then all
    channel-bound findings are delivered in a single consolidated digest POST.

    Non-bulk-resolvable findings (privilege changes, boundary changes, data
    exports) are presented individually (no batch_context kwarg).

    Each resolved finding generates a FeedbackRecord with source="batch"
    for the learning flywheel.

    Args:
        actor_runner: Callable (finding, **kwargs) -> RunResult.
        findings: List of findings to process.
        actor_name: Actor name to pass to the runner.
        finding_token_budget: Per-finding token budget.
        max_tokens: Max total tokens across the batch. Stops processing
            when this limit would be exceeded.
        baseline: Optional Baseline for cold-start framing.

    Returns:
        BatchResult with per-finding results, total token count, and feedback records.
    """
    from mallcop.actors.runtime import BatchResult, RunResult
    from mallcop.feedback import FeedbackRecord, HumanAction
    from datetime import datetime, timezone
    from pathlib import Path

    results: list[RunResult] = []
    total_tokens = 0
    feedback_records: list[FeedbackRecord] = []
    # Channel findings deferred for consolidated delivery at batch end.
    # Each entry is (finding, result_index) so we can update results in-place.
    _deferred_channel: list[tuple[Finding, int]] = []
    # Channel metadata set by actor_runner on first deferral: (manifest, dir, config)
    _deferred_channel_meta: list[tuple[ActorManifest, Path, Any]] = []

    batch_context = build_batch_context(findings, baseline=baseline)

    for finding in findings:
        # Check batch token budget before starting next finding
        if max_tokens is not None and total_tokens >= max_tokens:
            break

        kwargs: dict[str, Any] = {}
        if actor_name is not None:
            kwargs["actor_name"] = actor_name
        if finding_token_budget is not None:
            kwargs["finding_token_budget"] = finding_token_budget
        # Non-bulk-resolvable findings get no batch_context (presented individually)
        if batch_context is not None and not is_non_bulk_resolvable(finding):
            kwargs["batch_context"] = batch_context
        kwargs["_deferred_channel"] = _deferred_channel
        kwargs["_deferred_channel_meta"] = _deferred_channel_meta

        result = actor_runner(finding, **kwargs)
        result_idx = len(results)
        results.append(result)
        total_tokens += result.tokens_used

        # Create feedback record for resolved findings
        if (
            result.resolution is not None
            and result.resolution.action == ResolutionAction.RESOLVED
        ):
            feedback_records.append(FeedbackRecord(
                finding_id=finding.id,
                human_action=HumanAction.AGREE,
                reason=None,
                original_action="resolved",
                original_reason=result.resolution.reason,
                timestamp=datetime.now(timezone.utc),
                events=[],
                baseline_snapshot={},
                annotations=[],
                detector=finding.detector,
                source="batch",
            ))

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

    return BatchResult(results=results, total_tokens=total_tokens, feedback_records=feedback_records)
