"""Escalate command logic: route open findings to actor chain with budget controls."""

from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import BatchResult, RunResult, run_batch
from mallcop.budget import (
    BudgetConfig,
    BudgetTracker,
    CostEntry,
    append_cost_log,
    check_circuit_breaker,
    order_by_severity,
)
from mallcop.config import load_config
from mallcop.schemas import Annotation, Finding, FindingStatus
from mallcop.store import JsonlStore, Store


_SPOT_CHECK_RATE = 0.1  # 10% of squelched findings surface for audit


def _should_squelch(
    result: RunResult,
    squelch: int,
    _random_override: float | None = None,
) -> tuple[bool, bool]:
    """Determine if an escalated finding should be squelched.

    Args:
        result: The RunResult from actor chain.
        squelch: 0-10 gate setting (squelch/10 = confidence threshold).
        _random_override: Override random.random() for testing.

    Returns:
        (should_squelch, via_spot_check): both False means not squelched normally.
        via_spot_check=True means finding surfaces despite being below threshold.
    """
    # No resolution (error) or non-escalated action → never squelch
    if result.resolution is None:
        return False, False
    if result.resolution.action != ResolutionAction.ESCALATED:
        return False, False
    # squelch=0 → threshold=0.0 → nothing ever squelched
    threshold = squelch / 10.0
    if threshold <= 0.0:
        return False, False

    confidence = result.resolution.confidence
    if confidence >= threshold:
        return False, False

    # Below threshold — check spot-check override
    rand = _random_override if _random_override is not None else random.random()
    if rand < _SPOT_CHECK_RATE:
        # Spot-check: surface anyway for audit
        return False, True

    return True, False


# Haiku pricing (input + output blended estimate per 1k tokens)
_COST_PER_1K_TOKENS_USD = 0.00025


def run_escalate(
    root: Path,
    actor_runner: Callable[..., RunResult] | None = None,
    store: Store | None = None,
) -> dict[str, Any]:
    """Load open findings, route through actor chain with budget controls.

    Args:
        root: Deployment repo directory.
        actor_runner: Callable that processes a single finding.
            Signature: (finding: Finding, **kwargs) -> RunResult.
            If None, findings are logged but not processed.
        store: Optional Store instance. Defaults to JsonlStore(root) if None.

    Returns:
        Summary dict with escalation results.
    """
    config = load_config(root)
    if store is None:
        store = JsonlStore(root)
    budget_config = BudgetConfig(
        max_findings_for_actors=config.budget.max_findings_for_actors,
        max_tokens_per_run=config.budget.max_tokens_per_run,
        max_tokens_per_finding=config.budget.max_tokens_per_finding,
    )

    # Load open findings only
    all_findings = store.query_findings(status="open")

    # Check circuit breaker
    cb_finding = check_circuit_breaker(all_findings, budget_config)
    if cb_finding is not None:
        # Circuit breaker triggered — skip all actors
        store.append_findings([cb_finding])
        cost_entry = CostEntry(
            timestamp=datetime.now(timezone.utc),
            events=0,
            findings=len(all_findings),
            actors_invoked=False,
            tokens_used=0,
            estimated_cost_usd=0.0,
            budget_remaining_pct=100.0,
        )
        append_cost_log(root / ".mallcop" / "costs.jsonl", cost_entry)
        return {
            "status": "ok",
            "findings_processed": 0,
            "circuit_breaker_triggered": True,
            "budget_exhausted": False,
            "tokens_used": 0,
            "skipped": False,
            "reason": None,
        }

    # Order by severity: CRITICAL first
    ordered = order_by_severity(all_findings)

    # Group findings by entry actor (routing by severity)
    tracker = BudgetTracker(budget_config)
    processed = 0
    budget_exhausted = False
    skipped = 0

    # Separate routable findings from unroutable ones
    routable: list[tuple[Finding, str]] = []
    for finding in ordered:
        route = config.routing.get(finding.severity.value)
        if route is None:
            continue
        entry_actor = route.chain[0] if route.chain else None
        if entry_actor is None:
            continue
        routable.append((finding, entry_actor))

    if actor_runner is not None and routable:
        # Group by entry actor to enable batch processing
        actor_batches: dict[str, list[Finding]] = {}
        batch_order: list[str] = []  # preserve severity ordering
        for finding, entry_actor in routable:
            if entry_actor not in actor_batches:
                actor_batches[entry_actor] = []
                batch_order.append(entry_actor)
            actor_batches[entry_actor].append(finding)

        for actor_name in batch_order:
            batch_findings = actor_batches[actor_name]

            # Compute remaining token budget for this batch
            remaining_tokens: int | None = None
            if budget_config.max_tokens_per_run > 0:
                remaining_tokens = budget_config.max_tokens_per_run - tracker.tokens_used
                if remaining_tokens <= 0:
                    # Budget exhausted before this batch
                    budget_exhausted = True
                    for f in batch_findings:
                        skipped += 1
                        store.update_finding(
                            f.id,
                            annotations=[
                                Annotation(
                                    actor="mallcop-budget",
                                    timestamp=datetime.now(timezone.utc),
                                    content="Budget exhausted. Finding uninvestigated.",
                                    action="escalated",
                                    reason="Per-run token budget exhausted",
                                )
                            ],
                        )
                    continue

            batch_result = run_batch(
                actor_runner,
                batch_findings,
                actor_name=actor_name,
                finding_token_budget=budget_config.max_tokens_per_finding,
                max_tokens=remaining_tokens,
            )

            tracker.add_tokens(batch_result.total_tokens)

            # Apply resolutions from batch results
            for i, result in enumerate(batch_result.results):
                processed += 1
                finding = batch_findings[i]
                if result.resolution is not None:
                    if result.resolution.action == ResolutionAction.RESOLVED:
                        store.update_finding(
                            finding.id,
                            status=FindingStatus.RESOLVED,
                            annotations=[
                                Annotation(
                                    actor=actor_name,
                                    timestamp=datetime.now(timezone.utc),
                                    content=result.resolution.reason,
                                    action="resolved",
                                    reason=result.resolution.reason,
                                )
                            ],
                        )
                    elif result.resolution.action == ResolutionAction.ESCALATED:
                        # Squelch gate: suppress low-confidence escalations
                        squelched, via_spot_check = _should_squelch(
                            result, squelch=config.squelch
                        )
                        base_annotation = Annotation(
                            actor=actor_name,
                            timestamp=datetime.now(timezone.utc),
                            content=result.resolution.reason,
                            action="escalated",
                            reason=result.resolution.reason,
                        )
                        if squelched:
                            store.update_finding(
                                finding.id,
                                status=FindingStatus.SQUELCHED,
                                annotations=[base_annotation],
                            )
                        else:
                            extra_annotations = []
                            if via_spot_check:
                                extra_annotations.append(
                                    Annotation(
                                        actor="mallcop-squelch",
                                        timestamp=datetime.now(timezone.utc),
                                        content="Spot-check: surfaced for audit despite low confidence.",
                                        action="escalated",
                                        reason="Random 10% spot-check override",
                                    )
                                )
                            store.update_finding(
                                finding.id,
                                annotations=[base_annotation] + extra_annotations,
                            )

            # Mark unprocessed findings from this batch as budget-skipped
            unprocessed = batch_findings[len(batch_result.results):]
            if unprocessed:
                budget_exhausted = True
                for f in unprocessed:
                    skipped += 1
                    store.update_finding(
                        f.id,
                        annotations=[
                            Annotation(
                                actor="mallcop-budget",
                                timestamp=datetime.now(timezone.utc),
                                content="Budget exhausted. Finding uninvestigated.",
                                action="escalated",
                                reason="Per-run token budget exhausted",
                            )
                        ],
                    )

    # Log cost entry
    total_tokens = tracker.tokens_used
    estimated_cost = (total_tokens / 1000) * _COST_PER_1K_TOKENS_USD
    cost_entry = CostEntry(
        timestamp=datetime.now(timezone.utc),
        events=0,
        findings=processed,
        actors_invoked=processed > 0,
        tokens_used=total_tokens,
        estimated_cost_usd=estimated_cost,
        budget_remaining_pct=tracker.budget_remaining_pct(),
    )
    append_cost_log(root / ".mallcop" / "costs.jsonl", cost_entry)

    return {
        "status": "ok",
        "findings_processed": processed,
        "findings_skipped": skipped,
        "circuit_breaker_triggered": False,
        "budget_exhausted": budget_exhausted,
        "tokens_used": total_tokens,
        "skipped": False,
        "reason": None,
    }
