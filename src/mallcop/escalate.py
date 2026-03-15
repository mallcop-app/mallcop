"""Escalate command logic: route open findings to actor chain with budget controls."""

from __future__ import annotations

import json
import logging
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

_log = logging.getLogger(__name__)

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


_SEVERITY_RANK = {"critical": 0, "warn": 1, "info": 2}


def _maybe_notify(
    *,
    config: Any,
    hard_escalated: int,
    circuit_breaker_triggered: bool,
    budget_exhausted: bool,
    skipped: int,
    all_findings: list,
) -> None:
    """Fire email notification if conditions are met. Never raises."""
    # Pro config required
    if config.pro is None or not config.pro.account_id or not config.pro.service_token:
        return
    # Notify must be enabled
    if not config.notify.email:
        return

    triggers = config.notify.triggers

    # Determine which trigger fired and collect relevant findings
    trigger_name: str | None = None
    notify_findings: list = []

    if hard_escalated > 0 and triggers.get("hard_escalated", True):
        trigger_name = "hard_escalated"
        # Hard-escalated findings have an annotation with action="escalated"
        # from the hard constraint check. Collect all findings with that marker.
        for f in all_findings:
            for ann in getattr(f, "annotations", []):
                if getattr(ann, "action", None) == "escalated" and "hard-escalat" in getattr(ann, "reason", "").lower():
                    notify_findings.append(f)
                    break
    elif circuit_breaker_triggered and triggers.get("circuit_breaker", True):
        trigger_name = "circuit_breaker"
        notify_findings = list(all_findings)
    elif budget_exhausted and skipped > 0 and triggers.get("budget_exhausted", True):
        trigger_name = "budget_exhausted"
        # Budget-skipped findings
        for f in all_findings:
            for ann in getattr(f, "annotations", []):
                if getattr(ann, "actor", None) == "mallcop-budget":
                    notify_findings.append(f)
                    break

    # Also check for heal_failed: actor returned ESCALATED (not RESOLVED)
    if trigger_name is None and triggers.get("heal_failed", True):
        for f in all_findings:
            for ann in getattr(f, "annotations", []):
                if getattr(ann, "action", None) == "escalated" and getattr(ann, "actor", "") not in ("mallcop-budget", "mallcop-squelch"):
                    # Check it's not a hard-escalation (those have specific reason patterns)
                    reason = getattr(ann, "reason", "")
                    if "hard constraint" not in reason.lower():
                        notify_findings.append(f)
                        break
        if notify_findings:
            trigger_name = "heal_failed"

    if trigger_name is None or not notify_findings:
        return

    # Apply min_severity filter
    min_sev = config.notify.min_severity
    min_rank = _SEVERITY_RANK.get(min_sev, 1)
    filtered = [f for f in notify_findings if _SEVERITY_RANK.get(f.severity.value, 2) <= min_rank]
    if not filtered:
        return

    # Build finding summaries
    summaries = []
    for f in filtered:
        summaries.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "detector": f.detector,
            "reason": f.annotations[-1].reason if f.annotations else "",
        })

    # Send notification
    from mallcop.pro import ProClient

    try:
        client = ProClient(account_url=config.pro.account_url)
        client.notify(
            config.pro.account_id,
            config.pro.service_token,
            subject=f"mallcop: {trigger_name} — {len(summaries)} finding(s)",
            findings=summaries,
            trigger=trigger_name,
        )
    except RuntimeError as exc:
        msg = str(exc)
        if "email_not_verified" in msg:
            _log.warning("Email notify skipped: email not verified for account %s", config.pro.account_id)
        elif "rate_limited" in msg:
            parts = msg.split(":")
            seconds = parts[-1] if len(parts) > 2 else "?"
            _log.info("Email notify rate-limited, retry in %s seconds", seconds)
        else:
            _log.warning("Email notify failed: %s", msg)
    except Exception:
        _log.warning("Email notify failed (unexpected)", exc_info=True)


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
        max_donuts_per_run=config.budget.max_donuts_per_run,
        max_donuts_per_finding=config.budget.max_donuts_per_finding,
    )

    # Load open findings only
    all_findings = store.query_findings(status="open")

    # Partition findings: boundary-violation findings are exempt from all gates
    boundary_findings = [f for f in all_findings if f.detector == "boundary-violation"]
    gated_findings = [f for f in all_findings if f.detector != "boundary-violation"]

    # Check circuit breaker using only gated findings (boundary violations don't count)
    cb_finding = check_circuit_breaker(gated_findings, budget_config)
    circuit_breaker_triggered = cb_finding is not None
    if circuit_breaker_triggered:
        # Circuit breaker triggered — skip all gated actors, but still process
        # boundary-violation findings (they are exempt from the circuit breaker).
        store.append_findings([cb_finding])

    if circuit_breaker_triggered and not boundary_findings:
        # No boundary findings to process — early exit
        cost_entry = CostEntry(
            timestamp=datetime.now(timezone.utc),
            events=0,
            findings=len(all_findings),
            actors_invoked=False,
            donuts_used=0,
            estimated_cost_usd=0.0,
            budget_remaining_pct=100.0,
        )
        append_cost_log(root / ".mallcop" / "costs.jsonl", cost_entry)
        return {
            "status": "ok",
            "findings_processed": 0,
            "circuit_breaker_triggered": True,
            "budget_exhausted": False,
            "donuts_used": 0,
            "skipped": False,
            "reason": None,
        }

    # Order by severity: CRITICAL first (gated findings only; boundary handled separately)
    # When circuit breaker triggered, skip gated findings entirely.
    ordered = [] if circuit_breaker_triggered else order_by_severity(gated_findings)

    # --- Hard constraints: deterministic escalation BEFORE anything else ---
    from mallcop.resolution_rules import (
        auto_escalate_finding,
        auto_resolve_finding,
        check_hard_constraints,
        count_patterns,
        evaluate_rules,
        generate_rules,
        load_rules,
        save_rules,
    )

    rules_path = root / ".mallcop" / "resolution_rules.yaml"
    auto_resolved = 0

    # Update rules from accumulated feedback (cheap — just counting)
    try:
        feedback_records = store.query_feedback()
        candidates = count_patterns(feedback_records)
        new_rules = generate_rules(candidates)
        if new_rules:
            existing = load_rules(rules_path)
            merged_ids = {nr.id for nr in new_rules}
            merged = [r for r in existing if r.id not in merged_ids] + new_rules
            save_rules(merged, rules_path)
    except Exception:
        _log.debug("Rule update failed (non-fatal)", exc_info=True)

    # Evaluate rules against open findings
    try:
        rules = load_rules(rules_path)
        baseline_for_rules = store.get_baseline() if rules else None
    except Exception:
        rules = []
        baseline_for_rules = None

    hard_escalated = 0
    remaining: list[Finding] = []
    for finding in ordered:
        # Hard constraints first — deterministic, no LLM
        constraint_reason = check_hard_constraints(finding)
        if constraint_reason is not None:
            auto_escalate_finding(finding, constraint_reason)
            store.update_finding(finding.id, annotations=finding.annotations)
            hard_escalated += 1
            _log.info("Hard-escalated %s: %s", finding.id, finding.detector)
            continue

        # Resolution rules — deterministic, no LLM
        if rules:
            match = evaluate_rules(finding, rules, baseline=baseline_for_rules)
            if match is not None:
                auto_resolve_finding(finding, match)
                store.update_finding(finding.id, status="resolved", annotations=finding.annotations)
                auto_resolved += 1
                _log.info("Auto-resolved %s via rule %s", finding.id, match.id)
                continue
        remaining.append(finding)

    if hard_escalated:
        _log.info("Hard-escalated %d findings (deterministic)", hard_escalated)
    if auto_resolved:
        _log.info("Auto-resolved %d/%d findings via rules", auto_resolved, len(ordered))
    ordered = remaining

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

    # Boundary-violation findings always flow through the actor chain, exempt from budget.
    # They are routed via CRITICAL routing (they are always CRITICAL severity).
    # If no CRITICAL route exists, they are still flagged (annotated) but not actor-processed.
    boundary_routable: list[tuple[Finding, str]] = []
    for finding in boundary_findings:
        route = config.routing.get(finding.severity.value)
        if route is None:
            continue
        entry_actor = route.chain[0] if route.chain else None
        if entry_actor is None:
            continue
        boundary_routable.append((finding, entry_actor))

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

            # Compute remaining donut budget for this batch
            remaining_tokens: int | None = None
            if budget_config.max_donuts_per_run > 0:
                remaining_tokens = budget_config.max_donuts_per_run - tracker.donuts_used
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
                                    reason="Per-run donut budget exhausted",
                                )
                            ],
                        )
                    continue

            # Load baseline for cold start detection (best-effort: None if unavailable)
            try:
                baseline = store.get_baseline()
            except Exception:
                baseline = None

            batch_result = run_batch(
                actor_runner,
                batch_findings,
                actor_name=actor_name,
                finding_token_budget=budget_config.max_donuts_per_finding,
                max_tokens=remaining_tokens,
                baseline=baseline,
            )

            tracker.add_donuts(batch_result.total_tokens)

            # Persist feedback records from batch (resolved findings → learning flywheel)
            for fb_record in batch_result.feedback_records:
                try:
                    store.append_feedback(fb_record)
                except Exception:
                    pass  # Best-effort: feedback loss is non-fatal

            # Apply resolutions from batch results
            # Use zip to pair results with findings — avoids index mismatch if
            # run_batch ever returns fewer results than input findings.
            for finding, result in zip(batch_findings, batch_result.results):
                processed += 1
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
                        # boundary-violation findings are always escalated — never squelched
                        if finding.detector == "boundary-violation":
                            squelched, via_spot_check = False, False
                        else:
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
                                reason="Per-run donut budget exhausted",
                            )
                        ],
                    )

    # Process boundary-violation findings through the actor chain, exempt from budget.
    # These always flow regardless of circuit breaker or budget exhaustion.
    # Tokens consumed by boundary findings do NOT count against the run budget.
    if actor_runner is not None and boundary_routable:
        # Group by entry actor
        bv_batches: dict[str, list[Finding]] = {}
        bv_order: list[str] = []
        for finding, entry_actor in boundary_routable:
            if entry_actor not in bv_batches:
                bv_batches[entry_actor] = []
                bv_order.append(entry_actor)
            bv_batches[entry_actor].append(finding)

        for actor_name in bv_order:
            bv_batch_findings = bv_batches[actor_name]

            # Load baseline (best-effort)
            try:
                baseline = store.get_baseline()
            except Exception:
                baseline = None

            # No budget limit for boundary findings — they always get processed.
            bv_result = run_batch(
                actor_runner,
                bv_batch_findings,
                actor_name=actor_name,
                finding_token_budget=None,
                max_tokens=None,
                baseline=baseline,
            )

            # Boundary tokens are NOT added to tracker — they don't count against budget.

            # Apply resolutions — boundary findings cannot be RESOLVED by actors.
            # Any RESOLVED action is overridden to ESCALATED here as a second enforcement
            # layer (the resolve-finding tool also enforces this).
            for finding, result in zip(bv_batch_findings, bv_result.results):
                processed += 1
                if result.resolution is not None:
                    reason = result.resolution.reason
                    if result.resolution.action == ResolutionAction.RESOLVED:
                        reason = (
                            f"[boundary-violation: actor resolution overridden to escalated — "
                            f"original reason: {reason}]"
                        )
                    # Never squelch — always annotate boundary findings as escalated
                    store.update_finding(
                        finding.id,
                        annotations=[
                            Annotation(
                                actor=actor_name,
                                timestamp=datetime.now(timezone.utc),
                                content=reason,
                                action="escalated",
                                reason=reason,
                            )
                        ],
                    )

    # --- Email notification ---
    # Re-query findings so we see annotations added by actors/hard-constraints
    post_findings = store.query_findings()
    _maybe_notify(
        config=config,
        hard_escalated=hard_escalated,
        circuit_breaker_triggered=circuit_breaker_triggered,
        budget_exhausted=budget_exhausted,
        skipped=skipped,
        all_findings=post_findings,
    )

    # Log cost entry
    total_donuts = tracker.donuts_used
    estimated_cost = (total_donuts / 1000) * _COST_PER_1K_TOKENS_USD
    cost_entry = CostEntry(
        timestamp=datetime.now(timezone.utc),
        events=0,
        findings=processed,
        actors_invoked=processed > 0,
        donuts_used=total_donuts,
        estimated_cost_usd=estimated_cost,
        budget_remaining_pct=tracker.budget_remaining_pct(),
    )
    append_cost_log(root / ".mallcop" / "costs.jsonl", cost_entry)

    return {
        "status": "ok",
        "findings_processed": processed,
        "findings_skipped": skipped,
        "auto_resolved": auto_resolved,
        "circuit_breaker_triggered": circuit_breaker_triggered,
        "budget_exhausted": budget_exhausted,
        "donuts_used": total_donuts,
        "skipped": False,
        "reason": None,
    }
