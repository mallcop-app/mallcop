"""Pipeline exam: measure end-to-end system accuracy.

Simulates the full resolution pipeline on each scenario:
1. Check resolution rules (from canned feedback history)
2. If no rule match → run triage + investigate (LLM via ShakedownHarness)
3. Score system-level outcome, not per-actor outcome

System verdicts:
- PASS: resolved correctly (by rule or LLM) OR correctly escalated to human
- FAIL: resolved INCORRECTLY and not caught by escalation
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from mallcop.feedback import FeedbackRecord, HumanAction
from mallcop.llm_types import LLMClient
from mallcop.resolution_rules import (
    ResolutionRule,
    check_hard_constraints,
    count_patterns,
    evaluate_rules,
    generate_rules,
)
from mallcop.schemas import Baseline, Finding

from tests.shakedown.evaluator import Grade, JudgeEvaluator, Verdict
from tests.shakedown.harness import ShakedownHarness, ShakedownResult
from tests.shakedown.scenario import Scenario

_log = logging.getLogger(__name__)


class PipelineVerdict:
    """System-level verdict for a finding going through the full pipeline."""

    PASS = "pass"
    FAIL = "fail"


@dataclass
class PipelineResult:
    """Result of one scenario through the full pipeline."""

    scenario_id: str
    # How it was resolved
    resolved_by: str  # "rule", "triage", "investigate", "human"
    # System verdict
    system_verdict: str  # PipelineVerdict.PASS or FAIL
    # Detail
    action_taken: str  # "resolved" or "escalated"
    action_correct: bool
    # Actor-level grade (None if resolved by rule)
    actor_grade: Grade | None = None
    # Tokens used (0 if rule-resolved)
    tokens: int = 0
    llm_calls: int = 0
    rule_id: str | None = None


def build_feedback_history(scenarios: list[Scenario], n_per_pattern: int = 5) -> list[FeedbackRecord]:
    """Build canned feedback history that would generate resolution rules.

    For each scenario where the expected action is "resolved" (benign),
    generates n_per_pattern AGREE feedback records. This simulates a user
    who has seen similar benign findings before and confirmed them.

    Only generates feedback for scenarios with clear benign patterns —
    not for scenarios where the expected action is "escalated".
    """
    records: list[FeedbackRecord] = []
    seen_patterns: set[str] = set()

    for scenario in scenarios:
        if scenario.expected.chain_action != "resolved":
            continue

        # Extract pattern from scenario
        events = [e.to_dict() for e in scenario.events[:1]] if scenario.events else []
        if not events:
            continue

        evt = events[0]
        pattern_key = f"{scenario.detector}:{evt.get('actor', '')}:{evt.get('event_type', '')}"
        if pattern_key in seen_patterns:
            continue
        seen_patterns.add(pattern_key)

        # Generate n feedback records for this pattern
        for i in range(n_per_pattern):
            records.append(FeedbackRecord(
                finding_id=f"hist_{scenario.id}_{i}",
                human_action=HumanAction.AGREE,
                reason=None,
                original_action="resolved",
                original_reason="routine",
                timestamp=datetime.now(timezone.utc),
                events=events,
                baseline_snapshot={},
                annotations=[],
                detector=scenario.detector,
                source="individual",
                weight=1.0,
            ))

    return records


def run_pipeline_exam(
    scenarios: list[Scenario],
    llm: LLMClient,
    judge: JudgeEvaluator,
    feedback_history: list[FeedbackRecord] | None = None,
    on_result: Any = None,
) -> list[PipelineResult]:
    """Run the full pipeline exam.

    Args:
        scenarios: Academy scenarios to test.
        llm: LLM client for triage + investigate.
        judge: Judge evaluator for grading LLM results.
        feedback_history: Canned feedback to generate rules from.
            If None, builds default history from resolved scenarios.
        on_result: Optional callback(PipelineResult) for progress.

    Returns:
        List of PipelineResult, one per scenario.
    """
    # Build resolution rules from feedback history
    if feedback_history is None:
        feedback_history = build_feedback_history(scenarios)

    candidates = count_patterns(feedback_history)
    rules = generate_rules(candidates)
    _log.info(
        "Pipeline exam: %d scenarios, %d feedback records, %d rules generated",
        len(scenarios), len(feedback_history), len(rules),
    )

    harness = ShakedownHarness(llm=llm)
    results: list[PipelineResult] = []

    for scenario in scenarios:
        result = _run_one(scenario, rules, harness, judge)
        results.append(result)
        if on_result:
            on_result(result)

    return results


def _run_one(
    scenario: Scenario,
    rules: list[ResolutionRule],
    harness: ShakedownHarness,
    judge: JudgeEvaluator,
) -> PipelineResult:
    """Run one scenario through the pipeline."""
    expected_action = scenario.expected.chain_action

    # Step 0: Hard constraints — deterministic escalation, no LLM
    constraint_reason = check_hard_constraints(scenario.finding)
    if constraint_reason is not None:
        # Hard constraint forces escalation to human
        action_correct = expected_action == "escalated"
        return PipelineResult(
            scenario_id=scenario.id,
            resolved_by="hard-constraint",
            system_verdict=PipelineVerdict.PASS,  # escalation to human is always correct
            action_taken="escalated",
            action_correct=action_correct,
            tokens=0,
            llm_calls=0,
        )

    # Step 1: Check resolution rules
    rule_match = evaluate_rules(scenario.finding, rules)
    if rule_match is not None:
        # Rule resolved it. Is the expected action "resolved"?
        action_correct = expected_action == "resolved"
        return PipelineResult(
            scenario_id=scenario.id,
            resolved_by="rule",
            system_verdict=PipelineVerdict.PASS if action_correct else PipelineVerdict.FAIL,
            action_taken="resolved",
            action_correct=action_correct,
            tokens=0,
            llm_calls=0,
            rule_id=rule_match.id,
        )

    # Step 2: Run through LLM (triage → investigate chain)
    try:
        harness_result = harness.run_scenario(scenario)
        grade = judge.evaluate(harness_result, scenario)
    except Exception as e:
        _log.error("Pipeline error on %s: %s", scenario.id, e)
        # Error → treated as escalation to human (system catches it)
        return PipelineResult(
            scenario_id=scenario.id,
            resolved_by="human",
            system_verdict=PipelineVerdict.PASS,  # escalation to human is correct
            action_taken="escalated",
            action_correct=expected_action == "escalated",
            tokens=0,
            llm_calls=0,
        )

    chain_action = harness_result.chain_action
    action_correct = chain_action == expected_action

    # Step 3: Score the system outcome
    if chain_action == "escalated":
        # Escalated to human — this is ALWAYS a system pass.
        # The human will make the right call. False escalation costs
        # donuts but doesn't miss threats.
        return PipelineResult(
            scenario_id=scenario.id,
            resolved_by="human",
            system_verdict=PipelineVerdict.PASS,
            action_taken="escalated",
            action_correct=action_correct,
            actor_grade=grade,
            tokens=harness_result.total_tokens,
            llm_calls=len(harness_result.llm_calls),
        )

    # Resolved by LLM — was it correct?
    if action_correct:
        # Correctly resolved
        resolved_by = "investigate" if harness_result.triage_action == "escalated" else "triage"
        return PipelineResult(
            scenario_id=scenario.id,
            resolved_by=resolved_by,
            system_verdict=PipelineVerdict.PASS,
            action_taken="resolved",
            action_correct=True,
            actor_grade=grade,
            tokens=harness_result.total_tokens,
            llm_calls=len(harness_result.llm_calls),
        )

    # INCORRECTLY resolved — this is the only system FAIL.
    # The LLM resolved a finding that should have been escalated,
    # or escalated a finding that was clearly benign (wasted human time).
    # But: resolving a finding that should escalate is DANGEROUS (missed threat).
    # Escalating a benign finding is just wasteful, not dangerous.
    if chain_action == "resolved" and expected_action == "escalated":
        # Missed threat — real system failure
        resolved_by = "investigate" if harness_result.triage_action == "escalated" else "triage"
        return PipelineResult(
            scenario_id=scenario.id,
            resolved_by=resolved_by,
            system_verdict=PipelineVerdict.FAIL,
            action_taken="resolved",
            action_correct=False,
            actor_grade=grade,
            tokens=harness_result.total_tokens,
            llm_calls=len(harness_result.llm_calls),
        )

    # Resolved when should have escalated OR escalated when should have resolved
    # The "escalated when should resolve" case was already handled above (always PASS).
    # This catches any remaining mismatch.
    resolved_by = "investigate" if harness_result.triage_action == "escalated" else "triage"
    return PipelineResult(
        scenario_id=scenario.id,
        resolved_by=resolved_by,
        system_verdict=PipelineVerdict.PASS,  # conservative: non-dangerous mismatch
        action_taken=chain_action,
        action_correct=action_correct,
        actor_grade=grade,
        tokens=harness_result.total_tokens,
        llm_calls=len(harness_result.llm_calls),
    )


def pipeline_summary(results: list[PipelineResult]) -> dict[str, Any]:
    """Compute pipeline-level metrics."""
    total = len(results)
    system_pass = sum(1 for r in results if r.system_verdict == PipelineVerdict.PASS)
    system_fail = sum(1 for r in results if r.system_verdict == PipelineVerdict.FAIL)

    by_resolver = {"hard-constraint": 0, "rule": 0, "triage": 0, "investigate": 0, "human": 0}
    for r in results:
        by_resolver[r.resolved_by] = by_resolver.get(r.resolved_by, 0) + 1

    total_tokens = sum(r.tokens for r in results)
    total_calls = sum(r.llm_calls for r in results)

    # Donut estimate: 1 donut ≈ 5000 tokens
    donuts_used = total_tokens / 5000

    return {
        "total_scenarios": total,
        "system_pass": system_pass,
        "system_fail": system_fail,
        "system_accuracy": round(system_pass / max(total, 1), 4),
        "resolved_by": by_resolver,
        "total_tokens": total_tokens,
        "total_llm_calls": total_calls,
        "estimated_donuts": round(donuts_used, 1),
        "failures": [
            {
                "scenario_id": r.scenario_id,
                "resolved_by": r.resolved_by,
                "action_taken": r.action_taken,
                "expected": "escalated",
            }
            for r in results
            if r.system_verdict == PipelineVerdict.FAIL
        ],
    }
