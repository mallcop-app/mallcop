"""Tests for the pipeline exam — offline, no LLM calls."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mallcop.feedback import FeedbackRecord, HumanAction
from mallcop.schemas import Finding, FindingStatus, Severity

from tests.shakedown.pipeline import (
    PipelineResult,
    PipelineVerdict,
    build_feedback_history,
    pipeline_summary,
)
from tests.shakedown.scenario import ExpectedOutcome, Scenario


def _make_scenario(
    scenario_id: str = "TEST-01",
    detector: str = "new-external-access",
    expected_action: str = "escalated",
    actor: str = "admin-user",
    event_type: str = "add_collaborator",
    target: str = "acme-corp/repo",
) -> Scenario:
    from mallcop.schemas import Baseline, Event

    finding = Finding(
        id=f"fnd_{scenario_id}",
        timestamp=datetime.now(timezone.utc),
        detector=detector,
        event_ids=["evt_001"],
        title="Test finding",
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": actor, "event_type": event_type, "target": target},
    )
    events = [Event(
        id="evt_001",
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        source="github",
        event_type=event_type,
        actor=actor,
        action=event_type,
        target=target,
        severity=Severity.CRITICAL,
        metadata={},
        raw={},
    )]

    return Scenario(
        id=scenario_id,
        failure_mode="test",
        detector=detector,
        category="test",
        difficulty="test",
        trap_description="",
        trap_resolved_means="",
        finding=finding,
        events=events,
        baseline=Baseline(frequency_tables={}, known_entities={}, relationships={}),
        expected=ExpectedOutcome(chain_action=expected_action, triage_action=expected_action),
    )


class TestBuildFeedbackHistory:
    def test_generates_feedback_for_resolved_scenarios(self) -> None:
        scenarios = [
            _make_scenario("S1", expected_action="resolved"),
            _make_scenario("S2", expected_action="escalated"),
        ]
        history = build_feedback_history(scenarios, n_per_pattern=5)
        # Only S1 generates feedback (expected=resolved)
        assert len(history) == 5
        assert all(r.human_action == HumanAction.AGREE for r in history)

    def test_deduplicates_patterns(self) -> None:
        # Same detector+actor+event_type should only generate once
        scenarios = [
            _make_scenario("S1", expected_action="resolved"),
            _make_scenario("S2", expected_action="resolved"),  # same pattern
        ]
        history = build_feedback_history(scenarios, n_per_pattern=5)
        assert len(history) == 5  # not 10


class TestPipelineSummary:
    def test_summary_counts(self) -> None:
        results = [
            PipelineResult("S1", "rule", PipelineVerdict.PASS, "resolved", True),
            PipelineResult("S2", "triage", PipelineVerdict.PASS, "resolved", True, tokens=5000, llm_calls=2),
            PipelineResult("S3", "human", PipelineVerdict.PASS, "escalated", True, tokens=3000, llm_calls=1),
            PipelineResult("S4", "triage", PipelineVerdict.FAIL, "resolved", False, tokens=4000, llm_calls=2),
        ]
        s = pipeline_summary(results)
        assert s["system_pass"] == 3
        assert s["system_fail"] == 1
        assert s["system_accuracy"] == 0.75
        assert s["resolved_by"]["rule"] == 1
        assert s["resolved_by"]["triage"] == 2
        assert s["resolved_by"]["human"] == 1
        assert s["total_tokens"] == 12000
        assert len(s["failures"]) == 1
        assert s["failures"][0]["scenario_id"] == "S4"

    def test_all_pass(self) -> None:
        results = [
            PipelineResult("S1", "rule", PipelineVerdict.PASS, "resolved", True),
            PipelineResult("S2", "human", PipelineVerdict.PASS, "escalated", True),
        ]
        s = pipeline_summary(results)
        assert s["system_accuracy"] == 1.0
        assert s["failures"] == []


class TestPipelineScoring:
    def test_escalation_is_always_pass(self) -> None:
        """Escalating to human is always a system pass, even if the expected
        action was 'resolved'. False escalation wastes donuts but doesn't miss threats."""
        r = PipelineResult("S1", "human", PipelineVerdict.PASS, "escalated", False)
        assert r.system_verdict == PipelineVerdict.PASS

    def test_missed_threat_is_fail(self) -> None:
        """Resolving a finding that should have been escalated is a system failure."""
        r = PipelineResult("S1", "triage", PipelineVerdict.FAIL, "resolved", False)
        assert r.system_verdict == PipelineVerdict.FAIL
