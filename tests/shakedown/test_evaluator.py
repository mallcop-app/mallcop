"""Tests for ShakedownEvaluator structured grading."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from tests.shakedown.evaluator import (
    FixTarget,
    Grade,
    ShakedownEvaluator,
    Verdict,
)
from tests.shakedown.scenario import ExpectedOutcome, Scenario
from mallcop.schemas import Baseline, Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# Mock types for duck-typed result objects
# ---------------------------------------------------------------------------


@dataclass
class MockCapturedCall:
    actor: str
    model: str = "haiku"
    message_count: int = 5
    tool_calls: list[str] = field(default_factory=list)
    has_resolution: bool = True
    tokens_used: int = 100


@dataclass
class MockResult:
    scenario_id: str = "TEST-001"
    chain_action: str = "escalated"
    triage_action: str = "escalated"
    chain_reason: str = "Suspicious activity detected"
    investigate_tool_calls: list[str] = field(default_factory=list)
    total_tokens: int = 200
    llm_calls: list[MockCapturedCall] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**overrides) -> Finding:
    defaults = dict(
        id="f-001",
        timestamp="2026-01-01T00:00:00Z",
        detector="new-actor",
        event_ids=["e-001"],
        title="Test finding",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )
    defaults.update(overrides)
    from datetime import datetime
    if isinstance(defaults["timestamp"], str):
        defaults["timestamp"] = datetime.fromisoformat(defaults["timestamp"])
    return Finding(**defaults)


def _make_scenario(
    *,
    scenario_id: str = "TEST-001",
    detector: str = "volume-anomaly",
    failure_mode: str = "AE",
    chain_action: str = "escalated",
    triage_action: str = "escalated",
    reasoning_must_mention: list[str] | None = None,
    reasoning_must_not_mention: list[str] | None = None,
    investigate_must_use_tools: bool = False,
    min_investigate_iterations: int = 1,
) -> Scenario:
    return Scenario(
        id=scenario_id,
        failure_mode=failure_mode,
        detector=detector,
        category="identity",
        difficulty="benign-obvious",
        trap_description="Test trap",
        trap_resolved_means="Test resolution",
        finding=_make_finding(detector=detector),
        events=[],
        baseline=Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
        ),
        expected=ExpectedOutcome(
            chain_action=chain_action,
            triage_action=triage_action,
            reasoning_must_mention=reasoning_must_mention or [],
            reasoning_must_not_mention=reasoning_must_not_mention or [],
            investigate_must_use_tools=investigate_must_use_tools,
            min_investigate_iterations=min_investigate_iterations,
        ),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestShakedownEvaluator:
    """Test suite for ShakedownEvaluator.evaluate()."""

    def setup_method(self):
        self.evaluator = ShakedownEvaluator()

    def test_pass_verdict(self):
        """Result matches expected -> Grade.verdict == PASS, no fix_target."""
        scenario = _make_scenario(
            chain_action="escalated",
            triage_action="escalated",
        )
        result = MockResult(
            chain_action="escalated",
            triage_action="escalated",
            chain_reason="Suspicious volume anomaly detected",
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.PASS
        assert grade.fix_target is None
        assert grade.fix_hint is None
        assert not grade.wrong_action
        assert not grade.wrong_triage
        assert grade.missing_reasoning == []
        assert grade.forbidden_reasoning == []
        assert grade.tool_gaps == []
        assert grade.notes == []

    def test_fail_wrong_chain_action(self):
        """chain_action mismatch -> FAIL."""
        scenario = _make_scenario(chain_action="escalated")
        result = MockResult(
            chain_action="resolved",
            triage_action="escalated",
            chain_reason="Resolved as benign",
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.FAIL
        assert grade.wrong_action is True
        assert "Wrong chain action" in grade.notes[0]

    def test_fail_wrong_triage_action(self):
        """triage_action mismatch -> FAIL."""
        scenario = _make_scenario(triage_action="escalated")
        result = MockResult(
            chain_action="escalated",
            triage_action="resolved",
            chain_reason="Triage resolved it",
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.FAIL
        assert grade.wrong_triage is True
        assert "Wrong triage action" in grade.notes[0]

    def test_warn_missing_reasoning(self):
        """Missing required keyword -> WARN + missing_reasoning list."""
        scenario = _make_scenario(
            reasoning_must_mention=["anomaly", "baseline"],
        )
        result = MockResult(
            chain_action="escalated",
            triage_action="escalated",
            chain_reason="Something unusual happened",
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.WARN
        assert "anomaly" in grade.missing_reasoning
        assert "baseline" in grade.missing_reasoning
        assert len(grade.notes) == 2

    def test_warn_forbidden_reasoning(self):
        """Forbidden keyword found -> WARN."""
        scenario = _make_scenario(
            reasoning_must_not_mention=["benign"],
        )
        result = MockResult(
            chain_action="escalated",
            triage_action="escalated",
            chain_reason="This looks benign but escalating anyway",
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.WARN
        assert "benign" in grade.forbidden_reasoning
        assert "Forbidden reasoning keyword found: 'benign'" in grade.notes

    def test_warn_no_investigation_tools(self):
        """investigate_must_use_tools=True but no tools used -> WARN."""
        scenario = _make_scenario(investigate_must_use_tools=True)
        result = MockResult(
            chain_action="escalated",
            triage_action="escalated",
            chain_reason="Escalated without investigation",
            investigate_tool_calls=[],
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.WARN
        assert "any-investigation-tool" in grade.tool_gaps
        assert "Investigate did not use any investigation tools" in grade.notes

    def test_warn_no_investigation_tools_excludes_resolution_tools(self):
        """resolve-finding and annotate-finding don't count as investigation tools."""
        scenario = _make_scenario(investigate_must_use_tools=True)
        result = MockResult(
            chain_action="escalated",
            triage_action="escalated",
            chain_reason="Investigated",
            investigate_tool_calls=["resolve-finding", "annotate-finding"],
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.WARN
        assert "any-investigation-tool" in grade.tool_gaps

    def test_classify_fix_triage_prompt(self):
        """Wrong triage on non-resolvable detector -> TRIAGE_PROMPT."""
        scenario = _make_scenario(
            detector="volume-anomaly",
            triage_action="escalated",
        )
        result = MockResult(
            chain_action="escalated",
            triage_action="resolved",
            chain_reason="Triage resolved it",
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.fix_target == FixTarget.TRIAGE_PROMPT
        assert "volume-anomaly" in grade.fix_hint

    def test_classify_fix_runtime_policy(self):
        """Wrong triage on resolvable detector -> RUNTIME_POLICY."""
        scenario = _make_scenario(
            detector="new-actor",
            triage_action="escalated",
        )
        result = MockResult(
            chain_action="escalated",
            triage_action="resolved",
            chain_reason="Triage resolved new actor",
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.fix_target == FixTarget.RUNTIME_POLICY
        assert "new-actor" in grade.fix_hint

    def test_classify_fix_investigate_prompt(self):
        """Wrong chain action (investigate wrong) -> INVESTIGATE_PROMPT."""
        scenario = _make_scenario(
            chain_action="escalated",
            triage_action="escalated",
        )
        result = MockResult(
            chain_action="resolved",
            triage_action="escalated",
            chain_reason="Investigate resolved it",
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.fix_target == FixTarget.INVESTIGATE_PROMPT
        assert "escalated" in grade.fix_hint

    def test_fail_takes_priority_over_warn(self):
        """Both wrong action and missing reasoning -> verdict is FAIL not WARN."""
        scenario = _make_scenario(
            chain_action="escalated",
            reasoning_must_mention=["anomaly"],
        )
        result = MockResult(
            chain_action="resolved",
            triage_action="escalated",
            chain_reason="Nothing to see here",
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.FAIL
        assert grade.wrong_action is True
        assert "anomaly" in grade.missing_reasoning
        # Notes should contain both the action failure and the reasoning gap
        action_notes = [n for n in grade.notes if "Wrong chain action" in n]
        reason_notes = [n for n in grade.notes if "Missing reasoning" in n]
        assert len(action_notes) == 1
        assert len(reason_notes) == 1

    def test_min_investigate_iterations_warn(self):
        """Fewer investigate iterations than expected -> WARN."""
        scenario = _make_scenario(min_investigate_iterations=3)
        result = MockResult(
            chain_action="escalated",
            triage_action="escalated",
            chain_reason="Investigated briefly",
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.WARN
        assert "Investigate iterations: 1 < expected 3" in grade.notes

    def test_grade_has_scenario_metadata(self):
        """Grade captures scenario_id, failure_modes, and tokens."""
        scenario = _make_scenario(
            scenario_id="SC-042",
            failure_mode="KA",
        )
        result = MockResult(
            scenario_id="SC-042",
            chain_action="escalated",
            triage_action="escalated",
            chain_reason="All good",
            total_tokens=500,
            llm_calls=[MockCapturedCall(actor="investigate")],
        )

        grade = self.evaluator.evaluate(result, scenario)

        assert grade.scenario_id == "SC-042"
        assert grade.failure_modes == ["KA"]
        assert grade.tokens == 500
