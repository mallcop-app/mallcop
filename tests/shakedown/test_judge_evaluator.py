"""Tests for new JudgeEvaluator verdict logic (investigation quality over action correctness)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from unittest.mock import MagicMock

import pytest

from tests.shakedown.evaluator import (
    FixTarget,
    Grade,
    JudgeEvaluator,
    Verdict,
)
from tests.shakedown.scenario import ExpectedOutcome, Scenario
from mallcop.llm_types import LLMResponse
from mallcop.schemas import Baseline, Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_llm_response(
    reasoning_quality: int = 3,
    investigation_thoroughness: int = 3,
    resolve_quality: int = 3,
    escalation_actionability: int = 3,
    fix_target: str | None = None,
    fix_hint: str | None = None,
) -> MagicMock:
    """Build a mock LLM response that returns valid judge JSON."""
    payload = {
        "reasoning_quality": reasoning_quality,
        "investigation_thoroughness": investigation_thoroughness,
        "resolve_quality": resolve_quality,
        "escalation_actionability": escalation_actionability,
        "reasoning": "Test reasoning from judge",
        "fix_target": fix_target,
        "fix_hint": fix_hint,
    }
    mock = MagicMock(spec=["text", "tokens_used"])
    mock.text = json.dumps(payload)
    mock.tokens_used = 50
    return mock


@dataclass
class MockCapturedCall:
    actor: str
    model: str = "haiku"
    messages_sent: list = field(default_factory=list)
    response_text: str = ""
    tool_calls_detail: list = field(default_factory=list)
    tokens_used: int = 100


@dataclass
class MockResult:
    scenario_id: str = "TEST-001"
    chain_action: str = "escalated"
    triage_action: str = "escalated"
    chain_reason: str = "Suspicious activity detected"
    investigate_tool_calls: list = field(default_factory=list)
    total_tokens: int = 200
    llm_calls: list = field(default_factory=list)


def _make_finding() -> Finding:
    from datetime import datetime
    return Finding(
        id="fnd_001",
        timestamp=datetime.fromisoformat("2024-01-01T00:00:00"),
        detector="unusual-timing",
        event_ids=["evt_001"],
        title="Unusual timing",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_scenario(
    chain_action: str = "escalated",
    triage_action: str = "escalated",
    detector: str = "unusual-timing",
    scenario_id: str = "TEST-001",
) -> Scenario:
    return Scenario(
        id=scenario_id,
        failure_mode="AE",
        detector=detector,
        category="behavioral",
        difficulty="benign-obvious",
        trap_description="Test trap",
        trap_resolved_means="Test resolution",
        finding=_make_finding(),
        events=[],
        baseline=Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
        ),
        expected=ExpectedOutcome(
            chain_action=chain_action,
            triage_action=triage_action,
            reasoning_must_mention=[],
            reasoning_must_not_mention=[],
            investigate_must_use_tools=False,
            min_investigate_iterations=1,
        ),
        ground_truth=None,
    )


def _make_judge_evaluator(llm_response: MagicMock) -> JudgeEvaluator:
    mock_llm = MagicMock()
    mock_llm.chat.return_value = llm_response
    return JudgeEvaluator(judge_llm=mock_llm)


# ---------------------------------------------------------------------------
# New verdict logic tests
# ---------------------------------------------------------------------------

class TestNewVerdictLogic:
    def test_high_investigation_wrong_action_is_pass(self):
        """High-quality investigation that reaches different conclusion = PASS, not FAIL.

        This is the ID-02 case: agent did excellent work, reached different conclusion.
        """
        scenario = _make_scenario(chain_action="escalated")  # expected: escalate
        result = MockResult(
            chain_action="resolved",  # agent resolved (different from expected)
            triage_action="escalated",
            chain_reason="Thorough investigation concludes normal activity",
        )
        judge_response = _make_llm_response(
            reasoning_quality=4,
            investigation_thoroughness=4,
            resolve_quality=4,
            escalation_actionability=1,
        )
        evaluator = _make_judge_evaluator(judge_response)
        grade = evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.PASS
        # action_correct is tracked (for calibration) but does NOT gate verdict
        assert grade.action_correct is False

    def test_low_investigation_correct_action_is_fail(self):
        """Agent guessed the right action but did no work = FAIL (lazy)."""
        scenario = _make_scenario(chain_action="escalated")
        result = MockResult(
            chain_action="escalated",  # correct action
            triage_action="escalated",
        )
        judge_response = _make_llm_response(
            reasoning_quality=2,
            investigation_thoroughness=1,  # < 3 = FAIL
            resolve_quality=1,
            escalation_actionability=1,
        )
        evaluator = _make_judge_evaluator(judge_response)
        grade = evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.FAIL

    def test_right_action_low_reasoning_is_warn(self):
        """Correct action but shallow reasoning = WARN (lucky guess)."""
        scenario = _make_scenario(chain_action="escalated")
        result = MockResult(chain_action="escalated", triage_action="escalated")
        judge_response = _make_llm_response(
            reasoning_quality=2,  # low
            investigation_thoroughness=4,  # high
            resolve_quality=1,
            escalation_actionability=4,
        )
        evaluator = _make_judge_evaluator(judge_response)
        grade = evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.WARN

    def test_adequate_investigation_and_reasoning_is_pass(self):
        """investigation >= 3 AND reasoning >= 3 AND quality >= 3 = PASS."""
        scenario = _make_scenario(chain_action="escalated")
        result = MockResult(chain_action="escalated", triage_action="escalated")
        judge_response = _make_llm_response(
            reasoning_quality=3,
            investigation_thoroughness=3,
            resolve_quality=1,
            escalation_actionability=3,
        )
        evaluator = _make_judge_evaluator(judge_response)
        grade = evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.PASS

    def test_high_resolve_quality_passes_wrong_action(self):
        """High resolve_quality with adequate investigation = PASS even if action differs."""
        scenario = _make_scenario(chain_action="escalated")
        result = MockResult(
            chain_action="resolved",  # different from expected
            triage_action="escalated",
        )
        judge_response = _make_llm_response(
            reasoning_quality=4,
            investigation_thoroughness=4,
            resolve_quality=4,  # high resolve quality
            escalation_actionability=1,
        )
        evaluator = _make_judge_evaluator(judge_response)
        grade = evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.PASS

    def test_action_correct_tracked_as_calibration_metric(self):
        """action_correct is tracked in grade even when not the verdict gate."""
        scenario = _make_scenario(chain_action="escalated")
        result = MockResult(chain_action="resolved", triage_action="escalated")
        judge_response = _make_llm_response(
            reasoning_quality=4,
            investigation_thoroughness=4,
            resolve_quality=4,
            escalation_actionability=1,
        )
        evaluator = _make_judge_evaluator(judge_response)
        grade = evaluator.evaluate(result, scenario)

        # Grade tracks action_correct for calibration
        assert hasattr(grade, "action_correct")
        assert grade.action_correct is False  # different from expected

    def test_very_low_reasoning_quality_is_fail(self):
        """reasoning_quality < 2 = FAIL regardless of other scores."""
        scenario = _make_scenario()
        result = MockResult(chain_action="escalated", triage_action="escalated")
        judge_response = _make_llm_response(
            reasoning_quality=1,  # < 2 = FAIL
            investigation_thoroughness=5,
            resolve_quality=5,
            escalation_actionability=5,
        )
        evaluator = _make_judge_evaluator(judge_response)
        grade = evaluator.evaluate(result, scenario)

        assert grade.verdict == Verdict.FAIL


# ---------------------------------------------------------------------------
# Grade has new fields
# ---------------------------------------------------------------------------

class TestGradeFields:
    def test_grade_has_resolve_quality(self):
        scenario = _make_scenario()
        result = MockResult(chain_action="escalated", triage_action="escalated")
        judge_response = _make_llm_response(resolve_quality=4)
        evaluator = _make_judge_evaluator(judge_response)
        grade = evaluator.evaluate(result, scenario)

        assert hasattr(grade, "resolve_quality")
        assert grade.resolve_quality == 4

    def test_grade_has_escalation_actionability(self):
        scenario = _make_scenario()
        result = MockResult(chain_action="escalated", triage_action="escalated")
        judge_response = _make_llm_response(escalation_actionability=3)
        evaluator = _make_judge_evaluator(judge_response)
        grade = evaluator.evaluate(result, scenario)

        assert hasattr(grade, "escalation_actionability")
        assert grade.escalation_actionability == 3

    def test_grade_action_correct_present(self):
        scenario = _make_scenario(chain_action="escalated")
        result = MockResult(chain_action="escalated", triage_action="escalated")
        judge_response = _make_llm_response()
        evaluator = _make_judge_evaluator(judge_response)
        grade = evaluator.evaluate(result, scenario)

        assert hasattr(grade, "action_correct")
        assert grade.action_correct is True


# ---------------------------------------------------------------------------
# Judge prompt includes new metrics
# ---------------------------------------------------------------------------

class TestJudgePromptContent:
    def test_judge_prompt_mentions_resolve_quality(self):
        """Judge prompt must ask for resolve_quality field."""
        from tests.shakedown.evaluator import _build_judge_prompt
        scenario = _make_scenario()
        result = MockResult(llm_calls=[])
        prompt = _build_judge_prompt(result, scenario)
        assert "resolve_quality" in prompt

    def test_judge_prompt_mentions_escalation_actionability(self):
        """Judge prompt must ask for escalation_actionability field."""
        from tests.shakedown.evaluator import _build_judge_prompt
        scenario = _make_scenario()
        result = MockResult(llm_calls=[])
        prompt = _build_judge_prompt(result, scenario)
        assert "escalation_actionability" in prompt

    def test_judge_prompt_has_30_second_guidance(self):
        """Resolve quality guidance mentions 30 seconds."""
        from tests.shakedown.evaluator import _build_judge_prompt
        scenario = _make_scenario()
        result = MockResult(llm_calls=[])
        prompt = _build_judge_prompt(result, scenario)
        assert "30 second" in prompt.lower() or "30-second" in prompt.lower()

    def test_judge_prompt_has_1_minute_guidance(self):
        """Escalation actionability guidance mentions 1 minute."""
        from tests.shakedown.evaluator import _build_judge_prompt
        scenario = _make_scenario()
        result = MockResult(llm_calls=[])
        prompt = _build_judge_prompt(result, scenario)
        assert "1 minute" in prompt.lower() or "one minute" in prompt.lower()

    def test_judge_prompt_json_schema_includes_new_fields(self):
        """JSON output schema in prompt includes resolve_quality and escalation_actionability."""
        from tests.shakedown.evaluator import _build_judge_prompt
        scenario = _make_scenario()
        result = MockResult(llm_calls=[])
        prompt = _build_judge_prompt(result, scenario)
        assert '"resolve_quality"' in prompt
        assert '"escalation_actionability"' in prompt
