"""Tests for Grade/Verdict data types and FixTarget classification logic."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from tests.shakedown.evaluator import (
    FixTarget,
    Grade,
    Verdict,
)


# ---------------------------------------------------------------------------
# Grade dataclass tests
# ---------------------------------------------------------------------------

class TestGradeDataclass:
    def test_grade_fields_present(self):
        g = Grade(
            scenario_id="SC-001",
            verdict=Verdict.PASS,
            action_correct=True,
            reasoning_quality=4,
            investigation_thoroughness=4,
            resolve_quality=4,
            escalation_actionability=1,
            fix_target=None,
            fix_hint=None,
            judge_reasoning="Good work",
            tokens=500,
        )
        assert g.scenario_id == "SC-001"
        assert g.verdict == Verdict.PASS
        assert g.action_correct is True
        assert g.reasoning_quality == 4
        assert g.investigation_thoroughness == 4
        assert g.resolve_quality == 4
        assert g.escalation_actionability == 1
        assert g.tokens == 500

    def test_verdict_enum_values(self):
        assert Verdict.PASS.value == "pass"
        assert Verdict.FAIL.value == "fail"
        assert Verdict.WARN.value == "warn"

    def test_fix_target_enum_values(self):
        assert FixTarget.TRIAGE_PROMPT.value == "triage_prompt"
        assert FixTarget.INVESTIGATE_PROMPT.value == "investigate_prompt"
        assert FixTarget.DECLARATIVE_DETECTOR.value == "detectors/*.yaml"


# ---------------------------------------------------------------------------
# FixTarget mapping tests
# ---------------------------------------------------------------------------

class TestMapJudgeFixTarget:
    def test_maps_triage_prompt(self):
        from tests.shakedown.evaluator import _map_judge_fix_target
        assert _map_judge_fix_target("triage_prompt") == FixTarget.TRIAGE_PROMPT

    def test_maps_investigate_prompt(self):
        from tests.shakedown.evaluator import _map_judge_fix_target
        assert _map_judge_fix_target("investigate_prompt") == FixTarget.INVESTIGATE_PROMPT

    def test_maps_scenario_to_none(self):
        from tests.shakedown.evaluator import _map_judge_fix_target
        assert _map_judge_fix_target("scenario") is None

    def test_unknown_returns_none(self):
        from tests.shakedown.evaluator import _map_judge_fix_target
        assert _map_judge_fix_target("unknown_target") is None
