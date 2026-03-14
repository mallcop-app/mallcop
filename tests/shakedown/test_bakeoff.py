"""Tests for the bakeoff orchestrator — offline, no LLM calls."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.shakedown.bakeoff import (
    ModelResult,
    ModelSpec,
    _category_summary,
    _routing_recommendation,
    build_summary,
    load_models_from_pricing,
)
from tests.shakedown.evaluator import Grade, FixTarget, Verdict


@pytest.fixture
def pricing_yaml(tmp_path: Path) -> Path:
    data = {
        "models": {
            "cheap-flash": {
                "bedrock_id": "vendor.cheap-flash",
                "sovereignty": "open",
                "blended_per_mtok": 0.10,
                "cost_per_donut": 0.0005,
            },
            "mid-tier": {
                "bedrock_id": "vendor.mid-tier",
                "sovereignty": "allied",
                "blended_per_mtok": 0.50,
                "cost_per_donut": 0.0025,
            },
            "premium-claude": {
                "bedrock_id": "anthropic.claude-sonnet",
                "sovereignty": "us_only",
                "blended_per_mtok": 5.40,
                "cost_per_donut": 0.027,
                "auto_route": False,
            },
        },
    }
    p = tmp_path / "pricing.yaml"
    p.write_text(yaml.dump(data))
    return p


def test_load_models_excludes_non_auto_route(pricing_yaml: Path) -> None:
    models = load_models_from_pricing(pricing_yaml)
    aliases = {m.alias for m in models}
    assert "cheap-flash" in aliases
    assert "mid-tier" in aliases
    assert "premium-claude" not in aliases


def test_load_models_fields(pricing_yaml: Path) -> None:
    models = load_models_from_pricing(pricing_yaml)
    cheap = [m for m in models if m.alias == "cheap-flash"][0]
    assert cheap.bedrock_id == "vendor.cheap-flash"
    assert cheap.sovereignty == "open"
    assert cheap.blended_per_mtok == 0.10
    assert cheap.cost_per_donut == 0.0005


def _make_grade(
    scenario_id: str = "test-01",
    verdict: Verdict = Verdict.PASS,
    action_correct: bool = True,
    reasoning: int = 4,
    investigation: int = 4,
) -> Grade:
    return Grade(
        scenario_id=scenario_id,
        verdict=verdict,
        action_correct=action_correct,
        reasoning_quality=reasoning,
        investigation_thoroughness=investigation,
        resolve_quality=4,
        escalation_actionability=1,
        fix_target=None,
        fix_hint=None,
        judge_reasoning="test",
        tokens=1000,
    )


def test_category_summary() -> None:
    grades = [
        _make_grade(verdict=Verdict.PASS),
        _make_grade(verdict=Verdict.FAIL),
        _make_grade(verdict=Verdict.PASS),
        _make_grade(verdict=Verdict.WARN),
    ]
    categories = ["access", "access", "auth", "auth"]
    summary = _category_summary(grades, categories)
    assert summary["access"] == {"pass": 1, "warn": 0, "fail": 1, "total": 2}
    assert summary["auth"] == {"pass": 1, "warn": 1, "fail": 0, "total": 2}


def test_routing_recommendation_picks_cheapest_passing() -> None:
    spec_cheap = ModelSpec("cheap", "x", "open", 0.10, 0.0005)
    spec_mid = ModelSpec("mid", "y", "open", 0.50, 0.0025)

    # cheap: 60% pass (below patrol threshold of 70%)
    mr_cheap = ModelResult(model=spec_cheap)
    mr_cheap.grades = [_make_grade(verdict=Verdict.PASS)] * 6 + [_make_grade(verdict=Verdict.FAIL)] * 4

    # mid: 90% pass (above all thresholds)
    mr_mid = ModelResult(model=spec_mid)
    mr_mid.grades = [_make_grade(verdict=Verdict.PASS)] * 9 + [_make_grade(verdict=Verdict.FAIL)] * 1

    rec = _routing_recommendation([mr_cheap, mr_mid])
    # cheap doesn't meet patrol threshold (70%), mid does
    assert rec["patrol"]["open"] == "mid"
    assert rec["detective"]["open"] == "mid"


def test_routing_recommendation_sovereignty_filter() -> None:
    spec_open = ModelSpec("open-model", "x", "open", 0.10, 0.0005)
    spec_allied = ModelSpec("allied-model", "y", "allied", 0.50, 0.0025)

    mr_open = ModelResult(model=spec_open)
    mr_open.grades = [_make_grade(verdict=Verdict.PASS)] * 9 + [_make_grade(verdict=Verdict.FAIL)]

    mr_allied = ModelResult(model=spec_allied)
    mr_allied.grades = [_make_grade(verdict=Verdict.PASS)] * 9 + [_make_grade(verdict=Verdict.FAIL)]

    rec = _routing_recommendation([mr_open, mr_allied])
    # open tier: both eligible, cheapest wins
    assert rec["patrol"]["open"] == "open-model"
    # allied tier: only allied model eligible
    assert rec["patrol"]["allied"] == "allied-model"
    # us_only tier: neither eligible
    assert rec["patrol"]["us_only"] is None


def test_build_summary_structure() -> None:
    spec = ModelSpec("test-model", "vendor.test", "open", 0.50, 0.0025)
    mr = ModelResult(model=spec)
    mr.grades = [_make_grade(verdict=Verdict.PASS, scenario_id="SC-01")]
    mr.scenario_ids = ["SC-01"]
    mr.categories = ["access"]
    mr.total_tokens = 5000

    summary = build_summary([mr], scenarios_total=1)
    assert summary["bakeoff_version"] == 1
    assert summary["scenarios_total"] == 1
    assert "test-model" in summary["models"]
    m = summary["models"]["test-model"]
    assert m["pass"] == 1
    assert m["pass_rate"] == 1.0
    assert m["by_category"]["access"]["pass"] == 1
    assert "routing_recommendation" in summary


def test_build_summary_with_errors() -> None:
    spec = ModelSpec("broken-model", "vendor.broken", "open", 0.50, 0.0025)
    mr = ModelResult(model=spec)
    mr.errors = ["credential error: no creds"]

    summary = build_summary([mr], scenarios_total=10)
    m = summary["models"]["broken-model"]
    assert m["scenarios_run"] == 0
    assert "credential error" in m["errors"][0]
