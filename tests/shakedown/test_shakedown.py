"""Parametrized shakedown tests — one test per scenario YAML file."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.shakedown.evaluator import ShakedownEvaluator, Verdict
from tests.shakedown.harness import ShakedownHarness
from tests.shakedown.scenario import load_all_scenarios

SCENARIOS_DIR = Path(__file__).parent / "scenarios"


def _get_scenario_ids():
    """Collect scenario IDs for parametrization."""
    if not SCENARIOS_DIR.exists():
        return []
    scenarios = load_all_scenarios(SCENARIOS_DIR)
    return [s.id for s in scenarios]


def _get_scenarios_map():
    """Load scenarios keyed by ID."""
    if not SCENARIOS_DIR.exists():
        return {}
    scenarios = load_all_scenarios(SCENARIOS_DIR)
    return {s.id: s for s in scenarios}


@pytest.mark.shakedown
class TestShakedownScenarios:
    """Parametrized scenario tests — each scenario YAML becomes a test case."""

    @pytest.fixture(autouse=True)
    def _skip_if_no_scenarios(self):
        if not SCENARIOS_DIR.exists() or not list(SCENARIOS_DIR.rglob("*.yaml")):
            pytest.skip("No scenario files found")

    @pytest.fixture
    def evaluator(self):
        return ShakedownEvaluator()

    @pytest.mark.parametrize("scenario_id", _get_scenario_ids())
    def test_scenario(self, shakedown_harness, evaluator, scenario_id):
        """Run a single scenario and verify it doesn't FAIL."""
        scenarios = _get_scenarios_map()
        scenario = scenarios[scenario_id]
        result = shakedown_harness.run_scenario(scenario)
        grade = evaluator.evaluate(result, scenario)
        assert grade.verdict != Verdict.FAIL, (
            f"Scenario {scenario_id} FAILED:\n"
            + "\n".join(grade.notes)
        )

    @pytest.mark.parametrize("scenario_id", _get_scenario_ids())
    def test_scenario_stability(self, shakedown_harness, evaluator, scenario_id):
        """Run the same scenario 3 times — action should be consistent (X1)."""
        scenarios = _get_scenarios_map()
        scenario = scenarios[scenario_id]
        actions = []
        for _ in range(3):
            result = shakedown_harness.run_scenario(scenario)
            actions.append(result.chain_action)
        assert len(set(actions)) == 1, (
            f"Inconsistent results for {scenario_id}: {actions}"
        )
