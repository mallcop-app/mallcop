"""Tests for shakedown scenario dataclass and YAML loader."""

from pathlib import Path

from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

from tests.shakedown.scenario import (
    ConnectorToolDef,
    ExpectedOutcome,
    Scenario,
    load_all_scenarios,
    load_scenario,
    load_scenarios_tagged,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
FIXTURE_FILE = FIXTURES_DIR / "test_scenario.yaml"


class TestLoadScenario:
    """Tests for load_scenario."""

    def test_load_scenario(self):
        """Load fixture and verify all typed fields."""
        s = load_scenario(FIXTURE_FILE)

        assert isinstance(s, Scenario)
        assert s.id == "TEST-001-basic"
        assert s.failure_mode == "known-actor-trust"
        assert s.detector == "unusual-timing"
        assert s.category == "behavioral"
        assert s.difficulty == "malicious-hard"
        assert s.trap_description == "Test trap"
        assert s.trap_resolved_means == "Test resolved means"

        # Expected outcome
        assert isinstance(s.expected, ExpectedOutcome)
        assert s.expected.chain_action == "escalated"
        assert s.expected.triage_action == "escalated"
        assert s.expected.reasoning_must_mention == ["role_assignment"]
        assert s.expected.reasoning_must_not_mention == []
        assert s.expected.investigate_must_use_tools is True
        assert s.expected.min_investigate_iterations == 1

        # Defaults
        assert s.connector_tools == []
        assert s.tags == []

    def test_scenario_finding_type(self):
        """Verify finding is a Finding instance with correct fields."""
        s = load_scenario(FIXTURE_FILE)

        assert isinstance(s.finding, Finding)
        assert s.finding.id == "fnd_test_001"
        assert s.finding.detector == "unusual-timing"
        assert s.finding.title == "Test finding"
        assert s.finding.severity == Severity.WARN
        assert s.finding.status == FindingStatus.OPEN
        assert s.finding.event_ids == ["evt_001"]
        assert s.finding.metadata == {"actor": "admin-user", "source": "azure"}
        assert s.finding.annotations == []

    def test_scenario_events_type(self):
        """Verify events are Event instances with correct fields."""
        s = load_scenario(FIXTURE_FILE)

        assert len(s.events) == 1
        evt = s.events[0]
        assert isinstance(evt, Event)
        assert evt.id == "evt_001"
        assert evt.source == "azure"
        assert evt.event_type == "role_assignment"
        assert evt.actor == "admin-user"
        assert evt.action == "add_role_assignment"
        assert evt.target == "sub-169efd95/resourceGroups/atom-rg"
        assert evt.severity == Severity.WARN
        assert evt.metadata == {"ip": "203.0.113.10"}
        assert evt.raw == {}

    def test_scenario_baseline_type(self):
        """Verify baseline is a Baseline instance with correct fields."""
        s = load_scenario(FIXTURE_FILE)

        assert isinstance(s.baseline, Baseline)
        assert s.baseline.known_entities == {
            "actors": ["admin-user", "ci-bot"],
            "sources": ["azure"],
        }
        assert s.baseline.frequency_tables == {"azure:login:admin-user": 340}
        assert "admin-user:sub-169efd95/resourceGroups/atom-rg" in s.baseline.relationships


class TestLoadAllScenarios:
    """Tests for load_all_scenarios."""

    def test_load_all_scenarios(self):
        """Load from fixtures dir, get correct count."""
        scenarios = load_all_scenarios(FIXTURES_DIR)
        assert len(scenarios) == 1
        assert scenarios[0].id == "TEST-001-basic"

    def test_skips_underscore_prefixed(self, tmp_path):
        """Files starting with _ are skipped."""
        # Write a valid scenario
        (tmp_path / "good.yaml").write_text(FIXTURE_FILE.read_text())
        # Write an underscore-prefixed file (should be skipped)
        (tmp_path / "_skip.yaml").write_text(FIXTURE_FILE.read_text())

        scenarios = load_all_scenarios(tmp_path)
        assert len(scenarios) == 1


class TestLoadScenariosTagged:
    """Tests for load_scenarios_tagged."""

    def test_filter_by_detector(self):
        """Filter by detector returns matching scenarios."""
        result = load_scenarios_tagged(FIXTURES_DIR, detector="unusual-timing")
        assert len(result) == 1
        assert result[0].detector == "unusual-timing"

    def test_filter_by_detector_no_match(self):
        """Filter by non-existent detector returns empty."""
        result = load_scenarios_tagged(FIXTURES_DIR, detector="nonexistent")
        assert len(result) == 0

    def test_filter_by_failure_mode(self):
        """Filter by failure_mode returns matching scenarios."""
        result = load_scenarios_tagged(FIXTURES_DIR, failure_mode="known-actor-trust")
        assert len(result) == 1

    def test_filter_by_category(self):
        """Filter by category."""
        result = load_scenarios_tagged(FIXTURES_DIR, category="behavioral")
        assert len(result) == 1

    def test_filter_by_difficulty(self):
        """Filter by difficulty."""
        result = load_scenarios_tagged(FIXTURES_DIR, difficulty="malicious-hard")
        assert len(result) == 1

    def test_combined_filters(self):
        """Multiple filters are ANDed together."""
        result = load_scenarios_tagged(
            FIXTURES_DIR,
            detector="unusual-timing",
            failure_mode="known-actor-trust",
        )
        assert len(result) == 1

        result = load_scenarios_tagged(
            FIXTURES_DIR,
            detector="unusual-timing",
            failure_mode="nonexistent",
        )
        assert len(result) == 0
