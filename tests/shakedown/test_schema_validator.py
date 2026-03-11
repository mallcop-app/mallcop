"""Tests for the schema validator."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.shakedown.schema_validator import (
    SchemaError,
    validate_all_scenarios,
    validate_scenario_file,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestValidateScenarioFile:
    """Tests for validate_scenario_file."""

    def test_valid_scenario_no_errors(self):
        """test_scenario.yaml from fixtures produces no errors."""
        path = FIXTURES_DIR / "test_scenario.yaml"
        errors = validate_scenario_file(path)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_missing_required_field(self, tmp_path):
        """YAML missing 'detector' produces a SchemaError."""
        data = _minimal_scenario()
        del data["detector"]
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.dump(data))

        errors = validate_scenario_file(path)
        assert any("Missing required field: detector" in e.message for e in errors)

    def test_missing_finding_field(self, tmp_path):
        """Finding missing 'title' produces a SchemaError."""
        data = _minimal_scenario()
        del data["finding"]["title"]
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.dump(data))

        errors = validate_scenario_file(path)
        assert any("Missing finding.title" in e.message for e in errors)

    def test_missing_expected_field(self, tmp_path):
        """Expected missing 'chain_action' produces a SchemaError."""
        data = _minimal_scenario()
        del data["expected"]["chain_action"]
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.dump(data))

        errors = validate_scenario_file(path)
        assert any("Missing expected.chain_action" in e.message for e in errors)

    def test_event_id_cross_reference(self, tmp_path):
        """Finding references non-existent event produces a SchemaError."""
        data = _minimal_scenario()
        data["finding"]["event_ids"] = ["evt_001", "evt_nonexistent"]
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.dump(data))

        errors = validate_scenario_file(path)
        assert any(
            "Finding references non-existent event: evt_nonexistent" in e.message
            for e in errors
        )

    def test_invalid_yaml(self, tmp_path):
        """Corrupt YAML produces a SchemaError."""
        path = tmp_path / "corrupt.yaml"
        path.write_text("{{{{not yaml at all::::")

        errors = validate_scenario_file(path)
        assert len(errors) == 1
        assert "Invalid YAML" in errors[0].message

    def test_missing_event_field(self, tmp_path):
        """Event missing 'action' produces a SchemaError."""
        data = _minimal_scenario()
        del data["events"][0]["action"]
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.dump(data))

        errors = validate_scenario_file(path)
        assert any("Missing events[0].action" in e.message for e in errors)


class TestValidateAllScenarios:
    """Tests for validate_all_scenarios."""

    def test_validate_all_scenarios_valid_dir(self):
        """Fixtures dir with valid file produces no errors."""
        results = validate_all_scenarios(FIXTURES_DIR)
        assert results == {}, f"Unexpected errors: {results}"

    def test_validate_all_scenarios_empty_dir(self, tmp_path):
        """Empty directory produces no errors."""
        results = validate_all_scenarios(tmp_path)
        assert results == {}

    def test_validate_all_scenarios_skips_underscore(self, tmp_path):
        """Files starting with _ are skipped."""
        (tmp_path / "_schema.yaml").write_text("not a scenario")
        results = validate_all_scenarios(tmp_path)
        assert results == {}

    def test_validate_all_scenarios_with_errors(self, tmp_path):
        """Directory with invalid file returns errors keyed by path."""
        bad_data = {"id": "test", "finding": {}}
        (tmp_path / "bad.yaml").write_text(yaml.dump(bad_data))
        results = validate_all_scenarios(tmp_path)
        assert len(results) == 1
        path_key = list(results.keys())[0]
        assert "bad.yaml" in path_key
        assert len(results[path_key]) > 0


def _minimal_scenario() -> dict:
    """Return a minimal valid scenario dict for mutation tests."""
    return {
        "id": "TEST-001-basic",
        "failure_mode": "known-actor-trust",
        "detector": "unusual-timing",
        "category": "behavioral",
        "difficulty": "malicious-hard",
        "finding": {
            "id": "fnd_test_001",
            "title": "Test finding",
            "severity": "warn",
            "event_ids": ["evt_001"],
        },
        "events": [
            {
                "id": "evt_001",
                "timestamp": "2026-03-10T03:14:00Z",
                "ingested_at": "2026-03-10T03:15:00Z",
                "source": "azure",
                "event_type": "role_assignment",
                "actor": "admin-user",
                "action": "add_role_assignment",
                "target": "sub-169efd95/resourceGroups/atom-rg",
                "severity": "warn",
            }
        ],
        "baseline": {
            "known_entities": {"actors": ["admin-user"], "sources": ["azure"]},
            "frequency_tables": {},
            "relationships": {},
        },
        "expected": {
            "chain_action": "escalated",
            "triage_action": "escalated",
        },
    }
