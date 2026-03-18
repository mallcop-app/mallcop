"""Tests for the mallcop contribute command."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from click.testing import CliRunner

from mallcop.cli import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_capture_dict(**overrides) -> dict:
    """Build a minimal capture dict that passes quality gate."""
    base = {
        "capture_id": "test-cap-001",
        "captured_at": "2026-01-15T09:00:00+00:00",
        "mallcop_version": "1.0.0",
        "tenant_id": "abc123",
        "connector": "github",
        "detector": "unusual_timing",
        "failure_mode": "KA",
        "difficulty": "malicious-hard",
        "finding_raw": {
            "id": "f1",
            "actor": "user_A",
            "severity": "warn",
        },
        "events_raw": [
            {"id": "e1", "actor": "user_A", "timestamp": "2026-01-15T09:00:00Z", "event_type": "push"},
            {"id": "e2", "actor": "user_A", "timestamp": "2026-01-15T09:01:00Z", "event_type": "push"},
            {"id": "e3", "actor": "user_A", "timestamp": "2026-01-15T09:02:00Z", "event_type": "push"},
        ],
        "baseline_raw": {
            "known_entities": ["user_A"],
            "actor_frequency": {"user_A": 10},
        },
        "connector_tool_calls": [
            {
                "tool": "list_commits",
                "args_schema": {},
                "response_raw": {"commits": [{"sha": "abc"}]},
            },
            {
                "tool": "get_user",
                "args_schema": {},
                "response_raw": {"login": "user_A"},
            },
        ],
        "actor_chain": {
            "triage_action": "escalated",
            "chain_action": "escalated",
            "chain_reason": "Unusual activity detected.",
            "llm_calls": [],
            "total_tokens": 800,
        },
        "human_override": None,
        "confidence_score": 0.55,
        "anonymization_validated": True,
        # Novelty: detector not in corpus
        "corpus_detectors": [],
        "corpus_failure_modes": [],
        "corpus_difficulty_counts": {},
    }
    base.update(overrides)
    return base


def _write_capture(captures_dir: Path, capture: dict) -> Path:
    """Write a capture dict to a monthly subdir as a .jsonl file."""
    month_dir = captures_dir / "2026-01"
    month_dir.mkdir(parents=True, exist_ok=True)
    cap_id = capture["capture_id"]
    cap_file = month_dir / f"cap-{cap_id}.jsonl"
    cap_file.write_text(json.dumps(capture) + "\n")
    return cap_file


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestContributeDryRunNoCaptures:
    def test_empty_captures_dir_exits_zero(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)

        runner = CliRunner()
        result = runner.invoke(cli, ["contribute", "--captures-dir", str(captures_dir)])

        assert result.exit_code == 0

    def test_empty_dir_reports_zero_candidates(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)

        runner = CliRunner()
        result = runner.invoke(cli, ["contribute", "--captures-dir", str(captures_dir)])

        assert "0" in result.output or "no captures" in result.output.lower() or "nothing" in result.output.lower()

    def test_nonexistent_captures_dir_exits_zero(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        # Do not create — does not exist

        runner = CliRunner()
        result = runner.invoke(cli, ["contribute", "--captures-dir", str(captures_dir)])

        assert result.exit_code == 0


class TestContributeDryRunWithCaptures:
    def test_prints_summary_of_candidates(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        capture = _make_capture_dict()
        _write_capture(captures_dir, capture)

        runner = CliRunner()
        result = runner.invoke(cli, ["contribute", "--captures-dir", str(captures_dir)])

        assert result.exit_code == 0
        # Should mention capture count, scenario id, or "would contribute"
        output = result.output
        assert (
            "SYN-" in output
            or "would" in output.lower()
            or "1" in output
        )

    def test_does_not_write_files_in_dry_run(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        _write_capture(captures_dir, _make_capture_dict())

        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "contribute",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        assert result.exit_code == 0
        # Dry run (default) must NOT write YAML files
        assert not synthetic_dir.exists() or list(synthetic_dir.glob("*.yaml")) == []

    def test_multiple_captures_all_reported(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        for i in range(3):
            cap = _make_capture_dict(capture_id=f"test-cap-{i:03d}")
            _write_capture(captures_dir, cap)

        runner = CliRunner()
        result = runner.invoke(cli, ["contribute", "--captures-dir", str(captures_dir)])

        assert result.exit_code == 0
        # Should mention 3 somewhere in summary
        assert "3" in result.output or result.output.count("SYN-") == 3


class TestContributeLocalWritesYaml:
    def test_local_writes_yaml_file(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        _write_capture(captures_dir, _make_capture_dict())
        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "contribute", "--local",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        assert result.exit_code == 0
        yaml_files = list(synthetic_dir.glob("*.yaml"))
        assert len(yaml_files) == 1

    def test_yaml_file_has_valid_scenario_schema(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        _write_capture(captures_dir, _make_capture_dict())
        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        runner.invoke(
            cli,
            [
                "contribute", "--local",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        yaml_files = list(synthetic_dir.glob("*.yaml"))
        assert yaml_files
        scenario = yaml.safe_load(yaml_files[0].read_text())
        for field in ["id", "detector", "events", "expected", "tags"]:
            assert field in scenario, f"Missing field: {field}"

    def test_yaml_filename_matches_scenario_id(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        _write_capture(captures_dir, _make_capture_dict())
        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        runner.invoke(
            cli,
            [
                "contribute", "--local",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        yaml_files = list(synthetic_dir.glob("*.yaml"))
        assert yaml_files
        scenario = yaml.safe_load(yaml_files[0].read_text())
        assert yaml_files[0].stem == scenario["id"]

    def test_local_multiple_captures_writes_multiple_files(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        for i in range(3):
            cap = _make_capture_dict(capture_id=f"test-cap-{i:03d}")
            _write_capture(captures_dir, cap)
        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "contribute", "--local",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        assert result.exit_code == 0
        yaml_files = list(synthetic_dir.glob("*.yaml"))
        assert len(yaml_files) == 3


class TestContributeRejectsLowQuality:
    def test_capture_missing_events_not_synthesized(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        # Fails mandatory check: events_raw is empty
        bad = _make_capture_dict(events_raw=[])
        _write_capture(captures_dir, bad)
        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "contribute", "--local",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        assert result.exit_code == 0
        yaml_files = list(synthetic_dir.glob("*.yaml")) if synthetic_dir.exists() else []
        assert yaml_files == []

    def test_rejected_capture_reported_as_rejected(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        bad = _make_capture_dict(events_raw=[])
        _write_capture(captures_dir, bad)

        runner = CliRunner()
        result = runner.invoke(cli, ["contribute", "--captures-dir", str(captures_dir)])

        assert result.exit_code == 0
        # Should indicate rejection somewhere
        output = result.output.lower()
        assert "rejected" in output or "failed" in output or "skip" in output or "0" in output

    def test_credential_leak_hard_block_not_synthesized(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        bad = _make_capture_dict(credential_leak=True)
        _write_capture(captures_dir, bad)
        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        runner.invoke(
            cli,
            [
                "contribute", "--local",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        yaml_files = list(synthetic_dir.glob("*.yaml")) if synthetic_dir.exists() else []
        assert yaml_files == []

    def test_mixed_captures_only_passing_synthesized(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        good = _make_capture_dict(capture_id="good-cap-001")
        bad = _make_capture_dict(capture_id="bad-cap-001", events_raw=[])
        _write_capture(captures_dir, good)
        _write_capture(captures_dir, bad)
        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "contribute", "--local",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        assert result.exit_code == 0
        yaml_files = list(synthetic_dir.glob("*.yaml"))
        assert len(yaml_files) == 1


class TestContributeMarksEvaluated:
    def test_local_creates_evaluated_marker(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        cap = _make_capture_dict()
        cap_file = _write_capture(captures_dir, cap)
        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        runner.invoke(
            cli,
            [
                "contribute", "--local",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        marker = cap_file.with_suffix(".evaluated")
        assert marker.exists()

    def test_dry_run_does_not_create_evaluated_marker(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        cap = _make_capture_dict()
        cap_file = _write_capture(captures_dir, cap)

        runner = CliRunner()
        runner.invoke(cli, ["contribute", "--captures-dir", str(captures_dir)])

        marker = cap_file.with_suffix(".evaluated")
        assert not marker.exists()

    def test_already_evaluated_capture_skipped(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        cap = _make_capture_dict()
        cap_file = _write_capture(captures_dir, cap)
        # Pre-place the evaluated marker
        cap_file.with_suffix(".evaluated").touch()
        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "contribute", "--local",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        assert result.exit_code == 0
        # Should not write any new scenarios since the only capture was already evaluated
        yaml_files = list(synthetic_dir.glob("*.yaml")) if synthetic_dir.exists() else []
        assert yaml_files == []

    def test_rejected_capture_also_gets_evaluated_marker(self, tmp_path: Path) -> None:
        captures_dir = tmp_path / ".mallcop" / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        bad = _make_capture_dict(capture_id="bad-cap-001", events_raw=[])
        cap_file = _write_capture(captures_dir, bad)
        synthetic_dir = tmp_path / "synthetic"

        runner = CliRunner()
        runner.invoke(
            cli,
            [
                "contribute", "--local",
                "--captures-dir", str(captures_dir),
                "--synthetic-dir", str(synthetic_dir),
            ],
        )

        # Rejected captures are still marked evaluated so they're not re-processed
        marker = cap_file.with_suffix(".evaluated")
        assert marker.exists()
