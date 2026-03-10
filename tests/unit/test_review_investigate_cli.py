"""Tests for review and investigate CLI commands (--human flag, JSON output)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import (
    Annotation,
    Finding,
    FindingStatus,
    Severity,
)


def _make_config(tmp_path: Path) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": {"warn": "triage", "critical": "triage"},
        "actor_chain": {
            "triage": {"routes_to": "notify-teams"},
            "notify-teams": {"routes_to": None},
        },
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(tmp_path / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


def _make_finding(
    id: str,
    severity: Severity = Severity.WARN,
    title: str = "Test finding",
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new_actor",
        event_ids=["evt_001"],
        title=title,
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _write_findings(tmp_path: Path, findings: list[Finding]) -> None:
    with open(tmp_path / "findings.jsonl", "w") as f:
        for fnd in findings:
            f.write(fnd.to_json() + "\n")


class TestReviewCli:
    def test_review_outputs_json_by_default(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        _write_findings(tmp_path, [_make_finding("fnd_001")])

        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "review"
        assert "findings_by_severity" in data

    def test_review_human_output(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        _write_findings(tmp_path, [
            _make_finding("fnd_001", severity=Severity.CRITICAL, title="Admin role assigned"),
            _make_finding("fnd_002", severity=Severity.WARN, title="New IP login"),
        ])

        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--human", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        assert "CRITICAL" in result.output
        assert "WARN" in result.output
        assert "fnd_001" in result.output
        assert "fnd_002" in result.output

    def test_review_no_findings(self, tmp_path: Path) -> None:
        _make_config(tmp_path)

        runner = CliRunner()
        result = runner.invoke(cli, ["review", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings_by_severity"] == {}


class TestInvestigateCli:
    def test_investigate_outputs_json_by_default(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        _write_findings(tmp_path, [_make_finding("fnd_abc")])

        runner = CliRunner()
        result = runner.invoke(cli, ["investigate", "fnd_abc", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "investigate"
        assert data["finding"]["id"] == "fnd_abc"

    def test_investigate_human_output(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        _write_findings(tmp_path, [
            _make_finding("fnd_abc", title="Admin role assigned"),
        ])

        runner = CliRunner()
        result = runner.invoke(
            cli, ["investigate", "fnd_abc", "--human", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 0
        assert "fnd_abc" in result.output
        assert "Admin role assigned" in result.output

    def test_investigate_finding_not_found(self, tmp_path: Path) -> None:
        _make_config(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["investigate", "fnd_nope", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 1
