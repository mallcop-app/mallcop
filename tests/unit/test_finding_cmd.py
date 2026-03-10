"""Tests for mallcop finding <id> query command."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import (
    Annotation,
    Event,
    Finding,
    FindingStatus,
    Severity,
)


def _make_config(tmp_path: Path) -> None:
    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": {},
        "actor_chain": {},
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
    event_ids: list[str] | None = None,
    annotations: list[Annotation] | None = None,
    status: FindingStatus = FindingStatus.OPEN,
    detector: str = "new_actor",
    metadata: dict | None = None,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector=detector,
        event_ids=event_ids or ["evt_001"],
        title=title,
        severity=severity,
        status=status,
        annotations=annotations or [],
        metadata=metadata or {},
    )


def _write_findings(tmp_path: Path, findings: list[Finding]) -> None:
    with open(tmp_path / "findings.jsonl", "w") as f:
        for fnd in findings:
            f.write(fnd.to_json() + "\n")


class TestFindingCommand:
    def test_finding_returns_full_detail(self, tmp_path: Path) -> None:
        """finding <id> returns full finding detail as JSON."""
        _make_config(tmp_path)
        ann = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 6, 13, 0, 0, tzinfo=timezone.utc),
            content="Unknown actor, not in baseline. Escalated.",
            action="escalate",
            reason="unknown_actor",
        )
        finding = _make_finding(
            "fnd_abc",
            severity=Severity.CRITICAL,
            title="Admin role assigned",
            event_ids=["evt_001", "evt_002"],
            annotations=[ann],
            detector="new_actor",
            metadata={"key": "value"},
        )
        _write_findings(tmp_path, [finding])

        runner = CliRunner()
        result = runner.invoke(cli, ["finding", "fnd_abc", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "finding"
        assert data["status"] == "ok"

        f = data["finding"]
        assert f["id"] == "fnd_abc"
        assert f["severity"] == "critical"
        assert f["detector"] == "new_actor"
        assert f["title"] == "Admin role assigned"
        assert f["status"] == "open"
        assert f["event_ids"] == ["evt_001", "evt_002"]
        assert f["metadata"] == {"key": "value"}
        assert f["timestamp"] is not None

        # Annotations with timestamps and authors
        assert len(f["annotations"]) == 1
        a = f["annotations"][0]
        assert a["actor"] == "triage"
        assert a["content"] == "Unknown actor, not in baseline. Escalated."
        assert a["action"] == "escalate"
        assert a["timestamp"] is not None

    def test_finding_error_for_unknown_id(self, tmp_path: Path) -> None:
        """finding <id> returns error JSON + exit code 1 for unknown ID."""
        _make_config(tmp_path)

        runner = CliRunner()
        result = runner.invoke(cli, ["finding", "fnd_nope", "--dir", str(tmp_path)])

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "fnd_nope" in data["error"]

    def test_finding_with_multiple_annotations(self, tmp_path: Path) -> None:
        """finding returns all annotations with timestamps and authors."""
        _make_config(tmp_path)
        anns = [
            Annotation(
                actor="triage",
                timestamp=datetime(2026, 3, 6, 13, 0, 0, tzinfo=timezone.utc),
                content="First pass: uncertain.",
                action="annotate",
                reason=None,
            ),
            Annotation(
                actor="human",
                timestamp=datetime(2026, 3, 6, 14, 0, 0, tzinfo=timezone.utc),
                content="Confirmed suspicious.",
                action="annotate",
                reason=None,
            ),
        ]
        finding = _make_finding("fnd_multi", annotations=anns)
        _write_findings(tmp_path, [finding])

        runner = CliRunner()
        result = runner.invoke(cli, ["finding", "fnd_multi", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["finding"]["annotations"]) == 2
        assert data["finding"]["annotations"][0]["actor"] == "triage"
        assert data["finding"]["annotations"][1]["actor"] == "human"

    def test_finding_human_output(self, tmp_path: Path) -> None:
        """finding --human produces readable output."""
        _make_config(tmp_path)
        ann = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 6, 13, 0, 0, tzinfo=timezone.utc),
            content="Escalated.",
            action="escalate",
            reason=None,
        )
        finding = _make_finding(
            "fnd_hum",
            severity=Severity.CRITICAL,
            title="Admin role assigned",
            annotations=[ann],
        )
        _write_findings(tmp_path, [finding])

        runner = CliRunner()
        result = runner.invoke(
            cli, ["finding", "fnd_hum", "--human", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 0
        assert "fnd_hum" in result.output
        assert "CRITICAL" in result.output
        assert "Admin role assigned" in result.output
        assert "triage" in result.output
