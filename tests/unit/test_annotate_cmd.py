"""Tests for mallcop annotate command."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import (
    Annotation,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


def _make_finding(
    id: str,
    severity: Severity = Severity.WARN,
    title: str = "Test finding",
    annotations: list[Annotation] | None = None,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new_actor",
        event_ids=["evt_001"],
        title=title,
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=annotations or [],
        metadata={},
    )


def _write_findings(tmp_path: Path, findings: list[Finding]) -> None:
    mallcop_dir = tmp_path / ".mallcop"
    mallcop_dir.mkdir(parents=True, exist_ok=True)
    with open(mallcop_dir / "findings.jsonl", "w") as f:
        for fnd in findings:
            f.write(fnd.to_json() + "\n")


class TestAnnotateAppendsToFinding:
    def test_annotate_appends_annotation(self, tmp_path: Path) -> None:
        _write_findings(tmp_path, [_make_finding("fnd_001")])

        runner = CliRunner()
        result = runner.invoke(
            cli, ["annotate", "fnd_001", "Looks suspicious", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["annotation"]["content"] == "Looks suspicious"

        # Verify persisted to findings.jsonl
        store = JsonlStore(tmp_path)
        findings = store.query_findings()
        assert len(findings) == 1
        assert len(findings[0].annotations) == 1
        assert findings[0].annotations[0].content == "Looks suspicious"

    def test_annotate_preserves_existing_annotations(self, tmp_path: Path) -> None:
        existing_ann = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 6, 10, 0, 0, tzinfo=timezone.utc),
            content="Initial triage note",
            action="annotate",
            reason=None,
        )
        _write_findings(tmp_path, [_make_finding("fnd_001", annotations=[existing_ann])])

        runner = CliRunner()
        result = runner.invoke(
            cli, ["annotate", "fnd_001", "Follow-up note", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 0

        store = JsonlStore(tmp_path)
        findings = store.query_findings()
        assert len(findings[0].annotations) == 2
        assert findings[0].annotations[0].content == "Initial triage note"
        assert findings[0].annotations[1].content == "Follow-up note"


class TestAnnotateTimestampAndAuthor:
    def test_annotate_sets_utc_timestamp(self, tmp_path: Path) -> None:
        _write_findings(tmp_path, [_make_finding("fnd_001")])

        fixed_time = datetime(2026, 3, 6, 14, 30, 0, tzinfo=timezone.utc)
        with patch("mallcop.cli.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)

            runner = CliRunner()
            result = runner.invoke(
                cli, ["annotate", "fnd_001", "Test note", "--dir", str(tmp_path)]
            )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["annotation"]["timestamp"] == "2026-03-06T14:30:00+00:00"

    def test_annotate_default_author_is_interactive(self, tmp_path: Path) -> None:
        _write_findings(tmp_path, [_make_finding("fnd_001")])

        runner = CliRunner()
        result = runner.invoke(
            cli, ["annotate", "fnd_001", "Test note", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["annotation"]["actor"] == "interactive"

    def test_annotate_custom_author(self, tmp_path: Path) -> None:
        _write_findings(tmp_path, [_make_finding("fnd_001")])

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["annotate", "fnd_001", "Agent note", "--author", "security-agent",
             "--dir", str(tmp_path)],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["annotation"]["actor"] == "security-agent"


class TestAnnotateErrorOnUnknownFinding:
    def test_annotate_unknown_finding_exits_1(self, tmp_path: Path) -> None:
        _write_findings(tmp_path, [_make_finding("fnd_001")])

        runner = CliRunner()
        result = runner.invoke(
            cli, ["annotate", "fnd_nonexistent", "Note", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "not found" in data["error"].lower()

    def test_annotate_no_findings_file_exits_1(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["annotate", "fnd_001", "Note", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"


class TestAnnotateJsonOutput:
    def test_annotate_outputs_annotation_object(self, tmp_path: Path) -> None:
        _write_findings(tmp_path, [_make_finding("fnd_001")])

        runner = CliRunner()
        result = runner.invoke(
            cli, ["annotate", "fnd_001", "Analysis note", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "annotate"
        assert data["status"] == "ok"
        assert data["finding_id"] == "fnd_001"
        ann = data["annotation"]
        assert "actor" in ann
        assert "timestamp" in ann
        assert "content" in ann
        assert ann["content"] == "Analysis note"
        assert ann["action"] == "annotate"
