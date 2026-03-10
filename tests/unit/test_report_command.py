"""Tests for mallcop report command."""

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import Event, Finding, FindingStatus, Severity
from mallcop.store import JsonlStore


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_finding(
    id: str = "fnd_001",
    severity: Severity = Severity.WARN,
    status: FindingStatus = FindingStatus.OPEN,
    timestamp: datetime | None = None,
) -> Finding:
    return Finding(
        id=id,
        timestamp=timestamp or _utcnow(),
        detector="new-actor",
        event_ids=["evt_001"],
        title="New actor: intruder@evil.com on azure",
        severity=severity,
        status=status,
        annotations=[],
        metadata={},
    )


class TestReportCommand:
    def test_report_outputs_json(self, tmp_path) -> None:
        """Report outputs JSON by default."""
        store = JsonlStore(tmp_path)
        store.append_findings([_make_finding()])

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_report_filters_by_status(self, tmp_path) -> None:
        """Report --status filters findings."""
        store = JsonlStore(tmp_path)
        store.append_findings([
            _make_finding(id="fnd_001", status=FindingStatus.OPEN),
            _make_finding(id="fnd_002", status=FindingStatus.RESOLVED),
        ])

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--dir", str(tmp_path), "--status", "open"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["status"] == "open"

    def test_report_filters_by_severity(self, tmp_path) -> None:
        """Report --severity filters findings (comma-separated)."""
        store = JsonlStore(tmp_path)
        store.append_findings([
            _make_finding(id="fnd_001", severity=Severity.WARN),
            _make_finding(id="fnd_002", severity=Severity.INFO),
            _make_finding(id="fnd_003", severity=Severity.CRITICAL),
        ])

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--dir", str(tmp_path), "--severity", "warn,critical"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 2
        severities = {f["severity"] for f in data["findings"]}
        assert severities == {"warn", "critical"}

    def test_report_filters_by_since(self, tmp_path) -> None:
        """Report --since filters by time window."""
        now = _utcnow()
        store = JsonlStore(tmp_path)
        store.append_findings([
            _make_finding(id="fnd_old", timestamp=now - timedelta(hours=48)),
            _make_finding(id="fnd_new", timestamp=now - timedelta(hours=12)),
        ])

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--dir", str(tmp_path), "--since", "24h"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["id"] == "fnd_new"

    def test_report_no_findings(self, tmp_path) -> None:
        """Report with no findings returns empty list."""
        # Ensure the store root exists but no findings
        JsonlStore(tmp_path)

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["findings"] == []

    def test_report_human_flag(self, tmp_path) -> None:
        """Report --human outputs readable text, not JSON."""
        store = JsonlStore(tmp_path)
        store.append_findings([_make_finding()])

        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--dir", str(tmp_path), "--human"])

        assert result.exit_code == 0
        # Should NOT be valid JSON
        try:
            json.loads(result.output)
            assert False, "Expected non-JSON output with --human"
        except json.JSONDecodeError:
            pass
        # Should contain finding info
        assert "fnd_001" in result.output or "intruder" in result.output
