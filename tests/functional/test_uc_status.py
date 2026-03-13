"""UC: External agent uses mallcop as a security status tool.

Functional test exercising the scenario where an external agent (OpenClaw, Claude)
uses `mallcop status --json` and `mallcop report --json` to check security posture
and act on findings programmatically.

Scenarios:
  1. Agent runs `mallcop status --json` -- sees event counts, finding counts,
     events by source, findings by status/severity.
  2. Agent runs `mallcop report --json` -- parses findings array, checks severity.
  3. Agent runs `mallcop report --status open --json` -- filters to open findings.
  4. Agent runs `mallcop report --severity critical --json` -- filters by severity.
  5. Clean posture: no findings -> agent takes no action.
  6. Critical finding: agent sees CRITICAL and can act on it.
  7. Agent runs `mallcop status --costs --json` -- sees cost trends.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import (
    Annotation,
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


# --- Helpers ---


def _make_config_yaml(root: Path) -> None:
    """Write a minimal mallcop.yaml."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {"azure": {"subscription_ids": ["sub-001"]}},
        "routing": {},
        "actor_chain": {},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _make_events(
    source: str,
    base_time: datetime,
    actors: list[str],
    count_per_actor: int = 3,
) -> list[Event]:
    """Generate synthetic events."""
    events: list[Event] = []
    for i, actor in enumerate(actors):
        for j in range(count_per_actor):
            ts = base_time + timedelta(hours=i * 6 + j)
            events.append(Event(
                id=f"evt_{source}_{actor.split('@')[0]}_{i}_{j}",
                timestamp=ts,
                ingested_at=ts + timedelta(seconds=1),
                source=source,
                event_type="role_assignment",
                actor=actor,
                action="create",
                target=f"/subscriptions/sub-001/resource_{i}_{j}",
                severity=Severity.WARN,
                metadata={"ip_address": f"10.0.{i}.{j}"},
                raw={"raw_data": True},
            ))
    return events


def _make_finding(
    finding_id: str,
    title: str,
    severity: Severity,
    status: FindingStatus = FindingStatus.OPEN,
    detector: str = "new_actor",
    event_ids: list[str] | None = None,
    timestamp: datetime | None = None,
) -> Finding:
    """Create a synthetic finding."""
    return Finding(
        id=finding_id,
        timestamp=timestamp or datetime.now(timezone.utc),
        detector=detector,
        event_ids=event_ids or ["evt_001"],
        title=title,
        severity=severity,
        status=status,
        annotations=[],
        metadata={},
    )


def _seed_store(
    root: Path,
    events: list[Event] | None = None,
    findings: list[Finding] | None = None,
) -> None:
    """Seed the store with events and/or findings."""
    store = JsonlStore(root)
    if events:
        store.append_events(events)
    if findings:
        store.append_findings(findings)


def _write_cost_entries(root: Path, entries: list[dict[str, Any]]) -> None:
    """Write cost entries to costs.jsonl."""
    (root / ".mallcop").mkdir(parents=True, exist_ok=True)
    with open(root / ".mallcop" / "costs.jsonl", "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


# --- Tests ---


class TestStatusJsonOutput:
    """mallcop status --json returns well-structured JSON for agent consumption."""

    def test_status_returns_valid_json(self, tmp_path: Path) -> None:
        """status output is valid JSON with expected top-level keys."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        events = _make_events("azure", now - timedelta(days=5), ["admin@example.com"])
        _seed_store(root, events=events)

        result = CliRunner().invoke(cli, ["status", "--dir", str(root)])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"

        data = json.loads(result.output)

        # Top-level keys an agent would expect
        assert data["status"] == "ok"
        assert "total_events" in data
        assert "total_findings" in data
        assert "events_by_source" in data
        assert "findings_by_status" in data
        assert "findings_by_severity" in data

    def test_status_event_counts_accurate(self, tmp_path: Path) -> None:
        """status reports correct event counts by source."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        azure_events = _make_events("azure", now - timedelta(days=5), ["admin@example.com"], count_per_actor=4)
        github_events = _make_events("github", now - timedelta(days=3), ["dev@example.com"], count_per_actor=2)
        _seed_store(root, events=azure_events + github_events)

        result = CliRunner().invoke(cli, ["status", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert data["total_events"] == 6  # 4 azure + 2 github
        assert data["events_by_source"]["azure"] == 4
        assert data["events_by_source"]["github"] == 2

    def test_status_finding_counts_by_status_and_severity(self, tmp_path: Path) -> None:
        """status reports correct finding breakdown by status and severity."""
        root = tmp_path
        _make_config_yaml(root)

        findings = [
            _make_finding("f-001", "Unknown actor: evil@bad.com", Severity.WARN, FindingStatus.OPEN),
            _make_finding("f-002", "Unknown actor: evil2@bad.com", Severity.CRITICAL, FindingStatus.OPEN),
            _make_finding("f-003", "Known actor anomaly", Severity.INFO, FindingStatus.RESOLVED),
        ]
        _seed_store(root, findings=findings)

        result = CliRunner().invoke(cli, ["status", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert data["total_findings"] == 3
        assert data["findings_by_status"]["open"] == 2
        assert data["findings_by_status"]["resolved"] == 1
        assert data["findings_by_severity"]["warn"] == 1
        assert data["findings_by_severity"]["critical"] == 1
        assert data["findings_by_severity"]["info"] == 1

    def test_status_empty_deployment(self, tmp_path: Path) -> None:
        """status on empty deployment returns zeros, not errors."""
        root = tmp_path
        _make_config_yaml(root)

        result = CliRunner().invoke(cli, ["status", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert data["status"] == "ok"
        assert data["total_events"] == 0
        assert data["total_findings"] == 0
        assert data["events_by_source"] == {}
        assert data["findings_by_status"] == {}
        assert data["findings_by_severity"] == {}

    def test_status_with_costs(self, tmp_path: Path) -> None:
        """status --costs includes cost trend data."""
        root = tmp_path
        _make_config_yaml(root)

        # Write cost entries
        cost_entries = [
            {
                "timestamp": (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat(),
                "events": 10,
                "findings": 2,
                "tokens_used": 5000,
                "estimated_cost_usd": 0.00125,
                "actors_invoked": True,
                "budget_remaining_pct": 90.0,
            },
            {
                "timestamp": (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat(),
                "events": 15,
                "findings": 3,
                "tokens_used": 8000,
                "estimated_cost_usd": 0.002,
                "actors_invoked": True,
                "budget_remaining_pct": 84.0,
            },
        ]
        _write_cost_entries(root, cost_entries)

        result = CliRunner().invoke(cli, ["status", "--costs", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert "costs" in data
        costs = data["costs"]
        assert costs["total_runs"] == 2
        assert costs["total_tokens"] == 13000
        assert costs["avg_tokens_per_run"] == 6500.0
        assert costs["estimated_total_usd"] > 0
        assert "circuit_breaker_triggered" in costs
        assert "budget_exhausted" in costs


class TestReportJsonOutput:
    """mallcop report --json returns well-structured findings for agent parsing."""

    def test_report_returns_findings_array(self, tmp_path: Path) -> None:
        """report output contains a parseable findings array."""
        root = tmp_path
        _make_config_yaml(root)

        findings = [
            _make_finding("f-001", "Unknown actor: evil@bad.com", Severity.WARN),
            _make_finding("f-002", "Unknown actor: evil2@bad.com", Severity.CRITICAL),
        ]
        _seed_store(root, findings=findings)

        result = CliRunner().invoke(cli, ["report", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert data["command"] == "report"
        assert data["status"] == "ok"
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) == 2

    def test_report_finding_structure(self, tmp_path: Path) -> None:
        """Each finding in report has all fields an agent needs to act on."""
        root = tmp_path
        _make_config_yaml(root)

        findings = [
            _make_finding("f-001", "Unknown actor: evil@bad.com", Severity.WARN),
        ]
        _seed_store(root, findings=findings)

        result = CliRunner().invoke(cli, ["report", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        finding = data["findings"][0]
        # All fields an agent needs
        assert "id" in finding
        assert "timestamp" in finding
        assert "detector" in finding
        assert "title" in finding
        assert "severity" in finding
        assert "status" in finding
        assert "event_ids" in finding
        assert "annotations" in finding
        assert "metadata" in finding

        # Values are correct types
        assert finding["id"] == "f-001"
        assert finding["severity"] == "warn"
        assert finding["status"] == "open"

    def test_report_filter_by_status_open(self, tmp_path: Path) -> None:
        """report --status open returns only open findings."""
        root = tmp_path
        _make_config_yaml(root)

        findings = [
            _make_finding("f-001", "Open finding", Severity.WARN, FindingStatus.OPEN),
            _make_finding("f-002", "Resolved finding", Severity.INFO, FindingStatus.RESOLVED),
            _make_finding("f-003", "Another open", Severity.CRITICAL, FindingStatus.OPEN),
        ]
        _seed_store(root, findings=findings)

        result = CliRunner().invoke(cli, ["report", "--status", "open", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert len(data["findings"]) == 2
        for f in data["findings"]:
            assert f["status"] == "open"

    def test_report_filter_by_severity(self, tmp_path: Path) -> None:
        """report --severity critical returns only critical findings."""
        root = tmp_path
        _make_config_yaml(root)

        findings = [
            _make_finding("f-001", "Warning finding", Severity.WARN, FindingStatus.OPEN),
            _make_finding("f-002", "Critical finding", Severity.CRITICAL, FindingStatus.OPEN),
            _make_finding("f-003", "Info finding", Severity.INFO, FindingStatus.OPEN),
        ]
        _seed_store(root, findings=findings)

        result = CliRunner().invoke(cli, ["report", "--severity", "critical", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "critical"
        assert data["findings"][0]["id"] == "f-002"

    def test_report_filter_severity_comma_separated(self, tmp_path: Path) -> None:
        """report --severity warn,critical returns multiple severity levels."""
        root = tmp_path
        _make_config_yaml(root)

        findings = [
            _make_finding("f-001", "Warning finding", Severity.WARN),
            _make_finding("f-002", "Critical finding", Severity.CRITICAL),
            _make_finding("f-003", "Info finding", Severity.INFO),
        ]
        _seed_store(root, findings=findings)

        result = CliRunner().invoke(cli, ["report", "--severity", "warn,critical", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert len(data["findings"]) == 2
        severities = {f["severity"] for f in data["findings"]}
        assert severities == {"warn", "critical"}

    def test_report_empty_no_findings(self, tmp_path: Path) -> None:
        """report with no findings returns empty array, not error."""
        root = tmp_path
        _make_config_yaml(root)

        result = CliRunner().invoke(cli, ["report", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert data["command"] == "report"
        assert data["status"] == "ok"
        assert data["findings"] == []


class TestAgentCleanPostureScenario:
    """Agent checks posture, sees clean state, takes no action."""

    def test_clean_posture_workflow(self, tmp_path: Path) -> None:
        """Simulates: agent runs status, sees 0 findings, runs report --status open,
        confirms empty, logs that security posture is clean."""
        root = tmp_path
        _make_config_yaml(root)

        # Some events exist but no findings
        now = datetime.now(timezone.utc)
        events = _make_events("azure", now - timedelta(days=20), ["admin@example.com"])
        _seed_store(root, events=events)

        # Step 1: Agent checks status
        status_result = CliRunner().invoke(cli, ["status", "--dir", str(root)])
        assert status_result.exit_code == 0
        status_data = json.loads(status_result.output)

        assert status_data["status"] == "ok"
        assert status_data["total_events"] > 0
        assert status_data["total_findings"] == 0

        # Step 2: Agent confirms with report --status open
        report_result = CliRunner().invoke(cli, ["report", "--status", "open", "--dir", str(root)])
        assert report_result.exit_code == 0
        report_data = json.loads(report_result.output)

        assert report_data["findings"] == []

        # Agent decision: posture is clean, no action needed


class TestAgentCriticalFindingScenario:
    """Agent checks posture, sees CRITICAL finding, acts on it."""

    def test_critical_finding_workflow(self, tmp_path: Path) -> None:
        """Simulates: agent runs status, sees findings, runs report --json,
        sees CRITICAL finding, extracts details for notification."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        events = _make_events("azure", now - timedelta(days=20), ["admin@example.com"])

        critical_finding = _make_finding(
            "f-critical-001",
            "Unknown actor: attacker@evil.com performed role_assignment",
            Severity.CRITICAL,
            FindingStatus.OPEN,
            event_ids=["evt_azure_admin_0_0"],
            timestamp=now - timedelta(hours=1),
        )
        low_finding = _make_finding(
            "f-low-001",
            "New IP address for known actor admin@example.com",
            Severity.INFO,
            FindingStatus.OPEN,
            timestamp=now - timedelta(hours=2),
        )
        _seed_store(root, events=events, findings=[critical_finding, low_finding])

        # Step 1: Agent checks status
        status_result = CliRunner().invoke(cli, ["status", "--dir", str(root)])
        assert status_result.exit_code == 0
        status_data = json.loads(status_result.output)

        assert status_data["total_findings"] == 2
        assert status_data["findings_by_severity"]["critical"] == 1

        # Agent sees critical findings exist, digs deeper

        # Step 2: Agent gets full report
        report_result = CliRunner().invoke(cli, ["report", "--dir", str(root)])
        assert report_result.exit_code == 0
        report_data = json.loads(report_result.output)

        findings = report_data["findings"]
        assert len(findings) == 2

        # Step 3: Agent filters for critical
        critical_findings = [f for f in findings if f["severity"] == "critical"]
        assert len(critical_findings) == 1

        critical = critical_findings[0]
        assert critical["id"] == "f-critical-001"
        assert "attacker@evil.com" in critical["title"]
        assert critical["status"] == "open"
        assert len(critical["event_ids"]) > 0

        # Agent decision: notify human operator, create task
        # (verified by being able to extract all needed fields)

    def test_report_severity_filter_for_triage(self, tmp_path: Path) -> None:
        """Agent uses --severity to quickly check if anything critical/warn exists."""
        root = tmp_path
        _make_config_yaml(root)

        findings = [
            _make_finding("f-001", "Info finding", Severity.INFO),
            _make_finding("f-002", "Warn finding", Severity.WARN),
            _make_finding("f-003", "Critical finding", Severity.CRITICAL),
            _make_finding("f-004", "Another info", Severity.INFO),
        ]
        _seed_store(root, findings=findings)

        # Agent checks for actionable findings only
        result = CliRunner().invoke(cli, ["report", "--severity", "warn,critical", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert len(data["findings"]) == 2
        ids = {f["id"] for f in data["findings"]}
        assert ids == {"f-002", "f-003"}


class TestAgentLowSeverityScenario:
    """Agent sees only low-severity findings, logs clean posture."""

    def test_low_severity_only_workflow(self, tmp_path: Path) -> None:
        """Simulates: agent runs report --status open, sees 2 open findings,
        both low severity. Takes no action, logs posture as clean."""
        root = tmp_path
        _make_config_yaml(root)

        findings = [
            _make_finding("f-001", "Info observation 1", Severity.INFO, FindingStatus.OPEN),
            _make_finding("f-002", "Info observation 2", Severity.INFO, FindingStatus.OPEN),
        ]
        _seed_store(root, findings=findings)

        result = CliRunner().invoke(cli, ["report", "--status", "open", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert len(data["findings"]) == 2
        # Agent checks: are any critical or warn?
        actionable = [f for f in data["findings"] if f["severity"] in ("critical", "warn")]
        assert len(actionable) == 0
        # Agent decision: posture clean, no escalation


class TestReportSinceFilter:
    """report --since filters findings by time window."""

    def test_since_filter(self, tmp_path: Path) -> None:
        """report --since 12h returns only recent findings."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        findings = [
            _make_finding("f-old", "Old finding", Severity.WARN, timestamp=now - timedelta(days=2)),
            _make_finding("f-recent", "Recent finding", Severity.WARN, timestamp=now - timedelta(hours=6)),
        ]
        _seed_store(root, findings=findings)

        result = CliRunner().invoke(cli, ["report", "--since", "12h", "--dir", str(root)])
        assert result.exit_code == 0
        data = json.loads(result.output)

        assert len(data["findings"]) == 1
        assert data["findings"][0]["id"] == "f-recent"


class TestStatusAndReportCombined:
    """Agent uses both status and report in sequence for full picture."""

    def test_status_then_report_consistent(self, tmp_path: Path) -> None:
        """Status total_findings matches report findings count."""
        root = tmp_path
        _make_config_yaml(root)

        now = datetime.now(timezone.utc)
        events = _make_events("azure", now - timedelta(days=5), ["admin@example.com", "deploy@example.com"])
        findings = [
            _make_finding("f-001", "Finding 1", Severity.WARN, FindingStatus.OPEN),
            _make_finding("f-002", "Finding 2", Severity.INFO, FindingStatus.OPEN),
            _make_finding("f-003", "Finding 3", Severity.CRITICAL, FindingStatus.RESOLVED),
        ]
        _seed_store(root, events=events, findings=findings)

        # Status
        status_result = CliRunner().invoke(cli, ["status", "--dir", str(root)])
        assert status_result.exit_code == 0
        status_data = json.loads(status_result.output)

        # Report (all)
        report_result = CliRunner().invoke(cli, ["report", "--dir", str(root)])
        assert report_result.exit_code == 0
        report_data = json.loads(report_result.output)

        # Counts match
        assert status_data["total_findings"] == len(report_data["findings"])

        # Report --status open count matches status breakdown
        open_report = CliRunner().invoke(cli, ["report", "--status", "open", "--dir", str(root)])
        open_data = json.loads(open_report.output)
        assert status_data["findings_by_status"]["open"] == len(open_data["findings"])
