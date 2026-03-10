"""Tests for mallcop events query command."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import (
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


def _make_event(
    id: str,
    source: str = "azure",
    actor: str = "admin@example.com",
    event_type: str = "role_assignment",
    action: str = "assign",
    target: str = "subscription/abc",
    timestamp: datetime | None = None,
    severity: Severity = Severity.INFO,
) -> Event:
    ts = timestamp or datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc)
    return Event(
        id=id,
        timestamp=ts,
        ingested_at=ts,
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=severity,
        metadata={},
        raw={},
    )


def _write_events(tmp_path: Path, events: list[Event]) -> None:
    events_dir = tmp_path / "events"
    events_dir.mkdir(exist_ok=True)
    # Group by source+month
    groups: dict[str, list[Event]] = {}
    for evt in events:
        key = f"{evt.source}-{evt.timestamp.strftime('%Y-%m')}"
        groups.setdefault(key, []).append(evt)
    for key, evts in groups.items():
        with open(events_dir / f"{key}.jsonl", "w") as f:
            for evt in evts:
                f.write(evt.to_json() + "\n")


def _make_finding(
    id: str,
    event_ids: list[str],
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 6, 12, 0, 0, tzinfo=timezone.utc),
        detector="new_actor",
        event_ids=event_ids,
        title="Test finding",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _write_findings(tmp_path: Path, findings: list[Finding]) -> None:
    with open(tmp_path / "findings.jsonl", "w") as f:
        for fnd in findings:
            f.write(fnd.to_json() + "\n")


class TestEventsCommand:
    def test_events_no_filters_returns_all(self, tmp_path: Path) -> None:
        """events with no filters returns all events, newest first."""
        _make_config(tmp_path)
        now = datetime.now(timezone.utc)
        events = [
            _make_event("evt_001", timestamp=now - timedelta(hours=2)),
            _make_event("evt_002", timestamp=now - timedelta(hours=1)),
        ]
        _write_events(tmp_path, events)

        runner = CliRunner()
        result = runner.invoke(cli, ["events", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["command"] == "events"
        assert data["status"] == "ok"
        assert len(data["events"]) == 2
        # Newest first
        assert data["events"][0]["id"] == "evt_002"
        assert data["events"][1]["id"] == "evt_001"

    def test_events_filter_by_source(self, tmp_path: Path) -> None:
        """events --source filters by connector name."""
        _make_config(tmp_path)
        now = datetime.now(timezone.utc)
        events = [
            _make_event("evt_001", source="azure", timestamp=now - timedelta(hours=1)),
            _make_event("evt_002", source="github", timestamp=now - timedelta(hours=1)),
            _make_event("evt_003", source="azure", timestamp=now - timedelta(hours=1)),
        ]
        _write_events(tmp_path, events)

        runner = CliRunner()
        result = runner.invoke(cli, ["events", "--source", "azure", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["events"]) == 2
        assert all(e["source"] == "azure" for e in data["events"])

    def test_events_filter_by_actor(self, tmp_path: Path) -> None:
        """events --actor filters by actor ID."""
        _make_config(tmp_path)
        now = datetime.now(timezone.utc)
        events = [
            _make_event("evt_001", actor="admin@example.com", timestamp=now - timedelta(hours=1)),
            _make_event("evt_002", actor="attacker@evil.com", timestamp=now - timedelta(hours=1)),
            _make_event("evt_003", actor="admin@example.com", timestamp=now - timedelta(hours=1)),
        ]
        _write_events(tmp_path, events)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["events", "--actor", "attacker@evil.com", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["events"]) == 1
        assert data["events"][0]["actor"] == "attacker@evil.com"

    def test_events_filter_by_type(self, tmp_path: Path) -> None:
        """events --type filters by event type."""
        _make_config(tmp_path)
        now = datetime.now(timezone.utc)
        events = [
            _make_event("evt_001", event_type="role_assignment", timestamp=now - timedelta(hours=1)),
            _make_event("evt_002", event_type="login", timestamp=now - timedelta(hours=1)),
            _make_event("evt_003", event_type="role_assignment", timestamp=now - timedelta(hours=1)),
        ]
        _write_events(tmp_path, events)

        runner = CliRunner()
        result = runner.invoke(cli, ["events", "--type", "login", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["events"]) == 1
        assert data["events"][0]["event_type"] == "login"

    def test_events_filter_by_hours(self, tmp_path: Path) -> None:
        """events --hours N limits to events within N hours."""
        _make_config(tmp_path)
        now = datetime.now(timezone.utc)
        events = [
            _make_event("evt_old", timestamp=now - timedelta(hours=48)),
            _make_event("evt_recent", timestamp=now - timedelta(hours=1)),
        ]
        _write_events(tmp_path, events)

        runner = CliRunner()
        result = runner.invoke(cli, ["events", "--hours", "24", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["events"]) == 1
        assert data["events"][0]["id"] == "evt_recent"

    def test_events_default_hours_24(self, tmp_path: Path) -> None:
        """events without --hours defaults to 24h window."""
        _make_config(tmp_path)
        now = datetime.now(timezone.utc)
        events = [
            _make_event("evt_old", timestamp=now - timedelta(hours=48)),
            _make_event("evt_recent", timestamp=now - timedelta(hours=1)),
        ]
        _write_events(tmp_path, events)

        runner = CliRunner()
        result = runner.invoke(cli, ["events", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["events"]) == 1
        assert data["events"][0]["id"] == "evt_recent"

    def test_events_filter_by_finding(self, tmp_path: Path) -> None:
        """events --finding correlates via finding.event_ids."""
        _make_config(tmp_path)
        events = [
            _make_event("evt_001"),
            _make_event("evt_002"),
            _make_event("evt_003"),
        ]
        _write_events(tmp_path, events)
        _write_findings(tmp_path, [_make_finding("fnd_abc", event_ids=["evt_001", "evt_003"])])

        runner = CliRunner()
        result = runner.invoke(
            cli, ["events", "--finding", "fnd_abc", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["events"]) == 2
        ids = {e["id"] for e in data["events"]}
        assert ids == {"evt_001", "evt_003"}

    def test_events_finding_not_found(self, tmp_path: Path) -> None:
        """events --finding with unknown finding ID returns error."""
        _make_config(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["events", "--finding", "fnd_nope", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "fnd_nope" in data["error"]

    def test_events_combined_filters(self, tmp_path: Path) -> None:
        """events with multiple filters applies all of them."""
        _make_config(tmp_path)
        now = datetime.now(timezone.utc)
        events = [
            _make_event("evt_001", source="azure", actor="admin@example.com",
                        timestamp=now - timedelta(hours=1)),
            _make_event("evt_002", source="github", actor="admin@example.com",
                        timestamp=now - timedelta(hours=1)),
            _make_event("evt_003", source="azure", actor="other@example.com",
                        timestamp=now - timedelta(hours=1)),
            _make_event("evt_004", source="azure", actor="admin@example.com",
                        timestamp=now - timedelta(hours=48)),
        ]
        _write_events(tmp_path, events)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["events", "--source", "azure", "--actor", "admin@example.com",
             "--hours", "24", "--dir", str(tmp_path)],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["events"]) == 1
        assert data["events"][0]["id"] == "evt_001"

    def test_events_empty_result(self, tmp_path: Path) -> None:
        """events returns empty array when no events match."""
        _make_config(tmp_path)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["events", "--source", "nonexistent", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["events"] == []

    def test_events_human_output(self, tmp_path: Path) -> None:
        """events --human produces readable output."""
        _make_config(tmp_path)
        now = datetime.now(timezone.utc)
        events = [
            _make_event("evt_001", actor="admin@example.com", action="assign",
                        target="subscription/abc", timestamp=now - timedelta(hours=1)),
        ]
        _write_events(tmp_path, events)

        runner = CliRunner()
        result = runner.invoke(
            cli, ["events", "--human", "--dir", str(tmp_path)]
        )

        assert result.exit_code == 0
        assert "evt_001" in result.output
        assert "admin@example.com" in result.output
