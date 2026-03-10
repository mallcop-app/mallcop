"""Tests for mallcop baseline command."""

import json
from datetime import datetime, timezone

from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import Baseline, Event, Severity
from mallcop.store import JsonlStore


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str = "evt_001",
    source: str = "azure",
    actor: str = "admin@example.com",
    event_type: str = "role_assignment",
    target: str = "/subscriptions/123",
) -> Event:
    return Event(
        id=id,
        timestamp=_utcnow(),
        ingested_at=_utcnow(),
        source=source,
        event_type=event_type,
        actor=actor,
        action="create",
        target=target,
        severity=Severity.WARN,
        metadata={},
        raw={},
    )


class TestBaselineCommand:
    def test_baseline_shows_stats(self, tmp_path) -> None:
        """baseline command shows event count, known entity count, frequency summary."""
        store = JsonlStore(tmp_path)
        events = [
            _make_event(id="evt_1", actor="alice@ex.com"),
            _make_event(id="evt_2", actor="bob@ex.com"),
        ]
        store.append_events(events)
        store.update_baseline(events)

        runner = CliRunner()
        result = runner.invoke(cli, ["baseline", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "event_count" in data
        assert data["event_count"] == 2
        assert "known_actor_count" in data
        assert data["known_actor_count"] == 2
        assert "frequency_table_entries" in data

    def test_baseline_actor_filter(self, tmp_path) -> None:
        """baseline --actor shows profile for a specific actor."""
        store = JsonlStore(tmp_path)
        events = [
            _make_event(id="evt_1", actor="alice@ex.com", source="azure"),
            _make_event(id="evt_2", actor="bob@ex.com", source="azure"),
        ]
        store.append_events(events)
        store.update_baseline(events)

        runner = CliRunner()
        result = runner.invoke(cli, ["baseline", "--dir", str(tmp_path), "--actor", "alice@ex.com"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["actor"] == "alice@ex.com"
        assert "frequency_entries" in data

    def test_baseline_entity_filter(self, tmp_path) -> None:
        """baseline --entity looks up a specific entity."""
        store = JsonlStore(tmp_path)
        events = [_make_event(id="evt_1", actor="alice@ex.com")]
        store.append_events(events)
        store.update_baseline(events)

        runner = CliRunner()
        result = runner.invoke(cli, ["baseline", "--dir", str(tmp_path), "--entity", "alice@ex.com"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["entity"] == "alice@ex.com"
        assert "known" in data

    def test_baseline_empty_store(self, tmp_path) -> None:
        """baseline with no data returns zero counts."""
        JsonlStore(tmp_path)

        runner = CliRunner()
        result = runner.invoke(cli, ["baseline", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["event_count"] == 0
        assert data["known_actor_count"] == 0
