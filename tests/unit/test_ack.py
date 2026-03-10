"""Unit tests for mallcop ack command: resolve finding + update baseline."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import (
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


# --- Helpers ---


def _make_event(
    id: str,
    actor: str,
    source: str = "azure",
    event_type: str = "role_assignment",
    action: str = "create",
    target: str = "/subscriptions/sub-001/resource_0",
    hours_ago: int = 1,
) -> Event:
    now = datetime.now(timezone.utc)
    ts = now - timedelta(hours=hours_ago)
    return Event(
        id=id,
        timestamp=ts,
        ingested_at=ts + timedelta(seconds=1),
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=Severity.INFO,
        metadata={"ip_address": "10.0.0.1"},
        raw={"raw_data": True},
    )


def _make_finding(
    id: str,
    event_ids: list[str],
    actor: str = "intruder@evil.com",
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime.now(timezone.utc),
        detector="new-actor",
        event_ids=event_ids,
        title=f"New actor: {actor} on azure",
        severity=Severity.WARN,
        status=status,
        annotations=[],
        metadata={"actor": actor, "sources": ["azure"]},
    )


def _setup_env(tmp_path: Path, actor: str = "intruder@evil.com") -> tuple[JsonlStore, str]:
    """Create a store with one event and one open finding, return (store, finding_id)."""
    store = JsonlStore(tmp_path)
    evt = _make_event("evt_001", actor=actor)
    store.append_events([evt])
    fnd = _make_finding("fnd_001", event_ids=["evt_001"], actor=actor)
    store.append_findings([fnd])
    return store, "fnd_001"


# --- Tests ---


class TestAckSetsStatus:
    def test_ack_sets_status_to_acked(self, tmp_path: Path) -> None:
        """ack a finding -> status is ACKED."""
        _setup_env(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["ack", "fnd_001", "--dir", str(tmp_path)])

        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert data["finding"]["status"] == "acked"

        # Verify persisted
        store = JsonlStore(tmp_path)
        findings = store.query_findings()
        fnd = [f for f in findings if f.id == "fnd_001"][0]
        assert fnd.status == FindingStatus.ACKED


class TestAckAddsAnnotation:
    def test_ack_adds_annotation_with_defaults(self, tmp_path: Path) -> None:
        """Annotation has action=acked, default author, and reason."""
        _setup_env(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["ack", "fnd_001", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        finding = data["finding"]
        assert len(finding["annotations"]) == 1
        ann = finding["annotations"][0]
        assert ann["action"] == "acked"
        assert ann["actor"] == "interactive"
        assert ann["reason"] is None

    def test_ack_adds_annotation_with_custom_author_and_reason(self, tmp_path: Path) -> None:
        """Annotation has custom author and reason when provided."""
        _setup_env(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ack", "fnd_001", "--author", "admin-user", "--reason", "Known contractor", "--dir", str(tmp_path)],
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        ann = data["finding"]["annotations"][0]
        assert ann["actor"] == "admin-user"
        assert ann["reason"] == "Known contractor"
        assert ann["action"] == "acked"


class TestAckAddsToKnownEntities:
    def test_ack_adds_actor_to_baseline_known_entities(self, tmp_path: Path) -> None:
        """After ack, actor from triggering events appears in baseline known_entities."""
        actor = "newguy@example.com"
        store = JsonlStore(tmp_path)
        evt = _make_event("evt_new", actor=actor)
        store.append_events([evt])
        fnd = _make_finding("fnd_new", event_ids=["evt_new"], actor=actor)
        store.append_findings([fnd])

        runner = CliRunner()
        result = runner.invoke(cli, ["ack", "fnd_new", "--dir", str(tmp_path)])
        assert result.exit_code == 0

        # Verify baseline now includes the actor (may be sanitized with markers)
        store2 = JsonlStore(tmp_path)
        baseline = store2.get_baseline()
        known_actors = baseline.known_entities.get("actors", [])
        assert any(actor in a for a in known_actors), (
            f"Expected {actor} in known_actors, got: {known_actors}"
        )


class TestAckUpdatesFrequencyTables:
    def test_ack_updates_frequency_tables(self, tmp_path: Path) -> None:
        """After ack, frequency tables include patterns from triggering events."""
        actor = "newguy@example.com"
        store = JsonlStore(tmp_path)
        evt = _make_event("evt_freq", actor=actor, source="azure", event_type="sign_in")
        store.append_events([evt])
        fnd = _make_finding("fnd_freq", event_ids=["evt_freq"], actor=actor)
        store.append_findings([fnd])

        runner = CliRunner()
        result = runner.invoke(cli, ["ack", "fnd_freq", "--dir", str(tmp_path)])
        assert result.exit_code == 0

        # Verify frequency tables updated
        store2 = JsonlStore(tmp_path)
        baseline = store2.get_baseline()
        freq = baseline.frequency_tables
        # The store's update_baseline uses key format "source:event_type:actor"
        matching = [k for k in freq if actor in k]
        assert len(matching) > 0, f"Expected frequency entry for {actor}, got keys: {list(freq.keys())}"


class TestAckNotFound:
    def test_ack_not_found(self, tmp_path: Path) -> None:
        """Unknown finding ID -> exit 1, error message."""
        # Empty store
        JsonlStore(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["ack", "fnd_nonexistent", "--dir", str(tmp_path)])

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "not found" in data["error"].lower() or "fnd_nonexistent" in data["error"]


class TestAckAlreadyAcked:
    def test_ack_already_acked(self, tmp_path: Path) -> None:
        """Double-ack -> exit 1, error message."""
        store = JsonlStore(tmp_path)
        evt = _make_event("evt_dbl", actor="someone@example.com")
        store.append_events([evt])
        fnd = _make_finding("fnd_dbl", event_ids=["evt_dbl"], actor="someone@example.com",
                            status=FindingStatus.ACKED)
        store.append_findings([fnd])

        runner = CliRunner()
        result = runner.invoke(cli, ["ack", "fnd_dbl", "--dir", str(tmp_path)])

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "error"
        assert "already" in data["error"].lower() or "acked" in data["error"].lower()

    def test_ack_twice_sequentially(self, tmp_path: Path) -> None:
        """Ack same finding twice: first succeeds, second fails."""
        _setup_env(tmp_path)
        runner = CliRunner()

        # First ack succeeds
        result1 = runner.invoke(cli, ["ack", "fnd_001", "--dir", str(tmp_path)])
        assert result1.exit_code == 0

        # Second ack fails
        result2 = runner.invoke(cli, ["ack", "fnd_001", "--dir", str(tmp_path)])
        assert result2.exit_code == 1
        data = json.loads(result2.output)
        assert data["status"] == "error"


class TestAckHumanOutput:
    def test_ack_human_output(self, tmp_path: Path) -> None:
        """--human flag produces readable output."""
        _setup_env(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["ack", "fnd_001", "--human", "--dir", str(tmp_path)])

        assert result.exit_code == 0
        assert "fnd_001" in result.output
        assert "acked" in result.output.lower()
