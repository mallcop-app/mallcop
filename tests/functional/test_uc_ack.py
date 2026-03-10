"""UC: Ack finding suppresses future detection of the acked pattern.

Functional test: ack an actor -> run detect again -> no new finding for that actor.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.detect import run_detect
from mallcop.schemas import (
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


def _make_event(
    id: str,
    actor: str,
    source: str = "azure",
    event_type: str = "role_assignment",
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
        action="create",
        target="/subscriptions/sub-001/resource",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


class TestAckSuppressesFutureDetection:
    def test_ack_actor_then_detect_no_new_finding(self, tmp_path: Path) -> None:
        """Ack an actor -> run detect again -> no new finding for that actor.

        Flow:
        1. Create events from unknown actor
        2. Run detect -> produces finding
        3. Ack the finding (updates baseline with actor)
        4. Add more events from same actor
        5. Run detect again -> no new finding for that actor
        """
        root = tmp_path
        store = JsonlStore(root)

        # Step 1: Events from unknown actor
        unknown_actor = "contractor@external.com"
        events_batch1 = [
            _make_event("evt_a1", actor=unknown_actor, hours_ago=2),
            _make_event("evt_a2", actor=unknown_actor, hours_ago=1),
        ]
        store.append_events(events_batch1)

        # Step 2: Detect -> should find unknown actor
        all_events = store.query_events()
        baseline = store.get_baseline()
        findings = run_detect(all_events, baseline, learning_connectors=set())

        assert len(findings) >= 1
        # Actor may be sanitized with [USER_DATA_BEGIN/END] markers
        # Filter to new-actor detector (other detectors like unusual-timing may also fire)
        actor_findings = [
            f for f in findings
            if unknown_actor in str(f.metadata.get("actor", ""))
            and f.detector == "new-actor"
        ]
        assert len(actor_findings) == 1, f"Expected 1 new-actor finding for {unknown_actor}, got {len(actor_findings)}"

        # Persist the finding
        store.append_findings(actor_findings)
        finding_id = actor_findings[0].id

        # Step 3: Ack the finding via CLI
        runner = CliRunner()
        result = runner.invoke(cli, ["ack", finding_id, "--dir", str(root)])
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"

        # Step 4: More events from same actor
        events_batch2 = [
            _make_event("evt_a3", actor=unknown_actor, hours_ago=0),
        ]
        # Need a fresh store since ack updated baseline on disk
        store2 = JsonlStore(root)
        store2.append_events(events_batch2)

        # Step 5: Detect again -> no new finding for that actor
        all_events2 = store2.query_events()
        baseline2 = store2.get_baseline()

        # Verify the actor is now known (may be sanitized)
        known_actors = baseline2.known_entities.get("actors", [])
        assert any(unknown_actor in a for a in known_actors), (
            f"Expected {unknown_actor} in known_actors after ack, got: {known_actors}"
        )

        findings2 = run_detect(all_events2, baseline2, learning_connectors=set())
        # Filter to new-actor detector only (unusual-timing may still fire on empty freq tables)
        actor_findings2 = [
            f for f in findings2
            if unknown_actor in str(f.metadata.get("actor", ""))
            and f.detector == "new-actor"
        ]
        assert len(actor_findings2) == 0, (
            f"Expected no new-actor findings for {unknown_actor} after ack, got {len(actor_findings2)}"
        )

    def test_ack_one_actor_does_not_suppress_other_actors(self, tmp_path: Path) -> None:
        """Acking one actor doesn't suppress findings for a different unknown actor."""
        root = tmp_path
        store = JsonlStore(root)

        actor_a = "alice@example.com"
        actor_b = "bob@example.com"

        events = [
            _make_event("evt_ka", actor=actor_a, hours_ago=2),
            _make_event("evt_su", actor=actor_b, hours_ago=1),
        ]
        store.append_events(events)

        # Detect -> both unknown
        baseline = store.get_baseline()
        findings = run_detect(store.query_events(), baseline, learning_connectors=set())
        finding_a = [
            f for f in findings
            if actor_a in str(f.metadata.get("actor", ""))
            and f.detector == "new-actor"
        ]
        assert len(finding_a) == 1
        store.append_findings(finding_a)

        # Ack only actor_a
        runner = CliRunner()
        result = runner.invoke(cli, ["ack", finding_a[0].id, "--dir", str(root)])
        assert result.exit_code == 0

        # Detect again: actor_b should still be flagged
        store2 = JsonlStore(root)
        baseline2 = store2.get_baseline()
        findings2 = run_detect(store2.query_events(), baseline2, learning_connectors=set())
        actor_b_findings = [
            f for f in findings2
            if actor_b in str(f.metadata.get("actor", ""))
            and f.detector == "new-actor"
        ]
        assert len(actor_b_findings) == 1, (
            f"Expected new-actor finding for {actor_b}, got {len(actor_b_findings)}"
        )
