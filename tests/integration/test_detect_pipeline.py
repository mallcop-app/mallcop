"""Integration test: store → baseline → detect → findings written."""

from datetime import datetime, timedelta, timezone

import pytest

from mallcop.detect import run_detect
from mallcop.schemas import Event, Severity, FindingStatus
from mallcop.store import JsonlStore


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str,
    actor: str,
    source: str = "azure",
    event_type: str = "role_assignment",
    timestamp: datetime | None = None,
) -> Event:
    return Event(
        id=id,
        timestamp=timestamp or _utcnow(),
        ingested_at=_utcnow(),
        source=source,
        event_type=event_type,
        actor=actor,
        action="create",
        target="/subscriptions/123",
        severity=Severity.WARN,
        metadata={},
        raw={},
    )


class TestDetectPipeline:
    def test_full_pipeline_known_and_unknown_actors(self, tmp_path) -> None:
        """End-to-end: events → store → baseline → detect → findings persisted."""
        store = JsonlStore(tmp_path)

        # Phase 1: baseline events (known actors)
        baseline_events = [
            _make_event("evt_1", actor="admin@example.com"),
            _make_event("evt_2", actor="deploy-bot@example.com"),
        ]
        store.append_events(baseline_events)
        store.update_baseline(baseline_events)

        # Phase 2: new events with one known and one unknown actor
        new_events = [
            _make_event("evt_3", actor="admin@example.com"),
            _make_event("evt_4", actor="intruder@evil.com"),
        ]
        store.append_events(new_events)

        # Run detect
        baseline = store.get_baseline()
        findings = run_detect(new_events, baseline, learning_connectors=set())

        # Persist findings
        store.append_findings(findings)

        # Verify: finding(s) for the intruder (new-actor + possibly unusual-timing)
        assert len(findings) >= 1
        new_actor_findings = [f for f in findings if f.detector == "new-actor"]
        assert len(new_actor_findings) == 1
        assert "intruder@evil.com" in new_actor_findings[0].title
        assert new_actor_findings[0].status == FindingStatus.OPEN
        assert new_actor_findings[0].severity == Severity.WARN

        # Verify findings persisted and queryable
        stored_findings = store.query_findings(status="open")
        assert len(stored_findings) == len(findings)
        stored_ids = {f.id for f in stored_findings}
        assert new_actor_findings[0].id in stored_ids

    def test_learning_mode_integration(self, tmp_path) -> None:
        """Learning mode suppresses severity in detect pipeline."""
        store = JsonlStore(tmp_path)

        # Recent events (within learning period)
        events = [_make_event("evt_1", actor="new-user@example.com")]
        store.append_events(events)
        store.update_baseline(events)

        # New unknown actor
        new_events = [_make_event("evt_2", actor="intruder@evil.com")]
        store.append_events(new_events)

        baseline = store.get_baseline()
        findings = run_detect(new_events, baseline, learning_connectors={"azure"})

        assert len(findings) >= 1
        # All findings from learning connector should have severity forced to INFO
        for f in findings:
            assert f.severity == Severity.INFO  # forced by learning mode

    def test_findings_persist_to_disk(self, tmp_path) -> None:
        """Findings survive store reload from disk."""
        store = JsonlStore(tmp_path)
        events = [_make_event("evt_1", actor="intruder@evil.com")]
        store.append_events(events)
        store.update_baseline(events)

        baseline = store.get_baseline()
        findings = run_detect(
            [_make_event("evt_2", actor="new-person@example.com")],
            baseline,
            learning_connectors=set(),
        )
        store.append_findings(findings)

        # Reload store from disk
        store2 = JsonlStore(tmp_path)
        reloaded = store2.query_findings()
        assert len(reloaded) == len(findings)
        reloaded_ids = {f.id for f in reloaded}
        for f in findings:
            assert f.id in reloaded_ids
