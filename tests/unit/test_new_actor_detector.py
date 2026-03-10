"""Tests for new-actor detector."""

from datetime import datetime, timezone

import pytest

from mallcop.detectors.new_actor.detector import NewActorDetector
from mallcop.schemas import Baseline, Event, Finding, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str = "evt_001",
    source: str = "azure",
    timestamp: datetime | None = None,
    actor: str = "admin@example.com",
    event_type: str = "role_assignment",
    action: str = "create",
    target: str = "/subscriptions/123/roleAssignments/456",
    metadata: dict | None = None,
) -> Event:
    return Event(
        id=id,
        timestamp=timestamp or _utcnow(),
        ingested_at=_utcnow(),
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=Severity.WARN,
        metadata=metadata or {},
        raw={},
    )


def _make_baseline(actors: list[str] | None = None) -> Baseline:
    known = {}
    if actors is not None:
        known["actors"] = actors
    return Baseline(
        frequency_tables={},
        known_entities=known,
        relationships={},
    )


class TestNewActorDetector:
    def test_flags_unknown_actor(self) -> None:
        """An actor not in the baseline is flagged."""
        detector = NewActorDetector()
        events = [_make_event(actor="intruder@evil.com")]
        baseline = _make_baseline(actors=["admin@example.com"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert "intruder@evil.com" in findings[0].title
        assert findings[0].severity == Severity.WARN
        assert findings[0].detector == "new-actor"
        assert findings[0].event_ids == ["evt_001"]

    def test_does_not_flag_known_actor(self) -> None:
        """An actor already in the baseline is not flagged."""
        detector = NewActorDetector()
        events = [_make_event(actor="admin@example.com")]
        baseline = _make_baseline(actors=["admin@example.com"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_flags_multiple_unknown_actors(self) -> None:
        """Each unknown actor gets its own finding."""
        detector = NewActorDetector()
        events = [
            _make_event(id="evt_1", actor="intruder1@evil.com"),
            _make_event(id="evt_2", actor="intruder2@evil.com"),
        ]
        baseline = _make_baseline(actors=["admin@example.com"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 2
        actors_found = {f.title for f in findings}
        assert any("intruder1@evil.com" in t for t in actors_found)
        assert any("intruder2@evil.com" in t for t in actors_found)

    def test_empty_baseline_flags_all_actors(self) -> None:
        """With no known actors, every event actor is flagged."""
        detector = NewActorDetector()
        events = [_make_event(actor="anyone@example.com")]
        baseline = _make_baseline(actors=[])

        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    def test_no_actors_key_in_baseline_flags_all(self) -> None:
        """Baseline with no 'actors' key treats all actors as unknown."""
        detector = NewActorDetector()
        events = [_make_event(actor="anyone@example.com")]
        baseline = Baseline(frequency_tables={}, known_entities={}, relationships={})

        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    def test_same_unknown_actor_multiple_events_one_finding(self) -> None:
        """Multiple events from the same unknown actor produce one finding."""
        detector = NewActorDetector()
        events = [
            _make_event(id="evt_1", actor="intruder@evil.com", source="azure"),
            _make_event(id="evt_2", actor="intruder@evil.com", source="azure"),
        ]
        baseline = _make_baseline(actors=["admin@example.com"])

        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert set(findings[0].event_ids) == {"evt_1", "evt_2"}

    def test_title_includes_source(self) -> None:
        """Finding title includes the source connector."""
        detector = NewActorDetector()
        events = [_make_event(actor="intruder@evil.com", source="github")]
        baseline = _make_baseline(actors=[])

        findings = detector.detect(events, baseline)

        assert "github" in findings[0].title

    def test_finding_status_is_open(self) -> None:
        """Findings are created with status open."""
        detector = NewActorDetector()
        events = [_make_event(actor="intruder@evil.com")]
        baseline = _make_baseline(actors=[])

        findings = detector.detect(events, baseline)

        from mallcop.schemas import FindingStatus
        assert findings[0].status == FindingStatus.OPEN

    def test_relevant_sources_returns_none(self) -> None:
        """new-actor detector works on all sources."""
        detector = NewActorDetector()
        assert detector.relevant_sources() is None

    def test_relevant_event_types_returns_none(self) -> None:
        """new-actor detector works on all event types."""
        detector = NewActorDetector()
        assert detector.relevant_event_types() is None

    def test_no_events_no_findings(self) -> None:
        """No events produce no findings."""
        detector = NewActorDetector()
        findings = detector.detect([], _make_baseline(actors=["admin@example.com"]))
        assert len(findings) == 0
