"""Tests for unusual-timing detector."""

from datetime import datetime, timezone

import pytest

from mallcop.detectors.unusual_timing.detector import UnusualTimingDetector
from mallcop.schemas import Baseline, Event, FindingStatus, Severity

# A frequency table entry at a time that won't match Monday 03:00 (day=0, bucket=0).
# Tuesday hour_bucket=8 is a safe "other" slot.
_OTHER_SLOT = {"azure:role_assignment:other@example.com:1:8": 5}


def _make_event(
    id: str = "evt_001",
    source: str = "azure",
    event_type: str = "role_assignment",
    actor: str = "admin@example.com",
    action: str = "create",
    target: str = "/subscriptions/123",
    # Monday 03:00 UTC -> day_of_week=0, hour_bucket=0
    timestamp: datetime | None = None,
    metadata: dict | None = None,
) -> Event:
    return Event(
        id=id,
        timestamp=timestamp or datetime(2026, 3, 2, 3, 0, tzinfo=timezone.utc),  # Monday 03:00
        ingested_at=datetime.now(timezone.utc),
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=Severity.WARN,
        metadata=metadata or {},
        raw={},
    )


def _make_baseline(freq: dict[str, int] | None = None) -> Baseline:
    return Baseline(
        frequency_tables=freq or {},
        known_entities={},
        relationships={},
    )


class TestUnusualTimingDetector:
    def test_fires_on_zero_baseline_frequency(self) -> None:
        """Event at time with zero baseline frequency produces a finding."""
        detector = UnusualTimingDetector()
        # Monday 03:00 -> day=0, bucket=0
        events = [_make_event(actor="admin@example.com")]
        # Baseline has this actor at a DIFFERENT time (Tuesday bucket=8)
        baseline = _make_baseline({"azure:role_assignment:admin@example.com:1:8": 5})

        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert findings[0].detector == "unusual-timing"
        assert findings[0].severity == Severity.WARN
        assert "admin@example.com" in findings[0].title
        assert findings[0].event_ids == ["evt_001"]

    def test_no_finding_when_baseline_has_frequency(self) -> None:
        """Event at time with nonzero baseline frequency does not fire."""
        detector = UnusualTimingDetector()
        # Monday 03:00 -> day=0, bucket=0
        events = [_make_event(actor="admin@example.com")]
        # Baseline has this exact time slot
        baseline = _make_baseline({"azure:role_assignment:admin@example.com:0:0": 3})

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_groups_findings_by_actor(self) -> None:
        """Multiple unusual events from the same actor produce one finding."""
        detector = UnusualTimingDetector()
        events = [
            _make_event(id="evt_1", actor="admin@example.com", event_type="role_assignment"),
            _make_event(id="evt_2", actor="admin@example.com", event_type="sign_in"),
        ]
        # Baseline has data but not at this actor's time slots
        baseline = _make_baseline(_OTHER_SLOT)

        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert set(findings[0].event_ids) == {"evt_1", "evt_2"}

    def test_different_actors_get_separate_findings(self) -> None:
        """Two different actors with unusual timing get separate findings."""
        detector = UnusualTimingDetector()
        events = [
            _make_event(id="evt_1", actor="alice@example.com"),
            _make_event(id="evt_2", actor="bob@example.com"),
        ]
        # Baseline has data but not matching these actors' time slots
        baseline = _make_baseline(_OTHER_SLOT)

        findings = detector.detect(events, baseline)

        assert len(findings) == 2
        actors = {f.metadata["actor"] for f in findings}
        assert actors == {"alice@example.com", "bob@example.com"}

    def test_no_events_no_findings(self) -> None:
        """No events produce no findings."""
        detector = UnusualTimingDetector()
        findings = detector.detect([], _make_baseline(_OTHER_SLOT))
        assert len(findings) == 0

    def test_empty_baseline_returns_no_findings(self) -> None:
        """Empty frequency tables means no time patterns — detector skips."""
        detector = UnusualTimingDetector()
        events = [_make_event(actor="admin@example.com")]
        baseline = _make_baseline({})

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_finding_status_is_open(self) -> None:
        """Findings are created with status open."""
        detector = UnusualTimingDetector()
        events = [_make_event()]
        # Baseline has data but not at this event's time slot
        baseline = _make_baseline(_OTHER_SLOT)

        findings = detector.detect(events, baseline)

        assert findings[0].status == FindingStatus.OPEN

    def test_relevant_sources_returns_none(self) -> None:
        """unusual-timing works on all sources."""
        detector = UnusualTimingDetector()
        assert detector.relevant_sources() is None

    def test_relevant_event_types_returns_none(self) -> None:
        """unusual-timing works on all event types."""
        detector = UnusualTimingDetector()
        assert detector.relevant_event_types() is None

    def test_hour_bucket_boundaries(self) -> None:
        """Events at different hours map to correct buckets."""
        detector = UnusualTimingDetector()
        # Hour 7 -> bucket 4, Monday -> day 0
        evt = _make_event(
            timestamp=datetime(2026, 3, 2, 7, 30, tzinfo=timezone.utc),
        )
        # Baseline has bucket 4 on Monday for this actor
        baseline = _make_baseline({"azure:role_assignment:admin@example.com:0:4": 2})

        findings = detector.detect([evt], baseline)

        assert len(findings) == 0

    def test_weekend_vs_weekday(self) -> None:
        """An actor normal on Monday but unusual on Sunday gets flagged."""
        detector = UnusualTimingDetector()
        # Sunday 03:00 -> day=6, bucket=0
        evt = _make_event(
            timestamp=datetime(2026, 3, 1, 3, 0, tzinfo=timezone.utc),  # Sunday
        )
        # Baseline only has Monday bucket=0
        baseline = _make_baseline({"azure:role_assignment:admin@example.com:0:0": 5})

        findings = detector.detect([evt], baseline)

        assert len(findings) == 1

    def test_metadata_contains_unusual_events_info(self) -> None:
        """Finding metadata includes actor and event details."""
        detector = UnusualTimingDetector()
        events = [_make_event(actor="admin@example.com")]
        # Baseline has data but not at this event's time slot
        baseline = _make_baseline(_OTHER_SLOT)

        findings = detector.detect(events, baseline)

        assert findings[0].metadata["actor"] == "admin@example.com"
