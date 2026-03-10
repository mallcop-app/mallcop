"""Tests for unusual-resource-access detector."""

from __future__ import annotations

from datetime import datetime, timezone

from mallcop.detectors.unusual_resource_access.detector import UnusualResourceAccessDetector
from mallcop.schemas import Baseline, Event, Severity


def _make_event(
    actor: str = "alice@corp.com",
    target: str = "/subscriptions/sub-1",
    id: str = "evt_001",
) -> Event:
    now = datetime.now(timezone.utc)
    return Event(
        id=id,
        timestamp=now,
        ingested_at=now,
        source="azure",
        event_type="resource_access",
        actor=actor,
        action="read",
        target=target,
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _make_baseline(
    known_actors: list[str] | None = None,
    relationships: dict | None = None,
) -> Baseline:
    actors = known_actors or []
    return Baseline(
        frequency_tables={},
        known_entities={"actors": actors, "sources": ["azure"]},
        relationships=relationships or {},
    )


class TestUnusualResourceAccess:
    """unusual-resource-access detector tests."""

    def test_known_actor_touches_new_resource_fires(self) -> None:
        """Actor with established relationships touches new resource -> finding."""
        detector = UnusualResourceAccessDetector()
        baseline = _make_baseline(
            known_actors=["alice@corp.com"],
            relationships={
                "alice@corp.com:/subscriptions/sub-1": {"count": 10, "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-15T00:00:00+00:00"},
                "alice@corp.com:/subscriptions/sub-2": {"count": 5, "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-10T00:00:00+00:00"},
            },
        )
        event = _make_event(actor="alice@corp.com", target="/subscriptions/sub-NEW")

        findings = detector.detect([event], baseline)

        assert len(findings) == 1
        assert findings[0].detector == "unusual-resource-access"
        assert findings[0].metadata["actor"] == "alice@corp.com"
        assert findings[0].metadata["target"] == "/subscriptions/sub-NEW"
        assert findings[0].metadata["known_targets_count"] == 2

    def test_known_actor_touches_known_resource_no_finding(self) -> None:
        """Actor with established relationships touches known resource -> no finding."""
        detector = UnusualResourceAccessDetector()
        baseline = _make_baseline(
            known_actors=["alice@corp.com"],
            relationships={
                "alice@corp.com:/subscriptions/sub-1": {"count": 10, "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-15T00:00:00+00:00"},
            },
        )
        event = _make_event(actor="alice@corp.com", target="/subscriptions/sub-1")

        findings = detector.detect([event], baseline)

        assert len(findings) == 0

    def test_actor_below_threshold_suppressed(self) -> None:
        """Actor with < 5 total events -> no finding (still learning)."""
        detector = UnusualResourceAccessDetector()
        baseline = _make_baseline(
            known_actors=["alice@corp.com"],
            relationships={
                "alice@corp.com:/subscriptions/sub-1": {"count": 3, "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-05T00:00:00+00:00"},
            },
        )
        event = _make_event(actor="alice@corp.com", target="/subscriptions/sub-NEW")

        findings = detector.detect([event], baseline)

        assert len(findings) == 0

    def test_new_actor_not_in_known_entities_no_finding(self) -> None:
        """New actor (not in known_entities) -> no finding (new-actor detector handles this)."""
        detector = UnusualResourceAccessDetector()
        baseline = _make_baseline(
            known_actors=["alice@corp.com"],
            relationships={
                "alice@corp.com:/subscriptions/sub-1": {"count": 10, "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-15T00:00:00+00:00"},
            },
        )
        event = _make_event(actor="evil@hacker.com", target="/subscriptions/sub-1")

        findings = detector.detect([event], baseline)

        assert len(findings) == 0

    def test_actor_no_relationships_no_finding(self) -> None:
        """Actor with no relationship data -> no finding (nothing to compare against)."""
        detector = UnusualResourceAccessDetector()
        baseline = _make_baseline(
            known_actors=["alice@corp.com"],
            relationships={},
        )
        event = _make_event(actor="alice@corp.com", target="/subscriptions/sub-1")

        findings = detector.detect([event], baseline)

        assert len(findings) == 0
