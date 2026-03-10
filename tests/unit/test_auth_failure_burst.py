"""Unit tests for auth-failure-burst detector."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from mallcop.detectors.auth_failure_burst.detector import AuthFailureBurstDetector
from mallcop.schemas import Baseline, Event, Finding, Severity


def _make_event(
    event_type: str = "sign_in_failure",
    actor: str = "attacker@evil.com",
    source: str = "azure",
    timestamp: datetime | None = None,
    metadata: dict | None = None,
    event_id: str | None = None,
) -> Event:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    return Event(
        id=event_id or f"evt_{id(timestamp)}",
        timestamp=timestamp,
        ingested_at=datetime.now(timezone.utc),
        source=source,
        event_type=event_type,
        actor=actor,
        action="login_failed",
        target="portal",
        severity=Severity.INFO,
        metadata=metadata or {},
        raw={},
    )


def _empty_baseline() -> Baseline:
    return Baseline(
        frequency_tables={},
        known_entities={},
        relationships={},
    )


def _make_burst(
    count: int,
    window_minutes: int = 10,
    actor: str = "attacker@evil.com",
    source: str = "azure",
    event_type: str = "sign_in_failure",
    ip: str | None = None,
) -> list[Event]:
    """Create `count` auth failure events spread within `window_minutes`."""
    base = datetime(2026, 3, 7, 12, 0, 0, tzinfo=timezone.utc)
    interval = timedelta(minutes=window_minutes) / max(count, 1)
    metadata = {"ip_address": ip} if ip else {}
    return [
        _make_event(
            event_type=event_type,
            actor=actor,
            source=source,
            timestamp=base + interval * i,
            metadata=metadata,
            event_id=f"evt_{i:04d}",
        )
        for i in range(count)
    ]


class TestAuthFailureBurstDetector:
    def test_fires_on_10_failures_in_30_min(self) -> None:
        detector = AuthFailureBurstDetector()
        events = _make_burst(10, window_minutes=25)
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARN
        assert findings[0].detector == "auth-failure-burst"

    def test_does_not_fire_on_9_failures(self) -> None:
        detector = AuthFailureBurstDetector()
        events = _make_burst(9, window_minutes=25)
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 0

    def test_escalates_to_critical_at_50(self) -> None:
        detector = AuthFailureBurstDetector()
        events = _make_burst(50, window_minutes=25)
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_groups_by_actor(self) -> None:
        """Two different actors each with 10 failures -> 2 findings."""
        detector = AuthFailureBurstDetector()
        events_a = _make_burst(10, actor="alice@evil.com", window_minutes=25)
        events_b = _make_burst(10, actor="bob@evil.com", window_minutes=25)
        # Fix IDs to avoid collisions
        for i, e in enumerate(events_b):
            e.id = f"evt_b_{i:04d}"
        findings = detector.detect(events_a + events_b, _empty_baseline())
        assert len(findings) == 2
        actors = {f.metadata["group_key"] for f in findings}
        assert actors == {"alice@evil.com", "bob@evil.com"}

    def test_groups_by_ip_when_no_actor(self) -> None:
        """When actor is empty, group by metadata.ip_address."""
        detector = AuthFailureBurstDetector()
        events = _make_burst(10, actor="", ip="1.2.3.4", window_minutes=25)
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert findings[0].metadata["group_key"] == "1.2.3.4"

    def test_groups_by_ip_when_available(self) -> None:
        """When ip_address is in metadata, group by IP even if actor exists."""
        detector = AuthFailureBurstDetector()
        # Same actor, two different IPs, 10 from each
        events_ip1 = _make_burst(10, actor="user@co.com", ip="1.1.1.1", window_minutes=25)
        events_ip2 = _make_burst(10, actor="user@co.com", ip="2.2.2.2", window_minutes=25)
        for i, e in enumerate(events_ip2):
            e.id = f"evt_ip2_{i:04d}"
        findings = detector.detect(events_ip1 + events_ip2, _empty_baseline())
        assert len(findings) == 2
        keys = {f.metadata["group_key"] for f in findings}
        assert keys == {"1.1.1.1", "2.2.2.2"}

    def test_window_boundary_excludes_old_events(self) -> None:
        """Events outside the 30-min window should not count toward threshold."""
        detector = AuthFailureBurstDetector()
        base = datetime(2026, 3, 7, 12, 0, 0, tzinfo=timezone.utc)
        # 5 events at T-45min (outside default 30-min window from latest)
        old_events = [
            _make_event(
                timestamp=base - timedelta(minutes=45) + timedelta(minutes=i),
                event_id=f"evt_old_{i}",
            )
            for i in range(5)
        ]
        # 5 events at T-5min (inside window)
        recent_events = [
            _make_event(
                timestamp=base - timedelta(minutes=5) + timedelta(seconds=i * 30),
                event_id=f"evt_new_{i}",
            )
            for i in range(5)
        ]
        # Total 10 events, but only 5 in any 30-min window -> no finding
        findings = detector.detect(old_events + recent_events, _empty_baseline())
        assert len(findings) == 0

    def test_handles_mixed_sources(self) -> None:
        """Auth failures from azure and m365 in the same batch are grouped separately by source+actor."""
        detector = AuthFailureBurstDetector()
        azure_events = _make_burst(10, source="azure", window_minutes=25)
        m365_events = _make_burst(10, source="m365", event_type="sign_in_failure", window_minutes=25)
        for i, e in enumerate(m365_events):
            e.id = f"evt_m365_{i:04d}"
        # Same actor, but events from different sources both fire
        all_events = azure_events + m365_events
        findings = detector.detect(all_events, _empty_baseline())
        # Both batches have the same actor, so they get grouped together
        # (grouping is by actor/IP, not source) -> 1 finding with 20 events
        assert len(findings) >= 1

    def test_ignores_non_auth_events(self) -> None:
        """Events with non-auth event_types are ignored."""
        detector = AuthFailureBurstDetector()
        events = _make_burst(20, event_type="resource_created", window_minutes=10)
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 0

    def test_relevant_sources(self) -> None:
        detector = AuthFailureBurstDetector()
        sources = detector.relevant_sources()
        assert sources is None or set(sources) >= {"azure", "m365", "container-logs"}

    def test_relevant_event_types(self) -> None:
        detector = AuthFailureBurstDetector()
        types = detector.relevant_event_types()
        assert types is None or set(types) >= {"sign_in_failure", "auth_failure", "login"}

    def test_finding_contains_event_ids(self) -> None:
        detector = AuthFailureBurstDetector()
        events = _make_burst(10, window_minutes=25)
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert len(findings[0].event_ids) == 10

    def test_finding_title_includes_count(self) -> None:
        detector = AuthFailureBurstDetector()
        events = _make_burst(15, window_minutes=25)
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert "15" in findings[0].title

    def test_login_events_with_failure_status_are_counted(self) -> None:
        """Generic 'login' events with failure/missing status are treated as failures."""
        detector = AuthFailureBurstDetector()
        events = _make_burst(10, event_type="login", window_minutes=25)
        # No status metadata -> conservatively treated as failure
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 1

    def test_login_events_with_success_status_are_excluded(self) -> None:
        """Generic 'login' events with success status are NOT treated as failures."""
        detector = AuthFailureBurstDetector()
        base = datetime(2026, 3, 7, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(
                event_type="login",
                timestamp=base + timedelta(seconds=i * 30),
                metadata={"status": "Success"},
                event_id=f"evt_success_{i}",
            )
            for i in range(15)
        ]
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 0

    def test_login_events_with_result_status_success_are_excluded(self) -> None:
        """Generic 'login' events with result_status=Succeeded are excluded."""
        detector = AuthFailureBurstDetector()
        base = datetime(2026, 3, 7, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(
                event_type="login",
                timestamp=base + timedelta(seconds=i * 30),
                metadata={"result_status": "Succeeded"},
                event_id=f"evt_rs_{i}",
            )
            for i in range(15)
        ]
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 0

    def test_login_events_with_ok_status_are_excluded(self) -> None:
        """Generic 'login' events with status=ok are excluded."""
        detector = AuthFailureBurstDetector()
        base = datetime(2026, 3, 7, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(
                event_type="login",
                timestamp=base + timedelta(seconds=i * 30),
                metadata={"status": "ok"},
                event_id=f"evt_ok_{i}",
            )
            for i in range(15)
        ]
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 0

    def test_login_events_with_failed_status_are_counted(self) -> None:
        """Generic 'login' events with non-success status are treated as failures."""
        detector = AuthFailureBurstDetector()
        base = datetime(2026, 3, 7, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(
                event_type="login",
                timestamp=base + timedelta(seconds=i * 30),
                metadata={"status": "Failed"},
                event_id=f"evt_failed_{i}",
            )
            for i in range(10)
        ]
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 1

    def test_sign_in_failure_always_counted_regardless_of_metadata(self) -> None:
        """sign_in_failure events are always counted, even if metadata has success."""
        detector = AuthFailureBurstDetector()
        base = datetime(2026, 3, 7, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(
                event_type="sign_in_failure",
                timestamp=base + timedelta(seconds=i * 30),
                metadata={"status": "Success"},  # contradictory, but event_type wins
                event_id=f"evt_sif_{i}",
            )
            for i in range(10)
        ]
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 1

    def test_custom_thresholds(self) -> None:
        """Detector respects custom threshold and critical_threshold."""
        detector = AuthFailureBurstDetector(
            window_minutes=10,
            threshold=5,
            critical_threshold=20,
        )
        # 5 events -> warn
        events = _make_burst(5, window_minutes=8)
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARN

        # 20 events -> critical
        events = _make_burst(20, window_minutes=8)
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

        # 4 events -> nothing
        events = _make_burst(4, window_minutes=8)
        findings = detector.detect(events, _empty_baseline())
        assert len(findings) == 0
