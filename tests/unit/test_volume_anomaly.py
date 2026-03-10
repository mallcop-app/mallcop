"""Unit tests for volume-anomaly detector."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mallcop.detectors.volume_anomaly.detector import VolumeAnomalyDetector
from mallcop.schemas import Baseline, Event, FindingStatus, Severity


def _make_event(
    source: str = "azure",
    event_type: str = "sign_in",
    actor: str = "alice@example.com",
    event_id: str | None = None,
) -> Event:
    return Event(
        id=event_id or f"evt_{id(source)}_{event_type}",
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        source=source,
        event_type=event_type,
        actor=actor,
        action="test",
        target="resource",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _make_events(
    count: int,
    source: str = "azure",
    event_type: str = "sign_in",
    actor: str = "alice@example.com",
) -> list[Event]:
    return [
        Event(
            id=f"evt_{i}_{source}_{event_type}",
            timestamp=datetime.now(timezone.utc),
            ingested_at=datetime.now(timezone.utc),
            source=source,
            event_type=event_type,
            actor=actor,
            action="test",
            target="resource",
            severity=Severity.INFO,
            metadata={},
            raw={},
        )
        for i in range(count)
    ]


def _make_baseline(freq: dict[str, int]) -> Baseline:
    return Baseline(
        frequency_tables=freq,
        known_entities={},
        relationships={},
    )


class TestVolumeAnomalyDetector:
    def test_fires_at_3x_baseline(self) -> None:
        """When current volume is 3x+ baseline, a finding should fire."""
        # Baseline: 10 events for azure:sign_in (spread across actors)
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 5,
            "azure:sign_in:bob@example.com": 5,
        })
        # Current batch: 31 events (> 3.0 * 10 = 30)
        events = _make_events(31, source="azure", event_type="sign_in")

        detector = VolumeAnomalyDetector()
        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        f = findings[0]
        assert f.detector == "volume-anomaly"
        assert f.severity == Severity.WARN
        assert f.status == FindingStatus.OPEN
        assert "azure" in f.title
        assert "sign_in" in f.title
        assert f.metadata["source"] == "azure"
        assert f.metadata["event_type"] == "sign_in"
        assert f.metadata["current_count"] == 31
        assert f.metadata["baseline_count"] == 10
        assert f.metadata["ratio"] == 3.0

    def test_does_not_fire_at_2x(self) -> None:
        """When current volume is 2x baseline (below threshold), no finding."""
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 10,
        })
        # 20 events = 2x baseline (below default 3x threshold)
        events = _make_events(20, source="azure", event_type="sign_in")

        detector = VolumeAnomalyDetector()
        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_does_not_fire_at_exactly_3x(self) -> None:
        """Exactly 3x should NOT fire (must EXCEED, not equal)."""
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 10,
        })
        # 30 events = exactly 3x baseline
        events = _make_events(30, source="azure", event_type="sign_in")

        detector = VolumeAnomalyDetector()
        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_skips_zero_baseline(self) -> None:
        """Groups with zero baseline count should not fire (new, not anomalous)."""
        baseline = _make_baseline({})  # No baseline for this source:event_type
        events = _make_events(100, source="azure", event_type="sign_in")

        detector = VolumeAnomalyDetector()
        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_respects_min_baseline_count(self) -> None:
        """Don't fire when baseline count is below min_baseline_count."""
        # Baseline has only 3 events (below default min_baseline_count=5)
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 3,
        })
        # 100 events = way above 3x * 3 = 9, but baseline too small
        events = _make_events(100, source="azure", event_type="sign_in")

        detector = VolumeAnomalyDetector()
        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_fires_when_baseline_meets_min_count(self) -> None:
        """Should fire when baseline count equals min_baseline_count and volume exceeds ratio."""
        # Baseline has exactly 5 events (meets default min_baseline_count=5)
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 5,
        })
        # 16 events > 3.0 * 5 = 15
        events = _make_events(16, source="azure", event_type="sign_in")

        detector = VolumeAnomalyDetector()
        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    def test_custom_ratio(self) -> None:
        """Custom ratio parameter should be respected."""
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 10,
        })
        # 21 events > 2.0 * 10 = 20
        events = _make_events(21, source="azure", event_type="sign_in")

        detector = VolumeAnomalyDetector(ratio=2.0)
        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    def test_custom_min_baseline_count(self) -> None:
        """Custom min_baseline_count should be respected."""
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 2,
        })
        # 7 events > 3.0 * 2 = 6, and min_baseline_count=1
        events = _make_events(7, source="azure", event_type="sign_in")

        detector = VolumeAnomalyDetector(min_baseline_count=1)
        findings = detector.detect(events, baseline)

        assert len(findings) == 1

    def test_multiple_groups(self) -> None:
        """Each (source, event_type) group is evaluated independently."""
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 5,
            "github:push:bob@example.com": 10,
        })
        # Azure: 16 > 3*5=15 → fires
        # GitHub: 20 = 2*10 → does not fire
        events = (
            _make_events(16, source="azure", event_type="sign_in")
            + _make_events(20, source="github", event_type="push")
        )

        detector = VolumeAnomalyDetector()
        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert findings[0].metadata["source"] == "azure"

    def test_sums_across_actors_in_baseline(self) -> None:
        """Baseline volumes are summed across all actors for the same (source, event_type)."""
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 3,
            "azure:sign_in:bob@example.com": 3,
            "azure:sign_in:carol@example.com": 4,
        })
        # Total baseline for azure:sign_in = 10
        # 31 > 3*10=30 → fires
        events = _make_events(31, source="azure", event_type="sign_in")

        detector = VolumeAnomalyDetector()
        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert findings[0].metadata["baseline_count"] == 10

    def test_relevant_sources_none(self) -> None:
        """Volume anomaly works on all sources."""
        detector = VolumeAnomalyDetector()
        assert detector.relevant_sources() is None

    def test_relevant_event_types_none(self) -> None:
        """Volume anomaly works on all event types."""
        detector = VolumeAnomalyDetector()
        assert detector.relevant_event_types() is None

    def test_event_ids_included_in_finding(self) -> None:
        """All events in the anomalous group should be referenced."""
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 5,
        })
        events = _make_events(16, source="azure", event_type="sign_in")

        detector = VolumeAnomalyDetector()
        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert len(findings[0].event_ids) == 16

    def test_empty_events(self) -> None:
        """No events means no findings."""
        baseline = _make_baseline({
            "azure:sign_in:alice@example.com": 10,
        })

        detector = VolumeAnomalyDetector()
        findings = detector.detect([], baseline)

        assert len(findings) == 0
