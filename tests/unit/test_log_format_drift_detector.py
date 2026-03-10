"""Tests for log-format-drift detector."""

from datetime import datetime, timezone

import pytest

from mallcop.detectors.log_format_drift.detector import LogFormatDriftDetector
from mallcop.schemas import Baseline, Event, FindingStatus, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_parser_summary_event(
    id: str = "evt_001",
    app_name: str = "opensign",
    matched_count: int = 70,
    unmatched_count: int = 30,
    total_count: int = 100,
    unmatched_ratio: float = 0.3,
) -> Event:
    return Event(
        id=id,
        timestamp=_utcnow(),
        ingested_at=_utcnow(),
        source="container-logs",
        event_type="parser_summary",
        actor="mallcop",
        action="parse",
        target=app_name,
        severity=Severity.INFO,
        metadata={
            "matched_count": matched_count,
            "unmatched_count": unmatched_count,
            "total_count": total_count,
            "unmatched_ratio": unmatched_ratio,
            "app_name": app_name,
        },
        raw={},
    )


def _make_baseline() -> Baseline:
    return Baseline(
        frequency_tables={},
        known_entities={},
        relationships={},
    )


class TestLogFormatDriftDetector:
    def test_fires_when_unmatched_ratio_above_threshold(self) -> None:
        """Fires when unmatched_ratio > 0.3 (default threshold)."""
        detector = LogFormatDriftDetector()
        events = [_make_parser_summary_event(
            unmatched_ratio=0.6,
            unmatched_count=60,
            matched_count=40,
        )]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert findings[0].detector == "log-format-drift"
        assert "opensign" in findings[0].title
        assert "60%" in findings[0].title or "60.0%" in findings[0].title
        assert "mallcop discover-app opensign --refresh" in findings[0].title

    def test_does_not_fire_at_ratio_below_threshold(self) -> None:
        """Does NOT fire when unmatched_ratio is 0.2 (below default 0.3)."""
        detector = LogFormatDriftDetector()
        events = [_make_parser_summary_event(
            unmatched_ratio=0.2,
            unmatched_count=20,
            matched_count=80,
        )]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_does_not_fire_at_exact_threshold(self) -> None:
        """Does NOT fire when unmatched_ratio == 0.3 (must exceed, not equal)."""
        detector = LogFormatDriftDetector()
        events = [_make_parser_summary_event(
            unmatched_ratio=0.3,
            unmatched_count=30,
            matched_count=70,
        )]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

    def test_finding_includes_app_name(self) -> None:
        """Finding title includes the app name."""
        detector = LogFormatDriftDetector()
        events = [_make_parser_summary_event(
            app_name="myapp",
            unmatched_ratio=0.5,
            unmatched_count=50,
            matched_count=50,
        )]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert "myapp" in findings[0].title
        assert "mallcop discover-app myapp --refresh" in findings[0].title

    def test_finding_includes_refresh_command(self) -> None:
        """Finding message includes the refresh command."""
        detector = LogFormatDriftDetector()
        events = [_make_parser_summary_event(
            app_name="nextcloud",
            unmatched_ratio=0.45,
            unmatched_count=45,
            matched_count=55,
        )]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert len(findings) == 1
        assert "mallcop discover-app nextcloud --refresh" in findings[0].title

    def test_custom_threshold(self) -> None:
        """Supports custom threshold via constructor."""
        detector = LogFormatDriftDetector(threshold=0.5)
        # 0.45 is below 0.5 threshold — should not fire
        events = [_make_parser_summary_event(unmatched_ratio=0.45)]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert len(findings) == 0

        # 0.55 is above 0.5 threshold — should fire
        events2 = [_make_parser_summary_event(unmatched_ratio=0.55)]
        findings2 = detector.detect(events2, baseline)

        assert len(findings2) == 1

    def test_ignores_non_parser_summary_events(self) -> None:
        """Only processes parser_summary events."""
        detector = LogFormatDriftDetector()
        event = Event(
            id="evt_other",
            timestamp=_utcnow(),
            ingested_at=_utcnow(),
            source="container-logs",
            event_type="log_line",
            actor="mallcop",
            action="parse",
            target="opensign",
            severity=Severity.INFO,
            metadata={},
            raw={},
        )
        baseline = _make_baseline()

        findings = detector.detect([event], baseline)

        assert len(findings) == 0

    def test_multiple_apps_produce_separate_findings(self) -> None:
        """Each app with high drift gets its own finding."""
        detector = LogFormatDriftDetector()
        events = [
            _make_parser_summary_event(id="evt_1", app_name="app1", unmatched_ratio=0.5),
            _make_parser_summary_event(id="evt_2", app_name="app2", unmatched_ratio=0.6),
        ]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert any("app1" in t for t in titles)
        assert any("app2" in t for t in titles)

    def test_no_events_no_findings(self) -> None:
        """No events produce no findings."""
        detector = LogFormatDriftDetector()
        findings = detector.detect([], _make_baseline())
        assert len(findings) == 0

    def test_relevant_sources_returns_container_logs(self) -> None:
        """log-format-drift only processes container-logs source."""
        detector = LogFormatDriftDetector()
        assert detector.relevant_sources() == ["container-logs"]

    def test_relevant_event_types_returns_parser_summary(self) -> None:
        """log-format-drift only processes parser_summary events."""
        detector = LogFormatDriftDetector()
        assert detector.relevant_event_types() == ["parser_summary"]

    def test_finding_status_is_open(self) -> None:
        """Findings are created with status open."""
        detector = LogFormatDriftDetector()
        events = [_make_parser_summary_event(unmatched_ratio=0.5)]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert findings[0].status == FindingStatus.OPEN

    def test_finding_event_ids(self) -> None:
        """Finding references the parser_summary event that triggered it."""
        detector = LogFormatDriftDetector()
        events = [_make_parser_summary_event(id="evt_summary_1", unmatched_ratio=0.5)]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert findings[0].event_ids == ["evt_summary_1"]

    def test_finding_metadata_has_app_and_ratio(self) -> None:
        """Finding metadata includes app_name and unmatched_ratio."""
        detector = LogFormatDriftDetector()
        events = [_make_parser_summary_event(
            app_name="opensign", unmatched_ratio=0.6,
        )]
        baseline = _make_baseline()

        findings = detector.detect(events, baseline)

        assert findings[0].metadata["app_name"] == "opensign"
        assert findings[0].metadata["unmatched_ratio"] == 0.6
