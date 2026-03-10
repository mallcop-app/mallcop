"""Tests for mallcop detect command logic."""

from datetime import datetime, timedelta, timezone

import pytest

from mallcop.detect import run_detect
from mallcop.schemas import Baseline, Event, Finding, Severity, FindingStatus


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    id: str = "evt_001",
    source: str = "azure",
    timestamp: datetime | None = None,
    actor: str = "admin@example.com",
    event_type: str = "role_assignment",
    action: str = "create",
    target: str = "/subscriptions/123",
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


class TestRunDetect:
    def test_produces_findings_for_unknown_actor(self) -> None:
        """detect produces findings when unknown actors appear."""
        events = [_make_event(actor="intruder@evil.com")]
        baseline = _make_baseline(actors=["admin@example.com"])

        findings = run_detect(events, baseline, learning_connectors=set())

        assert len(findings) == 1
        assert "intruder@evil.com" in findings[0].title

    def test_no_findings_for_known_actor(self) -> None:
        """detect produces no findings for known actors."""
        events = [_make_event(actor="admin@example.com")]
        baseline = _make_baseline(actors=["admin@example.com"])

        findings = run_detect(events, baseline, learning_connectors=set())

        assert len(findings) == 0

    def test_learning_mode_forces_severity_to_info(self) -> None:
        """When a connector is in learning mode, findings severity is forced to INFO."""
        events = [_make_event(actor="intruder@evil.com", source="azure")]
        baseline = _make_baseline(actors=[])

        findings = run_detect(events, baseline, learning_connectors={"azure"})

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_non_learning_connector_keeps_severity(self) -> None:
        """When a connector is NOT in learning mode, severity is from detector."""
        events = [_make_event(actor="intruder@evil.com", source="azure")]
        baseline = _make_baseline(actors=[])

        findings = run_detect(events, baseline, learning_connectors=set())

        assert len(findings) == 1
        assert findings[0].severity == Severity.WARN

    def test_mixed_connectors_learning_and_live(self) -> None:
        """Only events from learning connectors get severity forced to INFO."""
        events = [
            _make_event(id="evt_1", actor="intruder@evil.com", source="azure"),
            _make_event(id="evt_2", actor="intruder2@evil.com", source="github"),
        ]
        baseline = _make_baseline(actors=[])

        findings = run_detect(events, baseline, learning_connectors={"azure"})

        azure_findings = [f for f in findings if "azure" in f.title.lower() or "intruder@evil.com" in f.title]
        github_findings = [f for f in findings if "github" in f.title.lower() or "intruder2@evil.com" in f.title]

        # Azure is learning -> INFO
        assert all(f.severity == Severity.INFO for f in azure_findings)
        # GitHub is live -> WARN
        assert all(f.severity == Severity.WARN for f in github_findings)

    def test_returns_summary(self) -> None:
        """run_detect returns findings list."""
        events = [_make_event(actor="intruder@evil.com")]
        baseline = _make_baseline(actors=[])

        findings = run_detect(events, baseline, learning_connectors=set())

        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)
