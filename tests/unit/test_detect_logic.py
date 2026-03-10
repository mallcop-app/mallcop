"""Unit tests for detect command logic."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.detect import run_detect
from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

_NOW = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)


def _make_event(
    eid: str = "e-1",
    source: str = "azure",
    event_type: str = "login",
    actor: str = "user@test.com",
) -> Event:
    return Event(
        id=eid,
        timestamp=_NOW,
        ingested_at=_NOW,
        source=source,
        event_type=event_type,
        actor=actor,
        action="SignIn",
        target="subscription",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _make_finding(
    fid: str = "f-1",
    severity: Severity = Severity.CRITICAL,
    event_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        id=fid,
        timestamp=_NOW,
        detector="test-detector",
        event_ids=event_ids or ["e-1"],
        title="Test finding",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={},
    )


def _make_baseline() -> Baseline:
    return Baseline(
        frequency_tables={},
        known_entities={"actors": []},
        relationships={},
    )


class StubDetector(DetectorBase):
    """A detector that returns pre-configured findings."""

    def __init__(self, findings: list[Finding] | None = None, sources=None, event_types=None):
        self._findings = findings or []
        self._sources = sources
        self._event_types = event_types

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        return self._findings

    def relevant_sources(self) -> list[str] | None:
        return self._sources

    def relevant_event_types(self) -> list[str] | None:
        return self._event_types


class ExplodingDetector(DetectorBase):
    """A detector that raises an exception."""

    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        raise RuntimeError("detector kaboom")

    def relevant_sources(self) -> list[str] | None:
        return None

    def relevant_event_types(self) -> list[str] | None:
        return None


# --- empty event list ---


@patch("mallcop.detect._get_detectors")
@patch("mallcop.app_integration.load_app_detectors", return_value=[])
@patch("mallcop.app_integration.get_configured_app_names", return_value=[])
def test_run_detect_empty_events(mock_app_names, mock_app_det, mock_get_det):
    """run_detect returns empty findings when no events provided."""
    mock_get_det.return_value = [StubDetector()]

    result = run_detect([], _make_baseline(), set())
    assert result == []


# --- normal detection produces findings ---


@patch("mallcop.detect._get_detectors")
@patch("mallcop.app_integration.load_app_detectors", return_value=[])
@patch("mallcop.app_integration.get_configured_app_names", return_value=[])
def test_run_detect_returns_findings(mock_app_names, mock_app_det, mock_get_det):
    """run_detect returns findings from detectors."""
    finding = _make_finding("f-1", Severity.CRITICAL, event_ids=["e-1"])
    mock_get_det.return_value = [StubDetector(findings=[finding])]

    events = [_make_event("e-1")]
    result = run_detect(events, _make_baseline(), set())

    assert len(result) == 1
    assert result[0].id == "f-1"
    assert result[0].severity == Severity.CRITICAL


# --- learning mode suppresses all findings to INFO ---


@patch("mallcop.detect._get_detectors")
@patch("mallcop.app_integration.load_app_detectors", return_value=[])
@patch("mallcop.app_integration.get_configured_app_names", return_value=[])
def test_run_detect_learning_mode_forces_info(mock_app_names, mock_app_det, mock_get_det):
    """Learning mode forces severity to INFO for findings from learning connectors."""
    finding = _make_finding("f-1", Severity.CRITICAL, event_ids=["e-1"])
    mock_get_det.return_value = [StubDetector(findings=[finding])]

    events = [_make_event("e-1", source="azure")]
    result = run_detect(events, _make_baseline(), learning_connectors={"azure"})

    assert len(result) == 1
    assert result[0].severity == Severity.INFO


@patch("mallcop.detect._get_detectors")
@patch("mallcop.app_integration.load_app_detectors", return_value=[])
@patch("mallcop.app_integration.get_configured_app_names", return_value=[])
def test_run_detect_learning_mode_does_not_affect_other_sources(
    mock_app_names, mock_app_det, mock_get_det
):
    """Learning mode only affects findings from learning connectors, not others."""
    finding = _make_finding("f-1", Severity.CRITICAL, event_ids=["e-1"])
    mock_get_det.return_value = [StubDetector(findings=[finding])]

    events = [_make_event("e-1", source="github")]
    result = run_detect(events, _make_baseline(), learning_connectors={"azure"})

    assert len(result) == 1
    assert result[0].severity == Severity.CRITICAL  # unchanged


# --- detector raises exception ---


@patch("mallcop.detect._get_detectors")
@patch("mallcop.app_integration.load_app_detectors", return_value=[])
@patch("mallcop.app_integration.get_configured_app_names", return_value=[])
def test_run_detect_detector_exception_propagates(mock_app_names, mock_app_det, mock_get_det):
    """An exception in a detector propagates (not silently swallowed)."""
    mock_get_det.return_value = [ExplodingDetector()]

    events = [_make_event("e-1")]
    with pytest.raises(RuntimeError, match="detector kaboom"):
        run_detect(events, _make_baseline(), set())


# --- source filtering ---


@patch("mallcop.detect._get_detectors")
@patch("mallcop.app_integration.load_app_detectors", return_value=[])
@patch("mallcop.app_integration.get_configured_app_names", return_value=[])
def test_run_detect_filters_events_by_source(mock_app_names, mock_app_det, mock_get_det):
    """Detectors only receive events matching their relevant_sources."""
    received_events: list[list[Event]] = []

    class CapturingDetector(DetectorBase):
        def detect(self, events, baseline):
            received_events.append(events)
            return []

        def relevant_sources(self):
            return ["github"]

        def relevant_event_types(self):
            return None

    mock_get_det.return_value = [CapturingDetector()]

    events = [
        _make_event("e-1", source="azure"),
        _make_event("e-2", source="github"),
    ]
    run_detect(events, _make_baseline(), set())

    assert len(received_events) == 1
    assert len(received_events[0]) == 1
    assert received_events[0][0].source == "github"
