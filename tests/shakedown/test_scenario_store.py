"""Tests for ScenarioStore — in-memory Store for shakedown harness."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mallcop.schemas import (
    Annotation,
    Baseline,
    Checkpoint,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from tests.shakedown.scenario_store import Mutation, ScenarioStore


# ── Helpers ──


def _ts(hour: int = 12, day: int = 1) -> datetime:
    return datetime(2026, 3, day, hour, 0, 0, tzinfo=timezone.utc)


def _event(
    id: str = "evt-1",
    source: str = "azure",
    actor: str = "admin-user",
    hour: int = 12,
    day: int = 1,
) -> Event:
    return Event(
        id=id,
        timestamp=_ts(hour, day),
        ingested_at=_ts(hour, day),
        source=source,
        event_type="sign_in",
        actor=actor,
        action="login",
        target="portal",
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _finding(
    id: str = "fnd-1",
    detector: str = "new-actor",
    status: FindingStatus = FindingStatus.OPEN,
    severity: Severity = Severity.WARN,
    actor: str | None = None,
    hour: int = 12,
    day: int = 1,
) -> Finding:
    metadata = {}
    if actor:
        metadata["actor"] = actor
    return Finding(
        id=id,
        timestamp=_ts(hour, day),
        detector=detector,
        event_ids=["evt-1"],
        title=f"Finding {id}",
        severity=severity,
        status=status,
        annotations=[],
        metadata=metadata,
    )


def _baseline(**kwargs) -> Baseline:
    return Baseline(
        frequency_tables=kwargs.get("frequency_tables", {}),
        known_entities=kwargs.get("known_entities", {}),
        relationships=kwargs.get("relationships", {}),
    )


def _store(
    events: list[Event] | None = None,
    findings: list[Finding] | None = None,
    baseline: Baseline | None = None,
) -> ScenarioStore:
    return ScenarioStore(
        events=events or [],
        baseline=baseline or _baseline(),
        findings=findings or [],
    )


# ── Event query tests ──


def test_query_events_all():
    events = [_event(id="e1"), _event(id="e2"), _event(id="e3")]
    store = _store(events=events)
    result = store.query_events()
    assert len(result) == 3
    assert [e.id for e in result] == ["e1", "e2", "e3"]


def test_query_events_by_source():
    events = [
        _event(id="e1", source="azure"),
        _event(id="e2", source="github"),
        _event(id="e3", source="azure"),
    ]
    store = _store(events=events)
    result = store.query_events(source="github")
    assert len(result) == 1
    assert result[0].id == "e2"


def test_query_events_by_actor():
    events = [
        _event(id="e1", actor="alice"),
        _event(id="e2", actor="bob"),
        _event(id="e3", actor="alice"),
    ]
    store = _store(events=events)
    result = store.query_events(actor="bob")
    assert len(result) == 1
    assert result[0].id == "e2"


def test_query_events_since():
    events = [
        _event(id="e1", day=1),
        _event(id="e2", day=5),
        _event(id="e3", day=10),
    ]
    store = _store(events=events)
    result = store.query_events(since=_ts(day=5))
    assert len(result) == 2
    assert [e.id for e in result] == ["e2", "e3"]


def test_query_events_limit():
    events = [_event(id="e1"), _event(id="e2"), _event(id="e3")]
    store = _store(events=events)
    result = store.query_events(limit=1)
    assert len(result) == 1
    assert result[0].id == "e1"


# ── Finding query tests ──


def test_query_findings_no_filter():
    findings = [_finding(id="f1"), _finding(id="f2")]
    store = _store(findings=findings)
    result = store.query_findings()
    assert len(result) == 2


def test_query_findings_by_detector():
    findings = [
        _finding(id="f1", detector="new-actor"),
        _finding(id="f2", detector="volume-anomaly"),
        _finding(id="f3", detector="new-actor"),
    ]
    store = _store(findings=findings)
    result = store.query_findings(detector="volume-anomaly")
    assert len(result) == 1
    assert result[0].id == "f2"


def test_query_findings_by_actor():
    findings = [
        _finding(id="f1", actor="alice"),
        _finding(id="f2", actor="bob"),
        _finding(id="f3"),  # no actor metadata
    ]
    store = _store(findings=findings)
    result = store.query_findings(actor="alice")
    assert len(result) == 1
    assert result[0].id == "f1"


def test_query_findings_by_status():
    findings = [
        _finding(id="f1", status=FindingStatus.OPEN),
        _finding(id="f2", status=FindingStatus.RESOLVED),
        _finding(id="f3", status=FindingStatus.OPEN),
    ]
    store = _store(findings=findings)
    result = store.query_findings(status="resolved")
    assert len(result) == 1
    assert result[0].id == "f2"


# ── Baseline test ──


def test_get_baseline():
    bl = _baseline(
        frequency_tables={"azure:sign_in:alice": 5},
        known_entities={"actors": ["alice"]},
    )
    store = _store(baseline=bl)
    result = store.get_baseline()
    assert result.frequency_tables == {"azure:sign_in:alice": 5}
    assert result.known_entities == {"actors": ["alice"]}


# ── Mutation tracking tests ──


def test_update_finding_tracks_mutation():
    findings = [_finding(id="f1")]
    store = _store(findings=findings)

    store.update_finding("f1", status="resolved")

    mutations = store.get_mutations()
    assert len(mutations) == 1
    assert mutations[0].finding_id == "f1"
    assert mutations[0].field == "status"
    assert mutations[0].value == "resolved"
    assert isinstance(mutations[0].timestamp, datetime)


def test_update_finding_applies_annotation():
    findings = [_finding(id="f1")]
    store = _store(findings=findings)

    ann = Annotation(
        actor="triage",
        timestamp=_ts(),
        content="Looks benign",
        action="annotate",
        reason="known admin activity",
    )
    store.update_finding("f1", annotations=[ann])

    # Verify annotation was applied
    result = store.query_findings()
    f = [f for f in result if f.id == "f1"][0]
    assert len(f.annotations) == 1
    assert f.annotations[0].content == "Looks benign"

    # Verify mutation tracked
    mutations = store.get_mutations()
    assert len(mutations) == 1
    assert mutations[0].field == "annotations"


# ── No-op tests ──


def test_noop_methods():
    store = _store()

    # These should not raise
    store.append_events([_event()])
    store.append_findings([_finding()])
    store.set_checkpoint(
        Checkpoint(connector="azure", value="abc", updated_at=_ts())
    )
    store.update_baseline([_event()])

    # get_checkpoint always returns None
    assert store.get_checkpoint("azure") is None

    # append_events doesn't actually add (canned data is read-only)
    assert len(store.query_events()) == 0
