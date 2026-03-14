"""Tests for tool enrichment: local time + related actors in read-events and check-baseline."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from mallcop.schemas import ActorProfile, Baseline, Event, Finding, FindingStatus, Severity
from mallcop.tools import ToolContext
from mallcop.tools.baseline import check_baseline
from mallcop.tools.events import read_events


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    actor: str = "alice",
    target: str = "subscriptions/sub-1/resourceGroups/atom-rg/vm-1",
    source: str = "azure",
    event_type: str = "vm_start",
    timestamp: datetime | None = None,
    evt_id: str = "evt_001",
) -> Event:
    if timestamp is None:
        timestamp = datetime(2024, 6, 15, 14, 0, tzinfo=timezone.utc)  # 14:00 UTC
    return Event(
        id=evt_id,
        timestamp=timestamp,
        ingested_at=timestamp,
        source=source,
        event_type=event_type,
        actor=actor,
        action="start",
        target=target,
        severity=Severity.INFO,
        metadata={},
        raw={},
    )


def _make_finding(event_ids: list[str] | None = None) -> Finding:
    return Finding(
        id="fnd_001",
        timestamp=datetime(2024, 6, 15, 14, 1, tzinfo=timezone.utc),
        detector="unusual-timing",
        event_ids=event_ids or ["evt_001"],
        title="Unusual timing",
        severity=Severity.WARN,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": "alice"},
    )


def _make_store(
    events: list[Event] | None = None,
    findings: list[Finding] | None = None,
    baseline: Baseline | None = None,
) -> MagicMock:
    store = MagicMock()
    store.query_events.return_value = events or []
    store.query_findings.return_value = findings or []
    store.get_baseline.return_value = baseline or Baseline(
        frequency_tables={},
        known_entities={"actors": []},
        relationships={},
    )
    return store


def _make_context(store: Any) -> ToolContext:
    return ToolContext(store=store, connectors={}, config=None)


def _make_actor_profile(
    timezone_str: str | None = None,
    location: str | None = None,
    actor_type: str = "human",
) -> ActorProfile:
    return ActorProfile(
        location=location,
        timezone=timezone_str,
        type=actor_type,
        last_confirmed=datetime(2024, 1, 1, tzinfo=timezone.utc),
        source_feedback_ids=["fnd_x"],
    )


# ---------------------------------------------------------------------------
# read-events enrichment tests
# ---------------------------------------------------------------------------

class TestReadEventsEnrichment:
    def test_no_enrichment_without_actor_context(self):
        """Events have no _enrichment when baseline has no actor_context."""
        event = _make_event(actor="alice")
        store = _make_store(events=[event])
        ctx = _make_context(store)

        result = read_events(ctx)
        assert len(result) == 1
        # Either no _enrichment key, or _enrichment is absent/empty
        assert "_enrichment" not in result[0] or result[0]["_enrichment"] is None or result[0]["_enrichment"] == {}

    def test_enrichment_adds_local_time_for_known_actor(self):
        """Actor with known timezone gets local_time in _enrichment."""
        # 14:00 UTC → 10:00 America/New_York (EDT = UTC-4 in summer)
        ts = datetime(2024, 6, 15, 14, 0, tzinfo=timezone.utc)
        event = _make_event(actor="baron", timestamp=ts)
        profile = _make_actor_profile(timezone_str="America/New_York")
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["baron"]},
            relationships={},
            actor_context={"baron": profile},
        )
        store = _make_store(events=[event], baseline=baseline)
        ctx = _make_context(store)

        result = read_events(ctx)
        assert len(result) == 1
        enrichment = result[0].get("_enrichment", {})
        assert enrichment is not None
        assert "local_time" in enrichment
        # 14:00 UTC = 10:00 EDT (America/New_York in summer)
        assert "10:" in enrichment["local_time"] or "10:00" in enrichment["local_time"]

    def test_enrichment_includes_timing_note(self):
        """_enrichment includes a timing_note string."""
        ts = datetime(2024, 6, 15, 14, 0, tzinfo=timezone.utc)
        event = _make_event(actor="baron", timestamp=ts)
        profile = _make_actor_profile(timezone_str="America/New_York")
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["baron"]},
            relationships={},
            actor_context={"baron": profile},
        )
        store = _make_store(events=[event], baseline=baseline)
        ctx = _make_context(store)

        result = read_events(ctx)
        enrichment = result[0].get("_enrichment", {})
        assert "timing_note" in enrichment
        assert isinstance(enrichment["timing_note"], str)

    def test_enrichment_location_mismatch_noted(self):
        """If event metadata has location differing from actor_context, note it."""
        ts = datetime(2024, 6, 15, 14, 0, tzinfo=timezone.utc)
        event = Event(
            id="evt_001",
            timestamp=ts,
            ingested_at=ts,
            source="azure",
            event_type="login",
            actor="baron",
            action="login",
            target="portal",
            severity=Severity.INFO,
            metadata={"location": "London"},
            raw={},
        )
        # Actor's configured location is Portland
        profile = _make_actor_profile(location="Portland", timezone_str="US/Pacific")
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["baron"]},
            relationships={},
            actor_context={"baron": profile},
        )
        store = _make_store(events=[event], baseline=baseline)
        ctx = _make_context(store)

        result = read_events(ctx)
        enrichment = result[0].get("_enrichment", {})
        # Should note the location mismatch
        timing_note = enrichment.get("timing_note", "")
        assert "London" in timing_note or "Portland" in timing_note or "differ" in timing_note.lower() or "travel" in timing_note.lower()

    def test_enrichment_does_not_modify_original_fields(self):
        """_enrichment is additive — original event fields unchanged."""
        ts = datetime(2024, 6, 15, 14, 0, tzinfo=timezone.utc)
        event = _make_event(actor="baron", timestamp=ts)
        profile = _make_actor_profile(timezone_str="America/New_York")
        baseline = Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
            actor_context={"baron": profile},
        )
        store = _make_store(events=[event], baseline=baseline)
        ctx = _make_context(store)

        result = read_events(ctx)
        r = result[0]
        # Original fields should be intact
        assert r["actor"] == "baron"
        assert r["id"] == "evt_001"
        assert r["source"] == "azure"

    def test_enrichment_finding_id_filter_works(self):
        """Finding-filtered read-events still gets enrichment."""
        ts = datetime(2024, 6, 15, 14, 0, tzinfo=timezone.utc)
        event = _make_event(actor="baron", timestamp=ts)
        finding = _make_finding(event_ids=["evt_001"])
        profile = _make_actor_profile(timezone_str="America/New_York")
        baseline = Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
            actor_context={"baron": profile},
        )
        store = _make_store(events=[event], findings=[finding], baseline=baseline)
        ctx = _make_context(store)

        result = read_events(ctx, finding_id="fnd_001")
        assert len(result) == 1
        enrichment = result[0].get("_enrichment", {})
        assert "local_time" in enrichment

    def test_enrichment_unknown_timezone_graceful(self):
        """Invalid/unknown timezone string doesn't crash — graceful degradation."""
        ts = datetime(2024, 6, 15, 14, 0, tzinfo=timezone.utc)
        event = _make_event(actor="baron", timestamp=ts)
        profile = ActorProfile(
            location=None,
            timezone="Invalid/Timezone",
            type="human",
            last_confirmed=datetime(2024, 1, 1, tzinfo=timezone.utc),
            source_feedback_ids=[],
        )
        baseline = Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
            actor_context={"baron": profile},
        )
        store = _make_store(events=[event], baseline=baseline)
        ctx = _make_context(store)

        # Must not raise
        result = read_events(ctx)
        assert len(result) == 1

    def test_multiple_events_each_enriched(self):
        """Multiple events each get their own enrichment."""
        ts = datetime(2024, 6, 15, 14, 0, tzinfo=timezone.utc)
        events = [
            _make_event(actor="baron", timestamp=ts, evt_id="evt_001"),
            _make_event(actor="baron", timestamp=ts, evt_id="evt_002"),
        ]
        profile = _make_actor_profile(timezone_str="America/New_York")
        baseline = Baseline(
            frequency_tables={},
            known_entities={},
            relationships={},
            actor_context={"baron": profile},
        )
        store = _make_store(events=events, baseline=baseline)
        ctx = _make_context(store)

        result = read_events(ctx)
        assert len(result) == 2
        for r in result:
            assert "_enrichment" in r


# ---------------------------------------------------------------------------
# check-baseline enrichment tests
# ---------------------------------------------------------------------------

class TestCheckBaselineEnrichment:
    def test_related_actors_on_same_resource_group(self):
        """related_actors includes other actors on same resource group prefix."""
        # Three actors operating on same resource group "atom-rg"
        rels = {
            "alice:subscriptions/sub-1/resourceGroups/atom-rg/vm-1": {"count": 10, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-06-01T00:00:00"},
            "ci-bot:subscriptions/sub-1/resourceGroups/atom-rg/deploy": {"count": 156, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-06-01T00:00:00"},
            "deploy-svc:subscriptions/sub-1/resourceGroups/atom-rg/svc": {"count": 98, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-06-01T00:00:00"},
            "alice:subscriptions/sub-1/resourceGroups/other-rg/vm-9": {"count": 3, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-06-01T00:00:00"},
        }
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["alice", "ci-bot", "deploy-svc"]},
            relationships=rels,
        )
        store = _make_store(baseline=baseline)
        ctx = _make_context(store)

        result = check_baseline(ctx, actor="alice")
        related = result.get("related_actors", {})
        # ci-bot and deploy-svc share atom-rg with alice
        assert "ci-bot" in related or "deploy-svc" in related

    def test_related_actors_counts_summed(self):
        """related_actors shows total event counts per actor."""
        rels = {
            "alice:subscriptions/sub-1/resourceGroups/atom-rg/vm-1": {"count": 5, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-06-01T00:00:00"},
            "bob:subscriptions/sub-1/resourceGroups/atom-rg/vm-2": {"count": 20, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-06-01T00:00:00"},
        }
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["alice", "bob"]},
            relationships=rels,
        )
        store = _make_store(baseline=baseline)
        ctx = _make_context(store)

        result = check_baseline(ctx, actor="alice")
        related = result.get("related_actors", {})
        assert "bob" in related
        # Count should be the sum from bob's atom-rg entries
        assert related["bob"] >= 20

    def test_no_related_actors_different_groups(self):
        """Actors on different resource groups are not related."""
        rels = {
            "alice:subscriptions/sub-1/resourceGroups/atom-rg/vm-1": {"count": 5, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-06-01T00:00:00"},
            "bob:subscriptions/sub-1/resourceGroups/other-rg/vm-2": {"count": 10, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-06-01T00:00:00"},
        }
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["alice", "bob"]},
            relationships=rels,
        )
        store = _make_store(baseline=baseline)
        ctx = _make_context(store)

        result = check_baseline(ctx, actor="alice")
        related = result.get("related_actors", {})
        assert "bob" not in related

    def test_actor_context_included_in_response(self):
        """check-baseline includes actor_context profile if present."""
        profile = _make_actor_profile(timezone_str="US/Eastern", location="New York")
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["alice"]},
            relationships={},
            actor_context={"alice": profile},
        )
        store = _make_store(baseline=baseline)
        ctx = _make_context(store)

        result = check_baseline(ctx, actor="alice")
        assert "actor_context" in result
        assert result["actor_context"]["timezone"] == "US/Eastern"
        assert result["actor_context"]["location"] == "New York"

    def test_no_actor_context_no_key(self):
        """check-baseline omits actor_context key when actor has no profile."""
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["alice"]},
            relationships={},
        )
        store = _make_store(baseline=baseline)
        ctx = _make_context(store)

        result = check_baseline(ctx, actor="alice")
        # Should not crash; actor_context may be absent or None
        assert "actor_context" not in result or result["actor_context"] is None

    def test_empty_relationships_returns_empty_related(self):
        """No relationships → empty related_actors."""
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["alice"]},
            relationships={},
        )
        store = _make_store(baseline=baseline)
        ctx = _make_context(store)

        result = check_baseline(ctx, actor="alice")
        related = result.get("related_actors", {})
        assert related == {}

    def test_non_azure_paths_handled(self):
        """Non-Azure-style paths don't crash related_actors computation."""
        rels = {
            "alice:github/org/repo": {"count": 5, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-06-01T00:00:00"},
            "bob:github/org/repo": {"count": 10, "first_seen": "2024-01-01T00:00:00", "last_seen": "2024-06-01T00:00:00"},
        }
        baseline = Baseline(
            frequency_tables={},
            known_entities={"actors": ["alice", "bob"]},
            relationships=rels,
        )
        store = _make_store(baseline=baseline)
        ctx = _make_context(store)

        # Must not raise
        result = check_baseline(ctx, actor="alice")
        related = result.get("related_actors", {})
        # bob shares "github/org" prefix with alice
        assert isinstance(related, dict)
