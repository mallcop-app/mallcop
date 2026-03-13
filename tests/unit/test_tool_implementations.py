"""Tests for core tool implementations wired to Store and config.

TDD tests for mallcop-8.2.2. Each tool function receives ToolContext and
returns real data from the store, baseline, or config.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from mallcop.schemas import (
    Annotation,
    Baseline,
    Event,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.tools import ToolContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    id: str = "evt-1",
    source: str = "azure",
    event_type: str = "sign-in",
    actor: str = "alice@corp.com",
    action: str = "login",
    target: str = "/subscriptions/abc",
    severity: Severity = Severity.INFO,
    ts: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> Event:
    return Event(
        id=id,
        timestamp=ts or datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc),
        ingested_at=datetime(2026, 3, 1, 12, 1, tzinfo=timezone.utc),
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=severity,
        metadata=metadata or {},
        raw={},
    )


def _make_finding(
    id: str = "fnd-1",
    event_ids: list[str] | None = None,
    title: str = "New actor detected",
    severity: Severity = Severity.WARN,
    status: FindingStatus = FindingStatus.OPEN,
    annotations: list[Annotation] | None = None,
    detector: str = "new-actor",
    metadata: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        id=id,
        timestamp=datetime(2026, 3, 1, 12, 5, tzinfo=timezone.utc),
        detector=detector,
        event_ids=event_ids or ["evt-1"],
        title=title,
        severity=severity,
        status=status,
        annotations=annotations or [],
        metadata=metadata or {},
    )


def _make_baseline(
    frequency_tables: dict[str, Any] | None = None,
    known_entities: dict[str, Any] | None = None,
    relationships: dict[str, Any] | None = None,
) -> Baseline:
    return Baseline(
        frequency_tables=frequency_tables or {},
        known_entities=known_entities or {},
        relationships=relationships or {},
    )


def _make_context(
    events: list[Event] | None = None,
    findings: list[Finding] | None = None,
    baseline: Baseline | None = None,
    config: Any = None,
    connectors: dict[str, Any] | None = None,
) -> ToolContext:
    """Build a ToolContext with a mock store wired to return the given data."""
    store = MagicMock()
    store.query_events.return_value = events or []
    store.query_findings.return_value = findings or []
    store.get_baseline.return_value = baseline or _make_baseline()
    store.update_finding = MagicMock()

    if config is None:
        config = MagicMock()
        config.connectors = {"azure": {"tenant_id": "t-123", "client_secret": "s3cret"}}
        config.routing = {"critical": "teams", "warn": None}
        config.actor_chain = {"triage": {"model": "haiku", "permission": "read"}}
        config.budget = MagicMock()
        config.budget.max_findings_for_actors = 25
        config.budget.max_tokens_per_run = 50000
        config.budget.max_tokens_per_finding = 5000
        config.secrets_backend = "env"

    return ToolContext(
        store=store,
        connectors=connectors or {},
        config=config,
    )


# ---------------------------------------------------------------------------
# tools/events.py
# ---------------------------------------------------------------------------

class TestReadEvents:
    """read-events: returns events by finding ID or filters."""

    def test_read_events_by_finding(self) -> None:
        """Store has events + finding with event_ids -> returns matching events."""
        from mallcop.tools.events import read_events

        evt1 = _make_event(id="evt-1", actor="alice@corp.com")
        evt2 = _make_event(id="evt-2", actor="bob@corp.com")
        evt3 = _make_event(id="evt-3", actor="charlie@corp.com")
        finding = _make_finding(id="fnd-1", event_ids=["evt-1", "evt-3"])

        store = MagicMock()
        # query_findings returns the finding when queried by ID
        store.query_findings.return_value = [finding]
        # query_events returns all events; the tool filters by event_ids
        store.query_events.return_value = [evt1, evt2, evt3]

        ctx = ToolContext(store=store, connectors={}, config=MagicMock())
        result = read_events(ctx, finding_id="fnd-1")

        assert len(result) == 2
        ids = {e["id"] for e in result}
        assert ids == {"evt-1", "evt-3"}

    def test_read_events_by_actor(self) -> None:
        """Filter by actor returns correct results."""
        from mallcop.tools.events import read_events

        evt1 = _make_event(id="evt-1", actor="alice@corp.com")
        evt2 = _make_event(id="evt-2", actor="alice@corp.com")
        store = MagicMock()
        store.query_events.return_value = [evt1, evt2]

        ctx = ToolContext(store=store, connectors={}, config=MagicMock())
        result = read_events(ctx, actor="alice@corp.com")

        assert len(result) == 2
        # store.query_events called with actor filter
        store.query_events.assert_called_once_with(
            source=None, actor="alice@corp.com", limit=100
        )

    def test_read_events_by_source(self) -> None:
        """Filter by source passes through to store."""
        from mallcop.tools.events import read_events

        store = MagicMock()
        store.query_events.return_value = []
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())
        read_events(ctx, source="azure", limit=50)

        store.query_events.assert_called_once_with(
            source="azure", actor=None, limit=50
        )

    def test_read_events_finding_not_found(self) -> None:
        """If finding_id is given but not found, return error dict."""
        from mallcop.tools.events import read_events

        store = MagicMock()
        store.query_findings.return_value = []
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = read_events(ctx, finding_id="fnd-nonexistent")
        assert isinstance(result, list)
        assert len(result) == 0


class TestSearchEvents:
    """search-events: text search across event fields."""

    def test_search_events_text_match(self) -> None:
        """Search 'admin' returns events with admin in actor/target/action/event_type."""
        from mallcop.tools.events import search_events

        evt1 = _make_event(id="evt-1", actor="admin@corp.com", action="login")
        evt2 = _make_event(id="evt-2", actor="alice@corp.com", action="admin-reset")
        evt3 = _make_event(id="evt-3", actor="bob@corp.com", action="read",
                           target="/admin/panel")
        evt_no_match = _make_event(id="evt-4", actor="bob@corp.com",
                                   action="read", target="/users")

        store = MagicMock()
        store.query_events.return_value = [evt1, evt2, evt3, evt_no_match]
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = search_events(ctx, query="admin")
        ids = {e["id"] for e in result}
        assert "evt-1" in ids  # actor match
        assert "evt-2" in ids  # action match
        assert "evt-3" in ids  # target match
        assert "evt-4" not in ids

    def test_search_events_case_insensitive(self) -> None:
        """Search is case-insensitive."""
        from mallcop.tools.events import search_events

        evt = _make_event(id="evt-1", actor="Admin@Corp.com")
        store = MagicMock()
        store.query_events.return_value = [evt]
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = search_events(ctx, query="admin")
        assert len(result) == 1

    def test_search_events_with_source_filter(self) -> None:
        """Source filter is passed to store.query_events."""
        from mallcop.tools.events import search_events

        store = MagicMock()
        store.query_events.return_value = []
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        search_events(ctx, query="admin", source="azure")
        store.query_events.assert_called_once_with(source="azure", actor=None, limit=100)


# ---------------------------------------------------------------------------
# tools/baseline.py
# ---------------------------------------------------------------------------

class TestCheckBaseline:
    """check-baseline: check if actor/entity is known in baseline."""

    def test_check_baseline_known_actor(self) -> None:
        """Baseline has actor -> returns known:true with frequency summary."""
        from mallcop.tools.baseline import check_baseline

        baseline = _make_baseline(
            frequency_tables={
                "azure:sign-in:alice@corp.com": 42,
                "azure:role-assign:alice@corp.com": 3,
                "azure:sign-in:bob@corp.com": 10,
            },
            known_entities={
                "actors": ["alice@corp.com", "bob@corp.com"],
                "sources": ["azure"],
            },
        )
        ctx = _make_context(baseline=baseline)

        result = check_baseline(ctx, actor="alice@corp.com")
        assert result["known"] is True
        # Should include frequency info for this actor
        assert "frequency" in result
        assert result["frequency"]["azure:sign-in:alice@corp.com"] == 42
        assert result["frequency"]["azure:role-assign:alice@corp.com"] == 3
        # bob's entries should NOT appear
        assert "azure:sign-in:bob@corp.com" not in result["frequency"]

    def test_check_baseline_actor_with_relationships(self) -> None:
        """Actor with relationships -> result includes target dict with enriched data."""
        from mallcop.tools.baseline import check_baseline

        baseline = _make_baseline(
            known_entities={"actors": ["alice@corp.com"], "sources": ["azure"]},
            relationships={
                "alice@corp.com:/subscriptions/abc": {"count": 5, "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-15T00:00:00+00:00"},
                "alice@corp.com:/subscriptions/def": {"count": 2, "first_seen": "2026-01-10T00:00:00+00:00", "last_seen": "2026-01-12T00:00:00+00:00"},
                "bob@corp.com:/subscriptions/xyz": {"count": 1, "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-01T00:00:00+00:00"},
            },
        )
        ctx = _make_context(baseline=baseline)

        result = check_baseline(ctx, actor="alice@corp.com")
        assert result["known"] is True
        assert "relationships" in result
        assert "/subscriptions/abc" in result["relationships"]
        assert result["relationships"]["/subscriptions/abc"]["count"] == 5
        assert "/subscriptions/def" in result["relationships"]
        # bob's relationships should NOT appear
        assert "/subscriptions/xyz" not in result["relationships"]

    def test_check_baseline_actor_no_relationships(self) -> None:
        """Actor exists but has no relationships -> empty dict."""
        from mallcop.tools.baseline import check_baseline

        baseline = _make_baseline(
            known_entities={"actors": ["alice@corp.com"], "sources": ["azure"]},
            relationships={},
        )
        ctx = _make_context(baseline=baseline)

        result = check_baseline(ctx, actor="alice@corp.com")
        assert result["known"] is True
        assert "relationships" in result
        assert result["relationships"] == {}

    def test_check_baseline_unknown_actor_relationships_empty(self) -> None:
        """Unknown actor -> relationships is empty dict."""
        from mallcop.tools.baseline import check_baseline

        baseline = _make_baseline(
            known_entities={"actors": ["alice@corp.com"]},
            relationships={
                "alice@corp.com:/sub/abc": {"count": 1, "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-01T00:00:00+00:00"},
            },
        )
        ctx = _make_context(baseline=baseline)

        result = check_baseline(ctx, actor="evil@hacker.com")
        assert result["known"] is False
        assert "relationships" in result
        assert result["relationships"] == {}

    def test_check_baseline_relationship_data_sanitized_at_egress(self) -> None:
        """Relationship data with attacker-controlled targets gets sanitized at egress."""
        from mallcop.tools.baseline import check_baseline

        baseline = _make_baseline(
            known_entities={"actors": ["alice@corp.com"], "sources": ["azure"]},
            relationships={
                "alice@corp.com:/subscriptions/abc": {"count": 3, "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-15T00:00:00+00:00"},
            },
        )
        ctx = _make_context(baseline=baseline)

        result = check_baseline(ctx, actor="alice@corp.com")
        # Relationships returned as dict keyed by target
        assert "/subscriptions/abc" in result["relationships"]
        assert result["relationships"]["/subscriptions/abc"]["count"] == 3

    def test_check_baseline_unknown_actor(self) -> None:
        """Actor not in baseline -> returns known:false."""
        from mallcop.tools.baseline import check_baseline

        baseline = _make_baseline(
            known_entities={"actors": ["alice@corp.com"], "sources": ["azure"]},
        )
        ctx = _make_context(baseline=baseline)

        result = check_baseline(ctx, actor="evil@hacker.com")
        assert result["known"] is False

    def test_check_baseline_entity_search(self) -> None:
        """Entity search across all entity types."""
        from mallcop.tools.baseline import check_baseline

        baseline = _make_baseline(
            known_entities={
                "actors": ["alice@corp.com"],
                "sources": ["azure", "github"],
            },
        )
        ctx = _make_context(baseline=baseline)

        result = check_baseline(ctx, entity="azure")
        assert result["known"] is True
        assert result["type"] == "sources"

    def test_check_baseline_entity_not_found(self) -> None:
        """Entity not in any category."""
        from mallcop.tools.baseline import check_baseline

        baseline = _make_baseline(
            known_entities={"actors": ["alice@corp.com"], "sources": ["azure"]},
        )
        ctx = _make_context(baseline=baseline)

        result = check_baseline(ctx, entity="unknown-thing")
        assert result["known"] is False


class TestBaselineStats:
    """baseline-stats: summary counts from baseline."""

    def test_baseline_stats(self) -> None:
        """Returns correct counts for entities and frequency tables."""
        from mallcop.tools.baseline import baseline_stats

        baseline = _make_baseline(
            frequency_tables={
                "azure:sign-in:alice@corp.com": 42,
                "azure:role-assign:bob@corp.com": 3,
            },
            known_entities={
                "actors": ["alice@corp.com", "bob@corp.com"],
                "sources": ["azure"],
            },
        )
        ctx = _make_context(baseline=baseline)

        result = baseline_stats(ctx)
        assert result["total_frequency_entries"] == 2
        assert result["known_entities"]["actors"] == 2
        assert result["known_entities"]["sources"] == 1

    def test_baseline_stats_empty(self) -> None:
        """Empty baseline returns zero counts."""
        from mallcop.tools.baseline import baseline_stats

        ctx = _make_context(baseline=_make_baseline())
        result = baseline_stats(ctx)
        assert result["total_frequency_entries"] == 0
        assert result["known_entities"] == {}


# ---------------------------------------------------------------------------
# tools/findings.py
# ---------------------------------------------------------------------------

class TestReadFinding:
    """read-finding: returns full finding dict."""

    def test_read_finding_exists(self) -> None:
        """Returns full finding dict including annotations."""
        from mallcop.tools.findings import read_finding

        ann = Annotation(
            actor="triage",
            timestamp=datetime(2026, 3, 1, 12, 10, tzinfo=timezone.utc),
            content="Investigating actor",
            action="annotate",
            reason=None,
        )
        finding = _make_finding(
            id="fnd-1",
            annotations=[ann],
            metadata={"detector_version": "1.0"},
        )
        store = MagicMock()
        store.query_findings.return_value = [finding]
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = read_finding(ctx, finding_id="fnd-1")
        assert result["id"] == "fnd-1"
        assert result["title"] == "New actor detected"
        assert len(result["annotations"]) == 1
        assert result["annotations"][0]["content"] == "Investigating actor"

    def test_read_finding_not_found(self) -> None:
        """Returns error dict if not found."""
        from mallcop.tools.findings import read_finding

        store = MagicMock()
        store.query_findings.return_value = []
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = read_finding(ctx, finding_id="fnd-nonexistent")
        assert "error" in result
        assert "not found" in result["error"].lower()


class TestListFindings:
    """list-findings: query findings with filters."""

    def test_list_findings_with_filters(self) -> None:
        """Status/severity filters work."""
        from mallcop.tools.findings import list_findings

        f1 = _make_finding(id="fnd-1", status=FindingStatus.OPEN, severity=Severity.WARN)
        f2 = _make_finding(id="fnd-2", status=FindingStatus.RESOLVED, severity=Severity.CRITICAL)
        store = MagicMock()
        store.query_findings.return_value = [f1]
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = list_findings(ctx, status="open", severity="warn")
        store.query_findings.assert_called_once_with(status="open", severity="warn")
        assert len(result) == 1
        assert result[0]["id"] == "fnd-1"

    def test_list_findings_no_filters(self) -> None:
        """No filters returns all findings."""
        from mallcop.tools.findings import list_findings

        f1 = _make_finding(id="fnd-1")
        f2 = _make_finding(id="fnd-2")
        store = MagicMock()
        store.query_findings.return_value = [f1, f2]
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = list_findings(ctx)
        store.query_findings.assert_called_once_with(status=None, severity=None)
        assert len(result) == 2

    def test_list_findings_respects_limit(self) -> None:
        """Limit truncates results."""
        from mallcop.tools.findings import list_findings

        findings = [_make_finding(id=f"fnd-{i}") for i in range(10)]
        store = MagicMock()
        store.query_findings.return_value = findings
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = list_findings(ctx, limit=3)
        assert len(result) == 3


class TestAnnotateFinding:
    """annotate-finding: adds annotation and persists."""

    def test_annotate_finding(self) -> None:
        """Adds annotation, calls store.update_finding, returns updated finding."""
        from mallcop.tools.findings import annotate_finding

        finding = _make_finding(id="fnd-1", annotations=[])
        store = MagicMock()
        store.query_findings.return_value = [finding]
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = annotate_finding(ctx, finding_id="fnd-1", text="Looks suspicious")

        # Must have called update_finding with annotations
        store.update_finding.assert_called_once()
        call_kwargs = store.update_finding.call_args
        assert call_kwargs[0][0] == "fnd-1"  # finding_id
        annotations = call_kwargs[1]["annotations"]
        assert len(annotations) == 1
        assert annotations[0].content == "Looks suspicious"
        assert annotations[0].actor == "agent"
        assert annotations[0].action == "annotate"

        # Return value should include the finding info
        assert result["id"] == "fnd-1"

    def test_annotate_finding_not_found(self) -> None:
        """Annotating non-existent finding returns error."""
        from mallcop.tools.findings import annotate_finding

        store = MagicMock()
        store.query_findings.return_value = []
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = annotate_finding(ctx, finding_id="fnd-nonexistent", text="note")
        assert "error" in result


# ---------------------------------------------------------------------------
# tools/config.py
# ---------------------------------------------------------------------------

class TestReadConfig:
    """read-config: returns config dict with secrets redacted."""

    def test_read_config_redacts_secrets(self) -> None:
        """Secret values replaced with '***'."""
        from mallcop.tools.config import read_config

        config = MagicMock()
        config.connectors = {
            "azure": {
                "tenant_id": "t-123",
                "client_secret": "super-secret-value",
                "client_id": "c-456",
            }
        }
        config.routing = {"critical": "teams", "warn": None}
        config.actor_chain = {"triage": {"model": "haiku", "permission": "read"}}
        config.budget = MagicMock()
        config.budget.max_findings_for_actors = 25
        config.budget.max_tokens_per_run = 50000
        config.budget.max_tokens_per_finding = 5000
        config.secrets_backend = "env"

        ctx = ToolContext(store=MagicMock(), connectors={}, config=config)
        result = read_config(ctx)

        # Structure exists
        assert "connectors" in result
        assert "routing" in result
        assert "actor_chain" in result
        assert "budget" in result

        # Secret-looking values should be redacted
        azure_cfg = result["connectors"]["azure"]
        assert azure_cfg["client_secret"] == "***"
        # Non-secret values preserved
        assert azure_cfg["tenant_id"] == "t-123"

    def test_read_config_includes_connector_names(self) -> None:
        """Config output includes connector names."""
        from mallcop.tools.config import read_config

        config = MagicMock()
        config.connectors = {"azure": {"tenant_id": "t-1"}, "github": {"token": "ghp_xxx"}}
        config.routing = {}
        config.actor_chain = {}
        config.budget = MagicMock()
        config.budget.max_findings_for_actors = 25
        config.budget.max_tokens_per_run = 50000
        config.budget.max_tokens_per_finding = 5000
        config.secrets_backend = "env"

        ctx = ToolContext(store=MagicMock(), connectors={}, config=config)
        result = read_config(ctx)
        assert "azure" in result["connectors"]
        assert "github" in result["connectors"]
        # github token should be redacted
        assert result["connectors"]["github"]["token"] == "***"


# ---------------------------------------------------------------------------
# search-findings tool
# ---------------------------------------------------------------------------


class TestSearchFindings:
    """Tests for the search-findings tool."""

    def test_search_findings_by_actor(self) -> None:
        from mallcop.tools.findings import search_findings

        f1 = _make_finding(id="fnd-a1", metadata={"actor": "alice@corp.com"})
        f2 = _make_finding(id="fnd-a2", metadata={"actor": "bob@corp.com"})

        store = MagicMock()
        store.query_findings.return_value = [f1]
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = search_findings(ctx, actor="alice@corp.com")
        store.query_findings.assert_called_once_with(
            status=None, actor="alice@corp.com", detector=None, since=None,
        )
        assert len(result) == 1
        assert result[0]["id"] == "fnd-a1"

    def test_search_findings_by_detector(self) -> None:
        from mallcop.tools.findings import search_findings

        f1 = _make_finding(id="fnd-d1", detector="priv-escalation")
        store = MagicMock()
        store.query_findings.return_value = [f1]
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = search_findings(ctx, detector="priv-escalation")
        store.query_findings.assert_called_once_with(
            status=None, actor=None, detector="priv-escalation", since=None,
        )
        assert len(result) == 1
        assert result[0]["id"] == "fnd-d1"

    def test_search_findings_by_since(self) -> None:
        from mallcop.tools.findings import search_findings

        f1 = _make_finding(id="fnd-s1")
        store = MagicMock()
        store.query_findings.return_value = [f1]
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = search_findings(ctx, since="2026-03-01T00:00:00+00:00")
        call_kwargs = store.query_findings.call_args[1]
        assert call_kwargs["since"] == datetime(2026, 3, 1, tzinfo=timezone.utc)

    def test_search_findings_respects_limit(self) -> None:
        from mallcop.tools.findings import search_findings

        findings = [_make_finding(id=f"fnd-{i}") for i in range(10)]
        store = MagicMock()
        store.query_findings.return_value = findings
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = search_findings(ctx, limit=3)
        assert len(result) == 3

    def test_search_findings_no_filters(self) -> None:
        from mallcop.tools.findings import search_findings

        store = MagicMock()
        store.query_findings.return_value = []
        ctx = ToolContext(store=store, connectors={}, config=MagicMock())

        result = search_findings(ctx)
        store.query_findings.assert_called_once_with(
            status=None, actor=None, detector=None, since=None,
        )
