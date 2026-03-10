"""Shared fixtures for live integration tests.

These tests hit real APIs and require credentials in environment variables.
They are marked with @pytest.mark.live and excluded from the default pytest run.
Run them explicitly with: pytest -m live
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity


@pytest.fixture
def anthropic_api_key() -> str:
    """Return ANTHROPIC_API_KEY or skip test."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        pytest.skip("ANTHROPIC_API_KEY not set")
    return key


@pytest.fixture
def azure_tenant_id() -> str:
    key = os.environ.get("AZURE_TENANT_ID")
    if not key:
        pytest.skip("AZURE_TENANT_ID not set")
    return key


@pytest.fixture
def azure_client_id() -> str:
    key = os.environ.get("AZURE_CLIENT_ID")
    if not key:
        pytest.skip("AZURE_CLIENT_ID not set")
    return key


@pytest.fixture
def azure_client_secret() -> str:
    key = os.environ.get("AZURE_CLIENT_SECRET")
    if not key:
        pytest.skip("AZURE_CLIENT_SECRET not set")
    return key


def make_event(
    id: str = "evt_test001",
    actor: str = "unknown-user@example.com",
    action: str = "Microsoft.Authorization/roleAssignments/write",
    target: str = "/subscriptions/sub-1/resourceGroups/rg-prod",
    event_type: str = "role_assignment",
    source: str = "azure",
    severity: Severity = Severity.WARN,
) -> Event:
    """Build a test event."""
    now = datetime.now(timezone.utc)
    return Event(
        id=id,
        timestamp=now,
        ingested_at=now,
        source=source,
        event_type=event_type,
        actor=actor,
        action=action,
        target=target,
        severity=severity,
        metadata={"subscription_id": "sub-1", "resource_group": "rg-prod"},
        raw={"test": True},
    )


def make_finding(event: Event, id: str = "fnd_test001") -> Finding:
    """Build a finding referencing the given event."""
    return Finding(
        id=id,
        timestamp=event.timestamp,
        detector="new_actor",
        event_ids=[event.id],
        title=f"New actor detected: {event.actor}",
        severity=event.severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": event.actor, "source": event.source},
    )


def build_store_with_events(tmp_path: Path, events: list[Event]) -> "JsonlStore":
    """Create a JsonlStore, ingest events, update baseline."""
    from mallcop.store import JsonlStore

    store = JsonlStore(tmp_path)
    store.append_events(events)
    store.update_baseline(events)
    return store


def build_baseline_with_known_actor(actor: str = "admin@example.com") -> Baseline:
    """Build a baseline that knows one actor."""
    return Baseline(
        frequency_tables={f"azure:login:{actor}": 42},
        known_entities={"actors": [actor], "sources": ["azure"]},
        relationships={f"{actor}:/subscriptions/sub-1": {"count": 1, "first_seen": "2026-01-01T00:00:00+00:00", "last_seen": "2026-01-01T00:00:00+00:00"}},
    )
