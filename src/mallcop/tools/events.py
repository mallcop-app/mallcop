"""Event query tools for actor runtime."""

from __future__ import annotations

from typing import Any

from mallcop.tools import ToolContext, tool


@tool(name="read-events", description="Read events by finding ID or filters", permission="read")
def read_events(
    context: ToolContext,
    finding_id: str | None = None,
    source: str | None = None,
    actor: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Read events from the store, optionally filtered by finding, source, or actor.

    If finding_id is provided, loads the finding's event_ids and returns only
    those events. Otherwise queries events with source/actor/limit filters.
    """
    store = context.store

    if finding_id is not None:
        # Load finding to get event_ids
        findings = store.query_findings()
        matching = [f for f in findings if f.id == finding_id]
        if not matching:
            return []
        target_ids = set(matching[0].event_ids)
        # Get all events, filter to those referenced by the finding
        all_events = store.query_events(source=source, actor=actor, limit=limit)
        return [e.to_dict() for e in all_events if e.id in target_ids]

    events = store.query_events(source=source, actor=actor, limit=limit)
    return [e.to_dict() for e in events]


@tool(name="search-events", description="Search events with text query", permission="read")
def search_events(
    context: ToolContext,
    query: str = "",
    source: str | None = None,
    actor: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Search events with text matching across actor, target, action, event_type.

    Queries events from the store (with optional source/actor filter), then filters
    results where query appears (case-insensitive) in any searchable field.
    """
    store = context.store
    events = store.query_events(source=source, actor=actor, limit=limit)
    q = query.lower()

    results: list[dict[str, Any]] = []
    for evt in events:
        searchable = f"{evt.actor} {evt.target} {evt.action} {evt.event_type}".lower()
        if not q or q in searchable:
            results.append(evt.to_dict())
    return results
