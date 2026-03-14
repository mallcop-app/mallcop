"""Event query tools for actor runtime."""

from __future__ import annotations

from typing import Any

from mallcop.tools import ToolContext, tool


def _enrich_event(event_dict: dict[str, Any], actor_context: dict[str, Any]) -> dict[str, Any]:
    """Add _enrichment dict to an event dict using actor_context from baseline.

    Enrichment is additive — never modifies original event fields.
    Gracefully degrades: if actor is unknown or timezone is invalid, returns empty dict.
    """
    actor = event_dict.get("actor", "")
    # Strip USER_DATA markers if present (events may be sanitized)
    actor_clean = actor.replace("[USER_DATA_BEGIN]", "").replace("[USER_DATA_END]", "").strip()

    if not actor_clean or actor_clean not in actor_context:
        return {}

    profile = actor_context[actor_clean]
    enrichment: dict[str, Any] = {}

    # Timezone conversion
    tz_str = getattr(profile, "timezone", None)
    if tz_str:
        try:
            from datetime import datetime as _dt
            from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
            ts_raw = event_dict.get("timestamp", "")
            if ts_raw:
                ts = _dt.fromisoformat(ts_raw)
                local_ts = ts.astimezone(ZoneInfo(tz_str))
                enrichment["local_time"] = local_ts.strftime("%H:%M %Z")
        except Exception:
            pass  # Unknown timezone or parse error — graceful degradation

    # Location mismatch check
    configured_location = getattr(profile, "location", None)
    event_location = event_dict.get("metadata", {})
    if isinstance(event_location, dict):
        event_loc = event_location.get("location")
    else:
        event_loc = None

    if configured_location and event_loc and configured_location != event_loc:
        enrichment["timing_note"] = (
            f"Event location ({event_loc}) differs from actor's configured location "
            f"({configured_location}) — possible travel"
        )
    elif "local_time" in enrichment:
        # Generic timing note when we have local time
        tz_note = f" ({tz_str})" if tz_str else ""
        enrichment["timing_note"] = f"Actor local time{tz_note}: {enrichment['local_time']}"

    return enrichment


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

    Events for actors with known location/timezone have an added _enrichment dict:
      - local_time: actor's local time at the event timestamp
      - timing_note: context about timing (within hours, location mismatch)
    """
    store = context.store
    baseline = store.get_baseline()
    actor_context = getattr(baseline, "actor_context", {}) or {}

    if finding_id is not None:
        # Load finding to get event_ids
        findings = store.query_findings()
        matching = [f for f in findings if f.id == finding_id]
        if not matching:
            return []
        target_ids = set(matching[0].event_ids)
        # Get all events, filter to those referenced by the finding
        all_events = store.query_events(source=source, actor=actor, limit=limit)
        result = []
        for e in all_events:
            if e.id in target_ids:
                d = e.to_dict()
                enrichment = _enrich_event(d, actor_context)
                if enrichment:
                    d["_enrichment"] = enrichment
                result.append(d)
        return result

    events = store.query_events(source=source, actor=actor, limit=limit)
    result = []
    for e in events:
        d = e.to_dict()
        enrichment = _enrich_event(d, actor_context)
        if enrichment:
            d["_enrichment"] = enrichment
        result.append(d)
    return result


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
