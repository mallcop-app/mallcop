"""Baseline computation: frequency tables, known entities, learning mode."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mallcop.schemas import ActorProfile, Baseline, Event

# Learning mode window: 14 days from first event per connector
LEARNING_PERIOD_DAYS = 14

# Hour bucket size: 4-hour blocks (6 buckets per day)
HOUR_BUCKET_SIZE = 4

# Confidence decay threshold: profiles older than this without re-confirmation
# are considered stale (still present, but flagged for possible re-verification)
CONTEXT_DECAY_DAYS = 90


def hour_bucket(hour: int) -> int:
    """Map an hour (0-23) to its 4-hour bucket start (0, 4, 8, 12, 16, 20)."""
    return (hour // HOUR_BUCKET_SIZE) * HOUR_BUCKET_SIZE


def is_learning_mode(
    connector: str,
    connector_events: list[Event],
) -> bool:
    """Check if a connector is in learning mode.

    Learning mode is active for 14 days from the first event for that connector.
    The caller must filter events to only those matching the connector.
    If there are no events, the connector is considered in learning mode.
    """
    if not connector_events:
        return True

    earliest = min(evt.timestamp for evt in connector_events)
    now = datetime.now(timezone.utc)
    return (now - earliest) < timedelta(days=LEARNING_PERIOD_DAYS)


def update_actor_context(
    baseline: Baseline,
    records: list,  # list[FeedbackRecord] — avoid circular import
) -> Baseline:
    """Update baseline.actor_context from feedback records.

    Extracts structured signals (location, timezone, actor type) from each
    feedback record and merges them into actor_context. Only processes records
    that have an identifiable actor (from events or baseline_snapshot).

    Confidence decay: profiles older than CONTEXT_DECAY_DAYS without
    re-confirmation are left in place (they still represent valid org knowledge)
    but their last_confirmed timestamp exposes staleness to callers.

    Args:
        baseline: Current baseline to update.
        records: New feedback records to process.

    Returns:
        New Baseline with updated actor_context (original is not mutated).
    """
    from mallcop.feedback import extract_context

    # Start with a copy of existing context
    ctx: dict[str, ActorProfile] = dict(baseline.actor_context)

    for record in records:
        profile = extract_context(record)
        if profile is None:
            continue

        # Resolve actor from record: prefer events, then baseline_snapshot
        actor = _resolve_actor(record)
        if not actor:
            continue

        if actor in ctx:
            # Merge: update fields present in new profile, accumulate feedback IDs
            existing = ctx[actor]
            merged_ids = list(existing.source_feedback_ids)
            for fid in profile.source_feedback_ids:
                if fid not in merged_ids:
                    merged_ids.append(fid)
            ctx[actor] = ActorProfile(
                location=profile.location if profile.location is not None else existing.location,
                timezone=profile.timezone if profile.timezone is not None else existing.timezone,
                type=profile.type if profile.type != "human" or existing.type == "human" else existing.type,
                last_confirmed=profile.last_confirmed,
                source_feedback_ids=merged_ids,
            )
        else:
            ctx[actor] = ActorProfile(
                location=profile.location,
                timezone=profile.timezone,
                type=profile.type,
                last_confirmed=profile.last_confirmed,
                source_feedback_ids=list(profile.source_feedback_ids),
            )

    return Baseline(
        frequency_tables=baseline.frequency_tables,
        known_entities=baseline.known_entities,
        relationships=baseline.relationships,
        actor_context=ctx,
    )


def _resolve_actor(record: object) -> str | None:
    """Extract an actor name from a feedback record.

    Checks record.events first (most specific), then baseline_snapshot.
    Strips USER_DATA sanitization markers from actor names since events
    stored in feedback snapshots may have been sanitized at ingest time.
    Returns None if no actor can be determined.
    """
    def _strip_markers(s: str) -> str:
        return s.replace("[USER_DATA_BEGIN]", "").replace("[USER_DATA_END]", "").strip()

    # Try events list
    events = getattr(record, "events", []) or []
    for evt in events:
        if isinstance(evt, dict):
            raw = evt.get("actor", "")
            actor = _strip_markers(raw) if raw else ""
            if actor:
                return actor

    # Try baseline_snapshot
    bl_snap = getattr(record, "baseline_snapshot", {}) or {}
    if isinstance(bl_snap, dict):
        raw = bl_snap.get("actor", "")
        actor = _strip_markers(raw) if raw else ""
        if actor:
            return actor

    return None
