"""Baseline computation: frequency tables, known entities, learning mode."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from mallcop.schemas import ActorProfile, Baseline, Event

# Import run_detect at module level so tests can patch mallcop.baseline.run_detect.
# detect.py does not import baseline.py, so no circular import risk.
from mallcop.detect import run_detect  # noqa: E402

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


def retrospective_analysis(
    connector: str,
    all_events: list[Event],
    baseline: Baseline,
) -> list:
    """Re-run detectors on learning-period events using the established baseline.

    Called when a connector transitions from learning mode to normal mode.
    Any suspicious activity planted during the known 14-day window will now
    surface as a finding because the baseline is fully established.

    Args:
        connector: The connector name to analyze retrospectively.
        all_events: All stored events (will be filtered to connector + window).
        baseline: The now-established baseline to detect against.

    Returns:
        list[Finding] with source="retrospective" in metadata.
    """
    # Filter to this connector's events only
    connector_events = [e for e in all_events if e.source == connector]
    if not connector_events:
        return []

    # Only events within the learning period window: [earliest, earliest + 14 days]
    earliest = min(e.timestamp for e in connector_events)
    cutoff = earliest + timedelta(days=LEARNING_PERIOD_DAYS)
    learning_period_events = [
        e for e in connector_events
        if earliest <= e.timestamp <= cutoff
    ]

    if not learning_period_events:
        return []

    # Run detectors with NO learning connectors (we're past learning mode)
    findings = run_detect(
        learning_period_events,
        baseline,
        learning_connectors=set(),
    )

    # Tag all retrospective findings
    for f in findings:
        f.metadata["source"] = "retrospective"

    return findings


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
    # Track accumulated weights per actor for simple average confidence
    confidence_accum: dict[str, list[float]] = {}  # actor -> list of weights

    for record in records:
        profile = extract_context(record)
        if profile is None:
            continue

        # Resolve actor from record: prefer events, then baseline_snapshot
        actor = _resolve_actor(record)
        if not actor:
            continue

        weight = getattr(record, "weight", 1.0)

        if actor in ctx:
            # Merge: update fields present in new profile, accumulate feedback IDs
            existing = ctx[actor]
            merged_ids = list(existing.source_feedback_ids)
            for fid in profile.source_feedback_ids:
                if fid not in merged_ids:
                    merged_ids.append(fid)
            weights = confidence_accum.setdefault(actor, [])
            weights.append(weight)
            ctx[actor] = ActorProfile(
                location=profile.location if profile.location is not None else existing.location,
                timezone=profile.timezone if profile.timezone is not None else existing.timezone,
                # Prefer non-human type (automation/service) over human — more specific.
                # Keep existing non-human type if new observation is "human" (don't downgrade).
                type=existing.type if profile.type == "human" and existing.type != "human" else profile.type,
                last_confirmed=profile.last_confirmed,
                source_feedback_ids=merged_ids,
                confidence=existing.confidence,  # updated after loop
            )
        else:
            weights = confidence_accum.setdefault(actor, [])
            weights.append(weight)
            ctx[actor] = ActorProfile(
                location=profile.location,
                timezone=profile.timezone,
                type=profile.type,
                last_confirmed=profile.last_confirmed,
                source_feedback_ids=list(profile.source_feedback_ids),
                confidence=weight,  # initial; recalculated below
            )

    # Compute average confidence for each actor that received updates
    for actor, weights in confidence_accum.items():
        if actor in ctx and weights:
            # Simple average of all feedback weights: 0.3 for all-batch, 1.0 for all-individual
            avg_confidence = sum(weights) / len(weights)
            existing = ctx[actor]
            ctx[actor] = ActorProfile(
                location=existing.location,
                timezone=existing.timezone,
                type=existing.type,
                last_confirmed=existing.last_confirmed,
                source_feedback_ids=existing.source_feedback_ids,
                confidence=avg_confidence,
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
