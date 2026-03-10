"""Baseline computation: frequency tables, known entities, learning mode."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mallcop.schemas import Event

# Learning mode window: 14 days from first event per connector
LEARNING_PERIOD_DAYS = 14

# Hour bucket size: 4-hour blocks (6 buckets per day)
HOUR_BUCKET_SIZE = 4


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
