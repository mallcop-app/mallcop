"""Shared utilities for connector implementations."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta


# How far back to look on first poll when no checkpoint exists
DEFAULT_FIRST_POLL_LOOKBACK = timedelta(days=7)

# Token cache margin: refresh this many seconds before actual expiry
DEFAULT_TOKEN_EXPIRY_MARGIN = 60


def parse_iso_timestamp(ts: str) -> datetime:
    """Parse an ISO 8601 timestamp, handling Z suffix."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def make_event_id(source_id: str) -> str:
    """Deterministic event ID from a source identifier.

    Returns ``evt_`` followed by the first 12 hex characters of the
    SHA-256 digest of *source_id*.
    """
    h = hashlib.sha256(source_id.encode()).hexdigest()[:12]
    return f"evt_{h}"
