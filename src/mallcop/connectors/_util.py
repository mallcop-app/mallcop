"""Shared utilities for connector implementations."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from urllib.parse import urlparse


# How far back to look on first poll when no checkpoint exists
DEFAULT_FIRST_POLL_LOOKBACK = timedelta(days=7)

# Token cache margin: refresh this many seconds before actual expiry
DEFAULT_TOKEN_EXPIRY_MARGIN = 60


def parse_iso_timestamp(ts: str) -> datetime:
    """Parse an ISO 8601 timestamp, handling Z suffix."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


_ALLOWED_PAGINATION_HOSTS: dict[str, frozenset[str]] = {
    "azure": frozenset({"management.azure.com"}),
    "log_analytics": frozenset({"api.loganalytics.io"}),
    "github": frozenset({"api.github.com"}),
    "m365": frozenset({"manage.office.com", "graph.microsoft.com"}),
}


def validate_next_link(url: str, api: str) -> None:
    """Validate a pagination URL before following it (SSRF protection).

    Raises ValueError if the URL scheme is not HTTPS or the hostname
    is not in the allowed set for the given API.
    """
    allowed = _ALLOWED_PAGINATION_HOSTS.get(api)
    if allowed is None:
        raise ValueError(f"Unknown API type for pagination validation: {api!r}")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"Refusing to follow non-HTTPS pagination URL: {url!r}"
        )
    if parsed.hostname not in allowed:
        raise ValueError(
            f"Refusing to follow pagination URL to unexpected host "
            f"{parsed.hostname!r} (allowed: {allowed})"
        )


def make_event_id(source_id: str) -> str:
    """Deterministic event ID from a source identifier.

    Returns ``evt_`` followed by the first 12 hex characters of the
    SHA-256 digest of *source_id*.
    """
    h = hashlib.sha256(source_id.encode()).hexdigest()[:12]
    return f"evt_{h}"
