"""Shared utilities for connector implementations."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests

from mallcop.secrets import ConfigError


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


def fetch_microsoft_oauth_token(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    scope: str,
    *,
    service_name: str = "Microsoft",
) -> tuple[str, float]:
    """Fetch an OAuth2 client_credentials token from Azure AD.

    Returns (access_token, expires_at_monotonic).
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    resp = requests.post(url, data={
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": scope,
    })
    if resp.status_code != 200:
        raise ConfigError(
            f"{service_name} authentication failed (HTTP {resp.status_code}): {resp.text}"
        )
    data = resp.json()
    expires_at = time.monotonic() + data.get("expires_in", 3600) - DEFAULT_TOKEN_EXPIRY_MARGIN
    return data["access_token"], expires_at


def make_event_id(source_id: str) -> str:
    """Deterministic event ID from a source identifier.

    Returns ``evt_`` followed by the first 12 hex characters of the
    SHA-256 digest of *source_id*.
    """
    h = hashlib.sha256(source_id.encode()).hexdigest()[:12]
    return f"evt_{h}"
