"""Azure Activity Log connector — implements ConnectorBase."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from mallcop.connectors._base import ConnectorBase
from mallcop.connectors._util import (
    DEFAULT_FIRST_POLL_LOOKBACK,
    DEFAULT_TOKEN_EXPIRY_MARGIN,
    build_checkpoint,
    make_event_id,
    parse_iso_timestamp,
    validate_next_link,
)
from mallcop.schemas import Checkpoint, DiscoveryResult, Event, PollResult, Severity
from mallcop.secrets import ConfigError, SecretProvider

# Map Azure operation namespaces to mallcop event types
_EVENT_TYPE_MAP: dict[str, str] = {
    "Microsoft.Authorization/roleAssignments": "role_assignment",
    "Microsoft.Authorization/roleDefinitions": "role_assignment",
    "Microsoft.ContainerApp": "container_access",
    "Microsoft.Security": "defender_alert",
}

# Default event type for operations not in the map
_DEFAULT_EVENT_TYPE = "resource_modified"

# Map Azure log levels to mallcop severity
_SEVERITY_MAP: dict[str, Severity] = {
    "Informational": Severity.INFO,
    "Warning": Severity.WARN,
    "Error": Severity.CRITICAL,
    "Critical": Severity.CRITICAL,
}


def _classify_event_type(operation_name: str, resource_type: str) -> str:
    """Map an Azure operation to a mallcop event type."""
    # Check resource type prefix against the map
    for prefix, event_type in _EVENT_TYPE_MAP.items():
        if resource_type.startswith(prefix):
            return event_type
    # Login detection
    if "login" in operation_name.lower() or "signin" in operation_name.lower():
        return "login"
    return _DEFAULT_EVENT_TYPE


def _map_severity(level: str) -> Severity:
    return _SEVERITY_MAP.get(level, Severity.INFO)



class AzureConnector(ConnectorBase):
    def __init__(self) -> None:
        self._tenant_id: str | None = None
        self._client_id: str | None = None
        self._client_secret: str | None = None
        self._subscription_ids: list[str] = []
        # Token cache
        self._cached_token: str | None = None
        self._token_expires_at: float = 0.0

    def configure(self, config: dict) -> None:
        """Apply Azure-specific config: subscription_ids."""
        if "subscription_ids" in config:
            self._subscription_ids = config["subscription_ids"]

    def discover(self) -> DiscoveryResult:
        try:
            subs = self._list_subscriptions()
        except Exception:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
                notes=["Could not authenticate to Azure. Check credentials."],
            )

        if not subs:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=[],
                notes=["No subscriptions found for this tenant."],
            )

        resources = [
            f"{s['subscriptionId']} ({s['displayName']})" for s in subs
        ]
        sub_ids = [s["subscriptionId"] for s in subs]

        return DiscoveryResult(
            available=True,
            resources=resources,
            suggested_config={"subscription_ids": sub_ids},
            missing_credentials=[],
            notes=[f"Found {len(subs)} subscription(s)."],
        )

    def authenticate(self, secrets: SecretProvider) -> None:
        self._tenant_id = secrets.resolve("AZURE_TENANT_ID")
        self._client_id = secrets.resolve("AZURE_CLIENT_ID")
        self._client_secret = secrets.resolve("AZURE_CLIENT_SECRET")
        # Eagerly validate credentials by fetching a token
        self._get_token()

    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        raw_events: list[dict[str, Any]] = []
        for sub_id in self._subscription_ids:
            raw_events.extend(self._fetch_activity_log(sub_id, checkpoint))

        # Filter events after checkpoint
        checkpoint_dt: datetime | None = None
        if checkpoint is not None:
            checkpoint_dt = parse_iso_timestamp(checkpoint.value)

        events: list[Event] = []
        latest_ts: datetime | None = None
        now = datetime.now(timezone.utc)

        for raw in raw_events:
            event_ts = parse_iso_timestamp(raw["eventTimestamp"])

            # Skip events at or before the checkpoint
            if checkpoint_dt is not None and event_ts <= checkpoint_dt:
                continue

            operation = raw.get("operationName", {}).get("value", "")
            resource_type = raw.get("resourceType", {}).get("value", "")
            level = raw.get("level", "Informational")

            evt = Event(
                id=make_event_id(raw.get("eventDataId", "")),
                timestamp=event_ts,
                ingested_at=now,
                source="azure",
                event_type=_classify_event_type(operation, resource_type),
                actor=raw.get("caller", "unknown"),
                action=operation,
                target=raw.get("resourceId", ""),
                severity=_map_severity(level),
                metadata={
                    "subscription_id": raw.get("subscriptionId", ""),
                    "resource_group": raw.get("resourceGroupName", ""),
                    "correlation_id": raw.get("correlationId", ""),
                    "status": raw.get("status", {}).get("value", ""),
                },
                raw=raw,
            )
            events.append(evt)

            if latest_ts is None or event_ts > latest_ts:
                latest_ts = event_ts

        # Build checkpoint
        new_checkpoint = build_checkpoint("azure", latest_ts.isoformat() if latest_ts else None, checkpoint, now)

        return PollResult(events=events, checkpoint=new_checkpoint)

    def event_types(self) -> list[str]:
        return [
            "role_assignment",
            "login",
            "resource_modified",
            "defender_alert",
            "container_access",
        ]

    def _get_token(self) -> str:
        """Get an OAuth2 access token, using cache when valid."""
        if self._cached_token is not None and time.monotonic() < self._token_expires_at:
            return self._cached_token

        from mallcop.connectors._util import fetch_microsoft_oauth_token
        self._cached_token, self._token_expires_at = fetch_microsoft_oauth_token(
            self._tenant_id, self._client_id, self._client_secret,
            scope="https://management.azure.com/.default",
            service_name="Azure",
        )
        return self._cached_token

    def _auth_headers(self) -> dict[str, str]:
        """Return Authorization headers with a valid Bearer token."""
        return {"Authorization": f"Bearer {self._get_token()}"}

    def _get_paginated(self, url: str, params: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """GET a paginated Azure REST API endpoint, following nextLink."""
        results: list[dict[str, Any]] = []
        headers = self._auth_headers()

        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise TypeError(
                f"Expected JSON object from Azure API, got {type(data).__name__}: {str(data)[:200]}"
            )
        results.extend(data.get("value", []))

        while "nextLink" in data:
            validate_next_link(data["nextLink"], "azure")
            resp = requests.get(data["nextLink"], headers=headers)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                raise TypeError(
                    f"Expected JSON object from Azure API, got {type(data).__name__}: {str(data)[:200]}"
                )
            results.extend(data.get("value", []))

        return results

    def _list_subscriptions(self) -> list[dict[str, Any]]:
        """List Azure subscriptions via REST API."""
        url = "https://management.azure.com/subscriptions"
        return self._get_paginated(url, params={"api-version": "2022-12-01"})

    def _fetch_activity_log(
        self,
        subscription_id: str,
        checkpoint: Checkpoint | None,
    ) -> list[dict[str, Any]]:
        """Fetch Activity Log events via REST API.

        The Azure Activity Log API requires a $filter parameter with an
        eventTimestamp range — omitting it returns HTTP 400.
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/providers/Microsoft.Insights/eventtypes/management/values"
        )
        now = datetime.now(timezone.utc)
        if checkpoint is not None:
            # Normalize checkpoint to UTC ISO with Z suffix as required by Azure Activity Log API
            cp_dt = parse_iso_timestamp(checkpoint.value)
            start = cp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            start = (now - DEFAULT_FIRST_POLL_LOOKBACK).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        params: dict[str, str] = {
            "api-version": "2015-04-01",
            "$filter": f"eventTimestamp ge '{start}' and eventTimestamp le '{end}'",
        }
        return self._get_paginated(url, params=params)
