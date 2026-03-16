"""Container Apps Log connector — polls logs from Azure Container Apps via Log Analytics."""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

_log = logging.getLogger(__name__)

# ISO 8601 timestamp at start of line: 2026-03-05T14:30:00.000Z or 2026-03-05T14:30:00Z
_TS_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(.*)$")


def _parse_log_line(line: str) -> tuple[datetime | None, str]:
    """Parse a log line, extracting an optional ISO timestamp prefix.

    Used by discover-app for log statistics. Not used by the connector
    itself (which reads structured data from Log Analytics).
    """
    if not line:
        return None, ""
    m = _TS_PATTERN.match(line)
    if m:
        ts_str = m.group(1)
        content = m.group(2)
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return ts, content
        except ValueError:
            return None, line
    return None, line

from mallcop.connectors._base import ConnectorBase
from mallcop.connectors._util import DEFAULT_TOKEN_EXPIRY_MARGIN, build_checkpoint, make_event_id, validate_next_link
from mallcop.schemas import Checkpoint, DiscoveryResult, Event, PollResult, Severity
from mallcop.secrets import ConfigError, SecretProvider

_FIRST_POLL_LOOKBACK = timedelta(hours=1)
_MAX_LOG_ROWS = 500



class ContainerLogsConnector(ConnectorBase):
    def __init__(
        self,
        subscription_id: str = "",
        resource_group: str = "",
        apps: list[dict[str, str]] | None = None,
    ) -> None:
        self._subscription_id = subscription_id
        self._resource_group = resource_group
        self._apps = apps or []
        self._tenant_id: str | None = None
        self._client_id: str | None = None
        self._client_secret: str | None = None
        # Management API token
        self._cached_token: str | None = None
        self._token_expires_at: float = 0.0
        # Log Analytics token (different scope)
        self._la_token: str | None = None
        self._la_token_expires_at: float = 0.0
        # Cache: environment_id -> workspace_id
        self._workspace_cache: dict[str, str] = {}

    def configure(self, config: dict) -> None:
        """Apply container-logs specific config: subscription_id, resource_group, apps."""
        if "subscription_id" in config:
            self._subscription_id = config["subscription_id"]
        if "resource_group" in config:
            self._resource_group = config["resource_group"]
        if "apps" in config:
            self._apps = config["apps"]

    def discover(self) -> DiscoveryResult:
        try:
            apps = self._get_paginated(self._list_apps_url())
        except Exception:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=[
                    "AZURE_TENANT_ID",
                    "AZURE_CLIENT_ID",
                    "AZURE_CLIENT_SECRET",
                ],
                notes=["Could not list Container Apps. Check credentials."],
            )

        if not apps:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=[],
                notes=["No Container Apps found in resource group."],
            )

        resources = []
        app_configs = []
        for app in apps:
            name = app["name"]
            props = app.get("properties", {})
            rev = props.get("latestRevisionName", "unknown")
            resources.append(f"{name} (revision: {rev})")
            app_configs.append({"name": name, "container": name})

        return DiscoveryResult(
            available=True,
            resources=resources,
            suggested_config={
                "subscription_id": self._subscription_id,
                "resource_group": self._resource_group,
                "apps": app_configs,
            },
            missing_credentials=[],
            notes=[f"Found {len(apps)} Container App(s)."],
        )

    def authenticate(self, secrets: SecretProvider) -> None:
        self._tenant_id = secrets.resolve("AZURE_TENANT_ID")
        self._client_id = secrets.resolve("AZURE_CLIENT_ID")
        self._client_secret = secrets.resolve("AZURE_CLIENT_SECRET")
        self._get_token()

    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        now = datetime.now(timezone.utc)

        since: datetime | None = None
        if checkpoint is not None:
            try:
                since = datetime.fromisoformat(checkpoint.value)
            except ValueError:
                since = None

        all_events: list[Event] = []
        latest_ts: datetime | None = None
        app_errors: dict[str, str] = {}

        for app_cfg in self._apps:
            app_name = app_cfg["name"]
            resource_group = app_cfg.get("resource_group", self._resource_group)

            try:
                rows = self._fetch_logs_for_app(app_name, resource_group, since)
            except Exception as e:
                app_errors[app_name] = str(e)
                _log.warning("container-logs: failed to fetch %s: %s", app_name, e)
                continue

            for row in rows:
                ts_str = row.get("TimeGenerated", "")
                log_content = row.get("Log_s", "")
                container = row.get("ContainerName_s", "")
                stream = row.get("Stream_s", "stdout")

                if not log_content:
                    continue

                try:
                    event_ts = datetime.fromisoformat(
                        ts_str.replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    event_ts = now

                evt = Event(
                    id=make_event_id(f"{app_name}:{ts_str}:{log_content}"),
                    timestamp=event_ts,
                    ingested_at=now,
                    source="container-logs",
                    event_type="log_line",
                    actor=app_name,
                    action="log",
                    target=container,
                    severity=Severity.INFO,
                    metadata={
                        "app": app_name,
                        "container": container,
                        "stream": stream,
                        "revision": row.get("RevisionName_s", ""),
                    },
                    raw={"line": log_content},
                )
                all_events.append(evt)

                if latest_ts is None or event_ts > latest_ts:
                    latest_ts = event_ts

        # If every app failed, raise so the scan pipeline sees the failure
        if app_errors and len(app_errors) == len(self._apps):
            raise RuntimeError(
                f"container-logs: all {len(self._apps)} apps failed to fetch: "
                + "; ".join(f"{k}: {v}" for k, v in app_errors.items())
            )

        # Build checkpoint
        new_checkpoint = build_checkpoint("container-logs", latest_ts.isoformat() if latest_ts else None, checkpoint, now)

        return PollResult(events=all_events, checkpoint=new_checkpoint)

    def event_types(self) -> list[str]:
        return ["log_line"]

    # --- Token management ---

    def _get_token(self) -> str:
        """Get a management API OAuth2 token."""
        if self._cached_token is not None and time.monotonic() < self._token_expires_at:
            return self._cached_token

        url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        resp = requests.post(url, data={
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "client_credentials",
            "scope": "https://management.azure.com/.default",
        })

        if resp.status_code != 200:
            raise ConfigError(
                f"Azure authentication failed (HTTP {resp.status_code}): {resp.text}"
            )

        data = resp.json()
        self._cached_token = data["access_token"]
        self._token_expires_at = (
            time.monotonic() + data.get("expires_in", 3600) - DEFAULT_TOKEN_EXPIRY_MARGIN
        )
        return self._cached_token

    def _get_la_token(self) -> str:
        """Get a Log Analytics API OAuth2 token."""
        if self._la_token is not None and time.monotonic() < self._la_token_expires_at:
            return self._la_token

        url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        resp = requests.post(url, data={
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "client_credentials",
            "scope": "https://api.loganalytics.io/.default",
        })

        if resp.status_code != 200:
            raise ConfigError(
                f"Log Analytics auth failed (HTTP {resp.status_code}): {resp.text}"
            )

        data = resp.json()
        self._la_token = data["access_token"]
        self._la_token_expires_at = (
            time.monotonic() + data.get("expires_in", 3600) - DEFAULT_TOKEN_EXPIRY_MARGIN
        )
        return self._la_token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}"}

    # --- Azure REST helpers ---

    def _get_paginated(
        self, url: str, params: dict[str, str] | None = None
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        headers = self._auth_headers()

        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise TypeError(
                f"Expected JSON object from Azure API, got {type(data).__name__}"
            )
        results.extend(data.get("value", []))

        while "nextLink" in data:
            validate_next_link(data["nextLink"], "azure")
            resp = requests.get(data["nextLink"], headers=headers)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                raise TypeError(
                    f"Expected JSON object from Azure API, got {type(data).__name__}"
                )
            results.extend(data.get("value", []))

        return results

    def _list_apps_url(self) -> str:
        return (
            f"https://management.azure.com/subscriptions/{self._subscription_id}"
            f"/resourceGroups/{self._resource_group}"
            f"/providers/Microsoft.App/containerApps"
            f"?api-version=2024-03-01"
        )

    # --- Log Analytics queries ---

    def _get_workspace_id(self, app_name: str, resource_group: str) -> str:
        """Resolve the Log Analytics workspace ID for a Container App."""
        headers = self._auth_headers()

        # Get the app's environment ID
        app_url = (
            f"https://management.azure.com/subscriptions/{self._subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.App/containerApps/{app_name}"
            f"?api-version=2024-03-01"
        )
        resp = requests.get(app_url, headers=headers)
        resp.raise_for_status()
        env_id = resp.json().get("properties", {}).get("environmentId", "")
        if not env_id:
            raise ConfigError(f"No environment found for app {app_name}")

        # Check cache
        if env_id in self._workspace_cache:
            return self._workspace_cache[env_id]

        # Get the workspace ID from the environment
        env_url = f"https://management.azure.com{env_id}?api-version=2024-03-01"
        resp = requests.get(env_url, headers=headers)
        resp.raise_for_status()
        workspace_id = (
            resp.json()
            .get("properties", {})
            .get("appLogsConfiguration", {})
            .get("logAnalyticsConfiguration", {})
            .get("customerId", "")
        )
        if not workspace_id:
            raise ConfigError(f"No Log Analytics workspace for environment {env_id}")

        self._workspace_cache[env_id] = workspace_id
        return workspace_id

    def _fetch_logs_for_app(
        self,
        app_name: str,
        resource_group: str,
        since: datetime | None,
    ) -> list[dict[str, Any]]:
        """Fetch container logs via Log Analytics query.

        Returns a list of row dicts with keys:
        TimeGenerated, Log_s, ContainerName_s, Stream_s, RevisionName_s, etc.
        """
        workspace_id = self._get_workspace_id(app_name, resource_group)
        la_token = self._get_la_token()

        # Build KQL query
        time_filter = ""
        if since is not None:
            since_str = since.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            time_filter = f'| where TimeGenerated > datetime("{since_str}")'
        else:
            lookback = (
                datetime.now(timezone.utc) - _FIRST_POLL_LOOKBACK
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            time_filter = f'| where TimeGenerated > datetime("{lookback}")'

        # Sanitize app_name for KQL: only allow alphanumeric, hyphens, underscores
        import re as _re
        safe_app = _re.sub(r"[^a-zA-Z0-9_-]", "", app_name)[:128]
        query = (
            f"ContainerAppConsoleLogs_CL "
            f'| where ContainerAppName_s == "{safe_app}" '
            f"{time_filter} "
            f"| order by TimeGenerated asc "
            f"| take {_MAX_LOG_ROWS}"
        )

        resp = requests.post(
            f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query",
            headers={"Authorization": f"Bearer {la_token}"},
            json={"query": query},
        )
        resp.raise_for_status()

        data = resp.json()
        tables = data.get("tables", [])
        if not tables:
            return []

        columns = [c["name"] for c in tables[0]["columns"]]
        rows = tables[0].get("rows", [])

        return [dict(zip(columns, row)) for row in rows]
