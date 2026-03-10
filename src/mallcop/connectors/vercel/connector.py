"""Vercel connector — implements ConnectorBase."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import logging

import requests

from mallcop.connectors._base import ConnectorBase
from mallcop.schemas import Checkpoint, DiscoveryResult, Event, PollResult, Severity
from mallcop.secrets import ConfigError, SecretProvider

_log = logging.getLogger(__name__)

_BASE_URL = "https://api.vercel.com"

# Map Vercel audit actions to event types
_AUDIT_ACTION_MAP: dict[str, str] = {
    "project.created": "project_change",
    "project.removed": "project_change",
    "project.updated": "project_change",
    "deployment.created": "deployment",
    "member.added": "member_change",
    "member.removed": "member_change",
    "member.role-updated": "member_change",
    "domain.added": "domain_change",
    "domain.removed": "domain_change",
    "env.created": "env_change",
    "env.removed": "env_change",
    "env.updated": "env_change",
    "integration.installed": "integration_change",
    "integration.removed": "integration_change",
    "team.updated": "team_change",
    "access-token.created": "security_change",
    "access-token.deleted": "security_change",
}

_SECURITY_ACTIONS = {
    "member.added",
    "member.removed",
    "member.role-updated",
    "access-token.created",
    "access-token.deleted",
    "env.created",
    "env.removed",
    "env.updated",
}

_DEFAULT_EVENT_TYPE = "deployment"


def _classify_event_type(action: str) -> str:
    """Map a Vercel audit action string to a mallcop event type."""
    return _AUDIT_ACTION_MAP.get(action, _DEFAULT_EVENT_TYPE)


def _classify_severity(action: str) -> Severity:
    """Map a Vercel audit action to a severity level."""
    if action in _SECURITY_ACTIONS:
        return Severity.WARN
    return Severity.INFO


from mallcop.connectors._util import (
    DEFAULT_FIRST_POLL_LOOKBACK,
    make_event_id as _make_event_id,
)


class VercelConnector(ConnectorBase):
    """Connector for Vercel deployments and team audit log."""

    def __init__(self) -> None:
        self._token: str | None = None
        self._team_id: str | None = None

    def authenticate(self, secrets: SecretProvider) -> None:
        """Authenticate with Vercel API token. Optionally accepts a team ID."""
        self._token = secrets.resolve("VERCEL_TOKEN")
        try:
            self._team_id = secrets.resolve("VERCEL_TEAM_ID")
        except ConfigError:
            self._team_id = None
        # Validate token
        self._api_get("/v2/user")

    def discover(self) -> DiscoveryResult:
        """Probe Vercel for available teams, projects, and user info."""
        try:
            user = self._api_get("/v2/user")
        except Exception:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=["VERCEL_TOKEN"],
                notes=["Could not authenticate to Vercel. Check token."],
            )

        resources: list[str] = [
            f"User: {user.get('user', {}).get('username', 'unknown')}"
        ]
        config: dict[str, Any] = {}

        # Try to list teams
        try:
            teams_resp = self._api_get("/v2/teams")
            teams = teams_resp.get("teams", [])
            for t in teams:
                resources.append(
                    f"Team: {t.get('name', t.get('id', 'unknown'))}"
                )
            if teams and not self._team_id:
                config["team_id"] = teams[0]["id"]
        except Exception:
            pass

        # Try to list projects
        try:
            projects = self._api_get("/v9/projects")
            proj_list = projects.get("projects", [])
            resources.append(f"{len(proj_list)} project(s)")
        except Exception:
            pass

        return DiscoveryResult(
            available=True,
            resources=resources,
            suggested_config=config,
            missing_credentials=[],
            notes=[f"Found {len(resources)} resources."],
        )

    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        """Fetch new deployment and audit events since last checkpoint."""
        now = datetime.now(timezone.utc)

        if checkpoint is not None:
            since_ms = int(
                datetime.fromisoformat(checkpoint.value).timestamp() * 1000
            )
        else:
            since_ms = int(
                (now - DEFAULT_FIRST_POLL_LOOKBACK).timestamp() * 1000
            )

        events: list[Event] = []
        latest_ts: datetime | None = None

        # Fetch deployments
        try:
            deployments = self._fetch_deployments(since_ms)
            for d in deployments:
                evt = self._deployment_to_event(d, now)
                if evt:
                    events.append(evt)
                    if latest_ts is None or evt.timestamp > latest_ts:
                        latest_ts = evt.timestamp
        except Exception as e:
            _log.warning("Failed to fetch Vercel deployments: %s", e)

        # Fetch audit log (if team_id available)
        if self._team_id:
            try:
                audit_events = self._fetch_audit_log(since_ms)
                for a in audit_events:
                    evt = self._audit_to_event(a, now)
                    if evt:
                        events.append(evt)
                        if latest_ts is None or evt.timestamp > latest_ts:
                            latest_ts = evt.timestamp
            except Exception as e:
                _log.warning("Failed to fetch Vercel audit log: %s", e)

        # Build checkpoint
        if latest_ts is not None:
            new_cp = Checkpoint(
                connector="vercel",
                value=latest_ts.isoformat(),
                updated_at=now,
            )
        elif checkpoint is not None:
            new_cp = Checkpoint(
                connector="vercel",
                value=checkpoint.value,
                updated_at=now,
            )
        else:
            new_cp = Checkpoint(
                connector="vercel",
                value=now.isoformat(),
                updated_at=now,
            )

        return PollResult(events=events, checkpoint=new_cp)

    def event_types(self) -> list[str]:
        """Return all event types this connector can emit."""
        return sorted(set(_AUDIT_ACTION_MAP.values()) | {"deployment"})

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    def _api_get(self, path: str, params: dict | None = None) -> dict:
        """Make a GET request to the Vercel API."""
        url = f"{_BASE_URL}{path}"
        p = dict(params or {})
        if self._team_id:
            p["teamId"] = self._team_id
        resp = requests.get(url, headers=self._headers(), params=p, timeout=30)
        if resp.status_code != 200:
            _log.debug(
                "Vercel API error %s %s: %s", resp.status_code, path, resp.text
            )
            raise ConfigError(
                f"Vercel API error {resp.status_code} on {path}"
            )
        return resp.json()

    def _fetch_deployments(self, since_ms: int) -> list[dict]:
        """Fetch deployments created after since_ms."""
        data = self._api_get(
            "/v6/deployments", {"since": str(since_ms), "limit": "100"}
        )
        return data.get("deployments", [])

    def _fetch_audit_log(self, since_ms: int) -> list[dict]:
        """Fetch team audit log events after since_ms."""
        data = self._api_get(
            f"/v1/teams/{self._team_id}/audit-log",
            {"since": str(since_ms), "limit": "100"},
        )
        return data.get("events", [])

    def _deployment_to_event(
        self, d: dict, now: datetime
    ) -> Event | None:
        """Convert a Vercel deployment dict to a normalized Event."""
        created = d.get("created") or d.get("createdAt")
        if not created:
            return None
        ts = datetime.fromtimestamp(created / 1000, tz=timezone.utc)
        return Event(
            id=_make_event_id(d.get("uid", d.get("id", ""))),
            timestamp=ts,
            ingested_at=now,
            source="vercel",
            event_type="deployment",
            actor=d.get("creator", {}).get("username", "unknown"),
            action="deployment.created",
            target=d.get("name", d.get("url", "")),
            severity=Severity.INFO,
            metadata={
                "state": d.get("state", ""),
                "target": d.get("target", ""),
                "project_id": d.get("projectId", ""),
            },
            raw=d,
        )

    def _audit_to_event(
        self, a: dict, now: datetime
    ) -> Event | None:
        """Convert a Vercel audit log entry to a normalized Event."""
        ts_raw = a.get("createdAt")
        if not ts_raw:
            return None
        ts = datetime.fromtimestamp(ts_raw / 1000, tz=timezone.utc)
        action = a.get("action", "")
        return Event(
            id=_make_event_id(a.get("id", "")),
            timestamp=ts,
            ingested_at=now,
            source="vercel",
            event_type=_classify_event_type(action),
            actor=a.get("user", {}).get(
                "username", a.get("userId", "unknown")
            ),
            action=action,
            target=a.get("entity", {}).get(
                "name", a.get("entityId", "")
            ),
            severity=_classify_severity(action),
            metadata={
                "entity_type": a.get("entity", {}).get("type", ""),
                "entity_id": a.get("entityId", ""),
            },
            raw=a,
        )
