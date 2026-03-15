"""Supabase connector — auth audit logs + Management API config monitoring.

Two data paths:
1. Auth audit logs via PostgREST (auth.audit_log_entries table)
2. Management API config diff polling (secrets, API keys, auth config)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import requests

from mallcop.connectors._base import ConnectorBase
from mallcop.connectors._util import make_event_id, parse_iso_timestamp
from mallcop.schemas import Checkpoint, DiscoveryResult, Event, PollResult, Severity
from mallcop.secrets import ConfigError, SecretProvider

_MGMT_API_BASE = "https://api.supabase.com/v1"

# Map Supabase auth actions to mallcop event types
_AUTH_ACTION_MAP: dict[str, str] = {
    "login": "auth_success",
    "user_signedup": "user_created",
    "user_confirmation_requested": "user_created",
    "logout": "auth_logout",
    "token_refreshed": "token_refresh",
    "token_revoked": "token_refresh",
    "user_recovery_requested": "password_recovery",
    "user_invited": "user_invited",
    "user_deleted": "user_deleted",
    "user_updated": "config_change",
    "mfa_challenge_verified": "mfa_verified",
}

_DEFAULT_AUTH_EVENT_TYPE = "auth_success"

# Severity by event type
_SEVERITY_MAP: dict[str, Severity] = {
    "auth_success": Severity.INFO,
    "auth_failure": Severity.WARN,
    "auth_logout": Severity.INFO,
    "user_created": Severity.INFO,
    "user_deleted": Severity.WARN,
    "user_invited": Severity.INFO,
    "password_recovery": Severity.WARN,
    "token_refresh": Severity.INFO,
    "mfa_verified": Severity.INFO,
    "secret_change": Severity.CRITICAL,
    "api_key_change": Severity.CRITICAL,
    "config_change": Severity.WARN,
}


def _classify_auth_action(action: str, payload: dict[str, Any]) -> str:
    """Map a Supabase auth action to a mallcop event type."""
    # Failed logins have action="login" but traits.error in payload
    if action == "login" and payload.get("traits", {}).get("error"):
        return "auth_failure"
    return _AUTH_ACTION_MAP.get(action, _DEFAULT_AUTH_EVENT_TYPE)


def _map_severity(event_type: str) -> Severity:
    return _SEVERITY_MAP.get(event_type, Severity.INFO)


def _extract_actor(payload: dict[str, Any]) -> str:
    """Extract actor identity from auth audit payload."""
    # Try email first, then actor_id, then user_id from traits
    traits = payload.get("traits", {})
    if traits.get("email"):
        return traits["email"]
    if payload.get("actor_id"):
        return payload["actor_id"]
    if traits.get("user_id"):
        return traits["user_id"]
    return "unknown"


class SupabaseConnector(ConnectorBase):
    """Supabase auth audit logs + project config change monitoring."""

    def __init__(self) -> None:
        self._project_url: str | None = None
        self._service_role_key: str | None = None
        self._project_ref: str | None = None
        self._access_token: str | None = None  # Optional: Management API

    def discover(self) -> DiscoveryResult:
        """Probe Supabase for project availability."""
        if not self._project_url or not self._service_role_key:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=[
                    "SUPABASE_PROJECT_URL",
                    "SUPABASE_SERVICE_ROLE_KEY",
                    "SUPABASE_PROJECT_REF",
                ],
                notes=["Supabase credentials not configured."],
            )

        # Try querying the auth audit table
        try:
            resp = self._postgrest_get(
                "auth.audit_log_entries",
                params={"select": "id", "limit": "1"},
            )
            resp.raise_for_status()
        except Exception as exc:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=[],
                notes=[f"Cannot access auth.audit_log_entries: {exc}"],
            )

        resources = [f"project: {self._project_ref}"]
        notes = ["Auth audit log table accessible."]

        # Check Management API if token available
        if self._access_token:
            try:
                info = self._mgmt_get(f"/projects/{self._project_ref}")
                name = info.get("name", self._project_ref)
                resources.append(f"project_name: {name}")
                notes.append("Management API accessible.")
            except Exception:
                notes.append("Management API not accessible (SUPABASE_ACCESS_TOKEN may be invalid).")

        return DiscoveryResult(
            available=True,
            resources=resources,
            suggested_config={"project_ref": self._project_ref},
            missing_credentials=[],
            notes=notes,
        )

    def authenticate(self, secrets: SecretProvider) -> None:
        """Resolve credentials. service_role_key + project_url required, access_token optional."""
        self._project_url = secrets.resolve("SUPABASE_PROJECT_URL").rstrip("/")
        self._service_role_key = secrets.resolve("SUPABASE_SERVICE_ROLE_KEY")
        self._project_ref = secrets.resolve("SUPABASE_PROJECT_REF")

        try:
            self._access_token = secrets.resolve("SUPABASE_ACCESS_TOKEN")
        except ConfigError:
            self._access_token = None

        # Validate by querying auth audit table
        self._validate_connection()

    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        """Fetch auth audit logs and config changes since last checkpoint."""
        now = datetime.now(timezone.utc)
        all_events: list[Event] = []

        # Parse composite checkpoint: "auth_ts|config_ts"
        auth_checkpoint, config_checkpoint = self._parse_checkpoint(checkpoint)

        # 1. Auth audit logs via PostgREST
        auth_events, new_auth_ts = self._poll_auth_audit(auth_checkpoint, now)
        all_events.extend(auth_events)

        # 2. Config changes via Management API (if token available)
        config_events = []
        new_config_ts = config_checkpoint or now.isoformat()
        if self._access_token:
            config_events, new_config_ts = self._poll_config_changes(
                config_checkpoint, now
            )
            all_events.extend(config_events)

        # Build composite checkpoint
        checkpoint_value = f"{new_auth_ts}|{new_config_ts}"
        new_checkpoint = Checkpoint(
            connector="supabase",
            value=checkpoint_value,
            updated_at=now,
        )

        return PollResult(events=all_events, checkpoint=new_checkpoint)

    def event_types(self) -> list[str]:
        return [
            "auth_success",
            "auth_failure",
            "auth_logout",
            "user_created",
            "user_deleted",
            "user_invited",
            "password_recovery",
            "token_refresh",
            "mfa_verified",
            "secret_change",
            "api_key_change",
            "config_change",
        ]

    # ─── PostgREST helpers ───────────────────────────────────────

    def _postgrest_headers(self) -> dict[str, str]:
        return {
            "apikey": self._service_role_key or "",
            "Authorization": f"Bearer {self._service_role_key}",
            "Accept": "application/json",
        }

    def _postgrest_get(
        self, table: str, params: dict[str, str] | None = None
    ) -> requests.Response:
        """GET from PostgREST endpoint."""
        url = f"{self._project_url}/rest/v1/{table}"
        return requests.get(url, headers=self._postgrest_headers(), params=params)

    def _validate_connection(self) -> None:
        """Validate credentials by querying auth audit table."""
        resp = self._postgrest_get(
            "auth.audit_log_entries",
            params={"select": "id", "limit": "1"},
        )
        if resp.status_code == 401:
            raise ConfigError(
                "Supabase authentication failed: invalid service_role_key"
            )
        if resp.status_code >= 400:
            raise ConfigError(
                f"Supabase connection failed (HTTP {resp.status_code}): {resp.text}"
            )

    # ─── Management API helpers ──────────────────────────────────

    def _mgmt_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
        }

    def _mgmt_get(self, path: str) -> dict[str, Any]:
        """GET from Management API."""
        resp = requests.get(
            f"{_MGMT_API_BASE}{path}",
            headers=self._mgmt_headers(),
        )
        resp.raise_for_status()
        return resp.json()

    # ─── Checkpoint parsing ──────────────────────────────────────

    @staticmethod
    def _parse_checkpoint(
        checkpoint: Checkpoint | None,
    ) -> tuple[str | None, str | None]:
        """Parse composite checkpoint 'auth_ts|config_ts' into parts."""
        if checkpoint is None or not checkpoint.value:
            return None, None
        parts = checkpoint.value.split("|", 1)
        auth_ts = parts[0] if parts[0] else None
        config_ts = parts[1] if len(parts) > 1 and parts[1] else None
        return auth_ts, config_ts

    # ─── Auth audit polling ──────────────────────────────────────

    def _poll_auth_audit(
        self, since_ts: str | None, now: datetime
    ) -> tuple[list[Event], str]:
        """Query auth.audit_log_entries for new entries.

        Returns (events, latest_timestamp_iso).
        """
        params: dict[str, str] = {
            "select": "*",
            "order": "created_at.asc",
            "limit": "1000",
        }
        if since_ts:
            params["created_at"] = f"gt.{since_ts}"

        resp = self._postgrest_get("auth.audit_log_entries", params=params)
        resp.raise_for_status()
        entries: list[dict[str, Any]] = resp.json()

        events: list[Event] = []
        latest_ts = since_ts or ""

        for entry in entries:
            event = self._normalize_auth_entry(entry, now)
            events.append(event)

            entry_ts = entry.get("created_at", "")
            if entry_ts > latest_ts:
                latest_ts = entry_ts

        return events, latest_ts

    def _normalize_auth_entry(
        self, entry: dict[str, Any], now: datetime
    ) -> Event:
        """Normalize a single auth.audit_log_entries row to Event."""
        payload = entry.get("payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                payload = {}

        action = payload.get("action", entry.get("action", ""))
        event_type = _classify_auth_action(action, payload)
        severity = _map_severity(event_type)
        actor = _extract_actor(payload)

        raw_ts = entry.get("created_at", "")
        try:
            timestamp = parse_iso_timestamp(raw_ts)
        except (ValueError, TypeError):
            timestamp = now

        entry_id = str(entry.get("id", ""))
        ip_address = entry.get("ip_address", payload.get("traits", {}).get("ip", ""))

        return Event(
            id=make_event_id(f"supabase-auth-{entry_id}"),
            timestamp=timestamp,
            ingested_at=now,
            source="supabase",
            event_type=event_type,
            actor=actor,
            action=action,
            target=self._project_ref or "",
            severity=severity,
            metadata={
                "project_ref": self._project_ref,
                "ip_address": ip_address,
                "auth_action": action,
            },
            raw=entry,
        )

    # ─── Config diff polling ─────────────────────────────────────

    def _poll_config_changes(
        self, since_ts: str | None, now: datetime
    ) -> tuple[list[Event], str]:
        """Poll Management API for config changes. Returns synthetic events.

        Stub: config change detection requires caching previous state in the
        checkpoint. Until that is implemented, skip the API calls to avoid
        wasting rate limit quota for zero functional benefit.
        """
        return [], now.isoformat()
