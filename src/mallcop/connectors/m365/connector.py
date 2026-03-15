"""M365 Management Activity API connector — implements ConnectorBase."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from mallcop.connectors._base import ConnectorBase
from mallcop.connectors._util import (
    DEFAULT_FIRST_POLL_LOOKBACK,
    DEFAULT_TOKEN_EXPIRY_MARGIN,
    make_event_id,
    validate_next_link,
)
from mallcop.schemas import Checkpoint, DiscoveryResult, Event, PollResult, Severity
from mallcop.secrets import ConfigError, SecretProvider

_CONTENT_TYPES = [
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
]

_BASE_URL = "https://manage.office.com/api/v1.0"

# ─── Event classification ───────────────────────────────────────────

# Operations that map to admin actions
_ADMIN_OPS = {
    "Add member to role.",
    "Remove member from role.",
    "Update role.",
    "Add service principal.",
    "Update application.",
    "Add application.",
    "Reset user password.",
    "Set force change user password.",
    "Update user.",
    "Disable account.",
    "Enable account.",
}

# Operations that map to OAuth consent
_CONSENT_OPS = {"Consent to application."}

# Operations that map to mail forwarding rules
_FORWARDING_OPS = {"New-InboxRule", "Set-InboxRule", "Set-Mailbox"}

# Operations that map to mailbox access
_MAILBOX_OPS = {"MailboxLogin", "MailItemsAccessed"}

# Operations that map to SharePoint sharing
_SHARING_OPS = {"SharingSet", "SharingInvitationCreated", "AnonymousLinkCreated", "CompanyLinkCreated"}

# DLP record types
_DLP_RECORD_TYPES = {11, 33}


def _is_guest_invite(record: dict[str, Any]) -> bool:
    """Check if an 'Add user.' operation is a guest invitation."""
    op = record.get("Operation", "")
    if op != "Add user.":
        return False
    # Check ExtendedProperties for Guest UserType
    for prop in record.get("ExtendedProperties", []):
        if prop.get("Name") == "additionalDetails":
            val = prop.get("Value", "")
            if "Guest" in val:
                return True
    # Check Target type 5 = Guest
    for target in record.get("Target", []):
        if target.get("Type") == 5:
            return True
    return False


def _classify_event(record: dict[str, Any]) -> tuple[str, Severity]:
    """Map an M365 audit record to (event_type, severity)."""
    op = record.get("Operation", "")
    workload = record.get("Workload", "")
    record_type = record.get("RecordType", 0)

    # DLP alerts (check record type first, since DLP records come via General content type)
    if record_type in _DLP_RECORD_TYPES or op == "DlpRuleMatch":
        return "dlp_alert", Severity.WARN

    # AzureAD events
    if workload == "AzureActiveDirectory":
        if op == "UserLoggedIn":
            result = record.get("ResultStatus", "")
            if result.lower() in ("success", "succeeded"):
                return "sign_in_success", Severity.INFO
            return "sign_in_failure", Severity.INFO
        if op == "UserLoginFailed":
            return "sign_in_failure", Severity.INFO
        if op in _CONSENT_OPS:
            return "oauth_consent", Severity.WARN
        if _is_guest_invite(record):
            return "guest_invited", Severity.WARN
        if op in _ADMIN_OPS:
            return "admin_action", Severity.WARN
        # Default AzureAD → admin_action
        return "admin_action", Severity.WARN

    # Exchange events
    if workload == "Exchange":
        if op in _FORWARDING_OPS:
            return "mail_forwarding_rule", Severity.WARN
        if op in _MAILBOX_OPS:
            return "mailbox_access", Severity.INFO
        return "mailbox_access", Severity.INFO

    # SharePoint events
    if workload in ("SharePoint", "OneDrive"):
        if op in _SHARING_OPS:
            return "sharepoint_sharing", Severity.WARN
        return "sharepoint_activity", Severity.INFO

    # Fallback
    return "admin_action", Severity.WARN



def _parse_creation_time(ts: str) -> datetime:
    """Parse M365 CreationTime which may or may not have timezone info."""
    if ts.endswith("Z"):
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class M365Connector(ConnectorBase):
    def __init__(self) -> None:
        self._tenant_id: str | None = None
        self._client_id: str | None = None
        self._client_secret: str | None = None
        self._cached_token: str | None = None
        self._token_expires_at: float = 0.0

    def discover(self) -> DiscoveryResult:
        try:
            subs = self._list_subscriptions()
        except Exception:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"],
                notes=["Could not authenticate to M365 Management Activity API. Check credentials."],
            )

        if not subs:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=[],
                notes=["No M365 subscriptions found. Subscriptions may not be started."],
            )

        resources = [
            f"{s['contentType']} ({s['status']})" for s in subs
        ]
        content_types = [s["contentType"] for s in subs]

        return DiscoveryResult(
            available=True,
            resources=resources,
            suggested_config={"content_types": content_types},
            missing_credentials=[],
            notes=[f"Found {len(subs)} active content subscription(s)."],
        )

    def authenticate(self, secrets: SecretProvider) -> None:
        self._tenant_id = secrets.resolve("ENTRA_TENANT_ID")
        self._client_id = secrets.resolve("ENTRA_CLIENT_ID")
        self._client_secret = secrets.resolve("ENTRA_CLIENT_SECRET")
        self._get_token()
        self._ensure_subscriptions()

    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        now = datetime.now(timezone.utc)

        if checkpoint is not None:
            start_time = checkpoint.value
        else:
            start_time = (now - DEFAULT_FIRST_POLL_LOOKBACK).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        checkpoint_dt: datetime | None = None
        if checkpoint is not None:
            checkpoint_dt = _parse_creation_time(checkpoint.value)

        all_records: list[dict[str, Any]] = []
        for content_type in _CONTENT_TYPES:
            blobs = self._list_content_blobs(content_type, start_time, end_time)
            for blob in blobs:
                records = self._fetch_audit_records(blob["contentUri"])
                all_records.extend(records)

        events: list[Event] = []
        latest_ts: datetime | None = None

        for record in all_records:
            record_ts = _parse_creation_time(record["CreationTime"])

            if checkpoint_dt is not None and record_ts <= checkpoint_dt:
                continue

            event_type, severity = _classify_event(record)

            evt = Event(
                id=make_event_id(record.get("Id", "")),
                timestamp=record_ts,
                ingested_at=now,
                source="m365",
                event_type=event_type,
                actor=record.get("UserId", "unknown"),
                action=record.get("Operation", ""),
                target=record.get("ObjectId", ""),
                severity=severity,
                metadata={
                    "workload": record.get("Workload", ""),
                    "record_type": record.get("RecordType", 0),
                    "organization_id": record.get("OrganizationId", ""),
                    "result_status": record.get("ResultStatus", ""),
                    "ip_address": record.get("ClientIP", ""),
                },
                raw=record,
            )
            events.append(evt)

            if latest_ts is None or record_ts > latest_ts:
                latest_ts = record_ts

        if latest_ts is not None:
            new_checkpoint = Checkpoint(
                connector="m365",
                value=latest_ts.isoformat(),
                updated_at=now,
            )
        elif checkpoint is not None:
            new_checkpoint = Checkpoint(
                connector="m365",
                value=checkpoint.value,
                updated_at=now,
            )
        else:
            new_checkpoint = Checkpoint(
                connector="m365",
                value=now.isoformat(),
                updated_at=now,
            )

        return PollResult(events=events, checkpoint=new_checkpoint)

    def event_types(self) -> list[str]:
        return [
            "sign_in_success",
            "sign_in_failure",
            "admin_action",
            "oauth_consent",
            "guest_invited",
            "mailbox_access",
            "mail_forwarding_rule",
            "sharepoint_sharing",
            "sharepoint_activity",
            "dlp_alert",
        ]

    def _get_token(self) -> str:
        if self._cached_token is not None and time.monotonic() < self._token_expires_at:
            return self._cached_token

        url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        resp = requests.post(url, data={
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "client_credentials",
            "scope": "https://manage.office.com/.default",
        })

        if resp.status_code != 200:
            raise ConfigError(
                f"M365 authentication failed (HTTP {resp.status_code}): {resp.text}"
            )

        data = resp.json()
        self._cached_token = data["access_token"]
        self._token_expires_at = time.monotonic() + data.get("expires_in", 3600) - DEFAULT_TOKEN_EXPIRY_MARGIN
        return self._cached_token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}"}

    def _ensure_subscriptions(self) -> None:
        """Start subscriptions for all content types. Tolerate already-started."""
        for content_type in _CONTENT_TYPES:
            url = f"{_BASE_URL}/{self._tenant_id}/activity/feed/subscriptions/start"
            resp = requests.post(
                url,
                headers=self._auth_headers(),
                params={"contentType": content_type},
            )
            # 200 = started, 400 with AF20024 = already enabled — both OK
            if resp.status_code == 200:
                continue
            if resp.status_code == 400:
                try:
                    err = resp.json()
                    if err.get("error", {}).get("code") == "AF20024":
                        continue
                except (ValueError, KeyError):
                    pass
            resp.raise_for_status()

    def _list_subscriptions(self) -> list[dict[str, Any]]:
        """List current subscriptions."""
        url = f"{_BASE_URL}/{self._tenant_id}/activity/feed/subscriptions/list"
        resp = requests.get(url, headers=self._auth_headers())
        resp.raise_for_status()
        return resp.json()

    def _list_content_blobs(
        self,
        content_type: str,
        start_time: str,
        end_time: str,
    ) -> list[dict[str, Any]]:
        """List available content blobs for a content type within a time range."""
        url = f"{_BASE_URL}/{self._tenant_id}/activity/feed/subscriptions/content"
        params = {
            "contentType": content_type,
            "startTime": start_time,
            "endTime": end_time,
        }
        headers = self._auth_headers()

        blobs: list[dict[str, Any]] = []
        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        blobs.extend(resp.json())

        # M365 uses NextPageUri header for pagination
        while "NextPageUri" in resp.headers:
            next_url = resp.headers["NextPageUri"]
            validate_next_link(next_url, "m365")
            resp = requests.get(next_url, headers=headers)
            resp.raise_for_status()
            blobs.extend(resp.json())

        return blobs

    def _fetch_audit_records(self, content_uri: str) -> list[dict[str, Any]]:
        """Fetch audit records from a content blob URI."""
        validate_next_link(content_uri, "m365")
        headers = self._auth_headers()
        resp = requests.get(content_uri, headers=headers)
        resp.raise_for_status()
        return resp.json()
