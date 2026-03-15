"""AWS CloudTrail connector — implements ConnectorBase."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
import defusedxml.ElementTree as ET

_log = logging.getLogger(__name__)

import requests

from mallcop.connectors._base import ConnectorBase
from mallcop.schemas import Checkpoint, DiscoveryResult, Event, PollResult, Severity
from mallcop.secrets import ConfigError, SecretProvider

# Map CloudTrail event names to mallcop event types
_EVENT_TYPE_MAP: dict[str, str] = {
    "CreateUser": "iam_change",
    "DeleteUser": "iam_change",
    "CreateGroup": "iam_change",
    "DeleteGroup": "iam_change",
    "AddUserToGroup": "iam_change",
    "RemoveUserFromGroup": "iam_change",
    "AttachUserPolicy": "policy_change",
    "DetachUserPolicy": "policy_change",
    "AttachRolePolicy": "policy_change",
    "DetachRolePolicy": "policy_change",
    "AttachGroupPolicy": "policy_change",
    "PutUserPolicy": "policy_change",
    "PutRolePolicy": "policy_change",
    "CreatePolicy": "policy_change",
    "DeletePolicy": "policy_change",
    "ConsoleLogin": "console_login",
    "AssumeRole": "role_assumed",
    "AssumeRoleWithSAML": "role_assumed",
    "AssumeRoleWithWebIdentity": "role_assumed",
    "CreateAccessKey": "access_key_change",
    "DeleteAccessKey": "access_key_change",
    "UpdateAccessKey": "access_key_change",
    "RunInstances": "instance_launch",
    "TerminateInstances": "instance_launch",
    "StartInstances": "instance_launch",
    "StopInstances": "instance_launch",
    "CreateBucket": "bucket_change",
    "DeleteBucket": "bucket_change",
    "PutBucketPolicy": "bucket_change",
    "DeleteBucketPolicy": "bucket_change",
    "PutBucketAcl": "bucket_change",
    "StopLogging": "logging_change",
    "DeleteTrail": "logging_change",
    "UpdateTrail": "logging_change",
    "AuthorizeSecurityGroupIngress": "security_group_change",
    "AuthorizeSecurityGroupEgress": "security_group_change",
    "RevokeSecurityGroupIngress": "security_group_change",
    "CreateSecurityGroup": "security_group_change",
    "DeleteSecurityGroup": "security_group_change",
}

_SECURITY_CRITICAL_EVENTS = {
    "StopLogging",
    "DeleteTrail",
    "ConsoleLogin",
    "CreateAccessKey",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutBucketPolicy",
    "AuthorizeSecurityGroupIngress",
}

_DEFAULT_EVENT_TYPE = "resource_modified"


def _classify_event_type(event_name: str) -> str:
    """Map a CloudTrail event name to a mallcop event type."""
    return _EVENT_TYPE_MAP.get(event_name, _DEFAULT_EVENT_TYPE)


_AUTH_ERROR_CODES = {
    "UnauthorizedOperation",
    "AccessDenied",
    "UnauthorizedAccess",
    "Client.UnauthorizedAccess",
}


def _classify_severity(event_name: str, error_code: str | None) -> Severity:
    """Determine severity based on event name and error status."""
    if error_code:
        if error_code in _AUTH_ERROR_CODES:
            return Severity.WARN
        return Severity.INFO
    if event_name in _SECURITY_CRITICAL_EVENTS:
        return Severity.WARN
    return Severity.INFO


from mallcop.aws_sigv4 import sign_v4_request
from mallcop.connectors._util import (
    DEFAULT_FIRST_POLL_LOOKBACK,
    build_checkpoint,
    make_event_id as _make_event_id,
    parse_iso_timestamp,
)


# Backward-compat alias for tests that import sign_v4 from this module.
sign_v4 = sign_v4_request


class AwsCloudTrailConnector(ConnectorBase):
    """AWS CloudTrail audit log connector."""

    def __init__(self, region: str = "us-east-1") -> None:
        self._access_key: str | None = None
        self._secret_key: str | None = None
        self._region: str = region
        self._account_id: str | None = None
        self._identity_arn: str | None = None

    def discover(self) -> DiscoveryResult:
        """Probe AWS for identity and CloudTrail trails."""
        # Verify identity
        try:
            identity = self._get_caller_identity()
        except Exception:
            return DiscoveryResult(
                available=False,
                resources=[],
                suggested_config={},
                missing_credentials=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
                notes=["Could not authenticate to AWS. Check credentials."],
            )

        account_id = identity.get("Account", "unknown")
        arn = identity.get("Arn", "unknown")

        # Enumerate trails
        try:
            trails = self._describe_trails()
        except Exception:
            trails = []

        resources = [f"Account {account_id} ({arn})"]
        for trail in trails:
            name = trail.get("Name", "unknown")
            region = trail.get("HomeRegion", "unknown")
            resources.append(f"Trail: {name} (region: {region})")

        return DiscoveryResult(
            available=True,
            resources=resources,
            suggested_config={
                "region": self._region,
                "account_id": account_id,
            },
            missing_credentials=[],
            notes=[f"Found {len(trails)} CloudTrail trail(s) in account {account_id}."],
        )

    def authenticate(self, secrets: SecretProvider) -> None:
        """Resolve AWS credentials and verify them via STS."""
        self._access_key = secrets.resolve("AWS_ACCESS_KEY_ID")
        self._secret_key = secrets.resolve("AWS_SECRET_ACCESS_KEY")
        # Try to resolve optional region
        try:
            self._region = secrets.resolve("AWS_DEFAULT_REGION")
        except Exception:
            pass  # Keep default
        # Validate credentials
        identity = self._get_caller_identity()
        self._account_id = identity.get("Account")
        self._identity_arn = identity.get("Arn")

    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        """Fetch new CloudTrail events since last checkpoint."""
        now = datetime.now(timezone.utc)

        if checkpoint is not None:
            start_time = parse_iso_timestamp(checkpoint.value)
        else:
            start_time = now - DEFAULT_FIRST_POLL_LOOKBACK

        raw_events = self._lookup_events(start_time, now)

        # Filter events after checkpoint (CloudTrail may return events at start_time)
        checkpoint_dt: datetime | None = None
        if checkpoint is not None:
            checkpoint_dt = parse_iso_timestamp(checkpoint.value)

        events: list[Event] = []
        latest_ts: datetime | None = None

        for raw in raw_events:
            event_time_str = raw.get("EventTime", raw.get("eventTime", ""))
            if not event_time_str:
                continue

            event_ts = parse_iso_timestamp(event_time_str)

            # Skip events at or before the checkpoint
            if checkpoint_dt is not None and event_ts <= checkpoint_dt:
                continue

            event_name = raw.get("EventName", "")

            # Parse the embedded CloudTrailEvent JSON for full details
            cloud_trail_event_str = raw.get("CloudTrailEvent", "{}")
            try:
                ct_event = json.loads(cloud_trail_event_str) if isinstance(cloud_trail_event_str, str) else cloud_trail_event_str
            except (json.JSONDecodeError, TypeError):
                _log.warning(
                    "Failed to parse CloudTrailEvent JSON for event %s: %s",
                    raw.get("EventId", "unknown"),
                    cloud_trail_event_str[:200] if isinstance(cloud_trail_event_str, str) else repr(cloud_trail_event_str),
                )
                ct_event = {}

            # Extract actor from userIdentity
            user_identity = ct_event.get("userIdentity", {})
            actor = (
                user_identity.get("userName")
                or user_identity.get("arn")
                or raw.get("Username", "unknown")
            )

            # Extract target from resources
            resources = raw.get("Resources", [])
            target = resources[0].get("ResourceName", "") if resources else ""

            # Error code from the detailed event
            error_code = ct_event.get("errorCode")

            evt = Event(
                id=_make_event_id(raw.get("EventId", "")),
                timestamp=event_ts,
                ingested_at=now,
                source="aws-cloudtrail",
                event_type=_classify_event_type(event_name),
                actor=actor,
                action=event_name,
                target=target,
                severity=_classify_severity(event_name, error_code),
                metadata={
                    "aws_region": ct_event.get("awsRegion", self._region),
                    "source_ip": ct_event.get("sourceIPAddress", ""),
                    "event_source": ct_event.get("eventSource", ""),
                    "account_id": self._account_id or "",
                    "error_code": error_code or "",
                },
                raw=raw,
            )
            events.append(evt)

            if latest_ts is None or event_ts > latest_ts:
                latest_ts = event_ts

        # Build checkpoint
        new_checkpoint = build_checkpoint("aws-cloudtrail", latest_ts.isoformat() if latest_ts else None, checkpoint, now)

        return PollResult(events=events, checkpoint=new_checkpoint)

    def event_types(self) -> list[str]:
        return [
            "iam_change",
            "console_login",
            "role_assumed",
            "access_key_change",
            "instance_launch",
            "bucket_change",
            "logging_change",
            "policy_change",
            "security_group_change",
            "resource_modified",
        ]

    # ── Internal API methods ─────────────────────────────────────────

    def _signed_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        service: str,
    ) -> requests.Response:
        """Make a signed AWS API request."""
        signed_headers = sign_v4_request(
            method=method,
            url=url,
            headers=dict(headers),  # copy to avoid mutation
            body=body,
            region=self._region,
            service=service,
            access_key=self._access_key or "",
            secret_key=self._secret_key or "",
        )
        return requests.request(method, url, headers=signed_headers, data=body)

    def _get_caller_identity(self) -> dict[str, str]:
        """Call STS GetCallerIdentity to verify credentials."""
        url = f"https://sts.{self._region}.amazonaws.com/"
        body = b"Action=GetCallerIdentity&Version=2011-06-15"
        headers = {"content-type": "application/x-www-form-urlencoded"}

        resp = self._signed_request("POST", url, headers, body, "sts")

        if resp.status_code != 200:
            raise ConfigError(
                f"AWS STS authentication failed (HTTP {resp.status_code}): {resp.text}"
            )

        return self._parse_sts_xml(resp.text)

    @staticmethod
    def _parse_sts_xml(xml_text: str) -> dict[str, str]:
        """Parse STS GetCallerIdentity XML response."""
        root = ET.fromstring(xml_text)
        # Handle namespace
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        result = root.find(f"{ns}GetCallerIdentityResult")
        if result is None:
            raise ConfigError("Invalid STS response: missing GetCallerIdentityResult")

        return {
            "Arn": (result.findtext(f"{ns}Arn") or ""),
            "UserId": (result.findtext(f"{ns}UserId") or ""),
            "Account": (result.findtext(f"{ns}Account") or ""),
        }

    def _describe_trails(self) -> list[dict[str, Any]]:
        """Call CloudTrail DescribeTrails."""
        url = f"https://cloudtrail.{self._region}.amazonaws.com/"
        body = b"{}"
        headers = {
            "content-type": "application/x-amz-json-1.1",
            "x-amz-target": "com.amazonaws.cloudtrail.v20131101.CloudTrailService.DescribeTrails",
        }

        resp = self._signed_request("POST", url, headers, body, "cloudtrail")

        if resp.status_code != 200:
            raise ConfigError(
                f"CloudTrail DescribeTrails failed (HTTP {resp.status_code}): {resp.text}"
            )

        data = resp.json()
        return data.get("trailList", [])

    def _lookup_events(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> list[dict[str, Any]]:
        """Call CloudTrail LookupEvents with pagination."""
        url = f"https://cloudtrail.{self._region}.amazonaws.com/"
        all_events: list[dict[str, Any]] = []
        next_token: str | None = None

        while True:
            payload: dict[str, Any] = {
                "StartTime": start_time.isoformat(),
                "EndTime": end_time.isoformat(),
                "MaxResults": 50,
            }
            if next_token:
                payload["NextToken"] = next_token

            body = json.dumps(payload).encode("utf-8")
            headers = {
                "content-type": "application/x-amz-json-1.1",
                "x-amz-target": "com.amazonaws.cloudtrail.v20131101.CloudTrailService.LookupEvents",
            }

            resp = self._signed_request("POST", url, headers, body, "cloudtrail")

            if resp.status_code != 200:
                raise ConfigError(
                    f"CloudTrail LookupEvents failed (HTTP {resp.status_code}): {resp.text}"
                )

            data = resp.json()
            all_events.extend(data.get("Events", []))

            next_token = data.get("NextToken")
            if not next_token:
                break

        return all_events
