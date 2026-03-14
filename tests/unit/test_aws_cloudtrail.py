"""Tests for AWS CloudTrail connector."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.schemas import (
    Checkpoint,
    DiscoveryResult,
    Event,
    PollResult,
    Severity,
)
from mallcop.secrets import ConfigError, SecretProvider

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "aws_cloudtrail"


def _load_fixture(name: str) -> Any:
    with open(FIXTURES_DIR / name) as f:
        if name.endswith(".json"):
            return json.load(f)
        return f.read()


class FakeSecretProvider(SecretProvider):
    """Secret provider backed by a dict for testing."""

    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = secrets

    def resolve(self, name: str) -> str:
        if name not in self._secrets:
            raise ConfigError(f"Secret '{name}' not found")
        return self._secrets[name]


# ─── Event type classification ───────────────────────────────────────


class TestEventTypeClassification:
    def test_console_login(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_event_type

        assert _classify_event_type("ConsoleLogin") == "console_login"

    def test_iam_changes(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_event_type

        assert _classify_event_type("CreateUser") == "iam_change"
        assert _classify_event_type("DeleteUser") == "iam_change"
        assert _classify_event_type("AddUserToGroup") == "iam_change"

    def test_policy_changes(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_event_type

        assert _classify_event_type("AttachUserPolicy") == "policy_change"
        assert _classify_event_type("DetachRolePolicy") == "policy_change"
        assert _classify_event_type("CreatePolicy") == "policy_change"

    def test_role_assumed(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_event_type

        assert _classify_event_type("AssumeRole") == "role_assumed"
        assert _classify_event_type("AssumeRoleWithSAML") == "role_assumed"

    def test_access_key_change(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_event_type

        assert _classify_event_type("CreateAccessKey") == "access_key_change"
        assert _classify_event_type("DeleteAccessKey") == "access_key_change"

    def test_instance_launch(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_event_type

        assert _classify_event_type("RunInstances") == "instance_launch"
        assert _classify_event_type("TerminateInstances") == "instance_launch"

    def test_bucket_change(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_event_type

        assert _classify_event_type("CreateBucket") == "bucket_change"
        assert _classify_event_type("PutBucketPolicy") == "bucket_change"

    def test_logging_change(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_event_type

        assert _classify_event_type("StopLogging") == "logging_change"
        assert _classify_event_type("DeleteTrail") == "logging_change"

    def test_security_group_change(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_event_type

        assert _classify_event_type("AuthorizeSecurityGroupIngress") == "security_group_change"
        assert _classify_event_type("CreateSecurityGroup") == "security_group_change"

    def test_unknown_event_defaults_to_resource_modified(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_event_type

        assert _classify_event_type("SomeRandomEvent") == "resource_modified"
        assert _classify_event_type("DescribeInstances") == "resource_modified"


# ─── Severity classification ─────────────────────────────────────────


class TestSeverityClassification:
    def test_security_critical_events_are_warn(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_severity

        assert _classify_severity("StopLogging", None) == Severity.WARN
        assert _classify_severity("DeleteTrail", None) == Severity.WARN
        assert _classify_severity("ConsoleLogin", None) == Severity.WARN
        assert _classify_severity("CreateAccessKey", None) == Severity.WARN

    def test_normal_events_are_info(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_severity

        assert _classify_severity("DescribeInstances", None) == Severity.INFO
        assert _classify_severity("RunInstances", None) == Severity.INFO

    def test_unauthorized_error_is_warn(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_severity

        assert _classify_severity("RunInstances", "Client.UnauthorizedAccess") == Severity.WARN
        assert _classify_severity("DeleteBucket", "AccessDenied") == Severity.WARN

    def test_other_error_is_info(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _classify_severity

        assert _classify_severity("RunInstances", "Client.DryRunOperation") == Severity.INFO

    def test_exact_error_code_matching(self) -> None:
        """Error codes must match exactly, not by substring."""
        from mallcop.connectors.aws_cloudtrail.connector import _classify_severity

        # Exact matches should be WARN
        assert _classify_severity("RunInstances", "UnauthorizedOperation") == Severity.WARN
        assert _classify_severity("RunInstances", "AccessDenied") == Severity.WARN
        assert _classify_severity("RunInstances", "UnauthorizedAccess") == Severity.WARN

        # Substring-only matches should NOT be WARN — they are just errors
        assert _classify_severity("RunInstances", "Client.UnauthorizedFoo") == Severity.INFO
        assert _classify_severity("RunInstances", "SomeUnauthorizedThing") == Severity.INFO
        assert _classify_severity("RunInstances", "AccessDeniedByPolicy") == Severity.INFO


# ─── Event ID generation ─────────────────────────────────────────────


class TestEventIdGeneration:
    def test_event_id_is_deterministic(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _make_event_id

        id1 = _make_event_id("abc-123")
        id2 = _make_event_id("abc-123")
        assert id1 == id2

    def test_event_id_has_prefix(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _make_event_id

        assert _make_event_id("abc-123").startswith("evt_")

    def test_different_inputs_different_ids(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import _make_event_id

        assert _make_event_id("abc-123") != _make_event_id("xyz-789")


# ─── SigV4 signing ──────────────────────────────────────────────────


class TestSigV4Signing:
    def test_sign_v4_produces_authorization_header(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import sign_v4

        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        headers = sign_v4(
            method="POST",
            url="https://sts.us-east-1.amazonaws.com/",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body=b"Action=GetCallerIdentity&Version=2011-06-15",
            region="us-east-1",
            service="sts",
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            timestamp=ts,
        )

        assert "Authorization" in headers
        auth = headers["Authorization"]
        assert auth.startswith("AWS4-HMAC-SHA256")
        assert "Credential=AKIAIOSFODNN7EXAMPLE/20260310/us-east-1/sts/aws4_request" in auth
        assert "SignedHeaders=" in auth
        assert "Signature=" in auth

    def test_sign_v4_adds_amz_date_header(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import sign_v4

        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        headers = sign_v4(
            method="POST",
            url="https://sts.us-east-1.amazonaws.com/",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body=b"test",
            region="us-east-1",
            service="sts",
            access_key="AKIATEST",
            secret_key="secret",
            timestamp=ts,
        )

        assert headers["x-amz-date"] == "20260310T120000Z"

    def test_sign_v4_adds_host_header(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import sign_v4

        headers = sign_v4(
            method="POST",
            url="https://cloudtrail.us-west-2.amazonaws.com/",
            headers={"content-type": "application/x-amz-json-1.1"},
            body=b"{}",
            region="us-west-2",
            service="cloudtrail",
            access_key="AKIATEST",
            secret_key="secret",
        )

        assert headers["host"] == "cloudtrail.us-west-2.amazonaws.com"

    def test_sign_v4_different_bodies_produce_different_signatures(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import sign_v4

        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        common = dict(
            method="POST",
            url="https://sts.us-east-1.amazonaws.com/",
            region="us-east-1",
            service="sts",
            access_key="AKIATEST",
            secret_key="secret",
            timestamp=ts,
        )

        h1 = sign_v4(headers={"content-type": "text/plain"}, body=b"body1", **common)
        h2 = sign_v4(headers={"content-type": "text/plain"}, body=b"body2", **common)

        sig1 = h1["Authorization"].split("Signature=")[1]
        sig2 = h2["Authorization"].split("Signature=")[1]
        assert sig1 != sig2

    def test_sign_v4_is_deterministic(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import sign_v4

        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        kwargs = dict(
            method="POST",
            url="https://sts.us-east-1.amazonaws.com/",
            body=b"test",
            region="us-east-1",
            service="sts",
            access_key="AKIATEST",
            secret_key="secret",
            timestamp=ts,
        )

        h1 = sign_v4(headers={"content-type": "text/plain"}, **kwargs)
        h2 = sign_v4(headers={"content-type": "text/plain"}, **kwargs)

        assert h1["Authorization"] == h2["Authorization"]

    def test_sign_v4_session_token_included_in_headers(self) -> None:
        from mallcop.aws_sigv4 import sign_v4_request

        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        headers = sign_v4_request(
            method="POST",
            url="https://bedrock-runtime.us-east-1.amazonaws.com/model/x/converse",
            headers={"content-type": "application/json"},
            body=b'{"messages":[]}',
            region="us-east-1",
            service="bedrock",
            access_key="ASIAEXAMPLE",
            secret_key="secret",
            timestamp=ts,
            session_token="FwoGZXIvYXdzEBYaDHtest==",
        )

        assert headers["x-amz-security-token"] == "FwoGZXIvYXdzEBYaDHtest=="
        # Token header must be included in signed headers
        assert "x-amz-security-token" in headers["Authorization"]

    def test_sign_v4_no_session_token_when_empty(self) -> None:
        from mallcop.aws_sigv4 import sign_v4_request

        ts = datetime(2026, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        headers = sign_v4_request(
            method="POST",
            url="https://bedrock-runtime.us-east-1.amazonaws.com/model/x/converse",
            headers={"content-type": "application/json"},
            body=b'{"messages":[]}',
            region="us-east-1",
            service="bedrock",
            access_key="AKIAEXAMPLE",
            secret_key="secret",
            timestamp=ts,
        )

        assert "x-amz-security-token" not in headers


# ─── STS XML parsing ────────────────────────────────────────────────


class TestStsXmlParsing:
    def test_parse_sts_xml_from_fixture(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        xml_text = _load_fixture("get_caller_identity.xml")
        result = AwsCloudTrailConnector._parse_sts_xml(xml_text)

        assert result["Account"] == "123456789012"
        assert result["Arn"] == "arn:aws:iam::123456789012:user/mallcop-monitor"
        assert result["UserId"] == "AIDAEXAMPLEMONITOR"

    def test_parse_sts_xml_invalid_raises(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        with pytest.raises(ConfigError, match="missing GetCallerIdentityResult"):
            AwsCloudTrailConnector._parse_sts_xml("<Root></Root>")

    def test_parse_sts_xml_rejects_xxe(self) -> None:
        """XML with external entity declarations must be rejected (XXE defense)."""
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        xxe_xml = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
            ']>'
            '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
            '<GetCallerIdentityResult>'
            '<Arn>&xxe;</Arn>'
            '<UserId>AIDA</UserId>'
            '<Account>123</Account>'
            '</GetCallerIdentityResult>'
            '</GetCallerIdentityResponse>'
        )
        # defusedxml should raise on DTD with external entities
        with pytest.raises(Exception):
            AwsCloudTrailConnector._parse_sts_xml(xxe_xml)

    def test_parse_sts_xml_uses_defusedxml(self) -> None:
        """Verify the connector source uses defusedxml, not stdlib xml.etree.ElementTree."""
        connector_path = (
            Path(__file__).parent.parent.parent
            / "src" / "mallcop" / "connectors" / "aws_cloudtrail" / "connector.py"
        )
        source = connector_path.read_text()
        # Must import defusedxml
        assert "import defusedxml" in source, "connector must use defusedxml for XML parsing"
        # Must NOT import stdlib ElementTree
        assert "from xml.etree import ElementTree" not in source, (
            "connector must not use stdlib xml.etree.ElementTree (XXE vulnerable)"
        )


# ─── authenticate() ─────────────────────────────────────────────────


class TestAwsCloudTrailAuthenticate:
    def test_authenticate_succeeds_with_valid_secrets(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        secrets = FakeSecretProvider({
            "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "secret123",
        })

        connector = AwsCloudTrailConnector()
        identity = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test", "UserId": "AIDA"}

        with patch.object(connector, "_get_caller_identity", return_value=identity):
            connector.authenticate(secrets)

        assert connector._access_key == "AKIAEXAMPLE"
        assert connector._secret_key == "secret123"
        assert connector._account_id == "123456789012"

    def test_authenticate_raises_on_missing_access_key(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        secrets = FakeSecretProvider({
            "AWS_SECRET_ACCESS_KEY": "secret123",
        })

        connector = AwsCloudTrailConnector()
        with pytest.raises(ConfigError, match="AWS_ACCESS_KEY_ID"):
            connector.authenticate(secrets)

    def test_authenticate_raises_on_missing_secret_key(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        secrets = FakeSecretProvider({
            "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
        })

        connector = AwsCloudTrailConnector()
        with pytest.raises(ConfigError, match="AWS_SECRET_ACCESS_KEY"):
            connector.authenticate(secrets)

    def test_authenticate_resolves_optional_region(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        secrets = FakeSecretProvider({
            "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "secret123",
            "AWS_DEFAULT_REGION": "eu-west-1",
        })

        connector = AwsCloudTrailConnector()
        identity = {"Account": "123", "Arn": "arn", "UserId": "uid"}

        with patch.object(connector, "_get_caller_identity", return_value=identity):
            connector.authenticate(secrets)

        assert connector._region == "eu-west-1"


# ─── discover() ─────────────────────────────────────────────────────


class TestAwsCloudTrailDiscover:
    def test_discover_returns_available_with_trails(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        identity = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test", "UserId": "AIDA"}
        trails_fixture = _load_fixture("describe_trails.json")

        with patch.object(connector, "_get_caller_identity", return_value=identity), \
             patch.object(connector, "_describe_trails", return_value=trails_fixture["trailList"]):
            result = connector.discover()

        assert isinstance(result, DiscoveryResult)
        assert result.available is True
        assert len(result.resources) == 3  # 1 account + 2 trails
        assert "123456789012" in result.resources[0]
        assert "main-trail" in result.resources[1]
        assert "secondary-trail" in result.resources[2]

    def test_discover_returns_unavailable_on_auth_failure(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()

        with patch.object(connector, "_get_caller_identity", side_effect=Exception("Auth failed")):
            result = connector.discover()

        assert result.available is False
        assert "AWS_ACCESS_KEY_ID" in result.missing_credentials

    def test_discover_suggests_config(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        identity = {"Account": "123456789012", "Arn": "arn", "UserId": "uid"}

        with patch.object(connector, "_get_caller_identity", return_value=identity), \
             patch.object(connector, "_describe_trails", return_value=[]):
            result = connector.discover()

        assert "region" in result.suggested_config
        assert result.suggested_config["account_id"] == "123456789012"

    def test_discover_handles_trail_enumeration_failure(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        identity = {"Account": "123456789012", "Arn": "arn", "UserId": "uid"}

        with patch.object(connector, "_get_caller_identity", return_value=identity), \
             patch.object(connector, "_describe_trails", side_effect=Exception("Forbidden")):
            result = connector.discover()

        # Still available (identity works), just no trails
        assert result.available is True
        assert len(result.resources) == 1  # just the account


# ─── poll() ──────────────────────────────────────────────────────────


class TestAwsCloudTrailPoll:
    def _make_authenticated_connector(self):
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        connector._access_key = "AKIATEST"
        connector._secret_key = "secrettest"
        connector._region = "us-east-1"
        connector._account_id = "123456789012"
        return connector

    def test_poll_normalizes_events(self) -> None:
        fixture = _load_fixture("lookup_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(connector, "_lookup_events", return_value=fixture["Events"]):
            result = connector.poll(checkpoint=None)

        assert isinstance(result, PollResult)
        assert len(result.events) == 5

        # First event: ConsoleLogin
        evt = result.events[0]
        assert isinstance(evt, Event)
        assert evt.source == "aws-cloudtrail"
        assert evt.event_type == "console_login"
        assert evt.actor == "admin@example.com"
        assert evt.action == "ConsoleLogin"
        assert evt.target == "admin"
        assert evt.severity == Severity.WARN  # ConsoleLogin is security-critical

    def test_poll_sets_correct_timestamps(self) -> None:
        fixture = _load_fixture("lookup_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(connector, "_lookup_events", return_value=fixture["Events"]):
            result = connector.poll(checkpoint=None)

        evt = result.events[0]
        assert evt.timestamp == datetime(2026, 3, 10, 10, 0, 0, tzinfo=timezone.utc)
        assert isinstance(evt.ingested_at, datetime)
        assert evt.ingested_at.tzinfo is not None

    def test_poll_returns_checkpoint_at_latest_event(self) -> None:
        fixture = _load_fixture("lookup_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(connector, "_lookup_events", return_value=fixture["Events"]):
            result = connector.poll(checkpoint=None)

        assert isinstance(result.checkpoint, Checkpoint)
        assert result.checkpoint.connector == "aws-cloudtrail"
        # Latest event is at 16:00
        assert result.checkpoint.value == "2026-03-10T16:00:00+00:00"

    def test_poll_with_checkpoint_filters_events(self) -> None:
        fixture = _load_fixture("lookup_events.json")
        connector = self._make_authenticated_connector()

        checkpoint = Checkpoint(
            connector="aws-cloudtrail",
            value="2026-03-10T11:30:00+00:00",
            updated_at=datetime(2026, 3, 10, 11, 30, 0, tzinfo=timezone.utc),
        )

        with patch.object(connector, "_lookup_events", return_value=fixture["Events"]):
            result = connector.poll(checkpoint=checkpoint)

        # Should only return events after 11:30 — RunInstances, StopLogging, TerminateInstances
        assert len(result.events) == 3
        assert result.events[0].action == "RunInstances"
        assert result.events[1].action == "StopLogging"
        assert result.events[2].action == "TerminateInstances"

    def test_poll_empty_response_keeps_checkpoint(self) -> None:
        connector = self._make_authenticated_connector()

        checkpoint = Checkpoint(
            connector="aws-cloudtrail",
            value="2026-03-10T20:00:00+00:00",
            updated_at=datetime(2026, 3, 10, 20, 0, 0, tzinfo=timezone.utc),
        )

        with patch.object(connector, "_lookup_events", return_value=[]):
            result = connector.poll(checkpoint=checkpoint)

        assert len(result.events) == 0
        assert result.checkpoint.value == checkpoint.value

    def test_poll_classifies_event_types_correctly(self) -> None:
        fixture = _load_fixture("lookup_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(connector, "_lookup_events", return_value=fixture["Events"]):
            result = connector.poll(checkpoint=None)

        types = [e.event_type for e in result.events]
        assert types == [
            "console_login",
            "access_key_change",
            "instance_launch",
            "logging_change",
            "instance_launch",  # TerminateInstances
        ]

    def test_poll_unauthorized_error_gets_warn_severity(self) -> None:
        fixture = _load_fixture("lookup_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(connector, "_lookup_events", return_value=fixture["Events"]):
            result = connector.poll(checkpoint=None)

        # Last event has UnauthorizedAccess error
        assert result.events[4].severity == Severity.WARN

    def test_poll_preserves_raw_data(self) -> None:
        fixture = _load_fixture("lookup_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(connector, "_lookup_events", return_value=fixture["Events"]):
            result = connector.poll(checkpoint=None)

        for i, evt in enumerate(result.events):
            assert evt.raw == fixture["Events"][i]

    def test_poll_extracts_metadata(self) -> None:
        fixture = _load_fixture("lookup_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(connector, "_lookup_events", return_value=fixture["Events"]):
            result = connector.poll(checkpoint=None)

        meta = result.events[0].metadata
        assert meta["aws_region"] == "us-east-1"
        assert meta["source_ip"] == "203.0.113.1"
        assert meta["event_source"] == "signin.amazonaws.com"
        assert meta["account_id"] == "123456789012"

    def test_poll_logs_warning_on_malformed_cloudtrail_json(self, caplog) -> None:
        """Malformed CloudTrailEvent JSON should log a warning, not silently skip."""
        import logging

        connector = self._make_authenticated_connector()
        raw_event = {
            "EventId": "evt-bad-json",
            "EventName": "ConsoleLogin",
            "EventTime": "2026-03-10T10:00:00Z",
            "CloudTrailEvent": "{this is not valid json!!!",
            "Username": "attacker",
            "Resources": [],
        }

        with patch.object(connector, "_lookup_events", return_value=[raw_event]):
            with caplog.at_level(logging.WARNING):
                result = connector.poll(checkpoint=None)

        # Event should still be produced (with empty ct_event fallback)
        assert len(result.events) == 1
        assert result.events[0].actor == "attacker"
        # A warning should have been logged
        assert any("CloudTrailEvent" in msg for msg in caplog.messages)

    def test_poll_no_checkpoint_creates_new_one(self) -> None:
        connector = self._make_authenticated_connector()

        with patch.object(connector, "_lookup_events", return_value=[]):
            result = connector.poll(checkpoint=None)

        assert result.checkpoint.connector == "aws-cloudtrail"
        # Should be approximately now
        assert isinstance(result.checkpoint.updated_at, datetime)


# ─── event_types() ───────────────────────────────────────────────────


class TestAwsCloudTrailEventTypes:
    def test_event_types_matches_manifest(self) -> None:
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        types = connector.event_types()

        expected = [
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
        assert types == expected


# ─── manifest ────────────────────────────────────────────────────────


class TestAwsCloudTrailManifest:
    def test_manifest_loads_and_validates(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest

        plugin_dir = Path(__file__).parent.parent.parent / "src" / "mallcop" / "connectors" / "aws_cloudtrail"
        manifest = load_connector_manifest(plugin_dir)

        assert manifest.name == "aws-cloudtrail"
        assert manifest.version == "0.1.0"
        assert "console_login" in manifest.event_types
        assert "iam_change" in manifest.event_types
        assert "resource_modified" in manifest.event_types
        assert "aws_access_key_id" in manifest.auth["required"]
        assert "aws_secret_access_key" in manifest.auth["required"]

    def test_event_types_match_connector(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        plugin_dir = Path(__file__).parent.parent.parent / "src" / "mallcop" / "connectors" / "aws_cloudtrail"
        manifest = load_connector_manifest(plugin_dir)
        connector = AwsCloudTrailConnector()

        assert set(connector.event_types()) == set(manifest.event_types)


# ─── _lookup_events pagination ───────────────────────────────────────


class TestLookupEventsPagination:
    def _make_authenticated_connector(self):
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        connector._access_key = "AKIATEST"
        connector._secret_key = "secrettest"
        connector._region = "us-east-1"
        connector._account_id = "123456789012"
        return connector

    def test_lookup_events_follows_next_token(self) -> None:
        connector = self._make_authenticated_connector()

        page1_resp = MagicMock()
        page1_resp.status_code = 200
        page1_resp.json.return_value = {
            "Events": [{"EventId": "1", "EventName": "ConsoleLogin", "EventTime": "2026-03-10T10:00:00Z"}],
            "NextToken": "token123",
        }

        page2_resp = MagicMock()
        page2_resp.status_code = 200
        page2_resp.json.return_value = {
            "Events": [{"EventId": "2", "EventName": "CreateUser", "EventTime": "2026-03-10T11:00:00Z"}],
        }

        with patch.object(connector, "_signed_request", side_effect=[page1_resp, page2_resp]):
            start = datetime(2026, 3, 10, 0, 0, 0, tzinfo=timezone.utc)
            end = datetime(2026, 3, 10, 23, 59, 59, tzinfo=timezone.utc)
            events = connector._lookup_events(start, end)

        assert len(events) == 2
        assert events[0]["EventId"] == "1"
        assert events[1]["EventId"] == "2"

    def test_lookup_events_raises_on_error(self) -> None:
        connector = self._make_authenticated_connector()

        error_resp = MagicMock()
        error_resp.status_code = 403
        error_resp.text = "Forbidden"

        with patch.object(connector, "_signed_request", return_value=error_resp):
            start = datetime(2026, 3, 10, 0, 0, 0, tzinfo=timezone.utc)
            end = datetime(2026, 3, 10, 23, 59, 59, tzinfo=timezone.utc)
            with pytest.raises(ConfigError, match="LookupEvents failed"):
                connector._lookup_events(start, end)


# ─── _describe_trails ────────────────────────────────────────────────


class TestDescribeTrails:
    def _make_authenticated_connector(self):
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        connector._access_key = "AKIATEST"
        connector._secret_key = "secrettest"
        connector._region = "us-east-1"
        return connector

    def test_describe_trails_parses_response(self) -> None:
        connector = self._make_authenticated_connector()
        fixture = _load_fixture("describe_trails.json")

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = fixture

        with patch.object(connector, "_signed_request", return_value=resp):
            trails = connector._describe_trails()

        assert len(trails) == 2
        assert trails[0]["Name"] == "main-trail"
        assert trails[1]["Name"] == "secondary-trail"

    def test_describe_trails_raises_on_error(self) -> None:
        connector = self._make_authenticated_connector()

        resp = MagicMock()
        resp.status_code = 403
        resp.text = "Access Denied"

        with patch.object(connector, "_signed_request", return_value=resp):
            with pytest.raises(ConfigError, match="DescribeTrails failed"):
                connector._describe_trails()


# ─── Edge cases: timestamps, empty pages, pagination boundaries ──────


class TestTimestampParsing:
    @pytest.mark.parametrize(
        "ts_str,expected",
        [
            ("2026-03-10T10:00:00Z", datetime(2026, 3, 10, 10, 0, 0, tzinfo=timezone.utc)),
            ("2026-03-10T10:00:00+00:00", datetime(2026, 3, 10, 10, 0, 0, tzinfo=timezone.utc)),
            ("2026-03-10T10:00:00.123456Z", datetime(2026, 3, 10, 10, 0, 0, 123456, tzinfo=timezone.utc)),
            ("2026-03-10T10:00:00.999999Z", datetime(2026, 3, 10, 10, 0, 0, 999999, tzinfo=timezone.utc)),
            ("2026-03-10T10:00:00.000001Z", datetime(2026, 3, 10, 10, 0, 0, 1, tzinfo=timezone.utc)),
        ],
        ids=["z-suffix", "explicit-utc", "microseconds", "max-microseconds", "min-microseconds"],
    )
    def test_parse_timestamp_variants(self, ts_str, expected) -> None:
        from mallcop.connectors._util import parse_iso_timestamp

        result = parse_iso_timestamp(ts_str)
        assert result == expected

    def test_microsecond_timestamps_in_poll(self) -> None:
        """Events with microsecond-precision timestamps should be parsed and normalized."""
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        connector._access_key = "AKIATEST"
        connector._secret_key = "secrettest"
        connector._region = "us-east-1"
        connector._account_id = "123456789012"

        raw_event = {
            "EventId": "evt-micro-ts",
            "EventName": "ConsoleLogin",
            "EventTime": "2026-03-10T10:00:00.123456Z",
            "CloudTrailEvent": "{}",
            "Username": "admin",
            "Resources": [],
        }

        with patch.object(connector, "_lookup_events", return_value=[raw_event]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].timestamp.microsecond == 123456


class TestEmptyEventsPageResponse:
    def _make_authenticated_connector(self):
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        connector._access_key = "AKIATEST"
        connector._secret_key = "secrettest"
        connector._region = "us-east-1"
        connector._account_id = "123456789012"
        return connector

    def test_empty_events_list_in_response(self) -> None:
        """API returns 200 with empty Events array — no crash, no events."""
        connector = self._make_authenticated_connector()

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"Events": []}

        with patch.object(connector, "_signed_request", return_value=resp):
            start = datetime(2026, 3, 10, 0, 0, 0, tzinfo=timezone.utc)
            end = datetime(2026, 3, 10, 23, 59, 59, tzinfo=timezone.utc)
            events = connector._lookup_events(start, end)

        assert events == []

    def test_missing_events_key_in_response(self) -> None:
        """API returns 200 with no Events key — should return empty list."""
        connector = self._make_authenticated_connector()

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {}  # No "Events" key at all

        with patch.object(connector, "_signed_request", return_value=resp):
            start = datetime(2026, 3, 10, 0, 0, 0, tzinfo=timezone.utc)
            end = datetime(2026, 3, 10, 23, 59, 59, tzinfo=timezone.utc)
            events = connector._lookup_events(start, end)

        assert events == []


class TestMaxResultsBoundary:
    def _make_authenticated_connector(self):
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        connector._access_key = "AKIATEST"
        connector._secret_key = "secrettest"
        connector._region = "us-east-1"
        connector._account_id = "123456789012"
        return connector

    def test_exactly_max_results_events_with_no_next_token(self) -> None:
        """Exactly MaxResults (50) events with no NextToken means done."""
        connector = self._make_authenticated_connector()

        events_50 = [
            {"EventId": f"evt-{i}", "EventName": "DescribeInstances", "EventTime": "2026-03-10T10:00:00Z"}
            for i in range(50)
        ]

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"Events": events_50}

        with patch.object(connector, "_signed_request", return_value=resp) as mock_req:
            start = datetime(2026, 3, 10, 0, 0, 0, tzinfo=timezone.utc)
            end = datetime(2026, 3, 10, 23, 59, 59, tzinfo=timezone.utc)
            events = connector._lookup_events(start, end)

        assert len(events) == 50
        # Only one API call (no pagination)
        assert mock_req.call_count == 1

    def test_exactly_max_results_events_with_next_token_paginates(self) -> None:
        """Exactly MaxResults events WITH NextToken means there is a next page."""
        connector = self._make_authenticated_connector()

        events_50 = [
            {"EventId": f"evt-{i}", "EventName": "DescribeInstances", "EventTime": "2026-03-10T10:00:00Z"}
            for i in range(50)
        ]
        events_10 = [
            {"EventId": f"evt-{50 + i}", "EventName": "RunInstances", "EventTime": "2026-03-10T11:00:00Z"}
            for i in range(10)
        ]

        page1_resp = MagicMock()
        page1_resp.status_code = 200
        page1_resp.json.return_value = {"Events": events_50, "NextToken": "page2tok"}

        page2_resp = MagicMock()
        page2_resp.status_code = 200
        page2_resp.json.return_value = {"Events": events_10}

        with patch.object(connector, "_signed_request", side_effect=[page1_resp, page2_resp]):
            start = datetime(2026, 3, 10, 0, 0, 0, tzinfo=timezone.utc)
            end = datetime(2026, 3, 10, 23, 59, 59, tzinfo=timezone.utc)
            events = connector._lookup_events(start, end)

        assert len(events) == 60


class TestNextTokenVariants:
    def _make_authenticated_connector(self):
        from mallcop.connectors.aws_cloudtrail.connector import AwsCloudTrailConnector

        connector = AwsCloudTrailConnector()
        connector._access_key = "AKIATEST"
        connector._secret_key = "secrettest"
        connector._region = "us-east-1"
        connector._account_id = "123456789012"
        return connector

    @pytest.mark.parametrize(
        "next_token_value,should_paginate",
        [
            ("valid-token-123", True),
            (None, False),
            ("", False),
        ],
        ids=["present", "absent-none", "empty-string"],
    )
    def test_next_token_variants(self, next_token_value, should_paginate) -> None:
        """NextToken present triggers pagination; absent/None/empty does not."""
        connector = self._make_authenticated_connector()

        page1_data = {"Events": [{"EventId": "1", "EventName": "X", "EventTime": "2026-03-10T10:00:00Z"}]}
        if next_token_value is not None:
            page1_data["NextToken"] = next_token_value

        page1_resp = MagicMock()
        page1_resp.status_code = 200
        page1_resp.json.return_value = page1_data

        page2_resp = MagicMock()
        page2_resp.status_code = 200
        page2_resp.json.return_value = {"Events": [{"EventId": "2", "EventName": "Y", "EventTime": "2026-03-10T11:00:00Z"}]}

        with patch.object(connector, "_signed_request", side_effect=[page1_resp, page2_resp]) as mock_req:
            start = datetime(2026, 3, 10, 0, 0, 0, tzinfo=timezone.utc)
            end = datetime(2026, 3, 10, 23, 59, 59, tzinfo=timezone.utc)
            events = connector._lookup_events(start, end)

        if should_paginate:
            assert mock_req.call_count == 2
            assert len(events) == 2
        else:
            assert mock_req.call_count == 1
            assert len(events) == 1
