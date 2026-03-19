"""Tests for M365 Management Activity API connector."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest

from mallcop.schemas import (
    Checkpoint,
    DiscoveryResult,
    Event,
    PollResult,
    Severity,
)
from mallcop.secrets import ConfigError, SecretProvider

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "m365"


def _load_fixture(name: str) -> Any:
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


class FakeSecretProvider(SecretProvider):
    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = secrets

    def resolve(self, name: str) -> str:
        if name not in self._secrets:
            raise ConfigError(f"Secret '{name}' not found")
        return self._secrets[name]


_DEFAULT_SECRETS = {
    "ENTRA_TENANT_ID": "00000000-0000-0000-0000-000000000099",
    "ENTRA_CLIENT_ID": "00000000-0000-0000-0000-000000000088",
    "ENTRA_CLIENT_SECRET": "super-secret",
}


def _make_connector():
    from mallcop.connectors.m365.connector import M365Connector
    return M365Connector()


def _make_authenticated_connector():
    from mallcop.connectors.m365.connector import M365Connector
    c = M365Connector()
    c._tenant_id = _DEFAULT_SECRETS["ENTRA_TENANT_ID"]
    c._client_id = _DEFAULT_SECRETS["ENTRA_CLIENT_ID"]
    c._client_secret = _DEFAULT_SECRETS["ENTRA_CLIENT_SECRET"]
    return c


# ─── authenticate() ─────────────────────────────────────────────────


class TestM365ConnectorAuthenticate:
    def test_authenticate_stores_credentials(self) -> None:
        c = _make_connector()
        secrets = FakeSecretProvider(_DEFAULT_SECRETS)
        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch.object(c, "_ensure_subscriptions"):
            c.authenticate(secrets)
        assert c._tenant_id == _DEFAULT_SECRETS["ENTRA_TENANT_ID"]
        assert c._client_id == _DEFAULT_SECRETS["ENTRA_CLIENT_ID"]
        assert c._client_secret == _DEFAULT_SECRETS["ENTRA_CLIENT_SECRET"]

    def test_authenticate_calls_get_token(self) -> None:
        c = _make_connector()
        secrets = FakeSecretProvider(_DEFAULT_SECRETS)
        with patch.object(c, "_get_token", return_value="fake-token") as mock_token, \
             patch.object(c, "_ensure_subscriptions"):
            c.authenticate(secrets)
        mock_token.assert_called_once()

    def test_authenticate_ensures_subscriptions(self) -> None:
        c = _make_connector()
        secrets = FakeSecretProvider(_DEFAULT_SECRETS)
        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch.object(c, "_ensure_subscriptions") as mock_subs:
            c.authenticate(secrets)
        mock_subs.assert_called_once()

    def test_authenticate_raises_on_missing_tenant(self) -> None:
        c = _make_connector()
        secrets = FakeSecretProvider({
            "ENTRA_CLIENT_ID": "id",
            "ENTRA_CLIENT_SECRET": "secret",
        })
        with pytest.raises(ConfigError, match="ENTRA_TENANT_ID"):
            c.authenticate(secrets)

    def test_authenticate_raises_on_missing_client_id(self) -> None:
        c = _make_connector()
        secrets = FakeSecretProvider({
            "ENTRA_TENANT_ID": "tid",
            "ENTRA_CLIENT_SECRET": "secret",
        })
        with pytest.raises(ConfigError, match="ENTRA_CLIENT_ID"):
            c.authenticate(secrets)

    def test_authenticate_raises_on_missing_client_secret(self) -> None:
        c = _make_connector()
        secrets = FakeSecretProvider({
            "ENTRA_TENANT_ID": "tid",
            "ENTRA_CLIENT_ID": "cid",
        })
        with pytest.raises(ConfigError, match="ENTRA_CLIENT_SECRET"):
            c.authenticate(secrets)


# ─── _get_token() ───────────────────────────────────────────────────


class TestM365ConnectorGetToken:
    def test_get_token_posts_to_oauth_endpoint(self) -> None:
        c = _make_authenticated_connector()
        fixture = _load_fixture("oauth_token.json")

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = fixture

        with patch("mallcop.connectors.m365.connector.requests.post", return_value=fake_resp) as mock_post:
            token = c._get_token()

        assert token == fixture["access_token"]
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert "login.microsoftonline.com" in args[0]
        assert c._tenant_id in args[0]
        assert kwargs["data"]["scope"] == "https://manage.office.com/.default"
        assert kwargs["data"]["grant_type"] == "client_credentials"

    def test_get_token_caches_result(self) -> None:
        c = _make_authenticated_connector()
        fixture = _load_fixture("oauth_token.json")

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = fixture

        with patch("mallcop.connectors.m365.connector.requests.post", return_value=fake_resp) as mock_post:
            token1 = c._get_token()
            token2 = c._get_token()

        assert token1 == token2
        assert mock_post.call_count == 1

    def test_get_token_raises_on_failure(self) -> None:
        c = _make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 401
        fake_resp.text = "Unauthorized"

        with patch("mallcop.connectors.m365.connector.requests.post", return_value=fake_resp):
            with pytest.raises(ConfigError, match="401"):
                c._get_token()


# ─── _ensure_subscriptions() ────────────────────────────────────────


class TestM365ConnectorSubscriptions:
    def test_ensure_subscriptions_starts_all_content_types(self) -> None:
        c = _make_authenticated_connector()
        fixture = _load_fixture("subscription_start.json")

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = fixture

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.post", return_value=fake_resp) as mock_post:
            c._ensure_subscriptions()

        assert mock_post.call_count == 4  # One per content type

    def test_ensure_subscriptions_tolerates_already_started(self) -> None:
        c = _make_authenticated_connector()

        # First two succeed, third returns AF20024 (already enabled)
        success_resp = MagicMock()
        success_resp.status_code = 200
        success_resp.json.return_value = _load_fixture("subscription_start.json")

        already_resp = MagicMock()
        already_resp.status_code = 400
        already_resp.json.return_value = _load_fixture("subscription_already_started.json")
        already_resp.text = json.dumps(_load_fixture("subscription_already_started.json"))

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.post",
                   side_effect=[success_resp, already_resp, success_resp, already_resp]):
            # Should not raise
            c._ensure_subscriptions()


# ─── discover() ─────────────────────────────────────────────────────


class TestM365ConnectorDiscover:
    def test_discover_returns_available_with_subscriptions(self) -> None:
        c = _make_connector()
        fixture = _load_fixture("subscriptions_list.json")

        with patch.object(c, "_list_subscriptions", return_value=fixture):
            result = c.discover()

        assert isinstance(result, DiscoveryResult)
        assert result.available is True
        assert len(result.resources) == 4
        assert "Audit.AzureActiveDirectory" in result.resources[0]

    def test_discover_returns_unavailable_on_error(self) -> None:
        c = _make_connector()

        with patch.object(c, "_list_subscriptions", side_effect=Exception("Auth failed")):
            result = c.discover()

        assert result.available is False
        assert len(result.missing_credentials) > 0

    def test_discover_returns_unavailable_when_no_subscriptions(self) -> None:
        c = _make_connector()

        with patch.object(c, "_list_subscriptions", return_value=[]):
            result = c.discover()

        assert result.available is False


# ─── content blob listing ───────────────────────────────────────────


class TestM365ConnectorContentBlobs:
    def test_list_content_blobs_calls_correct_url(self) -> None:
        c = _make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = _load_fixture("content_blobs_aad.json")
        fake_resp.headers = {}

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.get", return_value=fake_resp) as mock_get:
            blobs = c._list_content_blobs(
                "Audit.AzureActiveDirectory",
                "2026-03-05T14:00:00Z",
                "2026-03-05T16:00:00Z",
            )

        assert len(blobs) == 2
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        assert "Audit.AzureActiveDirectory" in kwargs.get("params", {}).get("contentType", "")

    def test_list_content_blobs_paginates_via_next_page_uri(self) -> None:
        c = _make_authenticated_connector()

        page1_resp = MagicMock()
        page1_resp.status_code = 200
        page1_resp.raise_for_status = MagicMock()
        page1_resp.json.return_value = _load_fixture("content_blobs_aad.json")[:1]
        page1_resp.headers = {
            "NextPageUri": "https://manage.office.com/api/v1.0/tenant/activity/feed/subscriptions/content?nextpage=2"
        }

        page2_resp = MagicMock()
        page2_resp.status_code = 200
        page2_resp.raise_for_status = MagicMock()
        page2_resp.json.return_value = _load_fixture("content_blobs_aad.json")[1:]
        page2_resp.headers = {}

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.get",
                   side_effect=[page1_resp, page2_resp]):
            blobs = c._list_content_blobs(
                "Audit.AzureActiveDirectory",
                "2026-03-05T14:00:00Z",
                "2026-03-05T16:00:00Z",
            )

        assert len(blobs) == 2


# ─── audit record fetching ──────────────────────────────────────────


class TestM365ConnectorFetchAuditRecords:
    def test_fetch_audit_records_from_content_uri(self) -> None:
        c = _make_authenticated_connector()
        fixture = _load_fixture("audit_records_aad.json")

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = fixture

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.get", return_value=fake_resp):
            records = c._fetch_audit_records("https://manage.office.com/fake-content-uri")

        assert len(records) == 5
        assert records[0]["Id"] == "aad-rec-001"


# ─── event type mapping ────────────────────────────────────────────


class TestM365EventTypeMapping:
    def test_sign_in_success(self) -> None:
        from mallcop.connectors.m365.connector import _classify_event
        record = {"Operation": "UserLoggedIn", "Workload": "AzureActiveDirectory", "ResultStatus": "Success"}
        assert _classify_event(record) == ("sign_in_success", Severity.INFO)

    def test_sign_in_failure(self) -> None:
        from mallcop.connectors.m365.connector import _classify_event
        record = {"Operation": "UserLoginFailed", "Workload": "AzureActiveDirectory", "ResultStatus": "Failed"}
        assert _classify_event(record) == ("sign_in_failure", Severity.INFO)

    def test_admin_action(self) -> None:
        from mallcop.connectors.m365.connector import _classify_event
        record = {"Operation": "Add member to role.", "Workload": "AzureActiveDirectory", "ResultStatus": "Success"}
        assert _classify_event(record) == ("admin_action", Severity.WARN)

    def test_oauth_consent(self) -> None:
        from mallcop.connectors.m365.connector import _classify_event
        record = {"Operation": "Consent to application.", "Workload": "AzureActiveDirectory", "ResultStatus": "Success"}
        assert _classify_event(record) == ("oauth_consent", Severity.WARN)

    def test_guest_invited(self) -> None:
        from mallcop.connectors.m365.connector import _classify_event
        record = {
            "Operation": "Add user.",
            "Workload": "AzureActiveDirectory",
            "ResultStatus": "Success",
            "Target": [{"ID": "guest@external.com", "Type": 5}],
            "ExtendedProperties": [{"Name": "additionalDetails", "Value": '{"UserType":"Guest"}'}],
        }
        assert _classify_event(record) == ("guest_invited", Severity.WARN)

    def test_mailbox_access(self) -> None:
        from mallcop.connectors.m365.connector import _classify_event
        record = {"Operation": "MailboxLogin", "Workload": "Exchange", "ResultStatus": "Succeeded"}
        assert _classify_event(record) == ("mailbox_access", Severity.INFO)

    def test_mail_forwarding_rule(self) -> None:
        from mallcop.connectors.m365.connector import _classify_event
        record = {"Operation": "New-InboxRule", "Workload": "Exchange", "ResultStatus": "True"}
        assert _classify_event(record) == ("mail_forwarding_rule", Severity.WARN)

    def test_sharepoint_sharing(self) -> None:
        from mallcop.connectors.m365.connector import _classify_event
        record = {"Operation": "SharingSet", "Workload": "SharePoint", "ResultStatus": "Success"}
        assert _classify_event(record) == ("sharepoint_sharing", Severity.WARN)


    def test_sharepoint_non_sharing_op(self) -> None:
        from mallcop.connectors.m365.connector import _classify_event
        record = {"Operation": "FileAccessed", "Workload": "SharePoint", "ResultStatus": "Success"}
        assert _classify_event(record) == ("sharepoint_activity", Severity.INFO)
    def test_dlp_alert(self) -> None:
        from mallcop.connectors.m365.connector import _classify_event
        record = {"Operation": "DlpRuleMatch", "Workload": "Exchange", "RecordType": 11, "ResultStatus": ""}
        assert _classify_event(record) == ("dlp_alert", Severity.WARN)


# ─── poll() ──────────────────────────────────────────────────────────


class TestM365ConnectorPoll:
    @staticmethod
    def _blob_for(target_type: str):
        """Return a side_effect for _list_content_blobs that only returns blobs for target_type."""
        def _side_effect(content_type, start_time, end_time):
            if content_type == target_type:
                return [{"contentUri": "https://manage.office.com/fake", "contentType": content_type}]
            return []
        return _side_effect

    def test_poll_normalizes_aad_events(self) -> None:
        c = _make_authenticated_connector()
        aad_records = _load_fixture("audit_records_aad.json")

        with patch.object(c, "_list_content_blobs", side_effect=self._blob_for("Audit.AzureActiveDirectory")), \
             patch.object(c, "_fetch_audit_records", return_value=aad_records):
            result = c.poll(checkpoint=None)

        assert isinstance(result, PollResult)
        assert len(result.events) == 5

        # First: sign_in_success
        evt = result.events[0]
        assert isinstance(evt, Event)
        assert evt.source == "m365"
        assert evt.event_type == "sign_in_success"
        assert evt.actor == "admin@acme-corp.dev"
        assert evt.severity == Severity.INFO

        # Second: sign_in_failure
        assert result.events[1].event_type == "sign_in_failure"
        assert result.events[1].actor == "attacker@evil.com"

        # Third: admin_action
        assert result.events[2].event_type == "admin_action"

        # Fourth: oauth_consent
        assert result.events[3].event_type == "oauth_consent"

        # Fifth: guest_invited
        assert result.events[4].event_type == "guest_invited"

    def test_poll_normalizes_exchange_events(self) -> None:
        c = _make_authenticated_connector()
        exch_records = _load_fixture("audit_records_exchange.json")

        with patch.object(c, "_list_content_blobs", side_effect=self._blob_for("Audit.Exchange")), \
             patch.object(c, "_fetch_audit_records", return_value=exch_records):
            result = c.poll(checkpoint=None)

        assert len(result.events) == 2
        assert result.events[0].event_type == "mailbox_access"
        assert result.events[0].severity == Severity.INFO
        assert result.events[1].event_type == "mail_forwarding_rule"
        assert result.events[1].severity == Severity.WARN

    def test_poll_normalizes_sharepoint_events(self) -> None:
        c = _make_authenticated_connector()
        sp_records = _load_fixture("audit_records_sharepoint.json")

        with patch.object(c, "_list_content_blobs", side_effect=self._blob_for("Audit.SharePoint")), \
             patch.object(c, "_fetch_audit_records", return_value=sp_records):
            result = c.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].event_type == "sharepoint_sharing"
        assert result.events[0].severity == Severity.WARN
        assert result.events[0].actor == "admin@acme-corp.dev"

    def test_poll_normalizes_dlp_events(self) -> None:
        c = _make_authenticated_connector()
        dlp_records = _load_fixture("audit_records_general.json")

        with patch.object(c, "_list_content_blobs", side_effect=self._blob_for("Audit.General")), \
             patch.object(c, "_fetch_audit_records", return_value=dlp_records):
            result = c.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].event_type == "dlp_alert"
        assert result.events[0].severity == Severity.WARN

    def test_poll_returns_checkpoint_with_latest_timestamp(self) -> None:
        c = _make_authenticated_connector()
        aad_records = _load_fixture("audit_records_aad.json")

        with patch.object(c, "_list_content_blobs", side_effect=self._blob_for("Audit.AzureActiveDirectory")), \
             patch.object(c, "_fetch_audit_records", return_value=aad_records):
            result = c.poll(checkpoint=None)

        assert isinstance(result.checkpoint, Checkpoint)
        assert result.checkpoint.connector == "m365"
        # Latest record is aad-rec-005 at 2026-03-05T16:00:00
        assert "2026-03-05T16:00:00" in result.checkpoint.value

    def test_poll_with_checkpoint_filters_old_events(self) -> None:
        c = _make_authenticated_connector()
        aad_records = _load_fixture("audit_records_aad.json")

        checkpoint = Checkpoint(
            connector="m365",
            value="2026-03-05T15:00:00+00:00",
            updated_at=datetime(2026, 3, 5, 15, 0, 0, tzinfo=timezone.utc),
        )

        with patch.object(c, "_list_content_blobs", side_effect=self._blob_for("Audit.AzureActiveDirectory")), \
             patch.object(c, "_fetch_audit_records", return_value=aad_records):
            result = c.poll(checkpoint=checkpoint)

        # Records at or before 15:00:00 should be filtered out (3 records: 14:30, 14:35, 15:00)
        # Remaining: 15:30 and 16:00
        assert len(result.events) == 2
        assert result.events[0].event_type == "oauth_consent"
        assert result.events[1].event_type == "guest_invited"

    def test_poll_empty_returns_same_checkpoint(self) -> None:
        c = _make_authenticated_connector()

        checkpoint = Checkpoint(
            connector="m365",
            value="2026-03-06T00:00:00+00:00",
            updated_at=datetime(2026, 3, 6, 0, 0, 0, tzinfo=timezone.utc),
        )

        with patch.object(c, "_list_content_blobs", return_value=[]):
            result = c.poll(checkpoint=checkpoint)

        assert len(result.events) == 0
        assert result.checkpoint.value == checkpoint.value

    def test_poll_preserves_raw_data(self) -> None:
        c = _make_authenticated_connector()
        aad_records = _load_fixture("audit_records_aad.json")

        with patch.object(c, "_list_content_blobs", side_effect=self._blob_for("Audit.AzureActiveDirectory")), \
             patch.object(c, "_fetch_audit_records", return_value=aad_records):
            result = c.poll(checkpoint=None)

        for i, evt in enumerate(result.events):
            assert evt.raw == aad_records[i]

    def test_poll_queries_all_content_types(self) -> None:
        c = _make_authenticated_connector()

        with patch.object(c, "_list_content_blobs", return_value=[]) as mock_list:
            c.poll(checkpoint=None)

        # Should query all 4 content types
        assert mock_list.call_count == 4
        content_types_queried = [call_args[0][0] for call_args in mock_list.call_args_list]
        assert "Audit.AzureActiveDirectory" in content_types_queried
        assert "Audit.Exchange" in content_types_queried
        assert "Audit.SharePoint" in content_types_queried
        assert "Audit.General" in content_types_queried


# ─── event_types() ───────────────────────────────────────────────────


class TestM365ConnectorEventTypes:
    def test_event_types_returns_all_ten(self) -> None:
        c = _make_connector()
        types = c.event_types()
        expected = [
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
        assert types == expected


# ─── manifest ────────────────────────────────────────────────────────


class TestM365Manifest:
    def test_manifest_loads_and_validates(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest

        m365_dir = Path(__file__).parent.parent.parent / "src" / "mallcop" / "connectors" / "m365"
        manifest = load_connector_manifest(m365_dir)

        assert manifest.name == "m365"
        assert manifest.version == "0.1.0"
        assert "sign_in_success" in manifest.event_types
        assert "dlp_alert" in manifest.event_types
        assert "tenant_id" in manifest.auth["required"]
        assert "client_id" in manifest.auth["required"]
        assert "client_secret" in manifest.auth["required"]

    def test_event_types_match_connector(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest
        from mallcop.connectors.m365.connector import M365Connector

        m365_dir = Path(__file__).parent.parent.parent / "src" / "mallcop" / "connectors" / "m365"
        manifest = load_connector_manifest(m365_dir)
        connector = M365Connector()

        assert set(connector.event_types()) == set(manifest.event_types)


# ─── Error path tests ────────────────────────────────────────────────


class TestM365ConnectorErrorPaths:
    def test_get_token_401_unauthorized_raises_config_error(self) -> None:
        c = _make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 401
        fake_resp.text = "Unauthorized: Invalid client credentials"

        with patch("mallcop.connectors.m365.connector.requests.post", return_value=fake_resp):
            with pytest.raises(ConfigError, match="401"):
                c._get_token()

    def test_get_token_500_server_error_raises_config_error(self) -> None:
        c = _make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 500
        fake_resp.text = "Internal Server Error"

        with patch("mallcop.connectors.m365.connector.requests.post", return_value=fake_resp):
            with pytest.raises(ConfigError, match="500"):
                c._get_token()

    def test_list_subscriptions_429_throttled_raises_http_error(self) -> None:
        from requests.exceptions import HTTPError

        c = _make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status.side_effect = HTTPError("429 Too Many Requests")

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.get", return_value=fake_resp):
            with pytest.raises(HTTPError, match="429"):
                c._list_subscriptions()

    def test_list_content_blobs_network_timeout_raises(self) -> None:
        from requests.exceptions import ConnectionError as ReqConnectionError

        c = _make_authenticated_connector()

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.get",
                   side_effect=ReqConnectionError("Connection timed out")):
            with pytest.raises(ReqConnectionError):
                c._list_content_blobs("Audit.AzureActiveDirectory", "2026-03-05T00:00:00Z", "2026-03-05T23:59:59Z")

    def test_fetch_audit_records_500_raises_http_error(self) -> None:
        from requests.exceptions import HTTPError

        c = _make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status.side_effect = HTTPError("500 Internal Server Error")

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.get", return_value=fake_resp):
            with pytest.raises(HTTPError, match="500"):
                c._fetch_audit_records("https://manage.office.com/fake-content-uri")

    def test_ensure_subscriptions_non_af20024_400_raises(self) -> None:
        from requests.exceptions import HTTPError

        c = _make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 400
        fake_resp.json.return_value = {"error": {"code": "AF99999", "message": "Unknown error"}}
        fake_resp.raise_for_status.side_effect = HTTPError("400 Bad Request")

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.post", return_value=fake_resp):
            with pytest.raises(HTTPError, match="400"):
                c._ensure_subscriptions()

    def test_list_subscriptions_error_object_raises_config_error(self) -> None:
        """_list_subscriptions raises ConfigError when API returns an error dict instead of list."""
        from mallcop.secrets import ConfigError

        c = _make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status.return_value = None
        fake_resp.json.return_value = {"error": {"code": "AF20023", "message": "No subscription found"}}

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.get", return_value=fake_resp):
            with pytest.raises(ConfigError, match="unexpected shape"):
                c._list_subscriptions()

    def test_list_subscriptions_returns_list_unchanged(self) -> None:
        """_list_subscriptions returns a valid list without modification."""
        c = _make_authenticated_connector()

        sub = {"contentType": "Audit.SharePoint", "status": "enabled", "webhook": {}}
        fake_resp = MagicMock()
        fake_resp.raise_for_status.return_value = None
        fake_resp.json.return_value = [sub]

        with patch.object(c, "_get_token", return_value="fake-token"), \
             patch("mallcop.connectors.m365.connector.requests.get", return_value=fake_resp):
            result = c._list_subscriptions()
        assert result == [sub]


# ─── configure() / content_types filtering (bead 2.15) ──────────────


class TestM365ConnectorConfigureContentTypes:
    """poll() must use only configured content_types, not the full _CONTENT_TYPES list."""

    def test_default_uses_all_content_types(self) -> None:
        """Without configure(), poll iterates all 4 content types."""
        from mallcop.connectors.m365.connector import M365Connector, _CONTENT_TYPES
        c = _make_authenticated_connector()
        assert c._content_types == list(_CONTENT_TYPES)

    def test_configure_restricts_content_types(self) -> None:
        """configure() with content_types stores them so poll() uses only those."""
        c = _make_authenticated_connector()
        c.configure({"content_types": ["Audit.AzureActiveDirectory", "Audit.Exchange"]})
        assert c._content_types == ["Audit.AzureActiveDirectory", "Audit.Exchange"]

    def test_configure_empty_dict_preserves_defaults(self) -> None:
        """configure() with no content_types key leaves defaults intact."""
        from mallcop.connectors.m365.connector import _CONTENT_TYPES
        c = _make_authenticated_connector()
        c.configure({})
        assert c._content_types == list(_CONTENT_TYPES)

    def test_poll_only_fetches_configured_content_types(self) -> None:
        """poll() calls _list_content_blobs only for configured content_types."""
        c = _make_authenticated_connector()
        c.configure({"content_types": ["Audit.AzureActiveDirectory"]})

        fetched_types: list[str] = []

        def fake_list_blobs(content_type, start, end):
            fetched_types.append(content_type)
            return []

        with patch.object(c, "_list_content_blobs", side_effect=fake_list_blobs):
            c.poll(checkpoint=None)

        assert fetched_types == ["Audit.AzureActiveDirectory"]

    def test_poll_without_configure_fetches_all_four_types(self) -> None:
        """poll() without configure() iterates all 4 content types."""
        from mallcop.connectors.m365.connector import _CONTENT_TYPES
        c = _make_authenticated_connector()

        fetched_types: list[str] = []

        def fake_list_blobs(content_type, start, end):
            fetched_types.append(content_type)
            return []

        with patch.object(c, "_list_content_blobs", side_effect=fake_list_blobs):
            c.poll(checkpoint=None)

        assert set(fetched_types) == set(_CONTENT_TYPES)


# ---------------------------------------------------------------------------
# M365 content blob URI domain validation (ak1n.1.20)
# ---------------------------------------------------------------------------


class TestM365ContentUriDomainValidation:
    """Content blob URIs must be validated against allowed M365 domains.

    If an attacker can influence M365 API responses (MITM, DNS rebinding),
    they could inject a contentUri pointing to an internal service.
    The Bearer token is forwarded with the request, enabling token theft and SSRF.
    """

    def _make_patched_connector(self):
        """Return an authenticated M365 connector with _get_token mocked."""
        from unittest.mock import patch
        c = _make_authenticated_connector()
        c._cached_token = "fake-bearer-token"
        c._token_expires_at = float("inf")  # never expires
        return c

    def test_manage_office_com_uri_accepted(self) -> None:
        """URIs from manage.office.com are accepted (primary M365 API domain)."""
        from unittest.mock import MagicMock, patch

        c = self._make_patched_connector()
        mock_resp = MagicMock()
        mock_resp.json.return_value = []

        with patch("mallcop.connectors.m365.connector.requests.get", return_value=mock_resp):
            result = c._fetch_audit_records("https://manage.office.com/api/v1.0/tenant/blobs/xyz")
        assert result == []

    def test_protection_office_com_uri_accepted(self) -> None:
        """URIs from protection.office.com are accepted (M365 compliance domain)."""
        from unittest.mock import MagicMock, patch

        c = self._make_patched_connector()
        mock_resp = MagicMock()
        mock_resp.json.return_value = []

        with patch("mallcop.connectors.m365.connector.requests.get", return_value=mock_resp):
            result = c._fetch_audit_records("https://protection.office.com/api/v1.0/blobs/xyz")
        assert result == []

    def test_ssrf_internal_ip_rejected(self) -> None:
        """contentUri pointing to an internal IP is rejected."""
        import pytest

        c = self._make_patched_connector()

        with pytest.raises(ValueError):
            c._fetch_audit_records("https://192.168.1.100/steal-token")

    def test_ssrf_arbitrary_domain_rejected(self) -> None:
        """contentUri pointing to an attacker-controlled domain is rejected."""
        import pytest

        c = self._make_patched_connector()

        with pytest.raises(ValueError):
            c._fetch_audit_records("https://evil.com/steal-token")

    def test_http_uri_rejected(self) -> None:
        """Non-HTTPS URIs are rejected."""
        import pytest

        c = self._make_patched_connector()

        with pytest.raises(ValueError):
            c._fetch_audit_records("http://manage.office.com/api/blobs/xyz")
