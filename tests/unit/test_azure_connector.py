"""Tests for Azure Activity Log connector."""

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

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "azure"


def _load_fixture(name: str) -> dict[str, Any]:
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


class FakeSecretProvider(SecretProvider):
    """Secret provider backed by a dict for testing."""

    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = secrets

    def resolve(self, name: str) -> str:
        if name not in self._secrets:
            raise ConfigError(f"Secret '{name}' not found")
        return self._secrets[name]


# ─── discover() ─────────────────────────────────────────────────────


class TestAzureConnectorDiscover:
    def test_discover_returns_discovery_result_with_subscriptions(self) -> None:
        from mallcop.connectors.azure.connector import AzureConnector

        fixture = _load_fixture("discovery_subscriptions.json")

        connector = AzureConnector()
        # Mock the Azure subscription client
        with patch.object(connector, "_list_subscriptions", return_value=fixture["value"]):
            result = connector.discover()

        assert isinstance(result, DiscoveryResult)
        assert result.available is True
        assert len(result.resources) == 2
        assert "Acme Production" in result.resources[0]
        assert "Acme Development" in result.resources[1]

    def test_discover_no_subscriptions_returns_unavailable(self) -> None:
        from mallcop.connectors.azure.connector import AzureConnector

        connector = AzureConnector()
        with patch.object(connector, "_list_subscriptions", return_value=[]):
            result = connector.discover()

        assert isinstance(result, DiscoveryResult)
        assert result.available is False
        assert len(result.resources) == 0

    def test_discover_suggests_config(self) -> None:
        from mallcop.connectors.azure.connector import AzureConnector

        fixture = _load_fixture("discovery_subscriptions.json")

        connector = AzureConnector()
        with patch.object(connector, "_list_subscriptions", return_value=fixture["value"]):
            result = connector.discover()

        assert "subscription_ids" in result.suggested_config
        assert len(result.suggested_config["subscription_ids"]) == 2

    def test_discover_reports_missing_credentials(self) -> None:
        from mallcop.connectors.azure.connector import AzureConnector

        connector = AzureConnector()
        with patch.object(
            connector,
            "_list_subscriptions",
            side_effect=Exception("Authentication failed"),
        ):
            result = connector.discover()

        assert result.available is False
        assert len(result.missing_credentials) > 0


# ─── authenticate() ─────────────────────────────────────────────────


class TestAzureConnectorAuthenticate:
    def test_authenticate_succeeds_with_valid_secrets(self) -> None:
        from mallcop.connectors.azure.connector import AzureConnector

        secrets = FakeSecretProvider({
            "AZURE_TENANT_ID": "00000000-0000-0000-0000-000000000099",
            "AZURE_CLIENT_ID": "00000000-0000-0000-0000-000000000088",
            "AZURE_CLIENT_SECRET": "super-secret",
        })

        connector = AzureConnector()
        # Mock _get_token since authenticate now eagerly validates credentials
        with patch.object(connector, "_get_token", return_value="fake-token"):
            connector.authenticate(secrets)

        assert connector._tenant_id == "00000000-0000-0000-0000-000000000099"
        assert connector._client_id == "00000000-0000-0000-0000-000000000088"
        assert connector._client_secret == "super-secret"

    def test_authenticate_raises_on_missing_tenant_id(self) -> None:
        from mallcop.connectors.azure.connector import AzureConnector

        secrets = FakeSecretProvider({
            "AZURE_CLIENT_ID": "id",
            "AZURE_CLIENT_SECRET": "secret",
        })

        connector = AzureConnector()
        with pytest.raises(ConfigError, match="AZURE_TENANT_ID"):
            connector.authenticate(secrets)

    def test_authenticate_raises_on_missing_client_id(self) -> None:
        from mallcop.connectors.azure.connector import AzureConnector

        secrets = FakeSecretProvider({
            "AZURE_TENANT_ID": "tid",
            "AZURE_CLIENT_SECRET": "secret",
        })

        connector = AzureConnector()
        with pytest.raises(ConfigError, match="AZURE_CLIENT_ID"):
            connector.authenticate(secrets)

    def test_authenticate_raises_on_missing_client_secret(self) -> None:
        from mallcop.connectors.azure.connector import AzureConnector

        secrets = FakeSecretProvider({
            "AZURE_TENANT_ID": "tid",
            "AZURE_CLIENT_ID": "cid",
        })

        connector = AzureConnector()
        with pytest.raises(ConfigError, match="AZURE_CLIENT_SECRET"):
            connector.authenticate(secrets)


# ─── _get_paginated() ────────────────────────────────────────────────


class TestAzureConnectorGetPaginated:
    def _make_authenticated_connector(self):
        from mallcop.connectors.azure.connector import AzureConnector

        connector = AzureConnector()
        connector._tenant_id = "00000000-0000-0000-0000-000000000099"
        connector._client_id = "00000000-0000-0000-0000-000000000088"
        connector._client_secret = "super-secret"
        return connector

    def test_get_paginated_parses_json_response(self) -> None:
        connector = self._make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = {
            "value": [{"id": "1"}, {"id": "2"}],
        }

        with patch.object(connector, "_auth_headers", return_value={"Authorization": "Bearer fake"}), \
             patch("requests.get", return_value=fake_resp):
            results = connector._get_paginated("https://example.com/api")

        assert results == [{"id": "1"}, {"id": "2"}]
        fake_resp.raise_for_status.assert_called_once()

    def test_get_paginated_follows_next_link(self) -> None:
        connector = self._make_authenticated_connector()

        page1_resp = MagicMock()
        page1_resp.raise_for_status = MagicMock()
        page1_resp.json.return_value = {
            "value": [{"id": "1"}],
            "nextLink": "https://management.azure.com/subscriptions/sub-001?page=2",
        }

        page2_resp = MagicMock()
        page2_resp.raise_for_status = MagicMock()
        page2_resp.json.return_value = {
            "value": [{"id": "2"}],
        }

        with patch.object(connector, "_auth_headers", return_value={"Authorization": "Bearer fake"}), \
             patch("requests.get", side_effect=[page1_resp, page2_resp]):
            results = connector._get_paginated("https://management.azure.com/subscriptions/sub-001")

        assert results == [{"id": "1"}, {"id": "2"}]

    def test_get_paginated_raises_on_http_error(self) -> None:
        from requests.exceptions import HTTPError

        connector = self._make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status.side_effect = HTTPError("500 Server Error")

        with patch.object(connector, "_auth_headers", return_value={"Authorization": "Bearer fake"}), \
             patch("requests.get", return_value=fake_resp):
            with pytest.raises(HTTPError):
                connector._get_paginated("https://example.com/api")

    def test_get_paginated_raises_on_non_dict_response(self) -> None:
        connector = self._make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = "unexpected string response"

        with patch.object(connector, "_auth_headers", return_value={"Authorization": "Bearer fake"}), \
             patch("requests.get", return_value=fake_resp):
            with pytest.raises(TypeError, match="Expected JSON object"):
                connector._get_paginated("https://example.com/api")

    def test_get_paginated_handles_empty_value_list(self) -> None:
        connector = self._make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = {"value": []}

        with patch.object(connector, "_auth_headers", return_value={"Authorization": "Bearer fake"}), \
             patch("requests.get", return_value=fake_resp):
            results = connector._get_paginated("https://example.com/api")

        assert results == []


# ─── poll() ──────────────────────────────────────────────────────────


class TestAzureConnectorPoll:
    def _make_authenticated_connector(self):
        from mallcop.connectors.azure.connector import AzureConnector

        connector = AzureConnector()
        connector._tenant_id = "00000000-0000-0000-0000-000000000099"
        connector._client_id = "00000000-0000-0000-0000-000000000088"
        connector._client_secret = "super-secret"
        connector._subscription_ids = ["00000000-0000-0000-0000-000000000001"]
        return connector

    def test_poll_normalizes_events_to_event_schema(self) -> None:
        fixture = _load_fixture("activity_log_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(
            connector,
            "_fetch_activity_log",
            return_value=fixture["value"],
        ):
            result = connector.poll(checkpoint=None)

        assert isinstance(result, PollResult)
        assert len(result.events) == 3

        # Check first event (role assignment)
        evt = result.events[0]
        assert isinstance(evt, Event)
        assert evt.source == "azure"
        assert evt.event_type == "role_assignment"
        assert evt.actor == "admin@acme-corp.dev"
        assert evt.action == "Microsoft.Authorization/roleAssignments/write"
        assert evt.target.endswith("ra-001")
        assert evt.severity == Severity.INFO
        assert evt.raw == fixture["value"][0]

    def test_poll_sets_correct_timestamps(self) -> None:
        fixture = _load_fixture("activity_log_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(
            connector,
            "_fetch_activity_log",
            return_value=fixture["value"],
        ):
            result = connector.poll(checkpoint=None)

        evt = result.events[0]
        assert evt.timestamp == datetime(2026, 3, 5, 14, 30, 0, tzinfo=timezone.utc)
        # ingested_at should be approximately now (just check it's a datetime)
        assert isinstance(evt.ingested_at, datetime)
        assert evt.ingested_at.tzinfo is not None

    def test_poll_returns_checkpoint(self) -> None:
        fixture = _load_fixture("activity_log_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(
            connector,
            "_fetch_activity_log",
            return_value=fixture["value"],
        ):
            result = connector.poll(checkpoint=None)

        assert isinstance(result.checkpoint, Checkpoint)
        assert result.checkpoint.connector == "azure"
        # Checkpoint value should be the latest event timestamp
        assert result.checkpoint.value == "2026-03-05T16:00:00+00:00"

    def test_poll_with_checkpoint_filters_events(self) -> None:
        fixture = _load_fixture("activity_log_events.json")
        connector = self._make_authenticated_connector()

        checkpoint = Checkpoint(
            connector="azure",
            value="2026-03-05T14:30:00+00:00",
            updated_at=datetime(2026, 3, 5, 14, 30, 0, tzinfo=timezone.utc),
        )

        with patch.object(
            connector,
            "_fetch_activity_log",
            return_value=fixture["value"],
        ):
            result = connector.poll(checkpoint=checkpoint)

        # Should only return events after the checkpoint
        assert len(result.events) == 2
        assert result.events[0].actor == "deploy-sp@acme-corp.dev"

    def test_poll_empty_response_returns_same_checkpoint(self) -> None:
        connector = self._make_authenticated_connector()

        checkpoint = Checkpoint(
            connector="azure",
            value="2026-03-06T00:00:00+00:00",
            updated_at=datetime(2026, 3, 6, 0, 0, 0, tzinfo=timezone.utc),
        )

        with patch.object(connector, "_fetch_activity_log", return_value=[]):
            result = connector.poll(checkpoint=checkpoint)

        assert len(result.events) == 0
        assert result.checkpoint.value == checkpoint.value

    def test_poll_normalizes_resource_modified_event_type(self) -> None:
        fixture = _load_fixture("activity_log_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(
            connector,
            "_fetch_activity_log",
            return_value=fixture["value"],
        ):
            result = connector.poll(checkpoint=None)

        # Second event is a Compute write -> resource_modified
        assert result.events[1].event_type == "resource_modified"
        # Third event is a ContainerApp write -> container_access
        assert result.events[2].event_type == "container_access"

    def test_poll_preserves_raw_data(self) -> None:
        fixture = _load_fixture("activity_log_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(
            connector,
            "_fetch_activity_log",
            return_value=fixture["value"],
        ):
            result = connector.poll(checkpoint=None)

        for i, evt in enumerate(result.events):
            assert evt.raw == fixture["value"][i]

    def test_poll_assigns_warn_severity_for_warning_level(self) -> None:
        fixture = _load_fixture("activity_log_events.json")
        connector = self._make_authenticated_connector()

        with patch.object(
            connector,
            "_fetch_activity_log",
            return_value=fixture["value"],
        ):
            result = connector.poll(checkpoint=None)

        # Third event has level "Warning"
        assert result.events[2].severity == Severity.WARN


# ─── _fetch_activity_log() filter construction ───────────────────────


class TestAzureConnectorFetchActivityLogFilter:
    def _make_authenticated_connector(self):
        from mallcop.connectors.azure.connector import AzureConnector

        connector = AzureConnector()
        connector._tenant_id = "00000000-0000-0000-0000-000000000099"
        connector._client_id = "00000000-0000-0000-0000-000000000088"
        connector._client_secret = "super-secret"
        connector._subscription_ids = ["sub-001"]
        return connector

    def test_filter_includes_timestamp_range_without_checkpoint(self) -> None:
        from datetime import datetime, timedelta, timezone
        from unittest.mock import patch

        connector = self._make_authenticated_connector()
        captured_params: dict = {}

        def fake_get_paginated(url, params=None):
            captured_params.update(params or {})
            return []

        fake_now = datetime(2026, 3, 7, 12, 0, 0, tzinfo=timezone.utc)

        with patch.object(connector, "_get_paginated", side_effect=fake_get_paginated), \
             patch("mallcop.connectors.azure.connector.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            connector._fetch_activity_log("sub-001", checkpoint=None)

        assert "$filter" in captured_params
        f = captured_params["$filter"]
        # Should have both ge and le with proper timestamps
        assert "eventTimestamp ge '2026-02-28T12:00:00Z'" in f
        assert "eventTimestamp le '2026-03-07T12:00:00Z'" in f

    def test_filter_uses_checkpoint_value_as_start(self) -> None:
        from datetime import datetime, timezone
        from unittest.mock import patch

        connector = self._make_authenticated_connector()
        captured_params: dict = {}

        def fake_get_paginated(url, params=None):
            captured_params.update(params or {})
            return []

        checkpoint = Checkpoint(
            connector="azure",
            value="2026-03-06T10:00:00+00:00",
            updated_at=datetime(2026, 3, 6, 10, 0, 0, tzinfo=timezone.utc),
        )

        fake_now = datetime(2026, 3, 7, 12, 0, 0, tzinfo=timezone.utc)

        with patch.object(connector, "_get_paginated", side_effect=fake_get_paginated), \
             patch("mallcop.connectors.azure.connector.datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            connector._fetch_activity_log("sub-001", checkpoint=checkpoint)

        assert "$filter" in captured_params
        f = captured_params["$filter"]
        assert "eventTimestamp ge '2026-03-06T10:00:00+00:00'" in f
        assert "eventTimestamp le '2026-03-07T12:00:00Z'" in f

    def test_filter_always_present_even_without_checkpoint(self) -> None:
        """The Azure API returns 400 without a $filter — verify it's always set."""
        from unittest.mock import patch

        connector = self._make_authenticated_connector()
        captured_params: dict = {}

        def fake_get_paginated(url, params=None):
            captured_params.update(params or {})
            return []

        with patch.object(connector, "_get_paginated", side_effect=fake_get_paginated):
            connector._fetch_activity_log("sub-001", checkpoint=None)

        assert "$filter" in captured_params
        assert "eventTimestamp ge" in captured_params["$filter"]
        assert "eventTimestamp le" in captured_params["$filter"]


# ─── event_types() ───────────────────────────────────────────────────


class TestAzureConnectorEventTypes:
    def test_event_types_matches_manifest(self) -> None:
        from mallcop.connectors.azure.connector import AzureConnector

        connector = AzureConnector()
        types = connector.event_types()

        expected = [
            "role_assignment",
            "login",
            "resource_modified",
            "defender_alert",
            "container_access",
        ]
        assert types == expected


# ─── manifest ────────────────────────────────────────────────────────


class TestAzureManifest:
    def test_manifest_loads_and_validates(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest

        azure_dir = Path(__file__).parent.parent.parent / "src" / "mallcop" / "connectors" / "azure"
        manifest = load_connector_manifest(azure_dir)

        assert manifest.name == "azure"
        assert manifest.version == "0.1.0"
        assert "role_assignment" in manifest.event_types
        assert "login" in manifest.event_types
        assert "resource_modified" in manifest.event_types
        assert "tenant_id" in manifest.auth["required"]
        assert "client_id" in manifest.auth["required"]
        assert "client_secret" in manifest.auth["required"]

    def test_event_types_match_connector(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest
        from mallcop.connectors.azure.connector import AzureConnector

        azure_dir = Path(__file__).parent.parent.parent / "src" / "mallcop" / "connectors" / "azure"
        manifest = load_connector_manifest(azure_dir)
        connector = AzureConnector()

        assert set(connector.event_types()) == set(manifest.event_types)


# ─── Error path tests ────────────────────────────────────────────────


class TestAzureConnectorErrorPaths:
    def _make_authenticated_connector(self):
        from mallcop.connectors.azure.connector import AzureConnector

        connector = AzureConnector()
        connector._tenant_id = "00000000-0000-0000-0000-000000000099"
        connector._client_id = "00000000-0000-0000-0000-000000000088"
        connector._client_secret = "super-secret"
        return connector

    def test_get_token_401_unauthorized_raises_config_error(self) -> None:
        connector = self._make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 401
        fake_resp.text = "Unauthorized: Invalid client credentials"

        with patch("requests.post", return_value=fake_resp):
            with pytest.raises(ConfigError, match="401"):
                connector._get_token()

    def test_get_token_500_server_error_raises_config_error(self) -> None:
        connector = self._make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 500
        fake_resp.text = "Internal Server Error"

        with patch("requests.post", return_value=fake_resp):
            with pytest.raises(ConfigError, match="500"):
                connector._get_token()

    def test_get_paginated_429_throttled_raises_http_error(self) -> None:
        from requests.exceptions import HTTPError

        connector = self._make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status.side_effect = HTTPError(
            "429 Too Many Requests"
        )

        with patch.object(connector, "_auth_headers", return_value={"Authorization": "Bearer fake"}), \
             patch("requests.get", return_value=fake_resp):
            with pytest.raises(HTTPError, match="429"):
                connector._get_paginated("https://management.azure.com/test")

    def test_get_paginated_network_timeout_raises(self) -> None:
        from requests.exceptions import ConnectionError as ReqConnectionError

        connector = self._make_authenticated_connector()

        with patch.object(connector, "_auth_headers", return_value={"Authorization": "Bearer fake"}), \
             patch("requests.get", side_effect=ReqConnectionError("Connection timed out")):
            with pytest.raises(ReqConnectionError):
                connector._get_paginated("https://management.azure.com/test")

    def test_get_paginated_malformed_json_raises_type_error(self) -> None:
        connector = self._make_authenticated_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = [1, 2, 3]  # list instead of dict

        with patch.object(connector, "_auth_headers", return_value={"Authorization": "Bearer fake"}), \
             patch("requests.get", return_value=fake_resp):
            with pytest.raises(TypeError, match="Expected JSON object"):
                connector._get_paginated("https://management.azure.com/test")

    def test_get_paginated_next_link_page_error_raises(self) -> None:
        """HTTP error on the second page (nextLink) propagates correctly."""
        from requests.exceptions import HTTPError

        connector = self._make_authenticated_connector()

        page1_resp = MagicMock()
        page1_resp.raise_for_status = MagicMock()
        page1_resp.json.return_value = {
            "value": [{"id": "1"}],
            "nextLink": "https://management.azure.com/test?page=2",
        }

        page2_resp = MagicMock()
        page2_resp.raise_for_status.side_effect = HTTPError("500 Server Error")

        with patch.object(connector, "_auth_headers", return_value={"Authorization": "Bearer fake"}), \
             patch("requests.get", side_effect=[page1_resp, page2_resp]):
            with pytest.raises(HTTPError, match="500"):
                connector._get_paginated("https://management.azure.com/test")
