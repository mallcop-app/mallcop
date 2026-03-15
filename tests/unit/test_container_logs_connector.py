"""Tests for Container Apps Log connector (Log Analytics backend)."""

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

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "container_logs"


def _load_fixture(name: str) -> dict[str, Any]:
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


class FakeSecretProvider(SecretProvider):
    def __init__(self, secrets: dict[str, str]) -> None:
        self._secrets = secrets

    def resolve(self, name: str) -> str:
        if name not in self._secrets:
            raise ConfigError(f"Secret '{name}' not found")
        return self._secrets[name]


# ─── discover() ─────────────────────────────────────────────────────


class TestContainerLogsDiscover:
    def test_discover_lists_container_apps(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        fixture = _load_fixture("list_apps.json")
        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[{"name": "opensign", "container": "opensign"}],
        )

        with patch.object(connector, "_get_paginated", return_value=fixture["value"]):
            result = connector.discover()

        assert isinstance(result, DiscoveryResult)
        assert result.available is True
        assert len(result.resources) == 2
        assert "opensign" in result.resources[0]
        assert "rudi" in result.resources[1]

    def test_discover_no_apps_returns_unavailable(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[],
        )

        with patch.object(connector, "_get_paginated", return_value=[]):
            result = connector.discover()

        assert isinstance(result, DiscoveryResult)
        assert result.available is False

    def test_discover_reports_missing_credentials_on_error(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[],
        )

        with patch.object(
            connector, "_get_paginated", side_effect=Exception("Auth failed")
        ):
            result = connector.discover()

        assert result.available is False
        assert len(result.missing_credentials) > 0


# ─── authenticate() ─────────────────────────────────────────────────


class TestContainerLogsAuthenticate:
    def test_authenticate_stores_credentials(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        secrets = FakeSecretProvider({
            "AZURE_TENANT_ID": "tenant-001",
            "AZURE_CLIENT_ID": "client-001",
            "AZURE_CLIENT_SECRET": "secret-001",
        })
        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[{"name": "opensign", "container": "opensign"}],
        )

        with patch.object(connector, "_get_token", return_value="fake-token"):
            connector.authenticate(secrets)

        assert connector._tenant_id == "tenant-001"
        assert connector._client_id == "client-001"
        assert connector._client_secret == "secret-001"

    def test_authenticate_raises_on_missing_tenant(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        secrets = FakeSecretProvider({
            "AZURE_CLIENT_ID": "cid",
            "AZURE_CLIENT_SECRET": "secret",
        })
        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[],
        )

        with pytest.raises(ConfigError, match="AZURE_TENANT_ID"):
            connector.authenticate(secrets)

    def test_authenticate_raises_on_missing_client_id(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        secrets = FakeSecretProvider({
            "AZURE_TENANT_ID": "tid",
            "AZURE_CLIENT_SECRET": "secret",
        })
        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[],
        )

        with pytest.raises(ConfigError, match="AZURE_CLIENT_ID"):
            connector.authenticate(secrets)

    def test_authenticate_raises_on_missing_client_secret(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        secrets = FakeSecretProvider({
            "AZURE_TENANT_ID": "tid",
            "AZURE_CLIENT_ID": "cid",
        })
        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[],
        )

        with pytest.raises(ConfigError, match="AZURE_CLIENT_SECRET"):
            connector.authenticate(secrets)


# ─── poll() ──────────────────────────────────────────────────────────


class TestContainerLogsPoll:
    def _make_connector(self):
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[
                {"name": "opensign", "container": "opensign"},
            ],
        )
        connector._tenant_id = "tenant-001"
        connector._client_id = "client-001"
        connector._client_secret = "secret-001"
        return connector

    def test_poll_returns_events_from_log_rows(self) -> None:
        connector = self._make_connector()
        logs_fixture = _load_fixture("container_logs.json")

        with patch.object(connector, "_fetch_logs_for_app", return_value=logs_fixture["logs"]):
            result = connector.poll(checkpoint=None)

        assert isinstance(result, PollResult)
        assert len(result.events) == 3

    def test_poll_normalizes_events_to_schema(self) -> None:
        connector = self._make_connector()
        logs_fixture = _load_fixture("container_logs.json")

        with patch.object(connector, "_fetch_logs_for_app", return_value=logs_fixture["logs"]):
            result = connector.poll(checkpoint=None)

        evt = result.events[0]
        assert isinstance(evt, Event)
        assert evt.source == "container-logs"
        assert evt.event_type == "log_line"
        assert evt.actor == "opensign"
        assert evt.action == "log"
        assert evt.target == "opensign"  # ContainerName_s
        assert evt.severity == Severity.INFO
        assert "line" in evt.raw
        assert evt.raw["line"] == "opensign started on port 3000"
        assert evt.metadata["app"] == "opensign"
        assert evt.metadata["container"] == "opensign"

    def test_poll_sets_timestamps_from_log_rows(self) -> None:
        connector = self._make_connector()
        logs_fixture = _load_fixture("container_logs.json")

        with patch.object(connector, "_fetch_logs_for_app", return_value=logs_fixture["logs"]):
            result = connector.poll(checkpoint=None)

        assert result.events[0].timestamp == datetime(2026, 3, 5, 14, 30, 0, tzinfo=timezone.utc)
        assert result.events[2].timestamp == datetime(2026, 3, 5, 16, 0, 0, tzinfo=timezone.utc)

    def test_poll_returns_checkpoint_with_latest_timestamp(self) -> None:
        connector = self._make_connector()
        logs_fixture = _load_fixture("container_logs.json")

        with patch.object(connector, "_fetch_logs_for_app", return_value=logs_fixture["logs"]):
            result = connector.poll(checkpoint=None)

        assert isinstance(result.checkpoint, Checkpoint)
        assert result.checkpoint.connector == "container-logs"
        assert result.checkpoint.value == "2026-03-05T16:00:00+00:00"

    def test_poll_empty_logs_preserves_checkpoint(self) -> None:
        connector = self._make_connector()

        checkpoint = Checkpoint(
            connector="container-logs",
            value="2026-03-06T00:00:00+00:00",
            updated_at=datetime(2026, 3, 6, 0, 0, 0, tzinfo=timezone.utc),
        )

        with patch.object(connector, "_fetch_logs_for_app", return_value=[]):
            result = connector.poll(checkpoint=checkpoint)

        assert len(result.events) == 0
        assert result.checkpoint.value == checkpoint.value

    def test_poll_no_checkpoint_empty_logs_sets_now(self) -> None:
        connector = self._make_connector()

        with patch.object(connector, "_fetch_logs_for_app", return_value=[]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 0
        assert isinstance(result.checkpoint, Checkpoint)
        assert result.checkpoint.connector == "container-logs"

    def test_poll_multiple_apps(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[
                {"name": "opensign", "container": "opensign"},
                {"name": "rudi", "container": "rudi"},
            ],
        )
        connector._tenant_id = "tenant-001"
        connector._client_id = "client-001"
        connector._client_secret = "secret-001"

        opensign_rows = [
            {"TimeGenerated": "2026-03-05T14:30:00Z", "Log_s": "opensign started",
             "ContainerName_s": "opensign", "Stream_s": "stdout", "RevisionName_s": "rev1"},
        ]
        rudi_rows = [
            {"TimeGenerated": "2026-03-05T15:00:00Z", "Log_s": "rudi started",
             "ContainerName_s": "rudi", "Stream_s": "stdout", "RevisionName_s": "rev1"},
        ]

        def fake_fetch(app_name, resource_group, since):
            if app_name == "opensign":
                return opensign_rows
            return rudi_rows

        with patch.object(connector, "_fetch_logs_for_app", side_effect=fake_fetch):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 2
        assert result.events[0].actor == "opensign"
        assert result.events[1].actor == "rudi"

    def test_poll_skips_failed_apps(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[
                {"name": "broken-app", "container": "broken"},
                {"name": "working-app", "container": "working"},
            ],
        )
        connector._tenant_id = "tenant-001"
        connector._client_id = "client-001"
        connector._client_secret = "secret-001"

        def fake_fetch(app_name, resource_group, since):
            if app_name == "broken-app":
                raise Exception("Scaled to zero")
            return [
                {"TimeGenerated": "2026-03-05T14:30:00Z", "Log_s": "working",
                 "ContainerName_s": "working", "Stream_s": "stdout", "RevisionName_s": "rev1"},
            ]

        with patch.object(connector, "_fetch_logs_for_app", side_effect=fake_fetch):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].actor == "working-app"

    def test_poll_per_app_resource_group(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="default-rg",
            apps=[
                {"name": "app1", "container": "app1", "resource_group": "custom-rg"},
                {"name": "app2", "container": "app2"},
            ],
        )
        connector._tenant_id = "tenant-001"
        connector._client_id = "client-001"
        connector._client_secret = "secret-001"

        calls = []

        def fake_fetch(app_name, resource_group, since):
            calls.append((app_name, resource_group))
            return []

        with patch.object(connector, "_fetch_logs_for_app", side_effect=fake_fetch):
            connector.poll(checkpoint=None)

        assert calls == [("app1", "custom-rg"), ("app2", "default-rg")]

    def test_poll_skips_empty_log_content(self) -> None:
        connector = self._make_connector()
        rows = [
            {"TimeGenerated": "2026-03-05T14:30:00Z", "Log_s": "",
             "ContainerName_s": "opensign", "Stream_s": "stdout", "RevisionName_s": "rev1"},
            {"TimeGenerated": "2026-03-05T15:00:00Z", "Log_s": "actual log",
             "ContainerName_s": "opensign", "Stream_s": "stdout", "RevisionName_s": "rev1"},
        ]

        with patch.object(connector, "_fetch_logs_for_app", return_value=rows):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].raw["line"] == "actual log"


# ─── event_types() ───────────────────────────────────────────────────


class TestContainerLogsEventTypes:
    def test_event_types_returns_log_line(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[],
        )
        assert connector.event_types() == ["log_line"]


# ─── manifest ────────────────────────────────────────────────────────


class TestContainerLogsManifest:
    def test_manifest_loads_and_validates(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest

        plugin_dir = Path(__file__).parent.parent.parent / "src" / "mallcop" / "connectors" / "container_logs"
        manifest = load_connector_manifest(plugin_dir)

        assert manifest.name == "container-logs"
        assert manifest.version == "0.1.0"
        assert "log_line" in manifest.event_types
        assert "tenant_id" in manifest.auth["required"]
        assert "client_id" in manifest.auth["required"]
        assert "client_secret" in manifest.auth["required"]

    def test_event_types_match_connector(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        plugin_dir = Path(__file__).parent.parent.parent / "src" / "mallcop" / "connectors" / "container_logs"
        manifest = load_connector_manifest(plugin_dir)
        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[],
        )

        assert set(connector.event_types()) == set(manifest.event_types)


# ─── Error path tests ────────────────────────────────────────────────


class TestContainerLogsErrorPaths:
    def _make_connector(self):
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[{"name": "opensign", "container": "opensign"}],
        )
        connector._tenant_id = "tenant-001"
        connector._client_id = "client-001"
        connector._client_secret = "secret-001"
        return connector

    def test_get_token_401_unauthorized_raises_config_error(self) -> None:
        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 401
        fake_resp.text = "Unauthorized: Invalid client credentials"

        with patch("mallcop.connectors.container_logs.connector.requests.post", return_value=fake_resp):
            with pytest.raises(ConfigError, match="401"):
                connector._get_token()

    def test_get_la_token_401_raises_config_error(self) -> None:
        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 401
        fake_resp.text = "Unauthorized"

        with patch("mallcop.connectors.container_logs.connector.requests.post", return_value=fake_resp):
            with pytest.raises(ConfigError, match="401"):
                connector._get_la_token()

    def test_get_la_token_500_server_error_raises_config_error(self) -> None:
        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 500
        fake_resp.text = "Internal Server Error"

        with patch("mallcop.connectors.container_logs.connector.requests.post", return_value=fake_resp):
            with pytest.raises(ConfigError, match="500"):
                connector._get_la_token()

    def test_get_paginated_429_throttled_raises_http_error(self) -> None:
        from requests.exceptions import HTTPError

        connector = self._make_connector()
        connector._cached_token = "mgmt-token-123"
        connector._token_expires_at = 9999999999.0

        fake_resp = MagicMock()
        fake_resp.raise_for_status.side_effect = HTTPError("429 Too Many Requests")

        with patch("mallcop.connectors.container_logs.connector.requests.get", return_value=fake_resp):
            with pytest.raises(HTTPError, match="429"):
                connector._get_paginated("https://management.azure.com/test")

    def test_get_workspace_id_missing_environment_raises(self) -> None:
        connector = self._make_connector()
        connector._cached_token = "mgmt-token-123"
        connector._token_expires_at = 9999999999.0

        fake_resp = MagicMock()
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = {"properties": {}}  # No environmentId

        with patch("mallcop.connectors.container_logs.connector.requests.get", return_value=fake_resp):
            with pytest.raises(ConfigError, match="No environment found"):
                connector._get_workspace_id("opensign", "acme-rg")

    def test_poll_raises_when_all_apps_fail(self) -> None:
        """poll() raises RuntimeError when every app fails to fetch."""
        from requests.exceptions import ConnectionError as ReqConnectionError

        connector = self._make_connector()

        with patch.object(
            connector, "_fetch_logs_for_app",
            side_effect=ReqConnectionError("Connection timed out"),
        ):
            with pytest.raises(RuntimeError, match="all 1 apps failed"):
                connector.poll(checkpoint=None)

    def test_poll_partial_failure_returns_successful_events(self) -> None:
        """poll() returns events from successful apps when some fail."""
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector
        from requests.exceptions import ConnectionError as ReqConnectionError

        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[
                {"name": "app-ok", "container": "c1"},
                {"name": "app-fail", "container": "c2"},
            ],
        )
        connector._tenant_id = "tenant-001"
        connector._client_id = "client-001"
        connector._client_secret = "secret-001"

        def fetch_side_effect(app_name, rg, since):
            if app_name == "app-fail":
                raise ReqConnectionError("Connection timed out")
            return [{"TimeGenerated": "2026-03-15T00:00:00Z", "Log_s": "ok", "ContainerName_s": "c1", "Stream_s": "stdout"}]

        with patch.object(connector, "_fetch_logs_for_app", side_effect=fetch_side_effect):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert isinstance(result.checkpoint, Checkpoint)


# ─── _fetch_logs_for_app() (Log Analytics) ───────────────────────────


class TestFetchLogsForApp:
    def _make_connector(self):
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector(
            subscription_id="sub-001",
            resource_group="acme-rg",
            apps=[{"name": "opensign", "container": "opensign"}],
        )
        connector._tenant_id = "tenant-001"
        connector._client_id = "client-001"
        connector._client_secret = "secret-001"
        connector._cached_token = "mgmt-token-123"
        connector._token_expires_at = 9999999999.0
        connector._la_token = "la-token-456"
        connector._la_token_expires_at = 9999999999.0
        return connector

    def test_queries_log_analytics(self) -> None:
        connector = self._make_connector()
        connector._workspace_cache["env-001"] = "workspace-001"

        la_response = {
            "tables": [{
                "columns": [
                    {"name": "TimeGenerated"}, {"name": "Log_s"},
                    {"name": "ContainerName_s"}, {"name": "Stream_s"},
                    {"name": "RevisionName_s"}, {"name": "ContainerAppName_s"},
                ],
                "rows": [
                    ["2026-03-05T14:30:00Z", "started", "opensign", "stdout", "rev1", "opensign"],
                ],
            }],
        }

        mock_get = MagicMock()
        mock_get.return_value.raise_for_status = MagicMock()
        mock_get.return_value.json.return_value = {
            "properties": {"environmentId": "env-001"},
        }

        mock_post = MagicMock()
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = la_response

        with patch("mallcop.connectors.container_logs.connector.requests.get", mock_get), \
             patch("mallcop.connectors.container_logs.connector.requests.post", mock_post):
            result = connector._fetch_logs_for_app("opensign", "acme-rg", None)

        assert len(result) == 1
        assert result[0]["Log_s"] == "started"
        assert result[0]["ContainerName_s"] == "opensign"

    def test_returns_empty_when_no_tables(self) -> None:
        connector = self._make_connector()
        connector._workspace_cache["env-001"] = "workspace-001"

        mock_get = MagicMock()
        mock_get.return_value.raise_for_status = MagicMock()
        mock_get.return_value.json.return_value = {
            "properties": {"environmentId": "env-001"},
        }

        mock_post = MagicMock()
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"tables": []}

        with patch("mallcop.connectors.container_logs.connector.requests.get", mock_get), \
             patch("mallcop.connectors.container_logs.connector.requests.post", mock_post):
            result = connector._fetch_logs_for_app("opensign", "acme-rg", None)

        assert result == []

    def test_uses_since_in_query(self) -> None:
        connector = self._make_connector()
        connector._workspace_cache["env-001"] = "workspace-001"
        since = datetime(2026, 3, 5, 14, 0, 0, tzinfo=timezone.utc)

        mock_get = MagicMock()
        mock_get.return_value.raise_for_status = MagicMock()
        mock_get.return_value.json.return_value = {
            "properties": {"environmentId": "env-001"},
        }

        mock_post = MagicMock()
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"tables": []}

        with patch("mallcop.connectors.container_logs.connector.requests.get", mock_get), \
             patch("mallcop.connectors.container_logs.connector.requests.post", mock_post):
            connector._fetch_logs_for_app("opensign", "acme-rg", since)

        # Verify the Log Analytics query includes the since filter
        post_call = mock_post.call_args
        query = post_call[1]["json"]["query"]
        assert "2026-03-05T14:00:00" in query

    def test_resolves_workspace_from_environment(self) -> None:
        connector = self._make_connector()
        # No workspace cache — should resolve

        # Mock: app details → env ID, env details → workspace ID
        call_count = [0]

        def get_side_effect(url, **kwargs):
            call_count[0] += 1
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if call_count[0] == 1:
                # App details
                resp.json.return_value = {
                    "properties": {"environmentId": "/subs/sub-001/envs/my-env"},
                }
            else:
                # Environment details
                resp.json.return_value = {
                    "properties": {
                        "appLogsConfiguration": {
                            "logAnalyticsConfiguration": {
                                "customerId": "ws-resolved-001",
                            }
                        }
                    },
                }
            return resp

        mock_post = MagicMock()
        mock_post.return_value.raise_for_status = MagicMock()
        mock_post.return_value.json.return_value = {"tables": []}

        with patch("mallcop.connectors.container_logs.connector.requests.get", MagicMock(side_effect=get_side_effect)), \
             patch("mallcop.connectors.container_logs.connector.requests.post", mock_post):
            connector._fetch_logs_for_app("opensign", "acme-rg", None)

        # Should have cached the workspace
        assert connector._workspace_cache["/subs/sub-001/envs/my-env"] == "ws-resolved-001"

        # Log Analytics query should use the resolved workspace
        post_call = mock_post.call_args
        assert "ws-resolved-001" in post_call[0][0]


# ─── CLI config injection ────────────────────────────────────────────


class TestContainerLogsConfigInjection:
    def test_configure_sets_subscription_id(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector()
        config = {
            "subscription_id": "sub-injected",
            "resource_group": "rg-injected",
            "apps": [{"name": "app1", "container": "app1"}],
        }
        connector.configure(config)

        assert connector._subscription_id == "sub-injected"
        assert connector._resource_group == "rg-injected"
        assert connector._apps == [{"name": "app1", "container": "app1"}]

    def test_configure_skips_missing_keys(self) -> None:
        from mallcop.connectors.container_logs.connector import ContainerLogsConnector

        connector = ContainerLogsConnector(
            subscription_id="original",
            resource_group="original-rg",
        )
        connector.configure({})

        assert connector._subscription_id == "original"
        assert connector._resource_group == "original-rg"

    def test_configure_noop_on_base_connector(self) -> None:
        from mallcop.connectors._base import ConnectorBase

        # ConnectorBase.configure() is a no-op by default
        class FakeConnector(ConnectorBase):
            def discover(self):
                pass
            def authenticate(self, secrets):
                pass
            def poll(self, checkpoint):
                pass
            def event_types(self):
                return []

        connector = FakeConnector()
        config = {
            "subscription_id": "sub-001",
            "resource_group": "rg-001",
            "apps": [],
        }
        # Should not raise
        connector.configure(config)
