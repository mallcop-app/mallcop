"""Tests for Azure connector live API calls (OAuth2 + REST)."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from mallcop.connectors.azure.connector import AzureConnector
from mallcop.schemas import Checkpoint
from mallcop.secrets import ConfigError


def _make_connector() -> AzureConnector:
    """Create a connector with credentials set (bypassing authenticate)."""
    c = AzureConnector()
    c._tenant_id = "test-tenant-id"
    c._client_id = "test-client-id"
    c._client_secret = "test-client-secret"
    return c


# ─── _get_token() ────────────────────────────────────────────────────


class TestGetToken:
    def test_get_token_success(self) -> None:
        """Mock token endpoint returns access_token."""
        connector = _make_connector()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "eyJ-fake-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

        with patch("mallcop.connectors.azure.connector.requests.post", return_value=mock_resp) as mock_post:
            token = connector._get_token()

        assert token == "eyJ-fake-token"
        mock_post.assert_called_once()
        # Verify correct endpoint and body
        call_args = mock_post.call_args
        assert "test-tenant-id" in call_args[0][0]
        assert call_args[1]["data"]["grant_type"] == "client_credentials"
        assert call_args[1]["data"]["client_id"] == "test-client-id"
        assert call_args[1]["data"]["client_secret"] == "test-client-secret"
        assert call_args[1]["data"]["scope"] == "https://management.azure.com/.default"

    def test_get_token_caches(self) -> None:
        """Two calls should only make one HTTP request."""
        connector = _make_connector()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "cached-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

        with patch("mallcop.connectors.azure.connector.requests.post", return_value=mock_resp) as mock_post:
            token1 = connector._get_token()
            token2 = connector._get_token()

        assert token1 == "cached-token"
        assert token2 == "cached-token"
        mock_post.assert_called_once()

    def test_get_token_refreshes_on_expiry(self) -> None:
        """Expired cache triggers a new HTTP request."""
        connector = _make_connector()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "first-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

        with patch("mallcop.connectors.azure.connector.requests.post", return_value=mock_resp) as mock_post:
            token1 = connector._get_token()
            assert token1 == "first-token"
            assert mock_post.call_count == 1

            # Simulate expiry by backdating the cache
            connector._token_expires_at = time.monotonic() - 1

            mock_resp2 = MagicMock()
            mock_resp2.status_code = 200
            mock_resp2.json.return_value = {
                "access_token": "second-token",
                "expires_in": 3600,
                "token_type": "Bearer",
            }
            mock_post.return_value = mock_resp2

            token2 = connector._get_token()

        assert token2 == "second-token"
        assert mock_post.call_count == 2

    def test_get_token_auth_failure(self) -> None:
        """401 response raises ConfigError."""
        connector = _make_connector()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {
            "error": "invalid_client",
            "error_description": "Invalid client credentials",
        }
        mock_resp.text = "Invalid client credentials"

        with patch("mallcop.connectors.azure.connector.requests.post", return_value=mock_resp):
            with pytest.raises(ConfigError, match="Azure authentication failed"):
                connector._get_token()


# ─── _list_subscriptions() ───────────────────────────────────────────


class TestListSubscriptions:
    def test_list_subscriptions(self) -> None:
        """Mock response returns parsed subscription list."""
        connector = _make_connector()

        subs_data = [
            {"subscriptionId": "sub-1", "displayName": "Prod"},
            {"subscriptionId": "sub-2", "displayName": "Dev"},
        ]

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {
            "access_token": "tok",
            "expires_in": 3600,
        }

        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {"value": subs_data}

        with patch("mallcop.connectors.azure.connector.requests.post", return_value=mock_token_resp), \
             patch("mallcop.connectors.azure.connector.requests.get", return_value=mock_get_resp) as mock_get:
            result = connector._list_subscriptions()

        assert result == subs_data
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert "subscriptions" in call_args[0][0]
        assert "Bearer tok" in str(call_args[1]["headers"])

    def test_list_subscriptions_pagination(self) -> None:
        """Follows nextLink to aggregate all pages."""
        connector = _make_connector()

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {
            "access_token": "tok",
            "expires_in": 3600,
        }

        page1_resp = MagicMock()
        page1_resp.status_code = 200
        page1_resp.json.return_value = {
            "value": [{"subscriptionId": "sub-1", "displayName": "Prod"}],
            "nextLink": "https://management.azure.com/subscriptions?page=2",
        }

        page2_resp = MagicMock()
        page2_resp.status_code = 200
        page2_resp.json.return_value = {
            "value": [{"subscriptionId": "sub-2", "displayName": "Dev"}],
        }

        with patch("mallcop.connectors.azure.connector.requests.post", return_value=mock_token_resp), \
             patch("mallcop.connectors.azure.connector.requests.get", side_effect=[page1_resp, page2_resp]) as mock_get:
            result = connector._list_subscriptions()

        assert len(result) == 2
        assert result[0]["subscriptionId"] == "sub-1"
        assert result[1]["subscriptionId"] == "sub-2"
        assert mock_get.call_count == 2


# ─── _fetch_activity_log() ───────────────────────────────────────────


class TestFetchActivityLog:
    def test_fetch_activity_log_with_checkpoint(self) -> None:
        """Passes checkpoint as $filter parameter."""
        connector = _make_connector()

        events_data = [{"eventDataId": "e1", "eventTimestamp": "2026-03-05T15:00:00Z"}]

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {
            "access_token": "tok",
            "expires_in": 3600,
        }

        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {"value": events_data}

        checkpoint = Checkpoint(
            connector="azure",
            value="2026-03-05T14:00:00+00:00",
            updated_at=None,
        )

        with patch("mallcop.connectors.azure.connector.requests.post", return_value=mock_token_resp), \
             patch("mallcop.connectors.azure.connector.requests.get", return_value=mock_get_resp) as mock_get:
            result = connector._fetch_activity_log("sub-1", checkpoint)

        assert result == events_data
        call_args = mock_get.call_args
        # Verify the filter parameter includes the checkpoint
        params = call_args[1]["params"]
        assert "$filter" in params
        assert "2026-03-05T14:00:00+00:00" in params["$filter"]

    def test_fetch_activity_log_pagination(self) -> None:
        """Follows nextLink to aggregate all pages."""
        connector = _make_connector()

        mock_token_resp = MagicMock()
        mock_token_resp.status_code = 200
        mock_token_resp.json.return_value = {
            "access_token": "tok",
            "expires_in": 3600,
        }

        page1_resp = MagicMock()
        page1_resp.status_code = 200
        page1_resp.json.return_value = {
            "value": [{"eventDataId": "e1"}],
            "nextLink": "https://management.azure.com/next-page",
        }

        page2_resp = MagicMock()
        page2_resp.status_code = 200
        page2_resp.json.return_value = {
            "value": [{"eventDataId": "e2"}],
        }

        with patch("mallcop.connectors.azure.connector.requests.post", return_value=mock_token_resp), \
             patch("mallcop.connectors.azure.connector.requests.get", side_effect=[page1_resp, page2_resp]) as mock_get:
            result = connector._fetch_activity_log("sub-1", None)

        assert len(result) == 2
        assert result[0]["eventDataId"] == "e1"
        assert result[1]["eventDataId"] == "e2"
        assert mock_get.call_count == 2


# ─── authenticate() with eager validation ────────────────────────────


class TestAuthenticateEager:
    def test_authenticate_validates_credentials(self) -> None:
        """Successful token fetch means authenticate passes."""
        from mallcop.secrets import SecretProvider

        class FakeSecrets(SecretProvider):
            def resolve(self, name: str) -> str:
                return {"AZURE_TENANT_ID": "tid", "AZURE_CLIENT_ID": "cid", "AZURE_CLIENT_SECRET": "cs"}[name]

        connector = AzureConnector()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "valid-token",
            "expires_in": 3600,
        }

        with patch("mallcop.connectors.azure.connector.requests.post", return_value=mock_resp):
            connector.authenticate(FakeSecrets())

        assert connector._tenant_id == "tid"

    def test_authenticate_fails_on_bad_creds(self) -> None:
        """Token failure during authenticate raises ConfigError."""
        from mallcop.secrets import SecretProvider

        class FakeSecrets(SecretProvider):
            def resolve(self, name: str) -> str:
                return {"AZURE_TENANT_ID": "tid", "AZURE_CLIENT_ID": "cid", "AZURE_CLIENT_SECRET": "bad"}[name]

        connector = AzureConnector()

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {"error": "invalid_client"}
        mock_resp.text = "bad creds"

        with patch("mallcop.connectors.azure.connector.requests.post", return_value=mock_resp):
            with pytest.raises(ConfigError, match="Azure authentication failed"):
                connector.authenticate(FakeSecrets())
