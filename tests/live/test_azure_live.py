"""Live integration tests: Azure connector with real API calls.

These tests require AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET
in the environment. Run with: pytest -m live
"""

from __future__ import annotations

import pytest

from mallcop.connectors.azure.connector import AzureConnector
from mallcop.schemas import Checkpoint, Event, Severity
from mallcop.secrets import EnvSecretProvider


@pytest.fixture
def azure_connector(
    azure_tenant_id: str,
    azure_client_id: str,
    azure_client_secret: str,
) -> AzureConnector:
    """Build and authenticate an AzureConnector with real credentials."""
    connector = AzureConnector()
    secrets = EnvSecretProvider()
    connector.authenticate(secrets)
    return connector


@pytest.mark.live
class TestAzureConnectorPoll:
    """Test 4: Azure connector poll — authenticate, list subscriptions, poll."""

    def test_authentication_succeeds(
        self,
        azure_tenant_id: str,
        azure_client_id: str,
        azure_client_secret: str,
    ) -> None:
        """Authenticate with real credentials and verify token is obtained."""
        connector = AzureConnector()
        secrets = EnvSecretProvider()
        # authenticate() calls _get_token() internally — if it doesn't raise, auth worked
        connector.authenticate(secrets)
        # Token should be cached
        assert connector._cached_token is not None
        assert len(connector._cached_token) > 0

    def test_list_subscriptions_non_empty(self, azure_connector: AzureConnector) -> None:
        """List subscriptions and verify at least one exists."""
        subs = azure_connector._list_subscriptions()
        assert isinstance(subs, list)
        assert len(subs) > 0, "Expected at least one Azure subscription"

        # Each subscription should have an ID and display name
        for sub in subs:
            assert "subscriptionId" in sub
            assert "displayName" in sub

    def test_poll_activity_log(self, azure_connector: AzureConnector) -> None:
        """Poll activity log for the last hour. May return empty if quiet."""
        subs = azure_connector._list_subscriptions()
        assert len(subs) > 0

        # Set subscription IDs on the connector
        azure_connector._subscription_ids = [s["subscriptionId"] for s in subs[:1]]

        # Poll with no checkpoint (gets recent events)
        result = azure_connector.poll(checkpoint=None)

        # PollResult should always have a checkpoint
        assert result.checkpoint is not None
        assert result.checkpoint.connector == "azure"
        assert len(result.checkpoint.value) > 0

        # Events may be empty during a quiet period — that's OK
        assert isinstance(result.events, list)

        # If there are events, verify they normalize correctly
        for evt in result.events:
            assert isinstance(evt, Event)
            assert evt.source == "azure"
            assert evt.id.startswith("evt_")
            assert evt.severity in (Severity.INFO, Severity.WARN, Severity.CRITICAL)
            assert len(evt.actor) > 0
            assert len(evt.action) > 0
            assert isinstance(evt.metadata, dict)
            # Metadata should have subscription_id
            assert "subscription_id" in evt.metadata

    def test_poll_with_checkpoint_filters(self, azure_connector: AzureConnector) -> None:
        """Poll twice: first without checkpoint, then with the returned checkpoint.
        Second poll should return equal or fewer events."""
        subs = azure_connector._list_subscriptions()
        assert len(subs) > 0

        azure_connector._subscription_ids = [s["subscriptionId"] for s in subs[:1]]

        # First poll
        result1 = azure_connector.poll(checkpoint=None)

        # Second poll with the checkpoint from the first
        result2 = azure_connector.poll(checkpoint=result1.checkpoint)

        # Second poll should not return more events than the first
        # (it filters to events after the checkpoint)
        assert len(result2.events) <= len(result1.events)

        # Checkpoint should be updated
        assert result2.checkpoint is not None


@pytest.mark.live
class TestAzureConnectorDiscover:
    """Test 5: Azure connector discover — verify environment discovery."""

    def test_discover_returns_available(
        self,
        azure_tenant_id: str,
        azure_client_id: str,
        azure_client_secret: str,
    ) -> None:
        """Call discover() with valid credentials and verify results."""
        connector = AzureConnector()
        secrets = EnvSecretProvider()
        connector.authenticate(secrets)

        result = connector.discover()

        assert result.available is True
        assert len(result.resources) > 0, "Expected at least one resource (subscription)"
        assert "subscription_ids" in result.suggested_config
        assert len(result.suggested_config["subscription_ids"]) > 0
        assert len(result.missing_credentials) == 0

    def test_discover_without_auth_returns_unavailable(self) -> None:
        """Call discover() without authentication — should return unavailable."""
        connector = AzureConnector()
        # Don't authenticate — _get_token will fail
        result = connector.discover()

        assert result.available is False
        assert len(result.missing_credentials) > 0
