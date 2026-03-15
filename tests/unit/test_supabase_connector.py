"""Tests for Supabase connector — auth audit logs + config monitoring."""

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

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "supabase"


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


_FULL_SECRETS = {
    "SUPABASE_PROJECT_URL": "https://xyzcompany.supabase.co",
    "SUPABASE_SERVICE_ROLE_KEY": "eyJ_fake_service_role_key",
    "SUPABASE_PROJECT_REF": "xyzcompany",
    "SUPABASE_ACCESS_TOKEN": "sbp_fake_access_token",
}

_REQUIRED_SECRETS = {
    "SUPABASE_PROJECT_URL": "https://xyzcompany.supabase.co",
    "SUPABASE_SERVICE_ROLE_KEY": "eyJ_fake_service_role_key",
    "SUPABASE_PROJECT_REF": "xyzcompany",
}


def _mock_postgrest_response(data: Any, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = data
    resp.raise_for_status.return_value = None
    resp.text = json.dumps(data) if isinstance(data, (list, dict)) else str(data)
    if status_code >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    return resp


# ─── authenticate() ─────────────────────────────────────────────────


class TestSupabaseConnectorAuthenticate:
    def test_authenticate_succeeds_with_all_secrets(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        connector = SupabaseConnector()
        secrets = FakeSecretProvider(_FULL_SECRETS)

        with patch.object(connector, "_validate_connection"):
            connector.authenticate(secrets)

        assert connector._project_url == "https://xyzcompany.supabase.co"
        assert connector._service_role_key == "eyJ_fake_service_role_key"
        assert connector._project_ref == "xyzcompany"
        assert connector._access_token == "sbp_fake_access_token"

    def test_authenticate_succeeds_without_access_token(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        connector = SupabaseConnector()
        secrets = FakeSecretProvider(_REQUIRED_SECRETS)

        with patch.object(connector, "_validate_connection"):
            connector.authenticate(secrets)

        assert connector._access_token is None

    def test_authenticate_raises_on_missing_project_url(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        secrets = FakeSecretProvider({
            "SUPABASE_SERVICE_ROLE_KEY": "key",
            "SUPABASE_PROJECT_REF": "ref",
        })
        connector = SupabaseConnector()
        with pytest.raises(ConfigError, match="SUPABASE_PROJECT_URL"):
            connector.authenticate(secrets)

    def test_authenticate_raises_on_missing_service_role_key(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        secrets = FakeSecretProvider({
            "SUPABASE_PROJECT_URL": "https://x.supabase.co",
            "SUPABASE_PROJECT_REF": "ref",
        })
        connector = SupabaseConnector()
        with pytest.raises(ConfigError, match="SUPABASE_SERVICE_ROLE_KEY"):
            connector.authenticate(secrets)

    def test_authenticate_raises_on_missing_project_ref(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        secrets = FakeSecretProvider({
            "SUPABASE_PROJECT_URL": "https://x.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "key",
        })
        connector = SupabaseConnector()
        with pytest.raises(ConfigError, match="SUPABASE_PROJECT_REF"):
            connector.authenticate(secrets)

    def test_authenticate_strips_trailing_slash(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        secrets = FakeSecretProvider({
            **_REQUIRED_SECRETS,
            "SUPABASE_PROJECT_URL": "https://xyzcompany.supabase.co/",
        })
        connector = SupabaseConnector()
        with patch.object(connector, "_validate_connection"):
            connector.authenticate(secrets)
        assert connector._project_url == "https://xyzcompany.supabase.co"

    def test_validate_connection_raises_on_401(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        connector = SupabaseConnector()
        connector._project_url = "https://x.supabase.co"
        connector._service_role_key = "bad_key"
        connector._project_ref = "ref"

        mock_resp = _mock_postgrest_response({"message": "Invalid JWT"}, 401)
        with patch("mallcop.connectors.supabase.connector.requests.get", return_value=mock_resp):
            with pytest.raises(ConfigError, match="invalid service_role_key"):
                connector._validate_connection()


# ─── event_types() ──────────────────────────────────────────────────


class TestSupabaseConnectorEventTypes:
    def test_event_types_match_manifest(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector
        from mallcop.connectors._schema import load_connector_manifest

        connector = SupabaseConnector()
        manifest = load_connector_manifest(
            Path(__file__).parent.parent.parent
            / "src"
            / "mallcop"
            / "connectors"
            / "supabase"
        )
        assert sorted(connector.event_types()) == sorted(manifest.event_types)


# ─── Auth action classification ─────────────────────────────────────


class TestAuthActionClassification:
    def test_login_success(self) -> None:
        from mallcop.connectors.supabase.connector import _classify_auth_action

        assert _classify_auth_action("login", {"traits": {}}) == "auth_success"

    def test_login_failure(self) -> None:
        from mallcop.connectors.supabase.connector import _classify_auth_action

        payload = {"traits": {"error": "invalid_credentials"}}
        assert _classify_auth_action("login", payload) == "auth_failure"

    def test_signup(self) -> None:
        from mallcop.connectors.supabase.connector import _classify_auth_action

        assert _classify_auth_action("user_signedup", {}) == "user_created"

    def test_logout(self) -> None:
        from mallcop.connectors.supabase.connector import _classify_auth_action

        assert _classify_auth_action("logout", {}) == "auth_logout"

    def test_token_refresh(self) -> None:
        from mallcop.connectors.supabase.connector import _classify_auth_action

        assert _classify_auth_action("token_refreshed", {}) == "token_refresh"

    def test_password_recovery(self) -> None:
        from mallcop.connectors.supabase.connector import _classify_auth_action

        assert (
            _classify_auth_action("user_recovery_requested", {})
            == "password_recovery"
        )

    def test_mfa_verified(self) -> None:
        from mallcop.connectors.supabase.connector import _classify_auth_action

        assert (
            _classify_auth_action("mfa_challenge_verified", {}) == "mfa_verified"
        )

    def test_unknown_action_defaults(self) -> None:
        from mallcop.connectors.supabase.connector import _classify_auth_action

        assert _classify_auth_action("some_new_action", {}) == "auth_success"


# ─── Actor extraction ───────────────────────────────────────────────


class TestActorExtraction:
    def test_email_preferred(self) -> None:
        from mallcop.connectors.supabase.connector import _extract_actor

        payload = {
            "actor_id": "usr_001",
            "traits": {"email": "admin@acme-corp.com"},
        }
        assert _extract_actor(payload) == "admin@acme-corp.com"

    def test_falls_back_to_actor_id(self) -> None:
        from mallcop.connectors.supabase.connector import _extract_actor

        payload = {"actor_id": "usr_001", "traits": {}}
        assert _extract_actor(payload) == "usr_001"

    def test_falls_back_to_user_id(self) -> None:
        from mallcop.connectors.supabase.connector import _extract_actor

        payload = {"traits": {"user_id": "uid_abc"}}
        assert _extract_actor(payload) == "uid_abc"

    def test_unknown_when_empty(self) -> None:
        from mallcop.connectors.supabase.connector import _extract_actor

        assert _extract_actor({}) == "unknown"
        assert _extract_actor({"traits": {}}) == "unknown"


# ─── poll() — auth audit ────────────────────────────────────────────


class TestSupabaseConnectorPoll:
    def _make_connector(self) -> Any:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        c = SupabaseConnector()
        c._project_url = "https://xyzcompany.supabase.co"
        c._service_role_key = "eyJ_fake"
        c._project_ref = "xyzcompany"
        c._access_token = None
        return c

    def test_poll_no_checkpoint_returns_events(self) -> None:
        connector = self._make_connector()
        entries = _load_fixture("auth_audit_entries.json")

        mock_resp = _mock_postgrest_response(entries)
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ):
            result = connector.poll(None)

        assert isinstance(result, PollResult)
        assert len(result.events) == 9
        assert result.checkpoint.connector == "supabase"
        assert "|" in result.checkpoint.value  # Composite checkpoint

    def test_poll_classifies_events_correctly(self) -> None:
        connector = self._make_connector()
        entries = _load_fixture("auth_audit_entries.json")

        mock_resp = _mock_postgrest_response(entries)
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ):
            result = connector.poll(None)

        event_types = [e.event_type for e in result.events]
        assert event_types == [
            "auth_success",      # login (no error)
            "auth_failure",      # login (with error)
            "user_created",      # user_signedup
            "auth_logout",       # logout
            "token_refresh",     # token_refreshed
            "password_recovery", # user_recovery_requested
            "user_invited",      # user_invited
            "user_deleted",      # user_deleted
            "mfa_verified",      # mfa_challenge_verified
        ]

    def test_poll_sets_correct_severities(self) -> None:
        connector = self._make_connector()
        entries = _load_fixture("auth_audit_entries.json")

        mock_resp = _mock_postgrest_response(entries)
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ):
            result = connector.poll(None)

        severities = [e.severity for e in result.events]
        assert severities == [
            Severity.INFO,      # auth_success
            Severity.WARN,      # auth_failure
            Severity.INFO,      # user_created
            Severity.INFO,      # auth_logout
            Severity.INFO,      # token_refresh
            Severity.WARN,      # password_recovery
            Severity.INFO,      # user_invited
            Severity.WARN,      # user_deleted
            Severity.INFO,      # mfa_verified
        ]

    def test_poll_extracts_actors(self) -> None:
        connector = self._make_connector()
        entries = _load_fixture("auth_audit_entries.json")

        mock_resp = _mock_postgrest_response(entries)
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ):
            result = connector.poll(None)

        actors = [e.actor for e in result.events]
        assert actors[0] == "admin@acme-corp.com"
        assert actors[1] == "attacker@evil.com"
        assert actors[2] == "newuser@acme-corp.com"

    def test_poll_sets_source_to_supabase(self) -> None:
        connector = self._make_connector()
        entries = _load_fixture("auth_audit_entries.json")

        mock_resp = _mock_postgrest_response(entries)
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ):
            result = connector.poll(None)

        assert all(e.source == "supabase" for e in result.events)

    def test_poll_includes_ip_in_metadata(self) -> None:
        connector = self._make_connector()
        entries = _load_fixture("auth_audit_entries.json")

        mock_resp = _mock_postgrest_response(entries)
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ):
            result = connector.poll(None)

        assert result.events[0].metadata["ip_address"] == "203.0.113.42"
        assert result.events[1].metadata["ip_address"] == "198.51.100.7"

    def test_poll_with_checkpoint_passes_filter(self) -> None:
        connector = self._make_connector()
        checkpoint = Checkpoint(
            connector="supabase",
            value="2026-03-14T10:03:00.000000+00:00|",
            updated_at=datetime.now(timezone.utc),
        )

        mock_resp = _mock_postgrest_response([])
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ) as mock_get:
            connector.poll(checkpoint)

        # Verify the PostgREST filter was applied
        call_args = mock_get.call_args
        params = call_args.kwargs.get("params") or call_args[1].get("params", {})
        assert params.get("created_at") == "gt.2026-03-14T10:03:00.000000+00:00"

    def test_poll_empty_response(self) -> None:
        connector = self._make_connector()

        mock_resp = _mock_postgrest_response([])
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ):
            result = connector.poll(None)

        assert len(result.events) == 0
        assert result.checkpoint.connector == "supabase"

    def test_poll_handles_string_payload(self) -> None:
        """Payload might come as JSON string instead of dict."""
        connector = self._make_connector()
        entry = {
            "id": "test-id",
            "created_at": "2026-03-14T10:00:00+00:00",
            "ip_address": "1.2.3.4",
            "payload": json.dumps({
                "action": "login",
                "traits": {"email": "user@test.com"},
            }),
        }

        mock_resp = _mock_postgrest_response([entry])
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ):
            result = connector.poll(None)

        assert len(result.events) == 1
        assert result.events[0].actor == "user@test.com"
        assert result.events[0].event_type == "auth_success"


# ─── Checkpoint parsing ─────────────────────────────────────────────


class TestCheckpointParsing:
    def test_parse_none(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        auth, config = SupabaseConnector._parse_checkpoint(None)
        assert auth is None
        assert config is None

    def test_parse_empty(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        cp = Checkpoint(connector="supabase", value="", updated_at=datetime.now(timezone.utc))
        auth, config = SupabaseConnector._parse_checkpoint(cp)
        assert auth is None
        assert config is None

    def test_parse_composite(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        cp = Checkpoint(
            connector="supabase",
            value="2026-03-14T10:00:00+00:00|2026-03-14T10:05:00+00:00",
            updated_at=datetime.now(timezone.utc),
        )
        auth, config = SupabaseConnector._parse_checkpoint(cp)
        assert auth == "2026-03-14T10:00:00+00:00"
        assert config == "2026-03-14T10:05:00+00:00"

    def test_parse_auth_only(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        cp = Checkpoint(
            connector="supabase",
            value="2026-03-14T10:00:00+00:00|",
            updated_at=datetime.now(timezone.utc),
        )
        auth, config = SupabaseConnector._parse_checkpoint(cp)
        assert auth == "2026-03-14T10:00:00+00:00"
        assert config is None


# ─── discover() ─────────────────────────────────────────────────────


class TestSupabaseConnectorDiscover:
    def test_discover_no_credentials(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        connector = SupabaseConnector()
        result = connector.discover()
        assert result.available is False
        assert "SUPABASE_PROJECT_URL" in result.missing_credentials

    def test_discover_with_valid_credentials(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        connector = SupabaseConnector()
        connector._project_url = "https://xyzcompany.supabase.co"
        connector._service_role_key = "eyJ_fake"
        connector._project_ref = "xyzcompany"

        mock_resp = _mock_postgrest_response([{"id": "test"}])
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ):
            result = connector.discover()

        assert result.available is True
        assert "project: xyzcompany" in result.resources

    def test_discover_with_mgmt_api(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        connector = SupabaseConnector()
        connector._project_url = "https://xyzcompany.supabase.co"
        connector._service_role_key = "eyJ_fake"
        connector._project_ref = "xyzcompany"
        connector._access_token = "sbp_fake"

        def mock_get(url: str, **kwargs: Any) -> MagicMock:
            if "rest/v1" in url:
                return _mock_postgrest_response([{"id": "test"}])
            # Management API
            return _mock_postgrest_response({"name": "My Supabase Project"})

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=mock_get,
        ):
            result = connector.discover()

        assert result.available is True
        assert "project_name: My Supabase Project" in result.resources
        assert any("Management API accessible" in n for n in result.notes)

    def test_discover_auth_table_inaccessible(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        connector = SupabaseConnector()
        connector._project_url = "https://xyzcompany.supabase.co"
        connector._service_role_key = "bad_key"
        connector._project_ref = "xyzcompany"

        mock_resp = _mock_postgrest_response({"message": "Unauthorized"}, 401)
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=mock_resp,
        ):
            result = connector.discover()

        assert result.available is False


# ─── Event ID determinism ───────────────────────────────────────────


class TestEventIdDeterminism:
    def test_same_entry_same_id(self) -> None:
        from mallcop.connectors.supabase.connector import SupabaseConnector

        connector = SupabaseConnector()
        connector._project_url = "https://x.supabase.co"
        connector._service_role_key = "key"
        connector._project_ref = "ref"

        entry = {
            "id": "unique-entry-id",
            "created_at": "2026-03-14T10:00:00+00:00",
            "ip_address": "1.2.3.4",
            "payload": {"action": "login", "traits": {"email": "u@t.com"}},
        }
        now = datetime.now(timezone.utc)
        e1 = connector._normalize_auth_entry(entry, now)
        e2 = connector._normalize_auth_entry(entry, now)
        assert e1.id == e2.id
        assert e1.id.startswith("evt_")


# ─── _poll_config_changes() ─────────────────────────────────────────


def _make_connector_with_mgmt() -> Any:
    """Return a connector wired up with a management access token."""
    from mallcop.connectors.supabase.connector import SupabaseConnector

    c = SupabaseConnector()
    c._project_url = "https://xyzcompany.supabase.co"
    c._service_role_key = "eyJ_fake"
    c._project_ref = "xyzcompany"
    c._access_token = "sbp_fake_access_token"
    return c


_NOW = datetime(2026, 3, 14, 12, 0, 0, tzinfo=timezone.utc)


def _mgmt_side_effect(
    secrets: Any = None,
    api_keys: Any = None,
    auth_config: Any = None,
) -> Any:
    """Build a requests.get side_effect that routes Management API calls."""
    _secrets = secrets if secrets is not None else []
    _api_keys = api_keys if api_keys is not None else []
    _auth_cfg = auth_config if auth_config is not None else {}

    def _side_effect(url: str, **kwargs: Any) -> MagicMock:
        if "/secrets" in url:
            return _mock_postgrest_response(_secrets)
        if "/api-keys" in url:
            return _mock_postgrest_response(_api_keys)
        if "/config/auth" in url:
            return _mock_postgrest_response(_auth_cfg)
        return _mock_postgrest_response({})

    return _side_effect


class TestPollConfigChanges:
    """Unit tests for SupabaseConnector._poll_config_changes()."""

    # ── baseline establishment (first poll) ─────────────────────────

    def test_first_poll_returns_no_events(self) -> None:
        """On first poll (since_ts=None) no events are emitted — baseline only."""
        connector = _make_connector_with_mgmt()
        secrets_data = [{"name": "DATABASE_URL"}, {"name": "JWT_SECRET"}]

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=_mgmt_side_effect(secrets=secrets_data),
        ):
            events, ts = connector._poll_config_changes(None, _NOW)

        assert events == []

    def test_first_poll_returns_now_as_timestamp(self) -> None:
        """On first poll the returned timestamp is now.isoformat()."""
        connector = _make_connector_with_mgmt()

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=_mgmt_side_effect(),
        ):
            events, ts = connector._poll_config_changes(None, _NOW)

        assert ts == _NOW.isoformat()

    def test_first_poll_with_empty_secrets_returns_no_events(self) -> None:
        """Empty secret list on first poll still produces no events."""
        connector = _make_connector_with_mgmt()

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=_mgmt_side_effect(secrets=[]),
        ):
            events, ts = connector._poll_config_changes(None, _NOW)

        assert events == []
        assert ts == _NOW.isoformat()

    # ── subsequent polls ─────────────────────────────────────────────

    def test_subsequent_poll_returns_no_events_simplified(self) -> None:
        """Subsequent poll (since_ts set) emits no events in simplified implementation."""
        connector = _make_connector_with_mgmt()
        since_ts = "2026-03-14T10:00:00+00:00"

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=_mgmt_side_effect(),
        ):
            events, ts = connector._poll_config_changes(since_ts, _NOW)

        assert events == []

    def test_subsequent_poll_returns_now_as_timestamp(self) -> None:
        """Subsequent poll always updates the config checkpoint to now."""
        connector = _make_connector_with_mgmt()
        since_ts = "2026-03-14T10:00:00+00:00"

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=_mgmt_side_effect(),
        ):
            events, ts = connector._poll_config_changes(since_ts, _NOW)

        assert ts == _NOW.isoformat()

    # ── API error handling ───────────────────────────────────────────

    def test_secrets_api_error_does_not_raise(self) -> None:
        """Secrets endpoint failure is caught — poll continues."""
        connector = _make_connector_with_mgmt()

        def failing_secrets(url: str, **kwargs: Any) -> MagicMock:
            if "/secrets" in url:
                raise Exception("Connection timeout")
            if "/api-keys" in url:
                return _mock_postgrest_response([])
            if "/config/auth" in url:
                return _mock_postgrest_response({})
            return _mock_postgrest_response({})

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=failing_secrets,
        ):
            events, ts = connector._poll_config_changes(None, _NOW)

        assert events == []
        assert ts == _NOW.isoformat()

    def test_api_keys_error_does_not_raise(self) -> None:
        """api-keys endpoint failure is caught — poll continues."""
        connector = _make_connector_with_mgmt()

        def failing_api_keys(url: str, **kwargs: Any) -> MagicMock:
            if "/secrets" in url:
                return _mock_postgrest_response([{"name": "MY_SECRET"}])
            if "/api-keys" in url:
                raise Exception("HTTP 503")
            if "/config/auth" in url:
                return _mock_postgrest_response({})
            return _mock_postgrest_response({})

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=failing_api_keys,
        ):
            events, ts = connector._poll_config_changes(None, _NOW)

        assert events == []

    def test_auth_config_error_does_not_raise(self) -> None:
        """auth config endpoint failure is caught — poll continues."""
        connector = _make_connector_with_mgmt()

        def failing_auth_cfg(url: str, **kwargs: Any) -> MagicMock:
            if "/secrets" in url:
                return _mock_postgrest_response([])
            if "/api-keys" in url:
                return _mock_postgrest_response([])
            if "/config/auth" in url:
                raise Exception("403 Forbidden")
            return _mock_postgrest_response({})

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=failing_auth_cfg,
        ):
            events, ts = connector._poll_config_changes(None, _NOW)

        assert events == []
        assert ts == _NOW.isoformat()

    def test_all_endpoints_failing_still_returns_valid_result(self) -> None:
        """All three Management API endpoints failing returns ([], now.isoformat())."""
        connector = _make_connector_with_mgmt()

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=Exception("Network unreachable"),
        ):
            events, ts = connector._poll_config_changes(None, _NOW)

        assert events == []
        assert ts == _NOW.isoformat()

    # ── return type contract ─────────────────────────────────────────

    def test_return_type_is_tuple_list_str(self) -> None:
        """_poll_config_changes always returns (list, str)."""
        connector = _make_connector_with_mgmt()

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=_mgmt_side_effect(),
        ):
            result = connector._poll_config_changes(None, _NOW)

        assert isinstance(result, tuple)
        assert len(result) == 2
        events, ts = result
        assert isinstance(events, list)
        assert isinstance(ts, str)

    def test_api_keys_non_list_response_handled(self) -> None:
        """If api-keys returns a non-list (e.g. dict), key_names defaults to []."""
        connector = _make_connector_with_mgmt()

        # api-keys returns a dict instead of a list — should not raise
        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=_mgmt_side_effect(api_keys={"error": "unexpected"}),
        ):
            events, ts = connector._poll_config_changes(None, _NOW)

        assert events == []
        assert ts == _NOW.isoformat()

    # ── integration via poll() ───────────────────────────────────────

    def test_poll_calls_config_polling_when_access_token_set(self) -> None:
        """poll() invokes _poll_config_changes when access_token is present.

        Config polling is currently a stub (no API calls) until state caching
        is implemented. This test verifies it runs without error and returns
        a valid checkpoint.
        """
        connector = _make_connector_with_mgmt()

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=_mock_postgrest_response([]),
        ):
            result = connector.poll(None)

        # Stub returns empty events, checkpoint should still be valid
        assert "|" in result.checkpoint.value

    def test_poll_skips_config_polling_without_access_token(self) -> None:
        """poll() skips _poll_config_changes when no access_token."""
        from mallcop.connectors.supabase.connector import SupabaseConnector

        connector = SupabaseConnector()
        connector._project_url = "https://xyzcompany.supabase.co"
        connector._service_role_key = "eyJ_fake"
        connector._project_ref = "xyzcompany"
        connector._access_token = None  # No token

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            return_value=_mock_postgrest_response([]),
        ) as mock_requests:
            result = connector.poll(None)

        # Only PostgREST call — no Management API calls
        urls_called = [call.args[0] for call in mock_requests.call_args_list]
        mgmt_calls = [u for u in urls_called if "api.supabase.com" in u]
        assert mgmt_calls == []
        # Checkpoint still valid
        assert "|" in result.checkpoint.value

    def test_poll_config_checkpoint_embedded_in_composite(self) -> None:
        """Config timestamp from _poll_config_changes ends up in composite checkpoint."""
        connector = _make_connector_with_mgmt()

        def mock_get(url: str, **kwargs: Any) -> MagicMock:
            if "rest/v1" in url:
                return _mock_postgrest_response([])
            return _mock_postgrest_response([])

        with patch(
            "mallcop.connectors.supabase.connector.requests.get",
            side_effect=mock_get,
        ):
            result = connector.poll(None)

        # Checkpoint must be composite with pipe separator
        parts = result.checkpoint.value.split("|")
        assert len(parts) == 2
        # Config part must be a non-empty ISO timestamp
        config_ts = parts[1]
        assert len(config_ts) > 0
        # Should parse as a valid ISO datetime
        from datetime import datetime
        parsed = datetime.fromisoformat(config_ts)
        assert parsed.tzinfo is not None
