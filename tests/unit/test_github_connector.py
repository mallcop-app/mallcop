"""Tests for GitHub org audit log + security alerts connector."""

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

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "github"


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


# ─── authenticate() ─────────────────────────────────────────────────


class TestGitHubConnectorAuthenticate:
    def test_authenticate_succeeds_with_valid_secrets(self) -> None:
        from mallcop.connectors.github.connector import GitHubConnector

        secrets = FakeSecretProvider({
            "GITHUB_TOKEN": "ghp_fake_token_12345",
            "GITHUB_ORG": "acme-corp",
        })

        connector = GitHubConnector()
        with patch.object(connector, "_validate_token"):
            connector.authenticate(secrets)

        assert connector._token == "ghp_fake_token_12345"
        assert connector._org == "acme-corp"

    def test_authenticate_raises_on_missing_token(self) -> None:
        from mallcop.connectors.github.connector import GitHubConnector

        secrets = FakeSecretProvider({"GITHUB_ORG": "acme-corp"})
        connector = GitHubConnector()
        with pytest.raises(ConfigError, match="GITHUB_TOKEN"):
            connector.authenticate(secrets)

    def test_authenticate_raises_on_missing_org(self) -> None:
        from mallcop.connectors.github.connector import GitHubConnector

        secrets = FakeSecretProvider({"GITHUB_TOKEN": "ghp_fake"})
        connector = GitHubConnector()
        with pytest.raises(ConfigError, match="GITHUB_ORG"):
            connector.authenticate(secrets)

    def test_authenticate_validates_token(self) -> None:
        from mallcop.connectors.github.connector import GitHubConnector

        secrets = FakeSecretProvider({
            "GITHUB_TOKEN": "ghp_bad",
            "GITHUB_ORG": "acme-corp",
        })

        fake_resp = MagicMock()
        fake_resp.status_code = 401
        fake_resp.text = "Bad credentials"

        connector = GitHubConnector()
        with patch("mallcop.connectors.github.connector.requests.get", return_value=fake_resp):
            with pytest.raises(ConfigError, match="authentication failed"):
                connector.authenticate(secrets)


# ─── discover() ─────────────────────────────────────────────────────


class TestGitHubConnectorDiscover:
    def _make_connector(self) -> Any:
        from mallcop.connectors.github.connector import GitHubConnector

        connector = GitHubConnector()
        connector._token = "ghp_fake"
        connector._org = "acme-corp"
        return connector

    def test_discover_returns_repos_and_members(self) -> None:
        repos = _load_fixture("discovery_repos.json")
        members = _load_fixture("discovery_members.json")
        connector = self._make_connector()

        with patch.object(connector, "_list_repos", return_value=repos), \
             patch.object(connector, "_list_members", return_value=members):
            result = connector.discover()

        assert isinstance(result, DiscoveryResult)
        assert result.available is True
        assert len(result.resources) == 5  # 3 repos + 2 members
        assert "repo: acme-corp/mallcop" in result.resources
        assert "member: admin-user" in result.resources

    def test_discover_suggests_config(self) -> None:
        repos = _load_fixture("discovery_repos.json")
        members = _load_fixture("discovery_members.json")
        connector = self._make_connector()

        with patch.object(connector, "_list_repos", return_value=repos), \
             patch.object(connector, "_list_members", return_value=members):
            result = connector.discover()

        assert result.suggested_config == {"org": "acme-corp"}

    def test_discover_reports_missing_credentials_on_failure(self) -> None:
        connector = self._make_connector()

        with patch.object(connector, "_list_repos", side_effect=Exception("Auth failed")):
            result = connector.discover()

        assert result.available is False
        assert "GITHUB_TOKEN" in result.missing_credentials

    def test_discover_includes_notes(self) -> None:
        repos = _load_fixture("discovery_repos.json")
        members = _load_fixture("discovery_members.json")
        connector = self._make_connector()

        with patch.object(connector, "_list_repos", return_value=repos), \
             patch.object(connector, "_list_members", return_value=members):
            result = connector.discover()

        assert any("3 repo(s)" in n for n in result.notes)
        assert any("2 member(s)" in n for n in result.notes)


# ─── _get_paginated() ───────────────────────────────────────────────


class TestGitHubConnectorGetPaginated:
    def _make_connector(self) -> Any:
        from mallcop.connectors.github.connector import GitHubConnector

        connector = GitHubConnector()
        connector._token = "ghp_fake"
        connector._org = "acme-corp"
        return connector

    def test_get_paginated_returns_array_response(self) -> None:
        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = [{"id": 1}, {"id": 2}]
        fake_resp.headers = {}

        with patch("requests.get", return_value=fake_resp):
            results, cursor = connector._get_paginated("https://api.github.com/test")

        assert results == [{"id": 1}, {"id": 2}]
        assert cursor is None

    def test_get_paginated_follows_link_header(self) -> None:
        connector = self._make_connector()

        page1_resp = MagicMock()
        page1_resp.raise_for_status = MagicMock()
        page1_resp.json.return_value = [{"id": 1}]
        page1_resp.headers = {
            "Link": '<https://api.github.com/test?page=2>; rel="next"'
        }

        page2_resp = MagicMock()
        page2_resp.raise_for_status = MagicMock()
        page2_resp.json.return_value = [{"id": 2}]
        page2_resp.headers = {}

        with patch("requests.get", side_effect=[page1_resp, page2_resp]):
            results, cursor = connector._get_paginated("https://api.github.com/test")

        assert results == [{"id": 1}, {"id": 2}]
        assert cursor is None

    def test_get_paginated_raises_on_http_error(self) -> None:
        from requests.exceptions import HTTPError

        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status.side_effect = HTTPError("404 Not Found")

        with patch("requests.get", return_value=fake_resp):
            with pytest.raises(HTTPError):
                connector._get_paginated("https://api.github.com/test")

    def test_get_paginated_handles_empty_list(self) -> None:
        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = []
        fake_resp.headers = {}

        with patch("requests.get", return_value=fake_resp):
            results, cursor = connector._get_paginated("https://api.github.com/test")

        assert results == []
        assert cursor is None

    def test_get_paginated_raises_on_unexpected_type(self) -> None:
        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = "unexpected"
        fake_resp.headers = {}

        with patch("requests.get", return_value=fake_resp):
            with pytest.raises(TypeError, match="Expected JSON array"):
                connector._get_paginated("https://api.github.com/test")


# ─── _parse_next_link() ─────────────────────────────────────────────


class TestParseNextLink:
    def test_parses_next_url(self) -> None:
        from mallcop.connectors.github.connector import GitHubConnector

        link = '<https://api.github.com/orgs/acme-corp/audit-log?after=abc>; rel="next", <https://api.github.com/orgs/acme-corp/audit-log?before=xyz>; rel="prev"'
        result = GitHubConnector._parse_next_link(link)
        assert result == "https://api.github.com/orgs/acme-corp/audit-log?after=abc"

    def test_returns_none_for_empty(self) -> None:
        from mallcop.connectors.github.connector import GitHubConnector

        assert GitHubConnector._parse_next_link("") is None

    def test_returns_none_when_no_next(self) -> None:
        from mallcop.connectors.github.connector import GitHubConnector

        link = '<https://api.github.com/orgs/acme-corp/audit-log?before=xyz>; rel="prev"'
        assert GitHubConnector._parse_next_link(link) is None


# ─── poll() ─────────────────────────────────────────────────────────


class TestGitHubConnectorPoll:
    def _make_connector(self) -> Any:
        from mallcop.connectors.github.connector import GitHubConnector

        connector = GitHubConnector()
        connector._token = "ghp_fake"
        connector._org = "acme-corp"
        return connector

    def test_poll_normalizes_events(self) -> None:
        fixture = _load_fixture("audit_log_page1.json")
        connector = self._make_connector()

        with patch.object(connector, "_fetch_audit_log", return_value=(fixture, None)):
            result = connector.poll(checkpoint=None)

        assert isinstance(result, PollResult)
        assert len(result.events) == 3

        evt = result.events[0]
        assert isinstance(evt, Event)
        assert evt.source == "github"
        assert evt.event_type == "collaborator_added"
        assert evt.actor == "admin-user"
        assert evt.action == "org.add_member"
        assert evt.target == "acme-corp"
        assert evt.severity == Severity.WARN

    def test_poll_sets_timestamps(self) -> None:
        fixture = _load_fixture("audit_log_page1.json")
        connector = self._make_connector()

        with patch.object(connector, "_fetch_audit_log", return_value=(fixture, None)):
            result = connector.poll(checkpoint=None)

        evt = result.events[0]
        assert isinstance(evt.timestamp, datetime)
        assert evt.timestamp.tzinfo is not None
        assert isinstance(evt.ingested_at, datetime)
        assert evt.ingested_at.tzinfo is not None

    def test_poll_returns_checkpoint_with_last_cursor(self) -> None:
        fixture = _load_fixture("audit_log_page1.json")
        connector = self._make_connector()

        # No pagination cursor — falls back to last _document_id
        with patch.object(connector, "_fetch_audit_log", return_value=(fixture, None)):
            result = connector.poll(checkpoint=None)

        assert isinstance(result.checkpoint, Checkpoint)
        assert result.checkpoint.connector == "github"
        # Last document_id in fixture
        assert result.checkpoint.value == "abc125"

    def test_poll_prefers_pagination_cursor_over_document_id(self) -> None:
        fixture = _load_fixture("audit_log_page1.json")
        connector = self._make_connector()

        # Pagination cursor present — should be preferred over _document_id
        with patch.object(connector, "_fetch_audit_log", return_value=(fixture, "pagination_cursor_xyz")):
            result = connector.poll(checkpoint=None)

        assert result.checkpoint.value == "pagination_cursor_xyz"

    def test_poll_with_checkpoint_passes_after_param(self) -> None:
        connector = self._make_connector()
        captured_params: dict = {}

        def fake_get_paginated(url: str, params: dict | None = None) -> tuple:
            if params:
                captured_params.update(params)
            return [], None

        checkpoint = Checkpoint(
            connector="github",
            value="cursor_abc",
            updated_at=datetime(2026, 3, 6, 0, 0, 0, tzinfo=timezone.utc),
        )

        with patch.object(connector, "_get_paginated", side_effect=fake_get_paginated):
            connector._fetch_audit_log(checkpoint)

        assert captured_params.get("after") == "cursor_abc"

    def test_poll_empty_returns_same_checkpoint(self) -> None:
        connector = self._make_connector()

        checkpoint = Checkpoint(
            connector="github",
            value="old_cursor",
            updated_at=datetime(2026, 3, 6, 0, 0, 0, tzinfo=timezone.utc),
        )

        with patch.object(connector, "_fetch_audit_log", return_value=([], None)):
            result = connector.poll(checkpoint=checkpoint)

        assert len(result.events) == 0
        assert result.checkpoint.value == "old_cursor"

    def test_poll_empty_no_checkpoint_returns_empty_value(self) -> None:
        connector = self._make_connector()

        with patch.object(connector, "_fetch_audit_log", return_value=([], None)):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 0
        assert result.checkpoint.value == ""

    def test_poll_preserves_raw_data(self) -> None:
        fixture = _load_fixture("audit_log_page1.json")
        connector = self._make_connector()

        with patch.object(connector, "_fetch_audit_log", return_value=(fixture, None)):
            result = connector.poll(checkpoint=None)

        for i, evt in enumerate(result.events):
            assert evt.raw == fixture[i]

    def test_poll_sets_metadata(self) -> None:
        fixture = _load_fixture("audit_log_page1.json")
        connector = self._make_connector()

        with patch.object(connector, "_fetch_audit_log", return_value=(fixture, None)):
            result = connector.poll(checkpoint=None)

        evt = result.events[0]
        assert evt.metadata["org"] == "acme-corp"
        assert evt.metadata["action_detail"] == "org.add_member"

    def test_poll_skips_entries_without_timestamp(self) -> None:
        """Entries missing both @timestamp and created_at should be skipped."""
        connector = self._make_connector()
        entries = [
            {"action": "org.add_member", "_document_id": "no_ts_1"},
            {"action": "org.add_member", "_document_id": "has_ts_1", "@timestamp": 1710000000000},
        ]
        with patch.object(connector, "_fetch_audit_log", return_value=(entries, None)):
            result = connector.poll(checkpoint=None)
        assert len(result.events) == 1
        assert result.events[0].raw["_document_id"] == "has_ts_1"


# ─── Event type mapping (all 10 types) ──────────────────────────────


class TestGitHubEventTypeMapping:
    def _make_connector(self) -> Any:
        from mallcop.connectors.github.connector import GitHubConnector

        connector = GitHubConnector()
        connector._token = "ghp_fake"
        connector._org = "acme-corp"
        return connector

    def test_all_10_event_types_mapped(self) -> None:
        fixture = _load_fixture("audit_log_all_types.json")
        connector = self._make_connector()

        with patch.object(connector, "_fetch_audit_log", return_value=(fixture, None)):
            result = connector.poll(checkpoint=None)

        types = [evt.event_type for evt in result.events]

        # Entry 0: org.add_member → collaborator_added
        assert types[0] == "collaborator_added"
        # Entry 1: org.remove_member → collaborator_removed
        assert types[1] == "collaborator_removed"
        # Entry 2: repo.access → repo_visibility_changed
        assert types[2] == "repo_visibility_changed"
        # Entry 3: protected_branch.create → branch_protection_changed
        assert types[3] == "branch_protection_changed"
        # Entry 4: deploy_key.create → deploy_key_added
        assert types[4] == "deploy_key_added"
        # Entry 5: oauth_authorization.create → oauth_app_authorized
        assert types[5] == "oauth_app_authorized"
        # Entry 6: secret_scanning_alert.create → secret_scanning_alert
        assert types[6] == "secret_scanning_alert"
        # Entry 7: dependabot_alert.create → dependabot_alert
        assert types[7] == "dependabot_alert"
        # Entry 8: git.push → push
        assert types[8] == "push"
        # Entry 9: team.add_member → permission_change
        assert types[9] == "permission_change"
        # Entry 10: repo.add_member → collaborator_added (second pattern)
        assert types[10] == "collaborator_added"
        # Entry 11: org.update_member → permission_change
        assert types[11] == "permission_change"

    def test_collaborator_added_severity_warn(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("org.add_member")
        assert et == "collaborator_added"
        assert _map_severity(et) == Severity.WARN

    def test_collaborator_removed_severity_info(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("org.remove_member")
        assert et == "collaborator_removed"
        assert _map_severity(et) == Severity.INFO

    def test_repo_visibility_changed_severity_critical(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("repo.access")
        assert et == "repo_visibility_changed"
        assert _map_severity(et) == Severity.CRITICAL

    def test_branch_protection_changed_severity_warn(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("protected_branch.update_allow_force_pushes_enforcement_level")
        assert et == "branch_protection_changed"
        assert _map_severity(et) == Severity.WARN

    def test_deploy_key_added_severity_warn(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("deploy_key.create")
        assert et == "deploy_key_added"
        assert _map_severity(et) == Severity.WARN

    def test_oauth_app_authorized_severity_warn(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("oauth_authorization.create")
        assert et == "oauth_app_authorized"
        assert _map_severity(et) == Severity.WARN

    def test_secret_scanning_alert_severity_critical(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("secret_scanning_alert.create")
        assert et == "secret_scanning_alert"
        assert _map_severity(et) == Severity.CRITICAL

    def test_dependabot_alert_severity_warn(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("dependabot_alert.create")
        assert et == "dependabot_alert"
        assert _map_severity(et) == Severity.WARN

    def test_push_severity_info(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("git.push")
        assert et == "push"
        assert _map_severity(et) == Severity.INFO

    def test_permission_change_team_severity_warn(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("team.add_member")
        assert et == "permission_change"
        assert _map_severity(et) == Severity.WARN

    def test_permission_change_org_update_severity_warn(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("org.update_member")
        assert et == "permission_change"
        assert _map_severity(et) == Severity.WARN

    def test_unknown_action_returns_github_other(self) -> None:
        from mallcop.connectors.github.connector import _classify_action, _map_severity

        et = _classify_action("some.unknown.action")
        assert et == "github_other"
        assert _map_severity(et) == Severity.INFO


# ─── event_types() ──────────────────────────────────────────────────


class TestGitHubConnectorEventTypes:
    def test_event_types_returns_all_10(self) -> None:
        from mallcop.connectors.github.connector import GitHubConnector

        connector = GitHubConnector()
        types = connector.event_types()
        assert len(types) == 10
        assert "collaborator_added" in types
        assert "repo_visibility_changed" in types
        assert "secret_scanning_alert" in types
        assert "push" in types
        assert "permission_change" in types


# ─── manifest ───────────────────────────────────────────────────────


class TestGitHubManifest:
    def test_manifest_loads_and_validates(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest

        github_dir = Path(__file__).parent.parent.parent / "src" / "mallcop" / "connectors" / "github"
        manifest = load_connector_manifest(github_dir)

        assert manifest.name == "github"
        assert manifest.version == "0.1.0"
        assert "collaborator_added" in manifest.event_types
        assert "secret_scanning_alert" in manifest.event_types
        assert "token" in manifest.auth["required"]

    def test_event_types_match_connector(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest
        from mallcop.connectors.github.connector import GitHubConnector

        github_dir = Path(__file__).parent.parent.parent / "src" / "mallcop" / "connectors" / "github"
        manifest = load_connector_manifest(github_dir)
        connector = GitHubConnector()

        assert set(connector.event_types()) == set(manifest.event_types)


# ─── Integration: poll → store round-trip ────────────────────────────


class TestGitHubPollStoreRoundTrip:
    def test_poll_events_serialize_and_deserialize(self) -> None:
        from mallcop.connectors.github.connector import GitHubConnector

        fixture = _load_fixture("audit_log_page1.json")

        connector = GitHubConnector()
        connector._token = "ghp_fake"
        connector._org = "acme-corp"

        with patch.object(connector, "_fetch_audit_log", return_value=(fixture, None)):
            result = connector.poll(checkpoint=None)

        for evt in result.events:
            serialized = evt.to_json()
            deserialized = Event.from_json(serialized)
            assert deserialized.id == evt.id
            assert deserialized.source == "github"
            assert deserialized.event_type == evt.event_type
            assert deserialized.actor == evt.actor
            assert deserialized.severity == evt.severity

    def test_checkpoint_serialize_and_deserialize(self) -> None:
        from mallcop.connectors.github.connector import GitHubConnector

        fixture = _load_fixture("audit_log_page1.json")

        connector = GitHubConnector()
        connector._token = "ghp_fake"
        connector._org = "acme-corp"

        with patch.object(connector, "_fetch_audit_log", return_value=(fixture, None)):
            result = connector.poll(checkpoint=None)

        serialized = result.checkpoint.to_json()
        deserialized = Checkpoint.from_json(serialized)
        assert deserialized.connector == "github"
        assert deserialized.value == result.checkpoint.value


# ─── Error path tests ────────────────────────────────────────────────


class TestGitHubConnectorErrorPaths:
    def _make_connector(self) -> Any:
        from mallcop.connectors.github.connector import GitHubConnector

        connector = GitHubConnector()
        connector._token = "ghp_fake"
        connector._org = "acme-corp"
        return connector

    def test_validate_token_401_raises_config_error(self) -> None:
        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 401
        fake_resp.text = "Bad credentials"

        with patch("mallcop.connectors.github.connector.requests.get", return_value=fake_resp):
            with pytest.raises(ConfigError, match="401"):
                connector._validate_token()

    def test_validate_token_403_raises_config_error(self) -> None:
        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = "Forbidden: rate limit exceeded"

        with patch("mallcop.connectors.github.connector.requests.get", return_value=fake_resp):
            with pytest.raises(ConfigError, match="403"):
                connector._validate_token()

    def test_get_paginated_429_throttled_raises_http_error(self) -> None:
        from requests.exceptions import HTTPError

        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status.side_effect = HTTPError("429 Too Many Requests")

        with patch("requests.get", return_value=fake_resp):
            with pytest.raises(HTTPError, match="429"):
                connector._get_paginated("https://api.github.com/test")

    def test_get_paginated_500_server_error_raises_http_error(self) -> None:
        from requests.exceptions import HTTPError

        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status.side_effect = HTTPError("500 Internal Server Error")

        with patch("requests.get", return_value=fake_resp):
            with pytest.raises(HTTPError, match="500"):
                connector._get_paginated("https://api.github.com/test")

    def test_get_paginated_network_timeout_raises(self) -> None:
        from requests.exceptions import ConnectionError as ReqConnectionError

        connector = self._make_connector()

        with patch("requests.get", side_effect=ReqConnectionError("Connection timed out")):
            with pytest.raises(ReqConnectionError):
                connector._get_paginated("https://api.github.com/test")

    def test_get_paginated_dict_without_known_key_wraps_as_result(self) -> None:
        connector = self._make_connector()

        fake_resp = MagicMock()
        fake_resp.raise_for_status = MagicMock()
        fake_resp.json.return_value = {"not_a_list": True}
        fake_resp.headers = {}

        with patch("requests.get", return_value=fake_resp):
            results, cursor = connector._get_paginated("https://api.github.com/test")
        assert results == [{"not_a_list": True}]
        assert cursor is None


class TestPaginationMultiPage:
    def _make_connector(self) -> Any:
        from mallcop.connectors.github.connector import GitHubConnector

        connector = GitHubConnector()
        connector._token = "ghp_fake"
        connector._org = "acme-corp"
        return connector

    def test_paginated_follows_link_header(self) -> None:
        """Multi-page: first response has Link next, second has none."""
        connector = self._make_connector()

        page1 = MagicMock()
        page1.raise_for_status = MagicMock()
        page1.json.return_value = [{"id": 1}, {"id": 2}]
        page1.headers = {
            "Link": '<https://api.github.com/test?page=2&after=cursor1>; rel="next"'
        }

        page2 = MagicMock()
        page2.raise_for_status = MagicMock()
        page2.json.return_value = [{"id": 3}]
        page2.headers = {}

        with patch("requests.get", side_effect=[page1, page2]):
            results, cursor = connector._get_paginated("https://api.github.com/test")

        assert len(results) == 3
        assert results[0]["id"] == 1
        assert results[2]["id"] == 3
        assert cursor == "cursor1"

    def test_paginated_dict_with_value_key(self) -> None:
        """Response is {"value": [...]} dict, not a list."""
        connector = self._make_connector()

        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"value": [{"id": 10}, {"id": 11}]}
        resp.headers = {}

        with patch("requests.get", return_value=resp):
            results, cursor = connector._get_paginated("https://api.github.com/test")

        assert len(results) == 2
        assert results[0]["id"] == 10
        assert cursor is None


class TestFetchAuditLogParams:
    def _make_connector(self) -> Any:
        from mallcop.connectors.github.connector import GitHubConnector

        connector = GitHubConnector()
        connector._token = "ghp_fake"
        connector._org = "acme-corp"
        return connector

    def test_sends_after_param_with_checkpoint(self) -> None:
        connector = self._make_connector()
        cp = Checkpoint(connector="github", value="cursor_abc", updated_at=datetime.now(timezone.utc))

        with patch.object(connector, "_get_paginated", return_value=([], None)) as mock_pg:
            connector._fetch_audit_log(cp)

        _, kwargs = mock_pg.call_args
        assert kwargs["params"]["after"] == "cursor_abc"

    def test_no_after_when_empty_checkpoint(self) -> None:
        connector = self._make_connector()
        cp = Checkpoint(connector="github", value="", updated_at=datetime.now(timezone.utc))

        with patch.object(connector, "_get_paginated", return_value=([], None)) as mock_pg:
            connector._fetch_audit_log(cp)

        _, kwargs = mock_pg.call_args
        assert "after" not in kwargs["params"]

    def test_no_after_when_no_checkpoint(self) -> None:
        connector = self._make_connector()

        with patch.object(connector, "_get_paginated", return_value=([], None)) as mock_pg:
            connector._fetch_audit_log(None)

        _, kwargs = mock_pg.call_args
        assert "after" not in kwargs["params"]


# ---------------------------------------------------------------------------
# Checkpoint cursor validation (ak1n.1.16)
# ---------------------------------------------------------------------------


class TestGitHubCheckpointCursorValidation:
    """Checkpoint cursor must be validated before use as GitHub API parameter.

    The checkpoint is read from a plain YAML file that could be tampered with.
    An invalid cursor must be rejected to prevent checkpoint injection attacks
    that could skip events (blind spots) or manipulate pagination.
    """

    def _make_connector(self):
        from mallcop.connectors.github.connector import GitHubConnector
        from unittest.mock import patch

        connector = GitHubConnector()
        with patch.object(connector, "_validate_token"):
            connector.configure({
                "org": "test-org",
                "token": "ghp_test",
                "credentials_path": "",
            })
        return connector

    def test_valid_cursor_accepted(self) -> None:
        """A well-formed GitHub cursor is accepted and passed to the API."""
        from unittest.mock import patch
        from mallcop.schemas import Checkpoint
        from datetime import datetime, timezone

        connector = self._make_connector()
        # GitHub audit log cursors are base64-like alphanumeric strings
        valid_cursor = "MS42NjAzNzE0NDE4MzM1OTg2NCtleUpoWkdRaU9pSWlmUT09"
        cp = Checkpoint(connector="github", value=valid_cursor,
                        updated_at=datetime.now(timezone.utc))

        with patch.object(connector, "_get_paginated", return_value=([], None)) as mock_pg:
            connector._fetch_audit_log(cp)

        _, kwargs = mock_pg.call_args
        assert kwargs["params"]["after"] == valid_cursor

    def test_cursor_with_newlines_rejected(self) -> None:
        """Cursor containing newlines (header injection attempt) is rejected."""
        from unittest.mock import patch
        from mallcop.schemas import Checkpoint
        from datetime import datetime, timezone

        connector = self._make_connector()
        injected_cursor = "validcursor\nX-Injected: evil"
        cp = Checkpoint(connector="github", value=injected_cursor,
                        updated_at=datetime.now(timezone.utc))

        with patch.object(connector, "_get_paginated", return_value=([], None)) as mock_pg:
            with pytest.raises(ValueError, match="[Ii]nvalid.*cursor"):
                connector._fetch_audit_log(cp)

    def test_cursor_with_null_bytes_rejected(self) -> None:
        """Cursor containing null bytes is rejected."""
        from unittest.mock import patch
        from mallcop.schemas import Checkpoint
        from datetime import datetime, timezone

        connector = self._make_connector()
        bad_cursor = "cursor\x00evil"
        cp = Checkpoint(connector="github", value=bad_cursor,
                        updated_at=datetime.now(timezone.utc))

        with patch.object(connector, "_get_paginated", return_value=([], None)) as mock_pg:
            with pytest.raises(ValueError, match="[Ii]nvalid.*cursor"):
                connector._fetch_audit_log(cp)

    def test_excessively_long_cursor_rejected(self) -> None:
        """A cursor longer than the expected maximum is rejected."""
        from unittest.mock import patch
        from mallcop.schemas import Checkpoint
        from datetime import datetime, timezone

        connector = self._make_connector()
        long_cursor = "A" * 10001
        cp = Checkpoint(connector="github", value=long_cursor,
                        updated_at=datetime.now(timezone.utc))

        with patch.object(connector, "_get_paginated", return_value=([], None)) as mock_pg:
            with pytest.raises(ValueError, match="[Ii]nvalid.*cursor"):
                connector._fetch_audit_log(cp)
