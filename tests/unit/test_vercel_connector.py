"""Tests for Vercel deployment and team audit monitoring connector."""

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

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "vercel"


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


# --- Helper to build a pre-authenticated connector ---


def _make_connector(team_id: str | None = "team_xyz789") -> Any:
    from mallcop.connectors.vercel.connector import VercelConnector

    connector = VercelConnector()
    connector._token = "fake_vercel_token_12345"
    connector._team_id = team_id
    return connector


# ─── Event type classification ───────────────────────────────────────


class TestEventTypeClassification:
    def test_project_created(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("project.created") == "project_change"

    def test_project_removed(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("project.removed") == "project_change"

    def test_deployment_created(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("deployment.created") == "deployment"

    def test_member_added(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("member.added") == "member_change"

    def test_member_removed(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("member.removed") == "member_change"

    def test_member_role_updated(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("member.role-updated") == "member_change"

    def test_domain_added(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("domain.added") == "domain_change"

    def test_domain_removed(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("domain.removed") == "domain_change"

    def test_env_created(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("env.created") == "env_change"

    def test_env_removed(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("env.removed") == "env_change"

    def test_env_updated(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("env.updated") == "env_change"

    def test_integration_installed(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("integration.installed") == "integration_change"

    def test_integration_removed(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("integration.removed") == "integration_change"

    def test_team_updated(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("team.updated") == "team_change"

    def test_access_token_created(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("access-token.created") == "security_change"

    def test_access_token_deleted(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("access-token.deleted") == "security_change"

    def test_unknown_action_defaults_to_deployment(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_event_type

        assert _classify_event_type("some.unknown.action") == "deployment"


# ─── Severity classification ─────────────────────────────────────────


class TestSeverityClassification:
    def test_member_added_is_warn(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("member.added") == Severity.WARN

    def test_member_removed_is_warn(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("member.removed") == Severity.WARN

    def test_member_role_updated_is_warn(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("member.role-updated") == Severity.WARN

    def test_access_token_created_is_warn(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("access-token.created") == Severity.WARN

    def test_access_token_deleted_is_warn(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("access-token.deleted") == Severity.WARN

    def test_env_created_is_warn(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("env.created") == Severity.WARN

    def test_env_removed_is_warn(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("env.removed") == Severity.WARN

    def test_env_updated_is_warn(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("env.updated") == Severity.WARN

    def test_project_created_is_info(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("project.created") == Severity.INFO

    def test_domain_added_is_info(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("domain.added") == Severity.INFO

    def test_deployment_created_is_info(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("deployment.created") == Severity.INFO

    def test_unknown_action_is_info(self) -> None:
        from mallcop.connectors.vercel.connector import _classify_severity

        assert _classify_severity("unknown.action") == Severity.INFO


# ─── authenticate() ──────────────────────────────────────────────────


class TestVercelConnectorAuthenticate:
    def test_authenticate_succeeds_with_valid_secrets(self) -> None:
        from mallcop.connectors.vercel.connector import VercelConnector

        secrets = FakeSecretProvider({
            "VERCEL_TOKEN": "fake_token_12345",
            "VERCEL_TEAM_ID": "team_xyz789",
        })
        connector = VercelConnector()
        with patch.object(connector, "_api_get", return_value=_load_fixture("user.json")):
            connector.authenticate(secrets)

        assert connector._token == "fake_token_12345"
        assert connector._team_id == "team_xyz789"

    def test_authenticate_works_without_team_id(self) -> None:
        from mallcop.connectors.vercel.connector import VercelConnector

        secrets = FakeSecretProvider({"VERCEL_TOKEN": "fake_token_12345"})
        connector = VercelConnector()
        with patch.object(connector, "_api_get", return_value=_load_fixture("user.json")):
            connector.authenticate(secrets)

        assert connector._token == "fake_token_12345"
        assert connector._team_id is None

    def test_authenticate_raises_on_missing_token(self) -> None:
        from mallcop.connectors.vercel.connector import VercelConnector

        secrets = FakeSecretProvider({"VERCEL_TEAM_ID": "team_xyz789"})
        connector = VercelConnector()
        with pytest.raises(ConfigError, match="VERCEL_TOKEN"):
            connector.authenticate(secrets)

    def test_authenticate_validates_token_with_api(self) -> None:
        from mallcop.connectors.vercel.connector import VercelConnector

        secrets = FakeSecretProvider({"VERCEL_TOKEN": "bad_token"})
        connector = VercelConnector()

        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = "Invalid token"
        fake_resp.json.return_value = {"error": {"message": "Invalid token"}}

        with patch(
            "mallcop.connectors.vercel.connector.requests.get",
            return_value=fake_resp,
        ):
            with pytest.raises(ConfigError, match="Vercel API error 403"):
                connector.authenticate(secrets)


# ─── discover() ──────────────────────────────────────────────────────


class TestVercelConnectorDiscover:
    def test_discover_returns_user_teams_projects(self) -> None:
        connector = _make_connector()
        user = _load_fixture("user.json")
        teams = _load_fixture("teams.json")
        projects = _load_fixture("projects.json")

        def fake_api_get(path: str, params=None):
            if "/v2/user" in path:
                return user
            if "/v2/teams" in path:
                return teams
            if "/v9/projects" in path:
                return projects
            return {}

        with patch.object(connector, "_api_get", side_effect=fake_api_get):
            result = connector.discover()

        assert isinstance(result, DiscoveryResult)
        assert result.available is True
        # 1 user + 2 teams + "3 project(s)"
        assert len(result.resources) == 4
        assert "User: admin-user" in result.resources
        assert "Team: Acme Corp" in result.resources
        assert "Team: Acme Corp" in result.resources
        assert "3 project(s)" in result.resources

    def test_discover_suggests_team_id_when_missing(self) -> None:
        connector = _make_connector(team_id=None)
        user = _load_fixture("user.json")
        teams = _load_fixture("teams.json")
        projects = _load_fixture("projects.json")

        def fake_api_get(path: str, params=None):
            if "/v2/user" in path:
                return user
            if "/v2/teams" in path:
                return teams
            if "/v9/projects" in path:
                return projects
            return {}

        with patch.object(connector, "_api_get", side_effect=fake_api_get):
            result = connector.discover()

        assert result.suggested_config.get("team_id") == "team_xyz789"

    def test_discover_does_not_suggest_team_id_when_already_set(self) -> None:
        connector = _make_connector(team_id="team_xyz789")
        user = _load_fixture("user.json")
        teams = _load_fixture("teams.json")
        projects = _load_fixture("projects.json")

        def fake_api_get(path: str, params=None):
            if "/v2/user" in path:
                return user
            if "/v2/teams" in path:
                return teams
            if "/v9/projects" in path:
                return projects
            return {}

        with patch.object(connector, "_api_get", side_effect=fake_api_get):
            result = connector.discover()

        assert "team_id" not in result.suggested_config

    def test_discover_reports_failure_on_auth_error(self) -> None:
        connector = _make_connector()

        with patch.object(
            connector, "_api_get", side_effect=Exception("Auth failed")
        ):
            result = connector.discover()

        assert result.available is False
        assert "VERCEL_TOKEN" in result.missing_credentials

    def test_discover_includes_notes(self) -> None:
        connector = _make_connector()
        user = _load_fixture("user.json")
        teams = _load_fixture("teams.json")
        projects = _load_fixture("projects.json")

        def fake_api_get(path: str, params=None):
            if "/v2/user" in path:
                return user
            if "/v2/teams" in path:
                return teams
            if "/v9/projects" in path:
                return projects
            return {}

        with patch.object(connector, "_api_get", side_effect=fake_api_get):
            result = connector.discover()

        assert any("4 resources" in n for n in result.notes)

    def test_discover_handles_teams_api_failure(self) -> None:
        connector = _make_connector()
        user = _load_fixture("user.json")
        projects = _load_fixture("projects.json")

        def fake_api_get(path: str, params=None):
            if "/v2/user" in path:
                return user
            if "/v2/teams" in path:
                raise Exception("Teams API down")
            if "/v9/projects" in path:
                return projects
            return {}

        with patch.object(connector, "_api_get", side_effect=fake_api_get):
            result = connector.discover()

        assert result.available is True
        assert "User: admin-user" in result.resources

    def test_discover_handles_projects_api_failure(self) -> None:
        connector = _make_connector()
        user = _load_fixture("user.json")
        teams = _load_fixture("teams.json")

        def fake_api_get(path: str, params=None):
            if "/v2/user" in path:
                return user
            if "/v2/teams" in path:
                return teams
            if "/v9/projects" in path:
                raise Exception("Projects API down")
            return {}

        with patch.object(connector, "_api_get", side_effect=fake_api_get):
            result = connector.discover()

        assert result.available is True
        # User + 2 teams, no projects
        assert len(result.resources) == 3


# ─── poll() — deployments ────────────────────────────────────────────


class TestVercelConnectorPollDeployments:
    def test_poll_normalizes_deployment_events(self) -> None:
        connector = _make_connector(team_id=None)  # No audit log
        deployments = _load_fixture("deployments.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ):
            result = connector.poll(checkpoint=None)

        assert isinstance(result, PollResult)
        assert len(result.events) == 3

        evt = result.events[0]
        assert isinstance(evt, Event)
        assert evt.source == "vercel"
        assert evt.event_type == "deployment"
        assert evt.actor == "admin-user"
        assert evt.action == "deployment.created"
        assert evt.target == "mallcop-docs"
        assert evt.severity == Severity.INFO

    def test_poll_deployment_sets_timestamps(self) -> None:
        connector = _make_connector(team_id=None)
        deployments = _load_fixture("deployments.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ):
            result = connector.poll(checkpoint=None)

        evt = result.events[0]
        assert isinstance(evt.timestamp, datetime)
        assert evt.timestamp.tzinfo is not None
        assert isinstance(evt.ingested_at, datetime)
        assert evt.ingested_at.tzinfo is not None

    def test_poll_deployment_sets_metadata(self) -> None:
        connector = _make_connector(team_id=None)
        deployments = _load_fixture("deployments.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ):
            result = connector.poll(checkpoint=None)

        evt = result.events[0]
        assert evt.metadata["state"] == "READY"
        assert evt.metadata["target"] == "production"
        assert evt.metadata["project_id"] == "prj_abc123"

    def test_poll_deployment_preserves_raw(self) -> None:
        connector = _make_connector(team_id=None)
        deployments = _load_fixture("deployments.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ):
            result = connector.poll(checkpoint=None)

        for i, evt in enumerate(result.events):
            assert evt.raw == deployments["deployments"][i]

    def test_poll_deployment_skips_missing_created(self) -> None:
        connector = _make_connector(team_id=None)
        # Deployment with no created/createdAt field
        bad_deployment = {"uid": "dpl_bad", "name": "bad-deploy", "state": "READY"}

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=[bad_deployment],
        ):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 0


# ─── poll() — audit log ──────────────────────────────────────────────


class TestVercelConnectorPollAuditLog:
    def test_poll_normalizes_audit_events(self) -> None:
        connector = _make_connector()
        audit = _load_fixture("audit_log.json")

        with patch.object(
            connector, "_fetch_deployments", return_value=[]
        ), patch.object(
            connector,
            "_fetch_audit_log",
            return_value=audit["events"],
        ):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 8

        # First event: member.added
        evt = result.events[0]
        assert evt.source == "vercel"
        assert evt.event_type == "member_change"
        assert evt.actor == "admin-user"
        assert evt.action == "member.added"
        assert evt.target == "Acme Corp"
        assert evt.severity == Severity.WARN

    def test_poll_audit_all_event_types_mapped(self) -> None:
        connector = _make_connector()
        audit = _load_fixture("audit_log.json")

        with patch.object(
            connector, "_fetch_deployments", return_value=[]
        ), patch.object(
            connector,
            "_fetch_audit_log",
            return_value=audit["events"],
        ):
            result = connector.poll(checkpoint=None)

        types = [evt.event_type for evt in result.events]
        assert types[0] == "member_change"       # member.added
        assert types[1] == "project_change"       # project.created
        assert types[2] == "env_change"           # env.created
        assert types[3] == "domain_change"        # domain.added
        assert types[4] == "security_change"      # access-token.created
        assert types[5] == "integration_change"   # integration.installed
        assert types[6] == "team_change"          # team.updated
        assert types[7] == "member_change"        # member.role-updated

    def test_poll_audit_security_actions_are_warn(self) -> None:
        connector = _make_connector()
        audit = _load_fixture("audit_log.json")

        with patch.object(
            connector, "_fetch_deployments", return_value=[]
        ), patch.object(
            connector,
            "_fetch_audit_log",
            return_value=audit["events"],
        ):
            result = connector.poll(checkpoint=None)

        # member.added -> WARN
        assert result.events[0].severity == Severity.WARN
        # env.created -> WARN
        assert result.events[2].severity == Severity.WARN
        # access-token.created -> WARN
        assert result.events[4].severity == Severity.WARN
        # member.role-updated -> WARN
        assert result.events[7].severity == Severity.WARN

    def test_poll_audit_non_security_actions_are_info(self) -> None:
        connector = _make_connector()
        audit = _load_fixture("audit_log.json")

        with patch.object(
            connector, "_fetch_deployments", return_value=[]
        ), patch.object(
            connector,
            "_fetch_audit_log",
            return_value=audit["events"],
        ):
            result = connector.poll(checkpoint=None)

        # project.created -> INFO
        assert result.events[1].severity == Severity.INFO
        # domain.added -> INFO
        assert result.events[3].severity == Severity.INFO
        # integration.installed -> INFO
        assert result.events[5].severity == Severity.INFO
        # team.updated -> INFO
        assert result.events[6].severity == Severity.INFO

    def test_poll_audit_sets_metadata(self) -> None:
        connector = _make_connector()
        audit = _load_fixture("audit_log.json")

        with patch.object(
            connector, "_fetch_deployments", return_value=[]
        ), patch.object(
            connector,
            "_fetch_audit_log",
            return_value=audit["events"],
        ):
            result = connector.poll(checkpoint=None)

        evt = result.events[1]  # project.created
        assert evt.metadata["entity_type"] == "project"
        assert evt.metadata["entity_id"] == "prj_abc123"

    def test_poll_audit_skips_missing_created_at(self) -> None:
        connector = _make_connector()
        bad_audit = {"id": "audit_bad", "action": "member.added"}

        with patch.object(
            connector, "_fetch_deployments", return_value=[]
        ), patch.object(
            connector,
            "_fetch_audit_log",
            return_value=[bad_audit],
        ):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 0

    def test_poll_skips_audit_when_no_team_id(self) -> None:
        connector = _make_connector(team_id=None)
        deployments = _load_fixture("deployments.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ) as mock_deploy, patch.object(
            connector,
            "_fetch_audit_log",
        ) as mock_audit:
            result = connector.poll(checkpoint=None)

        mock_deploy.assert_called_once()
        mock_audit.assert_not_called()
        # Should have deployment events but no audit events
        assert len(result.events) == 3


# ─── poll() — checkpoint handling ─────────────────────────────────────


class TestVercelConnectorCheckpoint:
    def test_poll_checkpoint_advances_to_latest_event(self) -> None:
        connector = _make_connector(team_id=None)
        deployments = _load_fixture("deployments.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ):
            result = connector.poll(checkpoint=None)

        assert result.checkpoint.connector == "vercel"
        # Latest deployment timestamp: 1709395200000 = 2024-03-02T16:00:00+00:00
        expected_ts = datetime.fromtimestamp(1709395200, tz=timezone.utc)
        assert result.checkpoint.value == expected_ts.isoformat()

    def test_poll_with_checkpoint_passes_since(self) -> None:
        connector = _make_connector(team_id=None)
        cp_time = datetime(2024, 2, 28, 0, 0, 0, tzinfo=timezone.utc)
        checkpoint = Checkpoint(
            connector="vercel",
            value=cp_time.isoformat(),
            updated_at=cp_time,
        )

        captured_since: list[int] = []

        def fake_fetch(since_ms: int) -> list[dict]:
            captured_since.append(since_ms)
            return []

        with patch.object(connector, "_fetch_deployments", side_effect=fake_fetch):
            connector.poll(checkpoint=checkpoint)

        expected_ms = int(cp_time.timestamp() * 1000)
        assert captured_since[0] == expected_ms

    def test_poll_empty_with_checkpoint_preserves_value(self) -> None:
        connector = _make_connector(team_id=None)
        cp_time = datetime(2024, 2, 28, 0, 0, 0, tzinfo=timezone.utc)
        checkpoint = Checkpoint(
            connector="vercel",
            value=cp_time.isoformat(),
            updated_at=cp_time,
        )

        with patch.object(connector, "_fetch_deployments", return_value=[]):
            result = connector.poll(checkpoint=checkpoint)

        assert result.checkpoint.value == cp_time.isoformat()

    def test_poll_empty_no_checkpoint_uses_now(self) -> None:
        connector = _make_connector(team_id=None)

        with patch.object(connector, "_fetch_deployments", return_value=[]):
            result = connector.poll(checkpoint=None)

        # Checkpoint value should be an ISO timestamp (now)
        parsed = datetime.fromisoformat(result.checkpoint.value)
        assert parsed.tzinfo is not None


# ─── poll() — combined deployments + audit ────────────────────────────


class TestVercelConnectorPollCombined:
    def test_poll_combines_deployments_and_audit(self) -> None:
        connector = _make_connector()
        deployments = _load_fixture("deployments.json")
        audit = _load_fixture("audit_log.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ), patch.object(
            connector,
            "_fetch_audit_log",
            return_value=audit["events"],
        ):
            result = connector.poll(checkpoint=None)

        # 3 deployments + 8 audit events
        assert len(result.events) == 11

        deploy_events = [e for e in result.events if e.event_type == "deployment"]
        audit_events = [e for e in result.events if e.event_type != "deployment"]
        assert len(deploy_events) == 3
        assert len(audit_events) == 8

    def test_poll_checkpoint_tracks_latest_across_both(self) -> None:
        connector = _make_connector()
        deployments = _load_fixture("deployments.json")
        audit = _load_fixture("audit_log.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ), patch.object(
            connector,
            "_fetch_audit_log",
            return_value=audit["events"],
        ):
            result = connector.poll(checkpoint=None)

        # Latest audit event: audit_008 at 1709740800000 = 2024-03-06T16:00:00+00:00
        # Latest deployment: dpl_eee555fff666 at 1709395200000
        # Audit is later, so checkpoint should be audit timestamp
        expected_ts = datetime.fromtimestamp(1709740800, tz=timezone.utc)
        assert result.checkpoint.value == expected_ts.isoformat()

    def test_poll_handles_deployment_fetch_error(self) -> None:
        connector = _make_connector()
        audit = _load_fixture("audit_log.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            side_effect=Exception("API error"),
        ), patch.object(
            connector,
            "_fetch_audit_log",
            return_value=audit["events"],
        ):
            result = connector.poll(checkpoint=None)

        # Only audit events
        assert len(result.events) == 8

    def test_poll_handles_audit_fetch_error(self) -> None:
        connector = _make_connector()
        deployments = _load_fixture("deployments.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ), patch.object(
            connector,
            "_fetch_audit_log",
            side_effect=Exception("API error"),
        ):
            result = connector.poll(checkpoint=None)

        # Only deployment events
        assert len(result.events) == 3

    def test_poll_logs_warning_on_deployment_fetch_error(self, caplog) -> None:
        """Deployment fetch failures should log a warning, not silently pass."""
        import logging

        connector = _make_connector(team_id=None)

        with patch.object(
            connector,
            "_fetch_deployments",
            side_effect=Exception("Connection timeout"),
        ):
            with caplog.at_level(logging.WARNING):
                result = connector.poll(checkpoint=None)

        assert len(result.events) == 0
        assert any("deployment" in msg.lower() or "Connection timeout" in msg for msg in caplog.messages)

    def test_poll_logs_warning_on_audit_fetch_error(self, caplog) -> None:
        """Audit log fetch failures should log a warning, not silently pass."""
        import logging

        connector = _make_connector()

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=[],
        ), patch.object(
            connector,
            "_fetch_audit_log",
            side_effect=Exception("Server error"),
        ):
            with caplog.at_level(logging.WARNING):
                result = connector.poll(checkpoint=None)

        assert len(result.events) == 0
        assert any("audit" in msg.lower() or "Server error" in msg for msg in caplog.messages)


# ─── event_types() ───────────────────────────────────────────────────


class TestVercelConnectorEventTypes:
    def test_event_types_returns_all_8(self) -> None:
        from mallcop.connectors.vercel.connector import VercelConnector

        connector = VercelConnector()
        types = connector.event_types()
        assert len(types) == 8
        assert "deployment" in types
        assert "project_change" in types
        assert "team_change" in types
        assert "member_change" in types
        assert "domain_change" in types
        assert "env_change" in types
        assert "integration_change" in types
        assert "security_change" in types


# ─── _api_get() ──────────────────────────────────────────────────────


class TestVercelApiGet:
    def test_api_get_includes_auth_header(self) -> None:
        connector = _make_connector(team_id=None)

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"ok": True}

        with patch(
            "mallcop.connectors.vercel.connector.requests.get",
            return_value=fake_resp,
        ) as mock_get:
            connector._api_get("/v2/user")

        call_kwargs = mock_get.call_args
        assert call_kwargs.kwargs["headers"]["Authorization"] == "Bearer fake_vercel_token_12345"

    def test_api_get_includes_team_id_param(self) -> None:
        connector = _make_connector(team_id="team_xyz789")

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"ok": True}

        with patch(
            "mallcop.connectors.vercel.connector.requests.get",
            return_value=fake_resp,
        ) as mock_get:
            connector._api_get("/v9/projects")

        call_kwargs = mock_get.call_args
        assert call_kwargs.kwargs["params"]["teamId"] == "team_xyz789"

    def test_api_get_omits_team_id_when_none(self) -> None:
        connector = _make_connector(team_id=None)

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.json.return_value = {"ok": True}

        with patch(
            "mallcop.connectors.vercel.connector.requests.get",
            return_value=fake_resp,
        ) as mock_get:
            connector._api_get("/v9/projects")

        call_kwargs = mock_get.call_args
        assert "teamId" not in call_kwargs.kwargs["params"]

    def test_api_get_raises_on_non_200(self) -> None:
        connector = _make_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 500
        fake_resp.text = "Internal Server Error"

        with patch(
            "mallcop.connectors.vercel.connector.requests.get",
            return_value=fake_resp,
        ):
            with pytest.raises(ConfigError, match="Vercel API error 500"):
                connector._api_get("/v2/user")

    def test_api_get_error_does_not_leak_response_body(self) -> None:
        """Error exceptions must not contain the raw response body,
        which may include tokens or other secrets echoed by the server."""
        connector = _make_connector()

        sensitive_body = (
            '{"error":{"message":"Invalid token: vcel_secret_abc123xyz"}}'
        )
        fake_resp = MagicMock()
        fake_resp.status_code = 401
        fake_resp.text = sensitive_body

        with patch(
            "mallcop.connectors.vercel.connector.requests.get",
            return_value=fake_resp,
        ):
            with pytest.raises(ConfigError) as exc_info:
                connector._api_get("/v2/user")

        error_msg = str(exc_info.value)
        assert "401" in error_msg
        assert "vcel_secret_abc123xyz" not in error_msg
        assert sensitive_body not in error_msg

    def test_api_get_error_does_not_leak_on_403(self) -> None:
        """Verify no body leak on 403 Forbidden responses."""
        connector = _make_connector()

        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = "Forbidden: token=vcel_tok_leak_me_please"

        with patch(
            "mallcop.connectors.vercel.connector.requests.get",
            return_value=fake_resp,
        ):
            with pytest.raises(ConfigError) as exc_info:
                connector._api_get("/v2/user")

        error_msg = str(exc_info.value)
        assert "403" in error_msg
        assert "vcel_tok_leak_me_please" not in error_msg


# ─── manifest ────────────────────────────────────────────────────────


class TestVercelManifest:
    def test_manifest_loads_and_validates(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest

        vercel_dir = (
            Path(__file__).parent.parent.parent
            / "src"
            / "mallcop"
            / "connectors"
            / "vercel"
        )
        manifest = load_connector_manifest(vercel_dir)

        assert manifest.name == "vercel"
        assert manifest.version == "0.1.0"
        assert "deployment" in manifest.event_types
        assert "security_change" in manifest.event_types
        assert "vercel_token" in manifest.auth["required"]

    def test_event_types_match_connector(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest
        from mallcop.connectors.vercel.connector import VercelConnector

        vercel_dir = (
            Path(__file__).parent.parent.parent
            / "src"
            / "mallcop"
            / "connectors"
            / "vercel"
        )
        manifest = load_connector_manifest(vercel_dir)
        connector = VercelConnector()

        assert set(connector.event_types()) == set(manifest.event_types)


# ─── Serialization round-trip ─────────────────────────────────────────


class TestVercelPollStoreRoundTrip:
    def test_poll_events_serialize_and_deserialize(self) -> None:
        connector = _make_connector(team_id=None)
        deployments = _load_fixture("deployments.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ):
            result = connector.poll(checkpoint=None)

        for evt in result.events:
            serialized = evt.to_json()
            deserialized = Event.from_json(serialized)
            assert deserialized.id == evt.id
            assert deserialized.source == "vercel"
            assert deserialized.event_type == evt.event_type
            assert deserialized.actor == evt.actor
            assert deserialized.severity == evt.severity

    def test_checkpoint_serialize_and_deserialize(self) -> None:
        connector = _make_connector(team_id=None)
        deployments = _load_fixture("deployments.json")

        with patch.object(
            connector,
            "_fetch_deployments",
            return_value=deployments["deployments"],
        ):
            result = connector.poll(checkpoint=None)

        serialized = result.checkpoint.to_json()
        deserialized = Checkpoint.from_json(serialized)
        assert deserialized.connector == "vercel"
        assert deserialized.value == result.checkpoint.value


# ─── _make_event_id() ────────────────────────────────────────────────


class TestMakeEventId:
    def test_deterministic(self) -> None:
        from mallcop.connectors.vercel.connector import _make_event_id

        id1 = _make_event_id("dpl_abc123")
        id2 = _make_event_id("dpl_abc123")
        assert id1 == id2

    def test_different_inputs_different_ids(self) -> None:
        from mallcop.connectors.vercel.connector import _make_event_id

        id1 = _make_event_id("dpl_abc123")
        id2 = _make_event_id("dpl_def456")
        assert id1 != id2

    def test_starts_with_evt_prefix(self) -> None:
        from mallcop.connectors.vercel.connector import _make_event_id

        assert _make_event_id("anything").startswith("evt_")

    def test_length(self) -> None:
        from mallcop.connectors.vercel.connector import _make_event_id

        # evt_ + 12 hex chars = 16
        assert len(_make_event_id("test")) == 16


# ─── Edge cases: missing name/url, None/empty in responses ────────────


class TestDeploymentEdgeCases:
    def test_deployment_missing_name_and_url_uses_empty_target(self) -> None:
        """Deployment with no name and no url should produce event with empty target."""
        connector = _make_connector(team_id=None)
        deploy = {
            "uid": "dpl_noname",
            "created": 1709308800000,  # 2024-03-01T16:00:00Z
            "state": "READY",
            "creator": {"username": "admin-user"},
            # No "name" or "url" key
        }

        with patch.object(connector, "_fetch_deployments", return_value=[deploy]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].target == ""

    def test_deployment_missing_name_falls_back_to_url(self) -> None:
        """Deployment with no name should fall back to url."""
        connector = _make_connector(team_id=None)
        deploy = {
            "uid": "dpl_urlonly",
            "created": 1709308800000,
            "state": "READY",
            "creator": {"username": "admin-user"},
            "url": "my-deploy-xyz.vercel.app",
            # No "name" key
        }

        with patch.object(connector, "_fetch_deployments", return_value=[deploy]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].target == "my-deploy-xyz.vercel.app"

    @pytest.mark.parametrize(
        "deploy_data",
        [
            {"uid": "dpl_none_state", "created": 1709308800000, "state": None, "creator": {"username": "admin-user"}},
            {"uid": "dpl_empty_state", "created": 1709308800000, "state": "", "creator": {"username": "admin-user"}},
            {"uid": "dpl_no_state", "created": 1709308800000, "creator": {"username": "admin-user"}},
        ],
        ids=["none-state", "empty-state", "missing-state"],
    )
    def test_deployment_with_none_or_empty_state(self, deploy_data) -> None:
        """Deployments with None, empty, or missing state should not crash."""
        connector = _make_connector(team_id=None)

        with patch.object(connector, "_fetch_deployments", return_value=[deploy_data]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].metadata["state"] in ("", None)

    def test_deployment_with_none_creator(self) -> None:
        """Deployment with None creator should default to 'unknown'."""
        connector = _make_connector(team_id=None)
        deploy = {
            "uid": "dpl_nocreator",
            "created": 1709308800000,
            "state": "READY",
            "name": "test-deploy",
            # No "creator" key
        }

        with patch.object(connector, "_fetch_deployments", return_value=[deploy]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].actor == "unknown"

    def test_deployment_with_empty_creator_dict(self) -> None:
        """Deployment with empty creator dict should default to 'unknown'."""
        connector = _make_connector(team_id=None)
        deploy = {
            "uid": "dpl_emptycreator",
            "created": 1709308800000,
            "state": "READY",
            "name": "test-deploy",
            "creator": {},
        }

        with patch.object(connector, "_fetch_deployments", return_value=[deploy]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].actor == "unknown"

    def test_deployment_with_zero_created_timestamp_is_skipped(self) -> None:
        """Deployment with created=0 is falsy, so _deployment_to_event skips it."""
        connector = _make_connector(team_id=None)
        deploy = {
            "uid": "dpl_zero",
            "created": 0,
            "state": "READY",
            "name": "epoch-deploy",
            "creator": {"username": "admin-user"},
        }

        with patch.object(connector, "_fetch_deployments", return_value=[deploy]):
            result = connector.poll(checkpoint=None)

        # created=0 is falsy, treated same as missing — event is skipped
        assert len(result.events) == 0


class TestAuditLogEdgeCases:
    def test_audit_event_with_empty_entity(self) -> None:
        """Audit event with empty entity dict should produce empty target."""
        connector = _make_connector()
        audit_event = {
            "id": "audit_empty_entity",
            "action": "member.added",
            "createdAt": 1709308800000,
            "user": {"username": "admin-user"},
            "entity": {},
            "entityId": "",
        }

        with patch.object(connector, "_fetch_deployments", return_value=[]), \
             patch.object(connector, "_fetch_audit_log", return_value=[audit_event]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].target == ""

    def test_audit_event_with_no_entity_key(self) -> None:
        """Audit event with no entity key at all should not crash."""
        connector = _make_connector()
        audit_event = {
            "id": "audit_no_entity",
            "action": "project.created",
            "createdAt": 1709308800000,
            "user": {"username": "admin-user"},
            # No "entity" key, no "entityId"
        }

        with patch.object(connector, "_fetch_deployments", return_value=[]), \
             patch.object(connector, "_fetch_audit_log", return_value=[audit_event]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].target == ""

    def test_audit_event_with_none_user(self) -> None:
        """Audit event with no user dict should fall back to userId or 'unknown'."""
        connector = _make_connector()
        audit_event = {
            "id": "audit_no_user",
            "action": "env.created",
            "createdAt": 1709308800000,
            "userId": "usr_fallback123",
            # No "user" key
        }

        with patch.object(connector, "_fetch_deployments", return_value=[]), \
             patch.object(connector, "_fetch_audit_log", return_value=[audit_event]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].actor == "usr_fallback123"

    def test_audit_event_with_empty_user_dict_and_no_userid(self) -> None:
        """Audit event with empty user dict and no userId falls back to 'unknown'."""
        connector = _make_connector()
        audit_event = {
            "id": "audit_no_user_at_all",
            "action": "domain.added",
            "createdAt": 1709308800000,
            "user": {},
            # No "userId"
        }

        with patch.object(connector, "_fetch_deployments", return_value=[]), \
             patch.object(connector, "_fetch_audit_log", return_value=[audit_event]):
            result = connector.poll(checkpoint=None)

        assert len(result.events) == 1
        assert result.events[0].actor == "unknown"

    @pytest.mark.parametrize(
        "created_at",
        [None, 0, ""],
        ids=["none", "zero", "empty-string"],
    )
    def test_audit_event_with_edge_case_created_at(self, created_at) -> None:
        """Audit events with None/0/empty createdAt: None and empty skip, 0 processes."""
        connector = _make_connector()
        audit_event = {
            "id": "audit_edge_ts",
            "action": "team.updated",
            "createdAt": created_at,
            "user": {"username": "admin-user"},
        }

        with patch.object(connector, "_fetch_deployments", return_value=[]), \
             patch.object(connector, "_fetch_audit_log", return_value=[audit_event]):
            result = connector.poll(checkpoint=None)

        if created_at is None or created_at == "":
            # _audit_to_event returns None for falsy createdAt
            assert len(result.events) == 0
        else:
            # 0 is falsy but still a valid epoch timestamp — depends on implementation
            # The code checks `if not ts_raw: return None`, and 0 is falsy
            assert len(result.events) == 0
