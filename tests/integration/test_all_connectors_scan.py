"""Integration test: scan pipeline exercises all 8 connectors via ConnectorEventInjector.

Design specifies all 8 connectors must be exercised in the scan pipeline test.
This test seeds known events via a ConnectorEventInjector per connector and
asserts each connector's events appear in the scan output and on disk.

The 8 connectors are:
  1. azure
  2. github
  3. m365
  4. aws-cloudtrail
  5. container-logs
  6. openclaw
  7. supabase
  8. vercel

Each connector is exercised via a mock that bypasses real API calls but exercises
the full scan pipeline path: authenticate → configure → poll → append_events.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from mallcop.schemas import Checkpoint, Event, PollResult, Severity
from mallcop.store import JsonlStore


# ---------------------------------------------------------------------------
# ConnectorEventInjector: per-connector synthetic event factory
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(source: str, event_type: str, actor: str, idx: int = 0) -> Event:
    """Build a minimal synthetic Event for the given source connector."""
    ts = _now() - timedelta(minutes=10 + idx)
    return Event(
        id=f"evt_inject_{source.replace('-', '_')}_{idx:03d}",
        timestamp=ts,
        ingested_at=ts + timedelta(seconds=1),
        source=source,
        event_type=event_type,
        actor=actor,
        action=f"{event_type}_action",
        target=f"{source}-target",
        severity=Severity.INFO,
        metadata={"connector": source, "injected": True},
        raw={"synthetic": True, "connector": source},
    )


def _make_checkpoint(connector: str) -> Checkpoint:
    return Checkpoint(
        connector=connector,
        value=f"cursor-inject-{connector}",
        updated_at=_now(),
    )


def _make_poll_result(connector_name: str, events: list[Event]) -> PollResult:
    """Build a PollResult for a connector with the given synthetic events."""
    return PollResult(
        events=events,
        checkpoint=_make_checkpoint(connector_name),
    )


# One known event per connector, plus the expected source name in scan output
_CONNECTOR_EVENTS: dict[str, tuple[str, str, str]] = {
    # connector_key: (source_value, event_type, actor)
    "azure": ("azure", "policy_change", "admin@acme.dev"),
    "github": ("github", "collaborator_added", "ci-bot"),
    "m365": ("m365", "admin_action", "admin@acme.dev"),
    "aws-cloudtrail": ("aws-cloudtrail", "iam_change", "arn:aws:iam::123:user/ops"),
    "container-logs": ("container-logs", "log_line", "myapp"),
    "openclaw": ("openclaw", "skill_installed", "openclaw-agent"),
    "supabase": ("supabase", "auth_success", "user@acme.dev"),
    "vercel": ("vercel", "deployment", "ci-pipeline"),
}


def _make_mock_connector(connector_name: str) -> MagicMock:
    """Build a mock connector that returns one known synthetic event from poll()."""
    source, event_type, actor = _CONNECTOR_EVENTS[connector_name]
    events = [_make_event(source, event_type, actor)]
    poll_result = _make_poll_result(connector_name, events)

    mock = MagicMock()
    mock.authenticate.return_value = None
    mock.configure.return_value = None
    mock.poll.return_value = poll_result
    return mock


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _write_all_connectors_config(root: Path) -> None:
    """Write mallcop.yaml with all 8 connectors configured."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {
            "azure": {
                "tenant_id": "${AZURE_TENANT_ID}",
                "client_id": "${AZURE_CLIENT_ID}",
                "client_secret": "${AZURE_CLIENT_SECRET}",
                "subscription_ids": ["sub-001"],
            },
            "github": {
                "token": "${GITHUB_TOKEN}",
                "org": "acme-corp",
            },
            "m365": {
                "tenant_id": "${M365_TENANT_ID}",
                "client_id": "${M365_CLIENT_ID}",
                "client_secret": "${M365_CLIENT_SECRET}",
                "content_types": ["Audit.AzureActiveDirectory"],
            },
            "aws-cloudtrail": {
                "region": "us-east-1",
                "access_key_id": "${AWS_ACCESS_KEY_ID}",
                "secret_access_key": "${AWS_SECRET_ACCESS_KEY}",
            },
            "container-logs": {
                "subscription_id": "sub-001",
                "resource_group": "rg-prod",
                "apps": [{"name": "myapp", "container": "myapp"}],
            },
            "openclaw": {
                "openclaw_home": "${OPENCLAW_HOME}",
            },
            "supabase": {
                "project_url": "${SUPABASE_PROJECT_URL}",
                "service_role_key": "${SUPABASE_SERVICE_ROLE_KEY}",
                "project_ref": "${SUPABASE_PROJECT_REF}",
            },
            "vercel": {
                "token": "${VERCEL_TOKEN}",
            },
        },
        "routing": {},
        "actor_chain": {},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAllConnectorsScanPipeline:
    """scan pipeline exercises all 8 connectors via ConnectorEventInjector mocks.

    Each connector returns one known synthetic event. The tests verify:
    - scan exits 0
    - all 8 connectors appear in output
    - each connector's status is ok
    - each connector ingests exactly 1 event
    - total_events_ingested equals number of connectors (8)
    - all 8 connector sources appear in the on-disk event store
    """

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root = tmp_path
        _write_all_connectors_config(tmp_path)
        monkeypatch.chdir(tmp_path)
        # Provide dummy env vars so EnvSecretProvider does not raise on resolution
        env_vars = {
            "AZURE_TENANT_ID": "fake-tenant",
            "AZURE_CLIENT_ID": "fake-client",
            "AZURE_CLIENT_SECRET": "fake-secret",
            "GITHUB_TOKEN": "fake-gh-token",
            "M365_TENANT_ID": "fake-m365-tenant",
            "M365_CLIENT_ID": "fake-m365-client",
            "M365_CLIENT_SECRET": "fake-m365-secret",
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "OPENCLAW_HOME": str(tmp_path / "openclaw_home"),
            "SUPABASE_PROJECT_URL": "https://fake.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "fake-service-role-key",
            "SUPABASE_PROJECT_REF": "fake-project-ref",
            "VERCEL_TOKEN": "fake-vercel-token",
        }
        for k, v in env_vars.items():
            monkeypatch.setenv(k, v)

    def _run_scan_with_all_mocks(self) -> dict[str, Any]:
        """Run run_scan_pipeline with all 8 connectors mocked."""
        from mallcop.cli_pipeline import run_scan_pipeline

        def _mock_instantiate(name: str):
            if name in _CONNECTOR_EVENTS:
                return _make_mock_connector(name)
            return None

        with patch("mallcop.cli_pipeline.instantiate_connector", side_effect=_mock_instantiate):
            return run_scan_pipeline(self.root)

    def test_scan_exits_ok(self) -> None:
        """scan pipeline returns status ok when all 8 connectors succeed."""
        result = self._run_scan_with_all_mocks()
        assert result["status"] == "ok"

    def test_scan_all_eight_connectors_present(self) -> None:
        """All 8 connector names appear in scan output."""
        result = self._run_scan_with_all_mocks()
        connector_keys = set(result["connectors"].keys())
        expected = set(_CONNECTOR_EVENTS.keys())
        assert expected == connector_keys, (
            f"Missing connectors: {expected - connector_keys}. "
            f"Extra: {connector_keys - expected}."
        )

    def test_scan_each_connector_status_ok(self) -> None:
        """Each of the 8 connectors reports status ok."""
        result = self._run_scan_with_all_mocks()
        for name, summary in result["connectors"].items():
            assert summary["status"] == "ok", (
                f"Connector {name!r} reported status {summary['status']!r}: "
                f"{summary.get('error', '')}"
            )

    def test_scan_each_connector_ingests_one_event(self) -> None:
        """Each connector ingests exactly 1 synthetic event."""
        result = self._run_scan_with_all_mocks()
        for name, summary in result["connectors"].items():
            assert summary["events_ingested"] == 1, (
                f"Connector {name!r} ingested {summary['events_ingested']} events, expected 1"
            )

    def test_scan_total_events_equals_connector_count(self) -> None:
        """total_events_ingested equals the number of connectors (8)."""
        result = self._run_scan_with_all_mocks()
        assert result["total_events_ingested"] == len(_CONNECTOR_EVENTS), (
            f"Expected {len(_CONNECTOR_EVENTS)} total events, "
            f"got {result['total_events_ingested']}"
        )

    def test_scan_each_connector_source_on_disk(self) -> None:
        """All 8 connector source values appear in the on-disk event store."""
        self._run_scan_with_all_mocks()
        store = JsonlStore(self.root)
        events = store.query_events()

        on_disk_sources = {e.source for e in events}
        expected_sources = {v[0] for v in _CONNECTOR_EVENTS.values()}
        missing = expected_sources - on_disk_sources
        assert not missing, (
            f"Sources missing from on-disk event store: {missing}. "
            f"Found: {on_disk_sources}"
        )

    def test_scan_checkpoints_written_for_all_connectors(self) -> None:
        """Checkpoint is written for each of the 8 connectors after scan."""
        self._run_scan_with_all_mocks()
        store = JsonlStore(self.root)
        for name in _CONNECTOR_EVENTS:
            cp = store.get_checkpoint(name)
            assert cp is not None, f"No checkpoint written for connector {name!r}"
            assert cp.connector == name

    def test_scan_events_have_correct_source_per_connector(self) -> None:
        """Each connector's event has the expected source value."""
        self._run_scan_with_all_mocks()
        store = JsonlStore(self.root)
        events = store.query_events()

        source_to_events: dict[str, list[Event]] = {}
        for e in events:
            source_to_events.setdefault(e.source, []).append(e)

        for connector_name, (source, event_type, actor) in _CONNECTOR_EVENTS.items():
            assert source in source_to_events, (
                f"No events found for source {source!r} (connector {connector_name!r})"
            )
            matching = [e for e in source_to_events[source] if e.event_type == event_type]
            assert matching, (
                f"No events of type {event_type!r} found for source {source!r}"
            )

    def test_scan_manifest_written_with_all_connectors(self) -> None:
        """manifest.json is written and lists all 8 connectors as succeeded."""
        self._run_scan_with_all_mocks()
        manifest_path = self.root / ".mallcop" / "manifest.json"
        assert manifest_path.exists(), "manifest.json was not written"
        manifest = json.loads(manifest_path.read_text())
        assert manifest["pulse"] == 1.0
        assert set(manifest["connectors_configured"]) == set(_CONNECTOR_EVENTS.keys())
        assert manifest["connectors_failed"] == {}
        assert len(manifest["connectors_succeeded"]) == len(_CONNECTOR_EVENTS)
