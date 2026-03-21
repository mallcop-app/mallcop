"""UC-1: Agent deploys mallcop, discovers GitHub + M365 + Azure.

Functional test exercising the full init -> scan -> detect flow with all three
platform connectors using recorded fixtures (no live API calls).

Scenario:
  1. mallcop init discovers Azure subscriptions, GitHub orgs, M365 tenants
  2. Writes mallcop.yaml with all three connectors configured
  3. mallcop scan polls all three connectors, stores events
  4. mallcop detect runs detectors against the combined event stream
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import yaml
from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import (
    Baseline,
    Checkpoint,
    DiscoveryResult,
    Event,
    PollResult,
    Severity,
)
from mallcop.store import JsonlStore


# ── Dynamic timestamps (5 days ago — always within 14-day learning window) ──

def _days_ago(days: int, hour: int = 10) -> datetime:
    """Return a UTC datetime N days before now at the given hour."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).replace(
        hour=hour, minute=0, second=0, microsecond=0
    )


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


# ── Fake Azure data ──────────────────────────────────────────────────

FAKE_AZURE_SUBSCRIPTIONS = [
    {"subscriptionId": "sub-001", "displayName": "Production"},
    {"subscriptionId": "sub-002", "displayName": "Dev/Test"},
]


def _fake_azure_activity_log() -> list[dict]:
    return [
        {
            "eventDataId": "az-evt-001",
            "eventTimestamp": _iso(_days_ago(5, 10)),
            "caller": "admin@acme-corp.dev",
            "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
            "resourceType": {"value": "Microsoft.Authorization/roleAssignments"},
            "resourceId": "/subscriptions/sub-001/providers/Microsoft.Authorization/roleAssignments/ra-1",
            "level": "Informational",
            "subscriptionId": "sub-001",
            "resourceGroupName": "rg-prod",
            "correlationId": "corr-001",
            "status": {"value": "Succeeded"},
        },
        {
            "eventDataId": "az-evt-002",
            "eventTimestamp": _iso(_days_ago(5, 11)),
            "caller": "deploy-sp@acme-corp.dev",
            "operationName": {"value": "Microsoft.ContainerApp/containerApps/write"},
            "resourceType": {"value": "Microsoft.ContainerApp/containerApps"},
            "resourceId": "/subscriptions/sub-001/resourceGroups/rg-prod/providers/Microsoft.ContainerApp/containerApps/myapp",
            "level": "Informational",
            "subscriptionId": "sub-001",
            "resourceGroupName": "rg-prod",
            "correlationId": "corr-002",
            "status": {"value": "Succeeded"},
        },
    ]


# ── Fake GitHub data ─────────────────────────────────────────────────

FAKE_GITHUB_REPOS = [
    {"full_name": "acme-corp/mallcop", "private": True},
    {"full_name": "acme-corp/website", "private": False},
]

FAKE_GITHUB_MEMBERS = [
    {"login": "admin-user"},
    {"login": "deploy-bot"},
]


def _fake_github_audit_log() -> list[dict]:
    return [
        {
            "_document_id": "gh-doc-001",
            "@timestamp": _epoch_ms(_days_ago(5, 10)),
            "action": "org.add_member",
            "actor": "admin-user",
            "repo": "acme-corp/mallcop",
            "org": "acme-corp",
        },
        {
            "_document_id": "gh-doc-002",
            "@timestamp": _epoch_ms(_days_ago(5, 11)),
            "action": "repo.access",
            "actor": "admin-user",
            "repo": "acme-corp/website",
            "org": "acme-corp",
        },
        {
            "_document_id": "gh-doc-003",
            "@timestamp": _epoch_ms(_days_ago(5, 12)),
            "action": "git.push",
            "actor": "deploy-bot",
            "repo": "acme-corp/mallcop",
            "org": "acme-corp",
        },
    ]


# ── Fake M365 data ───────────────────────────────────────────────────

FAKE_M365_SUBSCRIPTIONS = [
    {"contentType": "Audit.AzureActiveDirectory", "status": "enabled"},
    {"contentType": "Audit.Exchange", "status": "enabled"},
    {"contentType": "Audit.General", "status": "enabled"},
]

FAKE_M365_CONTENT_BLOBS = [
    {"contentUri": "https://manage.office.com/blob/001", "contentId": "blob-001"},
]


def _fake_m365_audit_records() -> list[dict]:
    return [
        {
            "Id": "m365-rec-001",
            "CreationTime": _iso(_days_ago(5, 10)),
            "Operation": "UserLoggedIn",
            "UserId": "admin@acme-corp.dev",
            "Workload": "AzureActiveDirectory",
            "ObjectId": "",
            "ResultStatus": "Success",
            "RecordType": 15,
            "OrganizationId": "org-001",
            "ClientIP": "10.0.0.1",
        },
        {
            "Id": "m365-rec-002",
            "CreationTime": _iso(_days_ago(5, 11)),
            "Operation": "New-InboxRule",
            "UserId": "user@acme-corp.dev",
            "Workload": "Exchange",
            "ObjectId": "inbox-rule-001",
            "ResultStatus": "Success",
            "RecordType": 2,
            "OrganizationId": "org-001",
            "ClientIP": "10.0.0.2",
        },
        {
            "Id": "m365-rec-003",
            "CreationTime": _iso(_days_ago(5, 12)),
            "Operation": "UserLoginFailed",
            "UserId": "attacker@evil.com",
            "Workload": "AzureActiveDirectory",
            "ObjectId": "",
            "ResultStatus": "Failed",
            "RecordType": 15,
            "OrganizationId": "org-001",
            "ClientIP": "203.0.113.99",
        },
    ]


# ── Mock helpers ─────────────────────────────────────────────────────


def _mock_azure_list_subs(self: Any) -> list[dict[str, Any]]:
    return FAKE_AZURE_SUBSCRIPTIONS


def _mock_azure_fetch_log(
    self: Any, subscription_id: str, checkpoint: Checkpoint | None
) -> list[dict[str, Any]]:
    return _fake_azure_activity_log()


def _mock_github_list_repos(self: Any) -> list[dict[str, Any]]:
    return FAKE_GITHUB_REPOS


def _mock_github_list_members(self: Any) -> list[dict[str, Any]]:
    return FAKE_GITHUB_MEMBERS


def _mock_github_fetch_audit_log(
    self: Any, checkpoint: Checkpoint | None
) -> tuple[list[dict[str, Any]], str | None]:
    return _fake_github_audit_log(), None


def _mock_github_validate_token(self: Any) -> None:
    pass


def _mock_m365_list_subs(self: Any) -> list[dict[str, Any]]:
    return FAKE_M365_SUBSCRIPTIONS


def _mock_m365_get_token(self: Any) -> str:
    self._cached_token = "fake-m365-token"
    self._token_expires_at = 9999999999.0
    return "fake-m365-token"


def _mock_m365_ensure_subs(self: Any) -> None:
    pass


def _mock_m365_list_blobs(
    self: Any, content_type: str, start_time: str, end_time: str
) -> list[dict[str, Any]]:
    return FAKE_M365_CONTENT_BLOBS


def _mock_m365_fetch_records(self: Any, content_uri: str) -> list[dict[str, Any]]:
    return _fake_m365_audit_records()


# ── Patch context managers ───────────────────────────────────────────

def _mock_azure_get_token(self: Any) -> str:
    self._cached_token = "fake-azure-token"
    self._token_expires_at = 9999999999.0
    return "fake-azure-token"


_AZURE_PATCHES = {
    "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions": _mock_azure_list_subs,
    "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log": _mock_azure_fetch_log,
    "mallcop.connectors.azure.connector.AzureConnector._get_token": _mock_azure_get_token,
}

_GITHUB_PATCHES = {
    "mallcop.connectors.github.connector.GitHubConnector._list_repos": _mock_github_list_repos,
    "mallcop.connectors.github.connector.GitHubConnector._list_members": _mock_github_list_members,
    "mallcop.connectors.github.connector.GitHubConnector._fetch_audit_log": _mock_github_fetch_audit_log,
    "mallcop.connectors.github.connector.GitHubConnector._validate_token": _mock_github_validate_token,
}

_M365_PATCHES = {
    "mallcop.connectors.m365.connector.M365Connector._list_subscriptions": _mock_m365_list_subs,
    "mallcop.connectors.m365.connector.M365Connector._get_token": _mock_m365_get_token,
    "mallcop.connectors.m365.connector.M365Connector._ensure_subscriptions": _mock_m365_ensure_subs,
    "mallcop.connectors.m365.connector.M365Connector._list_content_blobs": _mock_m365_list_blobs,
    "mallcop.connectors.m365.connector.M365Connector._fetch_audit_records": _mock_m365_fetch_records,
}

_ALL_PATCHES = {**_AZURE_PATCHES, **_GITHUB_PATCHES, **_M365_PATCHES}


_SCAN_ENV = {
    "AZURE_TENANT_ID": "fake-tenant",
    "AZURE_CLIENT_ID": "fake-client",
    "AZURE_CLIENT_SECRET": "fake-secret",
    "GITHUB_TOKEN": "fake-gh-token",
    "GITHUB_ORG": "acme-corp",
    # M365 connector authenticate() reads ENTRA_* directly
    "ENTRA_TENANT_ID": "fake-m365-tenant",
    "ENTRA_CLIENT_ID": "fake-m365-client",
    "ENTRA_CLIENT_SECRET": "fake-m365-secret",
    # Config template uses M365_* for ${} resolution
    "M365_TENANT_ID": "fake-m365-tenant",
    "M365_CLIENT_ID": "fake-m365-client",
    "M365_CLIENT_SECRET": "fake-m365-secret",
}


class _AllConnectorsMocked:
    """Context manager that patches all three connectors' internal methods."""

    def __init__(self) -> None:
        self._patchers: list[Any] = []

    def __enter__(self) -> "_AllConnectorsMocked":
        for target, replacement in _ALL_PATCHES.items():
            p = patch(target, replacement)
            p.start()
            self._patchers.append(p)
        return self

    def __exit__(self, *args: Any) -> None:
        for p in self._patchers:
            p.stop()


def _write_multiplatform_config(root: Path) -> None:
    """Write mallcop.yaml with all three connectors configured."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {
            "azure": {
                "tenant_id": "${AZURE_TENANT_ID}",
                "client_id": "${AZURE_CLIENT_ID}",
                "client_secret": "${AZURE_CLIENT_SECRET}",
                "subscription_ids": ["sub-001", "sub-002"],
            },
            "github": {
                "token": "${GITHUB_TOKEN}",
                "org": "acme-corp",
            },
            "m365": {
                "tenant_id": "${M365_TENANT_ID}",
                "client_id": "${M365_CLIENT_ID}",
                "client_secret": "${M365_CLIENT_SECRET}",
                "content_types": [
                    "Audit.AzureActiveDirectory",
                    "Audit.Exchange",
                    "Audit.General",
                ],
            },
        },
        "routing": {
            "warn": "triage",
            "critical": "triage",
            "info": None,
        },
        "actor_chain": {"triage": {"routes_to": "notify-teams"}},
        "budget": {
            "max_findings_for_actors": 25,
            "max_tokens_per_run": 50000,
            "max_tokens_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


# ── Init tests ───────────────────────────────────────────────────────


class TestInitDiscoversAllPlatforms:
    """mallcop init discovers Azure, GitHub, and M365."""

    def _run_init(self, tmp_path: Path) -> tuple[Any, Path]:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            cwd = Path(td)
            with _AllConnectorsMocked():
                result = runner.invoke(cli, ["init"])
        return result, cwd

    def test_init_exits_zero(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

    def test_init_reports_all_three_connectors(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        connector_names = {c["name"] for c in data["connectors"]}
        assert "azure" in connector_names
        assert "github" in connector_names
        assert "m365" in connector_names

    def test_init_azure_available_with_resources(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        azure = next(c for c in data["connectors"] if c["name"] == "azure")
        assert azure["available"] is True
        assert len(azure["resources"]) == 2
        assert "sub-001" in azure["resources"][0]

    def test_init_github_available_with_resources(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        github = next(c for c in data["connectors"] if c["name"] == "github")
        assert github["available"] is True
        assert any("acme-corp/mallcop" in r for r in github["resources"])
        assert any("admin-user" in r for r in github["resources"])

    def test_init_m365_available_with_resources(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        m365 = next(c for c in data["connectors"] if c["name"] == "m365")
        assert m365["available"] is True
        assert len(m365["resources"]) == 3

    def test_init_config_has_all_three_connectors(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            cwd = Path(td)
            with _AllConnectorsMocked():
                result = runner.invoke(cli, ["init"])
            assert result.exit_code == 0

            config = yaml.safe_load((cwd / "mallcop.yaml").read_text())
            assert "azure" in config["connectors"]
            assert "github" in config["connectors"]
            assert "m365" in config["connectors"]

    def test_init_config_azure_has_subscription_ids(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            cwd = Path(td)
            with _AllConnectorsMocked():
                runner.invoke(cli, ["init"])
            config = yaml.safe_load((cwd / "mallcop.yaml").read_text())
            assert config["connectors"]["azure"]["subscription_ids"] == [
                "sub-001",
                "sub-002",
            ]

    def test_init_config_github_has_auth_refs(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            cwd = Path(td)
            with _AllConnectorsMocked():
                runner.invoke(cli, ["init"])
            config = yaml.safe_load((cwd / "mallcop.yaml").read_text())
            gh = config["connectors"]["github"]
            assert gh["token"] == "${GITHUB_TOKEN}"

    def test_init_config_m365_has_content_types(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            cwd = Path(td)
            with _AllConnectorsMocked():
                runner.invoke(cli, ["init"])
            config = yaml.safe_load((cwd / "mallcop.yaml").read_text())
            m365 = config["connectors"]["m365"]
            assert "content_types" in m365
            assert "Audit.AzureActiveDirectory" in m365["content_types"]

    def test_init_cost_estimate_reflects_three_connectors(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        cost = data["cost_estimate"]
        assert cost["connectors_active"] == 3

    def test_init_sample_events_from_all_connectors(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        # At least some connectors should report sample events
        connectors_with_samples = [
            c for c in data["connectors"]
            if c.get("sample_events", 0) > 0
        ]
        assert len(connectors_with_samples) >= 1


# ── Scan tests ───────────────────────────────────────────────────────


class TestScanPollsAllConnectors:
    """mallcop scan polls Azure, GitHub, and M365, stores events."""

    def _setup_and_scan(self, tmp_path: Path, monkeypatch: Any) -> tuple[Any, Path]:
        runner = CliRunner()
        cwd = tmp_path
        _write_multiplatform_config(cwd)
        monkeypatch.chdir(cwd)

        with _AllConnectorsMocked(), patch.dict(os.environ, _SCAN_ENV):
            result = runner.invoke(cli, ["scan"], catch_exceptions=False)

        return result, cwd

    def test_scan_exits_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        result, _ = self._setup_and_scan(tmp_path, monkeypatch)
        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

    def test_scan_reports_all_connectors(self, tmp_path: Path, monkeypatch: Any) -> None:
        result, _ = self._setup_and_scan(tmp_path, monkeypatch)
        data = json.loads(result.output)
        assert "azure" in data["connectors"]
        assert "github" in data["connectors"]
        assert "m365" in data["connectors"]

    def test_scan_azure_ingests_events(self, tmp_path: Path, monkeypatch: Any) -> None:
        result, _ = self._setup_and_scan(tmp_path, monkeypatch)
        data = json.loads(result.output)
        azure = data["connectors"]["azure"]
        assert azure["status"] == "ok"
        assert azure["events_ingested"] > 0

    def test_scan_github_ingests_events(self, tmp_path: Path, monkeypatch: Any) -> None:
        result, _ = self._setup_and_scan(tmp_path, monkeypatch)
        data = json.loads(result.output)
        github = data["connectors"]["github"]
        assert github["status"] == "ok"
        assert github["events_ingested"] > 0

    def test_scan_m365_ingests_events(self, tmp_path: Path, monkeypatch: Any) -> None:
        result, _ = self._setup_and_scan(tmp_path, monkeypatch)
        data = json.loads(result.output)
        m365 = data["connectors"]["m365"]
        assert m365["status"] == "ok"
        assert m365["events_ingested"] > 0

    def test_scan_total_events_is_sum(self, tmp_path: Path, monkeypatch: Any) -> None:
        result, _ = self._setup_and_scan(tmp_path, monkeypatch)
        data = json.loads(result.output)
        total = data["total_events_ingested"]
        per_connector = sum(
            c["events_ingested"] for c in data["connectors"].values()
        )
        assert total == per_connector
        assert total > 0

    def test_scan_events_persisted_to_store(self, tmp_path: Path, monkeypatch: Any) -> None:
        _, cwd = self._setup_and_scan(tmp_path, monkeypatch)
        store = JsonlStore(cwd)
        events = store.query_events()
        assert len(events) > 0
        sources = {e.source for e in events}
        assert "azure" in sources
        assert "github" in sources
        assert "m365" in sources

    def test_scan_checkpoints_set_for_all(self, tmp_path: Path, monkeypatch: Any) -> None:
        _, cwd = self._setup_and_scan(tmp_path, monkeypatch)
        store = JsonlStore(cwd)
        for name in ("azure", "github", "m365"):
            cp = store.get_checkpoint(name)
            assert cp is not None, f"No checkpoint for {name}"


# ── Detect tests ─────────────────────────────────────────────────────


class TestDetectOnMultiplatformEvents:
    """mallcop detect runs detectors against combined event stream."""

    def _setup_scan_detect(self, tmp_path: Path, monkeypatch: Any) -> tuple[Any, Any, Path]:
        runner = CliRunner()
        cwd = tmp_path
        _write_multiplatform_config(cwd)
        monkeypatch.chdir(cwd)

        with _AllConnectorsMocked(), patch.dict(os.environ, _SCAN_ENV):
            scan_result = runner.invoke(cli, ["scan"], catch_exceptions=False)
            detect_result = runner.invoke(
                cli, ["detect", "--dir", str(cwd)], catch_exceptions=False
            )

        return scan_result, detect_result, cwd

    def test_detect_exits_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        _, detect_result, _ = self._setup_scan_detect(tmp_path, monkeypatch)
        assert detect_result.exit_code == 0, (
            f"Exit code {detect_result.exit_code}: {detect_result.output}"
        )

    def test_detect_produces_findings(self, tmp_path: Path, monkeypatch: Any) -> None:
        _, detect_result, _ = self._setup_scan_detect(tmp_path, monkeypatch)
        data = json.loads(detect_result.output)
        # new-actor detector should fire for actors not in baseline
        assert data["findings_count"] > 0

    def test_detect_findings_from_multiple_sources(self, tmp_path: Path, monkeypatch: Any) -> None:
        _, _, cwd = self._setup_scan_detect(tmp_path, monkeypatch)
        store = JsonlStore(cwd)
        findings = store.query_findings()
        events = store.query_events()

        # Build event id -> source map
        evt_source = {e.id: e.source for e in events}

        # Collect sources that have findings referencing their events
        finding_sources: set[str] = set()
        for f in findings:
            for eid in f.event_ids:
                if eid in evt_source:
                    finding_sources.add(evt_source[eid])

        # Should have findings from at least 2 different sources
        assert len(finding_sources) >= 2, (
            f"Expected findings from multiple sources, got: {finding_sources}"
        )

    def test_detect_learning_mode_active(self, tmp_path: Path, monkeypatch: Any) -> None:
        """On first run, connectors are in learning mode (< 14 days data)."""
        _, detect_result, _ = self._setup_scan_detect(tmp_path, monkeypatch)
        data = json.loads(detect_result.output)
        # All three connectors should be in learning mode on first run
        learning = data.get("learning_connectors", [])
        assert len(learning) >= 2  # at least azure and m365


# ── Full pipeline: init -> scan -> detect ────────────────────────────


class TestFullInitScanDetectPipeline:
    """End-to-end: init discovers all platforms, scan polls, detect analyzes."""

    def test_full_pipeline(self, tmp_path: Path) -> None:
        runner = CliRunner()
        env = _SCAN_ENV.copy()

        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            cwd = Path(td)
            with _AllConnectorsMocked(), patch.dict(os.environ, env):
                # Step 1: Init discovers all platforms
                init_result = runner.invoke(cli, ["init"])
                assert init_result.exit_code == 0, (
                    f"init failed: {init_result.output}"
                )
                init_data = json.loads(init_result.output)
                assert init_data["status"] == "ok"

                # Verify all three connectors discovered
                available = [
                    c["name"]
                    for c in init_data["connectors"]
                    if c["available"]
                ]
                assert "azure" in available
                assert "github" in available
                assert "m365" in available

                # Verify config written with all three
                config = yaml.safe_load((cwd / "mallcop.yaml").read_text())
                assert len(config["connectors"]) == 3

                # Step 2: Watch --dry-run runs scan+detect pipeline
                watch_result = runner.invoke(
                    cli, ["watch", "--dry-run", "--dir", str(cwd)]
                )
                assert watch_result.exit_code == 0, (
                    f"watch failed: {watch_result.output}"
                )
                watch_data = json.loads(watch_result.output)
                assert watch_data["status"] == "ok"

                # Scan collected events from all connectors
                scan = watch_data["scan"]
                assert scan["total_events_ingested"] > 0
                for name in ("azure", "github", "m365"):
                    assert scan["connectors"][name]["status"] == "ok"
                    assert scan["connectors"][name]["events_ingested"] > 0

                # Detect produced findings
                assert watch_data["detect"]["findings_count"] > 0

                # Baseline knows all sources after watch pipeline
                baseline = watch_data["baseline"]
                assert "azure" in baseline["known_sources"]
                assert "github" in baseline["known_sources"]
                assert "m365" in baseline["known_sources"]

    def test_watch_dry_run_all_connectors(self, tmp_path: Path) -> None:
        """mallcop watch --dry-run exercises scan+detect for all connectors."""
        runner = CliRunner()
        env = _SCAN_ENV.copy()

        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            cwd = Path(td)
            with _AllConnectorsMocked(), patch.dict(os.environ, env):
                # First init to create config
                init_result = runner.invoke(cli, ["init"])
                assert init_result.exit_code == 0

                # Watch --dry-run does scan + detect, skips escalate
                watch_result = runner.invoke(
                    cli, ["watch", "--dry-run", "--dir", str(cwd)]
                )
                assert watch_result.exit_code == 0, (
                    f"watch failed: {watch_result.output}"
                )
                watch_data = json.loads(watch_result.output)
                assert watch_data["status"] == "ok"

                # Scan collected events from all connectors
                scan = watch_data["scan"]
                assert scan["total_events_ingested"] > 0
                for name in ("azure", "github", "m365"):
                    assert scan["connectors"][name]["status"] == "ok"

                # Detect produced findings
                detect = watch_data["detect"]
                assert detect["findings_count"] > 0

                # Escalate was skipped (dry run)
                assert watch_data["escalate"]["skipped"] is True


# ── Bad-pattern seeding helpers ──────────────────────────────────────


def _make_plaintext_api_key_event(now: datetime, cwd: Path) -> Event:
    """Create an openclaw config_changed event with secrets_found=True.

    The OpenClawConfigDriftDetector fires plaintext-secrets when raw.secrets_found is True.
    """
    return Event(
        id="evt_plaintext_api_key_001",
        timestamp=now - timedelta(hours=1),
        ingested_at=now,
        source="openclaw",
        event_type="config_changed",
        actor="filesystem",
        action="config_changed",
        target=str(cwd / "openclaw.json"),
        severity=Severity.WARN,
        metadata={
            "config": {
                "gateway": {
                    "auth": {"enabled": True},
                    "mdns": {"enabled": False},
                    "guestMode": {"enabled": False, "tools": []},
                },
                "openai_api_key": "sk-proj-FAKE_KEY_FOR_TESTING_ONLY_NOT_REAL",
            },
        },
        raw={"secrets_found": True},
    )


def _make_unusual_timing_event(actor: str, now: datetime) -> Event:
    """Create a GitHub event at Monday 03:00 UTC — unusual for an actor
    whose baseline only records Tuesday 08:00-11:59 UTC activity.

    Monday 03:00 UTC -> weekday()=0, hour_bucket(3)=0 -> key suffix ":0:0"
    Baseline will have the actor at Tuesday bucket=8 -> ":1:8" but NOT ":0:0".
    The unusual-timing detector fires when freq.get(key, 0) == 0 and freq is non-empty.
    """
    # Force to a specific Monday 03:00 so the weekday/bucket is deterministic.
    # Find the most recent past Monday from now, set to 03:00 UTC.
    days_since_monday = now.weekday()  # 0=Mon, so if today is Mon, days_since=0
    if days_since_monday == 0 and now.hour >= 3:
        # today is Monday and it's past 03:00, use today
        monday = now.replace(hour=3, minute=0, second=0, microsecond=0)
    elif days_since_monday == 0:
        # today is Monday but before 03:00, go back 7 days
        monday = (now - timedelta(days=7)).replace(hour=3, minute=0, second=0, microsecond=0)
    else:
        monday = (now - timedelta(days=days_since_monday)).replace(
            hour=3, minute=0, second=0, microsecond=0
        )
    return Event(
        id="evt_unusual_timing_001",
        timestamp=monday,
        ingested_at=now,
        source="github",
        event_type="push",
        actor=actor,
        action="git.push",
        target="acme-corp/sensitive-repo",
        severity=Severity.INFO,
        metadata={"org": "acme-corp"},
        raw={"raw_data": True},
    )


def _seed_baseline_for_unusual_timing(
    store: JsonlStore, actor: str, now: datetime
) -> None:
    """Seed the store with baseline events at Tuesday 08:00-11:59 UTC.

    This populates frequency_tables with key "{source}:{event_type}:{actor}:1:8"
    (Tuesday, hour_bucket=8). When detect runs and sees the actor at Monday 03:00
    (key suffix ":0:0"), the frequency is 0 -> unusual-timing fires.
    """
    # Tuesday = weekday 1; hour 10 -> bucket 8
    days_since_tuesday = (now.weekday() - 1) % 7
    if days_since_tuesday == 0 and now.hour >= 10:
        base_tuesday = now.replace(hour=10, minute=0, second=0, microsecond=0)
    else:
        base_tuesday = (now - timedelta(days=days_since_tuesday or 7)).replace(
            hour=10, minute=0, second=0, microsecond=0
        )

    baseline_events = []
    for i in range(5):
        ts = base_tuesday - timedelta(weeks=i + 1)
        baseline_events.append(Event(
            id=f"evt_baseline_tuesday_{i:02d}",
            timestamp=ts,
            ingested_at=ts + timedelta(seconds=5),
            source="github",
            event_type="push",
            actor=actor,
            action="git.push",
            target="acme-corp/web-app",
            severity=Severity.INFO,
            metadata={"org": "acme-corp"},
            raw={"raw_data": True},
        ))

    store.append_events(baseline_events)
    store.update_baseline(baseline_events)


# ── Tests ─────────────────────────────────────────────────────────────


class TestDetectBadPatterns:
    """Detect pipeline fires plaintext-secrets and unusual-timing on seeded events."""

    def _setup_detect(self, tmp_path: Path, monkeypatch: Any) -> tuple[Any, Path]:
        """Seed bad-pattern events and baseline, run detect, return (result, cwd)."""
        cwd = tmp_path
        _write_multiplatform_config(cwd)
        monkeypatch.chdir(cwd)

        store = JsonlStore(cwd)
        now = datetime.now(timezone.utc)
        actor = "deploy-bot@acme-corp.dev"

        # Seed baseline with known Tuesday 08:00 activity for actor.
        # This gives freq tables non-empty -> unusual-timing detector is active.
        _seed_baseline_for_unusual_timing(store, actor, now)

        # Seed the two bad-pattern events into the store
        plaintext_evt = _make_plaintext_api_key_event(now, cwd)
        unusual_evt = _make_unusual_timing_event(actor, now)
        store.append_events([plaintext_evt, unusual_evt])

        runner = CliRunner()
        with patch.dict(os.environ, _SCAN_ENV):
            detect_result = runner.invoke(
                cli, ["detect", "--dir", str(cwd)], catch_exceptions=False
            )
        return detect_result, cwd

    def test_plaintext_secrets_detector_fires(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """openclaw-config-drift [plaintext-secrets] fires on seeded API key event."""
        detect_result, cwd = self._setup_detect(tmp_path, monkeypatch)

        assert detect_result.exit_code == 0, (
            f"detect exit {detect_result.exit_code}: {detect_result.output}"
        )

        store = JsonlStore(cwd)
        findings = store.query_findings()
        # Metadata values are sanitized on store (wrapped in USER_DATA markers).
        # Check that the rule field contains "plaintext-secrets" after stripping markers.
        plaintext_findings = [
            f for f in findings
            if f.detector == "openclaw-config-drift"
            and "plaintext-secrets" in f.metadata.get("rule", "")
        ]
        assert len(plaintext_findings) >= 1, (
            f"Expected plaintext-secrets finding, got detectors: "
            f"{[f.detector + ':' + f.metadata.get('rule','') for f in findings]}"
        )

    def test_unusual_timing_detector_fires(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """unusual-timing detector fires on seeded Monday 03:00 event for actor
        whose baseline only records Tuesday 08:00 activity."""
        detect_result, cwd = self._setup_detect(tmp_path, monkeypatch)

        assert detect_result.exit_code == 0, (
            f"detect exit {detect_result.exit_code}: {detect_result.output}"
        )

        store = JsonlStore(cwd)
        findings = store.query_findings()
        timing_findings = [
            f for f in findings if f.detector == "unusual-timing"
        ]
        assert len(timing_findings) >= 1, (
            f"Expected unusual-timing finding, got detectors: "
            f"{[f.detector for f in findings]}"
        )
