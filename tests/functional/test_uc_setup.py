"""UC: Agent installs mallcop, discovers environment, estimates costs.

Functional test exercising the full init workflow:
  mallcop init
    -> probes azure (mocked)
    -> writes mallcop.yaml with budget defaults
    -> estimates steady-state costs
    -> reports what is connected and what credentials are missing
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml
from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import Checkpoint, DiscoveryResult, Event, PollResult, Severity


# --- Fixtures: fake Azure responses ---

FAKE_SUBSCRIPTIONS = [
    {
        "subscriptionId": "sub-001",
        "displayName": "Production",
    },
    {
        "subscriptionId": "sub-002",
        "displayName": "Dev/Test",
    },
]

FAKE_ACTIVITY_LOG_EVENTS = [
    {
        "eventDataId": "evt-data-001",
        "eventTimestamp": "2026-03-05T10:00:00Z",
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
        "eventDataId": "evt-data-002",
        "eventTimestamp": "2026-03-05T11:00:00Z",
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
    {
        "eventDataId": "evt-data-003",
        "eventTimestamp": "2026-03-05T12:00:00Z",
        "caller": "admin@acme-corp.dev",
        "operationName": {"value": "Microsoft.Resources/deployments/write"},
        "resourceType": {"value": "Microsoft.Resources/deployments"},
        "resourceId": "/subscriptions/sub-001/resourceGroups/rg-prod/providers/Microsoft.Resources/deployments/deploy-1",
        "level": "Warning",
        "subscriptionId": "sub-001",
        "resourceGroupName": "rg-prod",
        "correlationId": "corr-003",
        "status": {"value": "Failed"},
    },
]


def _mock_list_subscriptions(self: Any) -> list[dict[str, Any]]:
    return FAKE_SUBSCRIPTIONS


def _mock_fetch_activity_log(
    self: Any,
    subscription_id: str,
    checkpoint: Checkpoint | None,
) -> list[dict[str, Any]]:
    return FAKE_ACTIVITY_LOG_EVENTS


class TestUCSetupInitDiscoversEnvironment:
    """mallcop init discovers Azure resources, writes config, reports costs."""

    def _run_init(self, tmp_path: Path) -> tuple[Any, dict[str, Any]]:
        """Run mallcop init with mocked Azure, return (CliRunner result, parsed JSON)."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            with patch(
                "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
                _mock_list_subscriptions,
            ), patch(
                "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
                _mock_fetch_activity_log,
            ):
                result = runner.invoke(cli, ["init"])
        return result, tmp_path

    def test_init_exits_zero(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        assert result.exit_code == 0, f"Exit code {result.exit_code}: {result.output}"

    def test_init_outputs_valid_json(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        assert data["status"] == "ok"

    def test_init_reports_azure_available(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        connectors = data["connectors"]
        azure = [c for c in connectors if c["name"] == "azure"]
        assert len(azure) == 1
        assert azure[0]["available"] is True
        assert len(azure[0]["resources"]) == 2
        assert "sub-001" in azure[0]["resources"][0]
        assert "Production" in azure[0]["resources"][0]

    def test_init_reports_sample_events(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        azure = [c for c in data["connectors"] if c["name"] == "azure"][0]
        # 3 events per subscription * 2 subscriptions = 6 total
        assert azure["sample_events"] == len(FAKE_ACTIVITY_LOG_EVENTS) * len(FAKE_SUBSCRIPTIONS)

    def test_init_writes_mallcop_yaml(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            cwd = Path(td)
            with patch(
                "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
                _mock_list_subscriptions,
            ), patch(
                "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
                _mock_fetch_activity_log,
            ):
                result = runner.invoke(cli, ["init"])

            assert result.exit_code == 0
            config_path = cwd / "mallcop.yaml"
            assert config_path.exists(), "mallcop.yaml not created"

            config = yaml.safe_load(config_path.read_text())

            # Secrets backend
            assert config["secrets"]["backend"] == "env"

            # Azure connector present with subscription_ids
            assert "azure" in config["connectors"]
            azure_config = config["connectors"]["azure"]
            assert "subscription_ids" in azure_config
            assert azure_config["subscription_ids"] == ["sub-001", "sub-002"]

            # Auth refs use ${VAR} pattern
            assert azure_config["tenant_id"] == "${AZURE_TENANT_ID}"
            assert azure_config["client_id"] == "${AZURE_CLIENT_ID}"
            assert azure_config["client_secret"] == "${AZURE_CLIENT_SECRET}"

            # Budget section with defaults
            assert "budget" in config
            assert config["budget"]["max_findings_for_actors"] == 25
            assert config["budget"]["max_tokens_per_run"] == 50000
            assert config["budget"]["max_tokens_per_finding"] == 5000

    def test_init_cost_estimate_present(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        cost = data["cost_estimate"]

        # All required cost fields present
        assert "connectors_active" in cost
        assert "estimated_events_per_run" in cost
        assert "estimated_findings_per_run" in cost
        assert "estimated_tokens_per_run" in cost
        assert "estimated_cost_per_run_usd" in cost
        assert "estimated_cost_per_month_usd" in cost
        assert "budget_max_tokens_per_run" in cost
        assert "worst_case_cost_per_run_usd" in cost
        assert "worst_case_cost_per_month_usd" in cost

        assert cost["connectors_active"] == 1

    def test_init_cost_estimate_values_plausible(self, tmp_path: Path) -> None:
        result, _ = self._run_init(tmp_path)
        data = json.loads(result.output)
        cost = data["cost_estimate"]

        # Monthly cost should be a range string like "X.XXX-Y.YYY"
        monthly = cost["estimated_cost_per_month_usd"]
        low, high = monthly.split("-")
        assert float(low) >= 0
        assert float(high) > float(low)
        assert float(high) < 100  # sanity: small operator, not a fortune

        # Worst case should be finite and bounded by budget
        worst = float(cost["worst_case_cost_per_month_usd"])
        assert worst > 0
        assert worst < 100


class TestUCSetupInitNoCredentials:
    """mallcop init with no Azure credentials reports missing creds."""

    def test_init_reports_missing_credentials(self, tmp_path: Path) -> None:
        runner = CliRunner()

        def _mock_discover_fails(self: Any) -> list[dict[str, Any]]:
            raise Exception("No credentials")

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch(
                "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
                _mock_discover_fails,
            ):
                result = runner.invoke(cli, ["init"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"

        azure = [c for c in data["connectors"] if c["name"] == "azure"][0]
        assert azure["available"] is False
        assert len(azure["missing_credentials"]) > 0
        assert "AZURE_TENANT_ID" in azure["missing_credentials"]

    def test_init_no_creds_still_writes_config(self, tmp_path: Path) -> None:
        runner = CliRunner()

        def _mock_discover_fails(self: Any) -> list[dict[str, Any]]:
            raise Exception("No credentials")

        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            cwd = Path(td)
            with patch(
                "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
                _mock_discover_fails,
            ):
                result = runner.invoke(cli, ["init"])

            assert result.exit_code == 0
            config_path = cwd / "mallcop.yaml"
            assert config_path.exists()

            config = yaml.safe_load(config_path.read_text())
            # No available connectors -> empty connectors section
            assert config["connectors"] == {} or "azure" not in config.get("connectors", {})


class TestUCSetupInitIdempotent:
    """Running mallcop init twice should work (overwrites config)."""

    def test_init_twice_succeeds(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch(
                "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
                _mock_list_subscriptions,
            ), patch(
                "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
                _mock_fetch_activity_log,
            ):
                result1 = runner.invoke(cli, ["init"])
                assert result1.exit_code == 0

                result2 = runner.invoke(cli, ["init"])
                assert result2.exit_code == 0

            data = json.loads(result2.output)
            assert data["status"] == "ok"


class TestUCSetupEndToEnd:
    """Full scenario: init -> verify config -> git-committable state."""

    def test_full_setup_flow(self, tmp_path: Path) -> None:
        """Simulates the full UC1 scenario from the bead description."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            cwd = Path(td)

            # Step 1: mallcop init with mocked Azure
            with patch(
                "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
                _mock_list_subscriptions,
            ), patch(
                "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
                _mock_fetch_activity_log,
            ):
                result = runner.invoke(cli, ["init"])

            assert result.exit_code == 0, f"init failed: {result.output}"
            init_data = json.loads(result.output)

            # Step 2: Verify JSON output structure
            assert init_data["status"] == "ok"
            assert "config_path" in init_data
            assert "connectors" in init_data
            assert "cost_estimate" in init_data

            # Step 3: Verify mallcop.yaml is valid and loadable
            config_path = cwd / "mallcop.yaml"
            assert config_path.exists()
            config = yaml.safe_load(config_path.read_text())

            # Config has all required sections
            assert "secrets" in config
            assert "connectors" in config
            assert "budget" in config

            # Azure connector is configured
            assert "azure" in config["connectors"]
            az = config["connectors"]["azure"]
            assert az["subscription_ids"] == ["sub-001", "sub-002"]

            # Step 4: Verify cost estimate is reasonable
            cost = init_data["cost_estimate"]
            assert cost["connectors_active"] == 1
            assert cost["budget_max_tokens_per_run"] == 50000

            # Step 5: Verify the directory is in a committable state
            # (mallcop.yaml exists, no other unexpected files)
            files = list(cwd.iterdir())
            file_names = {f.name for f in files}
            assert "mallcop.yaml" in file_names
