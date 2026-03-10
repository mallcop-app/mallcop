"""Tests for cost estimation logic.

Validates _estimate_costs produces correct calculations for sample scenarios.
"""

from __future__ import annotations

from mallcop.cost_estimator import estimate_costs as _estimate_costs, COST_PER_1K_TOKENS_USD as _COST_PER_1K_TOKENS_USD
from mallcop.config import BudgetConfig


class TestEstimateCostsBasic:
    """Core estimation logic with default budget."""

    def test_returns_all_required_fields(self) -> None:
        budget = BudgetConfig()
        result = _estimate_costs(num_connectors=1, sample_event_count=50, budget=budget)
        required = [
            "connectors_active",
            "estimated_events_per_run",
            "estimated_findings_per_run",
            "estimated_tokens_per_run",
            "estimated_cost_per_run_usd",
            "estimated_cost_per_month_usd",
            "budget_max_tokens_per_run",
            "budget_max_findings_for_actors",
            "budget_max_tokens_per_finding",
            "worst_case_cost_per_run_usd",
            "worst_case_cost_per_month_usd",
        ]
        for field in required:
            assert field in result, f"Missing field: {field}"

    def test_connectors_active_matches_input(self) -> None:
        budget = BudgetConfig()
        result = _estimate_costs(num_connectors=3, sample_event_count=50, budget=budget)
        assert result["connectors_active"] == 3

    def test_budget_fields_reflect_config(self) -> None:
        budget = BudgetConfig(
            max_findings_for_actors=10,
            max_tokens_per_run=20000,
            max_tokens_per_finding=2000,
        )
        result = _estimate_costs(num_connectors=1, sample_event_count=50, budget=budget)
        assert result["budget_max_tokens_per_run"] == 20000
        assert result["budget_max_findings_for_actors"] == 10
        assert result["budget_max_tokens_per_finding"] == 2000


class TestEstimateCostsRanges:
    """Event/finding/token ranges are sensible."""

    def test_events_range_format(self) -> None:
        budget = BudgetConfig()
        result = _estimate_costs(num_connectors=1, sample_event_count=50, budget=budget)
        events = result["estimated_events_per_run"]
        parts = events.split("-")
        assert len(parts) == 2
        low, high = int(parts[0]), int(parts[1])
        assert low > 0
        assert high >= low

    def test_findings_range_format(self) -> None:
        budget = BudgetConfig()
        result = _estimate_costs(num_connectors=1, sample_event_count=50, budget=budget)
        findings = result["estimated_findings_per_run"]
        parts = findings.split("-")
        assert len(parts) == 2
        low, high = int(parts[0]), int(parts[1])
        assert low >= 0
        assert high >= low

    def test_cost_per_run_is_range(self) -> None:
        budget = BudgetConfig()
        result = _estimate_costs(num_connectors=1, sample_event_count=50, budget=budget)
        cost_range = result["estimated_cost_per_run_usd"]
        low_s, high_s = cost_range.split("-")
        low, high = float(low_s), float(high_s)
        assert low >= 0
        assert high >= low

    def test_monthly_cost_is_range(self) -> None:
        budget = BudgetConfig()
        result = _estimate_costs(num_connectors=1, sample_event_count=50, budget=budget)
        monthly = result["estimated_cost_per_month_usd"]
        low_s, high_s = monthly.split("-")
        low, high = float(low_s), float(high_s)
        assert low >= 0
        assert high >= low


class TestEstimateCostsWorstCase:
    """Worst-case calculations use budget ceilings."""

    def test_worst_case_per_run_uses_max_tokens(self) -> None:
        budget = BudgetConfig(max_tokens_per_run=50000)
        result = _estimate_costs(num_connectors=1, sample_event_count=50, budget=budget)
        expected = (50000 / 1000) * _COST_PER_1K_TOKENS_USD
        assert result["worst_case_cost_per_run_usd"] == f"{expected:.4f}"

    def test_worst_case_per_month_is_4_runs_per_day(self) -> None:
        budget = BudgetConfig(max_tokens_per_run=50000)
        result = _estimate_costs(num_connectors=1, sample_event_count=50, budget=budget)
        worst_run = (50000 / 1000) * _COST_PER_1K_TOKENS_USD
        expected_month = worst_run * 4 * 30
        assert result["worst_case_cost_per_month_usd"] == f"{expected_month:.3f}"


class TestEstimateCostsEdgeCases:
    """Edge cases: zero events, zero connectors."""

    def test_zero_sample_events(self) -> None:
        budget = BudgetConfig()
        result = _estimate_costs(num_connectors=1, sample_event_count=0, budget=budget)
        # Should still produce valid output with fallback ranges
        events = result["estimated_events_per_run"]
        parts = events.split("-")
        assert len(parts) == 2
        assert int(parts[0]) >= 0

    def test_zero_connectors(self) -> None:
        budget = BudgetConfig()
        result = _estimate_costs(num_connectors=0, sample_event_count=0, budget=budget)
        assert result["connectors_active"] == 0

    def test_large_sample_capped_by_budget(self) -> None:
        budget = BudgetConfig(max_tokens_per_run=10000, max_findings_for_actors=5)
        result = _estimate_costs(num_connectors=1, sample_event_count=1000, budget=budget)
        # Token high estimate should be capped at budget max
        tokens = result["estimated_tokens_per_run"]
        parts = tokens.split("-")
        high = int(parts[1])
        assert high <= budget.max_tokens_per_run


class TestEstimateCostsInitOutput:
    """mallcop init output references the workflow example and lists secrets."""

    def test_init_output_has_workflow_reference(self) -> None:
        """Init output JSON should include a reference to the example workflow."""
        import json
        from pathlib import Path
        from unittest.mock import patch
        from click.testing import CliRunner
        from mallcop.cli import cli

        runner = CliRunner()

        def _mock_list_subs(self):
            return [{"subscriptionId": "sub-1", "displayName": "Test"}]

        def _mock_fetch_log(self, sub_id, checkpoint):
            return []

        with runner.isolated_filesystem() as td:
            with patch(
                "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
                _mock_list_subs,
            ), patch(
                "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
                _mock_fetch_log,
            ):
                result = runner.invoke(cli, ["init"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "workflow_example" in data, "Init output should include workflow_example reference"
        assert "github-actions" in data["workflow_example"].lower() or "github" in data["workflow_example"].lower()

    def test_init_output_lists_required_secrets(self) -> None:
        """Init output JSON should list which secrets need to be configured."""
        import json
        from pathlib import Path
        from unittest.mock import patch
        from click.testing import CliRunner
        from mallcop.cli import cli

        runner = CliRunner()

        def _mock_list_subs(self):
            return [{"subscriptionId": "sub-1", "displayName": "Test"}]

        def _mock_fetch_log(self, sub_id, checkpoint):
            return []

        with runner.isolated_filesystem() as td:
            with patch(
                "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
                _mock_list_subs,
            ), patch(
                "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
                _mock_fetch_log,
            ):
                result = runner.invoke(cli, ["init"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "required_secrets" in data, "Init output should include required_secrets"
        secrets = data["required_secrets"]
        assert isinstance(secrets, list)
        assert "AZURE_TENANT_ID" in secrets
        assert "AZURE_CLIENT_ID" in secrets
        assert "AZURE_CLIENT_SECRET" in secrets
