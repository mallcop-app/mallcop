"""Tests for init --pro output: appetite estimate and donut plan recommendation.

The CLI now calls ProClient.recommend_plan() (service API) instead of local
appetite.py. Tests mock the ProClient to avoid live API calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from mallcop.cli import cli


_MOCK_RECOMMENDATION = {
    "recommended_tier": "starter",
    "estimated_donuts": 67,
    "headroom_pct": 55.3,
    "tiers": [
        {"name": "starter", "donuts": 150, "price": "$4.99/mo"},
        {"name": "pro",     "donuts": 500, "price": "$19.99/mo"},
        {"name": "team",    "donuts": 1500, "price": "$79.99/mo"},
    ],
}

_MOCK_RECOMMENDATION_MULTI = {
    "recommended_tier": "starter",
    "estimated_donuts": 110,
    "headroom_pct": 26.7,
    "tiers": [
        {"name": "starter", "donuts": 150, "price": "$4.99/mo"},
        {"name": "pro",     "donuts": 500, "price": "$19.99/mo"},
        {"name": "team",    "donuts": 1500, "price": "$79.99/mo"},
    ],
}

_MOCK_RECOMMENDATION_ZERO = {
    "recommended_tier": "starter",
    "estimated_donuts": 0,
    "headroom_pct": 100.0,
    "tiers": [
        {"name": "starter", "donuts": 150, "price": "$4.99/mo"},
        {"name": "pro",     "donuts": 500, "price": "$19.99/mo"},
        {"name": "team",    "donuts": 1500, "price": "$79.99/mo"},
    ],
}


def _make_mocks(connector_names=("azure",), recommendation=None):
    """Build mocks for init --pro tests."""
    if recommendation is None:
        recommendation = _MOCK_RECOMMENDATION

    connectors_dict = {}
    for name in connector_names:
        connectors_dict[name] = MagicMock(
            name=name,
            path=Path("/tmp") / name,
            class_name=f"{name.title()}Connector",
            module="connector",
        )

    mock_discover = MagicMock(return_value={
        "connectors": connectors_dict,
        "detectors": {},
        "actors": {},
    })

    mock_connector = MagicMock()
    mock_connector.discover.return_value = MagicMock(
        available=True,
        resources=["sub-123"],
        suggested_config={"subscription_ids": ["sub-123"]},
        missing_credentials=[],
        notes=["Found 1 subscription"],
    )

    mock_git = MagicMock(returncode=0, stdout="test@example.com")
    mock_client = MagicMock()
    mock_client.create_account.return_value = ("acct_123", "jwt.token")
    mock_client.recommend_plan.return_value = recommendation
    mock_client.subscribe.return_value = "https://checkout.polar.sh/test"

    return mock_discover, mock_connector, mock_git, mock_client


class TestProInitAppetiteOutput:
    """init --pro output includes appetite estimate and donut plan recommendation."""

    def _run_pro_init(self, tmp_path, connector_names=("azure",), recommendation=None):
        runner = CliRunner()
        mock_discover, mock_connector, mock_git, mock_client = _make_mocks(
            connector_names, recommendation=recommendation
        )

        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"):
                result = runner.invoke(cli, ["init", "--pro"])

        return result

    def test_pro_output_has_estimated_appetite_donuts(self, tmp_path):
        result = self._run_pro_init(tmp_path)
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output}"
        data = json.loads(result.output)
        pro = data["pro"]
        assert "estimated_appetite_donuts" in pro
        assert isinstance(pro["estimated_appetite_donuts"], int)
        assert pro["estimated_appetite_donuts"] >= 0

    def test_pro_output_has_plan_headroom_pct(self, tmp_path):
        result = self._run_pro_init(tmp_path)
        data = json.loads(result.output)
        pro = data["pro"]
        assert "plan_headroom_pct" in pro
        assert pro["plan_headroom_pct"] >= 0.0

    def test_pro_output_recommended_plan_is_valid_tier(self, tmp_path):
        result = self._run_pro_init(tmp_path)
        data = json.loads(result.output)
        valid_tiers = {"starter", "pro", "team"}
        assert data["pro"]["recommended_plan"] in valid_tiers

    def test_pro_output_plan_price_is_dollar_string(self, tmp_path):
        result = self._run_pro_init(tmp_path)
        data = json.loads(result.output)
        price = data["pro"]["plan_price"]
        assert "$" in price
        assert "/mo" in price

    def test_zero_connectors_gets_starter_plan(self, tmp_path):
        """When no connectors discovered, appetite is 0, recommend starter (smallest paid tier)."""
        runner = CliRunner()
        mock_discover = MagicMock(return_value={
            "connectors": {},
            "detectors": {},
            "actors": {},
        })
        mock_git = MagicMock(returncode=0, stdout="test@example.com")
        mock_client = MagicMock()
        mock_client.create_account.return_value = ("acct_123", "jwt.token")
        mock_client.recommend_plan.return_value = _MOCK_RECOMMENDATION_ZERO
        mock_client.subscribe.return_value = "https://checkout.polar.sh/test"

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("mallcop.cli.instantiate_connector", return_value=None), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"):
                result = runner.invoke(cli, ["init", "--pro"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        pro = data["pro"]
        assert pro["estimated_appetite_donuts"] == 0
        assert pro["recommended_plan"] == "starter"

    def test_appetite_scales_with_connector_count(self, tmp_path):
        """More connectors → higher appetite estimate (reflected in service response)."""
        result_one = self._run_pro_init(
            tmp_path, connector_names=("azure",), recommendation=_MOCK_RECOMMENDATION
        )
        result_multi = self._run_pro_init(
            tmp_path, connector_names=("azure", "github"),
            recommendation=_MOCK_RECOMMENDATION_MULTI,
        )

        data_one = json.loads(result_one.output)
        data_multi = json.loads(result_multi.output)

        # Multi-connector appetite should be higher
        appetite_one = data_one["pro"]["estimated_appetite_donuts"]
        appetite_multi = data_multi["pro"]["estimated_appetite_donuts"]
        assert appetite_multi > appetite_one

    def test_recommend_plan_called_with_connector_list(self, tmp_path):
        """ProClient.recommend_plan is called with the discovered connector names."""
        runner = CliRunner()
        mock_discover, mock_connector, mock_git, mock_client = _make_mocks(
            connector_names=("azure", "github")
        )

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"):
                result = runner.invoke(cli, ["init", "--pro"])

        assert result.exit_code == 0
        mock_client.recommend_plan.assert_called_once()
        call_args = mock_client.recommend_plan.call_args[0][0]
        assert set(call_args) == {"azure", "github"}

    def test_service_unreachable_returns_error(self, tmp_path):
        """When recommend_plan raises RuntimeError, CLI outputs error."""
        runner = CliRunner()
        mock_discover, mock_connector, mock_git, mock_client = _make_mocks()
        mock_client.recommend_plan.side_effect = RuntimeError(
            "Could not reach mallcop.app — try again or visit mallcop.app/pricing"
        )

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"):
                result = runner.invoke(cli, ["init", "--pro"])

        # Error output should mention the issue
        assert "error" in result.output.lower() or "error" in (result.stderr or "").lower()


# ---------------------------------------------------------------------------
# mallcop-ak1n.1.18: email disclosure and validation in _setup_pro
# ---------------------------------------------------------------------------

class TestProInitEmailDisclosure:
    """_setup_pro shows the email to the user before sending it to the API,
    and validates email format. (mallcop-ak1n.1.18)"""

    def _run_pro_init_with_email(self, tmp_path, email: str):
        runner = CliRunner()
        mock_discover, mock_connector, mock_git, mock_client = _make_mocks()
        mock_git.stdout = email

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"), \
                 patch("sys.stdin.isatty", return_value=False):
                result = runner.invoke(cli, ["init", "--pro"])
        return result, mock_client

    def test_email_shown_to_user_before_sending(self, tmp_path):
        """CLI prints the email to stderr before creating the account in TTY mode.

        The disclosure message includes the email address so the user knows what
        is being sent to api.mallcop.dev before it happens.
        """
        runner = CliRunner()
        mock_discover, mock_connector, mock_git, mock_client = _make_mocks()
        mock_git.stdout = "user@example.com"

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"), \
                 patch("sys.stdin.isatty", return_value=True), \
                 patch("click.prompt", return_value="Y"):
                result = runner.invoke(cli, ["init", "--pro"])

        # Email address must appear in output (disclosure message goes to stderr/mixed)
        assert "user@example.com" in result.output

    def test_invalid_email_format_returns_error(self, tmp_path):
        """If git config user.email is not a valid email address, CLI returns error."""
        result, mock_client = self._run_pro_init_with_email(tmp_path, "not-an-email")
        # Should fail with an error, not attempt to call create_account
        assert "error" in result.output.lower()
        mock_client.create_account.assert_not_called()

    def test_email_without_domain_rejected(self, tmp_path):
        """Email without domain (e.g. 'user@') is rejected before hitting the API."""
        result, mock_client = self._run_pro_init_with_email(tmp_path, "user@")
        # create_account must not be called with a malformed email
        mock_client.create_account.assert_not_called()

    def test_valid_email_proceeds_without_error(self, tmp_path):
        """A properly formatted email address proceeds normally."""
        result, _mock_client = self._run_pro_init_with_email(tmp_path, "baron@example.com")
        assert result.exit_code == 0, f"Exit {result.exit_code}: {result.output!r}"
        data = json.loads(result.output)
        assert data.get("status") == "ok"

