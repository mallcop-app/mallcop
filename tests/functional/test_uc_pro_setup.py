"""Functional test: mallcop init --pro end-to-end flow."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from mallcop.cli import cli


class TestProSetup:
    """Test the full init --pro flow with mocked services."""

    def _make_mocks(self, email: str = "test@example.com"):
        """Build common mocks for init --pro tests."""
        mock_client = MagicMock()
        mock_client.create_account.return_value = ("acct_test123", "jwt.token.here")
        mock_client.subscribe.return_value = "https://checkout.stripe.com/test"

        mock_git = MagicMock()
        mock_git.returncode = 0
        mock_git.stdout = email

        mock_discover = MagicMock(return_value={
            "connectors": {
                "azure": MagicMock(
                    name="azure",
                    path=Path("/tmp/azure"),
                    class_name="AzureConnector",
                    module="connector",
                ),
            },
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

        return mock_client, mock_git, mock_discover, mock_connector

    def test_init_pro_creates_account_and_writes_config(self, tmp_path):
        """Full init --pro: discover -> account -> subscribe -> config."""
        runner = CliRunner()
        mock_client, mock_git, mock_discover, mock_connector = self._make_mocks()

        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client) as mock_cls, \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"):

                result = runner.invoke(cli, ["init", "--pro"])

            assert result.exit_code == 0, f"CLI failed: {result.output}"

            config_path = Path(td) / "mallcop.yaml"
            assert config_path.exists()
            config = yaml.safe_load(config_path.read_text())

            assert "pro" in config
            assert config["pro"]["account_id"] == "acct_test123"
            assert config["pro"]["service_token"] == "jwt.token.here"
            assert config["pro"]["inference_url"] == "https://api.mallcop.dev"

            # Output should contain pro section
            output = json.loads(result.output)
            assert output["status"] == "ok"
            assert "pro" in output
            assert output["pro"]["account_id"] == "acct_test123"
            assert output["pro"]["checkout_url"] == "https://checkout.stripe.com/test"

    def test_init_pro_recommends_small_plan_for_few_connectors(self, tmp_path):
        """With 1 connector, recommend small plan."""
        runner = CliRunner()
        mock_client, mock_git, mock_discover, mock_connector = self._make_mocks()

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"):

                result = runner.invoke(cli, ["init", "--pro"])

            output = json.loads(result.output)
            assert output["pro"]["recommended_plan"] == "small"
            assert output["pro"]["plan_price"] == "$29/mo"

    def test_init_pro_recommends_medium_plan_for_several_connectors(self, tmp_path):
        """With 3-5 connectors, recommend medium plan."""
        runner = CliRunner()
        mock_client, mock_git, _, mock_connector = self._make_mocks()

        # 4 connectors
        connector_plugins = {}
        for name in ["azure", "github", "m365", "container-logs"]:
            connector_plugins[name] = MagicMock(
                name=name, path=Path(f"/tmp/{name}"),
                class_name="X", module="c",
            )

        mock_discover = MagicMock(return_value={
            "connectors": connector_plugins,
            "detectors": {},
            "actors": {},
        })

        # All connectors available
        mock_connector.discover.return_value = MagicMock(
            available=True, resources=[], suggested_config={},
            missing_credentials=[], notes=[],
        )

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"):

                result = runner.invoke(cli, ["init", "--pro"])

            output = json.loads(result.output)
            assert output["pro"]["recommended_plan"] == "medium"
            assert output["pro"]["plan_price"] == "$59/mo"

    def test_init_without_pro_no_pro_section(self, tmp_path):
        """Regular init (no --pro) should not create pro config."""
        runner = CliRunner()
        _, _, mock_discover, mock_connector = self._make_mocks()

        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.cli.EnvSecretProvider"):

                result = runner.invoke(cli, ["init"])

            assert result.exit_code == 0
            output = json.loads(result.output)
            assert "pro" not in output

            config = yaml.safe_load((Path(td) / "mallcop.yaml").read_text())
            assert "pro" not in config

    def test_init_pro_already_registered(self, tmp_path):
        """init --pro with already-registered email shows error on stderr."""
        runner = CliRunner(mix_stderr=False)
        mock_client, mock_git, mock_discover, mock_connector = self._make_mocks()
        mock_client.create_account.side_effect = ValueError("Email already registered")

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"):

                result = runner.invoke(cli, ["init", "--pro"])

            # Pro error goes to stderr, normal init output still works
            assert "already registered" in result.stderr_bytes.decode().lower()
            # Normal init output should still appear (pro section absent)
            output = json.loads(result.output)
            assert "pro" not in output

    def test_init_pro_no_email(self, tmp_path):
        """init --pro without git email shows error."""
        runner = CliRunner(mix_stderr=False)
        mock_client, _, mock_discover, mock_connector = self._make_mocks()

        mock_git_fail = MagicMock(returncode=1, stdout="")

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git_fail), \
                 patch("mallcop.cli.EnvSecretProvider"):

                result = runner.invoke(cli, ["init", "--pro"])

            assert "email" in result.stderr_bytes.decode().lower()
            output = json.loads(result.output)
            assert "pro" not in output

    def test_init_pro_removes_llm_section(self, tmp_path):
        """init --pro removes BYOK llm section from config."""
        runner = CliRunner()
        mock_client, mock_git, mock_discover, mock_connector = self._make_mocks()

        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"):

                result = runner.invoke(cli, ["init", "--pro"])

            config = yaml.safe_load((Path(td) / "mallcop.yaml").read_text())
            assert "llm" not in config
            assert "pro" in config

    def test_init_pro_subscribe_failure_still_writes_config(self, tmp_path):
        """If subscribe fails, still write pro config (just no checkout_url)."""
        runner = CliRunner()
        mock_client, mock_git, mock_discover, mock_connector = self._make_mocks()
        mock_client.subscribe.side_effect = Exception("Network error")

        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            with patch("mallcop.cli.instantiate_connector", return_value=mock_connector), \
                 patch("mallcop.cli.discover_plugins", mock_discover), \
                 patch("mallcop.pro.ProClient", return_value=mock_client), \
                 patch("subprocess.run", return_value=mock_git), \
                 patch("mallcop.cli.EnvSecretProvider"):

                result = runner.invoke(cli, ["init", "--pro"])

            output = json.loads(result.output)
            assert output["pro"]["account_id"] == "acct_test123"
            assert "checkout_url" not in output["pro"]
            assert output["pro"]["next_step"] == "Run: mallcop watch"

            config = yaml.safe_load((Path(td) / "mallcop.yaml").read_text())
            assert config["pro"]["account_id"] == "acct_test123"


class TestBuildLlmClientProRouting:
    """Test that build_llm_client auto-routes to ManagedClient with pro config."""

    def test_returns_managed_client_with_pro_config(self):
        """build_llm_client returns ManagedClient when pro config present."""
        from mallcop.config import ProConfig
        from mallcop.llm import ManagedClient, build_llm_client

        pro = ProConfig(
            account_id="acct_123",
            service_token="jwt.token.here",
            inference_url="https://api.mallcop.dev",
        )

        client = build_llm_client(None, pro_config=pro)
        assert isinstance(client, ManagedClient)

    def test_pro_config_takes_priority_over_byok(self):
        """Pro config should override BYOK llm config."""
        from mallcop.config import LLMConfig, ProConfig
        from mallcop.llm import ManagedClient, build_llm_client

        llm = LLMConfig(provider="anthropic", api_key="sk-test", default_model="haiku")
        pro = ProConfig(
            account_id="acct_123",
            service_token="jwt.token.here",
            inference_url="https://api.mallcop.dev",
        )

        client = build_llm_client(llm, pro_config=pro)
        assert isinstance(client, ManagedClient)

    def test_no_pro_config_falls_back_to_anthropic(self):
        """Without pro config, build_llm_client behaves as before."""
        from mallcop.config import LLMConfig
        from mallcop.llm import AnthropicClient, build_llm_client

        llm = LLMConfig(provider="anthropic", api_key="sk-test", default_model="haiku")

        client = build_llm_client(llm)
        assert isinstance(client, AnthropicClient)

    def test_no_pro_no_llm_returns_none(self):
        """Without pro or llm config, returns None."""
        from mallcop.llm import build_llm_client

        client = build_llm_client(None)
        assert client is None


class TestProConfigParsing:
    """Test that pro section in mallcop.yaml is parsed correctly."""

    def test_load_config_with_pro_section(self, tmp_path):
        """load_config parses pro section into ProConfig."""
        from mallcop.config import ProConfig, load_config

        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "pro": {
                "account_id": "acct_abc",
                "service_token": "my-token",
                "account_url": "https://api.mallcop.dev",
                "inference_url": "https://api.mallcop.dev",
            },
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))

        config = load_config(tmp_path)
        assert config.pro is not None
        assert isinstance(config.pro, ProConfig)
        assert config.pro.account_id == "acct_abc"
        assert config.pro.service_token == "my-token"

    def test_load_config_without_pro_section(self, tmp_path):
        """load_config returns pro=None when no pro section."""
        from mallcop.config import load_config

        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))

        config = load_config(tmp_path)
        assert config.pro is None

    def test_load_config_pro_with_env_var_token(self, tmp_path, monkeypatch):
        """Pro service_token can use ${VAR} references."""
        from mallcop.config import load_config

        monkeypatch.setenv("MALLCOP_PRO_TOKEN", "resolved-jwt")
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "pro": {
                "account_id": "acct_xyz",
                "service_token": "${MALLCOP_PRO_TOKEN}",
                "account_url": "https://api.mallcop.dev",
                "inference_url": "https://api.mallcop.dev",
            },
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))

        config = load_config(tmp_path)
        assert config.pro is not None
        assert config.pro.service_token == "resolved-jwt"
