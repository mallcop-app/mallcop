"""Installation path tests: manual pip install + mallcop init.

Covers §13.3 of docs/e2e-superintegration-design.md.

Tests use Click's CliRunner (in-process) so that the `responses` library can
intercept HTTP calls made by connector discover/poll. No per-test venv.
mallcop must be installed in the current Python env (pip install -e ".[dev]").

Mark: install_push (runs on every push to main).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
import responses as responses_lib
import yaml
from click.testing import CliRunner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _runner() -> CliRunner:
    return CliRunner()


def _invoke_init(runner: CliRunner, tmp_path: Path, env: dict | None = None):
    from mallcop.cli import init
    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        env_override = {"MALLCOP_NO_PRO": "1", **(env or {})}
        result = runner.invoke(init, [], env=env_override, catch_exceptions=False)
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.install_push
def test_mallcop_init_creates_config(tmp_path):
    """mallcop init creates mallcop.yaml in the working directory."""
    runner = _runner()
    from mallcop.cli import init

    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.GET, "https://api.github.com/user",
                 json={"login": "test-user", "id": 1}, status=200)
        rsps.add(responses_lib.GET, re.compile(r"https://api.github.com/.*"),
                 json={"data": []}, status=200)
        with runner.isolated_filesystem(temp_dir=str(tmp_path)):
            result = runner.invoke(
                init, [],
                env={"GITHUB_TOKEN": "ghs_fake_test_token"},
                catch_exceptions=False,
            )
            config_exists = Path("mallcop.yaml").exists()

    assert result.exit_code == 0, f"init failed (exit {result.exit_code}): {result.output}"
    assert config_exists, "mallcop.yaml was not created"


@pytest.mark.install_push
def test_config_structure_correct(tmp_path):
    """mallcop.yaml has required top-level keys: secrets, connectors, budget."""
    runner = _runner()
    from mallcop.cli import init

    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.GET, "https://api.github.com/user",
                 json={"login": "test-user", "id": 1}, status=200)
        rsps.add(responses_lib.GET, re.compile(r"https://api.github.com/.*"),
                 json={"data": []}, status=200)
        with runner.isolated_filesystem(temp_dir=str(tmp_path)):
            result = runner.invoke(
                init, [],
                env={"GITHUB_TOKEN": "ghs_fake_test_token"},
                catch_exceptions=False,
            )
            config_path = Path("mallcop.yaml")
            assert config_path.exists(), "mallcop.yaml was not created"
            config = yaml.safe_load(config_path.read_text())

    assert result.exit_code == 0
    assert "secrets" in config, "missing 'secrets' key"
    assert "connectors" in config, "missing 'connectors' key"
    assert "budget" in config, "missing 'budget' key"
    assert config["secrets"]["backend"] == "env", "secrets.backend must be 'env'"


@pytest.mark.install_push
def test_no_connectors_with_no_creds(tmp_path):
    """With no connector credentials set, init produces empty connectors and exits 0."""
    runner = _runner()
    from mallcop.cli import init

    # Unset all connector env vars by overriding with empty env
    clean_env = {
        k: v for k, v in os.environ.items()
        if k not in {
            "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID", "AZURE_CLIENT_ID",
            "VERCEL_TOKEN", "SUPABASE_URL", "M365_TENANT_ID",
            "AZURE_TENANT_ID", "ENTRA_TENANT_ID",
        }
    }

    with runner.isolated_filesystem(temp_dir=str(tmp_path)):
        result = runner.invoke(init, [], env=clean_env, catch_exceptions=False)
        config_path = Path("mallcop.yaml")
        assert config_path.exists(), "mallcop.yaml was not created"
        config = yaml.safe_load(config_path.read_text())

    assert result.exit_code == 0, (
        f"init crashed with no creds (exit {result.exit_code}): {result.output}"
    )
    connectors = config.get("connectors", {})
    assert connectors == {} or len(connectors) == 0, (
        f"Expected no connectors with no creds, got: {list(connectors.keys())}"
    )


@pytest.mark.install_push
def test_watch_dry_run_succeeds(tmp_path, minimal_mallcop_config):
    """mallcop watch --dry-run exits 0 with a minimal config and mocked GitHub API."""
    runner = _runner()
    from mallcop.cli import watch

    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.GET, "https://api.github.com/user",
                 json={"login": "test-org", "id": 1}, status=200)
        rsps.add(responses_lib.GET,
                 re.compile(r"https://api.github.com/orgs/.*/audit-log.*"),
                 json=[], status=200)
        rsps.add(responses_lib.GET, re.compile(r"https://api.github.com/.*"),
                 json=[], status=200)
        with runner.isolated_filesystem(temp_dir=str(tmp_path)):
            Path("mallcop.yaml").write_text(minimal_mallcop_config)
            result = runner.invoke(
                watch, ["--dry-run"],
                env={"GITHUB_TOKEN": "ghs_fake_watch_token"},
                catch_exceptions=False,
            )

    assert result.exit_code == 0, (
        f"watch --dry-run failed (exit {result.exit_code}):\n{result.output}"
    )


@pytest.mark.install_push
def test_credentials_not_hardcoded(tmp_path):
    """mallcop.yaml must use env var references (${VAR}), not literal credential values."""
    runner = _runner()
    from mallcop.cli import init

    secret_value = "actual-secret-value-must-not-appear-in-yaml"

    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.GET, "https://api.github.com/user",
                 json={"login": "test-user", "id": 1}, status=200)
        rsps.add(responses_lib.GET, re.compile(r"https://api.github.com/.*"),
                 json={"data": []}, status=200)
        with runner.isolated_filesystem(temp_dir=str(tmp_path)):
            result = runner.invoke(
                init, [],
                env={"GITHUB_TOKEN": secret_value},
                catch_exceptions=False,
            )
            config_path = Path("mallcop.yaml")
            assert config_path.exists(), "mallcop.yaml was not created"
            config_text = config_path.read_text()

    assert result.exit_code == 0
    assert secret_value not in config_text, (
        "Literal secret value found in mallcop.yaml — credentials must be env var references"
    )
    if "github" in config_text:
        assert "${GITHUB_TOKEN}" in config_text or "$GITHUB_TOKEN" in config_text, (
            "GitHub connector config must reference GITHUB_TOKEN via env var, not literal"
        )
