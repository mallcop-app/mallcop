"""Installation path tests: AI agent command ("Command Your AI").

Covers §13.5 of docs/e2e-superintegration-design.md.

Two modes:
  Mode A (install_push): Scripted simulation of the install-mallcop.md 10-step
      protocol via subprocess/CliRunner. Tests the protocol, not the AI.
  Mode B (install_prerelease): Real claude CLI invocation. Requires
      ANTHROPIC_API_KEY. Verifies the agent produces mallcop.yaml.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Path to the install-mallcop.md prompt.  The mallcop-cloud repo is a sibling
# of the mallcop OSS repo, so navigate: tests/install/ → repo root → sibling.
_INSTALL_DIR = Path(__file__).parent
_OSS_ROOT = _INSTALL_DIR.parent.parent
_CLOUD_ROOT = _OSS_ROOT.parent / "mallcop-cloud"
INSTALL_PROMPT_PATH = _CLOUD_ROOT / ".claude" / "prompts" / "install-mallcop.md"


def _python() -> str:
    """Return the current interpreter path so subprocess uses the same env."""
    return sys.executable


# ---------------------------------------------------------------------------
# Mode A — Scripted protocol (install_push)
# ---------------------------------------------------------------------------


@pytest.mark.install_push
def test_scripted_agent_install(tmp_path, monkeypatch, mock_github_device_flow):
    """Simulate the install-mallcop.md 10-step protocol via scripted subprocess calls.

    Reads the install-mallcop.md prompt to confirm it describes the expected
    steps, then exercises each automatable step:

    Step 1: Discover environment — GITHUB_TOKEN set in env (simulates user
            responding "GitHub" when asked which connectors they use).
    Step 2: pip install mallcop — mallcop is already installed in the test
            venv; verify the binary is accessible and version is parseable.
    Step 3: mallcop init — creates mallcop.yaml in tmp_path.
    Step 4: Write configuration — verify mallcop.yaml has required structure
            and uses env var references for credentials.
    Step 5: Set up GitHub Actions — verify the workflow template exists in the
            installed package and is valid YAML with a "jobs" key.
    Step 6: Store secrets — verify that GITHUB_TOKEN is referenced as an env
            var placeholder in mallcop.yaml (not hardcoded).
    Step 7: mallcop watch --dry-run — verify exit 0 with mocked GitHub API.
    Steps 8-10 are omitted: real run (CI skips), inference (optional),
            dashboard (requires live service).
    """
    import responses as responses_lib

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_scripted_agent_test_token")

    # --- Verify the prompt file exists and mentions the 10 steps ------------
    assert INSTALL_PROMPT_PATH.exists(), (
        f"install-mallcop.md not found at {INSTALL_PROMPT_PATH}"
    )
    prompt_text = INSTALL_PROMPT_PATH.read_text()
    # Steps 1-8 must be present in the prompt
    for step_num in range(1, 9):
        assert f"Step {step_num}" in prompt_text, (
            f"install-mallcop.md is missing 'Step {step_num}'"
        )

    # --- Step 2: mallcop binary must be accessible and version parseable ----
    version_result = subprocess.run(
        ["mallcop", "--version"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert version_result.returncode == 0, (
        f"mallcop --version failed: {version_result.stderr}"
    )
    version_output = version_result.stdout.strip()
    # Version string must contain a dotted version number (e.g. "0.1.0")
    assert re.search(r"\d+\.\d+", version_output), (
        f"Version output not parseable: {version_output!r}"
    )

    # --- Step 3: mallcop init -----------------------------------------------
    # Use CliRunner (in-process) so the `responses` mock can intercept HTTP
    # calls made by the connector discovery logic during init.
    from click.testing import CliRunner
    from mallcop.cli import init as _init_cmd, watch as _watch_cmd

    runner = CliRunner()
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.GET, "https://api.github.com/user",
                 json={"login": "test-user", "id": 1}, status=200)
        rsps.add(responses_lib.GET, re.compile(r"https://api.github.com/.*"),
                 json={"data": []}, status=200)
        with runner.isolated_filesystem(temp_dir=str(tmp_path)):
            init_result = runner.invoke(
                _init_cmd,
                [],
                env={"GITHUB_TOKEN": "ghs_scripted_agent_test_token"},
                catch_exceptions=False,
            )
            config_path = Path(tmp_path) / "mallcop.yaml"

    assert init_result.exit_code == 0, (
        f"mallcop init failed (exit {init_result.exit_code}):\n{init_result.output}"
    )

    # CliRunner.isolated_filesystem creates a temp dir inside tmp_path; find config
    # by searching or by looking at what was created.
    # isolated_filesystem uses a subdirectory — locate the created mallcop.yaml
    import glob as _glob
    found_configs = _glob.glob(str(tmp_path / "**" / "mallcop.yaml"), recursive=True)
    assert found_configs, "mallcop init did not create mallcop.yaml"
    config_path = Path(found_configs[0])

    # --- Step 4: Verify config structure (required keys) -------------------
    config = yaml.safe_load(config_path.read_text())
    assert "secrets" in config, "mallcop.yaml missing 'secrets' key"
    assert "connectors" in config, "mallcop.yaml missing 'connectors' key"
    assert "budget" in config, "mallcop.yaml missing 'budget' key"
    assert config["secrets"]["backend"] == "env", (
        "secrets.backend must be 'env'"
    )

    # --- Step 5: Workflow template exists and is valid YAML -----------------
    import mallcop as _mallcop_pkg
    template_path = (
        Path(_mallcop_pkg.__file__).parent / "templates" / "github-actions-example.yml"
    )
    assert template_path.exists(), (
        f"GitHub Actions workflow template missing at {template_path}"
    )
    workflow = yaml.safe_load(template_path.read_text())
    assert "jobs" in workflow, "Workflow template missing 'jobs' key"

    # --- Step 6: Credentials are env var references, not hardcoded ----------
    config_text = config_path.read_text()
    literal_token = "ghs_scripted_agent_test_token"
    assert literal_token not in config_text, (
        "Literal token value found in mallcop.yaml — must use env var reference"
    )

    # --- Step 7: mallcop watch --dry-run succeeds ---------------------------
    # Run in the same directory that contains mallcop.yaml
    config_dir = str(config_path.parent)
    with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses_lib.GET, "https://api.github.com/user",
                 json={"login": "test-user", "id": 1}, status=200)
        rsps.add(
            responses_lib.GET,
            re.compile(r"https://api.github.com/.*"),
            json=[],
            status=200,
        )
        with runner.isolated_filesystem(temp_dir=config_dir):
            # Copy the config into this isolated dir so watch can find it
            import shutil
            shutil.copy(str(config_path), "mallcop.yaml")
            dry_run_result = runner.invoke(
                _watch_cmd,
                ["--dry-run"],
                env={"GITHUB_TOKEN": "ghs_scripted_agent_test_token"},
                catch_exceptions=False,
            )

    assert dry_run_result.exit_code == 0, (
        f"mallcop watch --dry-run failed (exit {dry_run_result.exit_code}):\n"
        f"{dry_run_result.output}"
    )


# ---------------------------------------------------------------------------
# Mode B — Real agent invocation (install_prerelease)
# ---------------------------------------------------------------------------


@pytest.mark.install_prerelease
def test_real_agent_install(tmp_path):
    """Run claude CLI with the install-mallcop.md prompt and verify it completes steps 1-7.

    Requires ANTHROPIC_API_KEY in the environment. Skipped if not available.
    Timeout: 120s (LLM round-trips).

    The agent is instructed to work in tmp_path, use GITHUB_TOKEN from env,
    and stop after Step 7 (dry-run). We verify that it produces mallcop.yaml
    with the correct structure.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        pytest.skip("ANTHROPIC_API_KEY not set — skipping real agent install test")

    assert INSTALL_PROMPT_PATH.exists(), (
        f"install-mallcop.md not found at {INSTALL_PROMPT_PATH}"
    )

    env = {
        **os.environ,
        "GITHUB_TOKEN": "ghs_agent_test_token",
        "MALLCOP_TEST_DIR": str(tmp_path),
    }

    prompt = (
        f"Follow the install protocol at {INSTALL_PROMPT_PATH}. "
        f"Work in {tmp_path}. Use GITHUB_TOKEN from the environment. "
        f"Stop after Step 7 (dry-run). Do not ask interactive questions."
    )

    result = subprocess.run(
        ["claude", "-p", prompt],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=env,
        timeout=120,
    )

    # The agent may not return 0 if it pauses for interaction; check artifacts.
    config_path = tmp_path / "mallcop.yaml"
    assert config_path.exists(), (
        f"Agent did not produce mallcop.yaml.\n"
        f"claude exit code: {result.returncode}\n"
        f"stdout: {result.stdout[:2000]}\n"
        f"stderr: {result.stderr[:500]}"
    )

    config = yaml.safe_load(config_path.read_text())
    assert "connectors" in config, (
        f"mallcop.yaml produced by agent is missing 'connectors' key.\n"
        f"Config: {config}"
    )
    assert "secrets" in config, (
        f"mallcop.yaml produced by agent is missing 'secrets' key.\n"
        f"Config: {config}"
    )
