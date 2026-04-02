"""Tests for mallcop init — GitHub Actions workflow generation and secret setting."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest
import yaml
from click.testing import CliRunner

from mallcop.cli import cli


def _parse_init_output(output: str) -> dict:
    """Extract the status=ok JSON line from init command output."""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("{"):
            parsed = json.loads(line)
            if parsed.get("status") == "ok":
                return parsed
    raise ValueError(f"No status=ok JSON line found in output: {output!r}")


WORKFLOW_PATH = Path(".github/workflows/mallcop.yml")


class TestInitGHAWorkflow:
    """When GitHub config is present, init writes .github/workflows/mallcop.yml."""

    def _make_fake_proc(self, stdout: str = "camp-abc\n") -> MagicMock:
        proc = MagicMock()
        proc.stdout = stdout
        proc.returncode = 0
        return proc

    def _inject_github(self, campfire_id: str = "camp-abc"):
        """Return side_effect functions for patching _setup_github and subprocess.run."""

        def inject_github(config_data: dict) -> dict:
            config_data["github"] = {"repo": "owner/myrepo"}
            return {"repo": "owner/myrepo", "status": "authorized"}

        def inject_pro(config_data: dict) -> dict:
            config_data["pro"] = {
                "service_token": "mallcop-sk-test",
                "inference_url": "https://mallcop.app/api/inference",
                "account_url": "https://mallcop.app/api/account",
            }
            return {"inference_url": "https://mallcop.app/api/inference"}

        return inject_github, inject_pro

    def test_workflow_file_written_when_github_config_present(self, tmp_path: Path) -> None:
        """When github.repo is in config, .github/workflows/mallcop.yml is written."""
        runner = CliRunner()
        inject_github, inject_pro = self._inject_github()
        fake_proc = self._make_fake_proc()

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("subprocess.run", return_value=fake_proc), \
                 patch("mallcop.cli._setup_github", side_effect=inject_github), \
                 patch("mallcop.cli._setup_pro", side_effect=inject_pro):
                result = runner.invoke(cli, ["init", "--pro"])

            assert result.exit_code == 0, result.output
            assert WORKFLOW_PATH.exists(), f"Workflow file not created. Output: {result.output}"

            content = WORKFLOW_PATH.read_text()
            workflow = yaml.safe_load(content)

            # pyyaml parses the "on" key as True (Python bool) because "on" is a YAML bool value.
            # Use True as the key to access the triggers section.
            triggers = workflow[True]

            # Verify cron schedule
            schedules = triggers["schedule"]
            crons = [s["cron"] for s in schedules]
            assert "*/15 * * * *" in crons, f"Expected */15 cron, got: {crons}"

            # Verify workflow_dispatch trigger
            assert "workflow_dispatch" in triggers, "workflow_dispatch trigger missing"

            # Verify mallcop watch step
            steps = workflow["jobs"]["mallcop"]["steps"]
            run_steps = [s for s in steps if "run" in s]
            assert any("mallcop watch" in s["run"] for s in run_steps), \
                f"No 'mallcop watch' step found. Steps: {run_steps}"

    def test_workflow_file_has_correct_cron(self, tmp_path: Path) -> None:
        """Workflow cron is */15 * * * * (every 15 minutes)."""
        runner = CliRunner()
        inject_github, inject_pro = self._inject_github()
        fake_proc = self._make_fake_proc()

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("subprocess.run", return_value=fake_proc), \
                 patch("mallcop.cli._setup_github", side_effect=inject_github), \
                 patch("mallcop.cli._setup_pro", side_effect=inject_pro):
                result = runner.invoke(cli, ["init", "--pro"])

            assert result.exit_code == 0, result.output
            content = WORKFLOW_PATH.read_text()
            assert "*/15 * * * *" in content

    def test_gh_secret_set_called_for_campfire_id(self, tmp_path: Path) -> None:
        """gh secret set is called for CAMPFIRE_ID when GitHub config is present."""
        runner = CliRunner()
        inject_github, inject_pro = self._inject_github()

        calls_made = []

        def fake_subprocess_run(cmd, **kwargs):
            calls_made.append(cmd)
            proc = MagicMock()
            proc.stdout = "camp-gh42\n" if cmd[0] == "cf" else ""
            proc.returncode = 0
            return proc

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("subprocess.run", side_effect=fake_subprocess_run), \
                 patch("mallcop.cli._setup_github", side_effect=inject_github), \
                 patch("mallcop.cli._setup_pro", side_effect=inject_pro):
                result = runner.invoke(cli, ["init", "--pro"])

            assert result.exit_code == 0, result.output

            # Check gh secret set was called for CAMPFIRE_ID
            gh_calls = [c for c in calls_made if c and c[0] == "gh"]
            secret_names = []
            for c in gh_calls:
                if "secret" in c and "set" in c:
                    # Find the secret name (argument after "set")
                    set_idx = c.index("set")
                    if set_idx + 1 < len(c):
                        secret_names.append(c[set_idx + 1])

            assert "CAMPFIRE_ID" in secret_names, \
                f"gh secret set CAMPFIRE_ID not called. gh calls: {gh_calls}"

    def test_gh_secret_set_called_for_telegram_when_configured(self, tmp_path: Path) -> None:
        """gh secret set is called for Telegram secrets when configured."""
        runner = CliRunner()
        inject_github, inject_pro = self._inject_github()

        calls_made = []

        def fake_subprocess_run(cmd, **kwargs):
            calls_made.append(cmd)
            proc = MagicMock()
            proc.stdout = "camp-gh99\n" if cmd[0] == "cf" else ""
            proc.returncode = 0
            return proc

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("subprocess.run", side_effect=fake_subprocess_run), \
                 patch("mallcop.cli._setup_github", side_effect=inject_github), \
                 patch("mallcop.cli._setup_pro", side_effect=inject_pro):
                result = runner.invoke(cli, [
                    "init", "--pro",
                    "--telegram-bot-token", "bot123:TOKEN",
                    "--telegram-chat-id", "-100456",
                ])

            assert result.exit_code == 0, result.output

            gh_calls = [c for c in calls_made if c and c[0] == "gh"]
            secret_names = []
            for c in gh_calls:
                if "secret" in c and "set" in c:
                    set_idx = c.index("set")
                    if set_idx + 1 < len(c):
                        secret_names.append(c[set_idx + 1])

            assert "MALLCOP_TELEGRAM_BOT_TOKEN" in secret_names, \
                f"gh secret set MALLCOP_TELEGRAM_BOT_TOKEN not called. Secret names: {secret_names}"
            assert "MALLCOP_TELEGRAM_CHAT_ID" in secret_names, \
                f"gh secret set MALLCOP_TELEGRAM_CHAT_ID not called. Secret names: {secret_names}"

    def test_workflow_not_written_without_github_config(self, tmp_path: Path) -> None:
        """Without github config (no --pro), workflow file is NOT written."""
        runner = CliRunner()
        fake_proc = self._make_fake_proc()

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("subprocess.run", return_value=fake_proc):
                result = runner.invoke(cli, ["init"])

            assert result.exit_code == 0, result.output
            assert not WORKFLOW_PATH.exists(), \
                "Workflow file should not be written without github config"


class TestInitGHAWorkflowNoOverwrite:
    """If workflow file already exists, it must NOT be overwritten."""

    def test_existing_workflow_not_overwritten(self, tmp_path: Path) -> None:
        """When .github/workflows/mallcop.yml already exists, init leaves it unchanged."""
        runner = CliRunner()

        def inject_github(config_data: dict) -> dict:
            config_data["github"] = {"repo": "owner/repo"}
            return {"repo": "owner/repo", "status": "authorized"}

        def inject_pro(config_data: dict) -> dict:
            config_data["pro"] = {
                "service_token": "mallcop-sk-test",
                "inference_url": "https://mallcop.app/api/inference",
                "account_url": "https://mallcop.app/api/account",
            }
            return {"inference_url": "https://mallcop.app/api/inference"}

        existing_content = "# existing workflow — do not overwrite\nname: existing\n"

        def fake_subprocess_run(cmd, **kwargs):
            proc = MagicMock()
            proc.stdout = "camp-x\n" if cmd[0] == "cf" else ""
            proc.returncode = 0
            return proc

        with runner.isolated_filesystem(temp_dir=tmp_path):
            # Write the existing workflow file
            Path(".github/workflows").mkdir(parents=True)
            Path(".github/workflows/mallcop.yml").write_text(existing_content)

            with patch("subprocess.run", side_effect=fake_subprocess_run), \
                 patch("mallcop.cli._setup_github", side_effect=inject_github), \
                 patch("mallcop.cli._setup_pro", side_effect=inject_pro):
                result = runner.invoke(cli, ["init", "--pro"])

            assert result.exit_code == 0, result.output
            # File must be unchanged
            actual = Path(".github/workflows/mallcop.yml").read_text()
            assert actual == existing_content, \
                f"Workflow file was overwritten! Content: {actual!r}"


class TestInitGHANoGh:
    """When gh is not on PATH: write workflow file, skip secret setting, warn."""

    def test_workflow_written_but_secrets_skipped_when_no_gh(self, tmp_path: Path) -> None:
        """When gh is not found, workflow file is still written and output includes secrets_skipped."""
        runner = CliRunner()

        def inject_github(config_data: dict) -> dict:
            config_data["github"] = {"repo": "owner/repo"}
            return {"repo": "owner/repo", "status": "authorized"}

        def inject_pro(config_data: dict) -> dict:
            config_data["pro"] = {
                "service_token": "mallcop-sk-test",
                "inference_url": "https://mallcop.app/api/inference",
                "account_url": "https://mallcop.app/api/account",
            }
            return {"inference_url": "https://mallcop.app/api/inference"}

        def fake_subprocess_run(cmd, **kwargs):
            if cmd[0] == "gh":
                raise FileNotFoundError("gh not found")
            proc = MagicMock()
            proc.stdout = "camp-nogh\n" if cmd[0] == "cf" else ""
            proc.returncode = 0
            return proc

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("subprocess.run", side_effect=fake_subprocess_run), \
                 patch("mallcop.cli._setup_github", side_effect=inject_github), \
                 patch("mallcop.cli._setup_pro", side_effect=inject_pro):
                result = runner.invoke(cli, ["init", "--pro"])

            assert result.exit_code == 0, result.output
            data = _parse_init_output(result.output)

            # Workflow file must be written
            assert WORKFLOW_PATH.exists(), \
                f"Workflow file not created even when gh missing. Output: {result.output}"

            # Output must include secrets_skipped
            delivery = data.get("delivery", {})
            assert "secrets_skipped" in delivery, \
                f"Expected 'secrets_skipped' in delivery, got: {delivery}"
            assert "gh" in delivery["secrets_skipped"].lower(), \
                f"Expected 'gh' in secrets_skipped message, got: {delivery['secrets_skipped']}"

            # workflow_written must be true
            assert delivery.get("workflow_written") is True, \
                f"Expected workflow_written=true in delivery, got: {delivery}"
