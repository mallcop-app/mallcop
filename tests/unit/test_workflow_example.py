"""Tests for the GitHub Actions example workflow template.

Validates that the example workflow file:
- Exists in the package
- Is valid YAML
- Has the expected structure matching docs/design.md GitHub Actions Example
"""

from __future__ import annotations

from pathlib import Path

import yaml


TEMPLATE_PATH = Path(__file__).parents[2] / "src" / "mallcop" / "templates" / "github-actions-example.yml"


class TestWorkflowExampleExists:
    def test_file_exists(self) -> None:
        assert TEMPLATE_PATH.exists(), f"Example workflow not found at {TEMPLATE_PATH}"

    def test_file_is_valid_yaml(self) -> None:
        content = TEMPLATE_PATH.read_text()
        data = yaml.safe_load(content)
        assert isinstance(data, dict)


class TestWorkflowExampleStructure:
    def _load(self) -> dict:
        return yaml.safe_load(TEMPLATE_PATH.read_text())

    def test_name(self) -> None:
        data = self._load()
        assert data["name"] == "mallcop-watch"

    def test_schedule_trigger(self) -> None:
        data = self._load()
        triggers = data[True]  # yaml parses 'on' as True
        assert "schedule" in triggers
        crons = triggers["schedule"]
        assert len(crons) >= 1
        assert crons[0]["cron"] == "0 */6 * * *"

    def test_workflow_dispatch_trigger(self) -> None:
        data = self._load()
        triggers = data[True]  # yaml parses 'on' as True
        assert "workflow_dispatch" in triggers

    def test_job_exists(self) -> None:
        data = self._load()
        assert "jobs" in data
        assert "watch" in data["jobs"]

    def test_runs_on_ubuntu(self) -> None:
        data = self._load()
        job = data["jobs"]["watch"]
        assert job["runs-on"] == "ubuntu-latest"

    def test_checkout_step(self) -> None:
        data = self._load()
        steps = data["jobs"]["watch"]["steps"]
        checkout_steps = [s for s in steps if s.get("uses", "").startswith("actions/checkout")]
        assert len(checkout_steps) >= 1

    def test_setup_python_step(self) -> None:
        data = self._load()
        steps = data["jobs"]["watch"]["steps"]
        python_steps = [s for s in steps if s.get("uses", "").startswith("actions/setup-python")]
        assert len(python_steps) >= 1
        python_step = python_steps[0]
        assert python_step["with"]["python-version"] == "3.12"

    def test_pip_install_step(self) -> None:
        data = self._load()
        steps = data["jobs"]["watch"]["steps"]
        install_steps = [s for s in steps if "pip install mallcop" in s.get("run", "")]
        assert len(install_steps) >= 1

    def test_mallcop_watch_step(self) -> None:
        data = self._load()
        steps = data["jobs"]["watch"]["steps"]
        watch_steps = [s for s in steps if "mallcop watch" in s.get("run", "")]
        assert len(watch_steps) >= 1

    def test_mallcop_watch_has_env_secrets(self) -> None:
        data = self._load()
        steps = data["jobs"]["watch"]["steps"]
        watch_step = [s for s in steps if "mallcop watch" in s.get("run", "")][0]
        env = watch_step["env"]
        assert "AZURE_TENANT_ID" in env
        assert "AZURE_CLIENT_ID" in env
        assert "AZURE_CLIENT_SECRET" in env
        assert "GITHUB_TOKEN" in env
        assert "TEAMS_WEBHOOK_URL" in env

    def test_git_commit_push_step(self) -> None:
        data = self._load()
        steps = data["jobs"]["watch"]["steps"]
        git_steps = [s for s in steps if "git add" in s.get("run", "") and "git push" in s.get("run", "")]
        assert len(git_steps) >= 1

    def test_git_config_step(self) -> None:
        data = self._load()
        steps = data["jobs"]["watch"]["steps"]
        git_steps = [s for s in steps if "git config" in s.get("run", "")]
        assert len(git_steps) >= 1
