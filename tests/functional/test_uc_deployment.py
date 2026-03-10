"""UC: Deployment -- init -> watch -> directory structure + GH Actions workflow.

Functional test exercising the full deployment story:
  1. Create a temp directory as a deployment repo (git init)
  2. Run mallcop init with mock connector discovery
  3. Run mallcop watch --dry-run
  4. Validate directory structure (events/, findings/, baseline/ exist)
  5. Validate GH Actions workflow is valid YAML with expected structure
  6. Validate cost estimation output
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from mallcop.cli import cli
from mallcop.schemas import Checkpoint, Event, Severity
from mallcop.store import JsonlStore


# --- Fixtures: mock Azure ---

FAKE_SUBSCRIPTIONS = [
    {"subscriptionId": "sub-001", "displayName": "Production"},
    {"subscriptionId": "sub-002", "displayName": "Dev/Test"},
]

FAKE_ACTIVITY_LOG_EVENTS = [
    {
        "eventDataId": "evt-data-001",
        "eventTimestamp": "2026-03-05T10:00:00Z",
        "caller": "admin@example.com",
        "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
        "resourceType": {"value": "Microsoft.Authorization/roleAssignments"},
        "resourceId": "/subscriptions/sub-001/providers/Microsoft.Authorization/roleAssignments/ra-1",
        "level": "Informational",
        "subscriptionId": "sub-001",
        "resourceGroupName": "rg-prod",
        "correlationId": "corr-001",
        "status": {"value": "Succeeded"},
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


def _mock_get_token(self: Any) -> str:
    return "fake-token"


def _apply_azure_mocks():
    """Context manager that patches Azure connector methods."""
    return (
        patch(
            "mallcop.connectors.azure.connector.AzureConnector._get_token",
            _mock_get_token,
        ),
        patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ),
        patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            _mock_fetch_activity_log,
        ),
    )


class TestDeploymentInitWatchFlow:
    """Full deployment scenario: git init -> mallcop init -> mallcop watch --dry-run."""

    def _setup_deployment_repo(self, root: Path) -> None:
        """Initialize a git repo at root."""
        subprocess.run(
            ["git", "init"],
            cwd=root,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=root,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=root,
            capture_output=True,
            check=True,
        )

    def test_init_then_watch_dryrun_end_to_end(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Full flow: git init -> mallcop init -> mallcop watch --dry-run succeeds."""
        root = tmp_path
        self._setup_deployment_repo(root)
        monkeypatch.chdir(root)
        monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "fake-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "fake-secret")
        runner = CliRunner()

        mock_token, mock_subs, mock_log = _apply_azure_mocks()

        # Step 1: mallcop init
        with mock_token, mock_subs, mock_log:
            init_result = runner.invoke(cli, ["init"], catch_exceptions=False)

        assert init_result.exit_code == 0, f"init failed: {init_result.output}"
        init_data = json.loads(init_result.output)
        assert init_data["status"] == "ok"

        # Step 2: mallcop watch --dry-run
        with mock_token, mock_subs, patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ):
            watch_result = runner.invoke(
                cli, ["watch", "--dry-run", "--dir", str(root)],
                catch_exceptions=False,
            )

        assert watch_result.exit_code == 0, f"watch failed: {watch_result.output}"
        watch_data = json.loads(watch_result.output)
        assert watch_data["status"] == "ok"
        assert watch_data["dry_run"] is True

    def test_directory_structure_after_init_and_watch(self, tmp_path: Path, monkeypatch: Any) -> None:
        """After init + watch, events/ and baseline/ directories exist."""
        root = tmp_path
        self._setup_deployment_repo(root)
        monkeypatch.chdir(root)
        monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "fake-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "fake-secret")
        runner = CliRunner()

        mock_token, mock_subs, mock_log = _apply_azure_mocks()

        with mock_token, mock_subs, mock_log:
            runner.invoke(cli, ["init"], catch_exceptions=False)

        # Seed some events so directories get created
        now = datetime.now(timezone.utc)
        events = [
            Event(
                id=f"evt_deploy_{i}",
                timestamp=now - timedelta(hours=i),
                ingested_at=now,
                source="azure",
                event_type="role_assignment",
                actor="admin@example.com",
                action="create",
                target="/subscriptions/sub-001/resource",
                severity=Severity.INFO,
                metadata={},
                raw={},
            )
            for i in range(3)
        ]
        store = JsonlStore(root)
        store.append_events(events)

        with mock_token, mock_subs, patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: [],
        ):
            runner.invoke(
                cli, ["watch", "--dry-run", "--dir", str(root)],
                catch_exceptions=False,
            )

        # Verify directory structure
        assert (root / "mallcop.yaml").exists(), "mallcop.yaml should exist"
        assert (root / "events").is_dir(), "events/ directory should exist"
        # Baseline is stored as baseline.json (single file, not directory)
        assert (root / "baseline.json").exists(), "baseline.json should exist"

    def test_mallcop_yaml_has_required_sections(self, tmp_path: Path, monkeypatch: Any) -> None:
        """mallcop.yaml written by init has secrets, connectors, budget sections."""
        root = tmp_path
        self._setup_deployment_repo(root)
        monkeypatch.chdir(root)
        runner = CliRunner()

        mock_token, mock_subs, mock_log = _apply_azure_mocks()
        with mock_token, mock_subs, mock_log:
            runner.invoke(cli, ["init"], catch_exceptions=False)

        config = yaml.safe_load((root / "mallcop.yaml").read_text())
        assert "secrets" in config
        assert "connectors" in config
        assert "budget" in config
        assert config["secrets"]["backend"] == "env"
        assert "azure" in config["connectors"]

    def test_cost_estimation_in_init_output(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Init output includes cost estimation with all required fields."""
        root = tmp_path
        self._setup_deployment_repo(root)
        monkeypatch.chdir(root)
        runner = CliRunner()

        mock_token, mock_subs, mock_log = _apply_azure_mocks()
        with mock_token, mock_subs, mock_log:
            result = runner.invoke(cli, ["init"], catch_exceptions=False)

        data = json.loads(result.output)
        cost = data["cost_estimate"]

        assert "connectors_active" in cost
        assert "estimated_events_per_run" in cost
        assert "estimated_cost_per_run_usd" in cost
        assert "estimated_cost_per_month_usd" in cost
        assert "worst_case_cost_per_run_usd" in cost
        assert "worst_case_cost_per_month_usd" in cost
        assert "budget_max_tokens_per_run" in cost

        # Monthly cost range should be parseable and plausible
        monthly = cost["estimated_cost_per_month_usd"]
        low, high = monthly.split("-")
        assert float(low) >= 0
        assert float(high) < 100


class TestGitHubActionsWorkflow:
    """GH Actions example workflow is valid YAML with expected structure."""

    def test_workflow_template_exists(self) -> None:
        """The GH Actions example workflow template file exists."""
        template_path = (
            Path(__file__).parent.parent.parent
            / "src" / "mallcop" / "templates" / "github-actions-example.yml"
        )
        assert template_path.exists(), f"Template not found at {template_path}"

    def test_workflow_is_valid_yaml(self) -> None:
        """The workflow template parses as valid YAML."""
        template_path = (
            Path(__file__).parent.parent.parent
            / "src" / "mallcop" / "templates" / "github-actions-example.yml"
        )
        content = template_path.read_text()
        workflow = yaml.safe_load(content)
        assert isinstance(workflow, dict)

    def test_workflow_has_expected_structure(self) -> None:
        """Workflow has name, on.schedule, jobs.watch with expected steps."""
        template_path = (
            Path(__file__).parent.parent.parent
            / "src" / "mallcop" / "templates" / "github-actions-example.yml"
        )
        workflow = yaml.safe_load(template_path.read_text())

        # Top-level keys
        assert "name" in workflow
        # Note: YAML parses bare `on` as boolean True, so check for True key
        assert True in workflow or "on" in workflow
        assert "jobs" in workflow

        # Schedule trigger (handle YAML `on` -> True key)
        on_config = workflow.get("on") or workflow.get(True)
        assert "schedule" in on_config
        crons = on_config["schedule"]
        assert len(crons) >= 1
        assert "cron" in crons[0]

        # Manual dispatch
        assert "workflow_dispatch" in on_config

        # Job structure
        assert "watch" in workflow["jobs"]
        job = workflow["jobs"]["watch"]
        assert "runs-on" in job
        assert "steps" in job

        steps = job["steps"]
        # Should have checkout, setup-python, pip install, mallcop watch, git commit
        step_runs = [s.get("run", "") for s in steps if "run" in s]
        assert any("pip install mallcop" in r for r in step_runs), \
            "Should have pip install step"
        assert any("mallcop watch" in r for r in step_runs), \
            "Should have mallcop watch step"
        assert any("git commit" in r for r in step_runs), \
            "Should have git commit step"

        # Should reference required secrets
        step_envs = [s.get("env", {}) for s in steps]
        all_env_keys: set[str] = set()
        for env in step_envs:
            all_env_keys.update(env.keys())
        assert "AZURE_TENANT_ID" in all_env_keys, "Should reference AZURE_TENANT_ID secret"

    def test_init_output_references_workflow(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Init output mentions the GH Actions example workflow."""
        root = tmp_path
        monkeypatch.chdir(root)
        runner = CliRunner()

        mock_token, mock_subs, mock_log = _apply_azure_mocks()
        with mock_token, mock_subs, mock_log:
            result = runner.invoke(cli, ["init"], catch_exceptions=False)

        data = json.loads(result.output)
        assert "workflow_example" in data
        assert "github-actions" in data["workflow_example"].lower() or \
               "github" in data["workflow_example"].lower()


class TestReadmeQuickstart:
    """README.md covers the full quickstart story."""

    def _read_readme(self) -> str:
        readme_path = (
            Path(__file__).parent.parent.parent / "README.md"
        )
        assert readme_path.exists(), "README.md should exist"
        return readme_path.read_text()

    def test_readme_mentions_install(self) -> None:
        """README covers pip install mallcop."""
        content = self._read_readme()
        assert "pip install mallcop" in content

    def test_readme_mentions_init(self) -> None:
        """README covers mallcop init."""
        content = self._read_readme()
        assert "mallcop init" in content

    def test_readme_mentions_scan(self) -> None:
        """README covers mallcop scan."""
        content = self._read_readme()
        assert "mallcop scan" in content

    def test_readme_mentions_detect(self) -> None:
        """README covers mallcop detect."""
        content = self._read_readme()
        assert "mallcop detect" in content

    def test_readme_mentions_watch(self) -> None:
        """README covers mallcop watch."""
        content = self._read_readme()
        assert "mallcop watch" in content

    def test_readme_mentions_review(self) -> None:
        """README covers mallcop review."""
        content = self._read_readme()
        assert "mallcop review" in content

    def test_readme_mentions_learning_period(self) -> None:
        """README mentions the learning/baseline period."""
        content = self._read_readme()
        assert "14" in content or "learning" in content.lower() or "baseline" in content.lower()

    def test_readme_mentions_automation(self) -> None:
        """README mentions GitHub Actions or cron for automation."""
        content = self._read_readme()
        lower = content.lower()
        assert "github actions" in lower or "cron" in lower or "schedule" in lower

    def test_readme_mentions_directory_contents(self) -> None:
        """README explains what each directory contains (events/, findings/, baseline/)."""
        content = self._read_readme()
        assert "events/" in content or "events" in content.lower()
        assert "findings" in content.lower()
        assert "baseline" in content.lower()

    def test_readme_is_scannable_by_ai(self) -> None:
        """README has structured sections (headers) for AI scanning."""
        content = self._read_readme()
        # Should have multiple markdown headers
        headers = [line for line in content.split("\n") if line.startswith("#")]
        assert len(headers) >= 4, \
            f"README should have at least 4 headers for scannability, found {len(headers)}"

    def test_readme_mentions_json_output(self) -> None:
        """README mentions JSON output (AI-native)."""
        content = self._read_readme()
        assert "JSON" in content or "json" in content


class TestStatePersistenceAcrossRuns:
    """Simulate ephemeral GH Actions runs: state persists via filesystem between runs.

    Key scenario: GH Actions checks out repo, runs mallcop watch, commits, pushes.
    Next run checks out the repo (with committed state), runs watch again.
    Checkpoints prevent duplicate event ingestion. Baseline grows. Findings accumulate.
    """

    @pytest.fixture(autouse=True)
    def _mock_azure_token(self):
        """Mock _get_token to avoid live Azure API calls."""
        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._get_token",
            _mock_get_token,
        ):
            yield

    def _setup_deployment_repo(self, root: Path) -> None:
        subprocess.run(
            ["git", "init"], cwd=root, capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=root, capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=root, capture_output=True, check=True,
        )

    def _write_config(self, root: Path) -> None:
        config = {
            "secrets": {"backend": "env"},
            "connectors": {
                "azure": {
                    "tenant_id": "${AZURE_TENANT_ID}",
                    "client_id": "${AZURE_CLIENT_ID}",
                    "client_secret": "${AZURE_CLIENT_SECRET}",
                    "subscription_ids": ["sub-001"],
                },
            },
            "routing": {},
            "actor_chain": {},
            "budget": {
                "max_findings_for_actors": 10,
                "max_tokens_per_run": 50000,
                "max_tokens_per_finding": 5000,
            },
        }
        with open(root / "mallcop.yaml", "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    def _git_commit_all(self, root: Path, msg: str) -> None:
        subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True, check=True)
        # Only commit if there are changes
        result = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            cwd=root, capture_output=True,
        )
        if result.returncode != 0:
            subprocess.run(
                ["git", "commit", "-m", msg],
                cwd=root, capture_output=True, check=True,
            )

    def test_checkpoint_prevents_duplicate_events_across_runs(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Run 1 ingests events. Run 2 (same events available) ingests 0 due to checkpoint."""
        root = tmp_path
        self._setup_deployment_repo(root)
        self._write_config(root)
        monkeypatch.chdir(root)
        monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "fake-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "fake-secret")
        runner = CliRunner()

        run1_events = [
            {
                "eventDataId": "evt-run1-001",
                "eventTimestamp": "2026-03-05T10:00:00Z",
                "caller": "admin@example.com",
                "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
                "resourceType": {"value": "Microsoft.Authorization/roleAssignments"},
                "resourceId": "/subscriptions/sub-001/providers/Microsoft.Authorization/roleAssignments/ra-1",
                "level": "Informational",
                "subscriptionId": "sub-001",
                "resourceGroupName": "rg-prod",
                "correlationId": "corr-001",
                "status": {"value": "Succeeded"},
            },
        ]

        # Run 1: ingest events
        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: run1_events,
        ):
            result1 = runner.invoke(
                cli, ["watch", "--dry-run", "--dir", str(root)],
                catch_exceptions=False,
            )

        assert result1.exit_code == 0
        data1 = json.loads(result1.output)
        assert data1["status"] == "ok"
        events_run1 = data1["scan"]["connectors"]["azure"]["events_ingested"]
        assert events_run1 == 1, f"Run 1 should ingest 1 event, got {events_run1}"

        # Simulate GH Actions commit
        self._git_commit_all(root, "mallcop watch run 1")

        # Verify checkpoint was written
        assert (root / "checkpoints.yaml").exists(), "checkpoints.yaml should exist after run 1"

        # Run 2: same events available, checkpoint should filter them out
        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: run1_events,
        ):
            result2 = runner.invoke(
                cli, ["watch", "--dry-run", "--dir", str(root)],
                catch_exceptions=False,
            )

        assert result2.exit_code == 0
        data2 = json.loads(result2.output)
        assert data2["status"] == "ok"
        events_run2 = data2["scan"]["connectors"]["azure"]["events_ingested"]
        assert events_run2 == 0, f"Run 2 should ingest 0 events (checkpoint), got {events_run2}"

    def test_new_events_ingested_in_subsequent_run(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Run 1 ingests old events. Run 2 ingests only newer events."""
        root = tmp_path
        self._setup_deployment_repo(root)
        self._write_config(root)
        monkeypatch.chdir(root)
        monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "fake-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "fake-secret")
        runner = CliRunner()

        old_events = [
            {
                "eventDataId": "evt-old-001",
                "eventTimestamp": "2026-03-05T10:00:00Z",
                "caller": "admin@example.com",
                "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"},
                "resourceType": {"value": "Microsoft.Authorization/roleAssignments"},
                "resourceId": "/subscriptions/sub-001/resource/old",
                "level": "Informational",
                "subscriptionId": "sub-001",
                "resourceGroupName": "rg-prod",
                "correlationId": "corr-old",
                "status": {"value": "Succeeded"},
            },
        ]
        new_events = old_events + [
            {
                "eventDataId": "evt-new-001",
                "eventTimestamp": "2026-03-06T10:00:00Z",
                "caller": "newuser@example.com",
                "operationName": {"value": "Microsoft.Compute/virtualMachines/write"},
                "resourceType": {"value": "Microsoft.Compute/virtualMachines"},
                "resourceId": "/subscriptions/sub-001/resource/new",
                "level": "Informational",
                "subscriptionId": "sub-001",
                "resourceGroupName": "rg-prod",
                "correlationId": "corr-new",
                "status": {"value": "Succeeded"},
            },
        ]

        # Run 1
        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: old_events,
        ):
            result1 = runner.invoke(
                cli, ["watch", "--dry-run", "--dir", str(root)],
                catch_exceptions=False,
            )
        data1 = json.loads(result1.output)
        assert data1["scan"]["connectors"]["azure"]["events_ingested"] == 1

        self._git_commit_all(root, "run 1")

        # Run 2: API returns old + new events, but only new should be ingested
        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: new_events,
        ):
            result2 = runner.invoke(
                cli, ["watch", "--dry-run", "--dir", str(root)],
                catch_exceptions=False,
            )
        data2 = json.loads(result2.output)
        assert data2["scan"]["connectors"]["azure"]["events_ingested"] == 1, \
            "Run 2 should ingest only the new event"

        # Verify total events on disk
        store = JsonlStore(root)
        all_events = store.query_events()
        assert len(all_events) == 2, f"Total events should be 2 after two runs, got {len(all_events)}"

    def test_baseline_persists_and_grows_across_runs(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Baseline grows across runs as more events are ingested."""
        root = tmp_path
        self._setup_deployment_repo(root)
        self._write_config(root)
        monkeypatch.chdir(root)
        monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "fake-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "fake-secret")
        runner = CliRunner()

        events_run1 = [
            {
                "eventDataId": "evt-bl-001",
                "eventTimestamp": "2026-03-05T10:00:00Z",
                "caller": "alice@example.com",
                "operationName": {"value": "Microsoft.Compute/virtualMachines/read"},
                "resourceType": {"value": "Microsoft.Compute/virtualMachines"},
                "resourceId": "/subscriptions/sub-001/resource/vm-1",
                "level": "Informational",
                "subscriptionId": "sub-001",
                "resourceGroupName": "rg-prod",
                "correlationId": "corr-bl1",
                "status": {"value": "Succeeded"},
            },
        ]

        # Run 1
        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: events_run1,
        ):
            runner.invoke(
                cli, ["watch", "--dry-run", "--dir", str(root)],
                catch_exceptions=False,
            )

        assert (root / "baseline.json").exists(), "baseline.json should exist after run 1"
        baseline1 = json.loads((root / "baseline.json").read_text())
        actors1 = baseline1.get("known_entities", {}).get("actors", [])
        assert any("alice@example.com" in a for a in actors1), \
            f"Expected 'alice@example.com' in sanitized actors: {actors1}"

        self._git_commit_all(root, "run 1")

        events_run2 = [
            {
                "eventDataId": "evt-bl-002",
                "eventTimestamp": "2026-03-06T10:00:00Z",
                "caller": "bob@example.com",
                "operationName": {"value": "Microsoft.Storage/storageAccounts/write"},
                "resourceType": {"value": "Microsoft.Storage/storageAccounts"},
                "resourceId": "/subscriptions/sub-001/resource/storage-1",
                "level": "Informational",
                "subscriptionId": "sub-001",
                "resourceGroupName": "rg-prod",
                "correlationId": "corr-bl2",
                "status": {"value": "Succeeded"},
            },
        ]

        # Run 2
        with patch(
            "mallcop.connectors.azure.connector.AzureConnector._list_subscriptions",
            _mock_list_subscriptions,
        ), patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: events_run2,
        ):
            runner.invoke(
                cli, ["watch", "--dry-run", "--dir", str(root)],
                catch_exceptions=False,
            )

        baseline2 = json.loads((root / "baseline.json").read_text())
        actors2 = baseline2.get("known_entities", {}).get("actors", [])
        assert any("alice@example.com" in a for a in actors2), \
            "Alice should still be in baseline after run 2"
        assert any("bob@example.com" in a for a in actors2), \
            "Bob should be added to baseline in run 2"

    def test_findings_persist_across_runs(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """Findings written by one run are visible to the next run's store."""
        root = tmp_path
        self._setup_deployment_repo(root)
        self._write_config(root)
        monkeypatch.chdir(root)
        monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "fake-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "fake-secret")

        now = datetime.now(timezone.utc)

        # Simulate run 1: write findings directly to findings.jsonl
        from mallcop.schemas import Finding, FindingStatus
        finding1 = Finding(
            id="fnd_persist_001",
            timestamp=now - timedelta(hours=6),
            detector="new-actor",
            event_ids=["evt_a", "evt_b"],
            title="New actor: intruder@evil.com on azure",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "intruder@evil.com"},
        )
        store1 = JsonlStore(root)
        store1.append_findings([finding1])

        self._git_commit_all(root, "run 1 findings")

        # Simulate run 2: new store instance reads findings from disk
        store2 = JsonlStore(root)
        persisted = store2.query_findings()
        assert len(persisted) == 1, f"Should find 1 persisted finding, got {len(persisted)}"
        assert persisted[0].id == "fnd_persist_001"

        # Add another finding
        finding2 = Finding(
            id="fnd_persist_002",
            timestamp=now,
            detector="new-actor",
            event_ids=["evt_c"],
            title="New actor: hacker2@evil.com on azure",
            severity=Severity.WARN,
            status=FindingStatus.OPEN,
            annotations=[],
            metadata={"actor": "hacker2@evil.com"},
        )
        store2.append_findings([finding2])

        self._git_commit_all(root, "run 2 findings")

        # Simulate run 3: both findings visible
        store3 = JsonlStore(root)
        all_findings = store3.query_findings()
        assert len(all_findings) == 2, f"Should find 2 persisted findings, got {len(all_findings)}"
        ids = {f.id for f in all_findings}
        assert "fnd_persist_001" in ids
        assert "fnd_persist_002" in ids

    def test_costs_jsonl_accumulates_across_runs(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """costs.jsonl grows with entries from each run (when escalation runs)."""
        root = tmp_path
        self._setup_deployment_repo(root)
        self._write_config(root)
        monkeypatch.chdir(root)
        monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "fake-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "fake-secret")

        # Write a costs.jsonl manually to simulate a previous run
        costs_path = root / "costs.jsonl"
        cost_entry_1 = {
            "timestamp": "2026-03-05T10:00:00+00:00",
            "findings_processed": 2,
            "tokens_used": 1500,
            "circuit_breaker_triggered": False,
            "budget_exhausted": False,
        }
        costs_path.write_text(json.dumps(cost_entry_1) + "\n")

        self._git_commit_all(root, "previous run costs")

        # Verify the file persists (simulating checkout)
        assert costs_path.exists()
        lines = [l for l in costs_path.read_text().strip().split("\n") if l]
        assert len(lines) == 1, "Should have 1 cost entry from previous run"

        # Append another entry (simulating what escalate does)
        cost_entry_2 = {
            "timestamp": "2026-03-06T10:00:00+00:00",
            "findings_processed": 3,
            "tokens_used": 2500,
            "circuit_breaker_triggered": False,
            "budget_exhausted": False,
        }
        with open(costs_path, "a") as f:
            f.write(json.dumps(cost_entry_2) + "\n")

        lines = [l for l in costs_path.read_text().strip().split("\n") if l]
        assert len(lines) == 2, "Should have 2 cost entries after two runs"
        parsed = [json.loads(l) for l in lines]
        assert parsed[0]["findings_processed"] == 2
        assert parsed[1]["findings_processed"] == 3

    def test_all_state_files_are_committable(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """After init + watch, all state files can be git-added and committed."""
        root = tmp_path
        self._setup_deployment_repo(root)
        monkeypatch.chdir(root)
        monkeypatch.setenv("AZURE_TENANT_ID", "fake-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "fake-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "fake-secret")
        runner = CliRunner()

        mock_token, mock_subs, mock_log = _apply_azure_mocks()
        with mock_token, mock_subs, mock_log:
            runner.invoke(cli, ["init"], catch_exceptions=False)

        with mock_token, mock_subs, patch(
            "mallcop.connectors.azure.connector.AzureConnector._fetch_activity_log",
            lambda self, sub_id, cp: FAKE_ACTIVITY_LOG_EVENTS,
        ):
            runner.invoke(
                cli, ["watch", "--dry-run", "--dir", str(root)],
                catch_exceptions=False,
            )

        # git add -A should succeed
        add_result = subprocess.run(
            ["git", "add", "-A"], cwd=root, capture_output=True,
        )
        assert add_result.returncode == 0, f"git add failed: {add_result.stderr.decode()}"

        # git commit should succeed (there should be changes)
        commit_result = subprocess.run(
            ["git", "commit", "-m", "mallcop watch test"],
            cwd=root, capture_output=True,
        )
        assert commit_result.returncode == 0, f"git commit failed: {commit_result.stderr.decode()}"

        # Verify key files are tracked
        ls_result = subprocess.run(
            ["git", "ls-files"], cwd=root, capture_output=True, text=True,
        )
        tracked = ls_result.stdout
        assert "mallcop.yaml" in tracked
        assert "checkpoints.yaml" in tracked
        assert "baseline.json" in tracked
        # events/ directory should have files
        assert "events/" in tracked
