"""Unit tests for detect_repo_signals() and connector_status() in discover.py.

These tests exercise the pure functions directly, not the CLI layer.
No git init needed — these functions only look at filesystem paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mallcop.discover import connector_status, detect_repo_signals


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# ---------------------------------------------------------------------------
# detect_repo_signals — empty repo
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsEmpty:
    """Empty repo produces minimal signals (only secrets which is always active)."""

    def test_empty_repo_has_secrets_signal(self, tmp_path: Path) -> None:
        signals = detect_repo_signals(tmp_path)
        assert "secrets" in signals
        assert signals["secrets"] == ["source scan"]

    def test_empty_repo_has_no_aws_signal(self, tmp_path: Path) -> None:
        signals = detect_repo_signals(tmp_path)
        assert "aws" not in signals

    def test_empty_repo_has_no_dependency_scan_signal(self, tmp_path: Path) -> None:
        signals = detect_repo_signals(tmp_path)
        assert "dependency-scan" not in signals

    def test_empty_repo_has_no_azure_signal(self, tmp_path: Path) -> None:
        signals = detect_repo_signals(tmp_path)
        assert "azure" not in signals

    def test_empty_repo_has_no_ci_pipeline_signal(self, tmp_path: Path) -> None:
        signals = detect_repo_signals(tmp_path)
        assert "ci-pipeline" not in signals

    def test_empty_repo_returns_dict(self, tmp_path: Path) -> None:
        signals = detect_repo_signals(tmp_path)
        assert isinstance(signals, dict)


# ---------------------------------------------------------------------------
# detect_repo_signals — dependency-scan
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsDependencyScan:
    """dependency-scan connector is triggered by package manifest files."""

    def test_requirements_txt_triggers_dependency_scan(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "requests==2.31.0\nflask==3.0.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "dependency-scan" in signals
        combined = " ".join(signals["dependency-scan"])
        assert "requirements.txt" in combined

    def test_requirements_txt_signal_includes_package_count(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "requests==2.31.0\nflask==3.0.0\nboto3==1.34.0\n")
        signals = detect_repo_signals(tmp_path)
        combined = " ".join(signals["dependency-scan"])
        assert "3" in combined

    def test_empty_requirements_txt_does_not_trigger_dependency_scan(self, tmp_path: Path) -> None:
        # Empty file or only comments should not add a signal
        _write(tmp_path / "requirements.txt", "# just a comment\n")
        signals = detect_repo_signals(tmp_path)
        assert "dependency-scan" not in signals

    def test_package_json_triggers_dependency_scan(self, tmp_path: Path) -> None:
        pkg = {"name": "app", "dependencies": {"express": "^4.18.0"}}
        _write(tmp_path / "package.json", json.dumps(pkg))
        signals = detect_repo_signals(tmp_path)
        assert "dependency-scan" in signals
        combined = " ".join(signals["dependency-scan"])
        assert "package.json" in combined

    def test_package_json_with_no_deps_does_not_trigger_dependency_scan(self, tmp_path: Path) -> None:
        # package.json with no dependencies (empty or absent keys) should NOT add a signal
        pkg = {"name": "app", "version": "1.0.0"}
        _write(tmp_path / "package.json", json.dumps(pkg))
        signals = detect_repo_signals(tmp_path)
        assert "dependency-scan" not in signals

    def test_package_json_with_empty_deps_objects_does_not_trigger_dependency_scan(self, tmp_path: Path) -> None:
        # package.json with explicitly empty dependencies and devDependencies should NOT add a signal
        pkg = {"name": "app", "version": "1.0.0", "dependencies": {}, "devDependencies": {}}
        _write(tmp_path / "package.json", json.dumps(pkg))
        signals = detect_repo_signals(tmp_path)
        assert "dependency-scan" not in signals

    def test_go_mod_triggers_dependency_scan(self, tmp_path: Path) -> None:
        _write(tmp_path / "go.mod", "module example.com/myapp\n\ngo 1.21\n")
        signals = detect_repo_signals(tmp_path)
        assert "dependency-scan" in signals
        combined = " ".join(signals["dependency-scan"])
        assert "go.mod" in combined

    def test_cargo_toml_triggers_dependency_scan(self, tmp_path: Path) -> None:
        _write(tmp_path / "Cargo.toml", "[package]\nname = \"myapp\"\nversion = \"0.1.0\"\n")
        signals = detect_repo_signals(tmp_path)
        assert "dependency-scan" in signals
        combined = " ".join(signals["dependency-scan"])
        assert "Cargo.toml" in combined

    def test_poetry_lock_triggers_dependency_scan(self, tmp_path: Path) -> None:
        _write(tmp_path / "poetry.lock", "# This file is automatically generated\n")
        signals = detect_repo_signals(tmp_path)
        assert "dependency-scan" in signals
        combined = " ".join(signals["dependency-scan"])
        assert "poetry.lock" in combined

    def test_multiple_manifests_accumulate_signals(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
        _write(tmp_path / "go.mod", "module example.com/myapp\n\ngo 1.21\n")
        pkg = {"name": "app", "dependencies": {"express": "^4.18.0"}}
        _write(tmp_path / "package.json", json.dumps(pkg))
        signals = detect_repo_signals(tmp_path)
        assert "dependency-scan" in signals
        # Three signals: requirements.txt, go.mod, package.json
        assert len(signals["dependency-scan"]) == 3


# ---------------------------------------------------------------------------
# detect_repo_signals — AWS
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsAWS:
    """AWS connector detection from Python deps, Node deps, env files."""

    def test_boto3_in_requirements_triggers_aws(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "boto3==1.34.0\nrequests==2.31.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "aws" in signals
        combined = " ".join(signals["aws"])
        assert "boto3" in combined

    def test_botocore_in_requirements_triggers_aws(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "botocore==1.34.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "aws" in signals

    def test_aws_sdk_node_package_triggers_aws(self, tmp_path: Path) -> None:
        pkg = {"name": "app", "dependencies": {"@aws-sdk/client-s3": "^3.0.0"}}
        _write(tmp_path / "package.json", json.dumps(pkg))
        signals = detect_repo_signals(tmp_path)
        assert "aws" in signals
        combined = " ".join(signals["aws"])
        assert "@aws-sdk" in combined

    def test_legacy_aws_sdk_node_package_triggers_aws(self, tmp_path: Path) -> None:
        pkg = {"name": "app", "dependencies": {"aws-sdk": "^2.0.0"}}
        _write(tmp_path / "package.json", json.dumps(pkg))
        signals = detect_repo_signals(tmp_path)
        assert "aws" in signals

    def test_aws_vars_in_env_example_triggers_aws(self, tmp_path: Path) -> None:
        _write(tmp_path / ".env.example", "AWS_ACCESS_KEY_ID=\nAWS_SECRET_ACCESS_KEY=\nAWS_REGION=us-east-1\n")
        signals = detect_repo_signals(tmp_path)
        assert "aws" in signals
        combined = " ".join(signals["aws"])
        assert ".env.example" in combined

    def test_aws_vars_in_env_sample_triggers_aws(self, tmp_path: Path) -> None:
        _write(tmp_path / ".env.sample", "AWS_REGION=us-east-1\n")
        signals = detect_repo_signals(tmp_path)
        assert "aws" in signals

    def test_no_aws_packages_no_aws_signal(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "requests==2.31.0\nflask==3.0.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "aws" not in signals

    def test_non_aws_env_vars_do_not_trigger_aws(self, tmp_path: Path) -> None:
        _write(tmp_path / ".env.example", "DATABASE_URL=postgres://localhost/db\nSECRET_KEY=abc\n")
        signals = detect_repo_signals(tmp_path)
        assert "aws" not in signals


# ---------------------------------------------------------------------------
# detect_repo_signals — Azure
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsAzure:
    """Azure connector detection from Node packages, Python packages, .azure dir."""

    def test_azure_node_package_triggers_azure(self, tmp_path: Path) -> None:
        pkg = {"name": "app", "dependencies": {"@azure/identity": "^3.0.0"}}
        _write(tmp_path / "package.json", json.dumps(pkg))
        signals = detect_repo_signals(tmp_path)
        assert "azure" in signals
        combined = " ".join(signals["azure"])
        assert "@azure" in combined

    def test_azure_python_package_triggers_azure(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "azure-identity==1.15.0\nrequests==2.31.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "azure" in signals

    def test_azure_directory_triggers_azure(self, tmp_path: Path) -> None:
        (tmp_path / ".azure").mkdir()
        signals = detect_repo_signals(tmp_path)
        assert "azure" in signals
        combined = " ".join(signals["azure"])
        assert ".azure" in combined

    def test_no_azure_indicators_no_azure_signal(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "azure" not in signals


# ---------------------------------------------------------------------------
# detect_repo_signals — CI pipeline
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsCIPipeline:
    """CI pipeline detection from .github/workflows/ directory."""

    def test_github_workflows_yml_triggers_ci_pipeline(self, tmp_path: Path) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        _write(wf_dir / "ci.yml", "name: CI\non: [push]\n")
        signals = detect_repo_signals(tmp_path)
        assert "ci-pipeline" in signals
        combined = " ".join(signals["ci-pipeline"])
        assert ".github/workflows" in combined

    def test_github_workflows_yaml_triggers_ci_pipeline(self, tmp_path: Path) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        _write(wf_dir / "deploy.yaml", "name: Deploy\non: [push]\n")
        signals = detect_repo_signals(tmp_path)
        assert "ci-pipeline" in signals

    def test_multiple_workflow_files_counted_in_signal(self, tmp_path: Path) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        _write(wf_dir / "ci.yml", "name: CI\n")
        _write(wf_dir / "release.yml", "name: Release\n")
        _write(wf_dir / "deploy.yaml", "name: Deploy\n")
        signals = detect_repo_signals(tmp_path)
        assert "ci-pipeline" in signals
        combined = " ".join(signals["ci-pipeline"])
        assert "3" in combined

    def test_empty_workflows_dir_no_ci_signal(self, tmp_path: Path) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        # No .yml or .yaml files
        signals = detect_repo_signals(tmp_path)
        assert "ci-pipeline" not in signals

    def test_github_dir_without_workflows_no_ci_signal(self, tmp_path: Path) -> None:
        (tmp_path / ".github").mkdir()
        signals = detect_repo_signals(tmp_path)
        assert "ci-pipeline" not in signals


# ---------------------------------------------------------------------------
# detect_repo_signals — container scan
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsContainerScan:
    """container-scan triggered by Dockerfile or docker-compose files."""

    def test_dockerfile_triggers_container_scan(self, tmp_path: Path) -> None:
        _write(tmp_path / "Dockerfile", "FROM ubuntu:22.04\n")
        signals = detect_repo_signals(tmp_path)
        assert "container-scan" in signals
        combined = " ".join(signals["container-scan"])
        assert "Dockerfile" in combined

    def test_docker_compose_yml_triggers_container_scan(self, tmp_path: Path) -> None:
        _write(tmp_path / "docker-compose.yml", "version: '3'\nservices:\n  app:\n    image: nginx\n")
        signals = detect_repo_signals(tmp_path)
        assert "container-scan" in signals

    def test_docker_compose_yaml_triggers_container_scan(self, tmp_path: Path) -> None:
        _write(tmp_path / "docker-compose.yaml", "version: '3'\nservices:\n  app:\n    image: nginx\n")
        signals = detect_repo_signals(tmp_path)
        assert "container-scan" in signals

    def test_multiple_container_files_combined_in_single_signal(self, tmp_path: Path) -> None:
        _write(tmp_path / "Dockerfile", "FROM ubuntu:22.04\n")
        _write(tmp_path / "docker-compose.yml", "version: '3'\n")
        signals = detect_repo_signals(tmp_path)
        assert "container-scan" in signals
        # Combined into one signal entry
        assert len(signals["container-scan"]) == 1
        combined = signals["container-scan"][0]
        assert "Dockerfile" in combined
        assert "docker-compose.yml" in combined

    def test_no_docker_files_no_container_scan_signal(self, tmp_path: Path) -> None:
        signals = detect_repo_signals(tmp_path)
        assert "container-scan" not in signals


# ---------------------------------------------------------------------------
# detect_repo_signals — deployment
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsDeployment:
    """deployment connector triggered by Vercel, Netlify, Railway config files."""

    def test_vercel_json_triggers_deployment(self, tmp_path: Path) -> None:
        _write(tmp_path / "vercel.json", '{"version": 2}\n')
        signals = detect_repo_signals(tmp_path)
        assert "deployment" in signals
        combined = " ".join(signals["deployment"])
        assert "vercel.json" in combined

    def test_vercel_dir_triggers_deployment(self, tmp_path: Path) -> None:
        (tmp_path / ".vercel").mkdir()
        signals = detect_repo_signals(tmp_path)
        assert "deployment" in signals

    def test_netlify_toml_triggers_deployment(self, tmp_path: Path) -> None:
        _write(tmp_path / "netlify.toml", "[build]\n  command = \"npm run build\"\n")
        signals = detect_repo_signals(tmp_path)
        assert "deployment" in signals
        combined = " ".join(signals["deployment"])
        assert "netlify.toml" in combined

    def test_railway_toml_triggers_deployment(self, tmp_path: Path) -> None:
        _write(tmp_path / "railway.toml", "[build]\n  builder = \"nixpacks\"\n")
        signals = detect_repo_signals(tmp_path)
        assert "deployment" in signals
        combined = " ".join(signals["deployment"])
        assert "railway.toml" in combined

    def test_no_deployment_files_no_deployment_signal(self, tmp_path: Path) -> None:
        signals = detect_repo_signals(tmp_path)
        assert "deployment" not in signals


# ---------------------------------------------------------------------------
# detect_repo_signals — database
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsDatabase:
    """database connector triggered by ORM schema files and DB env vars."""

    def test_prisma_schema_triggers_database(self, tmp_path: Path) -> None:
        _write(tmp_path / "prisma" / "schema.prisma", 'datasource db {\n  provider = "postgresql"\n}\n')
        signals = detect_repo_signals(tmp_path)
        assert "database" in signals
        combined = " ".join(signals["database"])
        assert "prisma/schema.prisma" in combined

    def test_drizzle_config_ts_triggers_database(self, tmp_path: Path) -> None:
        _write(tmp_path / "drizzle.config.ts", "export default defineConfig({});\n")
        signals = detect_repo_signals(tmp_path)
        assert "database" in signals

    def test_drizzle_config_js_triggers_database(self, tmp_path: Path) -> None:
        _write(tmp_path / "drizzle.config.js", "module.exports = {};\n")
        signals = detect_repo_signals(tmp_path)
        assert "database" in signals

    def test_sqlalchemy_in_requirements_triggers_database(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "sqlalchemy==2.0.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "database" in signals

    def test_alembic_in_requirements_triggers_database(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "alembic==1.13.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "database" in signals

    def test_database_url_in_env_example_triggers_database(self, tmp_path: Path) -> None:
        _write(tmp_path / ".env.example", "DATABASE_URL=postgres://localhost/mydb\n")
        signals = detect_repo_signals(tmp_path)
        assert "database" in signals
        combined = " ".join(signals["database"])
        assert ".env.example" in combined

    def test_postgres_var_in_env_triggers_database(self, tmp_path: Path) -> None:
        _write(tmp_path / ".env.example", "POSTGRES_URL=postgres://localhost/mydb\n")
        signals = detect_repo_signals(tmp_path)
        assert "database" in signals

    def test_no_database_indicators_no_database_signal(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "database" not in signals


# ---------------------------------------------------------------------------
# detect_repo_signals — auth-provider
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsAuthProvider:
    """auth-provider triggered by Supabase packages or supabase/config.toml."""

    def test_supabase_node_package_triggers_auth_provider(self, tmp_path: Path) -> None:
        pkg = {"name": "app", "dependencies": {"@supabase/supabase-js": "^2.0.0"}}
        _write(tmp_path / "package.json", json.dumps(pkg))
        signals = detect_repo_signals(tmp_path)
        assert "auth-provider" in signals
        combined = " ".join(signals["auth-provider"])
        assert "@supabase" in combined

    def test_supabase_config_toml_triggers_auth_provider(self, tmp_path: Path) -> None:
        _write(tmp_path / "supabase" / "config.toml", "[api]\nport = 54321\n")
        signals = detect_repo_signals(tmp_path)
        assert "auth-provider" in signals
        combined = " ".join(signals["auth-provider"])
        assert "supabase/config.toml" in combined

    def test_supabase_dir_without_config_toml_no_signal(self, tmp_path: Path) -> None:
        # supabase dir exists but no config.toml
        (tmp_path / "supabase").mkdir()
        signals = detect_repo_signals(tmp_path)
        # Should not trigger based on empty supabase dir alone
        # (config.toml is required per implementation)
        assert "auth-provider" not in signals


# ---------------------------------------------------------------------------
# detect_repo_signals — M365
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsM365:
    """M365 connector triggered by msgraph/msal packages."""

    def test_msgraph_python_package_triggers_m365(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "msgraph-sdk==1.0.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "m365" in signals

    def test_msal_python_package_triggers_m365(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "msal==1.24.0\n")
        signals = detect_repo_signals(tmp_path)
        assert "m365" in signals

    def test_microsoft_graph_client_node_triggers_m365(self, tmp_path: Path) -> None:
        pkg = {"name": "app", "dependencies": {"@microsoft/microsoft-graph-client": "^3.0.0"}}
        _write(tmp_path / "package.json", json.dumps(pkg))
        signals = detect_repo_signals(tmp_path)
        assert "m365" in signals

    def test_unrelated_microsoft_package_no_m365_signal(self, tmp_path: Path) -> None:
        pkg = {"name": "app", "dependencies": {"@microsoft/teams-js": "^2.0.0"}}
        _write(tmp_path / "package.json", json.dumps(pkg))
        signals = detect_repo_signals(tmp_path)
        assert "m365" not in signals


# ---------------------------------------------------------------------------
# detect_repo_signals — openclaw
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsOpenClaw:
    """openclaw triggered by ~/.openclaw directory existence."""

    def test_openclaw_dir_at_home_triggers_openclaw(self, tmp_path: Path) -> None:
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        (fake_home / ".openclaw").mkdir()
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        with patch("mallcop.discover.Path.home", return_value=fake_home):
            signals = detect_repo_signals(repo_dir)
        assert "openclaw" in signals
        combined = " ".join(signals["openclaw"])
        assert "~/.openclaw" in combined

    def test_no_openclaw_dir_no_openclaw_signal(self, tmp_path: Path) -> None:
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        with patch("mallcop.discover.Path.home", return_value=fake_home):
            signals = detect_repo_signals(repo_dir)
        assert "openclaw" not in signals


# ---------------------------------------------------------------------------
# detect_repo_signals — return structure invariants
# ---------------------------------------------------------------------------


class TestDetectRepoSignalsInvariants:
    """Structural invariants: return type, signal values."""

    def test_returns_dict(self, tmp_path: Path) -> None:
        signals = detect_repo_signals(tmp_path)
        assert isinstance(signals, dict)

    def test_all_signal_values_are_lists(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "boto3==1.34.0\n")
        _write(tmp_path / "Dockerfile", "FROM ubuntu:22.04\n")
        signals = detect_repo_signals(tmp_path)
        for key, value in signals.items():
            assert isinstance(value, list), f"{key} value should be a list, got {type(value)}"

    def test_all_signal_entries_are_strings(self, tmp_path: Path) -> None:
        _write(tmp_path / "requirements.txt", "boto3==1.34.0\n")
        signals = detect_repo_signals(tmp_path)
        for key, value in signals.items():
            for entry in value:
                assert isinstance(entry, str), f"{key}[...] entry should be str, got {type(entry)}"

    def test_secrets_always_present_regardless_of_content(self, tmp_path: Path) -> None:
        # No files at all
        signals = detect_repo_signals(tmp_path)
        assert "secrets" in signals

    def test_secrets_signal_always_source_scan(self, tmp_path: Path) -> None:
        signals = detect_repo_signals(tmp_path)
        assert "source scan" in signals["secrets"]


# ---------------------------------------------------------------------------
# connector_status
# ---------------------------------------------------------------------------


class TestConnectorStatus:
    """connector_status() derives correct status from signals and secrets."""

    # -- no-credential connectors --

    def test_secrets_active_when_detected(self) -> None:
        status = connector_status("secrets", ["source scan"], {})
        assert status == "active"

    def test_secrets_available_when_no_signals(self) -> None:
        # secrets always has signals, but test the logic path
        status = connector_status("secrets", [], {})
        assert status == "available"

    def test_dependency_scan_active_when_detected(self) -> None:
        status = connector_status("dependency-scan", ["requirements.txt (3 packages)"], {})
        assert status == "active"

    def test_dependency_scan_available_when_no_signals(self) -> None:
        status = connector_status("dependency-scan", [], {})
        assert status == "available"

    def test_database_active_when_detected(self) -> None:
        status = connector_status("database", ["prisma/schema.prisma"], {})
        assert status == "active"

    def test_database_available_when_no_signals(self) -> None:
        status = connector_status("database", [], {})
        assert status == "available"

    def test_openclaw_active_when_detected(self) -> None:
        status = connector_status("openclaw", ["~/.openclaw found"], {})
        assert status == "active"

    def test_openclaw_available_when_no_signals(self) -> None:
        status = connector_status("openclaw", [], {})
        assert status == "available"

    # -- connectors with required credentials: detected (signals present, creds missing) --

    def test_aws_detected_when_signals_but_no_creds(self) -> None:
        secrets = {
            "AWS_ACCESS_KEY_ID": "missing",
            "AWS_SECRET_ACCESS_KEY": "missing",
            "AWS_REGION": "missing",
        }
        status = connector_status("aws", ["boto3 in requirements.txt"], secrets)
        assert status == "detected"

    def test_aws_detected_when_some_required_creds_missing(self) -> None:
        # Only access key present, secret missing
        secrets = {
            "AWS_ACCESS_KEY_ID": "present",
            "AWS_SECRET_ACCESS_KEY": "missing",
            "AWS_REGION": "present",
        }
        status = connector_status("aws", ["boto3 in requirements.txt"], secrets)
        assert status == "detected"

    def test_ci_pipeline_detected_with_signals_no_token(self) -> None:
        secrets = {"GITHUB_TOKEN": "missing"}
        status = connector_status("ci-pipeline", [".github/workflows/ (2 workflow files)"], secrets)
        assert status == "detected"

    # -- connectors with required credentials: active (signals present, valid creds) --

    def test_aws_active_when_signals_and_all_creds_present(self) -> None:
        valid_key = "A" * 20  # >= 16 chars for AWS_ACCESS_KEY_ID
        valid_secret = "S" * 25  # >= 20 chars for AWS_SECRET_ACCESS_KEY
        secrets = {
            "AWS_ACCESS_KEY_ID": "present",
            "AWS_SECRET_ACCESS_KEY": "present",
            "AWS_REGION": "present",
        }
        env = {
            "AWS_ACCESS_KEY_ID": valid_key,
            "AWS_SECRET_ACCESS_KEY": valid_secret,
            "AWS_REGION": "us-east-1",
        }
        status = connector_status("aws", ["boto3 in requirements.txt"], secrets, env)
        assert status == "active"

    def test_ci_pipeline_active_with_signals_and_valid_token(self) -> None:
        valid_token = "ghp_" + "x" * 36  # >= 20 chars
        secrets = {"GITHUB_TOKEN": "present"}
        env = {"GITHUB_TOKEN": valid_token}
        status = connector_status("ci-pipeline", [".github/workflows/ (1 workflow files)"], secrets, env)
        assert status == "active"

    # -- no signals, creds present: active (creds configured but connector not auto-detected) --

    def test_aws_active_when_no_signals_but_valid_creds(self) -> None:
        valid_key = "A" * 20
        valid_secret = "S" * 25
        secrets = {
            "AWS_ACCESS_KEY_ID": "present",
            "AWS_SECRET_ACCESS_KEY": "present",
            "AWS_REGION": "present",
        }
        env = {
            "AWS_ACCESS_KEY_ID": valid_key,
            "AWS_SECRET_ACCESS_KEY": valid_secret,
            "AWS_REGION": "us-east-1",
        }
        status = connector_status("aws", [], secrets, env)
        assert status == "active"

    # -- no signals, creds missing: available --

    def test_aws_available_when_no_signals_and_no_creds(self) -> None:
        secrets = {
            "AWS_ACCESS_KEY_ID": "missing",
            "AWS_SECRET_ACCESS_KEY": "missing",
            "AWS_REGION": "missing",
        }
        status = connector_status("aws", [], secrets)
        assert status == "available"

    def test_azure_available_when_no_signals_no_creds(self) -> None:
        secrets = {
            "AZURE_TENANT_ID": "missing",
            "AZURE_CLIENT_ID": "missing",
            "AZURE_CLIENT_SECRET": "missing",
            "AZURE_SUBSCRIPTION_ID": "missing",
        }
        status = connector_status("azure", [], secrets)
        assert status == "available"

    # -- error: creds present but fail validation --

    def test_aws_error_when_creds_present_but_too_short(self) -> None:
        # Short values that fail _validate_credential min-length checks
        secrets = {
            "AWS_ACCESS_KEY_ID": "present",
            "AWS_SECRET_ACCESS_KEY": "present",
            "AWS_REGION": "present",
        }
        env = {
            "AWS_ACCESS_KEY_ID": "short",  # < 16 chars
            "AWS_SECRET_ACCESS_KEY": "short",  # < 20 chars
            "AWS_REGION": "us-east-1",
        }
        status = connector_status("aws", ["boto3 in requirements.txt"], secrets, env)
        assert status == "error"

    def test_github_token_error_when_present_but_placeholder(self) -> None:
        secrets = {"GITHUB_TOKEN": "present"}
        env = {"GITHUB_TOKEN": "token"}  # < 20 chars
        status = connector_status("ci-pipeline", [".github/workflows/ (1 workflow files)"], secrets, env)
        assert status == "error"

    # -- azure detected, active, and error paths --

    def test_azure_detected_with_signals_missing_creds(self) -> None:
        secrets = {
            "AZURE_TENANT_ID": "missing",
            "AZURE_CLIENT_ID": "missing",
            "AZURE_CLIENT_SECRET": "missing",
            "AZURE_SUBSCRIPTION_ID": "missing",
        }
        status = connector_status("azure", ["@azure/identity in package.json"], secrets)
        assert status == "detected"

    def test_azure_active_with_signals_and_valid_creds(self) -> None:
        secrets = {
            "AZURE_TENANT_ID": "present",
            "AZURE_CLIENT_ID": "present",
            "AZURE_CLIENT_SECRET": "present",
            "AZURE_SUBSCRIPTION_ID": "present",
        }
        env = {
            "AZURE_TENANT_ID": "tenant-id-1234",
            "AZURE_CLIENT_ID": "client-id-5678",
            "AZURE_CLIENT_SECRET": "clientsecret99",  # >= 8 chars
            "AZURE_SUBSCRIPTION_ID": "sub-id-abcd",
        }
        status = connector_status("azure", ["@azure/identity in package.json"], secrets, env)
        assert status == "active"

    # -- m365 paths --

    def test_m365_detected_with_signals_missing_creds(self) -> None:
        secrets = {
            "M365_TENANT_ID": "missing",
            "M365_CLIENT_ID": "missing",
            "M365_CLIENT_SECRET": "missing",
        }
        status = connector_status("m365", ["msgraph-sdk in requirements.txt"], secrets)
        assert status == "detected"

    def test_m365_active_with_all_creds(self) -> None:
        secrets = {
            "M365_TENANT_ID": "present",
            "M365_CLIENT_ID": "present",
            "M365_CLIENT_SECRET": "present",
        }
        env = {
            "M365_TENANT_ID": "my-tenant-id",
            "M365_CLIENT_ID": "my-client-id",
            "M365_CLIENT_SECRET": "mysecretvalue99",  # >= 8 chars
        }
        status = connector_status("m365", ["msgraph-sdk in requirements.txt"], secrets, env)
        assert status == "active"

    # -- auth-provider paths --

    def test_auth_provider_detected_with_signals_missing_creds(self) -> None:
        secrets = {
            "SUPABASE_PROJECT_URL": "missing",
            "SUPABASE_SERVICE_ROLE_KEY": "missing",
        }
        status = connector_status("auth-provider", ["@supabase/supabase-js in package.json"], secrets)
        assert status == "detected"

    def test_auth_provider_active_with_valid_creds(self) -> None:
        secrets = {
            "SUPABASE_PROJECT_URL": "present",
            "SUPABASE_SERVICE_ROLE_KEY": "present",
        }
        env = {
            "SUPABASE_PROJECT_URL": "https://xyz.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.placeholder",
        }
        status = connector_status(
            "auth-provider", ["@supabase/supabase-js in package.json"], secrets, env
        )
        assert status == "active"

    # -- return value is always a valid status string --

    @pytest.mark.parametrize("connector_type", [
        "dependency-scan",
        "aws",
        "azure",
        "auth-provider",
        "ci-pipeline",
        "container-scan",
        "m365",
        "openclaw",
        "supabase",
        "deployment",
        "database",
        "secrets",
    ])
    def test_connector_status_always_returns_valid_enum(self, connector_type: str) -> None:
        valid_statuses = {"active", "detected", "error", "available"}
        # Test with no signals, no secrets
        status = connector_status(connector_type, [], {})
        assert status in valid_statuses, f"{connector_type} returned invalid status: {status}"
