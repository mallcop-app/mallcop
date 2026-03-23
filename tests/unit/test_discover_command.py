"""Tests for mallcop discover command.

TDD: tests written before implementation.

Done condition: mallcop discover runs against 3+ real repos:
- one with AWS deps (boto3 in requirements.txt)
- one with Node deps (package.json)
- one empty repo with no deps

Writes valid discovery.json. Bootstrap mode works without mallcop.yaml.
Tests run against real repo checkouts (tmp_path), not mocked file trees.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from mallcop.cli import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _init_git_repo(path: Path) -> None:
    """Initialize a git repo with a remote origin set to a fake owner/name."""
    subprocess.run(["git", "init", str(path)], check=True, capture_output=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/test-org/test-repo"],
        cwd=str(path),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(path),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(path),
        check=True,
        capture_output=True,
    )


def _run_discover(repo_path: Path, extra_args: list[str] | None = None) -> dict:
    """Run mallcop discover against repo_path, return parsed JSON output."""
    runner = CliRunner()
    args = ["discover", "--dir", str(repo_path)] + (extra_args or [])
    result = runner.invoke(cli, args, catch_exceptions=False, env={})
    # Use mix_stderr=False so stdout is clean
    assert result.exit_code == 0, f"exit_code={result.exit_code}\n{result.output}"
    return json.loads(result.output)


# ---------------------------------------------------------------------------
# Schema validation: discovery.json top-level fields
# ---------------------------------------------------------------------------


class TestDiscoveryJsonSchema:
    """discovery.json schema validation — every required field must be present."""

    def test_schema_version_is_1_0(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        assert out["schema_version"] == "1.0"

    def test_generated_at_is_iso_timestamp(self, tmp_path: Path) -> None:
        from datetime import datetime
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        # Must parse without error
        datetime.fromisoformat(out["generated_at"].replace("Z", "+00:00"))

    def test_cli_version_is_present(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        assert "cli_version" in out
        assert isinstance(out["cli_version"], str)
        assert len(out["cli_version"]) > 0

    def test_repo_field_present(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        assert "repo" in out

    def test_coverage_object_present(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        cov = out["coverage"]
        assert "percentage" in cov
        assert "active_count" in cov
        assert "detected_count" in cov
        assert "available_count" in cov
        assert "total_possible" in cov

    def test_coverage_percentage_is_int(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        assert isinstance(out["coverage"]["percentage"], int)
        assert 0 <= out["coverage"]["percentage"] <= 100

    def test_connectors_is_list(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        assert isinstance(out["connectors"], list)

    def test_each_connector_has_required_fields(self, tmp_path: Path) -> None:
        """Every connector entry must have required fields."""
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        required = {
            "type", "status", "category", "display_name", "description",
            "detection_signals", "secrets_required", "secrets_status",
            "last_run", "last_run_result", "finding_count",
        }
        for connector in out["connectors"]:
            missing = required - set(connector.keys())
            assert not missing, f"Connector {connector.get('type')} missing fields: {missing}"

    def test_connector_status_is_valid_enum(self, tmp_path: Path) -> None:
        valid_statuses = {"active", "detected", "error", "available"}
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        for connector in out["connectors"]:
            assert connector["status"] in valid_statuses, (
                f"Connector {connector['type']} has invalid status: {connector['status']}"
            )

    def test_connector_secrets_required_is_list_of_objects(self, tmp_path: Path) -> None:
        """secrets_required must be a list; each item must have name, description, how_to_get."""
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        for connector in out["connectors"]:
            assert isinstance(connector["secrets_required"], list)
            for secret in connector["secrets_required"]:
                assert "name" in secret
                assert "description" in secret
                assert "how_to_get" in secret

    def test_connector_finding_count_is_int(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        out = _run_discover(tmp_path)
        for connector in out["connectors"]:
            assert isinstance(connector["finding_count"], int)


# ---------------------------------------------------------------------------
# discovery.json written to disk
# ---------------------------------------------------------------------------


class TestDiscoveryJsonWrittenToDisk:
    """discover writes .mallcop/discovery.json to the target directory."""

    def test_discovery_json_file_written(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            pass  # just init; we use invoke with cwd-patching
        # Run discover which should write .mallcop/discovery.json
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "repo"
            dest.mkdir()
            _init_git_repo(dest)
            runner.invoke(cli, ["discover", "--dir", str(dest)], catch_exceptions=False)
            discovery_path = dest / ".mallcop" / "discovery.json"
            assert discovery_path.exists(), f"Expected {discovery_path} to exist"

    def test_discovery_json_is_valid_json(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "repo"
            dest.mkdir()
            _init_git_repo(dest)
            runner.invoke(cli, ["discover", "--dir", str(dest)], catch_exceptions=False)
            content = (dest / ".mallcop" / "discovery.json").read_text()
            data = json.loads(content)
            assert data["schema_version"] == "1.0"

    def test_mallcop_dir_created_if_missing(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "repo"
            dest.mkdir()
            _init_git_repo(dest)
            assert not (dest / ".mallcop").exists()
            runner.invoke(cli, ["discover", "--dir", str(dest)], catch_exceptions=False)
            assert (dest / ".mallcop").exists()


# ---------------------------------------------------------------------------
# Bootstrap mode: no mallcop.yaml
# ---------------------------------------------------------------------------


class TestBootstrapMode:
    """discover works without mallcop.yaml (bootstrap mode)."""

    def test_discover_runs_without_mallcop_yaml(self, tmp_path: Path) -> None:
        _init_git_repo(tmp_path)
        assert not (tmp_path / "mallcop.yaml").exists()
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "repo"
            dest.mkdir()
            _init_git_repo(dest)
            result = runner.invoke(cli, ["discover", "--dir", str(dest)], catch_exceptions=False)
            assert result.exit_code == 0

    def test_detected_connectors_have_status_detected_not_active_without_credentials(
        self, tmp_path: Path
    ) -> None:
        """Without credentials, detected connectors must not show as active."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "repo"
            dest.mkdir()
            _init_git_repo(dest)
            # Add AWS signal
            (dest / "requirements.txt").write_text("boto3==1.34.0\nrequests==2.31.0\n")
            # Run with no AWS credentials in env
            result = runner.invoke(
                cli,
                ["discover", "--dir", str(dest)],
                catch_exceptions=False,
                env={},  # no env vars → no credentials
            )
            assert result.exit_code == 0
            out = json.loads(result.output)
            aws_connector = next(
                (c for c in out["connectors"] if c["type"] == "aws"), None
            )
            if aws_connector is not None:
                assert aws_connector["status"] in {"detected", "error"}, (
                    f"Expected detected/error without credentials, got {aws_connector['status']}"
                )


# ---------------------------------------------------------------------------
# Repo content detection: AWS (boto3 in requirements.txt)
# ---------------------------------------------------------------------------


class TestRepoContentDetectionAWS:
    """Repo with boto3 in requirements.txt triggers aws detection."""

    def _make_aws_repo(self, dest: Path) -> None:
        _init_git_repo(dest)
        (dest / "requirements.txt").write_text(
            "boto3==1.34.0\nbotocore==1.34.0\nrequests==2.31.0\n"
        )

    def test_boto3_requirements_txt_detects_aws_connector(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "aws-repo"
            dest.mkdir()
            self._make_aws_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            assert result.exit_code == 0
            out = json.loads(result.output)
            connectors_by_type = {c["type"]: c for c in out["connectors"]}
            assert "aws" in connectors_by_type, (
                f"Expected aws in connectors, got: {list(connectors_by_type.keys())}"
            )

    def test_boto3_detection_signal_references_requirements_txt(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "aws-repo"
            dest.mkdir()
            self._make_aws_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            out = json.loads(result.output)
            connectors_by_type = {c["type"]: c for c in out["connectors"]}
            aws = connectors_by_type.get("aws")
            if aws is not None:
                signals = " ".join(aws["detection_signals"]).lower()
                assert "boto3" in signals or "requirements" in signals, (
                    f"Expected boto3/requirements in detection_signals, got: {aws['detection_signals']}"
                )

    def test_aws_connector_missing_credentials_shows_secrets_status(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "aws-repo"
            dest.mkdir()
            self._make_aws_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            out = json.loads(result.output)
            aws = next((c for c in out["connectors"] if c["type"] == "aws"), None)
            if aws is not None:
                # secrets_status should indicate missing credentials
                assert len(aws["secrets_status"]) > 0, "Expected secrets_status to be populated"


# ---------------------------------------------------------------------------
# Repo content detection: Node (package.json)
# ---------------------------------------------------------------------------


class TestRepoContentDetectionNode:
    """Repo with package.json triggers dependency-scan detection."""

    def _make_node_repo(self, dest: Path) -> None:
        _init_git_repo(dest)
        package_json = {
            "name": "my-app",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "^4.17.21",
            },
            "devDependencies": {
                "jest": "^29.0.0",
            },
        }
        (dest / "package.json").write_text(json.dumps(package_json, indent=2))

    def test_package_json_triggers_detection(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "node-repo"
            dest.mkdir()
            self._make_node_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            assert result.exit_code == 0
            out = json.loads(result.output)
            # At least one connector should reference package.json in detection_signals
            all_signals = [
                sig
                for c in out["connectors"]
                for sig in c["detection_signals"]
            ]
            assert any("package.json" in s for s in all_signals), (
                f"Expected package.json in detection signals, got: {all_signals}"
            )

    def test_node_with_aws_sdk_detects_aws(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "node-aws-repo"
            dest.mkdir()
            _init_git_repo(dest)
            package_json = {
                "name": "my-aws-app",
                "dependencies": {
                    "@aws-sdk/client-s3": "^3.0.0",
                    "express": "^4.18.0",
                },
            }
            (dest / "package.json").write_text(json.dumps(package_json, indent=2))
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            out = json.loads(result.output)
            connectors_by_type = {c["type"]: c for c in out["connectors"]}
            assert "aws" in connectors_by_type, (
                f"Expected aws when @aws-sdk/* present, got: {list(connectors_by_type.keys())}"
            )


# ---------------------------------------------------------------------------
# Repo content detection: empty repo
# ---------------------------------------------------------------------------


class TestEmptyRepo:
    """Empty repo (no deps): discover runs, reports available connectors."""

    def test_empty_repo_discover_succeeds(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "empty-repo"
            dest.mkdir()
            _init_git_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            assert result.exit_code == 0

    def test_empty_repo_has_no_detected_connectors(self, tmp_path: Path) -> None:
        """Empty repo: no detection signals, so no 'detected' connectors."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "empty-repo"
            dest.mkdir()
            _init_git_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            out = json.loads(result.output)
            detected = [c for c in out["connectors"] if c["status"] == "detected"]
            assert len(detected) == 0, (
                f"Empty repo should have no detected connectors, got: {detected}"
            )

    def test_empty_repo_coverage_active_connectors_match_active_count(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "empty-repo"
            dest.mkdir()
            _init_git_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            out = json.loads(result.output)
            active_in_list = len([c for c in out["connectors"] if c["status"] == "active"])
            assert out["coverage"]["active_count"] == active_in_list


# ---------------------------------------------------------------------------
# Coverage calculation correctness
# ---------------------------------------------------------------------------


class TestCoverageCalculation:
    """Coverage metrics are calculated correctly from connector statuses."""

    def test_coverage_counts_match_connector_list(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "repo"
            dest.mkdir()
            _init_git_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            out = json.loads(result.output)
            connectors = out["connectors"]
            cov = out["coverage"]

            active = len([c for c in connectors if c["status"] == "active"])
            detected = len([c for c in connectors if c["status"] == "detected"])
            available = len([c for c in connectors if c["status"] == "available"])

            assert cov["active_count"] == active
            assert cov["detected_count"] == detected
            assert cov["available_count"] == available
            assert cov["total_possible"] == len(connectors)

    def test_coverage_percentage_formula(self, tmp_path: Path) -> None:
        """percentage == round((active_count / total_possible) * 100)"""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "repo"
            dest.mkdir()
            _init_git_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            out = json.loads(result.output)
            cov = out["coverage"]
            if cov["total_possible"] == 0:
                assert cov["percentage"] == 0
            else:
                expected = round((cov["active_count"] / cov["total_possible"]) * 100)
                assert cov["percentage"] == expected


# ---------------------------------------------------------------------------
# --json flag and --dir flag
# ---------------------------------------------------------------------------


class TestCLIFlags:
    """CLI flags: --json outputs JSON, --dir targets specific directory."""

    def test_json_flag_produces_parseable_output(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "repo"
            dest.mkdir()
            _init_git_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--json", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert "schema_version" in data

    def test_dir_flag_targets_specified_directory(self, tmp_path: Path) -> None:
        """--dir flag makes discover run against specified path, not cwd."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "target-repo"
            dest.mkdir()
            _init_git_repo(dest)
            (dest / "requirements.txt").write_text("boto3==1.34.0\n")
            # cwd is td, not dest — but --dir points to dest
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            assert result.exit_code == 0
            # discovery.json should be in dest, not td
            assert (dest / ".mallcop" / "discovery.json").exists()

    def test_discover_writes_to_dir_not_cwd(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "target-repo"
            dest.mkdir()
            _init_git_repo(dest)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            assert result.exit_code == 0
            # File is in dest
            assert (dest / ".mallcop" / "discovery.json").exists()
            # Not in td (cwd)
            assert not (Path(td) / ".mallcop" / "discovery.json").exists()


# ---------------------------------------------------------------------------
# Credential metadata from manifest
# ---------------------------------------------------------------------------


class TestCredentialMetadata:
    """secrets_required fields populated from connector manifest.yaml."""

    def test_aws_connector_has_credential_metadata(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "aws-repo"
            dest.mkdir()
            _init_git_repo(dest)
            (dest / "requirements.txt").write_text("boto3==1.34.0\n")
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            out = json.loads(result.output)
            aws = next((c for c in out["connectors"] if c["type"] == "aws"), None)
            assert aws is not None
            assert len(aws["secrets_required"]) > 0, (
                "aws should have secrets_required metadata"
            )
            for secret in aws["secrets_required"]:
                assert "name" in secret
                assert "description" in secret
                assert "how_to_get" in secret
                assert "permissions_needed" in secret

    def test_no_credential_connector_has_empty_secrets_required(self, tmp_path: Path) -> None:
        """Connectors with no required auth have empty secrets_required.

        openclaw is detected by ~/.openclaw existing. We mock Path.home() to
        return dest so the detection signal fires without touching the real HOME.
        """
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "repo"
            dest.mkdir()
            _init_git_repo(dest)
            # Plant .openclaw in dest; mock Path.home() so detection finds it
            (dest / ".openclaw").mkdir()
            with patch("mallcop.discover.Path.home", return_value=dest):
                result = runner.invoke(
                    cli, ["discover", "--dir", str(dest)],
                    catch_exceptions=False, env={}
                )
            out = json.loads(result.output)
            openclaw = next((c for c in out["connectors"] if c["type"] == "openclaw"), None)
            assert openclaw is not None, "openclaw connector should be detected when ~/.openclaw exists"
            assert openclaw["secrets_required"] == []


# ---------------------------------------------------------------------------
# Repo identification
# ---------------------------------------------------------------------------


class TestRepoIdentification:
    """repo field in discovery.json identifies the repo."""

    def test_repo_field_from_git_remote(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "repo"
            dest.mkdir()
            _init_git_repo(dest)  # sets origin to github.com/test-org/test-repo
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            out = json.loads(result.output)
            # Should be "test-org/test-repo" (parsed from remote URL)
            assert "test-org" in out["repo"] or "test-repo" in out["repo"]

    def test_repo_field_fallback_when_no_remote(self, tmp_path: Path) -> None:
        """When no git remote, repo field uses directory name or empty string."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            dest = Path(td) / "my-project"
            dest.mkdir()
            # Init git but no remote
            subprocess.run(["git", "init", str(dest)], check=True, capture_output=True)
            result = runner.invoke(
                cli, ["discover", "--dir", str(dest)],
                catch_exceptions=False, env={}
            )
            assert result.exit_code == 0
            out = json.loads(result.output)
            # repo field must exist (even if empty or just dir name)
            assert "repo" in out
