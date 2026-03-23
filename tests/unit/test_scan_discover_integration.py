"""Tests for mallcop scan integrating discover.

TDD: tests written before implementation.

Done conditions:
- mallcop scan calls discover() before running connectors
- discovery.json is written alongside scan results (in .mallcop/)
- scan works even if discover fails (graceful degradation)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_minimal_config(root: Path) -> None:
    """Write a minimal mallcop.yaml for scan tests."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {},
        "routing": {},
        "actor_chain": {},
        "budget": {
            "max_findings_for_actors": 25,
            "max_donuts_per_run": 50000,
            "max_donuts_per_finding": 5000,
        },
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


def _write_github_config(root: Path) -> None:
    """Write a mallcop.yaml with github connector configured (literal token to skip secret resolution)."""
    config = {
        "secrets": {"backend": "env"},
        "connectors": {
            "github": {"token": "ghp_test_token", "org": "acme"},
        },
        "routing": {},
        "actor_chain": {},
        "budget": {},
    }
    with open(root / "mallcop.yaml", "w") as f:
        yaml.dump(config, f)


# ---------------------------------------------------------------------------
# Tests: scan calls discover before connectors
# ---------------------------------------------------------------------------


class TestScanCallsDiscover:
    """scan pipeline calls discover() before running connectors."""

    def test_scan_writes_discovery_json(self, tmp_path: Path) -> None:
        """After scan, .mallcop/discovery.json exists alongside scan results."""
        _write_minimal_config(tmp_path)

        from mallcop.cli_pipeline import run_scan_pipeline

        result = run_scan_pipeline(tmp_path)

        assert result["status"] == "ok"
        discovery_path = tmp_path / ".mallcop" / "discovery.json"
        assert discovery_path.exists(), "discovery.json must exist after scan"

        data = json.loads(discovery_path.read_text())
        assert data["schema_version"] == "1.0"
        assert "connectors" in data
        assert "coverage" in data

    def test_scan_calls_discover_function(self, tmp_path: Path) -> None:
        """scan pipeline calls discover.write_discovery_json during run."""
        _write_minimal_config(tmp_path)

        from mallcop.cli_pipeline import run_scan_pipeline
        from mallcop import discover as discover_module

        call_count = {"n": 0}
        original_write = discover_module.write_discovery_json

        def mock_write(repo_dir, discovery_data):
            call_count["n"] += 1
            return original_write(repo_dir, discovery_data)

        with patch.object(discover_module, "write_discovery_json", side_effect=mock_write):
            run_scan_pipeline(tmp_path)

        assert call_count["n"] == 1, "write_discovery_json must be called exactly once during scan"

    def test_scan_discovery_json_is_valid_schema(self, tmp_path: Path) -> None:
        """discovery.json written by scan has valid schema_version, repo, connectors, coverage."""
        _write_minimal_config(tmp_path)

        from mallcop.cli_pipeline import run_scan_pipeline

        run_scan_pipeline(tmp_path)

        data = json.loads((tmp_path / ".mallcop" / "discovery.json").read_text())
        assert data["schema_version"] == "1.0"
        assert isinstance(data["connectors"], list)
        assert "percentage" in data["coverage"]
        assert "active_count" in data["coverage"]
        assert "detected_count" in data["coverage"]

    def test_scan_still_succeeds_if_discover_fails(self, tmp_path: Path) -> None:
        """scan does not fail if discover raises an unexpected error."""
        _write_minimal_config(tmp_path)

        from mallcop.cli_pipeline import run_scan_pipeline
        from mallcop import discover as discover_module

        with patch.object(
            discover_module, "discover", side_effect=RuntimeError("discover exploded")
        ):
            result = run_scan_pipeline(tmp_path)

        # Scan should still return ok (discover failure is non-fatal)
        assert result["status"] == "ok"

    def test_scan_discovery_uses_cwd_as_repo_dir(self, tmp_path: Path) -> None:
        """scan discovers the deployment repo (root dir), not some other path."""
        _write_minimal_config(tmp_path)

        from mallcop.cli_pipeline import run_scan_pipeline
        from mallcop import discover as discover_module

        captured = {}

        def mock_discover(repo_dir, env=None):
            captured["repo_dir"] = repo_dir
            from mallcop.discover import discover as real_discover
            return real_discover(repo_dir, env)

        with patch.object(discover_module, "discover", side_effect=mock_discover):
            run_scan_pipeline(tmp_path)

        assert captured.get("repo_dir") == tmp_path, (
            f"discover must be called with the repo root, got {captured.get('repo_dir')}"
        )

    def test_scan_with_connectors_still_writes_discovery(self, tmp_path: Path) -> None:
        """discovery.json is written even when connectors are configured and run."""
        _write_github_config(tmp_path)

        from mallcop.schemas import Checkpoint, Event, PollResult, Severity
        from mallcop.cli_pipeline import run_scan_pipeline
        from datetime import datetime, timezone

        mock_connector = MagicMock()
        mock_connector.authenticate.return_value = None
        mock_connector.configure.return_value = None
        from datetime import datetime, timezone as tz
        mock_connector.poll.return_value = PollResult(
            events=[],
            checkpoint=Checkpoint(connector="github", value="abc123", updated_at=datetime.now(tz.utc)),
        )

        with patch("mallcop.cli_pipeline.instantiate_connector", return_value=mock_connector):
            result = run_scan_pipeline(tmp_path)

        assert result["status"] == "ok"
        discovery_path = tmp_path / ".mallcop" / "discovery.json"
        assert discovery_path.exists(), "discovery.json must exist even with connectors"
