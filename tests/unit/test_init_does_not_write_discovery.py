"""Test that mallcop init does NOT write .mallcop/discovery.json.

Design doc invariant: init writes mallcop.yaml and creates .mallcop/ directory.
It does not call discover.py and does not write discovery.json.
The lifecycle state DEPLOYING->DISCOVERING->NEEDS_CONFIG/ACTIVE relies on
discovery.json being absent after init and written only by mallcop scan/discover.

See: docs/design-mallcop-onboarding.md § 2. The `mallcop discover` Command
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from mallcop.cli import cli


class TestInitDoesNotWriteDiscovery:
    """mallcop init must not write .mallcop/discovery.json."""

    def test_init_does_not_write_discovery_json(self, tmp_path: Path) -> None:
        """After mallcop init, .mallcop/discovery.json must not exist.

        The dashboard lifecycle depends on discovery.json being absent after
        init so the repo transitions through DEPLOYING -> DISCOVERING correctly.
        If init wrote discovery.json, the lifecycle state machine would skip
        the DISCOVERING state and potentially mis-derive the repo state.
        """
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            result = runner.invoke(cli, ["init"], catch_exceptions=False)
            assert result.exit_code == 0, f"init failed: {result.output}"

            discovery_json = Path(td) / ".mallcop" / "discovery.json"
            assert not discovery_json.exists(), (
                "mallcop init must not write .mallcop/discovery.json. "
                "discovery.json is written by mallcop scan (Phase 0) and mallcop discover. "
                "The dashboard lifecycle relies on its absence after init. "
                "See docs/design-mallcop-onboarding.md §2."
            )

    def test_init_writes_mallcop_yaml(self, tmp_path: Path) -> None:
        """After mallcop init, mallcop.yaml exists (init's primary output)."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            result = runner.invoke(cli, ["init"], catch_exceptions=False)
            assert result.exit_code == 0, f"init failed: {result.output}"

            config_path = Path(td) / "mallcop.yaml"
            assert config_path.exists(), "mallcop init must write mallcop.yaml"

    def test_init_creates_mallcop_dir(self, tmp_path: Path) -> None:
        """After mallcop init, .mallcop/ directory exists."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path.parent) as td:
            result = runner.invoke(cli, ["init"], catch_exceptions=False)
            assert result.exit_code == 0, f"init failed: {result.output}"

            mallcop_dir = Path(td) / ".mallcop"
            assert mallcop_dir.is_dir(), "mallcop init must create .mallcop/ directory"
