"""Integration test: scaffold a plugin, then verify it passes."""

from pathlib import Path

from mallcop.scaffold import scaffold_plugin
from mallcop.verify import verify_plugin


class TestScaffoldThenVerify:
    def test_scaffolded_connector_passes_verify(self, tmp_path: Path) -> None:
        scaffold_plugin("connector", "testcloud", tmp_path)
        plugin_dir = tmp_path / "connectors" / "testcloud"
        result = verify_plugin(plugin_dir, "connector")
        assert result.passed, f"Scaffolded connector failed verify: {result.errors}"

    def test_scaffolded_detector_passes_verify(self, tmp_path: Path) -> None:
        scaffold_plugin("detector", "anomaly", tmp_path)
        plugin_dir = tmp_path / "detectors" / "anomaly"
        result = verify_plugin(plugin_dir, "detector")
        assert result.passed, f"Scaffolded detector failed verify: {result.errors}"

    def test_scaffolded_actor_passes_verify(self, tmp_path: Path) -> None:
        scaffold_plugin("actor", "responder", tmp_path)
        plugin_dir = tmp_path / "actors" / "responder"
        result = verify_plugin(plugin_dir, "actor")
        assert result.passed, f"Scaffolded actor failed verify: {result.errors}"
