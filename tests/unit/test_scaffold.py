"""Tests for mallcop scaffold command — plugin directory generation."""

import yaml
import pytest
from pathlib import Path

from mallcop.scaffold import scaffold_plugin


class TestScaffoldConnector:
    def test_creates_directory_structure(self, tmp_path: Path) -> None:
        scaffold_plugin("connector", "mycloud", tmp_path)
        plugin_dir = tmp_path / "connectors" / "mycloud"
        assert plugin_dir.is_dir()

    def test_creates_manifest(self, tmp_path: Path) -> None:
        scaffold_plugin("connector", "mycloud", tmp_path)
        manifest = tmp_path / "connectors" / "mycloud" / "manifest.yaml"
        assert manifest.exists()
        data = yaml.safe_load(manifest.read_text())
        assert data["name"] == "mycloud"
        assert "event_types" in data
        assert "auth" in data
        assert "version" in data
        assert "description" in data
        assert "discovery" in data

    def test_creates_connector_module(self, tmp_path: Path) -> None:
        scaffold_plugin("connector", "mycloud", tmp_path)
        mod = tmp_path / "connectors" / "mycloud" / "connector.py"
        assert mod.exists()
        content = mod.read_text()
        assert "ConnectorBase" in content
        assert "class MyCloudConnector" in content or "class MycloudConnector" in content

    def test_creates_tools_module(self, tmp_path: Path) -> None:
        scaffold_plugin("connector", "mycloud", tmp_path)
        tools = tmp_path / "connectors" / "mycloud" / "tools.py"
        assert tools.exists()

    def test_creates_fixtures_dir(self, tmp_path: Path) -> None:
        scaffold_plugin("connector", "mycloud", tmp_path)
        fixtures = tmp_path / "connectors" / "mycloud" / "fixtures"
        assert fixtures.is_dir()

    def test_creates_tests_file(self, tmp_path: Path) -> None:
        scaffold_plugin("connector", "mycloud", tmp_path)
        tests = tmp_path / "connectors" / "mycloud" / "tests.py"
        assert tests.exists()
        content = tests.read_text()
        assert "test_" in content

    def test_creates_init_file(self, tmp_path: Path) -> None:
        scaffold_plugin("connector", "mycloud", tmp_path)
        init = tmp_path / "connectors" / "mycloud" / "__init__.py"
        assert init.exists()

    def test_manifest_has_todo_placeholders(self, tmp_path: Path) -> None:
        scaffold_plugin("connector", "mycloud", tmp_path)
        manifest = tmp_path / "connectors" / "mycloud" / "manifest.yaml"
        content = manifest.read_text()
        assert "TODO" in content


class TestScaffoldDetector:
    def test_creates_directory_structure(self, tmp_path: Path) -> None:
        scaffold_plugin("detector", "anomaly", tmp_path)
        plugin_dir = tmp_path / "detectors" / "anomaly"
        assert plugin_dir.is_dir()

    def test_creates_manifest(self, tmp_path: Path) -> None:
        scaffold_plugin("detector", "anomaly", tmp_path)
        manifest = tmp_path / "detectors" / "anomaly" / "manifest.yaml"
        assert manifest.exists()
        data = yaml.safe_load(manifest.read_text())
        assert data["name"] == "anomaly"
        assert "sources" in data
        assert "event_types" in data
        assert "severity_default" in data

    def test_creates_detector_module(self, tmp_path: Path) -> None:
        scaffold_plugin("detector", "anomaly", tmp_path)
        mod = tmp_path / "detectors" / "anomaly" / "detector.py"
        assert mod.exists()
        content = mod.read_text()
        assert "DetectorBase" in content

    def test_creates_tests_file(self, tmp_path: Path) -> None:
        scaffold_plugin("detector", "anomaly", tmp_path)
        tests = tmp_path / "detectors" / "anomaly" / "tests.py"
        assert tests.exists()

    def test_no_fixtures_dir(self, tmp_path: Path) -> None:
        """Detectors don't need fixtures directories."""
        scaffold_plugin("detector", "anomaly", tmp_path)
        fixtures = tmp_path / "detectors" / "anomaly" / "fixtures"
        assert not fixtures.exists()

    def test_no_tools_module(self, tmp_path: Path) -> None:
        """Detectors don't have tools modules."""
        scaffold_plugin("detector", "anomaly", tmp_path)
        tools = tmp_path / "detectors" / "anomaly" / "tools.py"
        assert not tools.exists()


class TestScaffoldActor:
    def test_creates_directory_structure(self, tmp_path: Path) -> None:
        scaffold_plugin("actor", "responder", tmp_path)
        plugin_dir = tmp_path / "actors" / "responder"
        assert plugin_dir.is_dir()

    def test_creates_manifest(self, tmp_path: Path) -> None:
        scaffold_plugin("actor", "responder", tmp_path)
        manifest = tmp_path / "actors" / "responder" / "manifest.yaml"
        assert manifest.exists()
        data = yaml.safe_load(manifest.read_text())
        assert data["name"] == "responder"
        assert "type" in data
        assert "version" in data

    def test_creates_post_md(self, tmp_path: Path) -> None:
        scaffold_plugin("actor", "responder", tmp_path)
        post = tmp_path / "actors" / "responder" / "POST.md"
        assert post.exists()
        content = post.read_text()
        assert "TODO" in content

    def test_creates_tests_file(self, tmp_path: Path) -> None:
        scaffold_plugin("actor", "responder", tmp_path)
        tests = tmp_path / "actors" / "responder" / "tests.py"
        assert tests.exists()

    def test_no_fixtures_dir(self, tmp_path: Path) -> None:
        scaffold_plugin("actor", "responder", tmp_path)
        fixtures = tmp_path / "actors" / "responder" / "fixtures"
        assert not fixtures.exists()


class TestScaffoldErrors:
    def test_invalid_plugin_type(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="plugin_type"):
            scaffold_plugin("widget", "foo", tmp_path)

    def test_already_exists(self, tmp_path: Path) -> None:
        scaffold_plugin("connector", "mycloud", tmp_path)
        with pytest.raises(FileExistsError):
            scaffold_plugin("connector", "mycloud", tmp_path)
