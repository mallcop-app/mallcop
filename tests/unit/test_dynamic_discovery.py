"""Tests for dynamic plugin discovery wired into connector and detector registries."""

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from mallcop.connectors._base import ConnectorBase
from mallcop.detectors._base import DetectorBase
from mallcop.plugins import discover_plugins, load_plugin_class, PluginInfo
from mallcop.schemas import Baseline, Checkpoint, DiscoveryResult, Event, Finding, PollResult


# --- Helpers to create fake plugins on disk ---


def _write_connector_plugin(plugin_dir: Path, name: str, class_name: str = "FakeConnector") -> None:
    """Write a minimal connector plugin: manifest.yaml + connector.py."""
    plugin_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": name,
        "description": f"{name} connector",
        "version": "0.1.0",
        "auth": {"required": ["key"], "optional": []},
        "event_types": ["login"],
        "discovery": {"probes": ["check"]},
        "tools": [],
    }
    (plugin_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    (plugin_dir / "connector.py").write_text(f"""
from mallcop.connectors._base import ConnectorBase
from mallcop.schemas import Checkpoint, DiscoveryResult, PollResult

class {class_name}(ConnectorBase):
    def discover(self) -> DiscoveryResult:
        return DiscoveryResult(available=True, resources=[], suggested_config={{}}, missing_credentials=[], notes=["{name}"])
    def authenticate(self, secrets) -> None:
        pass
    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        return PollResult(events=[], new_checkpoint=None)
    def event_types(self) -> list[str]:
        return ["login"]
""")
    (plugin_dir / "__init__.py").write_text("")


def _write_detector_plugin(plugin_dir: Path, name: str, class_name: str = "FakeDetector") -> None:
    """Write a minimal detector plugin: manifest.yaml + detector.py."""
    plugin_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": name,
        "description": f"{name} detector",
        "version": "0.1.0",
        "sources": "*",
        "event_types": "*",
        "severity_default": "warn",
    }
    (plugin_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    (plugin_dir / "detector.py").write_text(f"""
from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding

class {class_name}(DetectorBase):
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        return []
    def relevant_sources(self) -> list[str] | None:
        return None
    def relevant_event_types(self) -> list[str] | None:
        return None
""")
    (plugin_dir / "__init__.py").write_text("")


# --- Tests for load_plugin_class ---


class TestLoadPluginClass:
    def test_loads_connector_class_from_plugin_dir(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "connectors" / "fake"
        _write_connector_plugin(plugin_dir, "fake", "FakeConnector")
        info = PluginInfo(name="fake", plugin_type="connector", path=plugin_dir)

        cls = load_plugin_class(info)
        assert cls is not None
        assert issubclass(cls, ConnectorBase)
        instance = cls()
        assert instance.discover().notes == ["fake"]

    def test_loads_detector_class_from_plugin_dir(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "detectors" / "fake"
        _write_detector_plugin(plugin_dir, "fake", "FakeDetector")
        info = PluginInfo(name="fake", plugin_type="detector", path=plugin_dir)

        cls = load_plugin_class(info)
        assert cls is not None
        assert issubclass(cls, DetectorBase)

    def test_returns_none_when_module_file_missing(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "connectors" / "broken"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "manifest.yaml").write_text(yaml.dump({"name": "broken"}))
        # No connector.py
        info = PluginInfo(name="broken", plugin_type="connector", path=plugin_dir)

        cls = load_plugin_class(info)
        assert cls is None

    def test_returns_none_when_no_matching_subclass(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "connectors" / "noclass"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "manifest.yaml").write_text(yaml.dump({"name": "noclass"}))
        (plugin_dir / "connector.py").write_text("x = 42\n")
        info = PluginInfo(name="noclass", plugin_type="connector", path=plugin_dir)

        cls = load_plugin_class(info)
        assert cls is None


# --- Tests for connector discovery wiring ---


class TestConnectorDiscoveryWiring:
    def test_instantiate_connector_finds_builtin_azure(self) -> None:
        """The built-in azure connector is discovered without hardcoded registry."""
        from mallcop.plugins import instantiate_connector
        from mallcop.connectors.azure.connector import AzureConnector

        connector = instantiate_connector("azure")
        assert connector is not None
        assert isinstance(connector, AzureConnector)

    def test_instantiate_connector_returns_none_for_unknown(self) -> None:
        from mallcop.plugins import instantiate_connector

        connector = instantiate_connector("nonexistent")
        assert connector is None

    def test_instantiate_connector_finds_deployment_plugin(self, tmp_path: Path) -> None:
        """A connector in deployment plugins/ is discovered and instantiated."""
        from mallcop.plugins import instantiate_connector

        # Create a deployment plugin
        plugin_dir = tmp_path / "plugins" / "connectors" / "custom"
        _write_connector_plugin(plugin_dir, "custom", "CustomConnector")

        # Patch get_search_paths to include our tmp deployment dir
        with patch("mallcop.plugins.get_search_paths") as mock_paths:
            # Deployment plugins first, then built-in
            mock_paths.return_value = [tmp_path / "plugins", Path(__file__).parent.parent.parent / "src" / "mallcop"]
            connector = instantiate_connector("custom")
            assert connector is not None
            assert connector.discover().notes == ["custom"]

    def test_deployment_connector_overrides_builtin(self, tmp_path: Path) -> None:
        """A deployment connector with same name as built-in takes precedence."""
        from mallcop.plugins import instantiate_connector

        # Create a deployment plugin named "azure" that overrides built-in
        plugin_dir = tmp_path / "plugins" / "connectors" / "azure"
        _write_connector_plugin(plugin_dir, "azure", "OverrideAzure")

        with patch("mallcop.plugins.get_search_paths") as mock_paths:
            mock_paths.return_value = [tmp_path / "plugins", Path(__file__).parent.parent.parent / "src" / "mallcop"]
            connector = instantiate_connector("azure")
            assert connector is not None
            # Should be the override, not the built-in AzureConnector
            assert connector.discover().notes == ["azure"]


# --- Tests for detector discovery wiring ---


class TestDetectorDiscoveryWiring:
    def test_get_detectors_finds_builtin_detectors(self) -> None:
        """Built-in detectors are discovered without hardcoded imports."""
        from mallcop.detect import _get_detectors
        from mallcop.detectors.new_actor.detector import NewActorDetector
        from mallcop.detectors.injection_probe.detector import InjectionProbeDetector

        detectors = _get_detectors()
        types = {type(d) for d in detectors}
        assert NewActorDetector in types
        assert InjectionProbeDetector in types

    def test_get_detectors_includes_deployment_plugins(self, tmp_path: Path) -> None:
        """Detectors from deployment plugins/ are included."""
        from mallcop.detect import _get_detectors

        plugin_dir = tmp_path / "plugins" / "detectors" / "custom"
        _write_detector_plugin(plugin_dir, "custom-det", "CustomDetector")

        with patch("mallcop.detect.get_search_paths") as mock_paths:
            mock_paths.return_value = [tmp_path / "plugins", Path(__file__).parent.parent.parent / "src" / "mallcop"]
            detectors = _get_detectors()
            # Should include built-in + custom
            assert len(detectors) >= 3
            class_names = {type(d).__name__ for d in detectors}
            assert "CustomDetector" in class_names

    def test_get_detectors_no_duplicates(self) -> None:
        """Each detector name appears once even if discovered multiple times."""
        from mallcop.detect import _get_detectors

        detectors = _get_detectors()
        names = [type(d).__name__ for d in detectors]
        assert len(names) == len(set(names))
