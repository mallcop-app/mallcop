"""Tests for plugin discovery system."""

from pathlib import Path

import pytest
import yaml

from mallcop.plugins import discover_plugins, PluginInfo


class TestDiscoverPlugins:
    """Plugin discovery finds plugins in correct resolution order."""

    def _make_connector_manifest(self, plugin_dir: Path, name: str) -> None:
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

    def _make_detector_manifest(self, plugin_dir: Path, name: str) -> None:
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

    def _make_actor_manifest(
        self, plugin_dir: Path, name: str, actor_type: str = "agent"
    ) -> None:
        plugin_dir.mkdir(parents=True, exist_ok=True)
        manifest: dict = {
            "name": name,
            "type": actor_type,
            "description": f"{name} actor",
            "version": "0.1.0",
        }
        if actor_type == "agent":
            manifest["model"] = "haiku"
            manifest["tools"] = []
            manifest["permissions"] = ["read"]
            manifest["max_iterations"] = 5
        else:
            manifest["config"] = {"webhook_url": "https://example.com"}
        (plugin_dir / "manifest.yaml").write_text(yaml.dump(manifest))

    def test_discovers_connectors_in_directory(self, tmp_path: Path) -> None:
        connectors_dir = tmp_path / "connectors"
        self._make_connector_manifest(connectors_dir / "azure", "azure")
        self._make_connector_manifest(connectors_dir / "github", "github")

        result = discover_plugins([tmp_path])
        assert "azure" in result["connectors"]
        assert "github" in result["connectors"]

    def test_discovers_detectors_in_directory(self, tmp_path: Path) -> None:
        detectors_dir = tmp_path / "detectors"
        self._make_detector_manifest(detectors_dir / "new_actor", "new-actor")

        result = discover_plugins([tmp_path])
        assert "new-actor" in result["detectors"]

    def test_discovers_actors_in_directory(self, tmp_path: Path) -> None:
        actors_dir = tmp_path / "actors"
        self._make_actor_manifest(actors_dir / "triage", "triage")

        result = discover_plugins([tmp_path])
        assert "triage" in result["actors"]

    def test_skips_private_files(self, tmp_path: Path) -> None:
        """Directories starting with _ (like _base.py, _schema.py) are not plugins."""
        connectors_dir = tmp_path / "connectors"
        connectors_dir.mkdir(parents=True)
        # _base.py and _schema.py are not plugin directories
        (connectors_dir / "_base.py").write_text("# base class")
        (connectors_dir / "_schema.py").write_text("# schema")
        self._make_connector_manifest(connectors_dir / "azure", "azure")

        result = discover_plugins([tmp_path])
        assert "azure" in result["connectors"]
        assert len(result["connectors"]) == 1

    def test_skips_directories_without_manifest(self, tmp_path: Path) -> None:
        connectors_dir = tmp_path / "connectors"
        (connectors_dir / "broken").mkdir(parents=True)
        # No manifest.yaml

        result = discover_plugins([tmp_path])
        assert len(result["connectors"]) == 0

    def test_resolution_order_first_wins(self, tmp_path: Path) -> None:
        """Earlier directories in the search path take priority."""
        deploy_dir = tmp_path / "deploy"
        builtin_dir = tmp_path / "builtin"

        # Both have a connector named "azure"
        deploy_connectors = deploy_dir / "connectors"
        self._make_connector_manifest(deploy_connectors / "azure", "azure")

        builtin_connectors = builtin_dir / "connectors"
        self._make_connector_manifest(builtin_connectors / "azure", "azure")

        result = discover_plugins([deploy_dir, builtin_dir])
        azure_info = result["connectors"]["azure"]
        # The deployment repo version should win (first in search path)
        assert str(deploy_dir) in str(azure_info.path)

    def test_later_paths_add_new_plugins(self, tmp_path: Path) -> None:
        """Later paths contribute plugins not found in earlier paths."""
        deploy_dir = tmp_path / "deploy"
        builtin_dir = tmp_path / "builtin"

        deploy_connectors = deploy_dir / "connectors"
        self._make_connector_manifest(deploy_connectors / "custom", "custom")

        builtin_connectors = builtin_dir / "connectors"
        self._make_connector_manifest(builtin_connectors / "azure", "azure")

        result = discover_plugins([deploy_dir, builtin_dir])
        assert "custom" in result["connectors"]
        assert "azure" in result["connectors"]

    def test_deployment_actors_override_builtin_postmd(self, tmp_path: Path) -> None:
        """Deployment repo actors/ dir with POST.md overrides built-in."""
        deploy_dir = tmp_path / "deploy"
        builtin_dir = tmp_path / "builtin"

        # Built-in has triage actor
        builtin_actors = builtin_dir / "actors"
        self._make_actor_manifest(builtin_actors / "triage", "triage")
        (builtin_actors / "triage" / "POST.md").write_text("Built-in instructions")

        # Deployment repo has POST.md override
        deploy_actors = deploy_dir / "actors"
        self._make_actor_manifest(deploy_actors / "triage", "triage")
        (deploy_actors / "triage" / "POST.md").write_text("Custom instructions")

        result = discover_plugins([deploy_dir, builtin_dir])
        triage = result["actors"]["triage"]
        assert str(deploy_dir) in str(triage.path)

    def test_empty_search_path(self) -> None:
        result = discover_plugins([])
        assert result["connectors"] == {}
        assert result["detectors"] == {}
        assert result["actors"] == {}

    def test_nonexistent_directory_skipped(self, tmp_path: Path) -> None:
        result = discover_plugins([tmp_path / "nonexistent"])
        assert result["connectors"] == {}

    def test_plugin_info_has_correct_fields(self, tmp_path: Path) -> None:
        connectors_dir = tmp_path / "connectors"
        self._make_connector_manifest(connectors_dir / "azure", "azure")

        result = discover_plugins([tmp_path])
        info = result["connectors"]["azure"]
        assert isinstance(info, PluginInfo)
        assert info.name == "azure"
        assert info.plugin_type == "connector"
        assert info.path == connectors_dir / "azure"

    def test_mixed_plugin_types(self, tmp_path: Path) -> None:
        """A single search path can contain connectors, detectors, and actors."""
        self._make_connector_manifest(tmp_path / "connectors" / "azure", "azure")
        self._make_detector_manifest(tmp_path / "detectors" / "new_actor", "new-actor")
        self._make_actor_manifest(tmp_path / "actors" / "triage", "triage")

        result = discover_plugins([tmp_path])
        assert "azure" in result["connectors"]
        assert "new-actor" in result["detectors"]
        assert "triage" in result["actors"]

    def test_three_tier_resolution(self, tmp_path: Path) -> None:
        """Full resolution: deployment plugins/ -> deployment actors/ -> built-ins."""
        deploy_plugins = tmp_path / "deploy_plugins"
        deploy_actors = tmp_path / "deploy_actors"
        builtins = tmp_path / "builtins"

        # Built-in triage
        self._make_actor_manifest(builtins / "actors" / "triage", "triage")
        # Deploy actors/ override for triage
        self._make_actor_manifest(deploy_actors / "actors" / "triage", "triage")
        # Deploy plugins/ custom detector
        self._make_detector_manifest(
            deploy_plugins / "detectors" / "custom", "custom"
        )
        # Built-in detector
        self._make_detector_manifest(
            builtins / "detectors" / "new_actor", "new-actor"
        )

        result = discover_plugins([deploy_plugins, deploy_actors, builtins])
        # triage comes from deploy_actors (first match)
        assert str(deploy_actors) in str(result["actors"]["triage"].path)
        # custom detector from deploy_plugins
        assert "custom" in result["detectors"]
        # built-in detector still available
        assert "new-actor" in result["detectors"]


# ---------------------------------------------------------------------------
# External plugin security warning (ak1n.1.14)
# ---------------------------------------------------------------------------


class TestExternalPluginSecurityWarning:
    """Loading external plugins must emit a security warning.

    The deployment repo plugins/ directory is a code-execution boundary.
    Any file placed there by anyone with write access executes in the mallcop
    process. Users must be warned that external plugin loading is occurring.
    """

    def _make_external_plugin(self, plugin_dir: Path, name: str, code: str) -> None:
        """Create a minimal external connector plugin for testing."""
        connector_dir = plugin_dir / "connectors" / name
        connector_dir.mkdir(parents=True, exist_ok=True)
        # Manifest
        manifest = {
            "name": name,
            "description": f"{name} connector",
            "version": "0.1.0",
            "auth": {"required": [], "optional": []},
            "event_types": ["test"],
            "discovery": {"probes": []},
            "tools": [],
        }
        (connector_dir / "manifest.yaml").write_text(yaml.dump(manifest))
        (connector_dir / "connector.py").write_text(code)

    def test_external_plugin_load_emits_warning(self, tmp_path: Path, caplog) -> None:
        """load_plugin_class must emit a WARNING when loading an external plugin."""
        import logging
        from mallcop.plugins import load_plugin_class, discover_plugins
        from mallcop.connectors._base import ConnectorBase

        code = '''
from mallcop.connectors._base import ConnectorBase
class TestConnector(ConnectorBase):
    def poll(self, checkpoint=None): return None
    def event_types(self): return ["test"]
    def relevant_event_types(self): return ["test"]
'''
        self._make_external_plugin(tmp_path, "testconn", code)
        plugins = discover_plugins([tmp_path])
        info = plugins["connectors"].get("testconn")
        assert info is not None, "External plugin not discovered"

        with caplog.at_level(logging.WARNING, logger="mallcop.plugins"):
            load_plugin_class(info)

        # Must have emitted a security warning about external plugin loading
        warning_messages = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        assert any(
            "external" in msg.lower() or "code execution" in msg.lower() or "trust" in msg.lower()
            for msg in warning_messages
        ), f"No external plugin security warning found. Got: {warning_messages}"

    def test_builtin_plugin_load_no_security_warning(self, tmp_path: Path, caplog) -> None:
        """Built-in plugins must NOT trigger the external plugin warning."""
        import logging
        from mallcop.plugins import load_plugin_class, discover_plugins

        # Use the actual mallcop package as the search path (built-in only)
        from mallcop import plugins as plugins_mod
        package_root = Path(plugins_mod.__file__).parent
        builtin_plugins = discover_plugins([package_root])
        info = builtin_plugins.get("connectors", {}).get("github")
        if info is None:
            pytest.skip("github connector not available in test env")

        with caplog.at_level(logging.WARNING, logger="mallcop.plugins"):
            load_plugin_class(info)

        warning_messages = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        assert not any(
            "external" in msg.lower() or "code execution" in msg.lower()
            for msg in warning_messages
        ), f"Unexpected security warning for built-in plugin: {warning_messages}"
