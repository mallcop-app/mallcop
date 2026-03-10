"""Tests for mallcop verify command — plugin validation."""

import yaml
import pytest
from pathlib import Path

from mallcop.verify import verify_plugin, VerifyResult


def _write_connector(plugin_dir: Path, manifest: dict, connector_code: str) -> None:
    """Helper: write a connector plugin directory."""
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    (plugin_dir / "__init__.py").write_text("")
    (plugin_dir / "connector.py").write_text(connector_code)


def _write_detector(plugin_dir: Path, manifest: dict, detector_code: str) -> None:
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    (plugin_dir / "__init__.py").write_text("")
    (plugin_dir / "detector.py").write_text(detector_code)


def _write_actor(plugin_dir: Path, manifest: dict) -> None:
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    (plugin_dir / "__init__.py").write_text("")
    (plugin_dir / "POST.md").write_text("# Actor\nTODO")


def _valid_connector_manifest() -> dict:
    return {
        "name": "testconn",
        "description": "Test connector",
        "version": "0.1.0",
        "auth": {"required": ["api_key"]},
        "event_types": ["login", "logout"],
        "discovery": {"probes": ["check access"]},
    }


def _valid_connector_code(event_types: list[str] | None = None) -> str:
    if event_types is None:
        event_types = ["login", "logout"]
    types_str = repr(event_types)
    return f'''
from mallcop.connectors._base import ConnectorBase, SecretProvider
from mallcop.schemas import Checkpoint, DiscoveryResult, PollResult


class TestconnConnector(ConnectorBase):
    def discover(self) -> DiscoveryResult:
        return DiscoveryResult(
            available=True, resources=[], suggested_config={{}},
            missing_credentials=[], notes=[],
        )

    def authenticate(self, secrets: SecretProvider) -> None:
        pass

    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        raise NotImplementedError

    def event_types(self) -> list[str]:
        return {types_str}
'''


def _valid_detector_manifest() -> dict:
    return {
        "name": "testdet",
        "description": "Test detector",
        "version": "0.1.0",
        "sources": "*",
        "event_types": "*",
        "severity_default": "warn",
    }


def _valid_detector_code() -> str:
    return '''
from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding


class TestdetDetector(DetectorBase):
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        return []

    def relevant_sources(self) -> list[str] | None:
        return None

    def relevant_event_types(self) -> list[str] | None:
        return None
'''


def _valid_actor_manifest() -> dict:
    return {
        "name": "testact",
        "type": "agent",
        "description": "Test actor",
        "version": "0.1.0",
        "model": "haiku",
        "tools": [],
        "permissions": ["read"],
    }


class TestVerifyConnector:
    def test_valid_connector_passes(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "connectors" / "testconn"
        _write_connector(plugin_dir, _valid_connector_manifest(), _valid_connector_code())
        result = verify_plugin(plugin_dir, "connector")
        assert result.passed, f"Expected pass, got errors: {result.errors}"

    def test_missing_manifest(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "connectors" / "testconn"
        plugin_dir.mkdir(parents=True)
        result = verify_plugin(plugin_dir, "connector")
        assert not result.passed
        assert any("manifest" in e.lower() for e in result.errors)

    def test_missing_manifest_field(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "connectors" / "testconn"
        manifest = _valid_connector_manifest()
        del manifest["event_types"]
        _write_connector(plugin_dir, manifest, _valid_connector_code())
        result = verify_plugin(plugin_dir, "connector")
        assert not result.passed
        assert any("event_types" in e.lower() for e in result.errors)

    def test_mismatched_event_types(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "connectors" / "testconn"
        manifest = _valid_connector_manifest()
        # Manifest says login+logout, code returns different types
        code = _valid_connector_code(["login", "signup"])
        _write_connector(plugin_dir, manifest, code)
        result = verify_plugin(plugin_dir, "connector")
        assert not result.passed
        assert any("event_types" in e.lower() for e in result.errors)

    def test_wrong_base_class(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "connectors" / "testconn"
        bad_code = '''
class TestconnConnector:
    def event_types(self):
        return ["login", "logout"]
'''
        _write_connector(plugin_dir, _valid_connector_manifest(), bad_code)
        result = verify_plugin(plugin_dir, "connector")
        assert not result.passed
        assert any("base" in e.lower() or "ConnectorBase" in e for e in result.errors)

    def test_empty_name_fails(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "connectors" / "testconn"
        manifest = _valid_connector_manifest()
        manifest["name"] = ""
        _write_connector(plugin_dir, manifest, _valid_connector_code())
        result = verify_plugin(plugin_dir, "connector")
        assert not result.passed


class TestVerifyDetector:
    def test_valid_detector_passes(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "detectors" / "testdet"
        _write_detector(plugin_dir, _valid_detector_manifest(), _valid_detector_code())
        result = verify_plugin(plugin_dir, "detector")
        assert result.passed, f"Expected pass, got errors: {result.errors}"

    def test_invalid_severity_default(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "detectors" / "testdet"
        manifest = _valid_detector_manifest()
        manifest["severity_default"] = "extreme"
        _write_detector(plugin_dir, manifest, _valid_detector_code())
        result = verify_plugin(plugin_dir, "detector")
        assert not result.passed

    def test_wrong_base_class(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "detectors" / "testdet"
        bad_code = '''
class TestdetDetector:
    pass
'''
        _write_detector(plugin_dir, _valid_detector_manifest(), bad_code)
        result = verify_plugin(plugin_dir, "detector")
        assert not result.passed

    def test_sources_mismatch(self, tmp_path: Path) -> None:
        """If manifest declares specific sources, detector.relevant_sources() must match."""
        plugin_dir = tmp_path / "detectors" / "testdet"
        manifest = _valid_detector_manifest()
        manifest["sources"] = ["azure", "github"]
        code = '''
from mallcop.detectors._base import DetectorBase
from mallcop.schemas import Baseline, Event, Finding


class TestdetDetector(DetectorBase):
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        return []

    def relevant_sources(self) -> list[str] | None:
        return ["azure"]  # missing github

    def relevant_event_types(self) -> list[str] | None:
        return None
'''
        _write_detector(plugin_dir, manifest, code)
        result = verify_plugin(plugin_dir, "detector")
        assert not result.passed
        assert any("sources" in e.lower() for e in result.errors)


class TestVerifyActor:
    def test_valid_actor_passes(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "actors" / "testact"
        _write_actor(plugin_dir, _valid_actor_manifest())
        result = verify_plugin(plugin_dir, "actor")
        assert result.passed, f"Expected pass, got errors: {result.errors}"

    def test_missing_type(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "actors" / "testact"
        manifest = _valid_actor_manifest()
        del manifest["type"]
        _write_actor(plugin_dir, manifest)
        result = verify_plugin(plugin_dir, "actor")
        assert not result.passed

    def test_agent_without_model(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "actors" / "testact"
        manifest = _valid_actor_manifest()
        del manifest["model"]
        _write_actor(plugin_dir, manifest)
        result = verify_plugin(plugin_dir, "actor")
        assert not result.passed

    def test_missing_post_md(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "actors" / "testact"
        _write_actor(plugin_dir, _valid_actor_manifest())
        (plugin_dir / "POST.md").unlink()
        result = verify_plugin(plugin_dir, "actor")
        assert not result.passed
        assert any("POST.md" in e for e in result.errors)


class TestVerifyResult:
    def test_passed_when_no_errors(self) -> None:
        r = VerifyResult(plugin_name="test", plugin_type="connector", errors=[], warnings=[])
        assert r.passed

    def test_not_passed_when_errors(self) -> None:
        r = VerifyResult(plugin_name="test", plugin_type="connector", errors=["bad"], warnings=[])
        assert not r.passed
