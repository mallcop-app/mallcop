"""Tests for plugin base classes and manifest schemas."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from mallcop.schemas import (
    Checkpoint,
    DiscoveryResult,
    Event,
    Finding,
    Baseline,
    PollResult,
    Severity,
)
from mallcop.connectors._base import ConnectorBase
from mallcop.connectors._schema import ConnectorManifest, load_connector_manifest
from mallcop.detectors._base import DetectorBase
from mallcop.detectors._schema import DetectorManifest, load_detector_manifest
from mallcop.actors._base import ActorBase
from mallcop.actors._schema import ActorManifest, load_actor_manifest


# ─── ConnectorBase ABC ───────────────────────────────────────────────


class TestConnectorBase:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            ConnectorBase()

    def test_subclass_must_implement_all(self) -> None:
        class Incomplete(ConnectorBase):
            pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_subclass_missing_one_method(self) -> None:
        class MissesDiscover(ConnectorBase):
            def authenticate(self, secrets):
                pass

            def poll(self, checkpoint):
                pass

            def event_types(self):
                return []

        with pytest.raises(TypeError):
            MissesDiscover()

    def test_valid_subclass_instantiates(self) -> None:
        class FakeConnector(ConnectorBase):
            def discover(self):
                return DiscoveryResult(
                    available=True,
                    resources=[],
                    suggested_config={},
                    missing_credentials=[],
                    notes=[],
                )

            def authenticate(self, secrets):
                pass

            def poll(self, checkpoint):
                return PollResult(events=[], checkpoint=Checkpoint(
                    connector="fake", value="0", updated_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                ))

            def event_types(self):
                return ["test_event"]

        conn = FakeConnector()
        assert conn.event_types() == ["test_event"]


# ─── DetectorBase ABC ────────────────────────────────────────────────


class TestDetectorBase:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            DetectorBase()

    def test_subclass_must_implement_all(self) -> None:
        class Incomplete(DetectorBase):
            pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_subclass_missing_detect(self) -> None:
        class MissesDetect(DetectorBase):
            def relevant_sources(self):
                return None

            def relevant_event_types(self):
                return None

        with pytest.raises(TypeError):
            MissesDetect()

    def test_valid_subclass_instantiates(self) -> None:
        class FakeDetector(DetectorBase):
            def detect(self, events, baseline):
                return []

            def relevant_sources(self):
                return None

            def relevant_event_types(self):
                return None

        det = FakeDetector()
        assert det.relevant_sources() is None
        assert det.detect([], Baseline(
            frequency_tables={}, known_entities={}, relationships={}
        )) == []


# ─── ActorBase ABC ───────────────────────────────────────────────────


class TestActorBase:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            ActorBase()

    def test_subclass_must_implement_all(self) -> None:
        class Incomplete(ActorBase):
            pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_valid_subclass_instantiates(self) -> None:
        class FakeActor(ActorBase):
            def handle(self, findings):
                return []

        actor = FakeActor()
        assert actor.handle([]) == []


# ─── ConnectorManifest ───────────────────────────────────────────────


class TestConnectorManifest:
    def test_valid_manifest(self) -> None:
        m = ConnectorManifest(
            name="azure",
            description="Azure Activity Log",
            version="0.1.0",
            auth={"required": ["tenant_id"], "optional": []},
            event_types=["login", "role_assignment"],
            discovery={"probes": ["Azure AD access"]},
            tools=[],
        )
        assert m.name == "azure"
        assert m.version == "0.1.0"
        assert "login" in m.event_types

    def test_missing_name_raises(self) -> None:
        with pytest.raises((TypeError, ValueError)):
            ConnectorManifest(
                name="",
                description="Test",
                version="0.1.0",
                auth={"required": [], "optional": []},
                event_types=["test"],
                discovery={"probes": []},
                tools=[],
            )

    def test_missing_event_types_raises(self) -> None:
        with pytest.raises((TypeError, ValueError)):
            ConnectorManifest(
                name="test",
                description="Test",
                version="0.1.0",
                auth={"required": [], "optional": []},
                event_types=[],
                discovery={"probes": []},
                tools=[],
            )


class TestLoadConnectorManifest:
    def test_load_valid_yaml(self, tmp_path: Path) -> None:
        manifest_data = {
            "name": "test-connector",
            "description": "A test connector",
            "version": "0.1.0",
            "auth": {"required": ["api_key"], "optional": []},
            "event_types": ["login"],
            "discovery": {"probes": ["Test probe"]},
            "tools": [],
        }
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(yaml.dump(manifest_data))

        m = load_connector_manifest(tmp_path)
        assert m.name == "test-connector"
        assert m.event_types == ["login"]

    def test_load_missing_fields_raises(self, tmp_path: Path) -> None:
        manifest_data = {"name": "bad", "version": "0.1.0"}
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(yaml.dump(manifest_data))

        with pytest.raises((ValueError, KeyError, TypeError)):
            load_connector_manifest(tmp_path)

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_connector_manifest(tmp_path / "nonexistent")


# ─── DetectorManifest ────────────────────────────────────────────────


class TestDetectorManifest:
    def test_valid_manifest(self) -> None:
        m = DetectorManifest(
            name="new-actor",
            description="Flags actors not in baseline",
            version="0.1.0",
            sources="*",
            event_types="*",
            severity_default="warn",
        )
        assert m.name == "new-actor"
        assert m.sources == "*"
        assert m.severity_default == "warn"

    def test_sources_list(self) -> None:
        m = DetectorManifest(
            name="azure-specific",
            description="Azure only",
            version="0.1.0",
            sources=["azure"],
            event_types="*",
            severity_default="warn",
        )
        assert m.sources == ["azure"]

    def test_missing_name_raises(self) -> None:
        with pytest.raises((TypeError, ValueError)):
            DetectorManifest(
                name="",
                description="Test",
                version="0.1.0",
                sources="*",
                event_types="*",
                severity_default="warn",
            )

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(ValueError):
            DetectorManifest(
                name="test",
                description="Test",
                version="0.1.0",
                sources="*",
                event_types="*",
                severity_default="high",
            )


class TestLoadDetectorManifest:
    def test_load_valid_yaml(self, tmp_path: Path) -> None:
        manifest_data = {
            "name": "test-detector",
            "description": "A test detector",
            "version": "0.1.0",
            "sources": "*",
            "event_types": "*",
            "severity_default": "warn",
        }
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(yaml.dump(manifest_data))

        m = load_detector_manifest(tmp_path)
        assert m.name == "test-detector"
        assert m.severity_default == "warn"

    def test_load_missing_fields_raises(self, tmp_path: Path) -> None:
        manifest_data = {"name": "bad"}
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(yaml.dump(manifest_data))

        with pytest.raises((ValueError, KeyError, TypeError)):
            load_detector_manifest(tmp_path)

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_detector_manifest(tmp_path / "nonexistent")


# ─── ActorManifest ───────────────────────────────────────────────────


class TestActorManifest:
    def test_valid_agent_manifest(self) -> None:
        m = ActorManifest(
            name="triage",
            type="agent",
            description="First-pass triage",
            version="0.1.0",
            model="haiku",
            tools=["read-events", "check-baseline"],
            permissions=["read"],
            routes_to="investigate",
            max_iterations=5,
            config={},
        )
        assert m.name == "triage"
        assert m.type == "agent"
        assert m.model == "haiku"
        assert m.max_iterations == 5

    def test_valid_channel_manifest(self) -> None:
        m = ActorManifest(
            name="notify-teams",
            type="channel",
            description="Teams notification",
            version="0.1.0",
            model=None,
            tools=[],
            permissions=[],
            routes_to=None,
            max_iterations=None,
            config={"webhook_url": "${TEAMS_WEBHOOK_URL}", "format": "digest"},
        )
        assert m.name == "notify-teams"
        assert m.type == "channel"
        assert m.model is None

    def test_missing_name_raises(self) -> None:
        with pytest.raises((TypeError, ValueError)):
            ActorManifest(
                name="",
                type="agent",
                description="Test",
                version="0.1.0",
                model="haiku",
                tools=[],
                permissions=[],
                routes_to=None,
                max_iterations=5,
                config={},
            )

    def test_invalid_type_raises(self) -> None:
        with pytest.raises(ValueError):
            ActorManifest(
                name="test",
                type="invalid",
                description="Test",
                version="0.1.0",
                model="haiku",
                tools=[],
                permissions=[],
                routes_to=None,
                max_iterations=5,
                config={},
            )

    def test_agent_requires_model(self) -> None:
        with pytest.raises(ValueError):
            ActorManifest(
                name="test",
                type="agent",
                description="Test",
                version="0.1.0",
                model=None,
                tools=[],
                permissions=[],
                routes_to=None,
                max_iterations=5,
                config={},
            )


class TestLoadActorManifest:
    def test_load_valid_yaml(self, tmp_path: Path) -> None:
        manifest_data = {
            "name": "test-actor",
            "type": "agent",
            "description": "A test actor",
            "version": "0.1.0",
            "model": "haiku",
            "tools": ["read-events"],
            "permissions": ["read"],
            "routes_to": None,
            "max_iterations": 5,
        }
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(yaml.dump(manifest_data))

        m = load_actor_manifest(tmp_path)
        assert m.name == "test-actor"
        assert m.type == "agent"
        assert m.model == "haiku"

    def test_load_channel_yaml(self, tmp_path: Path) -> None:
        manifest_data = {
            "name": "notify",
            "type": "channel",
            "description": "Notification channel",
            "version": "0.1.0",
            "config": {"webhook_url": "https://example.com"},
        }
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(yaml.dump(manifest_data))

        m = load_actor_manifest(tmp_path)
        assert m.name == "notify"
        assert m.type == "channel"
        assert m.model is None

    def test_load_missing_fields_raises(self, tmp_path: Path) -> None:
        manifest_data = {"name": "bad"}
        manifest_file = tmp_path / "manifest.yaml"
        manifest_file.write_text(yaml.dump(manifest_data))

        with pytest.raises((ValueError, KeyError, TypeError)):
            load_actor_manifest(tmp_path)

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_actor_manifest(tmp_path / "nonexistent")


# ─── Manifest Loader (type detection) ───────────────────────────────


from mallcop.connectors._schema import load_connector_manifest
from mallcop.detectors._schema import load_detector_manifest
from mallcop.actors._schema import load_actor_manifest


class TestManifestLoaderTypeDetection:
    def test_connector_manifest_loads_correctly(self, tmp_path: Path) -> None:
        manifest_data = {
            "name": "azure",
            "description": "Azure",
            "version": "0.1.0",
            "auth": {"required": ["key"], "optional": []},
            "event_types": ["login"],
            "discovery": {"probes": ["check"]},
            "tools": [],
        }
        (tmp_path / "manifest.yaml").write_text(yaml.dump(manifest_data))
        m = load_connector_manifest(tmp_path)
        assert isinstance(m, ConnectorManifest)

    def test_detector_manifest_loads_correctly(self, tmp_path: Path) -> None:
        manifest_data = {
            "name": "new-actor",
            "description": "Detect new actors",
            "version": "0.1.0",
            "sources": "*",
            "event_types": "*",
            "severity_default": "warn",
        }
        (tmp_path / "manifest.yaml").write_text(yaml.dump(manifest_data))
        m = load_detector_manifest(tmp_path)
        assert isinstance(m, DetectorManifest)

    def test_actor_manifest_loads_correctly(self, tmp_path: Path) -> None:
        manifest_data = {
            "name": "triage",
            "type": "agent",
            "description": "Triage",
            "version": "0.1.0",
            "model": "haiku",
            "tools": [],
            "permissions": ["read"],
            "max_iterations": 5,
        }
        (tmp_path / "manifest.yaml").write_text(yaml.dump(manifest_data))
        m = load_actor_manifest(tmp_path)
        assert isinstance(m, ActorManifest)
