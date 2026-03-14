"""Tests for OpenClaw local filesystem connector."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mallcop.connectors._base import SecretProvider
from mallcop.schemas import Checkpoint, DiscoveryResult, PollResult

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "openclaw"


def _make_checkpoint(skill_hashes: dict, config_hash: str) -> Checkpoint:
    return Checkpoint(
        connector="openclaw",
        value=json.dumps({"skill_hashes": skill_hashes, "config_hash": config_hash}),
        updated_at=datetime.now(timezone.utc),
    )


# ─── discover() ──────────────────────────────────────────────────────


class TestOpenClawConnectorDiscover:
    def test_discover_finds_openclaw_home(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        # Create a minimal openclaw home
        (tmp_path / "skills").mkdir()
        (tmp_path / "openclaw.json").write_text("{}")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.discover()

        assert isinstance(result, DiscoveryResult)
        assert result.available is True
        assert any("openclaw_home" in r for r in result.resources)

    def test_discover_no_openclaw_returns_empty(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        nonexistent = tmp_path / "nonexistent_openclaw"
        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(nonexistent)})

        result = connector.discover()

        assert result.available is False
        assert result.resources == []
        assert any("not found" in n for n in result.notes)

    def test_discover_enumerates_skills(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        # Copy clean_install fixture
        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        result = connector.discover()

        skill_resources = [r for r in result.resources if r.startswith("skill: ")]
        assert len(skill_resources) == 2
        names = {r.split(": ")[1] for r in skill_resources}
        assert "web-search" in names
        assert "calendar" in names

    def test_discover_notes_skill_count(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        result = connector.discover()

        assert any("2 skill(s)" in n for n in result.notes)


# ─── authenticate() ──────────────────────────────────────────────────


class TestOpenClawConnectorAuthenticate:
    def test_authenticate_is_noop(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        class FakeSecrets(SecretProvider):
            def get(self, key: str) -> str | None:
                return None

        connector = OpenClawConnector()
        # Should not raise
        connector.authenticate(FakeSecrets())


# ─── poll() ──────────────────────────────────────────────────────────


class TestOpenClawConnectorPoll:
    def test_poll_detects_new_skill(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        # Poll with empty checkpoint (no previous state)
        result = connector.poll(checkpoint=None)

        assert isinstance(result, PollResult)
        skill_installed = [e for e in result.events if e.event_type == "skill_installed"]
        assert len(skill_installed) == 2
        skill_names = {e.target for e in skill_installed}
        assert "web-search" in skill_names
        assert "calendar" in skill_names

    def test_poll_detects_modified_skill(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        # First poll to get current hashes
        first = connector.poll(checkpoint=None)

        # Modify a skill file
        skill_md = tmp_path / "openclaw" / "skills" / "web-search" / "SKILL.md"
        skill_md.write_text(skill_md.read_text() + "\n# Modified")

        # Poll with checkpoint from first poll
        result = connector.poll(checkpoint=first.checkpoint)

        modified = [e for e in result.events if e.event_type == "skill_modified"]
        assert len(modified) == 1
        assert modified[0].target == "web-search"

    def test_poll_detects_removed_skill(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        # First poll
        first = connector.poll(checkpoint=None)

        # Remove a skill directory
        shutil.rmtree(tmp_path / "openclaw" / "skills" / "calendar")

        # Poll again
        result = connector.poll(checkpoint=first.checkpoint)

        removed = [e for e in result.events if e.event_type == "skill_removed"]
        assert len(removed) == 1
        assert removed[0].target == "calendar"

    def test_poll_detects_config_change(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        # First poll
        first = connector.poll(checkpoint=None)

        # Modify config
        config_path = tmp_path / "openclaw" / "openclaw.json"
        config = json.loads(config_path.read_text())
        config["gateway"]["auth"]["enabled"] = False
        config_path.write_text(json.dumps(config))

        # Poll again
        result = connector.poll(checkpoint=first.checkpoint)

        config_events = [e for e in result.events if e.event_type == "config_changed"]
        assert len(config_events) == 1
        assert config_events[0].source == "openclaw"

    def test_poll_no_changes_returns_empty(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        # First poll
        first = connector.poll(checkpoint=None)

        # Poll again with no changes
        result = connector.poll(checkpoint=first.checkpoint)

        assert result.events == []

    def test_poll_checkpoint_contains_hashes(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        result = connector.poll(checkpoint=None)

        state = json.loads(result.checkpoint.value)
        assert "skill_hashes" in state
        assert "config_hash" in state
        assert "web-search" in state["skill_hashes"]
        assert "calendar" in state["skill_hashes"]

    def test_poll_events_have_source_openclaw(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        result = connector.poll(checkpoint=None)

        for evt in result.events:
            assert evt.source == "openclaw"

    def test_poll_skill_event_has_content_in_metadata(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        result = connector.poll(checkpoint=None)

        skill_events = [e for e in result.events if e.event_type == "skill_installed"]
        for evt in skill_events:
            assert "skill_content" in evt.metadata
            assert "skill_name" in evt.metadata

    def test_poll_config_event_has_config_in_metadata(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        src = FIXTURES_DIR / "clean_install"
        shutil.copytree(src, tmp_path / "openclaw")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path / "openclaw")})

        # Inject a fake previous checkpoint with wrong config hash so config_changed fires
        fake_cp = _make_checkpoint(
            skill_hashes={},
            config_hash="000000",
        )
        result = connector.poll(checkpoint=fake_cp)

        config_events = [e for e in result.events if e.event_type == "config_changed"]
        assert len(config_events) == 1
        assert "config" in config_events[0].metadata
        assert "config_raw" in config_events[0].metadata


# ─── event_types() ───────────────────────────────────────────────────


class TestOpenClawConnectorEventTypes:
    def test_event_types_declared(self) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        connector = OpenClawConnector()
        types = connector.event_types()

        assert "skill_installed" in types
        assert "skill_modified" in types
        assert "skill_removed" in types
        assert "config_changed" in types
        assert len(types) >= 4


# ─── SkillParser ─────────────────────────────────────────────────────


class TestSkillParser:
    def test_skill_parser_extracts_frontmatter(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.skills import parse_skill_md

        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text(
            "---\nname: my-skill\ndescription: A test skill\nversion: 1.0.0\nauthor: test-author\n---\n\n# Body\n"
        )

        info = parse_skill_md(skill_md)

        assert info.name == "my-skill"
        assert info.description == "A test skill"
        assert info.version == "1.0.0"
        assert info.author == "test-author"

    def test_skill_parser_handles_no_frontmatter(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.skills import parse_skill_md

        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text("# Just a Markdown File\n\nNo frontmatter here.")

        info = parse_skill_md(skill_md)

        # name falls back to directory name (parent of SKILL.md)
        assert info.name == tmp_path.name
        assert info.description == ""
        assert info.version == "0.0.0"

    def test_skill_parser_returns_full_content(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.skills import parse_skill_md

        content = "---\nname: x\n---\n\nSome body text"
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text(content)

        info = parse_skill_md(skill_md)

        assert info.content == content

    def test_skill_parser_extracts_extra_metadata(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.skills import parse_skill_md

        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text(
            "---\nname: x\ndescription: y\nversion: 1.0.0\nauthor: z\ntags:\n  - foo\n  - bar\n---\n"
        )

        info = parse_skill_md(skill_md)

        assert "tags" in info.metadata
        assert info.metadata["tags"] == ["foo", "bar"]


# ─── manifest ────────────────────────────────────────────────────────


class TestOpenClawManifest:
    def test_manifest_loads(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest

        connector_dir = (
            Path(__file__).parent.parent.parent
            / "src" / "mallcop" / "connectors" / "openclaw"
        )
        manifest = load_connector_manifest(connector_dir)

        assert manifest.name == "openclaw"
        assert "skill_installed" in manifest.event_types
        assert "config_changed" in manifest.event_types

    def test_manifest_event_types_match_connector(self) -> None:
        from mallcop.connectors._schema import load_connector_manifest
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        connector_dir = (
            Path(__file__).parent.parent.parent
            / "src" / "mallcop" / "connectors" / "openclaw"
        )
        manifest = load_connector_manifest(connector_dir)
        connector = OpenClawConnector()

        assert set(connector.event_types()) == set(manifest.event_types)
