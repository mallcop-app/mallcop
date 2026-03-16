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
            def resolve(self, name: str) -> str:
                return ""

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


# ─── poll() helpers ──────────────────────────────────────────────────


class TestDecodeCheckpoint:
    def test_decode_none_returns_empty_dict(self) -> None:
        from mallcop.connectors.openclaw.connector import _decode_checkpoint

        assert _decode_checkpoint(None) == {}

    def test_decode_empty_value_returns_empty_dict(self) -> None:
        from mallcop.connectors.openclaw.connector import _decode_checkpoint

        cp = Checkpoint(connector="openclaw", value="", updated_at=datetime.now(timezone.utc))
        assert _decode_checkpoint(cp) == {}

    def test_decode_valid_json_returns_dict(self) -> None:
        from mallcop.connectors.openclaw.connector import _decode_checkpoint

        state = {"skill_hashes": {"foo": "abc123"}, "config_hash": "xyz"}
        cp = Checkpoint(
            connector="openclaw",
            value=json.dumps(state),
            updated_at=datetime.now(timezone.utc),
        )
        result = _decode_checkpoint(cp)
        assert result["skill_hashes"] == {"foo": "abc123"}
        assert result["config_hash"] == "xyz"

    def test_decode_invalid_json_returns_empty_dict(self) -> None:
        from mallcop.connectors.openclaw.connector import _decode_checkpoint

        cp = Checkpoint(
            connector="openclaw",
            value="not-valid-json{{{",
            updated_at=datetime.now(timezone.utc),
        )
        assert _decode_checkpoint(cp) == {}

    def test_decode_non_string_value_returns_empty_dict(self) -> None:
        from mallcop.connectors.openclaw.connector import _decode_checkpoint

        cp = Checkpoint(connector="openclaw", value=None, updated_at=datetime.now(timezone.utc))  # type: ignore[arg-type]
        assert _decode_checkpoint(cp) == {}


class TestSkillInfoToDict:
    def test_converts_all_fields(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import _skill_info_to_dict
        from mallcop.connectors.openclaw.skills import SkillInfo

        skill_path = tmp_path / "SKILL.md"
        skill_path.write_text("content")
        info = SkillInfo(
            name="my-skill",
            description="does stuff",
            version="2.0.0",
            author="alice",
            path=skill_path,
            content="content",
        )
        result = _skill_info_to_dict(info)

        assert result["skill_name"] == "my-skill"
        assert result["skill_description"] == "does stuff"
        assert result["skill_version"] == "2.0.0"
        assert result["skill_author"] == "alice"
        assert result["skill_content"] == "content"
        assert result["skill_path"] == str(skill_path)

    def test_path_is_string(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import _skill_info_to_dict
        from mallcop.connectors.openclaw.skills import SkillInfo

        skill_path = tmp_path / "SKILL.md"
        skill_path.write_text("x")
        info = SkillInfo(name="x", description="", version="0", author="", path=skill_path, content="x")
        result = _skill_info_to_dict(info)

        assert isinstance(result["skill_path"], str)


class TestMakeSkillEvent:
    def test_event_fields(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import _make_skill_event

        now = datetime.now(timezone.utc)
        evt = _make_skill_event(
            event_type="skill_installed",
            skill_name="my-skill",
            skill_info_dict={"skill_name": "my-skill", "skill_content": "body"},
            timestamp=now,
            openclaw_home=tmp_path,
        )

        assert evt.source == "openclaw"
        assert evt.event_type == "skill_installed"
        assert evt.actor == "filesystem"
        assert evt.action == "skill_installed"
        assert evt.target == "my-skill"
        assert evt.timestamp == now
        assert evt.metadata["skill_name"] == "my-skill"
        assert evt.metadata["openclaw_home"] == str(tmp_path)

    def test_event_raw_contains_skill_name(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import _make_skill_event

        now = datetime.now(timezone.utc)
        evt = _make_skill_event(
            event_type="skill_removed",
            skill_name="gone-skill",
            skill_info_dict={"skill_name": "gone-skill"},
            timestamp=now,
            openclaw_home=tmp_path,
        )

        assert evt.raw["skill_name"] == "gone-skill"
        assert evt.raw["event_type"] == "skill_removed"

    def test_event_id_is_deterministic_for_same_inputs(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import _make_skill_event

        now = datetime.now(timezone.utc)
        evt1 = _make_skill_event(
            event_type="skill_installed",
            skill_name="foo",
            skill_info_dict={},
            timestamp=now,
            openclaw_home=tmp_path,
        )
        evt2 = _make_skill_event(
            event_type="skill_installed",
            skill_name="foo",
            skill_info_dict={},
            timestamp=now,
            openclaw_home=tmp_path,
        )
        assert evt1.id == evt2.id

    def test_event_id_differs_for_different_skill_names(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import _make_skill_event

        now = datetime.now(timezone.utc)
        evt1 = _make_skill_event(
            event_type="skill_installed",
            skill_name="foo",
            skill_info_dict={},
            timestamp=now,
            openclaw_home=tmp_path,
        )
        evt2 = _make_skill_event(
            event_type="skill_installed",
            skill_name="bar",
            skill_info_dict={},
            timestamp=now,
            openclaw_home=tmp_path,
        )
        assert evt1.id != evt2.id


# ─── poll() edge cases ────────────────────────────────────────────────


class TestOpenClawPollEdgeCases:
    def test_poll_empty_skills_dir_no_events_no_checkpoint(self, tmp_path: Path) -> None:
        """No skills, no config → checkpoint with empty hashes, zero events."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        (tmp_path / "skills").mkdir()
        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=None)

        assert result.events == []
        state = json.loads(result.checkpoint.value)
        assert state["skill_hashes"] == {}
        assert state["config_hash"] == ""

    def test_poll_no_skills_dir_no_events(self, tmp_path: Path) -> None:
        """Skills dir missing entirely → no skill events."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        # No skills/ subdir at all
        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=None)

        skill_events = [e for e in result.events if e.event_type.startswith("skill_")]
        assert skill_events == []

    def test_poll_config_invalid_json_still_emits_event(self, tmp_path: Path) -> None:
        """Config file with invalid JSON triggers config_changed with empty config dict."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        (tmp_path / "skills").mkdir()
        config_path = tmp_path / "openclaw.json"
        config_path.write_text("{invalid json!!!")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=None)

        config_events = [e for e in result.events if e.event_type == "config_changed"]
        assert len(config_events) == 1
        assert config_events[0].metadata["config"] == {}

    def test_poll_multiple_skills_all_appear_on_first_scan(self, tmp_path: Path) -> None:
        """All skills on disk appear as skill_installed on first (None) checkpoint."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        for skill_name in ("alpha", "beta", "gamma"):
            skill_dir = skills_dir / skill_name
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text(f"---\nname: {skill_name}\n---\n")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=None)

        installed = [e for e in result.events if e.event_type == "skill_installed"]
        assert len(installed) == 3
        assert {e.target for e in installed} == {"alpha", "beta", "gamma"}

    def test_poll_with_stale_checkpoint_detects_all_skills_as_installed(self, tmp_path: Path) -> None:
        """Checkpoint listing skills that no longer exist + new skills on disk → removed + installed."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "new-skill").mkdir()
        (skills_dir / "new-skill" / "SKILL.md").write_text("---\nname: new-skill\n---\n")

        cp = _make_checkpoint(
            skill_hashes={"old-skill": "deadbeef"},
            config_hash="",
        )
        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=cp)

        installed = [e for e in result.events if e.event_type == "skill_installed"]
        removed = [e for e in result.events if e.event_type == "skill_removed"]
        assert len(installed) == 1
        assert installed[0].target == "new-skill"
        assert len(removed) == 1
        assert removed[0].target == "old-skill"

    def test_poll_removed_skill_event_has_skill_name_in_metadata(self, tmp_path: Path) -> None:
        """Removed skill event carries skill_name in metadata even without a SKILL.md."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        (tmp_path / "skills").mkdir()
        cp = _make_checkpoint(skill_hashes={"vanished": "abc"}, config_hash="")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=cp)

        removed = [e for e in result.events if e.event_type == "skill_removed"]
        assert len(removed) == 1
        assert removed[0].metadata["skill_name"] == "vanished"

    def test_poll_checkpoint_updated_at_is_recent(self, tmp_path: Path) -> None:
        """The new checkpoint's updated_at is within the last few seconds."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        (tmp_path / "skills").mkdir()
        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        before = datetime.now(timezone.utc)
        result = connector.poll(checkpoint=None)
        after = datetime.now(timezone.utc)

        assert before <= result.checkpoint.updated_at <= after

    def test_poll_checkpoint_connector_name_is_openclaw(self, tmp_path: Path) -> None:
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        (tmp_path / "skills").mkdir()
        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=None)

        assert result.checkpoint.connector == "openclaw"

    def test_poll_unicode_skill_directory_name(self, tmp_path: Path) -> None:
        """Skills with unicode directory names are tracked correctly."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        skill_name = "résumé-skill"
        skill_dir = skills_dir / skill_name
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("---\nname: résumé-skill\n---\n")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=None)

        installed = [e for e in result.events if e.event_type == "skill_installed"]
        assert len(installed) == 1
        assert installed[0].target == skill_name

    def test_poll_skill_dir_without_skill_md_ignored(self, tmp_path: Path) -> None:
        """Directories lacking SKILL.md are not treated as skills."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        # A directory without SKILL.md
        (skills_dir / "not-a-skill").mkdir()
        (skills_dir / "not-a-skill" / "README.md").write_text("no skill here")
        # A valid skill
        (skills_dir / "real-skill").mkdir()
        (skills_dir / "real-skill" / "SKILL.md").write_text("---\nname: real-skill\n---\n")

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=None)

        installed = [e for e in result.events if e.event_type == "skill_installed"]
        assert len(installed) == 1
        assert installed[0].target == "real-skill"

    def test_poll_config_unchanged_no_config_event(self, tmp_path: Path) -> None:
        """When config hash matches checkpoint, no config_changed event is emitted."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        (tmp_path / "skills").mkdir()
        config_path = tmp_path / "openclaw.json"
        config_path.write_text('{"key": "value"}')

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        first = connector.poll(checkpoint=None)
        second = connector.poll(checkpoint=first.checkpoint)

        config_events = [e for e in second.events if e.event_type == "config_changed"]
        assert config_events == []

    def test_poll_config_event_target_is_config_path(self, tmp_path: Path) -> None:
        """config_changed event target is the absolute path to openclaw.json."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector

        (tmp_path / "skills").mkdir()
        config_path = tmp_path / "openclaw.json"
        config_path.write_text('{"x": 1}')

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=None)

        config_events = [e for e in result.events if e.event_type == "config_changed"]
        assert len(config_events) == 1
        assert config_events[0].target == str(config_path)

    def test_poll_config_hash_in_new_checkpoint(self, tmp_path: Path) -> None:
        """After seeing a config file, checkpoint stores its hash."""
        from mallcop.connectors.openclaw.connector import OpenClawConnector
        from mallcop.connectors.openclaw.skills import hash_file

        (tmp_path / "skills").mkdir()
        config_path = tmp_path / "openclaw.json"
        config_path.write_text('{"a": 1}')

        connector = OpenClawConnector()
        connector.configure({"openclaw_home": str(tmp_path)})

        result = connector.poll(checkpoint=None)

        state = json.loads(result.checkpoint.value)
        assert state["config_hash"] == hash_file(config_path)


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
