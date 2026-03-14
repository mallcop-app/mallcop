"""Tests for skill discovery via discover_plugins and discover_skills."""

from pathlib import Path

import pytest

from mallcop.plugins import discover_plugins
from mallcop.skills._schema import SkillManifest


def _make_skill_dir(parent: Path, dir_name: str, name: str, description: str = "A skill") -> Path:
    skill_dir = parent / dir_name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n\n# Instructions\n"
    )
    return skill_dir


class TestDiscoverSkillsViaPlugins:
    """discover_plugins() includes skills from skills/ subdirectory."""

    def test_discovers_skills_in_directory(self, tmp_path: Path) -> None:
        skills_dir = tmp_path / "skills"
        _make_skill_dir(skills_dir, "my-skill", "my-skill")

        result = discover_plugins([tmp_path])
        assert "my-skill" in result["skills"]

    def test_skill_manifest_returned(self, tmp_path: Path) -> None:
        skills_dir = tmp_path / "skills"
        _make_skill_dir(skills_dir, "my-skill", "my-skill", description="Does things")

        result = discover_plugins([tmp_path])
        manifest = result["skills"]["my-skill"]
        assert isinstance(manifest, SkillManifest)
        assert manifest.name == "my-skill"
        assert manifest.description == "Does things"

    def test_skips_private_directories(self, tmp_path: Path) -> None:
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir(parents=True)
        (skills_dir / "_schema.py").write_text("# private")
        (skills_dir / "__init__.py").write_text("# init")
        _make_skill_dir(skills_dir, "real-skill", "real-skill")

        result = discover_plugins([tmp_path])
        assert "real-skill" in result["skills"]
        assert len(result["skills"]) == 1

    def test_skips_directory_without_skill_md(self, tmp_path: Path) -> None:
        skills_dir = tmp_path / "skills"
        empty_dir = skills_dir / "no-skill-md"
        empty_dir.mkdir(parents=True)
        # No SKILL.md

        result = discover_plugins([tmp_path])
        assert len(result["skills"]) == 0

    def test_skips_skill_with_missing_required_fields(self, tmp_path: Path) -> None:
        skills_dir = tmp_path / "skills"
        bad_dir = skills_dir / "bad-skill"
        bad_dir.mkdir(parents=True)
        (bad_dir / "SKILL.md").write_text("---\ndescription: no name\n---\n")

        result = discover_plugins([tmp_path])
        assert len(result["skills"]) == 0

    def test_skips_malformed_skill_md(self, tmp_path: Path) -> None:
        skills_dir = tmp_path / "skills"
        bad_dir = skills_dir / "malformed"
        bad_dir.mkdir(parents=True)
        (bad_dir / "SKILL.md").write_text("---\nname: [bad\n---\n")

        result = discover_plugins([tmp_path])
        assert len(result["skills"]) == 0

    def test_resolution_order_first_wins(self, tmp_path: Path) -> None:
        """Deployment plugins/ skills override built-in skills with same name."""
        deploy_dir = tmp_path / "deploy"
        builtin_dir = tmp_path / "builtin"

        _make_skill_dir(deploy_dir / "skills", "my-skill", "my-skill", description="deploy version")
        _make_skill_dir(builtin_dir / "skills", "my-skill", "my-skill", description="builtin version")

        result = discover_plugins([deploy_dir, builtin_dir])
        manifest = result["skills"]["my-skill"]
        assert str(deploy_dir) in str(manifest.path)
        assert manifest.description == "deploy version"

    def test_later_paths_add_new_skills(self, tmp_path: Path) -> None:
        deploy_dir = tmp_path / "deploy"
        builtin_dir = tmp_path / "builtin"

        _make_skill_dir(deploy_dir / "skills", "custom-skill", "custom-skill")
        _make_skill_dir(builtin_dir / "skills", "builtin-skill", "builtin-skill")

        result = discover_plugins([deploy_dir, builtin_dir])
        assert "custom-skill" in result["skills"]
        assert "builtin-skill" in result["skills"]

    def test_empty_search_path_returns_empty_skills(self) -> None:
        result = discover_plugins([])
        assert result["skills"] == {}

    def test_nonexistent_path_skipped(self, tmp_path: Path) -> None:
        result = discover_plugins([tmp_path / "nonexistent"])
        assert result["skills"] == {}

    def test_multiple_skills_discovered(self, tmp_path: Path) -> None:
        skills_dir = tmp_path / "skills"
        _make_skill_dir(skills_dir, "skill-a", "skill-a")
        _make_skill_dir(skills_dir, "skill-b", "skill-b")
        _make_skill_dir(skills_dir, "skill-c", "skill-c")

        result = discover_plugins([tmp_path])
        assert "skill-a" in result["skills"]
        assert "skill-b" in result["skills"]
        assert "skill-c" in result["skills"]

    def test_skills_coexist_with_other_plugin_types(self, tmp_path: Path) -> None:
        """A single search path can contain connectors, detectors, actors, AND skills."""
        _make_skill_dir(tmp_path / "skills", "my-skill", "my-skill")

        # Also add a connector manifest
        connector_dir = tmp_path / "connectors" / "azure"
        connector_dir.mkdir(parents=True)
        import yaml
        (connector_dir / "manifest.yaml").write_text(
            yaml.dump({"name": "azure", "description": "Azure connector", "event_types": []})
        )

        result = discover_plugins([tmp_path])
        assert "my-skill" in result["skills"]
        assert "azure" in result["connectors"]

    def test_skill_manifest_path_is_skill_directory(self, tmp_path: Path) -> None:
        skills_dir = tmp_path / "skills"
        skill_dir = _make_skill_dir(skills_dir, "path-skill", "path-skill")

        result = discover_plugins([tmp_path])
        manifest = result["skills"]["path-skill"]
        assert manifest.path == skill_dir
