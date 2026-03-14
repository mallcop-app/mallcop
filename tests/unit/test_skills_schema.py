"""Tests for SkillManifest schema and SKILL.md frontmatter parsing."""

from pathlib import Path

import pytest

from mallcop.skills._schema import SkillManifest, parse_frontmatter


class TestParseFrontmatter:
    """parse_frontmatter splits YAML frontmatter from body text."""

    def test_parses_basic_frontmatter(self, tmp_path: Path) -> None:
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text(
            "---\nname: my-skill\ndescription: Does a thing\n---\n\n# Body text\n"
        )
        fm, body = parse_frontmatter(skill_md)
        assert fm["name"] == "my-skill"
        assert fm["description"] == "Does a thing"
        assert "Body text" in body

    def test_returns_empty_dict_when_no_frontmatter(self, tmp_path: Path) -> None:
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text("# Just a body\nNo frontmatter here.\n")
        fm, body = parse_frontmatter(skill_md)
        assert fm == {}
        assert "Just a body" in body

    def test_body_is_content_after_closing_delimiter(self, tmp_path: Path) -> None:
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text("---\nname: test\n---\nBody content here.\n")
        fm, body = parse_frontmatter(skill_md)
        assert fm["name"] == "test"
        assert body.strip() == "Body content here."

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text("")
        fm, body = parse_frontmatter(skill_md)
        assert fm == {}
        assert body == ""

    def test_only_opening_delimiter_treated_as_no_frontmatter(
        self, tmp_path: Path
    ) -> None:
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text("---\nname: test\nno closing delimiter\n")
        fm, body = parse_frontmatter(skill_md)
        assert fm == {}

    def test_all_standard_fields_parsed(self, tmp_path: Path) -> None:
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text(
            "---\n"
            "name: my-skill\n"
            "description: A great skill\n"
            "parent: base-skill\n"
            "tools: bash,python\n"
            "author: someone\n"
            "version: 1.2.3\n"
            "---\n"
        )
        fm, _ = parse_frontmatter(skill_md)
        assert fm["name"] == "my-skill"
        assert fm["description"] == "A great skill"
        assert fm["parent"] == "base-skill"
        assert fm["tools"] == "bash,python"
        assert fm["author"] == "someone"
        assert fm["version"] == "1.2.3"

    def test_extension_fields_preserved(self, tmp_path: Path) -> None:
        """Extra fields beyond standard ones are preserved in frontmatter dict."""
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text(
            "---\nname: ext-skill\ndescription: extended\ncustom_field: custom_val\n---\n"
        )
        fm, _ = parse_frontmatter(skill_md)
        assert fm["custom_field"] == "custom_val"


class TestSkillManifest:
    """SkillManifest parses SKILL.md frontmatter into a dataclass."""

    def _write_skill_md(
        self,
        skill_dir: Path,
        name: str = "test-skill",
        description: str = "A test skill",
        **extra: object,
    ) -> Path:
        skill_dir.mkdir(parents=True, exist_ok=True)
        lines = [f"name: {name}", f"description: {description}"]
        for k, v in extra.items():
            lines.append(f"{k}: {v}")
        content = "---\n" + "\n".join(lines) + "\n---\n\n# Instructions\nDo the thing.\n"
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text(content)
        return skill_dir

    def test_parses_required_fields(self, tmp_path: Path) -> None:
        skill_dir = self._write_skill_md(tmp_path / "my-skill")
        manifest = SkillManifest.from_skill_dir(skill_dir)
        assert manifest is not None
        assert manifest.name == "test-skill"
        assert manifest.description == "A test skill"
        assert manifest.path == skill_dir

    def test_optional_fields_default_to_none(self, tmp_path: Path) -> None:
        skill_dir = self._write_skill_md(tmp_path / "my-skill")
        manifest = SkillManifest.from_skill_dir(skill_dir)
        assert manifest is not None
        assert manifest.parent is None
        assert manifest.tools is None
        assert manifest.author is None
        assert manifest.version is None

    def test_optional_fields_populated_when_present(self, tmp_path: Path) -> None:
        skill_dir = self._write_skill_md(
            tmp_path / "my-skill",
            parent="base",
            tools="bash,python",
            author="baron",
            version="0.1.0",
        )
        manifest = SkillManifest.from_skill_dir(skill_dir)
        assert manifest is not None
        assert manifest.parent == "base"
        assert manifest.tools == "bash,python"
        assert manifest.author == "baron"
        assert manifest.version == "0.1.0"

    def test_returns_none_when_no_skill_md(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "empty-skill"
        skill_dir.mkdir()
        manifest = SkillManifest.from_skill_dir(skill_dir)
        assert manifest is None

    def test_returns_none_when_name_missing(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "bad-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\ndescription: No name here\n---\n"
        )
        manifest = SkillManifest.from_skill_dir(skill_dir)
        assert manifest is None

    def test_returns_none_when_description_missing(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "bad-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: no-desc-skill\n---\n"
        )
        manifest = SkillManifest.from_skill_dir(skill_dir)
        assert manifest is None

    def test_returns_none_when_malformed_yaml(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "malformed"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: [unclosed bracket\n---\n"
        )
        manifest = SkillManifest.from_skill_dir(skill_dir)
        assert manifest is None

    def test_path_field_is_skill_directory(self, tmp_path: Path) -> None:
        skill_dir = self._write_skill_md(tmp_path / "path-test")
        manifest = SkillManifest.from_skill_dir(skill_dir)
        assert manifest is not None
        assert manifest.path == skill_dir
        assert manifest.path.is_dir()
