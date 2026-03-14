"""Tests for skills.lock generation and verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from mallcop.trust import (
    check_lockfile_hash,
    generate_lockfile,
    load_lockfile,
    skill_content_for_signing,
    write_lockfile,
)
from mallcop.skills._schema import SkillManifest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_skill(skill_dir: Path, name: str = "test-skill") -> SkillManifest:
    """Create a minimal skill directory and return its SkillManifest."""
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A test skill\n---\n\n# Instructions\nDo the thing.\n"
    )
    manifest = SkillManifest.from_skill_dir(skill_dir)
    assert manifest is not None
    return manifest


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


# ---------------------------------------------------------------------------
# generate_lockfile
# ---------------------------------------------------------------------------

class TestGenerateLockfile:
    """generate_lockfile produces a correct lockfile dict."""

    def test_returns_version_1(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir)
        lockfile = generate_lockfile({"my-skill": manifest})
        assert lockfile["version"] == 1

    def test_includes_skill_entry(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir, name="my-skill")
        lockfile = generate_lockfile({"my-skill": manifest})
        assert "my-skill" in lockfile["skills"]

    def test_sha256_matches_content(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir, name="my-skill")
        content = skill_content_for_signing(skill_dir)
        expected = _sha256(content)
        lockfile = generate_lockfile({"my-skill": manifest})
        assert lockfile["skills"]["my-skill"]["sha256"] == expected

    def test_source_is_builtin_when_no_trust_store(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir, name="my-skill")
        lockfile = generate_lockfile({"my-skill": manifest})
        assert lockfile["skills"]["my-skill"]["source"] == "builtin"

    def test_author_from_manifest(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: authored\ndescription: By someone\nauthor: baron@example.com\n---\n"
        )
        manifest = SkillManifest.from_skill_dir(skill_dir)
        assert manifest is not None
        lockfile = generate_lockfile({"authored": manifest})
        assert lockfile["skills"]["authored"]["author"] == "baron@example.com"

    def test_author_is_none_when_not_in_manifest(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir, name="my-skill")
        lockfile = generate_lockfile({"my-skill": manifest})
        assert lockfile["skills"]["my-skill"]["author"] is None

    def test_verified_at_is_iso_string(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir)
        lockfile = generate_lockfile({"my-skill": manifest})
        verified_at = lockfile["skills"]["my-skill"]["verified_at"]
        assert isinstance(verified_at, str)
        # Should parse as ISO datetime
        from datetime import datetime
        datetime.fromisoformat(verified_at)

    def test_expires_is_none_by_default(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir)
        lockfile = generate_lockfile({"my-skill": manifest})
        assert lockfile["skills"]["my-skill"]["expires"] is None

    def test_multiple_skills(self, tmp_path: Path) -> None:
        skill_a = tmp_path / "skill-a"
        skill_b = tmp_path / "skill-b"
        ma = _make_skill(skill_a, name="skill-a")
        mb = _make_skill(skill_b, name="skill-b")
        lockfile = generate_lockfile({"skill-a": ma, "skill-b": mb})
        assert "skill-a" in lockfile["skills"]
        assert "skill-b" in lockfile["skills"]

    def test_empty_skills_dict(self) -> None:
        lockfile = generate_lockfile({})
        assert lockfile["version"] == 1
        assert lockfile["skills"] == {}

    def test_trust_chain_is_none_when_no_trust_store(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir)
        lockfile = generate_lockfile({"my-skill": manifest})
        assert lockfile["skills"]["my-skill"]["trust_chain"] is None


# ---------------------------------------------------------------------------
# write_lockfile / load_lockfile
# ---------------------------------------------------------------------------

class TestWriteLoadLockfile:
    """write_lockfile and load_lockfile are inverse operations."""

    def test_roundtrip_single_skill(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir)
        lockfile = generate_lockfile({"my-skill": manifest})
        lock_path = tmp_path / "skills.lock"
        write_lockfile(lockfile, lock_path)
        loaded = load_lockfile(lock_path)
        assert loaded == lockfile["skills"]

    def test_written_file_is_valid_yaml(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir)
        lockfile = generate_lockfile({"my-skill": manifest})
        lock_path = tmp_path / "skills.lock"
        write_lockfile(lockfile, lock_path)
        parsed = yaml.safe_load(lock_path.read_text())
        assert isinstance(parsed, dict)
        assert "version" in parsed
        assert "skills" in parsed

    def test_write_uses_sorted_keys(self, tmp_path: Path) -> None:
        skill_dir_a = tmp_path / "alpha"
        skill_dir_z = tmp_path / "zeta"
        ma = _make_skill(skill_dir_a, name="alpha")
        mz = _make_skill(skill_dir_z, name="zeta")
        lockfile = generate_lockfile({"zeta": mz, "alpha": ma})
        lock_path = tmp_path / "skills.lock"
        write_lockfile(lockfile, lock_path)
        content = lock_path.read_text()
        # alpha should appear before zeta when keys are sorted
        assert content.index("alpha") < content.index("zeta")

    def test_load_missing_file_returns_empty_dict(self, tmp_path: Path) -> None:
        lock_path = tmp_path / "nonexistent.lock"
        result = load_lockfile(lock_path)
        assert result == {}

    def test_load_returns_skills_dict_only(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir)
        lockfile = generate_lockfile({"my-skill": manifest})
        lock_path = tmp_path / "skills.lock"
        write_lockfile(lockfile, lock_path)
        loaded = load_lockfile(lock_path)
        # load_lockfile returns the skills dict, not the full lockfile structure
        assert "version" not in loaded
        assert "my-skill" in loaded


# ---------------------------------------------------------------------------
# check_lockfile_hash
# ---------------------------------------------------------------------------

class TestCheckLockfileHash:
    """check_lockfile_hash correctly validates skill content against lockfile."""

    def _build_locked_skill(self, tmp_path: Path, name: str = "my-skill") -> tuple[Path, dict]:
        """Helper: create skill + lockfile, return (skill_dir, skills_dict)."""
        skill_dir = tmp_path / name
        manifest = _make_skill(skill_dir, name=name)
        lockfile = generate_lockfile({name: manifest})
        lock_path = tmp_path / "skills.lock"
        write_lockfile(lockfile, lock_path)
        skills = load_lockfile(lock_path)
        return skill_dir, skills

    def test_returns_true_for_intact_skill(self, tmp_path: Path) -> None:
        skill_dir, skills = self._build_locked_skill(tmp_path)
        assert check_lockfile_hash("my-skill", skill_dir, skills) is True

    def test_returns_false_when_skill_not_in_lockfile(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "unknown-skill"
        _make_skill(skill_dir, name="unknown-skill")
        # Empty lockfile — skill not present
        assert check_lockfile_hash("unknown-skill", skill_dir, {}) is False

    def test_returns_false_when_file_modified(self, tmp_path: Path) -> None:
        skill_dir, skills = self._build_locked_skill(tmp_path)
        # Modify a file after locking
        (skill_dir / "SKILL.md").write_text(
            "---\nname: my-skill\ndescription: Tampered content\n---\n"
        )
        assert check_lockfile_hash("my-skill", skill_dir, skills) is False

    def test_returns_false_when_file_added(self, tmp_path: Path) -> None:
        skill_dir, skills = self._build_locked_skill(tmp_path)
        # Add a new file after locking
        (skill_dir / "extra.py").write_text("# injected\n")
        assert check_lockfile_hash("my-skill", skill_dir, skills) is False

    def test_returns_false_when_file_deleted(self, tmp_path: Path) -> None:
        # Add extra file first, then lock, then delete it
        skill_dir = tmp_path / "my-skill"
        manifest = _make_skill(skill_dir, name="my-skill")
        extra = skill_dir / "helper.py"
        extra.write_text("# helper\n")
        lockfile = generate_lockfile({"my-skill": manifest})
        skills = lockfile["skills"]
        # Now delete the extra file — hash mismatch
        extra.unlink()
        assert check_lockfile_hash("my-skill", skill_dir, skills) is False

    def test_returns_false_for_empty_lockfile(self, tmp_path: Path) -> None:
        skill_dir = tmp_path / "my-skill"
        _make_skill(skill_dir, name="my-skill")
        assert check_lockfile_hash("my-skill", skill_dir, {}) is False

    def test_hash_is_case_sensitive(self, tmp_path: Path) -> None:
        skill_dir, skills = self._build_locked_skill(tmp_path)
        # Manually corrupt hash to uppercase
        skills["my-skill"]["sha256"] = skills["my-skill"]["sha256"].upper()
        assert check_lockfile_hash("my-skill", skill_dir, skills) is False

    def test_verify_roundtrip_multiple_skills(self, tmp_path: Path) -> None:
        skill_a = tmp_path / "skill-a"
        skill_b = tmp_path / "skill-b"
        ma = _make_skill(skill_a, name="skill-a")
        mb = _make_skill(skill_b, name="skill-b")
        lockfile = generate_lockfile({"skill-a": ma, "skill-b": mb})
        skills = lockfile["skills"]
        assert check_lockfile_hash("skill-a", skill_a, skills) is True
        assert check_lockfile_hash("skill-b", skill_b, skills) is True

    def test_tamper_one_skill_does_not_affect_other(self, tmp_path: Path) -> None:
        skill_a = tmp_path / "skill-a"
        skill_b = tmp_path / "skill-b"
        ma = _make_skill(skill_a, name="skill-a")
        mb = _make_skill(skill_b, name="skill-b")
        lockfile = generate_lockfile({"skill-a": ma, "skill-b": mb})
        skills = lockfile["skills"]
        # Tamper skill-a
        (skill_a / "SKILL.md").write_text(
            "---\nname: skill-a\ndescription: Tampered\n---\n"
        )
        assert check_lockfile_hash("skill-a", skill_a, skills) is False
        assert check_lockfile_hash("skill-b", skill_b, skills) is True
