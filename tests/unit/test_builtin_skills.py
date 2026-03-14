"""Tests for built-in skills: discovery, parent relationships, and signature verification."""

from __future__ import annotations

from pathlib import Path

import pytest

from mallcop.plugins import discover_plugins
from mallcop.skills._schema import SkillManifest
from mallcop.trust import verify_skill_signature

# Public key for mallcop's built-in skill signing anchor
_MALLCOP_PUBKEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIw7XjZDugCcg7fA5w5oHRAEPhFoRKkCUCgn4ksIY8LK"
    " mallcop@mallcop.app"
)
_MALLCOP_IDENTITY = "mallcop@mallcop.app"

# Path to the built-in mallcop package root
_MALLCOP_PKG = Path(__file__).parent.parent.parent / "src" / "mallcop"


@pytest.fixture(scope="module")
def builtin_skills() -> dict[str, SkillManifest]:
    """Discover skills from the built-in mallcop package."""
    result = discover_plugins([_MALLCOP_PKG])
    return result["skills"]


class TestBuiltinSkillDiscovery:
    """All three built-in skills are discoverable via discover_plugins."""

    def test_privilege_analysis_discovered(self, builtin_skills: dict) -> None:
        assert "privilege-analysis" in builtin_skills

    def test_aws_iam_discovered(self, builtin_skills: dict) -> None:
        assert "aws-iam" in builtin_skills

    def test_openclaw_security_discovered(self, builtin_skills: dict) -> None:
        assert "openclaw-security" in builtin_skills

    def test_all_three_present(self, builtin_skills: dict) -> None:
        names = set(builtin_skills.keys())
        assert {"privilege-analysis", "aws-iam", "openclaw-security"}.issubset(names)

    def test_manifests_are_skill_manifest_instances(self, builtin_skills: dict) -> None:
        for name in ("privilege-analysis", "aws-iam", "openclaw-security"):
            assert isinstance(builtin_skills[name], SkillManifest), (
                f"{name} manifest is not a SkillManifest"
            )


class TestBuiltinSkillMetadata:
    """Skill manifests have correct metadata including version and author."""

    def test_privilege_analysis_metadata(self, builtin_skills: dict) -> None:
        m = builtin_skills["privilege-analysis"]
        assert m.version == "1.0"
        assert m.author == "mallcop@mallcop.app"
        assert m.parent is None

    def test_aws_iam_metadata(self, builtin_skills: dict) -> None:
        m = builtin_skills["aws-iam"]
        assert m.version == "1.0"
        assert m.author == "mallcop@mallcop.app"

    def test_openclaw_security_metadata(self, builtin_skills: dict) -> None:
        m = builtin_skills["openclaw-security"]
        assert m.version == "1.0"
        assert m.author == "mallcop@mallcop.app"
        assert m.parent is None

    def test_descriptions_are_non_empty(self, builtin_skills: dict) -> None:
        for name in ("privilege-analysis", "aws-iam", "openclaw-security"):
            assert builtin_skills[name].description, f"{name} has empty description"

    def test_skill_paths_are_directories(self, builtin_skills: dict) -> None:
        for name in ("privilege-analysis", "aws-iam", "openclaw-security"):
            assert builtin_skills[name].path.is_dir(), (
                f"{name} path is not a directory: {builtin_skills[name].path}"
            )

    def test_skill_md_files_exist(self, builtin_skills: dict) -> None:
        for name in ("privilege-analysis", "aws-iam", "openclaw-security"):
            skill_md = builtin_skills[name].path / "SKILL.md"
            assert skill_md.exists(), f"SKILL.md missing for {name}"


class TestParentRelationship:
    """aws-iam declares privilege-analysis as its parent."""

    def test_aws_iam_parent_is_privilege_analysis(self, builtin_skills: dict) -> None:
        m = builtin_skills["aws-iam"]
        assert m.parent == "privilege-analysis"

    def test_parent_skill_exists(self, builtin_skills: dict) -> None:
        """The parent referenced by aws-iam is itself discoverable."""
        parent_name = builtin_skills["aws-iam"].parent
        assert parent_name in builtin_skills, (
            f"Parent skill '{parent_name}' not found in discovered skills"
        )

    def test_privilege_analysis_has_no_parent(self, builtin_skills: dict) -> None:
        assert builtin_skills["privilege-analysis"].parent is None

    def test_openclaw_security_has_no_parent(self, builtin_skills: dict) -> None:
        assert builtin_skills["openclaw-security"].parent is None


class TestSignatureVerification:
    """All three built-in skills verify against the mallcop anchor key."""

    def test_privilege_analysis_signature_valid(self, builtin_skills: dict) -> None:
        skill_dir = builtin_skills["privilege-analysis"].path
        assert verify_skill_signature(skill_dir, _MALLCOP_PUBKEY, _MALLCOP_IDENTITY), (
            "privilege-analysis signature verification failed"
        )

    def test_aws_iam_signature_valid(self, builtin_skills: dict) -> None:
        skill_dir = builtin_skills["aws-iam"].path
        assert verify_skill_signature(skill_dir, _MALLCOP_PUBKEY, _MALLCOP_IDENTITY), (
            "aws-iam signature verification failed"
        )

    def test_openclaw_security_signature_valid(self, builtin_skills: dict) -> None:
        skill_dir = builtin_skills["openclaw-security"].path
        assert verify_skill_signature(skill_dir, _MALLCOP_PUBKEY, _MALLCOP_IDENTITY), (
            "openclaw-security signature verification failed"
        )

    def test_sig_files_exist(self, builtin_skills: dict) -> None:
        for name in ("privilege-analysis", "aws-iam", "openclaw-security"):
            sig_path = builtin_skills[name].path / "SKILL.md.sig"
            assert sig_path.exists(), f"SKILL.md.sig missing for {name}"

    def test_tampered_skill_fails_verification(
        self, builtin_skills: dict, tmp_path: Path
    ) -> None:
        """Modifying a skill file after signing causes verification to fail."""
        import shutil

        # Copy privilege-analysis to tmp and tamper with it
        src_dir = builtin_skills["privilege-analysis"].path
        tampered_dir = tmp_path / "privilege_analysis"
        shutil.copytree(src_dir, tampered_dir)

        # Append content to SKILL.md to invalidate the signature
        skill_md = tampered_dir / "SKILL.md"
        skill_md.write_text(skill_md.read_text() + "\n<!-- tampered -->")

        result = verify_skill_signature(tampered_dir, _MALLCOP_PUBKEY, _MALLCOP_IDENTITY)
        assert result is False, "Tampered skill should not verify"


class TestAnchorsFile:
    """The trust/anchors file contains the mallcop public key."""

    def test_anchors_file_exists(self) -> None:
        anchors = _MALLCOP_PKG / "trust" / "anchors"
        assert anchors.exists(), "trust/anchors file not found"

    def test_anchors_contains_mallcop_identity(self) -> None:
        anchors = _MALLCOP_PKG / "trust" / "anchors"
        content = anchors.read_text()
        assert "mallcop@mallcop.app" in content

    def test_anchors_contains_ed25519_key(self) -> None:
        anchors = _MALLCOP_PKG / "trust" / "anchors"
        content = anchors.read_text()
        assert "ssh-ed25519" in content
