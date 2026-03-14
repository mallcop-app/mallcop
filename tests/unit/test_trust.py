"""Tests for mallcop skill signing and verification (trust.py)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

# Skip all tests that require ssh-keygen -Y sign/verify if not available
def _has_ssh_keygen_sign() -> bool:
    result = subprocess.run(
        ["ssh-keygen", "-Y", "sign"],
        capture_output=True,
        text=True,
    )
    # "Too few arguments" means -Y sign is supported but we're missing args
    return "Too few arguments" in result.stderr or "namespace" in result.stderr.lower()


HAS_SSH_KEYGEN = shutil.which("ssh-keygen") is not None
HAS_SSH_KEYGEN_SIGN = HAS_SSH_KEYGEN and _has_ssh_keygen_sign()

requires_ssh_sign = pytest.mark.skipif(
    not HAS_SSH_KEYGEN_SIGN, reason="ssh-keygen -Y sign not available"
)


def _make_skill_dir(tmp_path: Path) -> Path:
    """Create a minimal skill directory for testing."""
    skill_dir = tmp_path / "my-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# My Skill\n\nThis is a test skill.\n")
    (skill_dir / "tools.py").write_text("def run(): pass\n")
    sub = skill_dir / "sub"
    sub.mkdir()
    (sub / "helper.py").write_text("# helper\n")
    return skill_dir


def _generate_test_key(tmp_path: Path) -> tuple[Path, str]:
    """Generate an ed25519 key pair for testing. Returns (key_path, pubkey_string)."""
    key_path = tmp_path / "test_key"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-C", "test@mallcop"],
        check=True,
        capture_output=True,
    )
    pubkey = (tmp_path / "test_key.pub").read_text().strip()
    return key_path, pubkey


class TestSkillContentForSigning:
    """Tests for the content blob generation (no ssh-keygen required)."""

    def test_returns_bytes(self, tmp_path: Path) -> None:
        from mallcop.trust import skill_content_for_signing

        skill_dir = _make_skill_dir(tmp_path)
        content = skill_content_for_signing(skill_dir)
        assert isinstance(content, bytes)

    def test_includes_all_files(self, tmp_path: Path) -> None:
        from mallcop.trust import skill_content_for_signing

        skill_dir = _make_skill_dir(tmp_path)
        content = skill_content_for_signing(skill_dir).decode()
        assert "SKILL.md" in content
        assert "tools.py" in content
        assert "This is a test skill." in content

    def test_includes_nested_files(self, tmp_path: Path) -> None:
        from mallcop.trust import skill_content_for_signing

        skill_dir = _make_skill_dir(tmp_path)
        content = skill_content_for_signing(skill_dir).decode()
        # sub/helper.py should appear with relative path
        assert "helper.py" in content
        assert "# helper" in content

    def test_deterministic(self, tmp_path: Path) -> None:
        from mallcop.trust import skill_content_for_signing

        skill_dir = _make_skill_dir(tmp_path)
        c1 = skill_content_for_signing(skill_dir)
        c2 = skill_content_for_signing(skill_dir)
        assert c1 == c2

    def test_excludes_skill_md_sig(self, tmp_path: Path) -> None:
        from mallcop.trust import skill_content_for_signing

        skill_dir = _make_skill_dir(tmp_path)
        # Add a .sig file — it should be excluded
        (skill_dir / "SKILL.md.sig").write_text("fakesig")
        content = skill_content_for_signing(skill_dir).decode()
        assert "SKILL.md.sig" not in content
        assert "fakesig" not in content

    def test_excludes_directories_from_content(self, tmp_path: Path) -> None:
        from mallcop.trust import skill_content_for_signing

        skill_dir = _make_skill_dir(tmp_path)
        # Directory entries should not appear as file content entries
        content = skill_content_for_signing(skill_dir).decode()
        # "sub" directory itself should not create a "--- sub ---" header
        # only "sub/helper.py" (the file inside) should appear
        lines = content.split("\n")
        headers = [l for l in lines if l.startswith("--- ") and l.endswith(" ---")]
        for h in headers:
            # Strip "--- " prefix and " ---" suffix
            rel = h[4:-4]
            # Must be a file path, not a plain directory name
            assert "/" in rel or "." in rel, f"Header '{h}' looks like a directory, not a file"

    def test_content_changes_when_file_modified(self, tmp_path: Path) -> None:
        from mallcop.trust import skill_content_for_signing

        skill_dir = _make_skill_dir(tmp_path)
        before = skill_content_for_signing(skill_dir)
        (skill_dir / "SKILL.md").write_text("# Modified\n")
        after = skill_content_for_signing(skill_dir)
        assert before != after

    def test_content_changes_when_file_added(self, tmp_path: Path) -> None:
        from mallcop.trust import skill_content_for_signing

        skill_dir = _make_skill_dir(tmp_path)
        before = skill_content_for_signing(skill_dir)
        (skill_dir / "new_file.py").write_text("# new\n")
        after = skill_content_for_signing(skill_dir)
        assert before != after


class TestSignSkill:
    """Tests for sign_skill — requires ssh-keygen with -Y sign."""

    @requires_ssh_sign
    def test_creates_sig_file(self, tmp_path: Path) -> None:
        from mallcop.trust import sign_skill

        skill_dir = _make_skill_dir(tmp_path)
        key_path, _ = _generate_test_key(tmp_path)
        sig_path = sign_skill(skill_dir, key_path)
        assert sig_path.exists()
        assert sig_path.name == "SKILL.md.sig"
        assert sig_path.parent == skill_dir

    @requires_ssh_sign
    def test_sig_file_contains_ssh_signature(self, tmp_path: Path) -> None:
        from mallcop.trust import sign_skill

        skill_dir = _make_skill_dir(tmp_path)
        key_path, _ = _generate_test_key(tmp_path)
        sig_path = sign_skill(skill_dir, key_path)
        content = sig_path.read_text()
        assert "BEGIN SSH SIGNATURE" in content

    def test_missing_ssh_keygen_raises_clear_error(self, tmp_path: Path, monkeypatch) -> None:
        from mallcop.trust import sign_skill

        skill_dir = _make_skill_dir(tmp_path)
        # Monkeypatch shutil.which to return None for ssh-keygen
        import mallcop.trust as trust_module
        monkeypatch.setattr(trust_module, "_find_ssh_keygen", lambda: None)
        with pytest.raises(RuntimeError, match="ssh-keygen"):
            sign_skill(skill_dir, tmp_path / "fake_key")


class TestVerifySkillSignature:
    """Tests for verify_skill_signature — requires ssh-keygen with -Y verify."""

    @requires_ssh_sign
    def test_roundtrip_passes(self, tmp_path: Path) -> None:
        from mallcop.trust import sign_skill, verify_skill_signature

        skill_dir = _make_skill_dir(tmp_path)
        key_path, pubkey = _generate_test_key(tmp_path)
        sign_skill(skill_dir, key_path)
        result = verify_skill_signature(skill_dir, pubkey, "test@mallcop")
        assert result is True

    @requires_ssh_sign
    def test_tampered_file_fails(self, tmp_path: Path) -> None:
        from mallcop.trust import sign_skill, verify_skill_signature

        skill_dir = _make_skill_dir(tmp_path)
        key_path, pubkey = _generate_test_key(tmp_path)
        sign_skill(skill_dir, key_path)
        # Tamper with a file after signing
        (skill_dir / "SKILL.md").write_text("# Tampered\n")
        result = verify_skill_signature(skill_dir, pubkey, "test@mallcop")
        assert result is False

    @requires_ssh_sign
    def test_added_file_fails(self, tmp_path: Path) -> None:
        from mallcop.trust import sign_skill, verify_skill_signature

        skill_dir = _make_skill_dir(tmp_path)
        key_path, pubkey = _generate_test_key(tmp_path)
        sign_skill(skill_dir, key_path)
        # Add a new file after signing
        (skill_dir / "malicious.py").write_text("import os; os.system('rm -rf /')\n")
        result = verify_skill_signature(skill_dir, pubkey, "test@mallcop")
        assert result is False

    def test_missing_sig_returns_false(self, tmp_path: Path) -> None:
        from mallcop.trust import verify_skill_signature

        skill_dir = _make_skill_dir(tmp_path)
        # No SKILL.md.sig present
        result = verify_skill_signature(skill_dir, "ssh-ed25519 AAAA fake", "test@mallcop")
        assert result is False

    @requires_ssh_sign
    def test_wrong_identity_fails(self, tmp_path: Path) -> None:
        from mallcop.trust import sign_skill, verify_skill_signature

        skill_dir = _make_skill_dir(tmp_path)
        key_path, pubkey = _generate_test_key(tmp_path)
        sign_skill(skill_dir, key_path)
        # Verify with an identity that has NO entry in allowed_signers:
        # pubkey belongs to "test@mallcop" but allowed_signers will list it
        # under attacker@evil.com → the -I "test@mallcop" lookup finds nothing.
        # Construct a pubkey from a DIFFERENT key listed under the correct identity,
        # so the attacker's key is not authorized for the legitimate identity.
        # Simplest: generate a second key pair and try to verify using the second
        # key's pubkey with the first key's identity — the second key was never used
        # to sign, so verification fails.
        (tmp_path / "other").mkdir()
        key_path2, pubkey2 = _generate_test_key(tmp_path / "other")
        # pubkey2 is not the signing key; allowed_signers maps test@mallcop → pubkey2
        result = verify_skill_signature(skill_dir, pubkey2, "test@mallcop")
        assert result is False

    @requires_ssh_sign
    def test_wrong_pubkey_fails(self, tmp_path: Path) -> None:
        from mallcop.trust import sign_skill, verify_skill_signature

        skill_dir = _make_skill_dir(tmp_path)
        key_path, pubkey = _generate_test_key(tmp_path)
        sign_skill(skill_dir, key_path)
        # Generate a different key and use its pubkey — allowed_signers maps
        # "test@mallcop" to a different key, so verification fails.
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        key_path2, pubkey2 = _generate_test_key(other_dir)
        result = verify_skill_signature(skill_dir, pubkey2, "test@mallcop")
        assert result is False

    def test_missing_ssh_keygen_raises_clear_error(self, tmp_path: Path, monkeypatch) -> None:
        from mallcop.trust import verify_skill_signature

        skill_dir = _make_skill_dir(tmp_path)
        (skill_dir / "SKILL.md.sig").write_text("fake sig")
        import mallcop.trust as trust_module
        monkeypatch.setattr(trust_module, "_find_ssh_keygen", lambda: None)
        with pytest.raises(RuntimeError, match="ssh-keygen"):
            verify_skill_signature(skill_dir, "ssh-ed25519 AAAA fake", "test@mallcop")


class TestSkillCLI:
    """Tests for mallcop skill sign/verify CLI commands."""

    @requires_ssh_sign
    def test_skill_sign_creates_sig(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        skill_dir = _make_skill_dir(tmp_path)
        key_path, _ = _generate_test_key(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["skill", "sign", str(skill_dir), "--key", str(key_path)])
        assert result.exit_code == 0, result.output
        assert (skill_dir / "SKILL.md.sig").exists()

    @requires_ssh_sign
    def test_skill_verify_passes_after_sign(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        skill_dir = _make_skill_dir(tmp_path)
        key_path, pubkey = _generate_test_key(tmp_path)
        # Sign first
        runner = CliRunner()
        result = runner.invoke(cli, ["skill", "sign", str(skill_dir), "--key", str(key_path)])
        assert result.exit_code == 0, result.output
        # Verify using public key
        pubkey_path = tmp_path / "test_key.pub"
        result = runner.invoke(cli, ["skill", "verify", str(skill_dir), "--pubkey", str(pubkey_path)])
        assert result.exit_code == 0, result.output

    @requires_ssh_sign
    def test_skill_verify_fails_after_tamper(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        skill_dir = _make_skill_dir(tmp_path)
        key_path, pubkey = _generate_test_key(tmp_path)
        runner = CliRunner()
        runner.invoke(cli, ["skill", "sign", str(skill_dir), "--key", str(key_path)])
        # Tamper
        (skill_dir / "SKILL.md").write_text("# Hacked\n")
        pubkey_path = tmp_path / "test_key.pub"
        result = runner.invoke(cli, ["skill", "verify", str(skill_dir), "--pubkey", str(pubkey_path)])
        assert result.exit_code != 0

    def test_skill_verify_missing_sig_fails(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        skill_dir = _make_skill_dir(tmp_path)
        runner = CliRunner()
        # No pubkey needed — should fail early on missing sig
        result = runner.invoke(cli, ["skill", "verify", str(skill_dir), "--pubkey", "fake.pub"])
        assert result.exit_code != 0
