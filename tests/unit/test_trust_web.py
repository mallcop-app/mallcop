"""Tests for TrustStore, find_trust_path, scope_matches, and trust CLI commands."""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml


# ---------------------------------------------------------------------------
# ssh-keygen availability helpers (mirrored from test_trust.py)
# ---------------------------------------------------------------------------

def _has_ssh_keygen_sign() -> bool:
    result = subprocess.run(
        ["ssh-keygen", "-Y", "sign"],
        capture_output=True,
        text=True,
    )
    return "Too few arguments" in result.stderr or "namespace" in result.stderr.lower()


HAS_SSH_KEYGEN = shutil.which("ssh-keygen") is not None
HAS_SSH_KEYGEN_SIGN = HAS_SSH_KEYGEN and _has_ssh_keygen_sign()

requires_ssh_sign = pytest.mark.skipif(
    not HAS_SSH_KEYGEN_SIGN, reason="ssh-keygen -Y sign not available"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_key(tmp_path: Path, name: str = "key", comment: str = "user@test") -> tuple[Path, str]:
    """Generate an ed25519 key pair. Returns (private_key_path, pubkey_string)."""
    key_path = tmp_path / name
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-C", comment],
        check=True,
        capture_output=True,
    )
    pubkey = (tmp_path / f"{name}.pub").read_text().strip()
    return key_path, pubkey


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _future(days: int = 365) -> datetime:
    return _now() + timedelta(days=days)


def _past(days: int = 1) -> datetime:
    return _now() - timedelta(days=days)


def _make_trust_dir(tmp_path: Path) -> Path:
    """Create a .mallcop/trust directory structure."""
    trust_dir = tmp_path / ".mallcop" / "trust"
    (trust_dir / "endorsements").mkdir(parents=True)
    return trust_dir


def _write_anchors(trust_dir: Path, entries: dict[str, str]) -> None:
    """Write anchors file with {identity: pubkey_string} entries."""
    lines = []
    for identity, pubkey in entries.items():
        # pubkey is "keytype base64 comment" — write as "identity keytype base64"
        parts = pubkey.split()
        lines.append(f"{identity} {parts[0]} {parts[1]}\n")
    (trust_dir / "anchors").write_text("".join(lines))


def _write_keyring(trust_dir: Path, entries: dict[str, str]) -> None:
    """Write keyring file with {identity: pubkey_string} entries."""
    lines = []
    for identity, pubkey in entries.items():
        parts = pubkey.split()
        lines.append(f"{identity} {parts[0]} {parts[1]}\n")
    (trust_dir / "keyring").write_text("".join(lines))


@requires_ssh_sign
def _sign_endorsement_file(endorse_path: Path, key_path: Path, identity: str) -> None:
    """Sign an endorsement file with an SSH key using the mallcop-endorsement namespace."""
    content = endorse_path.read_bytes()
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".content") as tf:
        content_file = Path(tf.name)
        tf.write(content)
    try:
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", "mallcop-endorsement",
             str(content_file)],
            check=True,
            capture_output=True,
        )
        sig_file = content_file.with_suffix(".content.sig")
        sig_file.rename(endorse_path.with_suffix(".endorse.sig"))
    finally:
        content_file.unlink(missing_ok=True)


def _write_endorsement(
    trust_dir: Path,
    endorser_identity: str,
    endorser_key: Path,
    endorser_pubkey: str,
    endorsed_identity: str,
    trust_level: str,
    scope: str,
    reason: str = "test",
    expires: datetime | None = None,
    sign: bool = True,
    filename: str | None = None,
) -> Path:
    """Write an endorsement YAML file (and optionally sign it).

    Returns path to the .endorse file.
    """
    if expires is None:
        expires = _future()

    data = {
        "endorser": endorser_identity,
        "signed_at": _now().isoformat(),
        "endorsements": [
            {
                "identity": endorsed_identity,
                "trust_level": trust_level,
                "scope": scope,
                "reason": reason,
                "expires": expires.isoformat(),
            }
        ],
    }
    # Canonical serialization
    content = yaml.dump(data, sort_keys=True, default_flow_style=False)

    fname = filename or f"{endorser_identity.replace('@', '_').replace('.', '_')}.endorse"
    endorse_path = trust_dir / "endorsements" / fname
    endorse_path.write_text(content)

    if sign and HAS_SSH_KEYGEN_SIGN:
        _sign_endorsement_file(endorse_path, endorser_key, endorser_identity)

    return endorse_path


# ---------------------------------------------------------------------------
# scope_matches tests (no ssh-keygen needed)
# ---------------------------------------------------------------------------

class TestScopeMatches:
    def test_wildcard_matches_everything(self) -> None:
        from mallcop.trust import scope_matches
        assert scope_matches("*", "aws-iam") is True
        assert scope_matches("*", "anything") is True

    def test_prefix_wildcard(self) -> None:
        from mallcop.trust import scope_matches
        assert scope_matches("aws-*", "aws-iam") is True
        assert scope_matches("aws-*", "aws-networking") is True
        assert scope_matches("aws-*", "gcp-iam") is False

    def test_exact_match(self) -> None:
        from mallcop.trust import scope_matches
        assert scope_matches("privilege-analysis", "privilege-analysis") is True
        assert scope_matches("privilege-analysis", "other-skill") is False

    def test_no_match(self) -> None:
        from mallcop.trust import scope_matches
        assert scope_matches("aws-*", "gcp-storage") is False


# ---------------------------------------------------------------------------
# load_anchors / load_keyring tests
# ---------------------------------------------------------------------------

class TestLoadAnchors:
    @requires_ssh_sign
    def test_loads_anchors(self, tmp_path: Path) -> None:
        from mallcop.trust import load_anchors
        _, pubkey = _generate_key(tmp_path, "anchor_key", "anchor@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": pubkey})

        anchors = load_anchors(trust_dir / "anchors")
        assert "anchor@test" in anchors
        # Value should be "keytype base64"
        assert anchors["anchor@test"].startswith("ssh-ed25519 ")

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        from mallcop.trust import load_anchors
        result = load_anchors(tmp_path / "nonexistent")
        assert result == {}

    @requires_ssh_sign
    def test_multiple_anchors(self, tmp_path: Path) -> None:
        from mallcop.trust import load_anchors
        _, pk1 = _generate_key(tmp_path, "k1", "alice@test")
        _, pk2 = _generate_key(tmp_path, "k2", "bob@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"alice@test": pk1, "bob@test": pk2})

        anchors = load_anchors(trust_dir / "anchors")
        assert "alice@test" in anchors
        assert "bob@test" in anchors

    def test_ignores_blank_lines_and_comments(self, tmp_path: Path) -> None:
        from mallcop.trust import load_anchors
        trust_dir = _make_trust_dir(tmp_path)
        (trust_dir / "anchors").write_text(
            "# comment\n\nalice@test ssh-ed25519 AAAA1234\n\n"
        )
        anchors = load_anchors(trust_dir / "anchors")
        assert "alice@test" in anchors


class TestLoadKeyring:
    @requires_ssh_sign
    def test_loads_keyring(self, tmp_path: Path) -> None:
        from mallcop.trust import load_keyring
        _, pubkey = _generate_key(tmp_path, "kring_key", "user@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_keyring(trust_dir, {"user@test": pubkey})

        keyring = load_keyring(trust_dir / "keyring")
        assert "user@test" in keyring

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        from mallcop.trust import load_keyring
        result = load_keyring(tmp_path / "nonexistent")
        assert result == {}


# ---------------------------------------------------------------------------
# load_endorsements tests
# ---------------------------------------------------------------------------

class TestLoadEndorsements:
    @requires_ssh_sign
    def test_loads_valid_endorsement(self, tmp_path: Path) -> None:
        from mallcop.trust import load_endorsements

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey})

        _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "author@test", "author", "*",
        )

        endorsements = load_endorsements(trust_dir / "endorsements", {"anchor@test": anchor_pubkey})
        assert "anchor@test" in endorsements
        assert len(endorsements["anchor@test"]) == 1
        assert endorsements["anchor@test"][0].identity == "author@test"

    def test_missing_dir_returns_empty(self, tmp_path: Path) -> None:
        from mallcop.trust import load_endorsements
        result = load_endorsements(tmp_path / "nonexistent", {})
        assert result == {}

    @requires_ssh_sign
    def test_invalid_sig_skipped(self, tmp_path: Path) -> None:
        """Endorsement with missing .sig file is skipped."""
        from mallcop.trust import load_endorsements

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})

        endorse_path = _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "author@test", "author", "*", sign=False,
        )
        # No .sig file — should be skipped
        endorsements = load_endorsements(trust_dir / "endorsements", {"anchor@test": anchor_pubkey})
        assert endorsements == {}

    @requires_ssh_sign
    def test_tampered_endorsement_skipped(self, tmp_path: Path) -> None:
        """Endorsement whose content was modified after signing is skipped."""
        from mallcop.trust import load_endorsements

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})

        endorse_path = _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "author@test", "author", "*",
        )
        # Tamper with the endorsement file
        endorse_path.write_text("tampered content\n")

        endorsements = load_endorsements(trust_dir / "endorsements", {"anchor@test": anchor_pubkey})
        assert endorsements == {}


# ---------------------------------------------------------------------------
# TrustStore loading
# ---------------------------------------------------------------------------

class TestLoadTrustStore:
    def test_missing_dir_returns_empty_store(self, tmp_path: Path) -> None:
        from mallcop.trust import load_trust_store
        ts = load_trust_store(tmp_path / "nonexistent")
        assert ts.anchors == {}
        assert ts.keyring == {}
        assert ts.endorsements == {}

    @requires_ssh_sign
    def test_loads_full_store(self, tmp_path: Path) -> None:
        from mallcop.trust import load_trust_store

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey})
        _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "author@test", "author", "*",
        )

        ts = load_trust_store(trust_dir)
        assert "anchor@test" in ts.anchors
        assert "anchor@test" in ts.keyring
        assert "anchor@test" in ts.endorsements


# ---------------------------------------------------------------------------
# find_trust_path tests
# ---------------------------------------------------------------------------

class TestFindTrustPath:
    @requires_ssh_sign
    def test_direct_anchor_to_author(self, tmp_path: Path) -> None:
        """Anchor directly endorses author: path = [anchor, author]."""
        from mallcop.trust import find_trust_path, load_trust_store

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey})
        _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "author@test", "author", "*",
        )

        ts = load_trust_store(trust_dir)
        path = find_trust_path(ts, "author@test", "some-skill")
        assert path is not None
        assert path[0] == "anchor@test"
        assert path[-1] == "author@test"

    @requires_ssh_sign
    def test_transitive_anchor_full_author(self, tmp_path: Path) -> None:
        """Anchor → intermediary(full) → author: path length 3."""
        from mallcop.trust import find_trust_path, load_trust_store

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        inter_key, inter_pubkey = _generate_key(tmp_path, "inter", "inter@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey, "inter@test": inter_pubkey})

        # Anchor endorses intermediary as full
        _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "inter@test", "full", "*", filename="anchor.endorse",
        )
        # Intermediary endorses author as author
        _write_endorsement(
            trust_dir, "inter@test", inter_key, inter_pubkey,
            "author@test", "author", "*", filename="inter.endorse",
        )

        ts = load_trust_store(trust_dir)
        path = find_trust_path(ts, "author@test", "some-skill")
        assert path is not None
        assert path == ["anchor@test", "inter@test", "author@test"]

    @requires_ssh_sign
    def test_no_path_returns_none(self, tmp_path: Path) -> None:
        """No endorsements for target → None."""
        from mallcop.trust import find_trust_path, load_trust_store

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey})
        # No endorsement files

        ts = load_trust_store(trust_dir)
        path = find_trust_path(ts, "nobody@test", "some-skill")
        assert path is None

    @requires_ssh_sign
    def test_scope_narrowing(self, tmp_path: Path) -> None:
        """Anchor gives *, intermediary gives aws-*, author cannot sign gcp-* skills."""
        from mallcop.trust import find_trust_path, load_trust_store

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        inter_key, inter_pubkey = _generate_key(tmp_path, "inter", "inter@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey, "inter@test": inter_pubkey})

        _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "inter@test", "full", "*", filename="anchor.endorse",
        )
        # Intermediary endorses author but only for aws-*
        _write_endorsement(
            trust_dir, "inter@test", inter_key, inter_pubkey,
            "author@test", "author", "aws-*", filename="inter.endorse",
        )

        ts = load_trust_store(trust_dir)
        # aws-iam should work
        assert find_trust_path(ts, "author@test", "aws-iam") is not None
        # gcp-iam should not (out of scope)
        assert find_trust_path(ts, "author@test", "gcp-iam") is None

    @requires_ssh_sign
    def test_expired_endorsement_no_path(self, tmp_path: Path) -> None:
        """Expired endorsement is treated as if it doesn't exist."""
        from mallcop.trust import find_trust_path, load_trust_store

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey})
        _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "author@test", "author", "*",
            expires=_past(days=1),
        )

        ts = load_trust_store(trust_dir)
        path = find_trust_path(ts, "author@test", "some-skill")
        assert path is None

    @requires_ssh_sign
    def test_intermediary_author_level_blocks_chain(self, tmp_path: Path) -> None:
        """Intermediary endorsed as 'author' (not 'full') cannot delegate further."""
        from mallcop.trust import find_trust_path, load_trust_store

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        inter_key, inter_pubkey = _generate_key(tmp_path, "inter", "inter@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey, "inter@test": inter_pubkey})

        # Anchor endorses intermediary as 'author' only (NOT 'full')
        _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "inter@test", "author", "*", filename="anchor.endorse",
        )
        # Intermediary endorses the real author — but chain is broken
        _write_endorsement(
            trust_dir, "inter@test", inter_key, inter_pubkey,
            "author@test", "author", "*", filename="inter.endorse",
        )

        ts = load_trust_store(trust_dir)
        # inter@test itself CAN be reached (anchor→inter is author level, that's fine)
        assert find_trust_path(ts, "inter@test", "some-skill") is not None
        # author@test CANNOT be reached through inter (inter has author, not full)
        assert find_trust_path(ts, "author@test", "some-skill") is None

    def test_empty_trust_store_returns_none(self) -> None:
        from mallcop.trust import TrustStore, find_trust_path
        ts = TrustStore(anchors={}, keyring={}, endorsements={})
        assert find_trust_path(ts, "nobody@test", "any-skill") is None


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestTrustCLI:
    @requires_ssh_sign
    def test_add_anchor(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        _, pubkey = _generate_key(tmp_path, "key", "anchor@test")
        pubkey_path = tmp_path / "key.pub"
        trust_dir = tmp_path / ".mallcop" / "trust"

        runner = CliRunner()
        result = runner.invoke(cli, [
            "trust", "--trust-dir", str(trust_dir),
            "add-anchor", "anchor@test", str(pubkey_path),
        ])
        assert result.exit_code == 0, result.output
        anchors_file = trust_dir / "anchors"
        assert anchors_file.exists()
        assert "anchor@test" in anchors_file.read_text()

    @requires_ssh_sign
    def test_add_key(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        _, pubkey = _generate_key(tmp_path, "key", "user@test")
        pubkey_path = tmp_path / "key.pub"
        trust_dir = tmp_path / ".mallcop" / "trust"

        runner = CliRunner()
        result = runner.invoke(cli, [
            "trust", "--trust-dir", str(trust_dir),
            "add-key", "user@test", str(pubkey_path),
        ])
        assert result.exit_code == 0, result.output
        keyring_file = trust_dir / "keyring"
        assert keyring_file.exists()
        assert "user@test" in keyring_file.read_text()

    @requires_ssh_sign
    def test_endorse_creates_files(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        trust_dir = tmp_path / ".mallcop" / "trust"
        trust_dir.mkdir(parents=True)
        (trust_dir / "endorsements").mkdir()
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey})

        runner = CliRunner()
        result = runner.invoke(cli, [
            "trust", "--trust-dir", str(trust_dir),
            "endorse", "author@test",
            "--scope", "*",
            "--level", "author",
            "--expires", "2027-01-01",
            "--reason", "trusted colleague",
            "--key", str(anchor_key),
            "--identity", "anchor@test",
        ])
        assert result.exit_code == 0, result.output
        endorse_files = list((trust_dir / "endorsements").glob("*.endorse"))
        assert len(endorse_files) >= 1
        sig_files = list((trust_dir / "endorsements").glob("*.endorse.sig"))
        assert len(sig_files) >= 1

    @requires_ssh_sign
    def test_trust_chain_shows_path(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey})
        _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "author@test", "author", "*",
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "trust", "--trust-dir", str(trust_dir),
            "chain", "author@test",
            "--skill", "some-skill",
        ])
        assert result.exit_code == 0, result.output
        assert "anchor@test" in result.output
        assert "author@test" in result.output

    @requires_ssh_sign
    def test_trust_chain_no_path(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        trust_dir = _make_trust_dir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, [
            "trust", "--trust-dir", str(trust_dir),
            "chain", "nobody@test",
            "--skill", "some-skill",
        ])
        assert result.exit_code != 0

    @requires_ssh_sign
    def test_trust_list(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from mallcop.cli import cli

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        trust_dir = _make_trust_dir(tmp_path)
        _write_anchors(trust_dir, {"anchor@test": anchor_pubkey})
        _write_keyring(trust_dir, {"anchor@test": anchor_pubkey})
        _write_endorsement(
            trust_dir, "anchor@test", anchor_key, anchor_pubkey,
            "author@test", "author", "*",
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "trust", "--trust-dir", str(trust_dir),
            "list",
        ])
        assert result.exit_code == 0, result.output
        assert "anchor@test" in result.output

    @requires_ssh_sign
    def test_endorse_roundtrip_chain_verifiable(self, tmp_path: Path) -> None:
        """Full CLI roundtrip: add-anchor → endorse → chain verifiable."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        anchor_key, anchor_pubkey = _generate_key(tmp_path, "anchor", "anchor@test")
        pubkey_path = tmp_path / "anchor.pub"
        trust_dir = tmp_path / ".mallcop" / "trust"

        runner = CliRunner()

        # Add anchor
        r = runner.invoke(cli, [
            "trust", "--trust-dir", str(trust_dir),
            "add-anchor", "anchor@test", str(pubkey_path),
        ])
        assert r.exit_code == 0, r.output

        # Endorse author
        r = runner.invoke(cli, [
            "trust", "--trust-dir", str(trust_dir),
            "endorse", "author@test",
            "--scope", "*",
            "--level", "author",
            "--expires", "2027-01-01",
            "--reason", "roundtrip test",
            "--key", str(anchor_key),
            "--identity", "anchor@test",
        ])
        assert r.exit_code == 0, r.output

        # Verify chain
        r = runner.invoke(cli, [
            "trust", "--trust-dir", str(trust_dir),
            "chain", "author@test",
            "--skill", "any-skill",
        ])
        assert r.exit_code == 0, r.output
        assert "author@test" in r.output
