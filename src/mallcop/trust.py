"""Skill signing and verification using SSH signatures.

Also provides TrustStore, Endorsement, find_trust_path, scope_matches,
and supporting load functions for the trust web feature.
"""

from __future__ import annotations

import fnmatch
import hashlib
import shutil
import subprocess
import tempfile
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from mallcop.skills._schema import SkillManifest


_SIGN_NAMESPACE = "mallcop-skill"
_ENDORSE_NAMESPACE = "mallcop-endorsement"


# ---------------------------------------------------------------------------
# Trust web dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Endorsement:
    """A single endorsement of one identity by another."""

    identity: str
    trust_level: str    # "full" | "author"
    scope: str          # glob pattern against skill names
    reason: str
    expires: datetime


@dataclass
class TrustStore:
    """Loaded trust state: anchors, keyring, and endorsements."""

    anchors: dict[str, str]                     # identity → "keytype base64"
    keyring: dict[str, str]                     # identity → "keytype base64"
    endorsements: dict[str, list[Endorsement]]  # endorser_identity → list


# ---------------------------------------------------------------------------
# Scope matching
# ---------------------------------------------------------------------------


def scope_matches(pattern: str, skill_name: str) -> bool:
    """Return True if skill_name matches the glob pattern.

    Uses fnmatch semantics:
      "*"                  matches everything
      "aws-*"              matches "aws-iam", "aws-networking", ...
      "privilege-analysis" matches exactly
    """
    return fnmatch.fnmatch(skill_name, pattern)


# ---------------------------------------------------------------------------
# File format parsers
# ---------------------------------------------------------------------------


def load_anchors(path: Path) -> dict[str, str]:
    """Parse an anchors/keyring file and return {identity: "keytype base64"}.

    File format: one entry per non-blank, non-comment line::

        identity keytype base64

    Missing file returns an empty dict.
    """
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        identity, keytype, b64 = parts[0], parts[1], parts[2]
        result[identity] = f"{keytype} {b64}"
    return result


def load_keyring(path: Path) -> dict[str, str]:
    """Same format as load_anchors.  Missing file returns an empty dict."""
    return load_anchors(path)


def _verify_endorsement_sig(
    endorse_path: Path,
    allowed_signers: dict[str, str],
) -> bool:
    """Verify an endorsement file's .endorse.sig against known signers.

    Returns True if the sig is present, the endorser is in allowed_signers,
    and the signature verifies against the file content.
    Returns False on any failure (missing sig, unknown signer, bad sig).
    """
    ssh_keygen = _find_ssh_keygen()
    if ssh_keygen is None:
        return False

    sig_path = endorse_path.with_suffix(".endorse.sig")
    if not sig_path.exists():
        return False

    # Parse the YAML to find the endorser identity
    try:
        data = yaml.safe_load(endorse_path.read_text())
        endorser = data.get("endorser", "")
    except Exception:
        return False

    if not endorser or endorser not in allowed_signers:
        return False

    pubkey_str = allowed_signers[endorser]
    content = endorse_path.read_bytes()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".allowed_signers", mode="w") as af:
        allowed_path = Path(af.name)
        af.write(f"{endorser} {pubkey_str}\n")

    try:
        result = subprocess.run(
            [
                ssh_keygen, "-Y", "verify",
                "-f", str(allowed_path),
                "-I", endorser,
                "-n", _ENDORSE_NAMESPACE,
                "-s", str(sig_path),
            ],
            input=content,
            capture_output=True,
        )
        return result.returncode == 0
    finally:
        allowed_path.unlink(missing_ok=True)


def load_endorsements(
    endorsements_dir: Path,
    known_pubkeys: dict[str, str],
) -> dict[str, list[Endorsement]]:
    """Load all *.endorse files from endorsements_dir.

    Each file is verified against known_pubkeys (identity → "keytype base64").
    Files that fail signature verification are silently skipped.

    Returns {endorser_identity: [Endorsement, ...]}
    """
    if not endorsements_dir.exists():
        return {}

    result: dict[str, list[Endorsement]] = {}

    for endorse_path in sorted(endorsements_dir.glob("*.endorse")):
        if not _verify_endorsement_sig(endorse_path, known_pubkeys):
            continue

        try:
            data = yaml.safe_load(endorse_path.read_text())
        except Exception:
            continue

        endorser = data.get("endorser", "")
        raw_list: list[dict[str, Any]] = data.get("endorsements", [])

        parsed: list[Endorsement] = []
        for e in raw_list:
            try:
                expires_raw = e["expires"]
                if isinstance(expires_raw, str):
                    expires = datetime.fromisoformat(expires_raw)
                elif isinstance(expires_raw, datetime):
                    expires = expires_raw
                else:
                    continue
                # Ensure timezone-aware
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                parsed.append(Endorsement(
                    identity=e["identity"],
                    trust_level=e["trust_level"],
                    scope=e["scope"],
                    reason=e.get("reason", ""),
                    expires=expires,
                ))
            except (KeyError, ValueError):
                continue

        if parsed and endorser:
            result.setdefault(endorser, []).extend(parsed)

    return result


def load_trust_store(trust_dir: Path) -> TrustStore:
    """Load a complete TrustStore from a .mallcop/trust/ directory layout.

    Missing files/dirs are treated as empty — no exceptions raised.

    Expected layout::

        trust_dir/anchors          — "identity keytype base64" lines
        trust_dir/keyring          — same format, all known keys
        trust_dir/endorsements/    — *.endorse + *.endorse.sig files
    """
    anchors = load_anchors(trust_dir / "anchors")
    keyring = load_keyring(trust_dir / "keyring")

    # Build combined pubkey map for endorsement verification
    all_pubkeys: dict[str, str] = {**keyring, **anchors}

    endorsements = load_endorsements(trust_dir / "endorsements", all_pubkeys)

    return TrustStore(anchors=anchors, keyring=keyring, endorsements=endorsements)


# ---------------------------------------------------------------------------
# BFS trust path finder
# ---------------------------------------------------------------------------


def find_trust_path(
    trust_store: TrustStore,
    target_identity: str,
    skill_name: str,
) -> list[str] | None:
    """Find a trust chain from any anchor to target_identity for skill_name.

    BFS from all anchors.  At each hop:

    * Endorsement must not be expired
    * Endorsement scope must match skill_name via scope_matches()
    * Intermediary nodes (not the target) must have trust_level="full"
    * Terminal (target) node can be "full" or "author"

    Returns path as list of identities ``[anchor, ..., target]``, or None if
    no valid chain exists.
    """
    now = datetime.now(timezone.utc)

    # BFS: each queue item is (current_identity, path_so_far)
    queue: deque[tuple[str, list[str]]] = deque()
    visited: set[str] = set()

    for anchor_identity in trust_store.anchors:
        queue.append((anchor_identity, [anchor_identity]))
        visited.add(anchor_identity)

    while queue:
        current, path = queue.popleft()

        for endorsement in trust_store.endorsements.get(current, []):
            # Expiry check
            if endorsement.expires <= now:
                continue

            # Scope check
            if not scope_matches(endorsement.scope, skill_name):
                continue

            endorsed_id = endorsement.identity

            # If this is the target, we found a path
            if endorsed_id == target_identity:
                return path + [endorsed_id]

            # Intermediary must be "full" to continue the chain
            if endorsement.trust_level != "full":
                continue

            if endorsed_id not in visited:
                visited.add(endorsed_id)
                queue.append((endorsed_id, path + [endorsed_id]))

    return None


def _find_ssh_keygen() -> str | None:
    """Return path to ssh-keygen binary, or None if not found."""
    return shutil.which("ssh-keygen")


def skill_content_for_signing(skill_dir: Path) -> bytes:
    """Build a deterministic content blob for a skill directory.

    Iterates all files under skill_dir in sorted order, skipping
    SKILL.md.sig and any directories. For each file, prepends a header
    line "--- {relative_path} ---\\n" then the raw file contents.

    Returns the concatenated bytes.
    """
    parts: list[bytes] = []
    for path in sorted(skill_dir.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(skill_dir)
        # Skip the signature file itself
        if str(rel) == "SKILL.md.sig":
            continue
        header = f"--- {rel} ---\n".encode()
        parts.append(header)
        parts.append(path.read_bytes())
    return b"".join(parts)


def sign_skill(skill_dir: Path, key_path: Path) -> Path:
    """Sign a skill directory with an SSH key.

    Generates a deterministic content blob, signs it with ssh-keygen -Y sign,
    and places the resulting signature at skill_dir/SKILL.md.sig.

    Returns the path to the signature file.

    Raises RuntimeError if ssh-keygen is not available.
    Raises subprocess.CalledProcessError if signing fails.
    """
    ssh_keygen = _find_ssh_keygen()
    if ssh_keygen is None:
        raise RuntimeError(
            "ssh-keygen not found. Install OpenSSH to use skill signing."
        )

    content = skill_content_for_signing(skill_dir)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".content") as tf:
        content_path = Path(tf.name)
        tf.write(content)

    try:
        subprocess.run(
            [ssh_keygen, "-Y", "sign", "-f", str(key_path), "-n", _SIGN_NAMESPACE, str(content_path)],
            check=True,
            capture_output=True,
        )
        # ssh-keygen writes the sig to {input}.sig
        generated_sig = content_path.with_suffix(".content.sig")
        sig_dest = skill_dir / "SKILL.md.sig"
        generated_sig.rename(sig_dest)
        return sig_dest
    finally:
        content_path.unlink(missing_ok=True)


def verify_skill_signature(skill_dir: Path, pubkey: str, identity: str) -> bool:
    """Verify a skill directory's signature.

    Regenerates the content blob, then verifies it against SKILL.md.sig
    using ssh-keygen -Y verify.

    Args:
        skill_dir: Path to the skill directory.
        pubkey: Full public key string (e.g. "ssh-ed25519 AAAA... comment").
        identity: The identity (email/principal) used when signing.

    Returns True if signature is valid, False otherwise.

    Raises RuntimeError if ssh-keygen is not available.
    """
    ssh_keygen = _find_ssh_keygen()
    if ssh_keygen is None:
        raise RuntimeError(
            "ssh-keygen not found. Install OpenSSH to use skill verification."
        )

    sig_path = skill_dir / "SKILL.md.sig"
    if not sig_path.exists():
        return False

    content = skill_content_for_signing(skill_dir)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".content") as tf:
        content_path = Path(tf.name)
        tf.write(content)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".allowed_signers", mode="w") as af:
        allowed_path = Path(af.name)
        af.write(f"{identity} {pubkey}\n")

    try:
        result = subprocess.run(
            [
                ssh_keygen, "-Y", "verify",
                "-f", str(allowed_path),
                "-I", identity,
                "-n", _SIGN_NAMESPACE,
                "-s", str(sig_path),
            ],
            input=content,
            capture_output=True,
        )
        return result.returncode == 0
    finally:
        content_path.unlink(missing_ok=True)
        allowed_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Lockfile functions
# ---------------------------------------------------------------------------

def _hash_skill(skill_path: Path) -> str:
    """Return SHA-256 hex digest of a skill directory's signing content."""
    content = skill_content_for_signing(skill_path)
    return hashlib.sha256(content).hexdigest()


def generate_lockfile(
    skills: "dict[str, SkillManifest]",
    trust_store: Any = None,
) -> dict:
    """Generate a lockfile dict for the given skills.

    Args:
        skills: Mapping of skill name → SkillManifest.
        trust_store: Optional TrustStore instance. When provided, the trust
            chain for each skill is included. Currently unused (reserved for
            the trust-web bead rw34.2.4).

    Returns:
        A lockfile dict with keys ``version`` and ``skills``.
    """
    skills_dict: dict[str, dict] = {}
    now = datetime.now(timezone.utc).isoformat()

    for name, manifest in skills.items():
        sha256 = _hash_skill(manifest.path)

        trust_chain = None
        if trust_store is not None:
            # Reserved: rw34.2.4 will populate this via trust_store.chain_for(name)
            pass

        skills_dict[name] = {
            "source": "builtin",
            "sha256": sha256,
            "author": manifest.author,
            "trust_chain": trust_chain,
            "verified_at": now,
            "expires": None,
        }

    return {"version": 1, "skills": skills_dict}


def write_lockfile(lockfile: dict, path: Path) -> None:
    """Write a lockfile dict to *path* as canonical YAML (sort_keys=True)."""
    path.write_text(yaml.dump(lockfile, sort_keys=True, default_flow_style=False))


def load_lockfile(path: Path) -> dict:
    """Load a skills.lock file and return the skills dict.

    Returns an empty dict if the file does not exist.
    """
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        return {}
    return data.get("skills", {})


def check_lockfile_hash(skill_name: str, skill_path: Path, lockfile: dict) -> bool:
    """Check whether *skill_path* matches its recorded hash in *lockfile*.

    Args:
        skill_name: The name key in the lockfile skills dict.
        skill_path: Path to the skill directory.
        lockfile: The skills dict returned by ``load_lockfile``.

    Returns:
        True if the computed SHA-256 matches the stored hash.
        False if the skill is not in the lockfile or the hash differs.
    """
    entry = lockfile.get(skill_name)
    if entry is None:
        return False
    stored = entry.get("sha256")
    if not stored:
        return False
    computed = _hash_skill(skill_path)
    return computed == stored
