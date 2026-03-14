"""Skill signing and verification using SSH signatures."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


_SIGN_NAMESPACE = "mallcop-skill"


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
