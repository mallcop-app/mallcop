"""OpenClaw skill parsing: SKILL.md frontmatter extraction and content hashing."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SkillInfo:
    """Parsed skill metadata from SKILL.md frontmatter."""

    name: str
    description: str
    version: str
    author: str
    path: Path
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


def parse_skill_md(path: Path) -> SkillInfo:
    """Parse a SKILL.md file, extracting YAML frontmatter and full content.

    Frontmatter is expected between --- markers at the top of the file.
    Fields: name, description, version, author, plus any additional metadata.
    If no frontmatter is present, returns a SkillInfo with empty/default fields.
    """
    content = path.read_text(encoding="utf-8")

    frontmatter: dict[str, Any] = {}
    if content.startswith("---"):
        # Find the closing --- marker
        lines = content.split("\n")
        end_idx = None
        for i, line in enumerate(lines[1:], start=1):
            if line.strip() == "---":
                end_idx = i
                break
        if end_idx is not None:
            fm_text = "\n".join(lines[1:end_idx])
            try:
                parsed = yaml.safe_load(fm_text)
                if isinstance(parsed, dict):
                    frontmatter = parsed
            except yaml.YAMLError:
                pass

    return SkillInfo(
        name=frontmatter.get("name", path.parent.name),
        description=frontmatter.get("description", ""),
        version=str(frontmatter.get("version", "0.0.0")),
        author=frontmatter.get("author", ""),
        path=path,
        content=content,
        metadata={
            k: v
            for k, v in frontmatter.items()
            if k not in ("name", "description", "version", "author")
        },
    )


def hash_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file's contents."""
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    return h


def enumerate_skills(skills_dir: Path) -> dict[str, Path]:
    """Enumerate skill directories under skills_dir.

    Returns mapping of skill_name -> SKILL.md path for each valid skill dir.
    A valid skill dir is a direct child directory containing a SKILL.md file.
    """
    result: dict[str, Path] = {}
    if not skills_dir.exists() or not skills_dir.is_dir():
        return result

    for entry in skills_dir.iterdir():
        if not entry.is_dir():
            continue
        skill_md = entry / "SKILL.md"
        if skill_md.exists():
            result[entry.name] = skill_md

    return result
