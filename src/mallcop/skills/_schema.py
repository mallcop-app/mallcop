"""SkillManifest dataclass and SKILL.md frontmatter parser."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def parse_frontmatter(skill_md: Path) -> tuple[dict[str, Any], str]:
    """Parse YAML frontmatter from a SKILL.md file.

    Returns (frontmatter_dict, body_text). If no valid frontmatter is found,
    returns ({}, full_content).
    """
    try:
        content = skill_md.read_text(encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not read %s: %s", skill_md, exc)
        return {}, ""

    if not content.startswith("---"):
        return {}, content

    # Find closing delimiter (must be on its own line after the opening)
    rest = content[3:]
    # Strip optional newline after opening ---
    if rest.startswith("\n"):
        rest = rest[1:]

    closing = rest.find("\n---")
    if closing == -1:
        return {}, content

    fm_text = rest[:closing]
    body = rest[closing + 4:]  # skip \n---
    # Strip leading newline from body if present
    if body.startswith("\n"):
        body = body[1:]

    try:
        fm = yaml.safe_load(fm_text)
    except yaml.YAMLError as exc:
        logger.warning("Malformed YAML frontmatter in %s: %s", skill_md, exc)
        return {}, content

    if not isinstance(fm, dict):
        return {}, content

    return fm, body


@dataclass
class SkillManifest:
    """Parsed manifest from a skill's SKILL.md frontmatter."""

    name: str
    description: str
    parent: str | None
    tools: str | None
    author: str | None
    version: str | None
    path: Path

    @classmethod
    def from_skill_dir(cls, skill_dir: Path) -> SkillManifest | None:
        """Load a SkillManifest from a skill directory.

        Returns None and logs a warning if SKILL.md is missing, malformed,
        or missing required fields (name, description).
        """
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            logger.debug("No SKILL.md in %s — skipping", skill_dir)
            return None

        fm, _ = parse_frontmatter(skill_md)
        if not fm:
            logger.warning("Could not parse frontmatter in %s — skipping", skill_md)
            return None

        name = fm.get("name", "")
        description = fm.get("description", "")
        if not name:
            logger.warning("Missing 'name' in frontmatter of %s — skipping", skill_md)
            return None
        if not description:
            logger.warning(
                "Missing 'description' in frontmatter of %s — skipping", skill_md
            )
            return None

        return cls(
            name=str(name),
            description=str(description),
            parent=fm.get("parent") or None,
            tools=fm.get("tools") or None,
            author=fm.get("author") or None,
            version=fm.get("version") or None,
            path=skill_dir,
        )
