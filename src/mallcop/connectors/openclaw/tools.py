"""OpenClaw connector-specific tools: list-skills, read-skill, check-config."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mallcop.connectors.openclaw.skills import enumerate_skills, parse_skill_md

# Patterns for redacting secrets from config output
_SECRET_PATTERNS = [
    re.compile(r"(sk-[a-zA-Z0-9]{20,})"),
    re.compile(r"(AKIA[A-Z0-9]{16})"),
    re.compile(r"(ghp_[a-zA-Z0-9]{36})"),
    re.compile(r'"([a-zA-Z_]*(?:key|token|secret|password|credential)[a-zA-Z_]*)"\s*:\s*"([^"]{8,})"', re.IGNORECASE),
]


def _redact_secrets(text: str) -> str:
    """Redact known secret patterns from a string."""
    result = text
    # Redact bare secret values (API key patterns)
    for pattern in _SECRET_PATTERNS[:3]:
        result = pattern.sub("[REDACTED]", result)
    # Redact JSON key-value pairs where key suggests a secret
    result = re.sub(
        r'("(?:[a-zA-Z_]*(?:key|token|secret|password|credential)[a-zA-Z_]*)")\s*:\s*"([^"]{4,})"',
        r'\1: "[REDACTED]"',
        result,
        flags=re.IGNORECASE,
    )
    return result


def list_skills(openclaw_home: Path) -> list[dict[str, Any]]:
    """List all installed skills with name, description, version, path."""
    skills_dir = openclaw_home / "skills"
    skill_map = enumerate_skills(skills_dir)

    result = []
    for skill_name, skill_md_path in sorted(skill_map.items()):
        info = parse_skill_md(skill_md_path)
        result.append({
            "name": info.name,
            "description": info.description,
            "version": info.version,
            "author": info.author,
            "path": str(skill_md_path),
        })
    return result


def read_skill(openclaw_home: Path, skill_name: str) -> dict[str, Any] | None:
    """Read a specific skill's SKILL.md content by name."""
    skills_dir = openclaw_home / "skills"
    skill_md_path = skills_dir / skill_name / "SKILL.md"

    if not skill_md_path.exists():
        return None

    info = parse_skill_md(skill_md_path)
    return {
        "name": info.name,
        "description": info.description,
        "version": info.version,
        "author": info.author,
        "path": str(skill_md_path),
        "content": info.content,
        "metadata": info.metadata,
    }


def check_config(openclaw_home: Path) -> dict[str, Any]:
    """Read OpenClaw gateway configuration with secrets redacted."""
    config_path = openclaw_home / "openclaw.json"

    if not config_path.exists():
        return {"error": "openclaw.json not found", "path": str(config_path)}

    raw_text = config_path.read_text(encoding="utf-8")
    redacted_text = _redact_secrets(raw_text)

    try:
        config = json.loads(redacted_text)
    except json.JSONDecodeError as exc:
        return {"error": f"Failed to parse openclaw.json: {exc}"}

    return {"config": config, "path": str(config_path)}
