"""load-skill tool — loads a skill's context into the actor runtime."""

from __future__ import annotations

import importlib.util
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mallcop.skills._schema import SkillManifest, parse_frontmatter
from mallcop.tools import ToolContext, tool

_log = logging.getLogger(__name__)


@dataclass
class LoadedSkill:
    """Cached result of a loaded skill."""

    name: str
    context: str  # concatenated parent + child body text
    new_tools: list[str]
    verified_by: str | None
    trust_chain: list[str] | None


def _verify_skill_trust(manifest: SkillManifest) -> tuple[str | None, list[str] | None]:
    """Verify skill trust. Stub: always trusted. Trust bead wires real logic later."""
    return None, None  # (verified_by, trust_chain)


def _load_skill_tools(manifest: SkillManifest, context: ToolContext) -> list[str]:
    """Register skill tools from tools.py into context.tool_registry.

    Returns list of newly registered tool names.
    """
    if manifest.tools is None:
        return []

    tools_path = manifest.path / manifest.tools
    if not tools_path.exists():
        _log.debug("Skill '%s' declares tools file '%s' but it doesn't exist", manifest.name, tools_path)
        return []

    if context.tool_registry is None:
        _log.debug("No tool_registry on context — cannot register skill tools for '%s'", manifest.name)
        return []

    try:
        spec = importlib.util.spec_from_file_location(
            f"mallcop_skill_tools.{manifest.name}", tools_path
        )
        if spec is None or spec.loader is None:
            return []
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception as exc:
        _log.warning("Failed to import skill tools from %s: %s", tools_path, exc)
        return []

    new_tools: list[str] = []
    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if callable(obj) and hasattr(obj, "_tool_meta"):
            registered = context.tool_registry.register_if_new(obj)
            if registered:
                new_tools.append(obj._tool_meta.name)

    return new_tools


def _load_one_skill(name: str, skill_root: Path, context: ToolContext) -> LoadedSkill | None:
    """Load a single skill (no parent chain) and cache in context.loaded_skills.

    Returns the LoadedSkill, or None if the skill directory/manifest is missing.
    Already-cached skills are returned from cache.
    """
    if name in context.loaded_skills:
        return context.loaded_skills[name]

    skill_dir = skill_root / name
    manifest = SkillManifest.from_skill_dir(skill_dir)
    if manifest is None:
        return None

    _, body = parse_frontmatter(manifest.path / "SKILL.md")

    verified_by, trust_chain = _verify_skill_trust(manifest)
    new_tools = _load_skill_tools(manifest, context)

    loaded = LoadedSkill(
        name=name,
        context=body,
        new_tools=new_tools,
        verified_by=verified_by,
        trust_chain=trust_chain,
    )
    context.loaded_skills[name] = loaded
    return loaded


def _load_with_parents(name: str, skill_root: Path, context: ToolContext) -> LoadedSkill | None:
    """Load a skill and its full parent chain, concatenating context parent-first.

    Returns a LoadedSkill whose context is parent_context + child_context.
    The individual loaded skills are cached in context.loaded_skills.
    """
    # Check cache first (already includes parent chain from previous load)
    if name in context.loaded_skills:
        return context.loaded_skills[name]

    skill_dir = skill_root / name
    manifest = SkillManifest.from_skill_dir(skill_dir)
    if manifest is None:
        return None

    # Load parent chain first (recurse)
    parent_context = ""
    parent_new_tools: list[str] = []
    if manifest.parent:
        parent_loaded = _load_with_parents(manifest.parent, skill_root, context)
        if parent_loaded is not None:
            parent_context = parent_loaded.context
            parent_new_tools = list(parent_loaded.new_tools)

    # Load this skill's own content
    _, body = parse_frontmatter(manifest.path / "SKILL.md")

    verified_by, trust_chain = _verify_skill_trust(manifest)
    own_new_tools = _load_skill_tools(manifest, context)

    # Combine: parent context first, then child
    combined_context = (parent_context + "\n" + body).lstrip("\n") if parent_context else body

    loaded = LoadedSkill(
        name=name,
        context=combined_context,
        new_tools=parent_new_tools + own_new_tools,
        verified_by=verified_by,
        trust_chain=trust_chain,
    )
    context.loaded_skills[name] = loaded
    return loaded


@tool(name="load-skill", description="Load a skill by name, returning its context and registering any skill tools", permission="read")
def load_skill(
    context: ToolContext,
    skill_name: str,
) -> dict[str, Any]:
    """Load a skill's context into the actor runtime.

    Reads the skill's SKILL.md body, auto-loads parent chain, registers
    skill tools into the tool registry, and caches the result for idempotency.

    Args:
        skill_name: Name of the skill to load (directory name under skill_root).

    Returns:
        {
            context: str — skill body text (parent + child, parent-first),
            new_tools: list[str] — tool names registered this call,
            verified_by: str|None — trust verification source,
            trust_chain: list|None — trust chain if applicable,
        }
        or {error: str} on failure.
    """
    skill_root = getattr(context, "skill_root", None)
    if skill_root is None:
        return {"error": "No skill_root configured on ToolContext"}

    skill_root = Path(skill_root)

    loaded = _load_with_parents(skill_name, skill_root, context)
    if loaded is None:
        return {"error": f"Skill '{skill_name}' not found in {skill_root}"}

    return {
        "context": loaded.context,
        "new_tools": loaded.new_tools,
        "verified_by": loaded.verified_by,
        "trust_chain": loaded.trust_chain,
    }
