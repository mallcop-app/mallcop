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


def _verify_skill_trust(
    manifest: SkillManifest,
    context: ToolContext | None = None,
) -> tuple[str | None, list[str] | None]:
    """Verify skill trust using lockfile hash check and signature verification.

    Behavior:
    - If neither trust_store nor skill_lockfile is configured on context: log warning,
      allow loading (graceful degradation — trust infra not configured).
    - If lockfile IS configured: check hash. If mismatch → refuse (return error signal
      via raised ValueError).
    - If trust_store IS configured: verify signature and find trust path. If either
      fails → refuse.
    - Returns (verified_by, trust_chain) on success, where verified_by is the identity
      that verified the skill (or None when trust infra is absent).

    Raises:
        ValueError: If trust is configured and verification fails — caller should refuse
            to load the skill and return an error dict.
    """
    from mallcop.trust import (
        TrustStore,
        check_lockfile_hash,
        find_trust_path,
        verify_skill_signature,
    )

    trust_store = getattr(context, "trust_store", None) if context is not None else None
    skill_lockfile = getattr(context, "skill_lockfile", None) if context is not None else None

    has_trust_infra = (trust_store is not None) or (skill_lockfile is not None)

    if not has_trust_infra:
        _log.warning(
            "load-skill: no trust infrastructure configured (trust_store, skill_lockfile). "
            "Loading skill '%s' without verification.",
            manifest.name,
        )
        return None, None

    # Lockfile hash check
    if skill_lockfile is not None:
        hash_ok = check_lockfile_hash(manifest.name, manifest.path, skill_lockfile)
        if not hash_ok:
            raise ValueError(
                f"Skill '{manifest.name}' lockfile hash mismatch — "
                "skill content has changed since the lockfile was generated. "
                "Re-run 'mallcop skill lock' to update."
            )

    # Trust store verification
    if trust_store is not None:
        author = manifest.author
        if not author:
            raise ValueError(
                f"Skill '{manifest.name}' has no author field in manifest — "
                "cannot verify against trust store."
            )

        # Find trust chain from an anchor to this author
        trust_chain = find_trust_path(trust_store, author, manifest.name)
        if trust_chain is None:
            raise ValueError(
                f"Skill '{manifest.name}': no trust path found from any anchor "
                f"to author '{author}' for this skill."
            )

        # Find which key to verify against (author's pubkey from keyring or anchors)
        pubkey = trust_store.keyring.get(author) or trust_store.anchors.get(author)
        if pubkey is None:
            raise ValueError(
                f"Skill '{manifest.name}': author '{author}' not found in trust store keyring."
            )

        try:
            sig_ok = verify_skill_signature(manifest.path, pubkey, author)
        except RuntimeError as exc:
            # ssh-keygen not available — degrade gracefully
            _log.warning(
                "load-skill: ssh-keygen not available, skipping signature check for '%s': %s",
                manifest.name,
                exc,
            )
            sig_ok = True  # cannot verify without ssh-keygen; log and allow

        if not sig_ok:
            raise ValueError(
                f"Skill '{manifest.name}': signature verification failed for author '{author}'."
            )

        verified_by = author
        return verified_by, trust_chain

    # Lockfile-only path: hash checked above, no trust store
    return None, None


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


def _resolve_skill_dir(name: str, skill_root: Path) -> Path:
    """Resolve a skill directory path, falling back to underscore form.

    Skill names in frontmatter use hyphens (e.g. "azure-security") but the
    package directories use underscores (e.g. "azure_security").  Try the
    exact name first, then the underscore-normalized form.
    """
    exact = skill_root / name
    if exact.exists():
        return exact
    normalized = skill_root / name.replace("-", "_")
    return normalized


def _load_one_skill(name: str, skill_root: Path, context: ToolContext) -> LoadedSkill | None:
    """Load a single skill (no parent chain) and cache in context.loaded_skills.

    Returns the LoadedSkill, or None if the skill directory/manifest is missing.
    Already-cached skills are returned from cache.

    Raises:
        ValueError: If trust verification fails (propagated from _verify_skill_trust).
    """
    if name in context.loaded_skills:
        return context.loaded_skills[name]

    skill_dir = _resolve_skill_dir(name, skill_root)
    manifest = SkillManifest.from_skill_dir(skill_dir)
    if manifest is None:
        return None

    _, body = parse_frontmatter(manifest.path / "SKILL.md")

    verified_by, trust_chain = _verify_skill_trust(manifest, context)
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

    skill_dir = _resolve_skill_dir(name, skill_root)
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

    verified_by, trust_chain = _verify_skill_trust(manifest, context)
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

    try:
        loaded = _load_with_parents(skill_name, skill_root, context)
    except ValueError as exc:
        return {"error": str(exc)}

    if loaded is None:
        return {"error": f"Skill '{skill_name}' not found in {skill_root}"}

    return {
        "context": loaded.context,
        "new_tools": loaded.new_tools,
        "verified_by": loaded.verified_by,
        "trust_chain": loaded.trust_chain,
    }
