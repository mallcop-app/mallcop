"""Baseline query tools for actor runtime."""

from __future__ import annotations

from typing import Any

from mallcop.tools import ToolContext, tool


@tool(name="check-baseline", description="Check if an actor/entity is in the baseline", permission="read")
def check_baseline(
    context: ToolContext,
    actor: str | None = None,
    entity: str | None = None,
) -> dict[str, Any]:
    """Check if an actor or entity is known in the baseline.

    If actor is provided: check known_entities for actor in "actors" list,
    and gather frequency_table entries keyed by this actor.

    If entity is provided: search all entity type lists for a match.
    """
    baseline = context.store.get_baseline()
    known = baseline.known_entities
    freq = baseline.frequency_tables

    if actor is not None:
        actors_list = known.get("actors", [])
        is_known = actor in actors_list

        # Gather frequency entries for this actor.
        # Matches both 3-part aggregate keys (end with :actor) and action-level keys
        # (contain :actor: in the middle, format: source:event_type:actor:action:target_prefix).
        actor_freq = {
            k: v for k, v in freq.items()
            if k.endswith(f":{actor}") or f":{actor}:" in k
        }

        # Gather relationship data for this actor (keys are "actor:target")
        rels = baseline.relationships
        actor_relationships: dict[str, Any] = {}
        prefix = f"{actor}:"
        for rel_key, rel_data in rels.items():
            if rel_key.startswith(prefix):
                target = rel_key[len(prefix):]
                actor_relationships[target] = rel_data

        # Related actors: other actors sharing the same resource group / parent path
        related_actors: dict[str, int] = _compute_related_actors(actor, rels)

        # Actor context profile if available
        actor_ctx = getattr(baseline, "actor_context", {}) or {}
        profile = actor_ctx.get(actor)

        result: dict[str, Any] = {
            "known": is_known,
            "frequency": actor_freq,
            "relationships": actor_relationships,
            "related_actors": related_actors,
        }
        if profile is not None:
            result["actor_context"] = profile.to_dict()
        return result

    if entity is not None:
        for entity_type, values in known.items():
            if isinstance(values, list) and entity in values:
                return {"known": True, "type": entity_type}
        return {"known": False}

    return {"known": False, "error": "Provide either actor or entity parameter"}


def _compute_related_actors(actor: str, relationships: dict[str, Any]) -> dict[str, int]:
    """Find actors sharing resource group / parent path prefixes with the given actor.

    For each target the actor has accessed, computes a 3-segment prefix
    (e.g. "subscriptions/sub-1/resourceGroups/atom-rg" for Azure paths).
    Then finds other actors who have accessed any target with the same prefix.

    Returns: dict mapping other_actor -> total event count on shared resources.
    """
    # Gather target prefixes for the given actor
    actor_prefixes: set[str] = set()
    actor_prefix = f"{actor}:"
    for rel_key in relationships:
        if rel_key.startswith(actor_prefix):
            target = rel_key[len(actor_prefix):]
            prefix = _target_prefix(target)
            if prefix:
                actor_prefixes.add(prefix)

    if not actor_prefixes:
        return {}

    # Find other actors sharing any of those prefixes
    related: dict[str, int] = {}
    for rel_key, rel_data in relationships.items():
        if ":" not in rel_key:
            continue
        other_actor, target = rel_key.split(":", 1)
        if other_actor == actor:
            continue
        prefix = _target_prefix(target)
        if prefix and prefix in actor_prefixes:
            count = rel_data.get("count", 0) if isinstance(rel_data, dict) else 0
            related[other_actor] = related.get(other_actor, 0) + count

    return related


def _target_prefix(target: str) -> str | None:
    """Compute the parent prefix of a target path (up to 3 segments).

    Examples:
      "subscriptions/sub-1/resourceGroups/atom-rg/vm-1" → "subscriptions/sub-1/resourceGroups/atom-rg"
      "github/org/repo"                                  → "github/org"
      "simple"                                           → None (no useful prefix)
    """
    parts = target.split("/")
    if len(parts) < 2:
        return None
    # Use up to 4 segments for Azure-style paths (sub/rg depth), otherwise 2
    depth = min(4, len(parts) - 1)
    return "/".join(parts[:depth])


@tool(name="baseline-stats", description="Get baseline statistics", permission="read")
def baseline_stats(context: ToolContext) -> dict[str, Any]:
    """Return summary statistics from the baseline.

    Includes total known entities by type, total frequency table entries.
    """
    baseline = context.store.get_baseline()
    known = baseline.known_entities
    freq = baseline.frequency_tables

    entity_counts: dict[str, int] = {}
    for entity_type, values in known.items():
        if isinstance(values, list):
            entity_counts[entity_type] = len(values)

    return {
        "total_frequency_entries": len(freq),
        "known_entities": entity_counts,
    }
