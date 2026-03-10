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

        # Gather frequency entries for this actor
        actor_freq = {
            k: v for k, v in freq.items() if k.endswith(f":{actor}")
        }

        # Gather relationship data for this actor (keys are "actor:target")
        rels = baseline.relationships
        actor_relationships: dict[str, Any] = {}
        prefix = f"{actor}:"
        for rel_key, rel_data in rels.items():
            if rel_key.startswith(prefix):
                target = rel_key[len(prefix):]
                actor_relationships[target] = rel_data

        result: dict[str, Any] = {
            "known": is_known,
            "frequency": actor_freq,
            "relationships": actor_relationships,
        }
        return result

    if entity is not None:
        for entity_type, values in known.items():
            if isinstance(values, list) and entity in values:
                return {"known": True, "type": entity_type}
        return {"known": False}

    return {"known": False, "error": "Provide either actor or entity parameter"}


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
