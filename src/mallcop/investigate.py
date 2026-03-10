"""Investigate command logic: deep context for a single finding."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mallcop.actors.actor_selection import select_entry_actor
from mallcop.config import RouteConfig, load_config
from mallcop.review import _find_post_md
from mallcop.schemas import Finding
from mallcop.store import JsonlStore


def _determine_actor_for_finding(
    finding: Finding,
    routing: dict[str, RouteConfig | str | None],
    actor_chain: dict[str, dict[str, Any]],
) -> str | None:
    """Determine which actor's POST.md to load based on finding state.

    - Untriaged (no triage annotation) -> entry actor from routing
    - Triaged (has annotation from entry actor) -> next actor in chain (routes_to)
    """
    return select_entry_actor(
        routing=routing,
        severity=finding.severity.value,
        annotations=finding.annotations,
        actor_chain=actor_chain,
    )


def run_investigate(root: Path, finding_id: str) -> dict[str, Any]:
    """Load full context for a specific finding.

    Returns structured dict with finding, events, baseline, actor history, POST.md.
    """
    config = load_config(root)
    store = JsonlStore(root)

    # Find the specific finding
    all_findings = store.query_findings()
    target_finding: Finding | None = None
    for f in all_findings:
        if f.id == finding_id:
            target_finding = f
            break

    if target_finding is None:
        return {
            "command": "investigate",
            "status": "error",
            "error": f"Finding {finding_id} not found",
        }

    # Load triggering events
    all_events = store.query_events()
    triggering_events = [
        e for e in all_events if e.id in target_finding.event_ids
    ]

    # Determine involved actors from triggering events
    involved_actors = {e.actor for e in triggering_events}

    # Load actor history (all events from involved actors)
    actor_history: dict[str, list[dict[str, Any]]] = {}
    for actor in involved_actors:
        actor_events = [e for e in all_events if e.actor == actor]
        actor_history[actor] = [e.to_dict() for e in actor_events]

    # Load baseline for involved actors
    baseline = store.get_baseline()
    baseline_actors: dict[str, dict[str, Any]] = {}
    for actor in involved_actors:
        actor_baseline: dict[str, Any] = {
            "known": actor in baseline.known_entities.get("actors", []),
            "frequency_entries": {
                k: v
                for k, v in baseline.frequency_tables.items()
                if actor in k
            },
            "relationships": {
                k[len(f"{actor}:"):]: v for k, v in baseline.relationships.items()
                if k.startswith(f"{actor}:")
            },
        }
        baseline_actors[actor] = actor_baseline

    # Select POST.md based on finding state
    actor_name = _determine_actor_for_finding(
        target_finding, config.routing, config.actor_chain
    )

    post_md: str | None = None
    post_md_source: str | None = None
    if actor_name is not None:
        post_md = _find_post_md(actor_name, root)
        if post_md is not None:
            post_md_source = actor_name

    return {
        "command": "investigate",
        "status": "ok",
        "finding": target_finding.to_dict(),
        "events": [e.to_dict() for e in triggering_events],
        "actor_history": actor_history,
        "baseline": {
            "actors": baseline_actors,
        },
        "post_md": post_md,
        "post_md_source": post_md_source,
    }
