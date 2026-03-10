"""Shared actor selection logic for review and investigate commands."""

from __future__ import annotations

import logging
from typing import Any

from mallcop.config import RouteConfig

logger = logging.getLogger(__name__)


def _extract_entry_actor(route: Any) -> str | None:
    """Extract the entry actor name from a route config value.

    Handles both RouteConfig objects (new format) and plain strings (old format).
    """
    if route is None:
        return None
    if isinstance(route, RouteConfig):
        return route.chain[0] if route.chain else None
    if isinstance(route, str):
        return route
    return None


def select_entry_actor(
    routing: dict[str, RouteConfig | str | None],
    severity: str,
    annotations: list[dict[str, Any]] | None = None,
    actor_chain: dict[str, dict[str, Any]] | None = None,
) -> str | None:
    """Select the appropriate actor for a finding based on routing and annotation state.

    Args:
        routing: Severity -> RouteConfig or actor name string mapping.
        severity: The severity level to look up (e.g. "critical", "warn", "info").
        annotations: List of annotation dicts with at least an "actor" key.
            Also accepts objects with an ``actor`` attribute (e.g. Annotation dataclass).
            If None or empty, the finding is treated as untriaged.
        actor_chain: Actor name -> manifest dict with optional "routes_to" key.

    Returns:
        Actor name string, or None if no route is configured.

    Logic:
        1. Look up entry actor for the given severity from routing.
        2. If annotations show the entry actor has already acted, follow
           actor_chain to the next actor (routes_to).
        3. Otherwise return the entry actor.
    """
    if actor_chain is None:
        actor_chain = {}
    if annotations is None:
        annotations = []

    entry_actor = _extract_entry_actor(routing.get(severity))
    if entry_actor is None:
        return None

    # Check if the entry actor has already annotated this finding.
    # Support both dict annotations (from to_dict()) and Annotation objects.
    def _ann_actor(ann: Any) -> str | None:
        if isinstance(ann, dict):
            return ann.get("actor")
        return getattr(ann, "actor", None)

    has_annotation = any(
        _ann_actor(ann) == entry_actor for ann in annotations
    )

    if has_annotation:
        # Follow actor chain to next actor
        chain_entry = actor_chain.get(entry_actor, {})
        next_actor = chain_entry.get("routes_to")
        if next_actor is not None:
            if next_actor not in actor_chain:
                logger.warning(
                    "Actor '%s' routes_to '%s' which is not found in actor_chain",
                    entry_actor, next_actor,
                )
            return next_actor

    return entry_actor
