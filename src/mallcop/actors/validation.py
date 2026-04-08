"""Escalation path validation: validate routing chains reach channel actors."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from mallcop.actors._schema import ActorManifest, load_actor_manifest
from mallcop.actors.channels import _resolve_channel_config

_log = logging.getLogger(__name__)


class EscalationPathError(Exception):
    """Raised when the actor chain has no valid delivery path."""


def _validate_channel_config(
    current: str,
    channel_manifests: dict[str, tuple[ActorManifest, Path]],
    config: Any,
    severity: str,
    entry_actor: str,
) -> list[str]:
    """Validate a channel actor's config. Returns list of errors.

    For webhook-based channels (slack, teams): validates webhook_url is present and HTTP.
    For structured-config channels (email): validates required fields are present.
    """
    errors: list[str] = []
    ch_manifest, _ = channel_manifests[current]
    try:
        resolved = _resolve_channel_config(ch_manifest, config)
    except ValueError as exc:
        env_msg = str(exc)
        # Map to user-friendly error messages
        if "not set" in env_msg:
            # Unset env var -> "not configured"
            errors.append(
                f"Routing '{severity}' \u2192 '{entry_actor}' \u2192 ... \u2192 "
                f"channel '{current}': webhook_url not configured "
                f"({env_msg})"
            )
        elif "HTTPS required" in env_msg or "private" in env_msg.lower():
            errors.append(
                f"Routing '{severity}' \u2192 '{entry_actor}' \u2192 ... \u2192 "
                f"channel '{current}': webhook_url is not a valid URL "
                f"({env_msg})"
            )
        else:
            errors.append(
                f"Routing '{severity}' \u2192 '{entry_actor}' \u2192 ... \u2192 "
                f"channel '{current}': {env_msg}"
            )
        return errors

    if "webhook_url" in (ch_manifest.config or {}):
        # Webhook-based channel: validate URL
        webhook_url = resolved.get("webhook_url", "")
        if not webhook_url or (isinstance(webhook_url, str) and webhook_url.startswith("${")):
            errors.append(
                f"Routing '{severity}' \u2192 '{entry_actor}' \u2192 ... \u2192 "
                f"channel '{current}': webhook_url not configured "
                f"(got '{webhook_url}')"
            )
        elif isinstance(webhook_url, str) and not webhook_url.startswith("http"):
            errors.append(
                f"Routing '{severity}' \u2192 '{entry_actor}' \u2192 ... \u2192 "
                f"channel '{current}': webhook_url is not a valid URL "
                f"(got '{webhook_url}')"
            )
    else:
        # Structured-config channel (e.g., email): validate required fields
        required = ["smtp_host", "from_addr", "to_addrs"]
        for field_name in required:
            val = resolved.get(field_name, "")
            if not val or (isinstance(val, str) and val.startswith("${")):
                errors.append(
                    f"Routing '{severity}' \u2192 '{entry_actor}' \u2192 ... \u2192 "
                    f"channel '{current}': {field_name} not configured "
                    f"(got '{val}')"
                )

    return errors


def validate_escalation_paths(
    routing: dict[str, Any],
    manifests: dict[str, tuple[ActorManifest, Path]],
    channel_manifests: dict[str, tuple[ActorManifest, Path]],
    config: Any = None,
) -> list[str]:
    """Validate that every routing entry terminates at a reachable channel actor.

    Accepts both old-format routing (str values) and new-format (RouteConfig).
    Returns a list of error strings. Empty list means all paths are valid.
    """
    errors: list[str] = []

    for severity, route_value in routing.items():
        if route_value is None:
            continue  # severity not routed -- that's fine

        # Normalize: extract entry_actor and notify list from either format
        from mallcop.config import RouteConfig
        if isinstance(route_value, RouteConfig):
            if not route_value.chain:
                continue
            entry_actor = route_value.chain[0]
            notify_actors = route_value.notify
        elif isinstance(route_value, str):
            # Old format passed directly (e.g., from tests)
            entry_actor = route_value
            notify_actors = []
        else:
            continue

        # Walk the chain from entry_actor to terminal
        visited: set[str] = set()
        current: str | None = entry_actor
        reached_channel = False

        while current is not None:
            if current in visited:
                errors.append(
                    f"Routing '{severity}' \u2192 '{entry_actor}': "
                    f"cycle detected at '{current}'"
                )
                break
            visited.add(current)

            if current in channel_manifests:
                errors.extend(_validate_channel_config(
                    current, channel_manifests, config, severity, entry_actor,
                ))
                reached_channel = True
                break

            if current in manifests:
                # actor_chain config overrides manifest routes_to
                actor_chain = getattr(config, "actor_chain", {}) or {}
                chain_override = actor_chain.get(current, {})
                if "routes_to" in chain_override:
                    current = chain_override["routes_to"]
                else:
                    manifest, _ = manifests[current]
                    current = manifest.routes_to
            else:
                errors.append(
                    f"Routing '{severity}' \u2192 '{entry_actor}': "
                    f"actor '{current}' not found"
                )
                break
        else:
            if not reached_channel:
                errors.append(
                    f"Routing '{severity}' \u2192 '{entry_actor}': "
                    f"chain ends without reaching a channel actor"
                )

        # Validate notify actors exist as channel actors
        for notify_name in notify_actors:
            if notify_name not in channel_manifests:
                errors.append(
                    f"Routing '{severity}': notify actor '{notify_name}' not found "
                    f"in channel manifests"
                )
            else:
                errors.extend(_validate_channel_config(
                    notify_name, channel_manifests, config, severity, entry_actor,
                ))

    return errors


def check_escalation_health(config: Any) -> list[str]:
    """Lightweight check: discover actor manifests and validate escalation paths.

    Returns a list of error strings. Empty list means all paths are valid.
    Does not require LLM or store -- just reads manifests and config.
    """
    actors_pkg_dir = Path(__file__).parent
    actor_dirs = [
        d for d in actors_pkg_dir.iterdir()
        if d.is_dir() and not d.name.startswith("_") and (d / "manifest.yaml").exists()
    ]

    manifests: dict[str, tuple[ActorManifest, Path]] = {}
    channel_manifests: dict[str, tuple[ActorManifest, Path]] = {}
    for actor_dir in actor_dirs:
        try:
            manifest = load_actor_manifest(actor_dir)
            if manifest.type == "agent":
                manifests[manifest.name] = (manifest, actor_dir)
            elif manifest.type == "channel":
                channel_manifests[manifest.name] = (manifest, actor_dir)
        except ValueError:
            continue

    if not manifests and not channel_manifests:
        return []  # No actors configured -- nothing to validate

    routing = getattr(config, "routing", {}) or {}
    if not routing:
        return []  # No routing configured

    return validate_escalation_paths(routing, manifests, channel_manifests, config)
