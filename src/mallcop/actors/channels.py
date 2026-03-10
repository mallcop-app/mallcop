"""Channel delivery: loading channel modules, resolving config, delivering digests."""

from __future__ import annotations

import importlib
import importlib.util
import ipaddress
import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mallcop.actors._schema import ActorManifest, ActorResolution, ResolutionAction
from mallcop.schemas import Finding

_log = logging.getLogger(__name__)


_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

_BLOCKED_HOSTNAMES = {"localhost"}


def _validate_webhook_url(url: str) -> None:
    """Validate webhook URL: must be HTTPS, must not target private/reserved IPs."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"HTTPS required for webhook URL, got {parsed.scheme!r}")

    hostname = parsed.hostname or ""

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(f"Webhook URL points to private/reserved address: {hostname}")

    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        # Not an IP literal — hostname is allowed (DNS resolution checked at delivery time)
        return

    for network in _BLOCKED_NETWORKS:
        if addr in network:
            raise ValueError(
                f"Webhook URL points to private/reserved address: {hostname}"
            )


def _resolve_channel_config(
    manifest: ActorManifest,
    runtime_config: Any = None,
) -> dict[str, Any]:
    """Resolve channel actor config from runtime config + manifest defaults.

    Runtime config.actors[name] overrides manifest.config values.
    Returns a flat dict of resolved config fields.
    """
    # Start with manifest defaults
    resolved: dict[str, Any] = dict(manifest.config or {})

    # Override with runtime config.actors[name]
    actors_cfg = getattr(runtime_config, "actors", None) or {}
    actor_cfg = actors_cfg.get(manifest.name, {})
    if isinstance(actor_cfg, dict):
        for key, value in actor_cfg.items():
            if value:  # Only override with non-empty values
                resolved[key] = value

    # Resolve ${VAR} references from environment
    for key, value in list(resolved.items()):
        if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
            var_name = value[2:-1]
            env_val = os.environ.get(var_name, "")
            if not env_val:
                raise ValueError(f"Environment variable {var_name} is not set")
            resolved[key] = env_val

    # Validate webhook_url after resolution
    if "webhook_url" in resolved and isinstance(resolved["webhook_url"], str):
        _validate_webhook_url(resolved["webhook_url"])

    return resolved


def _load_channel_module(actor_dir: Path) -> Any:
    """Load the channel.py module from an actor directory."""
    package_root = Path(__file__).parent.parent  # src/mallcop
    try:
        rel = actor_dir.relative_to(package_root)
        dotted = "mallcop." + ".".join(rel.parts) + ".channel"
        return importlib.import_module(dotted)
    except (ValueError, ModuleNotFoundError):
        # External plugin: load from file
        channel_path = actor_dir / "channel.py"
        if not channel_path.exists():
            return None
        spec = importlib.util.spec_from_file_location(
            f"mallcop_channel_{actor_dir.name}", channel_path
        )
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def _call_deliver_digest(
    mod: Any,
    findings: list[Finding],
    config: dict[str, Any],
) -> Any:
    """Call deliver_digest with the right signature based on config shape.

    Webhook-based channels (slack, teams): deliver_digest(findings, webhook_url)
    Structured-config channels (email): deliver_digest(findings, **config_fields)
    """
    if "webhook_url" in config:
        return mod.deliver_digest(findings, config["webhook_url"])
    else:
        # Structured config — pass individual fields as kwargs
        # Convert smtp_port to int if present
        cfg = dict(config)
        if "smtp_port" in cfg:
            try:
                cfg["smtp_port"] = int(cfg["smtp_port"])
            except (ValueError, TypeError):
                pass
        return mod.deliver_digest(findings, **cfg)


def _run_channel_actor(
    manifest: ActorManifest, actor_dir: Path, finding: Finding,
    runtime_config: Any = None,
) -> ActorResolution:
    """Invoke a channel actor's deliver_digest and return a resolution."""
    mod = _load_channel_module(actor_dir)
    if mod is None or not hasattr(mod, "deliver_digest"):
        _log.warning("Channel actor '%s' has no deliver_digest function", manifest.name)
        return ActorResolution(
            finding_id=finding.id,
            action=ResolutionAction.ESCALATED,
            reason=f"Channel actor '{manifest.name}' missing deliver_digest",
        )

    resolved_config = _resolve_channel_config(manifest, runtime_config)

    try:
        result = _call_deliver_digest(mod, [finding], resolved_config)
    except (OSError, ValueError, RuntimeError) as exc:
        _log.warning("Channel actor '%s' delivery failed: %s", manifest.name, exc)
        return ActorResolution(
            finding_id=finding.id,
            action=ResolutionAction.ESCALATED,
            reason=f"Channel delivery exception: {exc}",
        )

    if hasattr(result, "success") and not result.success:
        error_msg = getattr(result, "error", "unknown error")
        _log.warning("Channel actor '%s' delivery failed: %s", manifest.name, error_msg)
        return ActorResolution(
            finding_id=finding.id,
            action=ResolutionAction.ESCALATED,
            reason=f"Channel delivery failed: {error_msg}",
        )

    return ActorResolution(
        finding_id=finding.id,
        action=ResolutionAction.RESOLVED,
        reason=f"Delivered to channel '{manifest.name}'",
    )


def _deliver_channel_batch(
    manifest: ActorManifest,
    actor_dir: Path,
    findings: list[Finding],
    results: list[Any],
    result_indices: list[int],
    runtime_config: Any = None,
) -> None:
    """Deliver all deferred channel findings in a single consolidated digest.

    Updates the corresponding RunResult entries in-place with the delivery outcome.
    """
    mod = _load_channel_module(actor_dir)
    if mod is None or not hasattr(mod, "deliver_digest"):
        _log.warning("Channel actor '%s' has no deliver_digest function", manifest.name)
        for idx in result_indices:
            results[idx].resolution = ActorResolution(
                finding_id=findings[result_indices.index(idx)].id,
                action=ResolutionAction.ESCALATED,
                reason=f"Channel actor '{manifest.name}' missing deliver_digest",
            )
        return

    resolved_config = _resolve_channel_config(manifest, runtime_config)

    try:
        result = _call_deliver_digest(mod, findings, resolved_config)
    except (OSError, ValueError, RuntimeError) as exc:
        _log.warning("Channel actor '%s' batch delivery failed: %s", manifest.name, exc)
        for i, idx in enumerate(result_indices):
            results[idx].resolution = ActorResolution(
                finding_id=findings[i].id,
                action=ResolutionAction.ESCALATED,
                reason=f"Channel batch delivery exception: {exc}",
            )
        return

    if hasattr(result, "success") and not result.success:
        error_msg = getattr(result, "error", "unknown error")
        _log.warning("Channel actor '%s' batch delivery failed: %s", manifest.name, error_msg)
        for i, idx in enumerate(result_indices):
            results[idx].resolution = ActorResolution(
                finding_id=findings[i].id,
                action=ResolutionAction.ESCALATED,
                reason=f"Channel batch delivery failed: {error_msg}",
            )
        return

    # Success: update deferred results to resolved
    for i, idx in enumerate(result_indices):
        results[idx].resolution = ActorResolution(
            finding_id=findings[i].id,
            action=ResolutionAction.RESOLVED,
            reason=f"Delivered to channel '{manifest.name}' (batch digest)",
        )


def _discover_configured_connector_dirs(
    config: Any,
    connector_dirs: list[Path] | None = None,
) -> list[Path]:
    """Return connector directories for connectors listed in config.connectors.

    If connector_dirs is provided, filter to only those whose directory name
    matches a key in config.connectors. If None, auto-discover from the
    built-in connectors package, filtering by config.connectors keys.
    """
    configured_names = set(getattr(config, "connectors", {}) or {})
    if not configured_names:
        return []

    if connector_dirs is not None:
        # Explicit list: filter to configured only
        return [d for d in connector_dirs if d.name in configured_names]

    # Auto-discover from built-in connectors package
    connectors_pkg = Path(__file__).parent.parent / "connectors"
    if not connectors_pkg.exists():
        return []

    result: list[Path] = []
    for d in sorted(connectors_pkg.iterdir()):
        if (
            d.is_dir()
            and not d.name.startswith("_")
            and d.name in configured_names
            and (d / "tools.py").exists()
        ):
            result.append(d)
    return result
