"""Config read tool for actor runtime."""

from __future__ import annotations

from typing import Any

from mallcop.tools import ToolContext, tool

# Keys that look like secrets and should be redacted
_SECRET_KEY_PATTERNS = {"secret", "token", "password", "key", "credential"}


def _is_secret_key(key: str) -> bool:
    """Check if a config key name looks like it holds a secret value."""
    key_lower = key.lower()
    return any(pattern in key_lower for pattern in _SECRET_KEY_PATTERNS)


def _redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy a dict, replacing secret-looking string values with '***'."""
    result: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            result[k] = _redact_dict(v)
        elif isinstance(v, str) and _is_secret_key(k):
            result[k] = "***"
        else:
            result[k] = v
    return result


def _serialize_routing(routing: Any) -> dict[str, Any]:
    """Serialize routing config to JSON-friendly dict."""
    from mallcop.config import RouteConfig
    if not isinstance(routing, dict):
        return routing
    result: dict[str, Any] = {}
    for k, v in routing.items():
        if v is None:
            result[k] = None
        elif isinstance(v, RouteConfig):
            result[k] = {"chain": v.chain, "notify": v.notify}
        else:
            result[k] = v
    return result


@tool(name="read-config", description="Read mallcop configuration (read-only)", permission="read")
def read_config(context: ToolContext) -> dict[str, Any]:
    """Return the mallcop config as a dict with secret values redacted.

    Includes connectors, routing, actor_chain, and budget.
    Secret-looking values (keys containing 'secret', 'token', 'password',
    'key', 'credential') are replaced with '***'.
    """
    config = context.config

    # Redact connector configs
    connectors_redacted: dict[str, Any] = {}
    for name, cfg in config.connectors.items():
        connectors_redacted[name] = _redact_dict(cfg) if isinstance(cfg, dict) else cfg

    return {
        "secrets_backend": config.secrets_backend,
        "connectors": connectors_redacted,
        "routing": _serialize_routing(config.routing),
        "actor_chain": dict(config.actor_chain) if hasattr(config.actor_chain, '__iter__') else config.actor_chain,
        "budget": {
            "max_findings_for_actors": config.budget.max_findings_for_actors,
            "max_tokens_per_run": config.budget.max_tokens_per_run,
            "max_tokens_per_finding": config.budget.max_tokens_per_finding,
        },
    }
