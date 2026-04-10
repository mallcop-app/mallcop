"""Tool registry with @tool decorator, ToolContext, and dynamic discovery."""

from __future__ import annotations

import importlib.util
import inspect
import logging
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any, Callable

_VALID_PERMISSIONS = {"read", "write"}
_PERMISSION_LEVEL = {"read": 0, "write": 1}

_log = logging.getLogger(__name__)


class PermissionError(Exception):
    """Raised when a tool is requested with insufficient permission."""


class ToolNotFoundError(Exception):
    """Raised when a tool name is not in the registry."""


@dataclass
class ToolContext:
    """Runtime context injected into tool functions. Hidden from LLM schema."""

    store: Any  # Store instance
    connectors: dict[str, Any]  # connector name -> authenticated ConnectorBase
    config: Any  # MallcopConfig instance
    actor_name: str = "agent"  # Name of the actor using this context
    reputation: Any = None  # Optional EntityReputation instance
    skill_root: Any = None  # Path to skill root directory (optional)
    loaded_skills: dict = field(default_factory=dict)  # name -> LoadedSkill (cache)
    tool_registry: Any = None  # ToolRegistry for skill tool registration
    trust_store: Any = None  # Optional TrustStore for skill signature verification
    skill_lockfile: Any = None  # Optional dict (from load_lockfile) for hash checks
    actor_runner: Any = None  # Optional actor_runner closure for recursive dispatch
    session_id: str = ""  # Session ID for chat history filtering (empty in autonomous chain)


@dataclass
class ToolMeta:
    name: str
    description: str
    permission: str
    parameter_schema: dict[str, Any]


def _derive_schema(fn: Callable) -> dict[str, Any]:
    """Derive parameter schema from function signature, skipping 'context' param."""
    sig = inspect.signature(fn)
    hints = fn.__annotations__
    schema: dict[str, Any] = {}
    for param_name, param in sig.parameters.items():
        if param_name == "return":
            continue
        # Skip context parameter — it's injected by the runtime, not by the LLM
        if param_name == "context":
            continue
        type_hint = hints.get(param_name)
        type_str = getattr(type_hint, "__name__", str(type_hint)) if type_hint else "Any"
        # Normalize common type representations
        if type_str.startswith("typing."):
            type_str = type_str.replace("typing.", "")
        has_default = param.default is not inspect.Parameter.empty
        entry: dict[str, Any] = {
            "type": type_str,
            "required": not has_default,
        }
        if has_default:
            entry["default"] = param.default
        schema[param_name] = entry
    return schema


def _has_context_param(fn: Callable) -> bool:
    """Check if the underlying function accepts a 'context' parameter."""
    # Unwrap the decorator wrapper to get the original function
    inner = getattr(fn, "__wrapped__", fn)
    sig = inspect.signature(inner)
    return "context" in sig.parameters


def tool(
    name: str, description: str, permission: str
) -> Callable:
    if permission not in _VALID_PERMISSIONS:
        raise ValueError(
            f"Invalid permission '{permission}', must be one of {_VALID_PERMISSIONS}"
        )

    def decorator(fn: Callable) -> Callable:
        schema = _derive_schema(fn)
        meta = ToolMeta(
            name=name,
            description=description,
            permission=permission,
            parameter_schema=schema,
        )

        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return fn(*args, **kwargs)

        wrapper._tool_meta = meta  # type: ignore[attr-defined]
        return wrapper

    return decorator


def make_query_events_tool(
    tool_name: str,
    description: str,
    default_source: str,
) -> Callable:
    """Factory that creates a source-specific event query tool.

    Returns a @tool-decorated function that queries events filtered
    to the given source by default.
    """

    @tool(name=tool_name, description=description, permission="read")
    def query_events(
        context: ToolContext,
        source: str | None = None,
        actor: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        from datetime import datetime as _dt

        since_dt = None
        if since:
            since_dt = _dt.fromisoformat(since)
        effective_source = source or default_source
        events = context.store.query_events(
            source=effective_source,
            actor=actor,
            since=since_dt,
            limit=limit,
        )
        return [e.to_dict() for e in events]

    return query_events


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Callable] = {}

    def register(self, fn: Callable) -> None:
        meta: ToolMeta = fn._tool_meta  # type: ignore[attr-defined]
        if meta.name in self._tools:
            raise ValueError(f"Tool '{meta.name}' already registered")
        self._tools[meta.name] = fn

    def register_if_new(self, fn: Callable) -> bool:
        """Register tool only if name not already registered. Returns True if registered."""
        meta: ToolMeta = fn._tool_meta  # type: ignore[attr-defined]
        if meta.name in self._tools:
            return False
        self._tools[meta.name] = fn
        return True

    @classmethod
    def discover_tools(cls, paths: list[Path]) -> ToolRegistry:
        """Scan directories for .py files containing @tool-decorated functions.

        Paths are scanned in order. First path wins on name conflict (precedence).
        Non-existent paths and files with errors are silently skipped.
        """
        import sys

        registry = cls()
        for path in paths:
            if not path.exists() or not path.is_dir():
                continue
            for py_file in sorted(path.glob("*.py")):
                if py_file.name.startswith("_"):
                    continue
                module_name = f"mallcop_tool_discovery.{py_file.stem}"
                try:
                    spec = importlib.util.spec_from_file_location(
                        module_name, py_file
                    )
                    if spec is None or spec.loader is None:
                        continue
                    module = importlib.util.module_from_spec(spec)
                    # Register in sys.modules before exec so @dataclass and other
                    # decorators that look up cls.__module__ work correctly.
                    sys.modules[module_name] = module
                    try:
                        spec.loader.exec_module(module)  # type: ignore[union-attr]
                    except Exception:
                        del sys.modules[module_name]
                        raise
                except Exception:
                    _log.debug("Skipping %s: failed to import", py_file)
                    continue

                for attr_name in dir(module):
                    obj = getattr(module, attr_name)
                    if callable(obj) and hasattr(obj, "_tool_meta"):
                        registry.register_if_new(obj)
        return registry

    def execute(
        self,
        name: str,
        context: ToolContext,
        max_permission: str = "write",
        **llm_params: Any,
    ) -> Any:
        """Look up tool by name, enforce permission, inject context, call with LLM params."""
        if name not in self._tools:
            raise ToolNotFoundError(f"Tool '{name}' not found")
        fn = self._tools[name]
        meta: ToolMeta = fn._tool_meta  # type: ignore[attr-defined]

        # Permission check
        max_level = _PERMISSION_LEVEL[max_permission]
        tool_level = _PERMISSION_LEVEL[meta.permission]
        if tool_level > max_level:
            raise PermissionError(
                f"Tool '{name}' requires '{meta.permission}' permission, "
                f"but max allowed is '{max_permission}'"
            )

        # Inject context if the tool accepts it
        if _has_context_param(fn):
            return fn(context, **llm_params)
        return fn(**llm_params)

    def get_tool(self, name: str) -> Callable:
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' not found")
        return self._tools[name]

    def get_tools(self, names: list[str], max_permission: str) -> list[Callable]:
        max_level = _PERMISSION_LEVEL[max_permission]
        result: list[Callable] = []
        for name in names:
            if name not in self._tools:
                raise KeyError(f"Tool '{name}' not found")
            fn = self._tools[name]
            meta: ToolMeta = fn._tool_meta  # type: ignore[attr-defined]
            tool_level = _PERMISSION_LEVEL[meta.permission]
            if tool_level > max_level:
                raise PermissionError(
                    f"Tool '{name}' requires '{meta.permission}' permission, "
                    f"but max allowed is '{max_permission}'"
                )
            result.append(fn)
        return result

    def get_eligible_tools(
        self, names: list[str] | None, max_permission: str
    ) -> list[ToolMeta]:
        """Filter tools by optional name list and permission level.

        Unlike get_tools(), this does NOT raise on permission mismatch —
        it silently excludes tools that exceed max_permission.
        """
        max_level = _PERMISSION_LEVEL[max_permission]
        candidates = self._tools.values()
        if names is not None:
            candidates = [
                self._tools[n] for n in names if n in self._tools
            ]
        result: list[ToolMeta] = []
        for fn in candidates:
            meta: ToolMeta = fn._tool_meta  # type: ignore[attr-defined]
            if _PERMISSION_LEVEL[meta.permission] <= max_level:
                result.append(meta)
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": fn._tool_meta.name,  # type: ignore[attr-defined]
                "description": fn._tool_meta.description,  # type: ignore[attr-defined]
                "permission": fn._tool_meta.permission,  # type: ignore[attr-defined]
            }
            for fn in self._tools.values()
        ]
