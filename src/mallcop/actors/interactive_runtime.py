"""Interactive runtime: single-turn chat loop with tool execution."""

from __future__ import annotations

import dataclasses
import logging

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mallcop.actors._schema import ActorManifest, load_actor_manifest
from mallcop.actors.runtime import _build_tool_schemas, _TRUSTED_TOOLS, load_post_md
from mallcop.actors.channels import _discover_configured_connector_dirs
from mallcop.chat import TOKENS_PER_DONUT
from mallcop.llm_types import LLMAPIError, LLMClient
from mallcop.sanitize import sanitize_tool_result
from mallcop.tools import ToolContext, ToolRegistry

_log = logging.getLogger(__name__)


@dataclass
class TurnResult:
    text: str
    tokens_used: int
    iterations: int
    tool_calls: int = 0
    tool_call_log: list[dict[str, Any]] = field(default_factory=list)
    # tool_call_log entries: {"name": str, "arguments": dict, "iteration": int}


class InteractiveRuntime:
    """Sibling of ActorRuntime for human-facing chat turns.

    The system_prompt is loaded from the interactive actor's POST.md once
    at build time (stored as self._system_prompt), NOT passed per-call.
    This keeps the signature simple for callers (C7 chat_turn):
        run_turn(messages, turn_budget_donuts=12, session_id="")
    """

    def __init__(
        self,
        manifest: ActorManifest,
        registry: ToolRegistry,
        llm: LLMClient,
        context: ToolContext,
        system_prompt: str,
    ) -> None:
        self._manifest = manifest
        self._registry = registry
        self._llm = llm
        self._context = context
        self._system_prompt = system_prompt

        # Determine max permission from manifest permissions list
        max_perm = "write" if "write" in manifest.permissions else "read"
        # This will raise PermissionError or KeyError if tools are invalid
        self._filtered_tools = registry.get_tools(manifest.tools, max_perm)

    def run_turn(
        self,
        messages: list[dict[str, Any]],
        turn_budget_donuts: int = 12,
        session_id: str = "",
    ) -> TurnResult:
        """Execute a single chat turn with full tool loop."""
        max_iter = 20
        turn_token_budget = turn_budget_donuts * TOKENS_PER_DONUT
        tool_schemas = _build_tool_schemas(self._filtered_tools)

        if session_id:
            self._context.session_id = session_id

        loop_messages = list(messages)
        total_tokens = 0
        total_tool_calls = 0
        tool_call_log: list[dict[str, Any]] = []

        for iteration in range(max_iter):
            _log.info(
                "InteractiveRuntime iter %d/%d (%d msgs, %d tokens so far)",
                iteration + 1, max_iter, len(loop_messages), total_tokens,
            )

            try:
                response = self._llm.chat(
                    model=self._manifest.model or "detective",
                    system_prompt=self._system_prompt,
                    messages=loop_messages,
                    tools=tool_schemas,
                )
            except LLMAPIError:
                _log.error(
                    "InteractiveRuntime: LLM backend error on iter %d",
                    iteration + 1,
                )
                raise

            total_tokens += response.tokens_used

            # Check turn token budget
            if total_tokens > turn_token_budget:
                _log.warning(
                    "InteractiveRuntime: turn budget exhausted (%d > %d tokens)",
                    total_tokens, turn_token_budget,
                )
                return TurnResult(
                    text=(
                        f"That ran over the {turn_budget_donuts}-donut turn budget. "
                        "Try a more specific question."
                    ),
                    tokens_used=total_tokens,
                    iterations=iteration + 1,
                    tool_calls=total_tool_calls,
                    tool_call_log=tool_call_log,
                )

            # Normal termination: text with no tool calls
            if not response.tool_calls and response.text:
                return TurnResult(
                    text=response.text,
                    tokens_used=total_tokens,
                    iterations=iteration + 1,
                    tool_calls=total_tool_calls,
                    tool_call_log=tool_call_log,
                )

            # Empty response
            if not response.tool_calls and not response.text:
                if iteration == 0 and response.tokens_used == 0:
                    raise LLMAPIError("backend returned empty response")
                return TurnResult(
                    text="(no response — model gave up)",
                    tokens_used=total_tokens,
                    iterations=iteration + 1,
                    tool_calls=total_tool_calls,
                    tool_call_log=tool_call_log,
                )

            # Execute tool calls
            for tc in response.tool_calls:
                total_tool_calls += 1
                tool_call_log.append({
                    "name": tc.name,
                    "arguments": tc.arguments,
                    "iteration": iteration,
                })
                try:
                    max_perm = "write" if "write" in self._manifest.permissions else "read"
                    result = self._registry.execute(
                        tc.name, self._context, max_permission=max_perm, **tc.arguments
                    )
                except Exception as exc:
                    _log.warning(
                        "InteractiveRuntime tool '%s' raised %s: %s",
                        tc.name, type(exc).__name__, exc,
                    )
                    result = {"error": f"Tool '{tc.name}' failed: {type(exc).__name__}: {exc}"}

                # Sanitize result (skip trusted tools)
                if tc.name in _TRUSTED_TOOLS:
                    sanitized_result = result
                else:
                    sanitized_result = sanitize_tool_result(result)

                loop_messages.append({
                    "role": "assistant",
                    "content": f"Calling tool: {tc.name}",
                })
                loop_messages.append({
                    "role": "tool",
                    "name": tc.name,
                    "content": str(sanitized_result),
                })

        # Hit max iterations without text response
        return TurnResult(
            text=(
                f"I worked on that but couldn't reach a conclusion in {max_iter} steps. "
                "Try a more specific question."
            ),
            tokens_used=total_tokens,
            iterations=max_iter,
            tool_calls=total_tool_calls,
            tool_call_log=tool_call_log,
        )


def build_interactive_runtime(
    root: Path,
    store: Any,
    config: Any,
    llm: LLMClient,
    actor_runner: Any,
) -> InteractiveRuntime:
    """Build an InteractiveRuntime for human-facing chat turns.

    Discovers tools using the same path order as build_actor_runner
    (deploy plugins → connectors → built-in tools). Auto-grants all
    read-permission tools in addition to the manifest's named tools.
    """
    # Discover tools using same path order as build_actor_runner
    builtin_tools_dir = Path(__file__).parent.parent / "tools"
    tool_search_paths: list[Path] = []

    # Deploy plugins first (highest precedence)
    deploy_tools = root / "plugins" / "tools"
    if deploy_tools.exists():
        tool_search_paths.append(deploy_tools)

    # Connector tools for configured connectors
    configured_conn_dirs = _discover_configured_connector_dirs(config, None)
    tool_search_paths.extend(configured_conn_dirs)

    # Built-in tools (lowest precedence)
    tool_search_paths.append(builtin_tools_dir)

    registry = ToolRegistry.discover_tools(tool_search_paths)

    # Load the interactive actor manifest
    interactive_actor_dir = Path(__file__).parent / "interactive"
    manifest = load_actor_manifest(interactive_actor_dir)

    # AUTO-GRANT all read-permission tools in addition to named tools
    named_tools = set(manifest.tools)
    all_reads = {meta.name for meta in registry.get_eligible_tools(names=None, max_permission="read")}
    effective_tools = sorted(named_tools | all_reads)

    # Build synthetic manifest with expanded tool list
    synthetic_manifest = dataclasses.replace(manifest, tools=effective_tools)

    # Build ToolContext
    context = ToolContext(
        store=store,
        connectors={},
        config=config,
        actor_runner=actor_runner,
    )

    # Load system prompt from POST.md
    system_prompt = load_post_md(interactive_actor_dir)

    return InteractiveRuntime(
        manifest=synthetic_manifest,
        registry=registry,
        llm=llm,
        context=context,
        system_prompt=system_prompt,
    )
