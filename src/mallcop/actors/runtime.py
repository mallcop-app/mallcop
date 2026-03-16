"""Actor runtime: manifest loading, LLM tool loop, output validation."""

from __future__ import annotations

import logging

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from mallcop.actors._schema import ActorManifest, ActorResolution, ResolutionAction, load_actor_manifest
from mallcop.llm_types import LLMAPIError, LLMClient, LLMResponse, ToolCall  # canonical home
from mallcop.sanitize import sanitize_finding, sanitize_tool_result
from mallcop.schemas import Finding
from mallcop.tools import ToolContext, ToolRegistry

# Re-export from new modules so existing imports keep working.
from mallcop.actors.batch import build_batch_context, run_batch  # noqa: F401
from mallcop.actors.channels import (  # noqa: F401
    _deliver_channel_batch,
    _discover_configured_connector_dirs,
    _load_channel_module,
    _resolve_channel_config,
    _run_channel_actor,
    _validate_webhook_url,
)
from mallcop.actors.validation import (  # noqa: F401
    EscalationPathError,
    _validate_channel_config,
    check_escalation_health,
    validate_escalation_paths,
)

# Re-export so existing ``from mallcop.actors.runtime import ...`` keeps working.
__all__ = [
    "LLMClient",
    "LLMResponse",
    "ToolCall",
    "ActorRuntime",
    "RunResult",
    "BatchResult",
    "build_actor_runner",
    "build_batch_context",
    "run_batch",
    "validate_resolution",
    "load_post_md",
    "EscalationPathError",
    "check_escalation_health",
    "validate_escalation_paths",
]

_log = logging.getLogger(__name__)


@dataclass
class RunResult:
    resolution: ActorResolution | None
    tokens_used: int
    iterations: int
    tool_calls: int = field(default=0)
    distinct_tools: int = field(default=0)
    backend_error: bool = field(default=False)


@dataclass
class BatchResult:
    """Aggregated result from processing a batch of findings."""
    results: list[RunResult]
    total_tokens: int
    feedback_records: list[Any] = field(default_factory=list)  # list[FeedbackRecord]

_VALID_ACTIONS = {a.value for a in ResolutionAction}

# All tool results are sanitized (defense in depth). Skills are verified at
# load time via trust infrastructure, but their content still gets USER_DATA
# markers to prevent injection if a skill is compromised.
_TRUSTED_TOOLS: frozenset[str] = frozenset()


def validate_resolution(raw: Any) -> ActorResolution | None:
    """Validate raw LLM output and return a clean ActorResolution, or None if invalid.

    Layer 5 defense: validates actor responses against expected schema before applying.
    Invalid data is rejected (returns None), causing the runtime to escalate (fail-safe).
    Extra fields are silently stripped.
    """
    if not isinstance(raw, dict):
        _log.warning("Resolution validation failed: not a dict (got %s)", type(raw).__name__)
        return None

    # Check required fields exist and are strings
    for field_name in ("finding_id", "action", "reason"):
        if field_name not in raw:
            _log.warning("Resolution validation failed: missing required field '%s'", field_name)
            return None
        if not isinstance(raw[field_name], str):
            _log.warning(
                "Resolution validation failed: field '%s' must be str, got %s",
                field_name, type(raw[field_name]).__name__,
            )
            return None

    # Validate action is an allowed enum value
    if raw["action"] not in _VALID_ACTIONS:
        _log.warning(
            "Resolution validation failed: invalid action '%s', must be one of %s",
            raw["action"], _VALID_ACTIONS,
        )
        return None

    # Build clean ActorResolution (extra fields are stripped by construction)
    return ActorResolution(
        finding_id=raw["finding_id"],
        action=ResolutionAction(raw["action"]),
        reason=raw["reason"],
    )


def load_post_md(actor_dir: Path) -> str:
    post_path = actor_dir / "POST.md"
    if post_path.exists():
        return post_path.read_text()
    return ""


def _build_tool_schemas(tools: list[Any]) -> list[dict[str, Any]]:
    schemas = []
    for fn in tools:
        meta = fn._tool_meta
        schemas.append({
            "name": meta.name,
            "description": meta.description,
            "parameters": meta.parameter_schema,
        })
    return schemas


class ActorRuntime:
    def __init__(
        self,
        manifest: ActorManifest,
        registry: ToolRegistry,
        llm: LLMClient,
        context: ToolContext | None = None,
    ) -> None:
        self._manifest = manifest
        self._registry = registry
        self._llm = llm
        self._context = context
        # Determine max permission from manifest permissions list
        max_perm = "read"
        if "write" in manifest.permissions:
            max_perm = "write"
        # This will raise PermissionError or KeyError if tools are invalid
        self._filtered_tools = registry.get_tools(manifest.tools, max_perm)

    def get_filtered_tools(self) -> list[Any]:
        return list(self._filtered_tools)

    def _prepack_context(self, finding: Finding) -> list[dict[str, Any]]:
        """Pre-pack finding events and baseline data into initial messages.

        This avoids multi-round tool calls for data the runtime already has.
        The LLM gets everything it needs to classify in one shot.
        """
        import json as _json

        extra_messages: list[dict[str, Any]] = []

        if self._context is None:
            return extra_messages

        store = self._context.store

        # Pre-fetch events referenced by this finding
        matched_events = store.query_events_by_ids(finding.event_ids) if finding.event_ids else []
        if matched_events:
            matched = [e.to_dict() for e in matched_events]
            sanitized_events = sanitize_tool_result(matched)
            extra_messages.extend([
                {"role": "assistant", "content": "Calling tool: read-events"},
                {
                    "role": "tool",
                    "name": "read-events",
                    "content": str(sanitized_events),
                },
            ])

        # Pre-fetch baseline check for the finding's actor(s)
        baseline = store.get_baseline()
        actors_checked: set[str] = set()
        # Extract actor from finding metadata
        meta = finding.metadata or {}
        actor = meta.get("actor", "")
        if actor:
            actors_checked.add(actor)
        # Also check the finding's event actors if we have events
        for evt in matched_events:
            if evt.actor:
                actors_checked.add(evt.actor)

        for actor_name in actors_checked:
            known_actors = baseline.known_entities.get("actors", [])
            is_known = actor_name in known_actors
            actor_freq = {
                k: v for k, v in baseline.frequency_tables.items()
                if k.endswith(f":{actor_name}")
            }
            rels = baseline.relationships
            actor_rels: dict[str, Any] = {}
            prefix = f"{actor_name}:"
            for rk, rv in rels.items():
                if rk.startswith(prefix):
                    actor_rels[rk[len(prefix):]] = rv

            baseline_result = sanitize_tool_result({
                "actor": actor_name,
                "known": is_known,
                "frequency": actor_freq,
                "relationships": actor_rels,
            })
            extra_messages.extend([
                {"role": "assistant", "content": "Calling tool: check-baseline"},
                {
                    "role": "tool",
                    "name": "check-baseline",
                    "content": str(baseline_result),
                },
            ])

        # Pre-pack skill catalog if skill_root is configured
        skill_root = getattr(self._context, "skill_root", None)
        if skill_root is not None:
            import json as _json2
            from pathlib import Path as _Path
            from mallcop.skills._schema import SkillManifest as _SkillManifest

            skill_root_path = _Path(skill_root)
            catalog: list[dict[str, Any]] = []
            if skill_root_path.exists() and skill_root_path.is_dir():
                for skill_dir in sorted(skill_root_path.iterdir()):
                    if not skill_dir.is_dir():
                        continue
                    manifest = _SkillManifest.from_skill_dir(skill_dir)
                    if manifest is None:
                        continue
                    catalog.append({
                        "name": manifest.name,
                        "description": manifest.description,
                        "parent": manifest.parent,
                        "has_tools": manifest.tools is not None,
                    })
            if catalog:
                extra_messages.extend([
                    {"role": "assistant", "content": "Calling tool: list-skills"},
                    {
                        "role": "tool",
                        "name": "list-skills",
                        "content": _json2.dumps(catalog),
                    },
                ])

        return extra_messages

    def run(
        self,
        finding: Finding,
        system_prompt: str,
        finding_token_budget: int | None = None,
    ) -> RunResult:
        max_iter = self._manifest.max_iterations or 10
        tool_schemas = _build_tool_schemas(self._filtered_tools)

        # Build initial messages: deliver finding as structured tool result
        # (defense layer 1 — never interpolate external data into user messages)
        sanitized = sanitize_finding(finding)
        messages: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": "A new finding has been loaded for investigation. "
                "Finding context, events, and baseline data are provided below. "
                "Review them, then use your tools to investigate before resolving.",
            },
            {
                "role": "assistant",
                "content": "Calling tool: get-finding-context",
            },
            {
                "role": "tool",
                "name": "get-finding-context",
                "content": sanitized.to_json(),
            },
        ]

        # Pre-pack events + baseline as starting context for investigation
        messages.extend(self._prepack_context(finding))

        total_tokens = 0
        finding_tokens = 0

        for iteration in range(max_iter):
            _log.info(
                "Actor %s iter %d/%d for %s (%d msgs, %d tokens so far)",
                self._manifest.name, iteration + 1, max_iter,
                finding.id[:12], len(messages), finding_tokens,
            )
            try:
                response = self._llm.chat(
                    model=self._manifest.model or "haiku",
                    system_prompt=system_prompt,
                    messages=messages,
                    tools=tool_schemas,
                )
            except LLMAPIError:
                _log.error(
                    "Actor %s: LLM backend error on iter %d for %s",
                    self._manifest.name, iteration + 1, finding.id[:12],
                )
                raise

            total_tokens += response.tokens_used
            finding_tokens += response.tokens_used
            _log.info(
                "Actor %s iter %d: +%d tokens, tool_calls=%d, has_resolution=%s",
                self._manifest.name, iteration + 1, response.tokens_used,
                len(response.tool_calls), response.raw_resolution is not None,
            )

            # Check per-finding token budget
            if finding_token_budget is not None and finding_tokens > finding_token_budget:
                _log.warning(
                    "Actor %s budget exhausted for %s: %d/%d tokens",
                    self._manifest.name, finding.id[:12],
                    finding_tokens, finding_token_budget,
                )
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.ESCALATED,
                        reason="Per-finding token budget exhausted",
                    ),
                    tokens_used=total_tokens,
                    iterations=iteration + 1,
                )

            # If resolution returned, validate before accepting (Layer 5)
            resolved = None
            if response.raw_resolution is not None:
                # LLM returned raw data — validate it
                resolved = validate_resolution(response.raw_resolution)
                if resolved is None:
                    _log.warning(
                        "Actor returned invalid raw resolution for finding %s, escalating",
                        finding.id,
                    )
                    return RunResult(
                        resolution=ActorResolution(
                            finding_id=finding.id,
                            action=ResolutionAction.ESCALATED,
                            reason="Actor output validation failed: invalid resolution schema",
                        ),
                        tokens_used=total_tokens,
                        iterations=iteration + 1,
                    )
            elif response.resolution is not None:
                # Already-parsed resolution — validate via round-trip
                resolved = validate_resolution(response.resolution.to_dict())
                if resolved is None:
                    _log.warning(
                        "Actor returned invalid resolution for finding %s, escalating",
                        finding.id,
                    )
                    return RunResult(
                        resolution=ActorResolution(
                            finding_id=finding.id,
                            action=ResolutionAction.ESCALATED,
                            reason="Actor output validation failed: invalid resolution schema",
                        ),
                        tokens_used=total_tokens,
                        iterations=iteration + 1,
                    )

            if resolved is not None:
                _log.info(
                    "Actor %s resolved %s: action=%s reason=%s tokens=%d iters=%d",
                    self._manifest.name, finding.id[:12],
                    resolved.action.value, resolved.reason[:80],
                    total_tokens, iteration + 1,
                )
                return RunResult(
                    resolution=resolved,
                    tokens_used=total_tokens,
                    iterations=iteration + 1,
                )

            # Process tool calls
            if not response.tool_calls:
                # No tool calls and no resolution on first iteration with 0 tokens
                # = backend failure, not a legitimate escalation
                if iteration == 0 and response.tokens_used == 0:
                    raise LLMAPIError(
                        f"LLM backend returned empty response for {finding.id} "
                        f"(0 tokens, no tool calls, no resolution)"
                    )
                # Later iterations with actual tokens = legitimate escalation
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.ESCALATED,
                        reason="LLM returned no tool calls and no resolution",
                    ),
                    tokens_used=total_tokens,
                    iterations=iteration + 1,
                )

            # Check for resolve-finding tool call — intercept as resolution
            for tc in response.tool_calls:
                if tc.name == "resolve-finding":
                    action_str = tc.arguments.get("action", "escalated")
                    reason = tc.arguments.get("reason", "No reason provided")
                    confidence = int(tc.arguments.get("confidence", 3))
                    action_enum = (
                        ResolutionAction.RESOLVED
                        if action_str == "resolved"
                        else ResolutionAction.ESCALATED
                    )
                    return RunResult(
                        resolution=ActorResolution(
                            finding_id=tc.arguments.get("finding_id", finding.id),
                            action=action_enum,
                            reason=reason,
                            confidence=float(confidence),
                        ),
                        tokens_used=total_tokens,
                        iterations=iteration + 1,
                    )

            # Execute tool calls and collect results
            _log.debug(
                "Actor %s executing %d tool calls: %s",
                self._manifest.name, len(response.tool_calls),
                ", ".join(tc.name for tc in response.tool_calls),
            )
            for tc in response.tool_calls:
                try:
                    if self._context is not None:
                        # Use registry.execute for context injection + permission check
                        max_perm = "write" if "write" in self._manifest.permissions else "read"
                        result = self._registry.execute(
                            tc.name, self._context, max_permission=max_perm, **tc.arguments
                        )
                    else:
                        # Legacy path: direct call without context
                        tool_fn = self._registry.get_tool(tc.name)
                        result = tool_fn(**tc.arguments)
                except Exception as exc:
                    _log.warning(
                        "Actor %s tool '%s' raised %s: %s",
                        self._manifest.name, tc.name,
                        type(exc).__name__, exc,
                    )
                    # Feed the error back to the LLM so it can try a different approach
                    result = {"error": f"Tool '{tc.name}' failed: {type(exc).__name__}: {exc}"}
                # Sanitize tool result before it reaches the LLM
                # (defense layer 2 — all tool results get markers)
                # Exception: trusted tools (e.g. load-skill) deliver trusted
                # instructions — skip sanitization so skill context is not
                # wrapped in USER_DATA markers.
                if tc.name in _TRUSTED_TOOLS:
                    sanitized_result = result
                else:
                    sanitized_result = sanitize_tool_result(result)
                messages.append({
                    "role": "assistant",
                    "content": f"Calling tool: {tc.name}",
                })
                messages.append({
                    "role": "tool",
                    "name": tc.name,
                    "content": str(sanitized_result),
                })

        # Hit max iterations without resolution
        return RunResult(
            resolution=ActorResolution(
                finding_id=finding.id,
                action=ResolutionAction.ESCALATED,
                reason=f"Max iterations ({max_iter}) reached without resolution",
            ),
            tokens_used=total_tokens,
            iterations=max_iter,
        )


def build_actor_runner(
    root: Path,
    store: Any,
    config: Any,
    llm: LLMClient | None,
    actor_dirs: list[Path] | None = None,
    connector_dirs: list[Path] | None = None,
    validate_paths: bool = False,
    extra_tools: list[Callable] | None = None,
) -> Callable[..., RunResult] | None:
    """Build an actor_runner closure for the escalate pipeline.

    Discovers tools from the built-in tools directory (and any connector/plugin
    tools directories). Loads actor manifests from actor_dirs. Returns a callable
    that, given a Finding, creates an ActorRuntime with the appropriate manifest
    and executes it.

    Args:
        root: Deployment repo directory.
        store: JsonlStore instance.
        config: MallcopConfig instance.
        llm: LLMClient for actor execution.
        actor_dirs: Explicit list of actor directories. If None, discovers from
                    the built-in actors/ package directory.
        connector_dirs: Explicit list of connector directories to scan for tools.
                       If None, auto-discovers from the built-in connectors package.
                       Only connectors listed in config.connectors are included.

    Returns:
        A callable (finding, **kwargs) -> RunResult, or None if no agent-type
        actors are found.
    """
    # No LLM client and no validation needed -> no actor execution possible
    if llm is None and not validate_paths:
        return None

    # Discover tools from built-in tools directory
    builtin_tools_dir = Path(__file__).parent.parent / "tools"
    tool_search_paths: list[Path] = []

    # Check for deployment-level plugins/tools/
    deploy_tools = root / "plugins" / "tools"
    if deploy_tools.exists():
        tool_search_paths.append(deploy_tools)

    # Connector tools: only for configured connectors
    # Precedence: deployment > connector > built-in
    configured_conn_dirs = _discover_configured_connector_dirs(config, connector_dirs)
    tool_search_paths.extend(configured_conn_dirs)

    # Built-in tools always included (lowest precedence)
    tool_search_paths.append(builtin_tools_dir)

    registry = ToolRegistry.discover_tools(tool_search_paths)

    if extra_tools:
        for fn in extra_tools:
            registry.register(fn)

    # Build ToolContext
    context = ToolContext(
        store=store,
        connectors={},  # Connectors not authenticated in escalate path yet
        config=config,
    )

    # Load actor manifests
    if actor_dirs is None:
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
        except Exception as exc:
            _log.warning(
                "Failed to load actor manifest from %s: %s: %s",
                actor_dir, type(exc).__name__, exc,
            )
            continue

    if not manifests and not channel_manifests:
        return None

    # Validate escalation paths before processing any findings
    if validate_paths:
        routing = getattr(config, "routing", {}) or {}
        path_errors = validate_escalation_paths(
            routing, manifests, channel_manifests, config,
        )
        if path_errors:
            error_msg = "Escalation path validation failed:\n" + "\n".join(
                f"  - {e}" for e in path_errors
            )
            raise EscalationPathError(error_msg)

    if llm is None:
        return None

    def actor_runner(finding: Finding, **kwargs: Any) -> RunResult:
        # Select actor by name from kwargs, falling back to first available
        requested_name = kwargs.get("actor_name")
        batch_context = kwargs.get("batch_context")
        if requested_name is None:
            requested_name = next(iter(manifests))

        # Walk the actor chain: run actor, follow routes_to on escalation
        current_name: str | None = requested_name
        total_tokens = 0
        total_iterations = 0
        finding_token_budget = kwargs.get("finding_token_budget")
        chain_path: list[str] = []  # track actor chain walk for logging

        # Batch-mode deferred channel delivery support
        deferred_channel = kwargs.get("_deferred_channel")
        deferred_channel_meta = kwargs.get("_deferred_channel_meta")

        while current_name is not None:
            # Check if this is a channel actor
            if current_name in channel_manifests:
                ch_manifest, ch_dir = channel_manifests[current_name]

                # If running inside a batch, defer delivery for consolidation
                if deferred_channel is not None:
                    # Store channel metadata on first deferral
                    if deferred_channel_meta is not None and not deferred_channel_meta:
                        deferred_channel_meta.append((ch_manifest, ch_dir, config))
                    return RunResult(
                        resolution=ActorResolution(
                            finding_id=finding.id,
                            action=ResolutionAction.RESOLVED,
                            reason=f"Deferred for batch channel delivery via '{ch_manifest.name}'",
                        ),
                        tokens_used=total_tokens,
                        iterations=total_iterations,
                    )

                # Single-finding mode: deliver immediately
                ch_result = _run_channel_actor(ch_manifest, ch_dir, finding, runtime_config=config)
                return RunResult(
                    resolution=ch_result,
                    tokens_used=total_tokens,
                    iterations=total_iterations,
                )

            if current_name not in manifests:
                _log.warning("Actor '%s' not found, skipping", current_name)
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.ESCALATED,
                        reason=f"Actor '{current_name}' not found \u2014 skipped",
                    ),
                    tokens_used=total_tokens,
                    iterations=total_iterations,
                )

            manifest, actor_dir = manifests[current_name]
            post_md = load_post_md(actor_dir)
            chain_path.append(current_name)

            _log.info(
                "finding=%s actor=%s status=entering chain_position=%d",
                finding.id[:12], current_name, len(chain_path),
            )

            # Set actor_name on context so tools (e.g. annotate-finding) use it
            context.actor_name = current_name

            runtime = ActorRuntime(
                manifest=manifest,
                registry=registry,
                llm=llm,
                context=context,
            )

            # Adjust per-finding budget for remaining tokens
            remaining_budget = None
            if finding_token_budget is not None:
                remaining_budget = finding_token_budget - total_tokens
                if remaining_budget <= 0:
                    return RunResult(
                        resolution=ActorResolution(
                            finding_id=finding.id,
                            action=ResolutionAction.ESCALATED,
                            reason="Per-finding token budget exhausted during chain",
                        ),
                        tokens_used=total_tokens,
                        iterations=total_iterations,
                    )

            system_prompt = post_md or f"You are the {manifest.name} agent."
            if batch_context is not None:
                system_prompt = f"{system_prompt}\n\n{batch_context}"

            try:
                result = runtime.run(
                    finding=finding,
                    system_prompt=system_prompt,
                    finding_token_budget=remaining_budget,
                )
            except LLMAPIError as exc:
                _log.error(
                    "LLM backend error in actor '%s' for finding %s: %s",
                    current_name, finding.id[:12], exc,
                )
                return RunResult(
                    resolution=ActorResolution(
                        finding_id=finding.id,
                        action=ResolutionAction.ESCALATED,
                        reason=f"LLM backend error: {exc}",
                    ),
                    tokens_used=total_tokens,
                    iterations=total_iterations,
                    backend_error=True,
                )

            total_tokens += result.tokens_used
            total_iterations += result.iterations

            # If resolved (not escalated), return immediately
            if (
                result.resolution is not None
                and result.resolution.action != ResolutionAction.ESCALATED
            ):
                _log.info(
                    "finding=%s action=%s actor=%s tokens=%d iters=%d chain=%s reason=%s",
                    finding.id[:12], result.resolution.action.value,
                    current_name, total_tokens, total_iterations,
                    "→".join(chain_path), result.resolution.reason[:80],
                )
                return RunResult(
                    resolution=result.resolution,
                    tokens_used=total_tokens,
                    iterations=total_iterations,
                )

            # Escalated -- follow routes_to if available
            next_name = manifest.routes_to
            _log.info(
                "finding=%s actor=%s status=escalated next=%s reason=%s",
                finding.id[:12], current_name,
                next_name or "(chain end)", result.resolution.reason[:80] if result.resolution else "no resolution",
            )
            current_name = next_name

        # Chain exhausted (routes_to was None or missing) -- return last escalation
        _log.warning(
            "finding=%s status=chain_exhausted tokens=%d chain=%s",
            finding.id[:12], total_tokens, "→".join(chain_path),
        )
        return RunResult(
            resolution=ActorResolution(
                finding_id=finding.id,
                action=ResolutionAction.ESCALATED,
                reason=f"Actor chain exhausted \u2014 no further routes_to",
            ),
            tokens_used=total_tokens,
            iterations=total_iterations,
        )

    return actor_runner
