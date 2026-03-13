"""Shakedown harness: drives the actor chain with canned data and real LLM."""

from __future__ import annotations

import copy
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from mallcop.actors.runtime import RunResult, build_actor_runner
from mallcop.config import load_config
from mallcop.llm_types import LLMClient, LLMResponse
from mallcop.tools import tool, ToolContext

from tests.shakedown.scenario import (
    ConnectorToolDef,
    Scenario,
    load_all_scenarios,
    load_scenarios_tagged,
)
from tests.shakedown.scenario_store import ScenarioStore


@dataclass
class CapturedCall:
    """Record of a single LLM chat() invocation."""

    actor: str
    model: str
    tokens_used: int
    latency_ms: int
    messages_sent: list[dict]
    response_text: str
    tool_calls_detail: list[dict]
    has_resolution: bool

    @property
    def tool_calls(self) -> list[str]:
        return [tc["name"] for tc in self.tool_calls_detail]

    @property
    def message_count(self) -> int:
        return len(self.messages_sent)


class InstrumentedLLMClient(LLMClient):
    """Wraps an LLM client, capturing all calls for post-run evaluation."""

    def __init__(self, inner: LLMClient) -> None:
        self.inner = inner
        self.calls: list[CapturedCall] = []

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        messages_copy = copy.deepcopy(messages)

        start = time.monotonic()
        response = self.inner.chat(model, system_prompt, messages, tools)
        latency_ms = int((time.monotonic() - start) * 1000)

        self.calls.append(
            CapturedCall(
                actor=self._infer_actor(system_prompt),
                model=model,
                tokens_used=response.tokens_used,
                latency_ms=latency_ms,
                messages_sent=messages_copy,
                response_text=response.text if hasattr(response, "text") else "",
                tool_calls_detail=[
                    {
                        "name": tc.name,
                        "arguments": tc.arguments if hasattr(tc, "arguments") else {},
                    }
                    for tc in response.tool_calls
                ],
                has_resolution=response.resolution is not None
                or response.raw_resolution is not None,
            )
        )
        return response

    def _infer_actor(self, system_prompt: str) -> str:
        prompt_lower = system_prompt.lower()[:200]
        # Check investigate first — investigate POST.md mentions "triage" as substring
        if "level-2" in prompt_lower or "investigation agent" in prompt_lower:
            return "investigate"
        if "level-1" in prompt_lower or "triage" in prompt_lower:
            return "triage"
        return "unknown"

    def reset(self) -> None:
        self.calls.clear()


@dataclass
class ShakedownResult:
    """Result of running a single scenario through the actor chain."""

    scenario_id: str
    chain_result: RunResult
    llm_calls: list[CapturedCall]
    store_mutations: list[Any]  # list[Mutation] from ScenarioStore

    @property
    def total_tokens(self) -> int:
        return sum(c.tokens_used for c in self.llm_calls)

    @property
    def chain_action(self) -> str:
        if self.chain_result.resolution:
            return self.chain_result.resolution.action.value
        return "unknown"

    @property
    def triage_action(self) -> str:
        """What did triage decide?"""
        triage_calls = [c for c in self.llm_calls if c.actor == "triage"]
        investigate_calls = [c for c in self.llm_calls if c.actor == "investigate"]
        if not triage_calls:
            return "unknown"
        # If investigate was invoked, triage must have escalated
        if investigate_calls:
            return "escalated"
        # Only triage calls — triage resolved
        return "resolved"

    @property
    def chain_reason(self) -> str:
        if self.chain_result.resolution:
            return self.chain_result.resolution.reason
        return ""

    @property
    def transcript(self) -> list[dict]:
        """Complete ordered conversation across all LLM calls."""
        result = []
        for call in self.llm_calls:
            for msg in call.messages_sent:
                result.append(msg)
            if call.response_text:
                result.append({"role": "assistant", "content": call.response_text})
        return result

    @property
    def investigate_tool_calls(self) -> list[str]:
        inv_calls = [c for c in self.llm_calls if c.actor == "investigate"]
        tools: list[str] = []
        for c in inv_calls:
            tools.extend(c.tool_calls)
        return tools


class ShakedownHarness:
    """Drives scenarios through the real actor chain with canned data."""

    def __init__(
        self,
        llm: LLMClient,
        actor_dirs: list[Path] | None = None,
        scenario_dir: Path | None = None,
    ) -> None:
        self._llm = llm
        self._actor_dirs = actor_dirs or [
            Path(__file__).resolve().parents[2]
            / "src"
            / "mallcop"
            / "actors"
            / "triage",
            Path(__file__).resolve().parents[2]
            / "src"
            / "mallcop"
            / "actors"
            / "investigate",
        ]
        self._scenario_dir = scenario_dir or (
            Path(__file__).resolve().parent / "scenarios"
        )

    def run_scenario(self, scenario: Scenario) -> ShakedownResult:
        """Run a single scenario through the actor chain."""
        store = ScenarioStore(
            events=scenario.events,
            baseline=scenario.baseline,
            findings=[scenario.finding],
        )

        # Build canned connector tools from scenario definition
        extra_tools = self._build_canned_tools(scenario.connector_tools)

        # Create a minimal config for the actor runner
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            config_data = {
                "secrets": {"backend": "env"},
                "connectors": {},
                "routing": {
                    "critical": "triage",
                    "warn": "triage",
                    "info": "triage",
                },
            }
            with open(tmp_path / "mallcop.yaml", "w") as f:
                yaml.dump(config_data, f)
            config = load_config(tmp_path)

            # Wrap LLM for instrumentation
            instrumented = InstrumentedLLMClient(self._llm)

            runner = build_actor_runner(
                root=tmp_path,
                store=store,
                config=config,
                llm=instrumented,
                actor_dirs=self._actor_dirs,
                extra_tools=extra_tools or None,
            )

            if runner is None:
                raise RuntimeError(
                    "build_actor_runner returned None — no agent actors found"
                )

            chain_result = runner(scenario.finding, actor_name="triage")

        return ShakedownResult(
            scenario_id=scenario.id,
            chain_result=chain_result,
            llm_calls=list(instrumented.calls),
            store_mutations=store.get_mutations(),
        )

    def _build_canned_tools(
        self, tool_defs: list[ConnectorToolDef]
    ) -> list[Callable]:
        """Build @tool-decorated functions that return canned data."""
        tools: list[Callable] = []
        for td in tool_defs:
            canned_return = td.returns

            @tool(name=td.name, description=td.description, permission="read")
            def canned_tool(
                context: ToolContext, _returns=canned_return, **kwargs: Any
            ) -> Any:
                return _returns

            tools.append(canned_tool)
        return tools

    def run_scenarios(
        self, scenarios: list[Scenario]
    ) -> list[ShakedownResult]:
        """Run multiple scenarios, returning results for each."""
        return [self.run_scenario(s) for s in scenarios]

    def run_tagged(
        self,
        failure_mode: str | None = None,
        detector: str | None = None,
    ) -> list[ShakedownResult]:
        """Run scenarios filtered by tags."""
        scenarios = load_scenarios_tagged(
            self._scenario_dir,
            failure_mode=failure_mode,
            detector=detector,
        )
        return self.run_scenarios(scenarios)

    def run_all(self) -> list[ShakedownResult]:
        """Run all scenarios."""
        scenarios = load_all_scenarios(self._scenario_dir)
        return self.run_scenarios(scenarios)
