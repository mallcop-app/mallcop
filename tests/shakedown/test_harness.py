"""Tests for InstrumentedLLMClient, ShakedownResult, and ShakedownHarness."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.llm_types import LLMClient, LLMResponse, ToolCall
from mallcop.schemas import Baseline, Event, Finding, FindingStatus, Severity

from tests.shakedown.harness import (
    CapturedCall,
    InstrumentedLLMClient,
    ShakedownHarness,
    ShakedownResult,
)
from tests.shakedown.scenario import ConnectorToolDef, ExpectedOutcome, Scenario


# ── Helpers ──────────────────────────────────────────────────────────────


def _make_finding(
    finding_id: str = "f-001",
    detector: str = "new-actor",
    severity: Severity = Severity.WARN,
) -> Finding:
    return Finding(
        id=finding_id,
        timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        detector=detector,
        event_ids=["e-001"],
        title="Test finding",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": "admin-user@acme-corp.com"},
    )


def _make_event(event_id: str = "e-001") -> Event:
    return Event(
        id=event_id,
        timestamp=datetime(2026, 1, 15, 9, 55, 0, tzinfo=timezone.utc),
        ingested_at=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        source="azure",
        event_type="Microsoft.Authorization/roleAssignments/write",
        actor="admin-user@acme-corp.com",
        action="write",
        target="/subscriptions/abc/providers/Microsoft.Authorization/roleAssignments/xyz",
        severity=Severity.WARN,
        metadata={},
        raw={},
    )


def _make_baseline() -> Baseline:
    return Baseline(
        frequency_tables={"azure:action:admin-user@acme-corp.com": 5},
        known_entities={"actors": ["admin-user@acme-corp.com"]},
        relationships={},
    )


def _make_scenario(
    scenario_id: str = "test-scenario-001",
    detector: str = "new-actor",
    connector_tools: list[ConnectorToolDef] | None = None,
) -> Scenario:
    return Scenario(
        id=scenario_id,
        failure_mode="KA",
        detector=detector,
        category="identity",
        difficulty="benign-obvious",
        trap_description="Known actor triggered new-actor detector",
        trap_resolved_means="Triage resolves as known",
        finding=_make_finding(detector=detector),
        events=[_make_event()],
        baseline=_make_baseline(),
        expected=ExpectedOutcome(
            chain_action="resolved",
            triage_action="resolved",
        ),
        connector_tools=connector_tools or [],
        tags=["KA"],
    )


class MockResolveLLM(LLMClient):
    """Mock LLM that resolves at triage via resolve-finding tool call."""

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        return LLMResponse(
            tool_calls=[
                ToolCall(
                    name="resolve-finding",
                    arguments={
                        "finding_id": "f-001",
                        "action": "resolved",
                        "reason": "Known actor, routine activity",
                    },
                )
            ],
            resolution=None,
            tokens_used=150,
        )


class MockEscalateLLM(LLMClient):
    """Mock LLM that escalates from triage and resolves at investigate."""

    def __init__(self) -> None:
        self._call_count = 0

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        self._call_count += 1
        prompt_lower = system_prompt.lower()[:200]
        # Check investigate first — investigate POST.md mentions "triage" as substring
        is_investigate = "level-2" in prompt_lower or "investigation agent" in prompt_lower
        is_triage = not is_investigate and "triage" in prompt_lower

        if is_triage:
            # Triage escalates
            return LLMResponse(
                tool_calls=[
                    ToolCall(
                        name="resolve-finding",
                        arguments={
                            "finding_id": "f-001",
                            "action": "escalated",
                            "reason": "Needs deeper investigation",
                        },
                    )
                ],
                resolution=None,
                tokens_used=200,
            )
        else:
            # Investigate resolves
            return LLMResponse(
                tool_calls=[
                    ToolCall(
                        name="resolve-finding",
                        arguments={
                            "finding_id": "f-001",
                            "action": "resolved",
                            "reason": "Investigated and cleared",
                        },
                    )
                ],
                resolution=None,
                tokens_used=300,
            )


# ── Tests ────────────────────────────────────────────────────────────────


class TestInstrumentedLLMClient:
    def test_captures_calls(self):
        """InstrumentedLLMClient records CapturedCall for each chat() invocation."""
        inner = MockResolveLLM()
        instrumented = InstrumentedLLMClient(inner)

        response = instrumented.chat(
            model="haiku",
            system_prompt="You are the triage agent.",
            messages=[{"role": "user", "content": "hello"}],
            tools=[],
        )

        assert len(instrumented.calls) == 1
        call = instrumented.calls[0]
        assert call.actor == "triage"
        assert call.model == "haiku"
        assert call.message_count == 1
        assert call.tool_calls == ["resolve-finding"]
        assert call.has_resolution is False  # resolution is None, raw_resolution is None
        assert call.tokens_used == 150

        # Verify the response is passed through correctly
        assert len(response.tool_calls) == 1
        assert response.tool_calls[0].name == "resolve-finding"

    def test_infer_actor_triage(self):
        """_infer_actor detects triage from system prompt."""
        inner = MockResolveLLM()
        instrumented = InstrumentedLLMClient(inner)

        assert instrumented._infer_actor("You are the triage agent.") == "triage"
        assert instrumented._infer_actor("Level-1 security analyst") == "triage"

    def test_infer_actor_investigate(self):
        """_infer_actor detects investigate from system prompt."""
        inner = MockResolveLLM()
        instrumented = InstrumentedLLMClient(inner)

        assert instrumented._infer_actor("You are a Level-2 security investigation agent.") == "investigate"
        assert instrumented._infer_actor("Level-2 investigation specialist") == "investigate"

    def test_infer_actor_unknown(self):
        """_infer_actor returns unknown for unrecognized prompts."""
        inner = MockResolveLLM()
        instrumented = InstrumentedLLMClient(inner)

        assert instrumented._infer_actor("You are a helpful assistant.") == "unknown"

    def test_reset_clears_calls(self):
        """reset() clears all captured calls."""
        inner = MockResolveLLM()
        instrumented = InstrumentedLLMClient(inner)

        instrumented.chat("haiku", "triage agent", [{"role": "user", "content": "hi"}], [])
        assert len(instrumented.calls) == 1

        instrumented.reset()
        assert len(instrumented.calls) == 0


class TestShakedownResult:
    def test_total_tokens(self):
        """total_tokens sums tokens across all LLM calls."""
        result = ShakedownResult(
            scenario_id="test-001",
            chain_result=RunResult(
                resolution=ActorResolution(
                    finding_id="f-001",
                    action=ResolutionAction.RESOLVED,
                    reason="All clear",
                ),
                tokens_used=450,
                iterations=2,
            ),
            llm_calls=[
                CapturedCall(
                    actor="triage", model="haiku", tokens_used=200,
                    latency_ms=10,
                    messages_sent=[{}, {}, {}],
                    response_text="",
                    tool_calls_detail=[{"name": "resolve-finding", "arguments": {}}],
                    has_resolution=False,
                ),
                CapturedCall(
                    actor="investigate", model="haiku", tokens_used=250,
                    latency_ms=10,
                    messages_sent=[{}, {}, {}, {}, {}],
                    response_text="",
                    tool_calls_detail=[
                        {"name": "read-events", "arguments": {}},
                        {"name": "resolve-finding", "arguments": {}},
                    ],
                    has_resolution=False,
                ),
            ],
            store_mutations=[],
        )

        assert result.total_tokens == 450

    def test_chain_action(self):
        """chain_action returns the resolution action value."""
        result = ShakedownResult(
            scenario_id="test-001",
            chain_result=RunResult(
                resolution=ActorResolution(
                    finding_id="f-001",
                    action=ResolutionAction.RESOLVED,
                    reason="Done",
                ),
                tokens_used=100,
                iterations=1,
            ),
            llm_calls=[],
            store_mutations=[],
        )

        assert result.chain_action == "resolved"

    def test_chain_action_unknown_when_no_resolution(self):
        """chain_action returns 'unknown' when no resolution exists."""
        result = ShakedownResult(
            scenario_id="test-001",
            chain_result=RunResult(resolution=None, tokens_used=0, iterations=0),
            llm_calls=[],
            store_mutations=[],
        )

        assert result.chain_action == "unknown"

    def test_chain_reason(self):
        """chain_reason returns the resolution reason."""
        result = ShakedownResult(
            scenario_id="test-001",
            chain_result=RunResult(
                resolution=ActorResolution(
                    finding_id="f-001",
                    action=ResolutionAction.ESCALATED,
                    reason="Suspicious activity detected",
                ),
                tokens_used=100,
                iterations=1,
            ),
            llm_calls=[],
            store_mutations=[],
        )

        assert result.chain_reason == "Suspicious activity detected"

    def test_chain_reason_empty_when_no_resolution(self):
        """chain_reason returns empty string when no resolution."""
        result = ShakedownResult(
            scenario_id="test-001",
            chain_result=RunResult(resolution=None, tokens_used=0, iterations=0),
            llm_calls=[],
            store_mutations=[],
        )

        assert result.chain_reason == ""

    def test_triage_action_resolved(self):
        """triage_action returns 'resolved' when triage resolved and was only call."""
        result = ShakedownResult(
            scenario_id="test-001",
            chain_result=RunResult(
                resolution=ActorResolution(
                    finding_id="f-001",
                    action=ResolutionAction.RESOLVED,
                    reason="OK",
                ),
                tokens_used=100,
                iterations=1,
            ),
            llm_calls=[
                CapturedCall(
                    actor="triage", model="haiku", tokens_used=100,
                    latency_ms=10,
                    messages_sent=[{}, {}, {}],
                    response_text="",
                    tool_calls_detail=[{"name": "resolve-finding", "arguments": {}}],
                    has_resolution=True,
                ),
            ],
            store_mutations=[],
        )

        assert result.triage_action == "resolved"

    def test_triage_action_escalated(self):
        """triage_action returns 'escalated' when triage resolved but chain continued."""
        result = ShakedownResult(
            scenario_id="test-001",
            chain_result=RunResult(
                resolution=ActorResolution(
                    finding_id="f-001",
                    action=ResolutionAction.RESOLVED,
                    reason="OK",
                ),
                tokens_used=500,
                iterations=2,
            ),
            llm_calls=[
                CapturedCall(
                    actor="triage", model="haiku", tokens_used=200,
                    latency_ms=10,
                    messages_sent=[{}, {}, {}],
                    response_text="",
                    tool_calls_detail=[{"name": "resolve-finding", "arguments": {}}],
                    has_resolution=True,
                ),
                CapturedCall(
                    actor="investigate", model="haiku", tokens_used=300,
                    latency_ms=10,
                    messages_sent=[{}, {}, {}, {}, {}],
                    response_text="",
                    tool_calls_detail=[{"name": "resolve-finding", "arguments": {}}],
                    has_resolution=True,
                ),
            ],
            store_mutations=[],
        )

        assert result.triage_action == "escalated"

    def test_investigate_tool_calls(self):
        """investigate_tool_calls collects tool calls from investigate actor only."""
        result = ShakedownResult(
            scenario_id="test-001",
            chain_result=RunResult(
                resolution=ActorResolution(
                    finding_id="f-001",
                    action=ResolutionAction.RESOLVED,
                    reason="OK",
                ),
                tokens_used=500,
                iterations=2,
            ),
            llm_calls=[
                CapturedCall(
                    actor="triage", model="haiku", tokens_used=200,
                    latency_ms=10,
                    messages_sent=[{}, {}, {}],
                    response_text="",
                    tool_calls_detail=[{"name": "resolve-finding", "arguments": {}}],
                    has_resolution=True,
                ),
                CapturedCall(
                    actor="investigate", model="haiku", tokens_used=300,
                    latency_ms=10,
                    messages_sent=[{}, {}, {}, {}, {}],
                    response_text="",
                    tool_calls_detail=[
                        {"name": "read-events", "arguments": {}},
                        {"name": "check-baseline", "arguments": {}},
                    ],
                    has_resolution=False,
                ),
            ],
            store_mutations=[],
        )

        assert result.investigate_tool_calls == ["read-events", "check-baseline"]


class TestShakedownHarness:
    def test_run_scenario_with_mock_resolve(self):
        """ShakedownHarness.run_scenario returns correct ShakedownResult for triage resolve."""
        scenario = _make_scenario()
        harness = ShakedownHarness(llm=MockResolveLLM())

        result = harness.run_scenario(scenario)

        assert result.scenario_id == "test-scenario-001"
        assert result.chain_result.resolution is not None
        assert result.chain_result.resolution.action == ResolutionAction.RESOLVED
        assert len(result.llm_calls) >= 1
        assert result.llm_calls[0].actor == "triage"

    def test_run_scenario_escalation(self):
        """ShakedownHarness.run_scenario captures both triage and investigate calls."""
        scenario = _make_scenario()
        harness = ShakedownHarness(llm=MockEscalateLLM())

        result = harness.run_scenario(scenario)

        assert result.chain_result.resolution is not None
        # Triage escalated, investigate resolved
        assert result.chain_result.resolution.action == ResolutionAction.RESOLVED
        assert result.chain_result.resolution.reason == "Investigated and cleared"

        # Should have calls from both actors
        actors = [c.actor for c in result.llm_calls]
        assert "triage" in actors
        assert "investigate" in actors

        # Total tokens should be sum of both
        assert result.total_tokens == sum(c.tokens_used for c in result.llm_calls)

    def test_canned_connector_tools(self):
        """Scenario connector_tools are registered and return canned data."""
        connector_tools = [
            ConnectorToolDef(
                name="query-azure-logs",
                description="Query Azure activity logs",
                parameter_schema={},
                returns={"events": [{"id": "e-canned"}]},
            ),
        ]
        scenario = _make_scenario(connector_tools=connector_tools)

        harness = ShakedownHarness(llm=MockResolveLLM())

        # Verify canned tools are built correctly
        built = harness._build_canned_tools(scenario.connector_tools)
        assert len(built) == 1
        assert built[0]._tool_meta.name == "query-azure-logs"
        assert built[0]._tool_meta.description == "Query Azure activity logs"
        assert built[0]._tool_meta.permission == "read"

    def test_run_scenarios_multiple(self):
        """run_scenarios processes each scenario and returns list of results."""
        scenarios = [
            _make_scenario(scenario_id="s-001"),
            _make_scenario(scenario_id="s-002"),
        ]
        harness = ShakedownHarness(llm=MockResolveLLM())

        results = harness.run_scenarios(scenarios)

        assert len(results) == 2
        assert results[0].scenario_id == "s-001"
        assert results[1].scenario_id == "s-002"
