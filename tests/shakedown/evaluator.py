"""Shakedown evaluator: grades scenario results with machine-readable output."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mallcop.actors.runtime import _TRIAGE_RESOLVABLE_DETECTORS


class Verdict(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


class FixTarget(Enum):
    TRIAGE_PROMPT = "triage/POST.md"
    INVESTIGATE_PROMPT = "investigate/POST.md"
    DECLARATIVE_DETECTOR = "detectors/*.yaml"
    PARSER_TEMPLATE = "apps/*/parser.yaml"
    CONNECTOR_TOOL = "connectors/*/tools.py"
    RUNTIME_POLICY = "actors/runtime.py"


@dataclass
class Grade:
    scenario_id: str
    verdict: Verdict
    failure_modes: list[str]
    notes: list[str]
    tokens: int

    # Machine-readable root cause
    wrong_action: bool
    wrong_triage: bool
    missing_reasoning: list[str]
    forbidden_reasoning: list[str]
    tool_gaps: list[str]

    # Coding agent guidance
    fix_target: FixTarget | None = None
    fix_hint: str | None = None


class ShakedownEvaluator:
    """Evaluates scenario results against expected outcomes."""

    def evaluate(self, result: Any, scenario: Any) -> Grade:
        """Grade a single scenario result.

        result: ShakedownResult (duck-typed) with properties:
            chain_action, triage_action, chain_reason,
            investigate_tool_calls, total_tokens, llm_calls
        scenario: Scenario with expected: ExpectedOutcome
        """
        verdict = Verdict.PASS
        notes: list[str] = []
        missing_reasoning: list[str] = []
        forbidden_reasoning: list[str] = []
        tool_gaps: list[str] = []

        expected = scenario.expected

        # 1. Chain action correct?
        actual_chain = result.chain_action
        wrong_action = actual_chain != expected.chain_action
        if wrong_action:
            verdict = Verdict.FAIL
            notes.append(
                f"Wrong chain action: expected {expected.chain_action}, "
                f"got {actual_chain}"
            )

        # 2. Triage action correct?
        actual_triage = result.triage_action
        wrong_triage = actual_triage != expected.triage_action
        if wrong_triage:
            verdict = Verdict.FAIL
            notes.append(
                f"Wrong triage action: expected {expected.triage_action}, "
                f"got {actual_triage}"
            )

        # 3. Reasoning quality — required keywords present?
        reason = result.chain_reason.lower()
        for required in expected.reasoning_must_mention:
            if required.lower() not in reason:
                missing_reasoning.append(required)
                if verdict != Verdict.FAIL:
                    verdict = Verdict.WARN
                notes.append(f"Missing reasoning keyword: '{required}'")

        # 4. Reasoning quality — forbidden keywords absent?
        for forbidden in expected.reasoning_must_not_mention:
            if forbidden.lower() in reason:
                forbidden_reasoning.append(forbidden)
                if verdict != Verdict.FAIL:
                    verdict = Verdict.WARN
                notes.append(f"Forbidden reasoning keyword found: '{forbidden}'")

        # 5. Investigation depth — tools used?
        if expected.investigate_must_use_tools:
            inv_tools = result.investigate_tool_calls
            # Filter out resolve-finding and annotate-finding — those are
            # resolution tools, not investigation tools
            investigation_tools = [
                t
                for t in inv_tools
                if t not in ("resolve-finding", "annotate-finding")
            ]
            if not investigation_tools:
                tool_gaps.append("any-investigation-tool")
                if verdict != Verdict.FAIL:
                    verdict = Verdict.WARN
                notes.append("Investigate did not use any investigation tools")

        # 6. Minimum investigate iterations
        inv_calls = [c for c in result.llm_calls if c.actor == "investigate"]
        if len(inv_calls) < expected.min_investigate_iterations:
            if verdict != Verdict.FAIL:
                verdict = Verdict.WARN
            notes.append(
                f"Investigate iterations: {len(inv_calls)} < "
                f"expected {expected.min_investigate_iterations}"
            )

        # 7. Classify fix target for coding agent
        fix_target, fix_hint = self._classify_fix(
            wrong_action, wrong_triage, missing_reasoning, tool_gaps, scenario
        )

        return Grade(
            scenario_id=scenario.id,
            verdict=verdict,
            failure_modes=[scenario.failure_mode],
            notes=notes,
            tokens=result.total_tokens,
            wrong_action=wrong_action,
            wrong_triage=wrong_triage,
            missing_reasoning=missing_reasoning,
            forbidden_reasoning=forbidden_reasoning,
            tool_gaps=tool_gaps,
            fix_target=fix_target,
            fix_hint=fix_hint,
        )

    def _classify_fix(
        self,
        wrong_action: bool,
        wrong_triage: bool,
        missing_reasoning: list[str],
        tool_gaps: list[str],
        scenario: Any,
    ) -> tuple[FixTarget | None, str | None]:
        """Determine which artifact to fix based on failure pattern."""
        if (
            not wrong_action
            and not wrong_triage
            and not missing_reasoning
            and not tool_gaps
        ):
            return None, None

        # Triage made wrong decision
        if wrong_triage:
            # Check if this is a policy issue (detector should be in resolvable set)
            # vs a prompt issue (triage prompt doesn't guide correctly)
            if scenario.detector in _TRIAGE_RESOLVABLE_DETECTORS:
                return FixTarget.RUNTIME_POLICY, (
                    f"Triage policy allows resolving {scenario.detector} "
                    f"but scenario expects escalation"
                )
            return FixTarget.TRIAGE_PROMPT, (
                f"Triage prompt should guide {scenario.expected.triage_action} "
                f"for {scenario.detector} findings"
            )

        # Investigation made wrong final decision
        if wrong_action and not wrong_triage:
            return FixTarget.INVESTIGATE_PROMPT, (
                f"Investigate should {scenario.expected.chain_action} "
                f"but got {scenario.detector} wrong"
            )

        # Tool gaps
        if tool_gaps:
            return FixTarget.INVESTIGATE_PROMPT, (
                f"Investigate should use tools: {', '.join(tool_gaps)}"
            )

        # Missing reasoning keywords (prompt quality)
        if missing_reasoning:
            # Determine which actor's prompt based on where the failure is
            if scenario.expected.chain_action == "escalated":
                return FixTarget.INVESTIGATE_PROMPT, (
                    f"Reasoning should mention: {', '.join(missing_reasoning)}"
                )
            return FixTarget.TRIAGE_PROMPT, (
                f"Reasoning should mention: {', '.join(missing_reasoning)}"
            )

        return None, None
