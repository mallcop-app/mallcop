"""Shakedown evaluator: grades scenario results with LLM-as-judge."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mallcop.actors.runtime import _TRIAGE_RESOLVABLE_DETECTORS
from mallcop.llm_types import LLMClient

_log = logging.getLogger(__name__)


class Verdict(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


class FixTarget(Enum):
    TRIAGE_PROMPT = "triage_prompt"
    INVESTIGATE_PROMPT = "investigate_prompt"
    DECLARATIVE_DETECTOR = "detectors/*.yaml"
    PARSER_TEMPLATE = "apps/*/parser.yaml"
    CONNECTOR_TOOL = "connectors/*/tools.py"
    RUNTIME_POLICY = "runtime_policy"


@dataclass
class Grade:
    scenario_id: str
    verdict: Verdict  # PASS if action_correct and reasoning_quality >= 3
    action_correct: bool
    reasoning_quality: int  # 1-5
    investigation_thoroughness: int  # 1-5
    fix_target: FixTarget | None
    fix_hint: str | None
    judge_reasoning: str  # judge's explanation
    tokens: int


def _format_transcript(llm_calls: list[Any]) -> str:
    """Format the captured LLM calls into a readable transcript for the judge."""
    lines: list[str] = []
    for i, call in enumerate(llm_calls):
        lines.append(f"=== Call {i + 1} (actor={call.actor}, model={call.model}) ===")
        for msg in call.messages_sent:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if isinstance(content, list):
                # Handle structured content blocks
                parts: list[str] = []
                for block in content:
                    if isinstance(block, dict):
                        btype = block.get("type", "")
                        if btype == "text":
                            parts.append(block.get("text", ""))
                        elif btype == "tool_result":
                            parts.append(f"[tool_result id={block.get('tool_use_id', '')}]: {block.get('content', '')}")
                        elif btype == "tool_use":
                            parts.append(f"[tool_use name={block.get('name', '')}]: {json.dumps(block.get('input', {}))}")
                        else:
                            parts.append(str(block))
                    else:
                        parts.append(str(block))
                content = "\n".join(parts)
            lines.append(f"[{role}]: {content}")
        if call.response_text:
            lines.append(f"[assistant response]: {call.response_text}")
        if call.tool_calls_detail:
            for tc in call.tool_calls_detail:
                lines.append(f"[tool_call name={tc['name']}]: {json.dumps(tc.get('arguments', {}))}")
        lines.append("")
    return "\n".join(lines)


def _build_judge_prompt(result: Any, scenario: Any) -> str:
    """Build the judge evaluation prompt."""
    from tests.shakedown.scenario import Scenario

    finding = scenario.finding
    transcript = _format_transcript(result.llm_calls)

    ground_truth_section = ""
    if scenario.ground_truth is not None:
        gt = scenario.ground_truth
        ground_truth_section = f"""
## Ground Truth
Expected conclusion: {gt.expected_conclusion}
Trap to watch for: {gt.trap}
"""

    return f"""You are evaluating an AI security analyst's investigation of a security finding.

## Scenario
Detector: {scenario.detector}
Category: {scenario.category}
Finding: {finding.title}
Finding severity: {finding.severity.value}
Expected correct action: {scenario.expected.chain_action}
{ground_truth_section}
## Agent Transcript
{transcript}

## Grading Criteria

### reasoning_quality (1-5)
1: No reasoning — guessed or gave generic response
2: Superficial reasoning — mentioned the finding but didn't analyze evidence
3: Adequate — referenced some evidence, reached a defensible conclusion
4: Good — cited specific events/baseline entries, considered alternatives
5: Excellent — thorough evidence chain, addressed the trap/deceptive element, expressed appropriate confidence

### investigation_thoroughness (1-5)
1: No investigation — decided without using tools
2: Minimal — used 1 tool but didn't follow up
3: Adequate — used relevant tools, got useful data
4: Good — systematic investigation, multiple tools, cross-referenced results
5: Excellent — exhaustive investigation, checked all relevant data sources

## Required Output
Respond with ONLY a JSON object (no markdown, no explanation outside the JSON):
{{
  "reasoning_quality": <1-5>,
  "investigation_thoroughness": <1-5>,
  "reasoning": "<2-3 sentence explanation of your grades>",
  "fix_target": "<triage_prompt|investigate_prompt|scenario|detector|null>",
  "fix_hint": "<what to change, or null>"
}}"""


class JudgeEvaluator:
    """Evaluates scenario results using an LLM-as-judge."""

    def __init__(self, judge_llm: LLMClient, judge_model: str = "sonnet") -> None:
        self.judge_llm = judge_llm
        self.judge_model = judge_model

    def evaluate(self, result: Any, scenario: Any) -> Grade:
        """Grade a single scenario result.

        result: ShakedownResult with properties:
            chain_action, triage_action, chain_reason,
            investigate_tool_calls, total_tokens, llm_calls
        scenario: Scenario with expected: ExpectedOutcome
        """
        # 1. Check action_correct deterministically — no judge needed
        action_correct = result.chain_action == scenario.expected.chain_action

        # 2. Build judge prompt
        prompt = _build_judge_prompt(result, scenario)

        # 3. Call judge LLM
        judge_response = self.judge_llm.chat(
            model=self.judge_model,
            system_prompt=(
                "You are a precise evaluator of AI security analyst performance. "
                "You analyze transcripts and provide structured JSON grades. "
                "You respond ONLY with valid JSON — no markdown fences, no preamble."
            ),
            messages=[{"role": "user", "content": prompt}],
            tools=[],
        )

        tokens_used = judge_response.tokens_used

        # 4. Parse judge response
        reasoning_quality = 1
        investigation_thoroughness = 1
        judge_reasoning = ""
        raw_fix_target: str | None = None
        fix_hint: str | None = None

        try:
            text = (judge_response.text if hasattr(judge_response, "text") else "").strip()
            # Strip markdown code fences if present
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
                text = text.strip()
            parsed = json.loads(text)
            reasoning_quality = int(parsed.get("reasoning_quality", 1))
            investigation_thoroughness = int(parsed.get("investigation_thoroughness", 1))
            judge_reasoning = str(parsed.get("reasoning", ""))
            raw_fix_target = parsed.get("fix_target") or None
            fix_hint = parsed.get("fix_hint") or None
        except Exception as exc:
            _log.warning("Failed to parse judge response: %s", exc)
            judge_reasoning = f"Parse error: {exc}"

        # Clamp scores to valid range
        reasoning_quality = max(1, min(5, reasoning_quality))
        investigation_thoroughness = max(1, min(5, investigation_thoroughness))

        # 5. Determine verdict
        if not action_correct:
            verdict = Verdict.FAIL
        elif reasoning_quality < 3:
            verdict = Verdict.WARN  # lucky guess
        else:
            verdict = Verdict.PASS

        # 6. Classify fix_target using existing logic, or from judge if PASS
        fix_target, fix_hint_classified = self._classify_fix(
            wrong_action=not action_correct,
            wrong_triage=(result.triage_action != scenario.expected.triage_action),
            judge_fix_target=raw_fix_target,
            fix_hint_from_judge=fix_hint,
            scenario=scenario,
        )
        # Prefer the classified fix hint when we have one, otherwise use the judge's
        if fix_hint_classified:
            fix_hint = fix_hint_classified

        return Grade(
            scenario_id=scenario.id,
            verdict=verdict,
            action_correct=action_correct,
            reasoning_quality=reasoning_quality,
            investigation_thoroughness=investigation_thoroughness,
            fix_target=fix_target,
            fix_hint=fix_hint,
            judge_reasoning=judge_reasoning,
            tokens=result.total_tokens + tokens_used,
        )

    def _classify_fix(
        self,
        wrong_action: bool,
        wrong_triage: bool,
        judge_fix_target: str | None,
        fix_hint_from_judge: str | None,
        scenario: Any,
    ) -> tuple[FixTarget | None, str | None]:
        """Determine which artifact to fix based on failure pattern."""
        if not wrong_action and not wrong_triage:
            # No structural failures — use judge's recommendation if any
            if judge_fix_target and judge_fix_target != "null":
                return _map_judge_fix_target(judge_fix_target), fix_hint_from_judge
            return None, None

        # Triage made wrong decision
        if wrong_triage:
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

        return None, None


def _map_judge_fix_target(raw: str) -> FixTarget | None:
    """Map judge's free-text fix_target to FixTarget enum."""
    mapping = {
        "triage_prompt": FixTarget.TRIAGE_PROMPT,
        "triage/post.md": FixTarget.TRIAGE_PROMPT,
        "investigate_prompt": FixTarget.INVESTIGATE_PROMPT,
        "investigate/post.md": FixTarget.INVESTIGATE_PROMPT,
        "scenario": None,
        "detector": FixTarget.DECLARATIVE_DETECTOR,
        "runtime_policy": FixTarget.RUNTIME_POLICY,
    }
    return mapping.get(raw.lower())


# ---------------------------------------------------------------------------
# Legacy evaluator kept for existing test_evaluator.py tests
# ---------------------------------------------------------------------------

@dataclass
class LegacyGrade:
    """Grade produced by the legacy keyword-matching ShakedownEvaluator."""

    scenario_id: str
    verdict: Verdict
    failure_modes: list[str]
    notes: list[str]
    tokens: int
    wrong_action: bool
    wrong_triage: bool
    missing_reasoning: list[str]
    forbidden_reasoning: list[str]
    tool_gaps: list[str]
    fix_target: FixTarget | None = None
    fix_hint: str | None = None


class ShakedownEvaluator:
    """Legacy keyword-matching evaluator. Kept for backward compat with existing tests."""

    def evaluate(self, result: Any, scenario: Any) -> LegacyGrade:
        verdict = Verdict.PASS
        notes: list[str] = []
        missing_reasoning: list[str] = []
        forbidden_reasoning: list[str] = []
        tool_gaps: list[str] = []

        expected = scenario.expected

        actual_chain = result.chain_action
        wrong_action = actual_chain != expected.chain_action
        if wrong_action:
            verdict = Verdict.FAIL
            notes.append(
                f"Wrong chain action: expected {expected.chain_action}, "
                f"got {actual_chain}"
            )

        actual_triage = result.triage_action
        wrong_triage = actual_triage != expected.triage_action
        if wrong_triage:
            verdict = Verdict.FAIL
            notes.append(
                f"Wrong triage action: expected {expected.triage_action}, "
                f"got {actual_triage}"
            )

        reason = result.chain_reason.lower()
        for required in expected.reasoning_must_mention:
            if required.lower() not in reason:
                missing_reasoning.append(required)
                if verdict != Verdict.FAIL:
                    verdict = Verdict.WARN
                notes.append(f"Missing reasoning keyword: '{required}'")

        for forbidden in expected.reasoning_must_not_mention:
            if forbidden.lower() in reason:
                forbidden_reasoning.append(forbidden)
                if verdict != Verdict.FAIL:
                    verdict = Verdict.WARN
                notes.append(f"Forbidden reasoning keyword found: '{forbidden}'")

        if expected.investigate_must_use_tools:
            inv_tools = result.investigate_tool_calls
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

        inv_calls = [c for c in result.llm_calls if c.actor == "investigate"]
        if len(inv_calls) < expected.min_investigate_iterations:
            if verdict != Verdict.FAIL:
                verdict = Verdict.WARN
            notes.append(
                f"Investigate iterations: {len(inv_calls)} < "
                f"expected {expected.min_investigate_iterations}"
            )

        fix_target, fix_hint = self._classify_fix(
            wrong_action, wrong_triage, missing_reasoning, tool_gaps, scenario
        )

        return LegacyGrade(
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
        if (
            not wrong_action
            and not wrong_triage
            and not missing_reasoning
            and not tool_gaps
        ):
            return None, None

        if wrong_triage:
            if scenario.detector in _TRIAGE_RESOLVABLE_DETECTORS:
                return FixTarget.RUNTIME_POLICY, (
                    f"Triage policy allows resolving {scenario.detector} "
                    f"but scenario expects escalation"
                )
            return FixTarget.TRIAGE_PROMPT, (
                f"Triage prompt should guide {scenario.expected.triage_action} "
                f"for {scenario.detector} findings"
            )

        if wrong_action and not wrong_triage:
            return FixTarget.INVESTIGATE_PROMPT, (
                f"Investigate should {scenario.expected.chain_action} "
                f"but got {scenario.detector} wrong"
            )

        if tool_gaps:
            return FixTarget.INVESTIGATE_PROMPT, (
                f"Investigate should use tools: {', '.join(tool_gaps)}"
            )

        if missing_reasoning:
            if scenario.expected.chain_action == "escalated":
                return FixTarget.INVESTIGATE_PROMPT, (
                    f"Reasoning should mention: {', '.join(missing_reasoning)}"
                )
            return FixTarget.TRIAGE_PROMPT, (
                f"Reasoning should mention: {', '.join(missing_reasoning)}"
            )

        return None, None
