"""Shakedown evaluator: grades scenario results with LLM-as-judge."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

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
    verdict: Verdict
    action_correct: bool  # tracked for calibration; NOT the verdict gate
    reasoning_quality: int  # 1-5
    investigation_thoroughness: int  # 1-5
    resolve_quality: int  # 1-5: for resolves — is evidence trail auditable in 30 seconds?
    escalation_actionability: int  # 1-5: for escalates — can human decide in <1 minute?
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
Score based on whether the conclusion is SUPPORTED BY EVIDENCE, not on
prose style or narration length. Different models express reasoning
differently — a terse conclusion citing the right evidence scores the
same as a verbose step-by-step walkthrough.
1: No reasoning — guessed or gave generic response with no evidence
2: Conclusion stated but not supported — no specific events, timestamps, or baseline data cited
3: Adequate — conclusion references specific evidence (event IDs, actor names, baseline entries)
4: Good — conclusion cites specific evidence AND considers alternative explanations
5: Excellent — thorough evidence chain, addressed the trap/deceptive element, expressed appropriate confidence

### investigation_thoroughness (1-5)
1: No investigation — decided without using tools
2: Minimal — used 1 tool but didn't follow up
3: Adequate — used relevant tools, got useful data
4: Good — systematic investigation, multiple tools, cross-referenced results
5: Excellent — exhaustive investigation, checked all relevant data sources

### resolve_quality (1-5) — rate ONLY when agent resolved; set 1 if escalated
Could a human spot-check this resolution in under 30 seconds from the evidence trail?
1: No evidence trail — impossible to verify
2: Vague evidence — human can't quickly confirm
3: Adequate trail — key facts stated, checkable
4: Good trail — specific events, timestamps, baseline refs cited
5: Excellent — airtight case, all signals addressed, trivial to spot-check

### escalation_actionability (1-5) — rate ONLY when agent escalated; set 1 if resolved
Could a human decide what to do in under 1 minute from the escalation summary?
1: No useful context — human starts from scratch
2: Minimal context — where to start is unclear
3: Adequate — key facts present, human can decide
4: Good — investigation already done, clear decision point
5: Excellent — human just needs to confirm, answer is obvious from evidence

## Required Output
Respond with ONLY a JSON object (no markdown, no explanation outside the JSON):
{{
  "reasoning_quality": <1-5>,
  "investigation_thoroughness": <1-5>,
  "resolve_quality": <1-5>,
  "escalation_actionability": <1-5>,
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
        resolve_quality = 1
        escalation_actionability = 1
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
            resolve_quality = int(parsed.get("resolve_quality", 1))
            escalation_actionability = int(parsed.get("escalation_actionability", 1))
            judge_reasoning = str(parsed.get("reasoning", ""))
            raw_fix_target = parsed.get("fix_target") or None
            fix_hint = parsed.get("fix_hint") or None
        except Exception as exc:
            _log.warning("Failed to parse judge response: %s", exc)
            judge_reasoning = f"Parse error: {exc}"

        # Clamp scores to valid range
        reasoning_quality = max(1, min(5, reasoning_quality))
        investigation_thoroughness = max(1, min(5, investigation_thoroughness))
        resolve_quality = max(1, min(5, resolve_quality))
        escalation_actionability = max(1, min(5, escalation_actionability))

        # 5. Determine verdict — investigation quality gates verdict, not action_correct
        # PASS: investigation_thoroughness >= 3 AND reasoning_quality >= 3 AND
        #        (resolve_quality >= 3 OR escalation_actionability >= 3)
        # WARN: action correct but reasoning_quality < 3 (lucky guess)
        # FAIL: investigation_thoroughness < 3 OR reasoning_quality < 2
        if investigation_thoroughness < 3 or reasoning_quality < 2:
            verdict = Verdict.FAIL
        elif action_correct and reasoning_quality < 3:
            verdict = Verdict.WARN  # right action, shallow reasoning = lucky guess
        elif (resolve_quality >= 3 or escalation_actionability >= 3) and reasoning_quality >= 3:
            verdict = Verdict.PASS
        else:
            verdict = Verdict.WARN

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
            resolve_quality=resolve_quality,
            escalation_actionability=escalation_actionability,
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


def compute_run_summary(grades: list[Grade], results: list[Any]) -> dict[str, Any]:
    """Compute aggregate metrics from a shakedown run.

    Returns:
        pass_rate: float — fraction of scenarios with PASS verdict
        action_correct_rate: float — fraction where agent matched expected action
          (calibration metric: compare to pass_rate over time)
        resolve_rate: float — fraction of scenarios where agent resolved
          (higher is better IF pass_rate is high — tracks model efficiency improvement)
        total_tokens: int — total tokens consumed
        fail_count: int
        warn_count: int
        pass_count: int
    """
    if not grades:
        return {
            "pass_rate": 0.0,
            "action_correct_rate": 0.0,
            "resolve_rate": 0.0,
            "total_tokens": 0,
            "fail_count": 0,
            "warn_count": 0,
            "pass_count": 0,
        }

    total = len(grades)
    pass_count = sum(1 for g in grades if g.verdict == Verdict.PASS)
    warn_count = sum(1 for g in grades if g.verdict == Verdict.WARN)
    fail_count = sum(1 for g in grades if g.verdict == Verdict.FAIL)
    action_correct_count = sum(1 for g in grades if g.action_correct)
    total_tokens = sum(g.tokens for g in grades)

    # Resolve rate: count scenarios where agent action was "resolved" (regardless of correctness)
    resolve_count = sum(
        1 for r in results
        if getattr(r, "chain_action", "") == "resolved"
    )

    return {
        "pass_rate": pass_count / total,
        "action_correct_rate": action_correct_count / total,
        "resolve_rate": resolve_count / total,
        "total_tokens": total_tokens,
        "pass_count": pass_count,
        "warn_count": warn_count,
        "fail_count": fail_count,
    }


