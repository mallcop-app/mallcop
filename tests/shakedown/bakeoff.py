"""Bakeoff orchestrator: run Academy Exam against multiple Bedrock models.

Reads model catalog from pricing.yaml, runs all scenarios per model,
grades with LLM-as-judge, and produces a diffable summary JSON with
routing recommendations.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mallcop.llm.bedrock import BedrockClient
from mallcop.llm.bedrock_mantle import BedrockMantleClient
from mallcop.llm_types import LLMClient
from tests.shakedown.evaluator import Grade, JudgeEvaluator, Verdict
from tests.shakedown.harness import ShakedownHarness
from tests.shakedown.runs import RunRecorder
from tests.shakedown.scenario import Scenario, load_all_scenarios

_log = logging.getLogger(__name__)


# Models whose Bedrock integration does NOT support Converse API toolResult.
# These use the bedrock-mantle (OpenAI Chat Completions) endpoint instead.
# Source: AWS Converse API feature matrix + empirical testing 2026-03-14.
_MANTLE_MODELS: frozenset[str] = frozenset({
    "zai.glm-4.7",
    "zai.glm-4.7-flash",
    "mistral.mistral-large-3-675b-instruct",
})

# Models that require cross-region inference profiles (us. prefix)
# instead of direct on-demand invocation.
_CROSS_REGION_MODELS: frozenset[str] = frozenset({
    "meta.llama4-scout-17b-instruct-v1:0",
    "meta.llama4-maverick-17b-instruct-v1:0",
    "amazon.nova-lite-v1:0",
    "amazon.nova-pro-v1:0",
    "amazon.nova-premier-v1:0",
})


@dataclass
class ModelSpec:
    """A model to test, parsed from pricing.yaml."""

    alias: str
    bedrock_id: str
    sovereignty: str
    blended_per_mtok: float
    cost_per_donut: float
    auto_route: bool = True


def load_models_from_pricing(pricing_path: Path) -> list[ModelSpec]:
    """Load auto-routable models from pricing.yaml."""
    data = yaml.safe_load(pricing_path.read_text())
    models = []
    for alias, info in data.get("models", {}).items():
        if not info.get("auto_route", True):
            continue
        models.append(ModelSpec(
            alias=alias,
            bedrock_id=info["bedrock_id"],
            sovereignty=info.get("sovereignty", "open"),
            blended_per_mtok=float(info.get("blended_per_mtok", 0)),
            cost_per_donut=float(info.get("cost_per_donut", 0)),
        ))
    return models


def build_llm_for_model(
    model: ModelSpec,
    region: str = "us-east-1",
    profile: str | None = None,
) -> LLMClient:
    """Build the right LLM client for a model based on its Bedrock capabilities.

    - Models in _MANTLE_MODELS → BedrockMantleClient (OpenAI Chat Completions + SigV4)
    - Models in _CROSS_REGION_MODELS → BedrockClient with us. prefix
    - Everything else → BedrockClient (Converse API)
    """
    bedrock_id = model.bedrock_id

    if bedrock_id in _MANTLE_MODELS:
        return BedrockMantleClient.from_profile(
            model=bedrock_id,
            region=region,
            profile=profile,
        )

    if bedrock_id in _CROSS_REGION_MODELS:
        bedrock_id = f"us.{bedrock_id}"

    return BedrockClient.from_profile(
        model=bedrock_id,
        region=region,
        profile=profile,
    )


@dataclass
class ModelResult:
    """Aggregated results for one model across all scenarios."""

    model: ModelSpec
    grades: list[Grade] = field(default_factory=list)
    scenario_ids: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    total_tokens: int = 0
    total_latency_ms: int = 0
    errors: list[str] = field(default_factory=list)


def _category_summary(
    grades: list[Grade], categories: list[str],
) -> dict[str, dict[str, int]]:
    """Group grades by category and count verdicts."""
    by_cat: dict[str, dict[str, int]] = {}
    for grade, cat in zip(grades, categories):
        if cat not in by_cat:
            by_cat[cat] = {"pass": 0, "warn": 0, "fail": 0, "total": 0}
        by_cat[cat][grade.verdict.value] += 1
        by_cat[cat]["total"] += 1
    return dict(sorted(by_cat.items()))


def _routing_recommendation(
    model_results: list[ModelResult],
    lane_token_budgets: dict[str, int] | None = None,
) -> dict[str, dict[str, str | None]]:
    """Produce routing recommendation from bakeoff results.

    For each lane (patrol, detective, forensic) and sovereignty tier,
    pick the cheapest model that passes a quality threshold.

    patrol: pass_rate >= 0.70 (triage is low-stakes, cost-optimize)
    detective: pass_rate >= 0.80
    forensic: pass_rate >= 0.85
    """
    thresholds = {"patrol": 0.70, "detective": 0.80, "forensic": 0.85}
    sov_tiers = ["open", "allied", "us_only"]

    # Build (alias, sovereignty, pass_rate, cost_per_donut) tuples
    candidates: list[tuple[str, str, float, float]] = []
    for mr in model_results:
        if mr.errors or not mr.grades:
            continue
        total = len(mr.grades)
        pass_count = sum(1 for g in mr.grades if g.verdict == Verdict.PASS)
        pass_rate = pass_count / total
        candidates.append((
            mr.model.alias,
            mr.model.sovereignty,
            pass_rate,
            mr.model.cost_per_donut,
        ))

    def _eligible(sov: str, model_sov: str) -> bool:
        """Can a model of model_sov serve requests in the sov tier?"""
        # open tier accepts any model
        if sov == "open":
            return True
        # allied tier accepts allied + us_only models
        if sov == "allied":
            return model_sov in ("allied", "us_only")
        # us_only accepts only us_only
        return model_sov == "us_only"

    recommendation: dict[str, dict[str, str | None]] = {}
    for lane, threshold in thresholds.items():
        recommendation[lane] = {}
        for sov in sov_tiers:
            eligible = [
                (alias, pr, cpd)
                for alias, msov, pr, cpd in candidates
                if _eligible(sov, msov) and pr >= threshold
            ]
            if not eligible:
                recommendation[lane][sov] = None
                continue
            # Pick cheapest among those meeting threshold
            eligible.sort(key=lambda x: x[2])  # sort by cost_per_donut
            recommendation[lane][sov] = eligible[0][0]

    return recommendation


def run_bakeoff(
    models: list[ModelSpec],
    scenarios: list[Scenario],
    judge: JudgeEvaluator,
    region: str = "us-east-1",
    profile: str | None = None,
    recorder: RunRecorder | None = None,
    on_scenario_done: Any = None,
) -> list[ModelResult]:
    """Run all scenarios against each model and grade results.

    Args:
        models: Models to test (from pricing.yaml).
        scenarios: Academy scenarios to run.
        judge: JudgeEvaluator for grading (uses its own LLM, typically sonnet).
        region: AWS region for Bedrock.
        profile: AWS profile for SSO credentials.
        recorder: Optional RunRecorder for JSONL output.
        on_scenario_done: Optional callback(model_alias, scenario_id, grade)
            for progress reporting.

    Returns:
        List of ModelResult, one per model.
    """
    results: list[ModelResult] = []

    for model in models:
        _log.info("Starting model: %s (%s)", model.alias, model.bedrock_id)
        mr = ModelResult(model=model)

        try:
            llm = build_llm_for_model(model, region=region, profile=profile)
        except Exception as e:
            mr.errors.append(f"credential error: {e}")
            results.append(mr)
            continue

        harness = ShakedownHarness(llm=llm)

        for scenario in scenarios:
            try:
                result = harness.run_scenario(scenario)
                grade = judge.evaluate(result, scenario)

                mr.grades.append(grade)
                mr.scenario_ids.append(scenario.id)
                mr.categories.append(scenario.category)
                mr.total_tokens += result.total_tokens
                mr.total_latency_ms += sum(c.latency_ms for c in result.llm_calls)

                if recorder:
                    recorder.record(
                        grade=grade,
                        result=result,
                        scenario=scenario,
                        model=model.alias,
                        backend="bedrock",
                        judge_model=judge.judge_model,
                    )

                if on_scenario_done:
                    on_scenario_done(model.alias, scenario.id, grade)

            except Exception as e:
                _log.warning(
                    "Error on %s / %s: %s", model.alias, scenario.id, e,
                )
                mr.errors.append(f"{scenario.id}: {e}")

        results.append(mr)
        _log.info(
            "Finished %s: %d/%d pass",
            model.alias,
            sum(1 for g in mr.grades if g.verdict == Verdict.PASS),
            len(mr.grades),
        )

    return results


def build_summary(
    model_results: list[ModelResult],
    scenarios_total: int,
) -> dict[str, Any]:
    """Build a diffable JSON summary of bakeoff results.

    Deterministic: sorted keys, no timestamps (those go in the JSONL).
    """
    models_out: dict[str, Any] = {}

    for mr in sorted(model_results, key=lambda m: m.model.alias):
        total = len(mr.grades)
        if total == 0:
            models_out[mr.model.alias] = {
                "bedrock_id": mr.model.bedrock_id,
                "sovereignty": mr.model.sovereignty,
                "cost_per_donut": mr.model.cost_per_donut,
                "blended_per_mtok": mr.model.blended_per_mtok,
                "scenarios_run": 0,
                "errors": mr.errors,
            }
            continue

        pass_count = sum(1 for g in mr.grades if g.verdict == Verdict.PASS)
        warn_count = sum(1 for g in mr.grades if g.verdict == Verdict.WARN)
        fail_count = sum(1 for g in mr.grades if g.verdict == Verdict.FAIL)
        avg_reasoning = sum(g.reasoning_quality for g in mr.grades) / total
        avg_investigation = sum(g.investigation_thoroughness for g in mr.grades) / total

        # Cost estimate: tokens * blended rate
        cost_usd = mr.total_tokens * mr.model.blended_per_mtok / 1_000_000

        models_out[mr.model.alias] = {
            "bedrock_id": mr.model.bedrock_id,
            "sovereignty": mr.model.sovereignty,
            "cost_per_donut": mr.model.cost_per_donut,
            "blended_per_mtok": mr.model.blended_per_mtok,
            "scenarios_run": total,
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
            "pass_rate": round(pass_count / total, 3),
            "avg_reasoning_quality": round(avg_reasoning, 2),
            "avg_investigation_thoroughness": round(avg_investigation, 2),
            "total_tokens": mr.total_tokens,
            "total_cost_usd": round(cost_usd, 4),
            "cost_per_scenario_usd": round(cost_usd / total, 4) if total else 0,
            "by_category": _category_summary(mr.grades, mr.categories),
            "errors": mr.errors,
        }

    recommendation = _routing_recommendation(model_results)

    return {
        "bakeoff_version": 1,
        "scenarios_total": scenarios_total,
        "models": models_out,
        "routing_recommendation": recommendation,
    }
