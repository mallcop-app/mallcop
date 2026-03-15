#!/usr/bin/env python3
"""Prompt optimization loop for commodity model quality.

Runs prompt variants against a subset of scenarios, grades with judge,
and reports comparative results. Designed for rapid iteration.

Usage:
    python3 runs/prompt_optimize.py --variant triage-v1.md --model glm-4.7-flash
    python3 runs/prompt_optimize.py --variant investigate-v1.md --actor investigate --model glm-4.7-flash
    python3 runs/prompt_optimize.py --all-variants --model glm-4.7-flash
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.shakedown.bakeoff import build_llm_for_model, ModelSpec, load_models_from_pricing
from tests.shakedown.evaluator import JudgeEvaluator, Verdict
from tests.shakedown.harness import ShakedownHarness
from tests.shakedown.scenario import load_all_scenarios
from tests.shakedown.conftest import _build_llm_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
_log = logging.getLogger("optimize")

SCENARIOS_DIR = Path(__file__).resolve().parents[1] / "tests" / "shakedown" / "scenarios"
ACTORS_DIR = Path(__file__).resolve().parents[1] / "src" / "mallcop" / "actors"
VARIANTS_DIR = Path(__file__).resolve().parent / "prompt_variants"
PRICING_YAML = Path(__file__).resolve().parents[1].parent / "mallcop-cloud" / "config" / "pricing.yaml"

# Curated test set: 5 pass, 5 warn, 5 fail from GLM Flash 68% run
# Covers all major failure categories
TEST_SCENARIOS = [
    # Passes (regression check)
    "AC-01-external-access-stolen-cred",
    "AC-05-contractor-first-day",
    "AF-01-fat-finger-benign",
    "PE-03-cross-account-grant",
    "LFD-02-log-tampering",
    # Warns (target: flip to pass)
    "URA-01-shallow-baseline",
    "UT-01-competing-signals",
    "CO-02-benign-events-first",
    "IT-01-tools-called-results-ignored",
    "PE-02-self-elevation",
    # Fails (target: flip to warn or pass)
    "CO-01-newest-first",
    "PI-01-metadata-instruction",
    "PE-01-admin-exemption-owner-grant",
    "VA-04-api-enumeration",
    "ID-01-new-actor-benign-onboarding",
]


def load_test_scenarios() -> list:
    all_s = load_all_scenarios(SCENARIOS_DIR)
    id_set = set(TEST_SCENARIOS)
    selected = [s for s in all_s if s.id in id_set]
    missing = id_set - {s.id for s in selected}
    if missing:
        _log.warning("Missing scenarios: %s", missing)
    return selected


def run_variant(
    variant_path: Path,
    actor: str,
    model_spec: ModelSpec,
    scenarios: list,
    judge: JudgeEvaluator,
    region: str,
    profile: str,
) -> dict:
    """Run a prompt variant and return results."""
    # Swap the POST.md temporarily
    target = ACTORS_DIR / actor / "POST.md"
    backup = target.with_suffix(".md.bak")
    shutil.copy2(target, backup)

    try:
        shutil.copy2(variant_path, target)
        llm = build_llm_for_model(model_spec, region=region, profile=profile)
        harness = ShakedownHarness(llm=llm)

        results = []
        for s in scenarios:
            try:
                result = harness.run_scenario(s)
                grade = judge.evaluate(result, s)
                results.append({
                    "scenario_id": s.id,
                    "verdict": grade.verdict.value,
                    "action_correct": grade.action_correct,
                    "reasoning_quality": grade.reasoning_quality,
                    "investigation_thoroughness": grade.investigation_thoroughness,
                    "llm_calls": len(result.llm_calls),
                    "tokens": result.total_tokens,
                })
            except Exception as e:
                _log.error("Error on %s: %s", s.id, e)
                results.append({
                    "scenario_id": s.id,
                    "verdict": "error",
                    "action_correct": False,
                    "reasoning_quality": 0,
                    "investigation_thoroughness": 0,
                    "llm_calls": 0,
                    "tokens": 0,
                })

        return _summarize(variant_path.stem, results)
    finally:
        shutil.copy2(backup, target)
        backup.unlink()


def _summarize(variant_name: str, results: list) -> dict:
    total = len(results)
    p = sum(1 for r in results if r["verdict"] == "pass")
    w = sum(1 for r in results if r["verdict"] == "warn")
    f = sum(1 for r in results if r["verdict"] == "fail")
    e = sum(1 for r in results if r["verdict"] == "error")
    avg_reason = sum(r["reasoning_quality"] for r in results) / max(total, 1)
    avg_invest = sum(r["investigation_thoroughness"] for r in results) / max(total, 1)
    avg_calls = sum(r["llm_calls"] for r in results) / max(total, 1)
    total_tokens = sum(r["tokens"] for r in results)

    summary = {
        "variant": variant_name,
        "total": total,
        "pass": p,
        "warn": w,
        "fail": f,
        "error": e,
        "pass_rate": round(p / max(total, 1), 3),
        "avg_reasoning": round(avg_reason, 2),
        "avg_investigation": round(avg_invest, 2),
        "avg_calls": round(avg_calls, 1),
        "total_tokens": total_tokens,
        "results": results,
    }
    return summary


def print_comparison(summaries: list[dict]) -> None:
    print()
    print(f"{'Variant':30s} {'Pass':>5s} {'Warn':>5s} {'Fail':>5s} {'Err':>4s} {'Rate':>6s} {'Reason':>7s} {'Invest':>7s} {'Calls':>6s} {'Tokens':>8s}")
    print("-" * 95)
    for s in sorted(summaries, key=lambda x: x["pass_rate"], reverse=True):
        print(
            f"{s['variant']:30s} {s['pass']:>5d} {s['warn']:>5d} {s['fail']:>5d} {s['error']:>4d}"
            f" {s['pass_rate']*100:>5.1f}% {s['avg_reasoning']:>7.2f} {s['avg_investigation']:>7.2f}"
            f" {s['avg_calls']:>6.1f} {s['total_tokens']:>8d}"
        )
    print()

    # Per-scenario breakdown for top variant
    best = sorted(summaries, key=lambda x: x["pass_rate"], reverse=True)[0]
    print(f"Best variant: {best['variant']} ({best['pass_rate']*100:.1f}%)")
    print(f"{'Scenario':45s} {'Verdict':>7s} {'Reason':>7s} {'Invest':>7s} {'Calls':>6s}")
    print("-" * 75)
    for r in best["results"]:
        print(f"{r['scenario_id']:45s} {r['verdict']:>7s} {r['reasoning_quality']:>7d} {r['investigation_thoroughness']:>7d} {r['llm_calls']:>6d}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", type=Path, help="Single variant to test")
    parser.add_argument("--all-variants", action="store_true", help="Test all variants in prompt_variants/")
    parser.add_argument("--actor", default="triage", help="Actor to optimize (triage or investigate)")
    parser.add_argument("--model", default="glm-4.7-flash", help="Model alias")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--profile", default="3dl")
    parser.add_argument("--full", action="store_true", help="Run full 54 scenarios instead of test set")
    parser.add_argument("--output", type=Path, help="Write results JSON to file")
    args = parser.parse_args()

    # Load model
    models = load_models_from_pricing(PRICING_YAML)
    model_spec = next((m for m in models if m.alias == args.model), None)
    if not model_spec:
        print(f"Model {args.model} not found in pricing.yaml", file=sys.stderr)
        sys.exit(1)

    # Load scenarios
    if args.full:
        scenarios = load_all_scenarios(SCENARIOS_DIR)
    else:
        scenarios = load_test_scenarios()
    _log.info("Model: %s, Actor: %s, Scenarios: %d", args.model, args.actor, len(scenarios))

    # Build judge
    judge_llm = _build_llm_client(backend="claude-code", model="sonnet")
    judge = JudgeEvaluator(judge_llm=judge_llm, judge_model="sonnet")

    # Determine variants to test
    variants = []
    if args.variant:
        variants = [args.variant]
    elif args.all_variants:
        actor_dir = VARIANTS_DIR / args.actor
        if actor_dir.exists():
            variants = sorted(actor_dir.glob("*.md"))
        else:
            variants = []
    else:
        variants = [ACTORS_DIR / args.actor / "POST.md"]

    _log.info("Variants: %s", [v.stem for v in variants])

    # Run each variant
    summaries = []
    for v in variants:
        _log.info("=== Running variant: %s ===", v.stem)
        start = time.monotonic()
        summary = run_variant(v, args.actor, model_spec, scenarios, judge, args.region, args.profile)
        elapsed = time.monotonic() - start
        summary["elapsed_seconds"] = round(elapsed)
        summaries.append(summary)
        _log.info("Done: %s — %d/%d pass in %ds", v.stem, summary["pass"], summary["total"], elapsed)

    print_comparison(summaries)

    if args.output:
        args.output.write_text(json.dumps(summaries, indent=2) + "\n")
        _log.info("Results written to %s", args.output)


if __name__ == "__main__":
    main()
