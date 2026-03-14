#!/usr/bin/env python3
"""Bakeoff runner — run one model through all Academy scenarios.

Usage:
    python3 runs/run_bakeoff.py <model-alias> [--region us-west-2] [--profile 3dl]

Writes:
    runs/bakeoff-<alias>.jsonl   — per-scenario grades
    runs/bakeoff-<alias>.json    — model summary
"""

import json
import logging
import os
import sys
import time
from pathlib import Path

# Ensure mallcop is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.shakedown.bakeoff import (
    ModelSpec,
    build_llm_for_model,
    load_models_from_pricing,
)
from tests.shakedown.evaluator import JudgeEvaluator, Verdict
from tests.shakedown.harness import ShakedownHarness
from tests.shakedown.runs import RunRecorder
from tests.shakedown.scenario import load_all_scenarios

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
_log = logging.getLogger("bakeoff")


def main() -> None:
    alias = sys.argv[1]
    region = "us-west-2"
    profile = "3dl"
    pricing_path = Path(os.environ.get(
        "PRICING_YAML",
        Path(__file__).resolve().parents[1].parent / "mallcop-cloud" / "config" / "pricing.yaml",
    ))
    judge_backend = os.environ.get("JUDGE_BACKEND", "claude-code")

    for arg in sys.argv[2:]:
        if arg.startswith("--region="):
            region = arg.split("=", 1)[1]
        elif arg.startswith("--profile="):
            profile = arg.split("=", 1)[1]

    # Load model spec
    models = load_models_from_pricing(pricing_path)
    model = next((m for m in models if m.alias == alias), None)
    if model is None:
        print(f"ERROR: model '{alias}' not found in {pricing_path}", file=sys.stderr)
        sys.exit(1)

    # Load scenarios
    scenarios_dir = Path(__file__).resolve().parents[1] / "tests" / "shakedown" / "scenarios"
    scenarios = load_all_scenarios(scenarios_dir)
    _log.info("Model: %s (%s)", model.alias, model.bedrock_id)
    _log.info("Scenarios: %d", len(scenarios))
    _log.info("Region: %s, Profile: %s", region, profile)

    # Build LLM client for model under test
    try:
        llm = build_llm_for_model(model, region=region, profile=profile)
    except Exception as e:
        _log.error("Failed to build LLM client: %s", e)
        sys.exit(1)

    # Build judge LLM
    from tests.shakedown.conftest import _build_llm_client
    judge_llm = _build_llm_client(backend=judge_backend, model="sonnet")
    judge = JudgeEvaluator(judge_llm=judge_llm, judge_model="sonnet")

    # Recorder
    runs_dir = Path(__file__).resolve().parent
    recorder = RunRecorder(output_dir=runs_dir)
    # Override output file name for easy identification
    recorder._file = runs_dir / f"bakeoff-{alias}.jsonl"
    _log.info("Output: %s", recorder._file)

    harness = ShakedownHarness(llm=llm)

    # Run scenarios
    pass_count = 0
    fail_count = 0
    warn_count = 0
    error_count = 0
    total_tokens = 0
    start_time = time.monotonic()

    for i, scenario in enumerate(scenarios):
        try:
            result = harness.run_scenario(scenario)
            grade = judge.evaluate(result, scenario)

            recorder.record(
                grade=grade,
                result=result,
                scenario=scenario,
                model=alias,
                backend="bedrock",
                judge_model="sonnet",
            )

            v = grade.verdict.value.upper()
            if grade.verdict == Verdict.PASS:
                pass_count += 1
            elif grade.verdict == Verdict.FAIL:
                fail_count += 1
            else:
                warn_count += 1

            total_tokens += result.total_tokens
            elapsed = time.monotonic() - start_time
            _log.info(
                "[%d/%d] %s %s  tokens=%d  elapsed=%.0fs",
                i + 1, len(scenarios), v, scenario.id,
                result.total_tokens, elapsed,
            )

        except Exception as e:
            error_count += 1
            _log.error("[%d/%d] ERROR %s: %s", i + 1, len(scenarios), scenario.id, e)

    elapsed_total = time.monotonic() - start_time
    total = pass_count + fail_count + warn_count
    pass_rate = pass_count / total if total else 0
    cost_usd = total_tokens * model.blended_per_mtok / 1_000_000

    summary = {
        "model": alias,
        "bedrock_id": model.bedrock_id,
        "sovereignty": model.sovereignty,
        "blended_per_mtok": model.blended_per_mtok,
        "cost_per_donut": model.cost_per_donut,
        "scenarios_run": total,
        "pass": pass_count,
        "warn": warn_count,
        "fail": fail_count,
        "errors": error_count,
        "pass_rate": round(pass_rate, 3),
        "total_tokens": total_tokens,
        "total_cost_usd": round(cost_usd, 4),
        "elapsed_seconds": round(elapsed_total),
    }

    summary_path = runs_dir / f"bakeoff-{alias}.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    _log.info("Summary written to %s", summary_path)
    _log.info(
        "DONE: %s pass=%d warn=%d fail=%d errors=%d rate=%.1f%% cost=$%.2f time=%ds",
        alias, pass_count, warn_count, fail_count, error_count,
        pass_rate * 100, cost_usd, elapsed_total,
    )


if __name__ == "__main__":
    main()
