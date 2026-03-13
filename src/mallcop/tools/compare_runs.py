#!/usr/bin/env python3
"""Compare shakedown run results across models and configurations.

Usage:
    python -m mallcop.tools.compare_runs runs/abc123.jsonl runs/def456.jsonl
    python -m mallcop.tools.compare_runs runs/
    python -m mallcop.tools.compare_runs runs/baseline.jsonl runs/latest.jsonl --fail-on-regression
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, median


def load_run(path: Path) -> list[dict]:
    """Load JSONL run file."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def group_by_config(records: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """Group records by (model, git_sha) — each unique pair is a config."""
    groups = defaultdict(list)
    for r in records:
        key = (r.get("model", "unknown"), r.get("git_sha", "unknown")[:7])
        groups[key].append(r)
    return dict(groups)


def summarize(records: list[dict]) -> dict:
    """Summarize a group of scenario results."""
    total = len(records)
    if total == 0:
        return {}

    passes = sum(1 for r in records if r.get("verdict") == "PASS")
    fails = sum(1 for r in records if r.get("verdict") == "FAIL")
    warns = sum(1 for r in records if r.get("verdict") == "WARN")

    rq = [r["reasoning_quality"] for r in records if r.get("reasoning_quality")]
    it = [r["investigation_thoroughness"] for r in records if r.get("investigation_thoroughness")]
    latencies = [r["latency_ms"] for r in records if r.get("latency_ms")]
    tokens = [r["tokens"] for r in records if r.get("tokens")]

    return {
        "scenarios": total,
        "pass_rate": f"{passes/total*100:.0f}%",
        "pass": passes,
        "fail": fails,
        "warn": warns,
        "avg_reasoning": f"{mean(rq):.1f}" if rq else "N/A",
        "avg_investigation": f"{mean(it):.1f}" if it else "N/A",
        "median_latency_ms": f"{median(latencies):.0f}" if latencies else "N/A",
        "total_tokens": sum(tokens) if tokens else 0,
    }


def find_regressions(baseline: list[dict], current: list[dict]) -> list[dict]:
    """Find scenarios that regressed: PASS->FAIL or score dropped >=2."""
    baseline_by_id = {r["scenario_id"]: r for r in baseline}
    regressions = []
    for r in current:
        sid = r["scenario_id"]
        if sid in baseline_by_id:
            b = baseline_by_id[sid]
            # Action regression: was PASS, now FAIL
            if b.get("verdict") == "PASS" and r.get("verdict") == "FAIL":
                regressions.append({
                    "scenario_id": sid,
                    "type": "verdict",
                    "before": b.get("verdict"),
                    "after": r.get("verdict"),
                })
            # Score regression: reasoning dropped >=2
            br = b.get("reasoning_quality", 0)
            cr = r.get("reasoning_quality", 0)
            if br and cr and br - cr >= 2:
                regressions.append({
                    "scenario_id": sid,
                    "type": "reasoning_quality",
                    "before": br,
                    "after": cr,
                })
    return regressions


def format_table(groups: dict[tuple[str, str], list[dict]]) -> str:
    """Format comparison as a table."""
    summaries = {}
    for key, records in groups.items():
        model, sha = key
        label = f"{model.split('-')[-1] if 'claude' in model else model}/{sha}"
        summaries[label] = summarize(records)

    if not summaries:
        return "No data."

    # Get all metric keys
    metrics = list(next(iter(summaries.values())).keys())

    # Column widths
    label_width = max(len(l) for l in summaries) + 2
    col_width = max(max(len(str(s.get(m, ""))) for s in summaries.values()) for m in metrics) + 2
    col_width = max(col_width, 12)

    # Header
    lines = []
    header = f"{'':>{label_width}}"
    for label in summaries:
        header += f"  {label:>{col_width}}"
    lines.append(header)
    lines.append("-" * len(header))

    # Rows
    for m in metrics:
        row = f"{m:>{label_width}}"
        for label in summaries:
            val = str(summaries[label].get(m, ""))
            row += f"  {val:>{col_width}}"
        lines.append(row)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Compare shakedown run results")
    parser.add_argument("paths", nargs="+", help="JSONL files or directories")
    parser.add_argument("--fail-on-regression", action="store_true",
                        help="Exit 1 if regressions found (for CI)")
    args = parser.parse_args()

    # Collect all JSONL files
    all_records = []
    files = []
    for p in args.paths:
        path = Path(p)
        if path.is_dir():
            files.extend(sorted(path.glob("*.jsonl")))
        elif path.is_file():
            files.append(path)

    for f in files:
        all_records.extend(load_run(f))

    if not all_records:
        print("No records found.")
        sys.exit(1)

    # Group and display
    groups = group_by_config(all_records)
    print(format_table(groups))

    # Regression check if exactly 2 groups
    if args.fail_on_regression and len(files) == 2:
        baseline = load_run(files[0])
        current = load_run(files[1])
        regressions = find_regressions(baseline, current)
        if regressions:
            print(f"\n{len(regressions)} regressions found:")
            for r in regressions:
                print(f"  {r['scenario_id']}: {r['type']} {r['before']}->{r['after']}")
            sys.exit(1)
        else:
            print("\nNo regressions.")


if __name__ == "__main__":
    main()
