"""Cost estimation for mallcop init output."""

from __future__ import annotations

from typing import Any

from mallcop.config import BudgetConfig

# Claude Haiku pricing as of 2026-03: $0.25/MTok input, $1.25/MTok output.
# Blended estimate assuming ~80% input / 20% output per triage run:
# (0.8 * 0.25 + 0.2 * 1.25) / 1000 = 0.00045, rounded down for conservatism.
# Used only for `mallcop init` cost estimates. Not worth making configurable.
COST_PER_1K_TOKENS_USD = 0.00025


def estimate_costs(
    num_connectors: int,
    sample_event_count: int,
    budget: BudgetConfig,
) -> dict[str, Any]:
    """Estimate per-run and monthly costs based on connector count and sample events."""
    est_events_low = max(sample_event_count, 10)
    est_events_high = sample_event_count * 5 if sample_event_count > 0 else 200

    est_findings_low = max(1, est_events_low // 20)
    est_findings_high = min(budget.max_findings_for_actors, est_events_high // 10)

    est_tokens_low = est_findings_low * 1000
    est_tokens_high = min(budget.max_tokens_per_run, est_findings_high * 3000)

    cost_per_run_low = (est_tokens_low / 1000) * COST_PER_1K_TOKENS_USD
    cost_per_run_high = (est_tokens_high / 1000) * COST_PER_1K_TOKENS_USD

    worst_case_tokens = budget.max_tokens_per_run
    worst_case_cost = (worst_case_tokens / 1000) * COST_PER_1K_TOKENS_USD

    runs_per_day = 4
    cost_per_month_low = cost_per_run_low * runs_per_day * 30
    cost_per_month_high = cost_per_run_high * runs_per_day * 30
    worst_case_month = worst_case_cost * runs_per_day * 30

    return {
        "connectors_active": num_connectors,
        "estimated_events_per_run": f"{est_events_low}-{est_events_high}",
        "estimated_findings_per_run": f"{est_findings_low}-{est_findings_high}",
        "estimated_tokens_per_run": f"{est_tokens_low}-{est_tokens_high}",
        "estimated_cost_per_run_usd": f"{cost_per_run_low:.4f}-{cost_per_run_high:.4f}",
        "estimated_cost_per_month_usd": f"{cost_per_month_low:.3f}-{cost_per_month_high:.3f}",
        "budget_max_tokens_per_run": budget.max_tokens_per_run,
        "budget_max_findings_for_actors": budget.max_findings_for_actors,
        "budget_max_tokens_per_finding": budget.max_tokens_per_finding,
        "worst_case_cost_per_run_usd": f"{worst_case_cost:.4f}",
        "worst_case_cost_per_month_usd": f"{worst_case_month:.3f}",
    }
