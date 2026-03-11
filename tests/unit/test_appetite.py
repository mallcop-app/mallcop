"""Tests for appetite estimation and plan recommendation (donut economy)."""

from __future__ import annotations

import pytest

from mallcop.appetite import (
    CONNECTOR_EVENTS_PER_DAY,
    FINDING_RATE,
    AVG_DONUTS_PER_FINDING,
    PLAN_TIERS,
    estimate_appetite,
    recommend_plan,
)


class TestEstimateAppetite:
    """estimate_appetite returns donuts/month based on connector list."""

    def test_empty_connectors(self) -> None:
        result = estimate_appetite([])
        assert result == 0

    def test_single_azure_connector(self) -> None:
        # azure: 50 events/day * 0.03 * 1.5 * 30 = 67.5 → 67
        result = estimate_appetite(["azure"])
        expected = int(CONNECTOR_EVENTS_PER_DAY["azure"] * FINDING_RATE * AVG_DONUTS_PER_FINDING * 30)
        assert result == expected

    def test_single_github_connector(self) -> None:
        result = estimate_appetite(["github"])
        expected = int(CONNECTOR_EVENTS_PER_DAY["github"] * FINDING_RATE * AVG_DONUTS_PER_FINDING * 30)
        assert result == expected

    def test_single_vercel_connector(self) -> None:
        result = estimate_appetite(["vercel"])
        expected = int(CONNECTOR_EVENTS_PER_DAY["vercel"] * FINDING_RATE * AVG_DONUTS_PER_FINDING * 30)
        assert result == expected

    def test_single_aws_connector(self) -> None:
        result = estimate_appetite(["aws"])
        expected = int(CONNECTOR_EVENTS_PER_DAY["aws"] * FINDING_RATE * AVG_DONUTS_PER_FINDING * 30)
        assert result == expected

    def test_single_container_logs_connector(self) -> None:
        result = estimate_appetite(["container-logs"])
        expected = int(CONNECTOR_EVENTS_PER_DAY["container-logs"] * FINDING_RATE * AVG_DONUTS_PER_FINDING * 30)
        assert result == expected

    def test_multiple_connectors_sum(self) -> None:
        # Combined estimate uses float accumulation before truncating once,
        # so combined >= sum of individually-truncated values.
        azure = estimate_appetite(["azure"])
        github = estimate_appetite(["github"])
        combined = estimate_appetite(["azure", "github"])
        # Allow for off-by-one due to single-truncation vs per-connector truncation
        assert abs(combined - (azure + github)) <= 1

    def test_three_connectors(self) -> None:
        # Single-truncation: accumulate as float, truncate once at the end.
        result = estimate_appetite(["azure", "github", "vercel"])
        expected_float = sum(
            CONNECTOR_EVENTS_PER_DAY[c] * FINDING_RATE * AVG_DONUTS_PER_FINDING * 30
            for c in ["azure", "github", "vercel"]
        )
        assert result == int(expected_float)

    def test_unknown_connector_uses_fallback(self) -> None:
        # Unknown connector should not crash — uses fallback estimate
        result = estimate_appetite(["unknown-connector"])
        assert result >= 0

    def test_result_is_int(self) -> None:
        result = estimate_appetite(["azure", "github"])
        assert isinstance(result, int)


class TestRecommendPlan:
    """recommend_plan returns smallest tier with ≥20% headroom over appetite."""

    def test_small_appetite_gets_small_plan(self) -> None:
        # appetite within small tier allocation with headroom
        # find small tier allocation
        small_alloc = next(t["monthly_donuts"] for t in PLAN_TIERS if t["name"] == "small")
        max_fitting_appetite = int(small_alloc / 1.2)
        tier, price, headroom_pct = recommend_plan(max_fitting_appetite)
        assert tier == "small"

    def test_large_appetite_gets_large_plan(self) -> None:
        medium_alloc = next(t["monthly_donuts"] for t in PLAN_TIERS if t["name"] == "medium")
        # appetite exceeds medium headroom
        too_big = int(medium_alloc / 1.2) + 1
        tier, price, headroom_pct = recommend_plan(too_big)
        assert tier == "large"

    def test_medium_appetite_gets_medium_plan(self) -> None:
        small_alloc = next(t["monthly_donuts"] for t in PLAN_TIERS if t["name"] == "small")
        # just above what fits in small
        too_big_for_small = int(small_alloc / 1.2) + 1
        tier, price, headroom_pct = recommend_plan(too_big_for_small)
        assert tier == "medium"

    def test_zero_appetite_gets_small_plan(self) -> None:
        tier, price, headroom_pct = recommend_plan(0)
        assert tier == "small"

    def test_headroom_at_least_20pct(self) -> None:
        # For any appetite, headroom should be ≥ 20%
        for appetite in [10, 50, 100, 200, 500]:
            tier, price, headroom_pct = recommend_plan(appetite)
            assert headroom_pct >= 20.0, f"appetite={appetite} → tier={tier} headroom={headroom_pct}%"

    def test_returns_tuple_of_three(self) -> None:
        result = recommend_plan(50)
        assert len(result) == 3
        tier, price, headroom_pct = result
        assert isinstance(tier, str)
        assert isinstance(price, str)
        assert isinstance(headroom_pct, float)

    def test_plan_price_format(self) -> None:
        tier, price, headroom_pct = recommend_plan(50)
        assert "$" in price
        assert "/mo" in price

    def test_connector_list_recommend_plan_integration(self) -> None:
        # smoke test: estimate_appetite + recommend_plan end-to-end
        appetite = estimate_appetite(["azure"])
        tier, price, headroom_pct = recommend_plan(appetite)
        assert tier in {"small", "medium", "large"}
