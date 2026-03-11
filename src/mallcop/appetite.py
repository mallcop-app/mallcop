"""Appetite estimation for mallcop Pro plan recommendation.

Donuts are the mallcop currency unit for managed inference.
This module estimates monthly donut consumption from connector config
and recommends the smallest Pro plan that covers the appetite with headroom.
"""

from __future__ import annotations

# Per-connector estimated events per day (conservative mid-range for small operators)
CONNECTOR_EVENTS_PER_DAY: dict[str, float] = {
    "azure": 50.0,
    "github": 20.0,
    "vercel": 10.0,
    "aws": 40.0,
    "container-logs": 30.0,
}

# Default fallback for unknown connectors
_FALLBACK_EVENTS_PER_DAY: float = 25.0

# 3% of events become findings (typical for well-tuned monitoring)
FINDING_RATE: float = 0.03

# Weighted average donuts per finding:
#   80% triage @ 1 donut, 15% investigation @ 3 donuts, 5% deep @ 6 donuts
#   = 0.8*1 + 0.15*3 + 0.05*6 = 0.8 + 0.45 + 0.30 = 1.55 → rounded to 1.5
AVG_DONUTS_PER_FINDING: float = 1.5

# Pro plan tiers: name, monthly_donuts allocation, price string
PLAN_TIERS: list[dict] = [
    {"name": "small", "monthly_donuts": 300, "price": "$29/mo"},
    {"name": "medium", "monthly_donuts": 750, "price": "$59/mo"},
    {"name": "large", "monthly_donuts": 2000, "price": "$99/mo"},
]

# Minimum headroom fraction: recommend only plans where allocation > appetite * (1 + HEADROOM)
HEADROOM_FRACTION: float = 0.20


def estimate_appetite(connectors: list[str]) -> int:
    """Estimate monthly donut consumption from a list of connector names.

    Formula: sum over connectors of (events_per_day × finding_rate × avg_donuts × 30)

    Args:
        connectors: List of connector name strings (e.g. ["azure", "github"]).

    Returns:
        Estimated donuts per month as an integer.
    """
    total: float = 0.0
    for connector in connectors:
        events_per_day = CONNECTOR_EVENTS_PER_DAY.get(connector, _FALLBACK_EVENTS_PER_DAY)
        total += events_per_day * FINDING_RATE * AVG_DONUTS_PER_FINDING * 30
    return int(total)


def recommend_plan(appetite: int) -> tuple[str, str, float]:
    """Recommend the smallest Pro plan that covers appetite with ≥20% headroom.

    Args:
        appetite: Estimated donuts/month from estimate_appetite().

    Returns:
        Tuple of (tier_name, price_string, headroom_pct) where headroom_pct is
        the percentage headroom the recommended tier provides over appetite.
        Returns the largest tier if none fit.
    """
    for tier in PLAN_TIERS:
        alloc = tier["monthly_donuts"]
        if alloc >= appetite * (1 + HEADROOM_FRACTION):
            headroom_pct = ((alloc - appetite) / alloc * 100) if alloc > 0 else 100.0
            return tier["name"], tier["price"], round(headroom_pct, 1)

    # Appetite exceeds all tiers — return largest with actual headroom
    largest = PLAN_TIERS[-1]
    alloc = largest["monthly_donuts"]
    headroom_pct = ((alloc - appetite) / alloc * 100) if appetite <= alloc else 0.0
    return largest["name"], largest["price"], round(headroom_pct, 1)
