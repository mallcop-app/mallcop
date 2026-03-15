"""Patrol config model and period-to-cron translation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from mallcop.secrets import ConfigError

__all__ = ["PatrolConfig", "period_to_cron", "parse_patrols"]

# Regex: optional leading integer + unit (m, h, d, w, mo)
_PERIOD_RE = re.compile(r"^(\d+)(m|h|d|w|mo)$")


def period_to_cron(period: str) -> str:
    """Convert a simplified period string to a cron expression.

    Supported formats:
        Nm  — every N minutes  e.g. 15m → */15 * * * *
        Nh  — every N hours    e.g. 1h  → 0 * * * *,  6h → 0 */6 * * *
        1d  — daily            → 0 0 * * *
        1w  — weekly (Sunday)  → 0 0 * * 0
        1mo — monthly          → 0 0 1 * *

    Raises ConfigError for unrecognised or invalid periods.
    """
    m = _PERIOD_RE.match(period)
    if not m:
        raise ConfigError(
            f"Invalid patrol period '{period}'. "
            f"Expected format: 15m, 1h, 6h, 1d, 1w, 1mo."
        )

    n = int(m.group(1))
    unit = m.group(2)

    if n == 0:
        raise ConfigError(f"Invalid patrol period '{period}': value must be > 0.")

    if unit == "m":
        return f"*/{n} * * * *"
    elif unit == "h":
        if n == 1:
            return "0 * * * *"
        return f"0 */{n} * * *"
    elif unit == "d":
        return "0 0 * * *"
    elif unit == "w":
        return "0 0 * * 0"
    elif unit == "mo":
        return "0 0 1 * *"
    else:
        # Should be unreachable given the regex, but be safe
        raise ConfigError(f"Unknown time unit '{unit}' in period '{period}'.")


@dataclass
class PatrolConfig:
    """Configuration for a single named patrol profile."""

    name: str
    every: str                          # simplified period: 15m, 1h, 6h, 1d, 1w, 1mo
    cron_schedule: str                  # translated cron expression
    connectors: str | list[str] = "all" # "all" or list of connector names
    detectors: str = "all"              # "static" or "all"
    budget: int = 0                     # max donuts for this patrol (0 = no actors)
    chain: list[str] | None = None      # patrol-level routing override
    notify: list[str] | None = None
    research: bool = False              # True = run mallcop research instead of watch
    with_git: bool = True               # True = include git wrapper in cron entry


def parse_patrols(config: dict[str, Any], max_donuts_per_run: int) -> list[PatrolConfig]:
    """Parse patrol configs from mallcop.yaml raw dict.

    Validates that each patrol's budget does not exceed max_donuts_per_run.
    Returns an empty list if 'patrols' key is absent or None.

    Raises ConfigError for invalid period formats or budget violations.
    """
    raw_patrols = config.get("patrols")
    if not raw_patrols or not isinstance(raw_patrols, dict):
        return []

    patrols: list[PatrolConfig] = []
    for name, raw in raw_patrols.items():
        if not isinstance(raw, dict):
            raise ConfigError(f"Patrol '{name}' must be a mapping, got {type(raw).__name__}.")

        every = raw.get("every", "")
        if not every:
            raise ConfigError(f"Patrol '{name}' is missing required field 'every'.")

        cron_schedule = period_to_cron(every)

        budget = int(raw.get("budget", 0))
        if budget > max_donuts_per_run:
            raise ConfigError(
                f"Patrol '{name}' budget ({budget}) exceeds max_donuts_per_run ({max_donuts_per_run}). "
                f"Reduce the patrol budget or raise max_donuts_per_run in the budget section."
            )

        patrols.append(
            PatrolConfig(
                name=name,
                every=every,
                cron_schedule=cron_schedule,
                connectors=raw.get("connectors", "all"),
                detectors=raw.get("detectors", "all"),
                budget=budget,
                chain=raw.get("chain"),
                notify=raw.get("notify"),
                research=bool(raw.get("research", False)),
                with_git=bool(raw.get("with_git", True)),
            )
        )

    return patrols
