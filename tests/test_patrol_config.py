"""Tests for PatrolConfig parsing and period-to-cron translation."""

from __future__ import annotations

import pytest

from mallcop.patrol import PatrolConfig, period_to_cron, parse_patrols
from mallcop.secrets import ConfigError


# ---------------------------------------------------------------------------
# period_to_cron
# ---------------------------------------------------------------------------


class TestPeriodToCron:
    def test_15m(self):
        assert period_to_cron("15m") == "*/15 * * * *"

    def test_30m(self):
        assert period_to_cron("30m") == "*/30 * * * *"

    def test_1h(self):
        assert period_to_cron("1h") == "0 * * * *"

    def test_6h(self):
        assert period_to_cron("6h") == "0 */6 * * *"

    def test_12h(self):
        assert period_to_cron("12h") == "0 */12 * * *"

    def test_1d(self):
        assert period_to_cron("1d") == "0 0 * * *"

    def test_1w(self):
        assert period_to_cron("1w") == "0 0 * * 0"

    def test_1mo(self):
        assert period_to_cron("1mo") == "0 0 1 * *"

    def test_invalid_period_raises(self):
        with pytest.raises(ConfigError):
            period_to_cron("invalid")

    def test_unknown_unit_raises(self):
        with pytest.raises(ConfigError):
            period_to_cron("5x")

    def test_zero_minutes_raises(self):
        with pytest.raises(ConfigError):
            period_to_cron("0m")


# ---------------------------------------------------------------------------
# parse_patrols — basic parsing
# ---------------------------------------------------------------------------

FULL_PATROL_YAML = {
    "patrols": {
        "sweep": {
            "every": "6h",
            "connectors": "all",
            "detectors": "static",
            "budget": 0,
        },
        "deep": {
            "every": "1d",
            "chain": ["triage", "investigate"],
            "notify": ["slack"],
            "budget": 500,
        },
        "research": {
            "every": "1w",
            "research": True,
            "budget": 1000,
        },
    }
}


class TestParsePatrols:
    def test_returns_list_of_patrol_configs(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        assert isinstance(patrols, list)
        assert len(patrols) == 3

    def test_patrol_names(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        names = {p.name for p in patrols}
        assert names == {"sweep", "deep", "research"}

    def test_cron_schedule_translated(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        sweep = next(p for p in patrols if p.name == "sweep")
        assert sweep.cron_schedule == "0 */6 * * *"

    def test_every_preserved(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        sweep = next(p for p in patrols if p.name == "sweep")
        assert sweep.every == "6h"

    def test_connectors_all(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        sweep = next(p for p in patrols if p.name == "sweep")
        assert sweep.connectors == "all"

    def test_connectors_list(self):
        config = {
            "patrols": {
                "targeted": {
                    "every": "1h",
                    "connectors": ["azure", "github"],
                    "budget": 0,
                }
            }
        }
        patrols = parse_patrols(config, max_donuts_per_run=50000)
        assert patrols[0].connectors == ["azure", "github"]

    def test_detectors_default_all(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        deep = next(p for p in patrols if p.name == "deep")
        # deep doesn't specify detectors, so should default to "all"
        assert deep.detectors == "all"

    def test_detectors_static(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        sweep = next(p for p in patrols if p.name == "sweep")
        assert sweep.detectors == "static"

    def test_budget_zero(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        sweep = next(p for p in patrols if p.name == "sweep")
        assert sweep.budget == 0

    def test_budget_nonzero(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        deep = next(p for p in patrols if p.name == "deep")
        assert deep.budget == 500

    def test_chain_override(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        deep = next(p for p in patrols if p.name == "deep")
        assert deep.chain == ["triage", "investigate"]

    def test_notify_override(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        deep = next(p for p in patrols if p.name == "deep")
        assert deep.notify == ["slack"]

    def test_no_chain_defaults_to_none(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        sweep = next(p for p in patrols if p.name == "sweep")
        assert sweep.chain is None

    def test_no_notify_defaults_to_none(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        sweep = next(p for p in patrols if p.name == "sweep")
        assert sweep.notify is None

    def test_research_true(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        research = next(p for p in patrols if p.name == "research")
        assert research.research is True

    def test_research_defaults_false(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        sweep = next(p for p in patrols if p.name == "sweep")
        assert sweep.research is False

    def test_with_git_defaults_true(self):
        patrols = parse_patrols(FULL_PATROL_YAML, max_donuts_per_run=50000)
        sweep = next(p for p in patrols if p.name == "sweep")
        assert sweep.with_git is True

    def test_with_git_explicit_false(self):
        config = {
            "patrols": {
                "norepo": {
                    "every": "1h",
                    "budget": 0,
                    "with_git": False,
                }
            }
        }
        patrols = parse_patrols(config, max_donuts_per_run=50000)
        assert patrols[0].with_git is False


# ---------------------------------------------------------------------------
# parse_patrols — budget validation
# ---------------------------------------------------------------------------


class TestPatrolBudgetValidation:
    def test_budget_exceeds_max_donuts_per_run_raises(self):
        config = {
            "patrols": {
                "expensive": {
                    "every": "1d",
                    "budget": 100000,
                }
            }
        }
        with pytest.raises(ConfigError, match="budget"):
            parse_patrols(config, max_donuts_per_run=50000)

    def test_budget_equal_to_max_is_allowed(self):
        config = {
            "patrols": {
                "maxed": {
                    "every": "1d",
                    "budget": 50000,
                }
            }
        }
        patrols = parse_patrols(config, max_donuts_per_run=50000)
        assert patrols[0].budget == 50000

    def test_budget_zero_always_allowed(self):
        config = {
            "patrols": {
                "free": {
                    "every": "1h",
                    "budget": 0,
                }
            }
        }
        patrols = parse_patrols(config, max_donuts_per_run=0)
        assert patrols[0].budget == 0


# ---------------------------------------------------------------------------
# parse_patrols — budget semantics
# ---------------------------------------------------------------------------


class TestBudgetSemantics:
    def test_budget_zero_means_scan_detect_only(self):
        """budget=0 means no actor invocation (scan+detect only)."""
        config = {
            "patrols": {
                "sweep": {
                    "every": "6h",
                    "budget": 0,
                }
            }
        }
        patrols = parse_patrols(config, max_donuts_per_run=50000)
        patrol = patrols[0]
        assert patrol.budget == 0
        # Consumers check budget == 0 to skip actor invocation

    def test_research_true_means_research_command(self):
        """research=True signals that mallcop research should be used, not watch."""
        config = {
            "patrols": {
                "weekly": {
                    "every": "1w",
                    "research": True,
                    "budget": 1000,
                }
            }
        }
        patrols = parse_patrols(config, max_donuts_per_run=50000)
        patrol = patrols[0]
        assert patrol.research is True


# ---------------------------------------------------------------------------
# parse_patrols — optional / missing
# ---------------------------------------------------------------------------


class TestPatrolsOptional:
    def test_missing_patrols_key_returns_empty_list(self):
        config: dict = {}
        patrols = parse_patrols(config, max_donuts_per_run=50000)
        assert patrols == []

    def test_patrols_none_returns_empty_list(self):
        config = {"patrols": None}
        patrols = parse_patrols(config, max_donuts_per_run=50000)
        assert patrols == []

    def test_patrols_empty_dict_returns_empty_list(self):
        config = {"patrols": {}}
        patrols = parse_patrols(config, max_donuts_per_run=50000)
        assert patrols == []


# ---------------------------------------------------------------------------
# period_to_cron — undocumented behavior / latent bugs
# ---------------------------------------------------------------------------


class TestPeriodToCronEdgeCases:
    def test_2d_same_as_1d_documents_behavior(self):
        """2d produces daily cron, same as 1d. Multi-day periods are not supported.

        This is a documented limitation: the 'd' unit always produces
        "0 0 * * *" regardless of the N value. A user setting "2d" gets
        daily scheduling, not every-2-days scheduling. This test documents
        the current behavior so a future change is visible.
        """
        assert period_to_cron("2d") == "0 0 * * *"
        assert period_to_cron("3d") == "0 0 * * *"

    def test_2w_same_as_1w_documents_behavior(self):
        """2w produces weekly cron, same as 1w. Multi-week periods are not supported."""
        assert period_to_cron("2w") == "0 0 * * 0"

    def test_90m_documents_behavior(self):
        """90m produces */90 * * * * which is valid cron but only fires at minute 0.

        This is a documented limitation: */90 in the minutes field only triggers
        when the minute is divisible by 90, which only occurs at minute 0 in each
        hour (90 > 60 so no other minute qualifies). Users expecting "every 90
        minutes" should use a different scheduling approach.
        """
        assert period_to_cron("90m") == "*/90 * * * *"

    def test_parse_patrols_string_value_raises(self):
        """A patrol configured as a string (not a dict) should raise ConfigError."""
        config = {
            "patrols": {
                "bad": "this-should-be-a-dict"
            }
        }
        with pytest.raises(ConfigError, match="mapping"):
            parse_patrols(config, max_donuts_per_run=50000)
