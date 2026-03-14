"""Tests for squelch gating: threshold config, notification filtering, spot-check."""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from mallcop.actors._schema import ActorResolution, ResolutionAction
from mallcop.actors.runtime import RunResult
from mallcop.config import MallcopConfig, BudgetConfig, BaselineConfig
from mallcop.escalate import run_escalate, _should_squelch
from mallcop.schemas import (
    Annotation,
    Finding,
    FindingStatus,
    Severity,
)
from mallcop.store import JsonlStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_finding(
    fid: str = "fnd_001",
    severity: Severity = Severity.WARN,
) -> Finding:
    return Finding(
        id=fid,
        timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        detector="unusual-timing",
        event_ids=["evt_001"],
        title="Unusual timing",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata={"actor": "alice"},
    )


def _make_run_result(action: str = "escalated", confidence: float = 0.5) -> RunResult:
    res = ActorResolution(
        finding_id="fnd_001",
        action=ResolutionAction(action),
        reason="Test reason",
        confidence=confidence,
    )
    return RunResult(
        resolution=res,
        tokens_used=100,
        iterations=2,
        tool_calls=3,
        distinct_tools=2,
    )


# ---------------------------------------------------------------------------
# Config parsing tests
# ---------------------------------------------------------------------------

class TestSquelchConfig:
    def test_default_squelch_is_5(self, tmp_path):
        import yaml
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {},
            "actor_chain": {},
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))
        from mallcop.config import load_config
        config = load_config(tmp_path)
        assert config.squelch == 5

    def test_explicit_squelch_parsed(self, tmp_path):
        import yaml
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {},
            "actor_chain": {},
            "squelch": 7,
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))
        from mallcop.config import load_config
        config = load_config(tmp_path)
        assert config.squelch == 7

    def test_squelch_zero_allowed(self, tmp_path):
        import yaml
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {},
            "actor_chain": {},
            "squelch": 0,
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))
        from mallcop.config import load_config
        config = load_config(tmp_path)
        assert config.squelch == 0

    def test_squelch_10_allowed(self, tmp_path):
        import yaml
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {},
            "actor_chain": {},
            "squelch": 10,
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))
        from mallcop.config import load_config
        config = load_config(tmp_path)
        assert config.squelch == 10


# ---------------------------------------------------------------------------
# FindingStatus.SQUELCHED tests
# ---------------------------------------------------------------------------

class TestFindingStatusSquelched:
    def test_squelched_is_valid_status(self):
        from mallcop.schemas import FindingStatus
        assert FindingStatus.SQUELCHED.value == "squelched"

    def test_squelched_distinct_from_resolved(self):
        from mallcop.schemas import FindingStatus
        assert FindingStatus.SQUELCHED != FindingStatus.RESOLVED
        assert FindingStatus.SQUELCHED != FindingStatus.ACKED


# ---------------------------------------------------------------------------
# _should_squelch() logic tests
# ---------------------------------------------------------------------------

class TestShouldSquelchLogic:
    def test_below_threshold_escalation_is_squelched(self):
        """confidence < squelch/10 AND action == escalated → squelch."""
        result = _make_run_result(action="escalated", confidence=0.3)
        # squelch=7 → threshold=0.7 → 0.3 < 0.7 → squelch
        should, via_spot_check = _should_squelch(result, squelch=7, _random_override=0.5)
        assert should is True
        assert via_spot_check is False

    def test_above_threshold_escalation_not_squelched(self):
        """confidence >= squelch/10 AND action == escalated → NOT squelched."""
        result = _make_run_result(action="escalated", confidence=0.8)
        # squelch=7 → threshold=0.7 → 0.8 >= 0.7 → no squelch
        should, _ = _should_squelch(result, squelch=7, _random_override=0.5)
        assert should is False

    def test_resolved_never_squelched(self):
        """Resolved findings are never squelched regardless of confidence."""
        result = _make_run_result(action="resolved", confidence=0.1)
        should, _ = _should_squelch(result, squelch=10, _random_override=0.5)
        assert should is False

    def test_squelch_0_never_squelches(self):
        """squelch=0 → threshold=0.0 → nothing squelched."""
        result = _make_run_result(action="escalated", confidence=0.0)
        should, _ = _should_squelch(result, squelch=0, _random_override=0.5)
        assert should is False

    def test_squelch_10_always_squelches_low_confidence(self):
        """squelch=10 → threshold=1.0 → confidence < 1.0 always squelches."""
        result = _make_run_result(action="escalated", confidence=0.9)
        should, _ = _should_squelch(result, squelch=10, _random_override=0.5)
        assert should is True

    def test_spot_check_overrides_squelch(self):
        """10% spot-check: random < 0.1 means finding surfaces anyway."""
        result = _make_run_result(action="escalated", confidence=0.1)
        should, via_spot_check = _should_squelch(result, squelch=7, _random_override=0.05)
        assert should is False  # spot-check overrides
        assert via_spot_check is True

    def test_spot_check_does_not_override_above_threshold(self):
        """Spot-check only matters when below threshold."""
        result = _make_run_result(action="escalated", confidence=0.8)
        should, via_spot_check = _should_squelch(result, squelch=7, _random_override=0.05)
        assert should is False
        assert via_spot_check is False

    def test_none_resolution_not_squelched(self):
        """None resolution (error state) is never squelched."""
        result = RunResult(
            resolution=None,
            tokens_used=100,
            iterations=1,
            tool_calls=0,
            distinct_tools=0,
        )
        should, _ = _should_squelch(result, squelch=10, _random_override=0.5)
        assert should is False


# ---------------------------------------------------------------------------
# Spot-check rate tests
# ---------------------------------------------------------------------------

class TestSpotCheckRate:
    def test_spot_check_rate_approximately_10_percent(self):
        """Over many trials, ~10% of squelched findings surface via spot-check."""
        result = _make_run_result(action="escalated", confidence=0.1)
        spot_check_count = 0
        total = 200
        for _ in range(total):
            should, via_spot_check = _should_squelch(result, squelch=7)
            if via_spot_check:
                spot_check_count += 1
        # Expect roughly 10% ± 5% (normal deviation)
        rate = spot_check_count / total
        assert 0.02 <= rate <= 0.25, f"Spot-check rate {rate:.2%} outside expected range"


# ---------------------------------------------------------------------------
# Integration: squelched findings persisted with annotations
# ---------------------------------------------------------------------------

class TestSquelchedFindingPersistence:
    def test_squelched_finding_gets_squelched_status(self, tmp_path):
        """Squelched findings are stored as squelched (not resolved/open)."""
        store = JsonlStore(tmp_path)
        finding = _make_finding()
        store.append_findings([finding])

        # Mock actor runner that returns low-confidence escalation
        low_confidence_result = _make_run_result(action="escalated", confidence=0.2)
        low_confidence_result.resolution.confidence = 0.2

        def mock_runner(f, **kwargs):
            return low_confidence_result

        import yaml
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {"warn": {"chain": ["triage"], "notify": []}},
            "actor_chain": {},
            "squelch": 7,  # threshold=0.7, so 0.2 < 0.7 → squelch
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))

        # Patch random to disable spot-check (0.5 > 0.1 threshold)
        with patch("mallcop.escalate.random.random", return_value=0.5):
            run_escalate(root=tmp_path, actor_runner=mock_runner, store=store)

        findings = store.query_findings()
        assert len(findings) == 1
        updated = findings[0]
        assert updated.status == FindingStatus.SQUELCHED

    def test_squelched_finding_has_annotation_trail(self, tmp_path):
        """Squelched findings have full annotation trail."""
        store = JsonlStore(tmp_path)
        finding = _make_finding()
        store.append_findings([finding])

        low_confidence_result = _make_run_result(action="escalated", confidence=0.2)

        def mock_runner(f, **kwargs):
            return low_confidence_result

        import yaml
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {"warn": {"chain": ["triage"], "notify": []}},
            "actor_chain": {},
            "squelch": 7,
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))

        # Patch random to disable spot-check (0.5 > 0.1 threshold)
        with patch("mallcop.escalate.random.random", return_value=0.5):
            run_escalate(root=tmp_path, actor_runner=mock_runner, store=store)

        findings = store.query_findings()
        assert len(findings[0].annotations) >= 1

    def test_above_threshold_escalation_not_squelched(self, tmp_path):
        """High-confidence escalation passes through normally (not squelched)."""
        store = JsonlStore(tmp_path)
        finding = _make_finding()
        store.append_findings([finding])

        high_confidence_result = _make_run_result(action="escalated", confidence=0.9)

        def mock_runner(f, **kwargs):
            return high_confidence_result

        import yaml
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {"warn": {"chain": ["triage"], "notify": []}},
            "actor_chain": {},
            "squelch": 5,  # threshold=0.5, 0.9 >= 0.5 → not squelched
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))

        run_escalate(root=tmp_path, actor_runner=mock_runner, store=store)

        findings = store.query_findings()
        # Status should NOT be squelched (may be open with annotations or escalated)
        assert findings[0].status != FindingStatus.SQUELCHED

    def test_resolved_finding_not_squelched(self, tmp_path):
        """Resolved findings are not squelched regardless of confidence."""
        store = JsonlStore(tmp_path)
        finding = _make_finding()
        store.append_findings([finding])

        resolved_result = _make_run_result(action="resolved", confidence=0.1)

        def mock_runner(f, **kwargs):
            return resolved_result

        import yaml
        config_data = {
            "secrets": {"backend": "env"},
            "connectors": {},
            "routing": {"warn": {"chain": ["triage"], "notify": []}},
            "actor_chain": {},
            "squelch": 10,
            "budget": {"max_findings_for_actors": 25, "max_tokens_per_run": 50000, "max_tokens_per_finding": 5000},
        }
        (tmp_path / "mallcop.yaml").write_text(yaml.dump(config_data))

        run_escalate(root=tmp_path, actor_runner=mock_runner, store=store)

        findings = store.query_findings()
        assert findings[0].status == FindingStatus.RESOLVED
